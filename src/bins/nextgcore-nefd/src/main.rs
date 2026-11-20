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
use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::context::SbiContext;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_internal_error, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod context;
mod southbound_reconcile; // #1877: failed southbound unsubscribes, retried until delivered
/// nextgsim#480 (demo d445a-fl-t8): TS 29.522 UE ID retrieval for an AF.
#[cfg(feature = "demo-d445a-fl-t8")]
mod ueid;

pub use context::*;

/// The TS 29.122 §5.10 `DeliveryResult` a Device Triggering create reports while
/// no SMS/T4 delivery leg exists (issue #111).
///
/// ONE constant so the stored transaction and the echoed body cannot drift: they
/// were two separate literals, and a fix applied to one would have left the other
/// claiming success.
const DEVICE_TRIGGERING_STUB_RESULT: &str = "UNKNOWN";

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

    #[arg(short = 'e', long)]
    log_level: Option<String>,

    #[arg(short = 'm', long)]
    no_color: bool,

    #[arg(long, default_value = nextgcore_core::sockaddr::DEFAULT_LISTEN_HOST)]
    sbi_addr: String,

    #[arg(long, default_value = "7817")]
    sbi_port: u16,

    /// The SBI host advertised in the NRF NFProfile and the default notify base
    /// (#1322). Without it, `NEXTGCORE_SBI_ADVERTISE`, else `--sbi-addr` when it
    /// is not a wildcard. A wildcard is never advertised.
    #[arg(long)]
    sbi_advertise: Option<String>,

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
    /// http://{advertised host}:{sbi-port} (#1322); with a wildcard --sbi-addr and
    /// nothing to advertise, the NEF refuses to start without it.
    #[arg(long)]
    notify_base: Option<String>,

    /// Maximum stored northbound monitoring subscriptions.
    #[arg(long, default_value = "4096")]
    max_subscriptions: usize,

    /// Maximum stored device triggering transactions.
    #[arg(long, default_value = "4096")]
    max_transactions: usize,

    /// BSF SBI base URI for UE ID retrieval's Nbsf_Management_Discovery
    /// (TS 23.502 §4.15.10 steps 7-8; demo d445a-fl-t8, nextgsim#480). Required
    /// while that demo is active.
    #[cfg(feature = "demo-d445a-fl-t8")]
    #[arg(long)]
    bsf_uri: Option<String>,
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

/// The outbound OAuth2 client (#1661): the NEF presents an NRF-issued token on
/// its southbound service requests to the UDM, AMF and BSF (TS 33.501
/// §13.4.1.1.2). Installed at startup by [`outbound_oauth2_client`].
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The installed outbound OAuth2 client, if any (#1661).
pub(crate) fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    #[cfg(test)]
    if let Ok(oauth2) = TEST_OAUTH2_CLIENT.try_with(Arc::clone) {
        return Some(oauth2);
    }
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

#[cfg(test)]
tokio::task_local! {
    /// #1661 tests: the OAuth2 client [`oauth2_client`] returns inside
    /// `TEST_OAUTH2_CLIENT.scope(..)`. Task-local, so the other tests in the
    /// process keep the default (none installed).
    pub(crate) static TEST_OAUTH2_CLIENT: Arc<nextgcore_sbi::oauth::OAuth2Client>;
}

/// #1661: the outbound OAuth2 client this NEF installs at startup: under the
/// `production` SBI profile or the `sbi.oauth2.require` knob, when an NRF is
/// configured (see [`nextgcore_sbi::oauth::outbound_oauth2_client`]).
fn outbound_oauth2_client(
    profile: nextgcore_sbi::security::SbiProfile,
    require_oauth2: bool,
    nrf_uri: Option<&str>,
) -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    nextgcore_sbi::oauth::outbound_oauth2_client(
        profile,
        require_oauth2,
        nrf_uri,
        nextgcore_sbi::types::NfType::Nef,
    )
}

fn northbound_auth() -> NorthboundAuth {
    #[cfg(test)]
    if let Ok(auth) = TEST_NORTHBOUND_AUTH.try_with(|a| *a) {
        return auth;
    }
    NORTHBOUND_AUTH.get().copied().unwrap_or_default()
}

#[cfg(test)]
tokio::task_local! {
    /// #2132 (R41 on #2159): the northbound enforcement [`northbound_auth`]
    /// returns inside `TEST_NORTHBOUND_AUTH.scope(..)`, so a handler test can
    /// run under mTLS/OAuth2 enforcement without setting the process-wide
    /// `NORTHBOUND_AUTH` once and for every other test.
    pub(crate) static TEST_NORTHBOUND_AUTH: NorthboundAuth;
}

/// The authenticated identity of the caller, `Ok(None)` when the request carries
/// no identity this process verified (issue #110), or `Err(why)` when what it
/// carries is no identity (#2132).
///
/// The shared rule, `nextgcore_sbi::owner_binding::verified_consumer_id`
/// (CONVENTIONS: caller identity always comes from it), over the identity THIS
/// PROCESS verified, never anything in the URL:
///
/// - `peer_cert_nf_instance_id`, the URI SAN of a chain-verified client
///   certificate (issue #186), only under `auth.mtls` (`verify_client`), and
///   only when the certificate is not a relay's (SCP/SEPP, RFC 9310 NFTypes);
/// - `oauth2_subject`, the `sub` the SBI server set after verifying the bearer
///   token's signature, audience, scope and expiry (#94), only under
///   `auth.oauth2`. The raw `Authorization` header is never read here, so an
///   unverified `sub` can never become an identity;
/// - a certificate and a token naming different instances refuse;
/// - under the production SBI profile, a certificate naming no NF type is no
///   identity on its own (#2065): it cannot be told from a relay's.
///
/// The `auth` guards are kept although the server populates both fields only
/// when it verified them, so a listener started without enforcement can never
/// admit an identity.
fn authenticated_client_id(
    request: &SbiRequest,
    auth: NorthboundAuth,
) -> Result<Option<String>, String> {
    authenticated_client_id_with(
        request,
        auth,
        nextgcore_sbi::owner_binding::identity_required(),
    )
}

/// [`authenticated_client_id`] under the profile `production` says.
fn authenticated_client_id_with(
    request: &SbiRequest,
    auth: NorthboundAuth,
    production: bool,
) -> Result<Option<String>, String> {
    let mut verified = SbiRequest::get("/");
    if auth.mtls {
        verified.peer_cert_nf_instance_id = request.peer_cert_nf_instance_id.clone();
        verified.peer_cert_nf_types = request.peer_cert_nf_types.clone();
    }
    if auth.oauth2 {
        verified.oauth2_subject = request.oauth2_subject.clone();
    }
    let identity = nextgcore_sbi::owner_binding::verified_consumer_id_with(&verified, production)?;
    // #2132 (R41 on #2159): under mTLS enforcement every caller presents a
    // certificate, so `None` here means a relay's (SCP/SEPP) certificate with
    // no verified token behind it. Taking that as anonymous would let the relay
    // create an ownerless (scsAsId-keyed) subscription whenever OAuth2 is not
    // also enforced; refuse it instead.
    if identity.is_none()
        && nextgcore_sbi::owner_binding::is_relay_certificate(&verified.peer_cert_nf_types)
    {
        return Err(
            "the requester's client certificate is a relay's (SCP/SEPP), which is no caller \
             identity, and no verified access token names the consumer behind it"
                .to_string(),
        );
    }
    Ok(identity)
}

/// #2132: the 403 for a request whose credentials are no identity (see
/// [`authenticated_client_id`]). Every route checks identity first, before
/// any validation, southbound call or subscription lookup, so the refusal says
/// nothing about whether a UE or a subscription exists.
fn refuse_unidentified(operation: &str, why: &str) -> SbiResponse {
    log::debug!("{operation} refused: {why}");
    nextgcore_sbi::server::send_forbidden(&format!("{operation}: {why}"), None)
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
    nextgcore_core::log::nf_log_builder(level).init();
}

fn setup_signal_handlers(shutdown: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown.store(true, Ordering::SeqCst);
    })
    .expect("value expected");
}

/// #1795: the NEF's SBI listener under the SBI security profile. Under
/// `production`: TLS from `policy`'s certificate paths (whatever `--tls` or the
/// config file said), the client certificate verified against its CA, and an
/// access token required, with NEF as the audience and the NRF's JWKS unless
/// the NF configured its own (TS 33.501 §13.1.0, §13.3, §13.4.1). A missing
/// certificate fails startup, naming it, rather than serving cleartext. Under
/// `dev` the config is left as the NF's own settings made it.
fn sbi_listener_config(
    config: SbiServerConfig,
    profile: nextgcore_sbi::security::SbiProfile,
    policy: &nextgcore_sbi::security::SbiSecurityPolicy,
    nrf_uri: &str,
) -> nextgcore_sbi::SbiResult<SbiServerConfig> {
    nextgcore_sbi::security::apply_sbi_security_policy(
        config,
        profile,
        policy,
        nextgcore_sbi::types::NfType::Nef,
        nrf_uri,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&nextgcore_core::log::nf_log_level(
        args.log_level.as_deref(),
        Some(&args.config),
    ));
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

    // nextgsim#458: the demo: block. Checked against the demos this build was
    // compiled with, so an unknown key or mode, or a demo whose cargo feature is
    // not built, fails start-up. With no demo active nothing below changes.
    let config_root = config_root(&args.config).map_err(|e| anyhow::anyhow!("{e}"))?;
    nextgcore_demo::init_from_root(&config_root, &demo_registry())
        .map_err(|e| anyhow::anyhow!("{e} ({e:?})"))?;
    // nextgsim#480: UE ID retrieval, decided once here, before the route can be
    // reached and before the NRF registration that advertises it.
    #[cfg(feature = "demo-d445a-fl-t8")]
    ueid::install(
        nextgcore_demo::active_mode(ueid::DEMO_KEY),
        args.bsf_uri.clone(),
        args.udm_sdm_uri.clone().or_else(|| args.udm_uri.clone()),
        &args.nrf_uri,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

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

    // Issue #187: `--nf-instance-id` seeds the shared resolver so the flag keeps
    // winning, and the fallback is the resolver rather than a local UUID -- an
    // operator can then pin this NEF's identity from the environment too, which a
    // CCA trust store keyed by nfInstanceId needs.
    if let Some(id) = args.nf_instance_id.as_deref() {
        nextgcore_sbi::nf_instance_id::seed(id);
    }
    let nf_instance_id =
        nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Nef)
            .to_string();

    // #1322: the advertised host, apart from the bind; never a wildcard.
    let sbi = nextgcore_core::sockaddr::SbiEndpoint::resolve(
        Some(&args.sbi_addr),
        Some(args.sbi_port),
        args.sbi_advertise.as_deref(),
        None,
        None,
        None,
        7817,
    );
    let notify_base =
        nef_notify_base(args.notify_base.as_deref(), &sbi).map_err(|why| anyhow::anyhow!(why))?;
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

    let addr: SocketAddr =
        nextgcore_core::sockaddr::parse_listen_addr(&args.sbi_addr, args.sbi_port)
            .context("Invalid SBI address")?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    nextgcore_core::sockaddr::warn_if_loopback_listener("SBI", &addr, "--sbi-addr");

    let mut sbi_server_config =
        SbiServerConfig::new(addr).with_oauth2_callback_exemptions(oauth2_callback_exemptions());
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
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    let _ = OAUTH2_CLIENT.set(outbound_oauth2_client(
        sbi_profile,
        oauth2,
        (!args.nrf_uri.is_empty()).then_some(args.nrf_uri.as_str()),
    ));
    // #1667: the same client gives this NF's own NRF calls their access token.
    nextgcore_sbi::nrf_tls::set_nrf_oauth2_client(OAUTH2_CLIENT.get().cloned().flatten());
    if oauth2 {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config, &args.nrf_uri);
    }
    // #1795: the listener follows the SBI security profile, before the
    // northbound posture below is read off it.
    let mut sbi_server_config = sbi_listener_config(
        sbi_server_config,
        sbi_profile,
        &nextgcore_sbi::security::SbiSecurityPolicy::for_profile(sbi_profile),
        &args.nrf_uri,
    )
    .map_err(|e| anyhow::anyhow!("SBI security profile: {e}"))?;
    if args.verify_client {
        if sbi_server_config.scheme != nextgcore_sbi::types::UriScheme::Https {
            // Fail startup rather than run with an option that silently does
            // nothing: --verify-client without --tls reads as "mutual TLS is on"
            // while the listener is plaintext and every request is unauthenticated.
            anyhow::bail!(
                "--verify-client requires --tls: there is no client certificate to verify on a \
                 plaintext listener, and starting anyway would present an unauthenticated \
                 northbound surface as an authenticated one"
            );
        }
        // Under production the profile already verifies against its CA.
        if !sbi_server_config.verify_client {
            sbi_server_config.verify_client = true;
            sbi_server_config.verify_client_cacert = args.verify_client_cacert.clone();
        }
    }
    // The posture actually installed, knob or profile.
    let oauth2 = sbi_server_config.require_oauth2;
    let mtls = sbi_server_config.verify_client;
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

    // nextgsim#480: this NEF's /metrics (nextg_demo_enabled and the UE ID
    // outcomes), only while the demo is active. NEXTGCORE_METRICS_BIND, loopback
    // by default.
    #[cfg(feature = "demo-d445a-fl-t8")]
    let _metrics = if ueid::serving() {
        nextgcore_metrics::nf::serve_nf_metrics(
            "NEF",
            "NEF_METRICS_PORT",
            Arc::new(render_prometheus),
        )
        .await
    } else {
        None
    };

    // #1791: the NFProfile advertises the scheme this listener serves.
    let sbi_scheme = sbi_server_config.scheme;
    let sbi_server = SbiServer::new(sbi_server_config);
    log::info!("Starting NEF SBI server on {addr}");
    sbi_server
        .start(nef_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // #111: retry deferred southbound legs so an accepted subscription either
    // becomes live or is expired. Without this a subscription created before the
    // AMF/UDM was configured stayed accepted-and-un-notifiable forever.
    tokio::spawn(async move {
        let period = Duration::from_secs(reconcile_interval_secs());
        loop {
            tokio::time::sleep(period).await;
            reconcile_pending_subscriptions().await;
        }
    });
    // #2102: live legs are refreshed before they lapse. #2128 (R42): on their
    // own task, so a blackholed producer's refreshes cannot hold up the #111
    // retries above (nor they it).
    tokio::spawn(async move {
        let period = Duration::from_secs(reconcile_interval_secs());
        loop {
            tokio::time::sleep(period).await;
            refresh_live_subscriptions_with(Arc::new(now_unix_secs)).await;
        }
    });
    // #1877: and southbound unsubscribes that failed are retried until delivered.
    drop(southbound_reconcile::spawn_reconciler());

    // Register with NRF as nfType NEF advertising nnef-eventexposure
    // (registration failure is non-fatal, mirroring nwdafd).
    let sbi_ctx = nextgcore_sbi::context::global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    // #1482: a failed attempt is retried in the background, and the heartbeat
    // starts after the one that succeeds.
    match sbi.registration_host() {
        Ok(host) => {
            let (host, port, id) = (host.to_string(), sbi.port, nf_instance_id.clone());
            nextgcore_sbi::heartbeat::register_or_retry(
                "NEF",
                Default::default(),
                move || {
                    let (ctx, host, id) = (sbi_ctx.clone(), host.clone(), id.clone());
                    async move {
                        register_with_nrf(ctx, &host, port, &id, sbi_scheme)
                            .await
                            .map(|()| Some(id))
                    }
                },
                |nf_instance_id| {
                    // PATCH a real NFProfile "/load" gauge to NRF each heartbeat: active
                    // monitoring subscriptions, saturated at 100 (TS 29.510 §5.2.2.3.2).
                    nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                        nf_instance_id,
                        5,
                        || {
                            let load = nef_self()
                                .read()
                                .map(|c| c.subscription_count())
                                .unwrap_or(0);
                            load.min(100) as u8
                        },
                    );
                },
            )
            .await;
        }
        Err(e) => log::warn!("NRF registration not attempted (will operate without NRF): {e}"),
    }

    log::info!("NextGCore NEF ready (instance: {nf_instance_id})");

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
    nef_context_final();
    log::info!("NEF shutdown complete");

    Ok(())
}

/// NEF SBI request handler
async fn nef_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!(
        "NEF SBI: {method} {}",
        nextgcore_sbi::log_redact::redact_callback_tokens(uri)
    );

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // Monitoring Event northbound API (TS 29.122 §5.3)
        ["3gpp-monitoring-event", "v1", scs_as_id, "subscriptions"] => match method {
            "POST" => {
                handle_monitoring_subscription_create(
                    scs_as_id,
                    &request,
                    NorthboundApi::T8MonitoringEvent,
                )
                .await
            }
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
        // Nnef_EventExposure (TS 29.591) -- the service the NF profile advertises
        // (issue #111). Declared BEFORE the notify sink so the more specific
        // `notify/{id}` arm below is still reached.
        ["nnef-eventexposure", "v1", "subscriptions"] => match method {
            "POST" => handle_nnef_event_exposure_create(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["nnef-eventexposure", "v1", "subscriptions", sub_id] => match method {
            "DELETE" => handle_nnef_event_exposure_delete(sub_id, &request).await,
            _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
        },
        // Producer (AMF/UDM) notification sink; the NEF subscription ID and its
        // token are embedded in the callback path handed to the producer (#1518).
        ["nnef-eventexposure", "v1", "notify", nef_sub_id, NEF_NOTIFY_SEGMENT, token] => {
            match method {
                "POST" => handle_producer_notification(nef_sub_id, Some(token), &request).await,
                _ => send_method_not_allowed(method, "notify/{subscriptionId}/..."),
            }
        }
        // The token-less URI of before #1518: served only for a subscription
        // persisted from then (`admits_notify`).
        ["nnef-eventexposure", "v1", "notify", nef_sub_id] => match method {
            "POST" => handle_producer_notification(nef_sub_id, None, &request).await,
            _ => send_method_not_allowed(method, "notify/{subscriptionId}"),
        },
        // nextgsim#480: TS 29.522 UE ID retrieval. The router's own 404 unless
        // demo d445a-fl-t8 is active.
        #[cfg(feature = "demo-d445a-fl-t8")]
        ["3gpp-ueid", "v1", "retrieve"] => ueid::route(method, path, &request).await,
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// Which northbound API a monitoring subscription arrived on (issue #111).
///
/// The two are the SAME subscription -- one NEF subscription, one southbound
/// producer leg, one notification path -- and differ only in the wire shape of the
/// request and the resource path of the created subscription. Parameterising the
/// one handler is what keeps them from drifting: a fix to the failure semantics or
/// the target resolution applies to both by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum NorthboundApi {
    /// TS 29.122 §5.3 T8 Monitoring Event. The default, so a subscription
    /// recorded before #2154 (every one of them made on either API) reads as
    /// T8, the shape it was notified in.
    #[default]
    T8MonitoringEvent,
    /// TS 29.591 `Nnef_EventExposure`, the service the NF profile advertises.
    NnefEventExposure,
}

impl NorthboundApi {
    /// The created subscription's resource path.
    fn subscription_location(&self, scs_as_id: &str, sub_id: &str) -> String {
        match self {
            Self::T8MonitoringEvent => {
                format!("/3gpp-monitoring-event/v1/{scs_as_id}/subscriptions/{sub_id}")
            }
            Self::NnefEventExposure => {
                format!("/nnef-eventexposure/v1/subscriptions/{sub_id}")
            }
        }
    }
}

/// TS 29.591 `Nnef_EventExposure` event IDs this NEF can serve, and the TS 29.122
/// MonitoringType each maps onto (issue #111).
///
/// One subscription machine serves both APIs, so an event the T8 side cannot serve
/// is not served here either -- and is refused by NAME rather than silently
/// accepted, which is what #111 is about.
const NNEF_EVENT_TO_MONITORING_TYPE: &[(&str, &str)] = &[
    ("LOCATION_REPORT", "LOCATION_REPORTING"),
    ("UE_REACHABILITY", "UE_REACHABILITY"),
    ("LOSS_OF_CONNECTIVITY", "LOSS_OF_CONNECTIVITY"),
];

/// POST /nnef-eventexposure/v1/subscriptions — TS 29.591 `Nnef_EventExposure`
/// Subscribe (issue #111).
///
/// **This route exists because the NF profile advertises `nnef-eventexposure`.**
/// Before #111 the only thing mounted under that API root was the internal
/// producer notification SINK, so a consumer that discovered this NEF via the NRF
/// and issued the advertised operation got `404` from the router fallthrough. The
/// alternative -- stop advertising the service -- was rejected: the sink path is a
/// callback the NEF hands to producers, not a service it offers, so dropping the
/// advertisement would have left the NEF offering nothing over SBI while the
/// machinery to offer something already existed.
///
/// The body is translated into the T8 shape and handed to the one subscription
/// handler, so the failure semantics, the anyUE guard and the target resolution are
/// shared rather than reimplemented. An `eventId` outside
/// [`NNEF_EVENT_TO_MONITORING_TYPE`] is refused with `501` naming it, rather than
/// accepted for an event that will never fire.
async fn handle_nnef_event_exposure_create(request: &SbiRequest) -> SbiResponse {
    let Some(body) = &request.http.content else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // TS 29.591 mandatory IEs: notifUri, notifId, and at least one nefEventSubs
    // entry carrying an eventId.
    let notif_uri = match data.get("notifUri").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return send_bad_request("notifUri is mandatory", Some("MANDATORY_IE_MISSING")),
    };
    let notif_id = match data.get("notifId").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return send_bad_request("notifId is mandatory", Some("MANDATORY_IE_MISSING")),
    };
    let subs = match data.get("nefEventSubs").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a,
        _ => {
            return send_bad_request(
                "nefEventSubs is mandatory and must be non-empty",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    // One southbound leg per subscription, so exactly one event is served. Refusing
    // a multi-event request is honest; accepting it and serving the first would be
    // the fabricated-success shape this issue exists to remove.
    if subs.len() > 1 {
        return send_error(
            501,
            "Not Implemented",
            "this NEF serves one event per subscription; send one nefEventSubs entry",
            Some("UNSUPPORTED_REQUEST"),
        );
    }
    let event_id = match subs[0].get("eventId").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return send_bad_request(
                "nefEventSubs[0].eventId is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let Some((_, monitoring_type)) = NNEF_EVENT_TO_MONITORING_TYPE
        .iter()
        .find(|(id, _)| *id == event_id)
    else {
        let supported: Vec<&str> = NNEF_EVENT_TO_MONITORING_TYPE
            .iter()
            .map(|(id, _)| *id)
            .collect();
        return send_error(
            501,
            "Not Implemented",
            &format!("eventId '{event_id}' is not served by this NEF (served: {supported:?})"),
            Some("UNSUPPORTED_REQUEST"),
        );
    };

    // Translate into the T8 shape the one subscription handler validates. The UE
    // identity keys are carried across verbatim so the anyUE guard and the
    // path-injection guard apply unchanged.
    let mut translated = serde_json::json!({
        "notificationDestination": notif_uri,
        "monitoringType": monitoring_type,
    });
    {
        let obj = translated.as_object_mut().expect("json! built an object");
        for key in ["supi", "msisdn", "externalId", "externalGroupId"] {
            if let Some(value) = subs[0].get(key).or_else(|| data.get(key)) {
                obj.insert(key.to_string(), value.clone());
            }
        }
    }
    let mut translated_request = request.clone();
    translated_request.http.content = Some(translated.to_string());

    // `notifId` is the consumer's correlation handle; it names the SUBSCRIPTION on
    // the consumer side, so it is the natural {scsAsId} equivalent for ownership.
    let response = handle_monitoring_subscription_create(
        &notif_id,
        &translated_request,
        NorthboundApi::NnefEventExposure,
    )
    .await;
    log::info!("Nnef_EventExposure subscribe: notifId={notif_id}, eventId={event_id}");
    response
}

/// DELETE /nnef-eventexposure/v1/subscriptions/{subId} — TS 29.591 Unsubscribe.
async fn handle_nnef_event_exposure_delete(sub_id: &str, request: &SbiRequest) -> SbiResponse {
    // #2132: identity first, so a caller whose credentials are no identity
    // cannot tell a 404 from a 403.
    if let Err(why) = authenticated_client_id(request, northbound_auth()) {
        return refuse_unidentified("Nnef_EventExposure unsubscribe", &why);
    }
    // Ownership is checked against the subscription's stored `scs_as_id`, which for
    // this API is the consumer's `notifId` -- so the delete resolves it from the
    // stored subscription rather than from the path, which carries no consumer id.
    let scs_as_id = match nef_self().read() {
        Ok(c) => c.subscription_find(sub_id).map(|s| s.scs_as_id),
        Err(_) => return send_internal_error("NEF context lock poisoned"),
    };
    let Some(scs_as_id) = scs_as_id else {
        return send_not_found(&format!("Subscription {sub_id} not found"), None);
    };
    handle_monitoring_subscription_delete(&scs_as_id, sub_id, request).await
}

/// POST /3gpp-monitoring-event/v1/{scsAsId}/subscriptions —
/// TS 29.122 §5.3 Monitoring Event subscription create. Validates the AF
/// request (mandatory-IE parity with udmd's `handle_ee_subscribe`),
/// translates it into a southbound producer subscription (best-effort),
/// stores the northbound↔southbound mapping, and returns 201 with Location.
/// #1877: spawn `fut` on its own task, so dropping its caller (an AF request that
/// went away) cannot cut it short. Test builds carry the caller's OAuth2 scope over.
fn spawn_detached<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    #[cfg(test)]
    if let Ok(oauth2) = TEST_OAUTH2_CLIENT.try_with(Arc::clone) {
        return tokio::spawn(TEST_OAUTH2_CLIENT.scope(oauth2, fut));
    }
    tokio::spawn(fut)
}

/// #1877: what became of a detached create, shared by its task and the request.
#[derive(Debug, Default)]
enum CreateHandoff {
    #[default]
    Pending,
    /// The AF went away first: the task removes what it creates.
    Abandoned,
    /// The create finished; the subscription id of a 201, else `None`.
    Finished(Option<String>),
}

/// The subscription id a 201's Location names.
fn created_subscription_id(response: &SbiResponse) -> Option<String> {
    if response.status != 201 {
        return None;
    }
    response
        .http
        .get_header("Location")?
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// #1877: remove a subscription whose 201 the AF never received, and its producer
/// leg: the AF holds no `self` link to delete it by, so nothing else ever would.
fn spawn_abandoned_create_removal(sub_id: String) {
    log::warn!(
        "monitoring subscription {sub_id}: its create was abandoned by the AF after it \
         was established; removing it and its southbound leg"
    );
    let removed = {
        let ctx = nef_self();
        let c = ctx.read().ok();
        let found = c.as_ref().and_then(|c| c.subscription_find(&sub_id));
        // #2086: owed before the removal is persisted, in the same snapshot.
        if let Some(southbound) = found.as_ref().and_then(|s| s.southbound.clone()) {
            southbound_reconcile::owe(southbound);
        }
        if let Some(c) = c.as_ref() {
            c.subscription_remove(&sub_id);
        }
        found
    };
    if let Some(southbound) = removed.and_then(|s| s.southbound) {
        let uri = producer_uri(southbound.producer);
        drop(spawn_detached(southbound_unsubscribe(uri, southbound)));
    }
}

impl CreateHandoff {
    fn finish(handoff: &Mutex<Self>, response: &SbiResponse) {
        let created = created_subscription_id(response);
        let mut state = handoff.lock().unwrap_or_else(|e| e.into_inner());
        match *state {
            CreateHandoff::Abandoned => {
                if let Some(id) = created {
                    spawn_abandoned_create_removal(id);
                }
            }
            _ => *state = CreateHandoff::Finished(created),
        }
    }

    fn abandon(handoff: &Mutex<Self>) {
        let mut state = handoff.lock().unwrap_or_else(|e| e.into_inner());
        if let CreateHandoff::Finished(Some(id)) =
            std::mem::replace(&mut *state, CreateHandoff::Abandoned)
        {
            spawn_abandoned_create_removal(id);
        }
    }
}

/// Held by the request awaiting a detached create; dropped unanswered, it hands
/// the subscription to the task.
struct CreateAbandonGuard {
    handoff: Arc<Mutex<CreateHandoff>>,
    answered: bool,
}

impl Drop for CreateAbandonGuard {
    fn drop(&mut self) {
        if !self.answered {
            CreateHandoff::abandon(&self.handoff);
        }
    }
}

/// POST of a monitoring subscription, run on its own task (#1877).
///
/// The southbound subscribe at the AMF or UDM is awaited before the local record
/// is stored, and the SBI server polls a handler inline in the request's stream:
/// an AF that went away after the producer accepted dropped the create there, and
/// the producer subscription was recorded nowhere (the #1755 shape). On its own
/// task the create always reaches its insert, or its rollback; and a 201 the AF
/// never read is removed, with its producer leg ([`spawn_abandoned_create_removal`]).
async fn handle_monitoring_subscription_create(
    scs_as_id: &str,
    request: &SbiRequest,
    api: NorthboundApi,
) -> SbiResponse {
    // #2132: identity first, before validation and before the southbound UDM
    // GPSI lookup, so a caller whose credentials are no identity learns
    // nothing (no 404 UE_NOT_FOUND) and causes no southbound call. Issue #110:
    // ownership is keyed to an identity this process verified, not to the
    // caller-supplied {scsAsId} path segment.
    let owner_id = match authenticated_client_id(request, northbound_auth()) {
        Ok(id) => id,
        Err(why) => return refuse_unidentified("monitoring subscription create", &why),
    };
    let handoff = Arc::new(Mutex::new(CreateHandoff::Pending));
    let mut guard = CreateAbandonGuard {
        handoff: handoff.clone(),
        answered: false,
    };
    let (scs_as_id, request) = (scs_as_id.to_string(), request.clone());
    let task = spawn_detached(async move {
        let response =
            handle_monitoring_subscription_create_inner(&scs_as_id, &request, api, owner_id).await;
        CreateHandoff::finish(&handoff, &response);
        response
    });
    let result = task.await;
    guard.answered = true;
    match result {
        Ok(response) => response,
        Err(e) => send_internal_error(&format!("the monitoring subscription create failed: {e}")),
    }
}

async fn handle_monitoring_subscription_create_inner(
    scs_as_id: &str,
    request: &SbiRequest,
    api: NorthboundApi,
    owner_id: Option<String>,
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

    let sub = NefMonitoringSubscription::new(
        scs_as_id,
        &monitoring_type,
        &notification_destination,
        body.clone(),
    )
    .with_af_target(af_target)
    .with_owner_id(owner_id)
    // #2154: notifications go out in the shape of the API it was made on.
    .with_northbound_api(api);

    let notify_base = notify_base.unwrap_or_else(|| "http://127.0.0.1:7817".to_string());
    let nf_instance_id = nf_instance_id.unwrap_or_else(|| "nef-unregistered".to_string());
    let nef_notify_uri = nef_notify_uri(&notify_base, &sub);

    // #111: a leg that CANNOT be established now rejects the northbound create;
    // one that has not been ATTEMPTED yet is accepted and retained for the
    // reconciler. Before this, all four failure modes returned 201 with a `self`
    // link for a subscription that could never notify.
    let built = build_southbound_subscribe(
        &monitoring_type,
        &target,
        &nef_notify_uri,
        &sub.id,
        &nf_instance_id,
    );
    let (southbound, pending) = match &built {
        Some(req) => {
            let producer_uri = match req.producer {
                SouthboundProducer::Amf => amf_uri.clone(),
                SouthboundProducer::Udm => udm_uri.clone(),
            };
            match attempt_southbound_subscribe(producer_uri, req).await {
                SouthboundOutcome::Live(reference, expiry) => (Some((reference, expiry)), None),
                SouthboundOutcome::Deferred => (
                    None,
                    Some(PendingSouthbound {
                        producer: req.producer,
                        path: req.path.clone(),
                        body: req.body.clone(),
                        since: now_unix_secs(),
                    }),
                ),
                SouthboundOutcome::Failed { retryable, detail } => {
                    log::warn!(
                        "rejecting monitoring subscription create for scsAsId={scs_as_id}: {detail}"
                    );
                    return SouthboundOutcome::failure_response(retryable, &detail);
                }
            }
        }
        // No southbound leg is REQUIRED for this monitoring type: there is nothing
        // deferred and nothing failed, which is why this is not an outcome variant.
        None => (None, None),
    };

    let (southbound, southbound_expiry) = match southbound {
        Some((reference, expiry)) => (Some(reference), Some(expiry)),
        None => (None, None),
    };
    let sub = NefMonitoringSubscription {
        southbound,
        pending,
        southbound_expiry,
        ..sub
    };
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

    let location = api.subscription_location(scs_as_id, &sub_id);
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
    let caller_id = match authenticated_client_id(request, northbound_auth()) {
        Ok(id) => id,
        Err(why) => return refuse_unidentified("monitoring subscription delete", &why),
    };
    let ctx = nef_self();
    let (sub, amf_uri, udm_uri) = match ctx.read() {
        Ok(c) => (c.subscription_find(sub_id), c.amf_uri(), c.udm_uri()),
        Err(_) => return send_internal_error("NEF context lock poisoned"),
    };
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

    // #1877: the record goes first, then the producer leg on its own task, so a
    // request dropped mid-DELETE (the AF went away) cannot leave the producer
    // subscription behind with nothing left to remove it. A DELETE that fails is
    // parked for the reconciler.
    {
        // #2086: the unsubscribe it owes is recorded before the removal is
        // persisted, in the same snapshot, so a restart cannot lose it.
        if let Some(southbound) = sub.southbound.clone() {
            southbound_reconcile::owe(southbound);
        }
        let ctx = nef_self();
        if let Ok(c) = ctx.read() {
            c.subscription_remove(sub_id);
        };
    }
    if let Some(southbound) = sub.southbound.clone() {
        let producer_uri = match southbound.producer {
            SouthboundProducer::Amf => amf_uri,
            SouthboundProducer::Udm => udm_uri,
        };
        let task = spawn_detached(southbound_unsubscribe(producer_uri, southbound));
        // Answered once the leg is done, as before, unless the caller goes first.
        let _ = task.await;
    }
    log::info!("Monitoring event subscription removed: id={sub_id}, scsAsId={scs_as_id}");
    SbiResponse::with_status(204)
}

/// POST /3gpp-device-triggering/v1/{scsAsId}/transactions — TS 29.122 §5.10
/// Device Triggering create. Validates and stores the transaction.
///
/// **No delivery leg exists**, so the reported `deliveryResult` is `UNKNOWN`
/// (issue #111). Forwarding the trigger toward SMS delivery is stubbed -- no SMSF
/// NF exists in this repo (`NfType::Smsf` is a routing label only) -- and this used
/// to report `TRIGGERED`.
///
/// `TRIGGERED` is a POSITIVE lifecycle state in TS 29.122 §5.10: it means the
/// trigger was accepted for delivery. Reporting it with no delivery path told the
/// AF the message was on its way and gave it no way to distinguish "queued" from
/// "silently dropped" -- which is precisely the failure mode device triggering
/// exists to prevent. `UNKNOWN` is the honest value: the transaction was accepted
/// and stored, and the NEF genuinely does not know the delivery outcome because it
/// never attempted one. Retire this once an SMSF/T4 leg lands.
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

    let txn = NefTriggerTransaction::new(scs_as_id, DEVICE_TRIGGERING_STUB_RESULT, body.clone());
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
        obj.insert(
            "deliveryResult".to_string(),
            serde_json::json!(DEVICE_TRIGGERING_STUB_RESULT),
        );
    }
    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_json_body(&echoed)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// The path segment before the token in the producer callback URI (#1518). It is
/// in `nextgcore_sbi::log_redact::CALLBACK_TOKEN_SEGMENTS`.
const NEF_NOTIFY_SEGMENT: &str = "nef-ee-notify";

/// The callback URI handed to the producer for `sub` (#1518):
/// `{base}/nnef-eventexposure/v1/notify/{id}/nef-ee-notify/{token}`.
fn nef_notify_uri(notify_base: &str, sub: &NefMonitoringSubscription) -> String {
    match &sub.notify_token {
        Some(token) => format!(
            "{notify_base}/nnef-eventexposure/v1/notify/{}/{NEF_NOTIFY_SEGMENT}/{}",
            sub.id,
            token.as_str()
        ),
        // Unreachable for a subscription made by this build; kept total rather
        // than panicking.
        None => format!("{notify_base}/nnef-eventexposure/v1/notify/{}", sub.id),
    }
}

/// The producer notification route admitted without an OAuth2 bearer when the
/// listener requires one (#1518): a notification carries no access token (TS 33.501
/// §13.4.1, TS 29.500 §6.10.7 NOTE). It needs the subscription's token AND a
/// verified mutual-TLS peer of a type that notifies for it, because third parties
/// can read the URI back (the #1522 rule):
/// - an AMF subscription travels in `UeContext.eventSubscriptionList` (TS 29.518
///   §6.1.6.2.25), so only an AMF;
/// - a UDM may keep its EE subscriptions in the UDR (`context-data/ee-subscriptions`,
///   TS 29.505), and for an AMF-assisted event the AMF notifies the NEF directly
///   (TS 23.502 §4.15.3.2.3 steps 3a-6), so a UDM or an AMF.
///
/// Without a verified certificate (plaintext, server-only TLS) the route stays on
/// the bearer. The token-less URI of before #1518 is never exempt.
fn oauth2_callback_exemptions() -> Vec<nextgcore_sbi::server::OAuth2CallbackExemption> {
    vec![
        nextgcore_sbi::server::OAuth2CallbackExemption::for_verified_peer(
            "POST",
            format!("/nnef-eventexposure/v1/notify/{{var}}/{NEF_NOTIFY_SEGMENT}/{{token}}"),
            |cb, peer| async move {
                let [nef_sub_id] = cb.vars.as_slice() else {
                    return false;
                };
                let Some(sub) = nef_self()
                    .read()
                    .ok()
                    .and_then(|c| c.subscription_find(nef_sub_id))
                else {
                    return false;
                };
                let notifier = match sub.producer() {
                    Some(SouthboundProducer::Amf) => peer.has_nf_type("AMF"),
                    Some(SouthboundProducer::Udm) => {
                        peer.has_nf_type("UDM") || peer.has_nf_type("AMF")
                    }
                    None => false,
                };
                notifier && sub.admits_notify(Some(&cb.token))
            },
        ),
    ]
}

/// POST /nnef-eventexposure/v1/notify/{nefSubId}/nef-ee-notify/{token} — producer notification
/// sink. Correlates the AMF/UDM notification back to the northbound AF
/// subscription and forwards it as a TS 29.122 MonitoringNotification on a
/// background task (fire-and-forget, amfd delivery parity), so the
/// producer's notify timeout never includes the AF round trip.
///
/// #1518: acted on only with the subscription's current token (or, for a
/// subscription persisted from before #1518, on the token-less URI), whatever
/// admitted the request; otherwise the same 404 an unknown id gets, and nothing is
/// forwarded.
async fn handle_producer_notification(
    nef_sub_id: &str,
    token: Option<&str>,
    request: &SbiRequest,
) -> SbiResponse {
    let ctx = nef_self();
    let sub = match ctx.read() {
        Ok(c) => c.subscription_find(nef_sub_id),
        Err(_) => return send_internal_error("NEF context lock poisoned"),
    };
    let Some(sub) = sub.filter(|s| s.admits_notify(token)) else {
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

    // #1439: nothing the AF subscribed to is in this body (every report was of
    // another type), so nothing is sent. The producer still gets 204: it
    // delivered correctly, and an error would only make it retry.
    let Some(notification) = build_monitoring_notification(&sub, &producer_body) else {
        return SbiResponse::no_content();
    };
    let destination = sub.notification_destination.clone();
    let sub_id = sub.id.clone();
    tokio::spawn(async move {
        forward_notification_to_af(&sub_id, destination, notification).await;
    });

    SbiResponse::no_content()
}

/// How long a deferred southbound leg is retried before it is expired
/// (issue #111). Overridable so a test does not have to wait.
fn pending_leg_deadline_secs() -> u64 {
    std::env::var("NEF_PENDING_LEG_DEADLINE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

/// How often the reconciler sweeps deferred legs.
fn reconcile_interval_secs() -> u64 {
    std::env::var("NEF_RECONCILE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

/// What one reconciler sweep did (issue #111). Returned rather than only logged so
/// the sweep is assertable without a timer.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Legs that reached their producer and are now live.
    pub promoted: usize,
    /// Legs past the deadline; the subscription was removed.
    pub expired: usize,
    /// Legs still deferred, to be retried next sweep.
    pub still_pending: usize,
}

/// Retry every deferred southbound leg once, promoting or expiring each
/// (issue #111).
///
/// This is the half that makes accepting a deferred subscription honest. Before
/// #111 a subscription whose producer was unconfigured was stored with
/// `southbound: None` and left there **forever**: it could never notify, nothing
/// retried it, and the AF held a `201` and a `self` link for a subscription that
/// was dead on arrival.
///
/// A leg is **expired** rather than retried indefinitely once it passes
/// [`pending_leg_deadline_secs`], and expiry REMOVES the subscription: an AF whose
/// subscription is gone can re-create it, whereas an AF holding one that will never
/// notify has no signal at all. That is the same reasoning as rejecting a hard
/// failure at create time, applied to the deferred case.
///
/// Returns what it did so a caller -- and a test -- can see it, rather than only
/// logging.
pub async fn reconcile_pending_subscriptions() -> ReconcileReport {
    let ctx = nef_self();
    let pending = match ctx.read() {
        Ok(c) => c.subscriptions_pending(),
        Err(_) => {
            log::error!("NEF context lock poisoned; skipping reconcile sweep");
            return ReconcileReport::default();
        }
    };
    if pending.is_empty() {
        return ReconcileReport::default();
    }

    let (amf_uri, udm_uri) = match ctx.read() {
        Ok(c) => (c.amf_uri(), c.udm_uri()),
        Err(_) => return ReconcileReport::default(),
    };
    let deadline = pending_leg_deadline_secs();
    let now = now_unix_secs();
    let mut report = ReconcileReport::default();

    for sub in pending {
        let Some(leg) = sub.pending.clone() else {
            continue;
        };
        let producer_uri = match leg.producer {
            SouthboundProducer::Amf => amf_uri.clone(),
            SouthboundProducer::Udm => udm_uri.clone(),
        };
        let req = SouthboundSubscribe {
            producer: leg.producer,
            path: leg.path.clone(),
            body: leg.body.clone(),
        };
        match attempt_southbound_subscribe(producer_uri, &req).await {
            SouthboundOutcome::Live(reference, expiry) => {
                if let Ok(c) = ctx.read() {
                    if c.subscription_promote(&sub.id, reference.clone(), Some(expiry)) {
                        log::info!(
                            "deferred southbound leg promoted to live: sub={} producer={}",
                            sub.id,
                            leg.producer.as_str()
                        );
                        report.promoted += 1;
                        continue;
                    }
                }
                // The AF deleted the subscription while this retry was in flight;
                // tear the producer-side subscription down rather than orphan it.
                log::info!(
                    "subscription {} vanished mid-retry; unsubscribing the producer leg",
                    sub.id
                );
                let uri = match reference.producer {
                    SouthboundProducer::Amf => amf_uri.clone(),
                    SouthboundProducer::Udm => udm_uri.clone(),
                };
                southbound_unsubscribe(uri, reference).await;
            }
            outcome => {
                // Still unreachable, or now failing outright. Either way the clock
                // that matters is how long the AF has held an un-notifiable
                // subscription, so both are treated the same by the deadline.
                if now.saturating_sub(leg.since) >= deadline {
                    log::warn!(
                        "expiring subscription {} after {}s with no southbound leg ({outcome:?})",
                        sub.id,
                        now.saturating_sub(leg.since)
                    );
                    // #2133: and the AF is told (cancelInd).
                    remove_and_tell_af(&sub.id);
                    report.expired += 1;
                } else {
                    log::debug!("southbound leg for {} still deferred ({outcome:?})", sub.id);
                    report.still_pending += 1;
                }
            }
        }
    }
    if report != ReconcileReport::default() {
        log::info!(
            "reconcile sweep: {} promoted, {} expired, {} still pending",
            report.promoted,
            report.expired,
            report.still_pending
        );
    }
    report
}

/// #2102: the lifetime asked for every southbound subscription, and granted
/// again by each refresh (`NEF_SOUTHBOUND_LIFETIME_SECS`, default one hour, at
/// least one minute). A subscription the NEF holds no record of -- its create
/// timed out after the producer took it, and neither TS 29.518 nor TS 29.503
/// gives the NEF a way to learn its id -- is never refreshed and lapses at the
/// producer within this.
///
/// #2128 (R42): at least four refresh ticks ([`reconcile_interval_secs`]), so
/// the margin below always leaves two ticks to refresh in.
fn southbound_lifetime_secs() -> u64 {
    let configured = std::env::var("NEF_SOUTHBOUND_LIFETIME_SECS")
        .ok()
        .and_then(|v| v.parse().ok());
    refresh_timing(configured, reconcile_interval_secs()).0
}

/// #2102: a live leg is refreshed once at most this much of its lifetime is
/// left: half of it, so several missed sweeps still refresh it in time. #2128
/// (R42): with the lifetime at least four ticks, that is at least two refresh
/// ticks ([`reconcile_interval_secs`]), so a refresh cannot first fall due a
/// second before the leg lapses.
fn southbound_refresh_margin_secs() -> u64 {
    southbound_lifetime_secs() / 2
}

/// #2128: (lifetime, refresh margin) for a configured lifetime (default one
/// hour, at least one minute) and a refresh tick of `interval` seconds: the
/// lifetime is at least four ticks, the margin half of it.
fn refresh_timing(configured: Option<u64>, interval: u64) -> (u64, u64) {
    let lifetime = configured
        .unwrap_or(3600)
        .max(60)
        .max(interval.saturating_mul(4));
    (lifetime, lifetime / 2)
}

/// #2128 (R42): at most this many producers are refreshed at once in a pass.
const REFRESH_MAX_PRODUCERS: usize = 8;

/// #2128 (R42): one producer's refreshes in a pass stop after this long (one
/// tick); the rest wait for the next pass.
fn refresh_pass_budget() -> Duration {
    Duration::from_secs(reconcile_interval_secs().max(1))
}

/// #2102: `body` asking for `expiry` (UNIX seconds): the AMF's
/// `subscription.options.expiry` (AmfEventMode, TS 29.518 §6.2.6.2.4; `trigger`
/// is mandatory there, CONTINUOUS when the body names none), the UDM's
/// `reportingOptions.expiry` (TS 29.503 §6.4.6.2.2 EeSubscription).
fn with_requested_expiry(
    producer: SouthboundProducer,
    body: &serde_json::Value,
    expiry: u64,
) -> serde_json::Value {
    let mut body = body.clone();
    let at = serde_json::json!(nextgcore_sbi::datetime::epoch_to_rfc3339(expiry));
    let holder = match producer {
        SouthboundProducer::Amf => body
            .get_mut("subscription")
            .and_then(serde_json::Value::as_object_mut)
            .map(|sub| {
                sub.entry("options")
                    .or_insert_with(|| serde_json::json!({ "trigger": "CONTINUOUS" }))
            }),
        SouthboundProducer::Udm => body.as_object_mut().map(|b| {
            b.entry("reportingOptions")
                .or_insert_with(|| serde_json::json!({}))
        }),
    };
    if let Some(options) = holder.and_then(serde_json::Value::as_object_mut) {
        options.insert("expiry".to_string(), at);
    }
    body
}

/// #2102: the expiry a producer's subscribe or modify answer confirms, if it
/// names one: AmfCreatedEventSubscription / AmfUpdatedEventSubscription
/// `subscription.options.expiry`, CreatedEeSubscription
/// `eeSubscription.reportingOptions.expiry` or a bare EeSubscription's.
fn confirmed_expiry(producer: SouthboundProducer, response: &SbiResponse) -> Option<u64> {
    let body: serde_json::Value = serde_json::from_str(response.http.content.as_deref()?).ok()?;
    let text = match producer {
        SouthboundProducer::Amf => body.pointer("/subscription/options/expiry"),
        SouthboundProducer::Udm => body
            .pointer("/eeSubscription/reportingOptions/expiry")
            .or_else(|| body.pointer("/reportingOptions/expiry")),
    };
    if let Some(text) = text {
        return nextgcore_sbi::datetime::rfc3339_to_epoch(text.as_str()?);
    }
    // #2149: a UDM modify answered 200 with a PatchResult (TS 29.571) reports a
    // shortened grant as the ReportItem for `/reportingOptions/expiry`, the
    // granted DateTime in its `reason` ("granted <DateTime>", nextgcore udmd).
    let item = body["report"]
        .as_array()?
        .iter()
        .find(|item| item["path"].as_str() == Some("/reportingOptions/expiry"))?;
    let granted = item["reason"].as_str()?.rsplit(' ').next()?;
    nextgcore_sbi::datetime::rfc3339_to_epoch(granted)
}

/// #2163 (R42 on #2158): whether a UDM's answer to the member-form refresh is
/// the refusal of the PATH itself, the one an older udmd gives: a 400 whose
/// ProblemDetails `invalidParams` names `/reportingOptions/expiry`, or whose
/// `detail` does (a udmd from before #2133 says the path "must address a
/// top-level EeSubscription member"). Any other 400 is a genuine refusal of the
/// refresh, so the whole-object form is not tried for it.
fn refuses_the_member_path(resp: &SbiResponse) -> bool {
    const PATH: &str = "/reportingOptions/expiry";
    if resp.status != 400 {
        return false;
    }
    let Some(problem) = resp
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
    else {
        return false;
    };
    let named_param = problem["invalidParams"]
        .as_array()
        .is_some_and(|params| params.iter().any(|p| p["param"].as_str() == Some(PATH)));
    let named_detail = problem["detail"].as_str().is_some_and(|d| d.contains(PATH));
    named_param || named_detail
}

/// #2102: the modification that moves a live leg's expiry to `expiry`: the
/// AMF's AmfUpdateEventOptionItem (TS 29.518 §6.2.6.2.7, `replace` of
/// `/options/expiry`), the UDM's PatchItem (TS 29.503 §5.5.2.4
/// UpdateEeSubscription).
///
/// #2133 (R42 on #2128): for the UDM, `add` of `/reportingOptions/expiry`
/// when the leg was made with `reportingOptions` (every leg that recorded an
/// expiry, `has_reporting_options`): RFC 6902 `add` on `/reportingOptions`
/// itself REPLACES the whole object, dropping every other member the UDM holds
/// (maxNumOfReports, reportMode, ...). A leg made before #2102 carries no
/// `reportingOptions`, so `/reportingOptions/expiry` has no parent to add to;
/// it gets the whole object, which replaces nothing.
fn refresh_patch(
    producer: SouthboundProducer,
    expiry: u64,
    has_reporting_options: bool,
) -> serde_json::Value {
    let at = nextgcore_sbi::datetime::epoch_to_rfc3339(expiry);
    match producer {
        SouthboundProducer::Amf => serde_json::json!([
            { "op": "replace", "path": "/options/expiry", "value": at }
        ]),
        SouthboundProducer::Udm if has_reporting_options => serde_json::json!([
            { "op": "add", "path": "/reportingOptions/expiry", "value": at }
        ]),
        SouthboundProducer::Udm => serde_json::json!([
            { "op": "add", "path": "/reportingOptions", "value": { "expiry": at } }
        ]),
    }
}

/// What one refresh sweep did (#2102).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RefreshReport {
    /// Legs the producer took a new expiry for.
    pub refreshed: usize,
    /// Subscriptions removed because their leg is gone: the producer answered
    /// 404, or the expiry passed before a refresh got through.
    pub lapsed: usize,
    /// Refreshes that failed and are tried again next sweep.
    pub failed: usize,
    /// #2128: due legs not tried this pass, because their producer had already
    /// failed one in it or the pass budget ran out; tried next pass.
    pub skipped: usize,
}

impl RefreshReport {
    fn add(&mut self, other: RefreshReport) {
        self.refreshed += other.refreshed;
        self.lapsed += other.lapsed;
        self.failed += other.failed;
        self.skipped += other.skipped;
    }
}

/// #2102: [`refresh_live_subscriptions_with`] with the clock stopped at `now`
/// (UNIX seconds).
pub async fn refresh_live_subscriptions_at(now: u64) -> RefreshReport {
    refresh_live_subscriptions_with(Arc::new(move || now)).await
}

/// #2128 (R42): remove `sub_id`, whose leg `southbound` lapsed, owing its DELETE
/// first (#2086): the snapshot that drops the subscription carries the owed
/// unsubscribe, so a restart in between still sends it.
fn remove_lapsed_leg(sub_id: &str, southbound: &SouthboundRef) {
    southbound_reconcile::owe(southbound.clone());
    remove_and_tell_af(sub_id);
}

/// #2133 (R42 on #2128): remove `sub_id` on the NEF's own initiative (its leg
/// lapsed, or was never established in time) and tell the AF, which would
/// otherwise wait for notifications that can no longer come. TS 29.122
/// MonitoringNotification `cancelInd` (reused by TS 29.522's MonitoringEvent
/// API) is the defined indication: a notification naming the subscription with
/// `cancelInd: true` and no reports. Best effort, on its own task, like every
/// AF notification: the removal does not wait for it. An AF-requested DELETE
/// is not notified (the AF asked).
fn remove_and_tell_af(sub_id: &str) {
    let removed = nef_self()
        .read()
        .ok()
        .and_then(|c| c.subscription_remove(sub_id));
    let Some(sub) = removed else {
        return;
    };
    // #2154: TS 29.591 defines no cancellation indication for a
    // Nnef_EventExposure subscriber (NefEventExposureNotif carries notifId and
    // eventNotifs only), so none is invented: the ceiling is in nef.md.
    if sub.northbound_api == NorthboundApi::NnefEventExposure {
        log::info!(
            "Nnef_EventExposure subscription {} removed; TS 29.591 has no cancellation \
             indication to send its consumer",
            sub.id
        );
        return;
    }
    let notification = cancellation_notification(&sub);
    if tokio::runtime::Handle::try_current().is_err() {
        log::warn!(
            "monitoring subscription {}: removed, but no runtime to tell the AF on",
            sub.id
        );
        return;
    }
    let (id, destination) = (sub.id.clone(), sub.notification_destination.clone());
    drop(spawn_detached(async move {
        forward_notification_to_af(&id, destination, notification).await;
    }));
}

/// #2133: the MonitoringNotification that tells the AF its subscription is
/// cancelled (TS 29.122 `cancelInd`; `subscription` is the only mandatory
/// member).
fn cancellation_notification(sub: &NefMonitoringSubscription) -> serde_json::Value {
    serde_json::json!({
        "subscription": format!(
            "/3gpp-monitoring-event/v1/{}/subscriptions/{}",
            sub.scs_as_id, sub.id
        ),
        "cancelInd": true,
    })
}

/// #2102: refresh every live southbound leg within
/// [`southbound_refresh_margin_secs`] of its expiry, reading `clock` (UNIX
/// seconds) afresh for each leg.
///
/// - A leg made before #2102 (no expiry recorded) is refreshed at once, which
///   bounds it.
/// - The producer taking the modification (2xx) records the expiry it confirms,
///   else the one asked for.
/// - A 404 means the producer no longer holds it, and a leg whose expiry has
///   passed is gone at a producer that honours expiry. Either way the
///   northbound subscription can never notify again and is removed, as an
///   expired pending leg is (#111). A passed one is also unsubscribed, in case
///   the producer ignored the expiry.
/// - Any other failure is retried next sweep.
///
/// #2128 (R42), the #1994 shape: legs are refreshed per producer, up to
/// [`REFRESH_MAX_PRODUCERS`] producers at once, each in expiry order. A producer
/// that fails a refresh (no answer, or a 5xx) is not tried again in this pass,
/// and one producer's refreshes stop after [`refresh_pass_budget`]. So a
/// blackholed producer costs one request timeout per pass, and other
/// producers' legs are refreshed regardless.
///
/// Only subscriptions this NEF holds are refreshed, so an orphan lapses.
pub async fn refresh_live_subscriptions_with(
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> RefreshReport {
    let live = match nef_self().read() {
        Ok(c) => c.subscriptions_live(),
        Err(_) => return RefreshReport::default(),
    };
    let mut report = RefreshReport::default();
    let mut by_producer: std::collections::BTreeMap<String, Vec<NefMonitoringSubscription>> =
        std::collections::BTreeMap::new();
    for sub in live {
        let Some(southbound) = sub.southbound.as_ref() else {
            continue;
        };
        match southbound
            .producer_base
            .clone()
            .or_else(|| producer_uri(southbound.producer))
        {
            Some(base) => by_producer.entry(base).or_default().push(sub),
            None => {
                log::warn!(
                    "monitoring subscription {}: no {} URI to refresh its leg at",
                    sub.id,
                    southbound.producer.as_str()
                );
                report.failed += 1;
            }
        }
    }
    let slots = Arc::new(tokio::sync::Semaphore::new(REFRESH_MAX_PRODUCERS));
    let mut workers = Vec::new();
    for (base, legs) in by_producer {
        let (slots, clock) = (slots.clone(), clock.clone());
        workers.push(spawn_detached(async move {
            let _slot = slots.acquire_owned().await;
            refresh_producer_legs(base, legs, clock).await
        }));
    }
    for worker in workers {
        match worker.await {
            Ok(r) => report.add(r),
            Err(e) => log::error!("a refresh worker failed: {e}"),
        }
    }
    if report != RefreshReport::default() {
        log::info!(
            "refresh sweep: {} refreshed, {} lapsed, {} failed, {} skipped",
            report.refreshed,
            report.lapsed,
            report.failed,
            report.skipped
        );
    }
    report
}

/// #2128: one producer's part of a refresh pass (see
/// [`refresh_live_subscriptions_with`]).
async fn refresh_producer_legs(
    base: String,
    legs: Vec<NefMonitoringSubscription>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> RefreshReport {
    let margin = southbound_refresh_margin_secs();
    let started = std::time::Instant::now();
    let budget = refresh_pass_budget();
    let mut producer_failed = false;
    let mut report = RefreshReport::default();
    // #2148: the DELETEs this pass owes for lapsed legs, sent below by this
    // worker (so at most REFRESH_MAX_PRODUCERS at once), not one task each.
    let mut lapsed = Vec::new();
    for sub in legs {
        let Some(southbound) = sub.southbound.clone() else {
            continue;
        };
        let now = clock();
        if sub
            .southbound_expiry
            .is_some_and(|e| e > now.saturating_add(margin))
        {
            continue;
        }
        let gone = |why: &str| {
            log::warn!(
                "monitoring subscription {}: its {} leg {why}; removing it",
                sub.id,
                southbound.producer.as_str()
            );
        };
        if sub.southbound_expiry.is_some_and(|e| e <= now) {
            gone("expired before a refresh got through");
            remove_lapsed_leg(&sub.id, &southbound);
            lapsed.push(southbound);
            report.lapsed += 1;
            continue;
        }
        if producer_failed || started.elapsed() >= budget {
            report.skipped += 1;
            continue;
        }
        let Some((host, port)) = parse_host_port(&base) else {
            log::warn!(
                "monitoring subscription {}: invalid {} URI {base:?} to refresh its leg at",
                sub.id,
                southbound.producer.as_str()
            );
            report.failed += 1;
            continue;
        };
        let requested = now.saturating_add(southbound_lifetime_secs());
        let client = service_client(&host, port, southbound.producer.nf_type());
        // #2133: a leg that recorded an expiry was made with reportingOptions.
        let patch = refresh_patch(
            southbound.producer,
            requested,
            sub.southbound_expiry.is_some(),
        );
        let mut answer = client.patch_json(&southbound.delete_path, &patch).await;
        // #2154 (R42 on #2152): a UDM from before #2133 accepts only top-level
        // patch paths and answers the member form 400. Fall back, once, to the
        // whole-object form it does accept, so its legs are refreshed rather than
        // left to lapse during a rolling upgrade (nef.md: upgrade udmd first).
        if southbound.producer == SouthboundProducer::Udm
            && sub.southbound_expiry.is_some()
            && matches!(&answer, Ok(resp) if refuses_the_member_path(resp))
        {
            log::warn!(
                "monitoring subscription {}: the UDM refused `add /reportingOptions/expiry` \
                 (400; a udmd older than #2133?); retrying with the whole reportingOptions",
                sub.id
            );
            let whole = refresh_patch(southbound.producer, requested, false);
            answer = client.patch_json(&southbound.delete_path, &whole).await;
        }
        match answer {
            Ok(resp) if resp.is_success() => {
                let expiry = confirmed_expiry(southbound.producer, &resp).unwrap_or(requested);
                let recorded = nef_self()
                    .read()
                    .map(|c| c.subscription_refreshed(&sub.id, &southbound, expiry))
                    .unwrap_or(false);
                if recorded {
                    report.refreshed += 1;
                }
            }
            Ok(resp) if resp.status == 404 => {
                gone("is gone at the producer (404 on refresh)");
                // #2133: and the AF is told (cancelInd).
                remove_and_tell_af(&sub.id);
                report.lapsed += 1;
            }
            Ok(resp) => {
                log::warn!(
                    "monitoring subscription {}: {} refresh returned {}",
                    sub.id,
                    southbound.producer.as_str(),
                    resp.status
                );
                // A 5xx is the producer failing; a 4xx is this one leg.
                producer_failed |= resp.status >= 500;
                report.failed += 1;
            }
            Err(e) => {
                log::warn!(
                    "monitoring subscription {}: {} refresh failed: {e}; its other legs \
                     wait for the next pass",
                    sub.id,
                    southbound.producer.as_str()
                );
                producer_failed = true;
                report.failed += 1;
            }
        }
    }
    // #2148: the lapsed legs' DELETEs, owed (and persisted) already by
    // `remove_lapsed_leg`. Sent one at a time, after the refreshes, and not
    // once this producer has failed or the budget is spent: whatever is not
    // sent stays owed, and the #1877 reconciler sends it with its backoff.
    for southbound in lapsed {
        if producer_failed || started.elapsed() >= budget {
            break;
        }
        southbound_unsubscribe(Some(base.clone()), southbound.clone()).await;
        if southbound_reconcile::is_owed(&southbound) {
            producer_failed = true;
        }
    }
    report
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
/// udmd serves the operation (#85) from the UDR's `identity-data`, keyed by the
/// GPSI. An `extid-` GPSI resolves once the subscriber record carries the
/// External Identifier (`extid`, nextgsim#480), which is what lets a T8 request
/// name the UE by the `externalId` UE ID retrieval handed the AF.
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
    let client = service_client(&host, port, nextgcore_sbi::types::NfType::Udm);
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
/// What happened to a southbound subscribe attempt (issue #111).
///
/// This replaced an `Option<SouthboundRef>` whose `None` meant FOUR different
/// things -- no producer configured, an unparseable URI, a producer that rejected
/// the subscribe, and a transport error -- all of which the caller turned into the
/// same `201 Created`. The AF was told it held a live subscription that could
/// never notify, with no error to drive a retry, which is the failure-masking half
/// of #111.
#[derive(Debug)]
enum SouthboundOutcome {
    /// The producer accepted and gave a usable reference, and the UNIX second
    /// the subscription lapses at unless refreshed (#2102).
    Live(SouthboundRef, u64),
    /// No producer URI is configured, so the leg has not been ATTEMPTED yet. The
    /// northbound create is accepted and the leg is retried by the reconciler --
    /// distinguished from a failure because a deployment that has not wired its
    /// AMF/UDM yet is a configuration state, not a request error.
    Deferred,
    /// The leg was attempted and cannot be established. `retryable` separates a
    /// transport problem (the producer may come back) from a protocol one (it
    /// answered, unusably), which is what picks the northbound status.
    Failed { retryable: bool, detail: String },
}

impl SouthboundOutcome {
    /// The northbound response for a failed leg (TS 29.500 §5.2.7).
    ///
    /// A retryable failure is the NEF's dependency being unavailable, so `503`; a
    /// non-retryable one is the producer answering in a way the NEF cannot use, so
    /// `500`. Both are statuses §5.2.7 lists; neither is `201`, which is the whole
    /// point.
    fn failure_response(retryable: bool, detail: &str) -> SbiResponse {
        if retryable {
            send_error(
                503,
                "Service Unavailable",
                &format!("southbound subscription could not be established: {detail}"),
                Some("SUBSCRIPTION_NOT_ESTABLISHED"),
            )
        } else {
            send_error(
                500,
                "Internal Server Error",
                &format!("southbound subscription could not be established: {detail}"),
                Some("SUBSCRIPTION_NOT_ESTABLISHED"),
            )
        }
    }
}

async fn attempt_southbound_subscribe(
    producer_uri: Option<String>,
    req: &SouthboundSubscribe,
) -> SouthboundOutcome {
    let producer = req.producer;
    let Some(uri) = producer_uri else {
        log::info!(
            "no {} URI configured; southbound subscription deferred for retry",
            producer.as_str()
        );
        return SouthboundOutcome::Deferred;
    };
    let Some((host, port)) = parse_host_port(&uri) else {
        // A configured-but-unparseable URI is an operator error, not a transient
        // one: retrying cannot fix it, and deferring would hide it behind an
        // accepted subscription.
        log::warn!(
            "invalid {} URI '{uri}'; southbound subscription cannot be established",
            producer.as_str()
        );
        return SouthboundOutcome::Failed {
            retryable: false,
            detail: format!("invalid {} URI '{uri}'", producer.as_str()),
        };
    };
    let client = service_client(&host, port, producer.nf_type());
    // #2102: every subscription asks for an expiry, stamped at send time (a
    // deferred leg's body is built long before), so one this NEF never learns
    // of -- the create timed out after the producer took it -- lapses on its own.
    let requested = now_unix_secs().saturating_add(southbound_lifetime_secs());
    let body = with_requested_expiry(producer, &req.body, requested);
    match client.post_json(&req.path, &body).await {
        Ok(response) if response.status == 200 || response.status == 201 => {
            match extract_southbound_ref(producer, &req.path, &response) {
                // #1877 (R27): remember where it was made.
                Some(southbound) => SouthboundOutcome::Live(
                    SouthboundRef {
                        producer_base: Some(uri.clone()),
                        ..southbound
                    },
                    confirmed_expiry(producer, &response).unwrap_or(requested),
                ),
                None => {
                    // The producer created something and did not say what. The NEF
                    // cannot unsubscribe it later, so accepting the northbound
                    // create would orphan a producer-side subscription AND leave
                    // the AF unable to delete it.
                    log::warn!(
                        "{} subscribe succeeded but no subscription id could be extracted",
                        producer.as_str()
                    );
                    SouthboundOutcome::Failed {
                        retryable: false,
                        detail: format!(
                            "{} accepted the subscribe but returned no subscription id",
                            producer.as_str()
                        ),
                    }
                }
            }
        }
        Ok(response) => {
            log::warn!(
                "{} subscribe returned status {}",
                producer.as_str(),
                response.status
            );
            SouthboundOutcome::Failed {
                retryable: false,
                detail: format!("{} returned status {}", producer.as_str(), response.status),
            }
        }
        Err(e) => {
            log::warn!("{} subscribe failed: {e}", producer.as_str());
            SouthboundOutcome::Failed {
                retryable: true,
                detail: format!("{} unreachable: {e}", producer.as_str()),
            }
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
            producer_base: None,
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
        producer_base: None,
    })
}

/// Best-effort DELETE of the southbound producer subscription.
/// #1877: the producer URI configured now for `producer`.
pub(crate) fn producer_uri(producer: SouthboundProducer) -> Option<String> {
    let ctx = nef_self();
    let c = ctx.read().ok()?;
    match producer {
        SouthboundProducer::Amf => c.amf_uri(),
        SouthboundProducer::Udm => c.udm_uri(),
    }
}

/// Best-effort DELETE of the southbound producer subscription; one that fails is
/// parked for [`southbound_reconcile`] and retried until the producer takes it
/// (#1877). It used to be tried once and only logged.
///
/// #2086: the DELETE is owed (and persisted) before it is sent, and settled once
/// delivered, so a restart in between still sends it.
async fn southbound_unsubscribe(producer_uri: Option<String>, southbound: SouthboundRef) {
    if southbound_reconcile::owe(southbound.clone()) {
        if let Ok(c) = nef_self().read() {
            c.persist_now();
        }
    }
    if try_southbound_unsubscribe(producer_uri, &southbound).await {
        southbound_reconcile::settle(&southbound);
    } else {
        southbound_reconcile::park(southbound);
    }
}

/// One DELETE of the southbound producer subscription: whether the producer
/// answered 2xx, or 404 (it does not hold the subscription, the state wanted).
pub(crate) async fn try_southbound_unsubscribe(
    producer_uri: Option<String>,
    southbound: &SouthboundRef,
) -> bool {
    let producer = southbound.producer;
    // #1877 (R27): the producer it was made at, else the one configured now.
    let Some(uri) = southbound.producer_base.clone().or(producer_uri) else {
        log::debug!(
            "no {} URI configured; southbound unsubscribe not sent",
            producer.as_str()
        );
        return false;
    };
    let Some((host, port)) = parse_host_port(&uri) else {
        log::warn!(
            "invalid {} URI '{uri}'; southbound unsubscribe not sent",
            producer.as_str()
        );
        return false;
    };
    let client = service_client(&host, port, producer.nf_type());
    match client.delete(&southbound.delete_path).await {
        Ok(response) if response.is_success() || response.status == 404 => {
            log::debug!(
                "{} subscription {} removed (status {})",
                producer.as_str(),
                southbound.subscription_id,
                response.status
            );
            true
        }
        Ok(response) => {
            log::warn!(
                "{} unsubscribe returned status {}",
                producer.as_str(),
                response.status
            );
            false
        }
        Err(e) => {
            log::warn!("{} unsubscribe failed: {e}", producer.as_str());
            false
        }
    }
}

/// Producer reports the NEF received but did not forward (issue #1439), by why.
///
/// `mismatched_type`: the report names an event of a different MonitoringType than
/// the subscription it arrived on. `unrecognised_type`: the report names no event
/// type this NEF maps onto a TS 29.122 MonitoringType, or none at all (both
/// `AmfEventReport.type` and `MonitoringReport.eventType` are mandatory).
/// `not_reachable`: an AMF reachability report whose state is not REACHABLE
/// (UNREACHABLE, REGULATORY_ONLY or absent), which is no UE_REACHABILITY event
/// (issue #1443). nefd
/// serves `/metrics` only in a `demo-d445a-fl-t8` build with that demo on
/// (nextgsim#480); otherwise this is read in-process (tests). Every drop is also
/// logged.
pub static DROPPED_PRODUCER_REPORTS: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "nef_producer_reports_dropped_total",
        "Producer event reports not forwarded to the AF, by reason",
        &["reason"],
    );

/// The TS 29.122 MonitoringType a producer report is ABOUT, read from the report's
/// own event type (issue #1439), with the reachability type when it has one.
///
/// - Namf_EventExposure `AmfEventReport.type` (TS 29.518 §6.2.6.2.5, mandatory):
///   `LOCATION_REPORT`, `REACHABILITY_REPORT`, `LOSS_OF_CONNECTIVITY`.
/// - Nudm_EE `MonitoringReport.eventType` (TS 29.503 §6.4.6.2.4, mandatory):
///   `LOCATION_REPORTING`, `UE_REACHABILITY_FOR_DATA`, `UE_REACHABILITY_FOR_SMS`,
///   `LOSS_OF_CONNECTIVITY`, `PDN_CONNECTIVITY_STATUS`.
///
/// `None` for anything else, including a report with no type: the NEF reports the
/// event that occurred and must not guess one.
fn report_monitoring_type(
    report: &serde_json::Value,
) -> Option<(&'static str, Option<&'static str>)> {
    let reported = report
        .get("type")
        .or_else(|| report.get("eventType"))
        .and_then(|v| v.as_str())?;
    match reported {
        "LOCATION_REPORT" | "LOCATION_REPORTING" => Some(("LOCATION_REPORTING", None)),
        "REACHABILITY_REPORT" => {
            // AMF `reachability` (TS 29.518 UeReachability): REACHABLE,
            // UNREACHABLE or REGULATORY_ONLY. Only REACHABLE is reachable for
            // downlink data; the other two come back with no reachability type
            // and are not forwarded (#1443).
            let data = report.get("reachability").and_then(|v| v.as_str()) == Some("REACHABLE");
            Some(("UE_REACHABILITY", data.then_some("DATA")))
        }
        "UE_REACHABILITY_FOR_DATA" => Some(("UE_REACHABILITY", Some("DATA"))),
        "UE_REACHABILITY_FOR_SMS" => Some(("UE_REACHABILITY", Some("SMS"))),
        "LOSS_OF_CONNECTIVITY" => Some(("LOSS_OF_CONNECTIVITY", None)),
        // A TS 29.122 MonitoringType this NEF does not accept a subscription for,
        // but udmd reports it, so it is named (and dropped as mismatched) rather
        // than unrecognised.
        "PDN_CONNECTIVITY_STATUS" => Some(("PDN_CONNECTIVITY_STATUS", None)),
        _ => None,
    }
}

/// The T8 `lossOfConnectReason` (TS 29.122 §5.3.2.3.2, an integer) for a
/// TS 29.518 §6.2.6.3.12 `LossOfConnectivityReason`, as TS 29.522 §4.4.2 mandates
/// for 5GS: 6 if the UE is deregistered, 7 if the maximum detection timer
/// expired, 8 if the UE is purged. Values 0-5 are the pre-5G TS 29.336 §8.4.58
/// MME/SGSN codes and are not applicable here (issue #1444).
///
/// `None` for anything else, `UNAVAILABLE_PERIOD` included: its code 9 is only
/// for an AF that negotiated `Loss_of_connectivity_notification_5G`, which this
/// NEF does not offer (it carries no `unavailPerDur` either). Forwarding the
/// TS 29.518 string used to put a string in an integer member, which a strict
/// AF rejects along with the whole notification.
fn t8_loss_of_connect_reason(reason: &serde_json::Value) -> Option<u8> {
    match reason.as_str()? {
        "DEREGISTERED" => Some(6),
        "MAX_DETECTION_TIME_EXPIRED" => Some(7),
        "PURGED" => Some(8),
        _ => None,
    }
}

/// Build the TS 29.122 §5.3 MonitoringNotification forwarded to the AF's
/// notificationDestination from a producer notification body (AMF
/// `AmfEventNotification.reportList` or UDM Nudm_EE `reportList`).
///
/// # Each report keeps the event it reports (issue #1439)
///
/// Every report is labelled with the MonitoringType of ITS OWN producer event type
/// ([`report_monitoring_type`]), never with the subscription's. A report whose type
/// differs from what the subscription monitors, or that names no type this NEF
/// knows, is dropped and counted in [`DROPPED_PRODUCER_REPORTS`]. When nothing is
/// left the result is `None` and the AF is sent nothing: this used to stamp the
/// subscribed type on every report and to synthesise one bare report from an empty
/// body, so an AF watching for `LOSS_OF_CONNECTIVITY` was told "loss of
/// connectivity" when the UE re-registered.
///
/// `lossOfConnectReason` is carried through for a `LOSS_OF_CONNECTIVITY` report,
/// read top level in an AMF report and inside `report` (TS 29.503
/// `LossConnectivityReport`) in a UDM one, and sent as its TS 29.522 §4.4.2
/// integer code ([`t8_loss_of_connect_reason`]).
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
) -> Option<serde_json::Value> {
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
    // #2154: each forwarded report's producer timestamp, for the TS 29.591 shape.
    let mut times = Vec::new();
    let report_list = producer_body
        .get("reportList")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    for report in report_list {
        let reported = report
            .get("type")
            .or_else(|| report.get("eventType"))
            .and_then(|v| v.as_str())
            .unwrap_or("<none>");
        let Some((monitoring_type, reachability_type)) = report_monitoring_type(report) else {
            DROPPED_PRODUCER_REPORTS.inc(&["unrecognised_type"]);
            log::info!(
                "subscription {}: producer report of type {reported} has no TS 29.122 \
                 MonitoringType; not forwarded",
                sub.id
            );
            continue;
        };
        if monitoring_type != sub.monitoring_type {
            DROPPED_PRODUCER_REPORTS.inc(&["mismatched_type"]);
            log::info!(
                "subscription {} monitors {}: producer report of type {reported} \
                 ({monitoring_type}) not forwarded",
                sub.id,
                sub.monitoring_type
            );
            continue;
        }
        // TS 29.122 UE_REACHABILITY is "notified when the UE becomes reachable"
        // (§5.3.2.4.3) and its report "shall" carry reachabilityType
        // (§5.3.2.3.2). An AMF report of UNREACHABLE or REGULATORY_ONLY (reachable
        // only for regulatory prioritised service, TS 29.518 §6.2.6.3.7) is
        // neither, so it is dropped: forwarding it used to tell the AF the UE was
        // reachable, with no reachabilityType (#1443).
        if monitoring_type == "UE_REACHABILITY" && reachability_type.is_none() {
            DROPPED_PRODUCER_REPORTS.inc(&["not_reachable"]);
            log::info!(
                "subscription {}: producer report of type {reported} (reachability {}) \
                 is not a UE becoming reachable; not forwarded",
                sub.id,
                report
                    .get("reachability")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<none>")
            );
            continue;
        }
        let mut out = serde_json::json!({ "monitoringType": monitoring_type });
        if let Some(location) = report.get("location") {
            out["locationInfo"] = location.clone();
        }
        if let Some(reachability_type) = reachability_type {
            out["reachabilityType"] = serde_json::json!(reachability_type);
        }
        if monitoring_type == "LOSS_OF_CONNECTIVITY" {
            let reported_reason = report
                .get("lossOfConnectReason")
                .or_else(|| report.pointer("/report/lossOfConnectReason"));
            if let Some(reason) = reported_reason {
                match t8_loss_of_connect_reason(reason) {
                    Some(code) => out["lossOfConnectReason"] = serde_json::json!(code),
                    // "shall be included if available" (TS 29.122 §5.3.2.3.2): a
                    // reason with no T8 code is not available, and the report is
                    // still the loss of connectivity it is.
                    None => log::debug!(
                        "subscription {}: lossOfConnectReason {reason} has no TS 29.522 \
                         §4.4.2 code; omitted",
                        sub.id
                    ),
                }
            }
        }
        // `report["supi"]` is deliberately NOT read. The producer sends the
        // internal identity; forwarding it is the leak this function exists
        // to prevent. Do not "restore" this for debugging convenience --
        // `af_bound_notification_never_contains_supi` fails if you do.
        if let Some((member, value)) = &af_identity {
            out[*member] = value.clone();
        }
        reports.push(out);
        times.push(
            report
                .get("timeStamp")
                .and_then(|t| t.as_str())
                .map(str::to_string),
        );
    }
    if reports.is_empty() {
        return None;
    }
    if sub.northbound_api == NorthboundApi::NnefEventExposure {
        return Some(nnef_event_exposure_notif(sub, &times));
    }
    Some(serde_json::json!({
        "subscription": self_link,
        "monitoringEventReports": reports,
    }))
}

/// #2154 (R42 on #2152): the TS 29.591 `NefEventExposureNotif` for a
/// Nnef_EventExposure subscriber: `notifId` (the consumer's, stored as the
/// subscription's `scs_as_id`) and one `NefEventNotification` per forwarded
/// report, each its `event` and `timeStamp` (both mandatory). The `event` is
/// the eventId the consumer subscribed to, the T8 MonitoringType mapped back
/// ([`NNEF_EVENT_TO_MONITORING_TYPE`]); `NefEvent` admits it through its
/// free-form string branch.
///
/// Ceiling, documented in nef.md: TS 29.591 defines no member for a location,
/// a reachability or a loss-of-connectivity report, so the notification says
/// which event occurred and when, and nothing more. The T8 API carries the
/// report itself.
fn nnef_event_exposure_notif(
    sub: &NefMonitoringSubscription,
    times: &[Option<String>],
) -> serde_json::Value {
    let event = NNEF_EVENT_TO_MONITORING_TYPE
        .iter()
        .find(|(_, t8)| *t8 == sub.monitoring_type)
        .map(|(id, _)| *id)
        .unwrap_or(sub.monitoring_type.as_str());
    let now = nextgcore_sbi::datetime::epoch_to_rfc3339(now_unix_secs());
    let notifs: Vec<serde_json::Value> = times
        .iter()
        .map(|t| {
            serde_json::json!({
                "event": event,
                "timeStamp": t.clone().unwrap_or_else(|| now.clone()),
            })
        })
        .collect();
    serde_json::json!({ "notifId": sub.scs_as_id, "eventNotifs": notifs })
}

/// POST a MonitoringNotification to the AF's notificationDestination
/// (best-effort, bounded timeouts; failures are logged, no retry).
async fn forward_notification_to_af(
    sub_id: &str,
    destination: String,
    notification: serde_json::Value,
) {
    let Some((host, port, path)) = parse_http_uri(&destination) else {
        log::warn!(
            "invalid notificationDestination '{destination}'; notification dropped",
            destination = nextgcore_sbi::log_redact::redact_last_segment(&destination)
        );
        return;
    };
    let client = bounded_client(&host, port);
    match client.post_json(&path, &notification).await {
        Ok(response) if response.is_success() => {
            // nextgsim#480: the nefd step of the demo's ordered amfd -> nefd -> AF
            // chain, at info while the demo is on. Debug otherwise, as before.
            #[cfg(feature = "demo-d445a-fl-t8")]
            if ueid::serving() {
                nextgcore_demo::demo_log!(
                    info,
                    ueid::DEMO_KEY,
                    "T8 delivery sub={sub_id} {} status={} to {destination}",
                    delivered_reports_summary(&notification),
                    response.status,
                    destination = nextgcore_sbi::log_redact::redact_last_segment(&destination)
                );
                return;
            }
            log::debug!(
                "monitoring notification {sub_id} delivered to {destination}",
                destination = nextgcore_sbi::log_redact::redact_last_segment(&destination)
            );
        }
        Ok(response) => {
            log::warn!(
                "monitoring notification to {destination} returned {}",
                response.status,
                destination = nextgcore_sbi::log_redact::redact_last_segment(&destination)
            );
        }
        Err(e) => {
            log::warn!(
                "monitoring notification to {destination} failed: {e}",
                destination = nextgcore_sbi::log_redact::redact_last_segment(&destination)
            );
        }
    }
}

/// `monitoringType=… lossOfConnectReason=…` of each report in a delivered
/// MonitoringNotification, for the demo's delivery line (nextgsim#480).
#[cfg(feature = "demo-d445a-fl-t8")]
fn delivered_reports_summary(notification: &serde_json::Value) -> String {
    let reports = notification
        .get("monitoringEventReports")
        .and_then(|r| r.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    reports
        .iter()
        .map(|r| {
            let field = |k: &str| match r.get(k) {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Null) | None => "-".to_string(),
                Some(other) => other.to_string(),
            };
            format!(
                "monitoringType={} lossOfConnectReason={}",
                field("monitoringType"),
                field("lossOfConnectReason")
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The NF config file's YAML root, or `Null` when the file does not exist (the
/// nwdafd pattern). An unreadable or invalid file fails startup: its `demo:`
/// block cannot be checked.
fn config_root(config_path: &str) -> Result<serde_yaml::Value, String> {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yaml::from_str(&content)
            .map_err(|e| format!("{config_path} is not valid YAML: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_yaml::Value::Null),
        Err(e) => Err(format!("cannot read {config_path}: {e}")),
    }
}

/// The demos this build can run: `d445a-fl-t8` under its cargo feature, none
/// otherwise.
fn demo_registry() -> nextgcore_demo::DemoRegistry {
    #[allow(unused_mut)]
    let mut specs: Vec<nextgcore_demo::DemoSpec> = Vec::new();
    #[cfg(feature = "demo-d445a-fl-t8")]
    specs.push(ueid::DEMO_SPEC);
    nextgcore_demo::DemoRegistry::new(&specs)
}

/// The `/metrics` body of a build with a demo: the families every NF shares
/// (including `nextg_demo_enabled` while a demo is active), the dropped
/// producer reports, and the UE ID outcomes.
#[cfg(feature = "demo-d445a-fl-t8")]
fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "nef",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    DROPPED_PRODUCER_REPORTS.render(&mut out);
    southbound_reconcile::render(&mut out);
    ueid::render_metrics(&mut out);
    out
}

/// Build an SBI client with bounded connect/request timeouts (amfd
/// notification-client parity).
fn bounded_client(host: &str, port: u16) -> SbiClient {
    let config = nextgcore_sbi::security::sbi_peer_client_config(host, port)
        .with_connect_timeout(Duration::from_secs(SOUTHBOUND_CONNECT_TIMEOUT_SECS))
        .with_request_timeout(Duration::from_secs(SOUTHBOUND_REQUEST_TIMEOUT_SECS));
    SbiClient::new(config)
}

/// [`bounded_client`] for a southbound **service request** to the `target`
/// producer (#1661): it carries the NRF-issued token when an outbound OAuth2
/// client is installed (TS 33.501 §13.4.1.1.2, TS 29.500 §6.7.3). Notifications
/// to an AF use [`bounded_client`] itself: they carry no token.
fn service_client(host: &str, port: u16, target: nextgcore_sbi::types::NfType) -> SbiClient {
    let client = bounded_client(host, port);
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
    }
}

impl context::SouthboundProducer {
    /// The producer's NF type, the audience of its access token.
    fn nf_type(self) -> nextgcore_sbi::types::NfType {
        match self {
            Self::Amf => nextgcore_sbi::types::NfType::Amf,
            Self::Udm => nextgcore_sbi::types::NfType::Udm,
        }
    }
}

/// Build the NFProfile registered with the NRF (TS 29.510): nfType NEF
/// advertising the nnef-eventexposure service (TS 29.591).
/// #1322: the base of every notification callback the NEF hands the AMF and UDM:
/// `--notify-base` (refused when it names no host or a wildcard one), else
/// `http://<advertised host>:<port>`. `Err` when there is nothing reachable to
/// advertise: the NEF must not start, since every southbound subscribe needs it.
fn nef_notify_base(
    notify_base: Option<&str>,
    sbi: &nextgcore_core::sockaddr::SbiEndpoint,
) -> Result<String, String> {
    if let Some(base) = notify_base {
        let base = base.trim().trim_end_matches('/');
        return match nextgcore_core::sockaddr::advertised_uri_host(base) {
            Some(_) => Ok(base.to_string()),
            None => Err(format!(
                "refusing to start: --notify-base '{base}' names no reachable host"
            )),
        };
    }
    let host = sbi
        .registration_host()
        .map_err(|why| format!("refusing to start: {why}, or --notify-base"))?;
    Ok(format!(
        "http://{}",
        nextgcore_sbi::uri_encode::uri_authority(host, sbi.port)
    ))
}

fn build_nf_profile(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    scheme: nextgcore_sbi::types::UriScheme,
) -> serde_json::Value {
    #[allow(unused_mut)]
    let mut profile = serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "NEF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": [
                {
                    "serviceInstanceId": format!("{nf_instance_id}-nnef-eventexposure"),
                    "serviceName": "nnef-eventexposure",
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": scheme.as_str(),
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
                }
            ],
            // #2141 (R41): and the UCMF, which types a NEF caller by
            // discovering it (the shared sbi verified-NF-type rule); nrfd hides a
            // profile from a requester this list leaves out.
            "allowedNfTypes": ["AF", "AMF", "UDM", "SCP", "UCMF"],
            "heartBeatTimer": 10
    });
    // nextgsim#480: offer nnef-ueid to AF consumers only, so the NRF mints that
    // scope for nothing else.
    #[cfg(feature = "demo-d445a-fl-t8")]
    if ueid::serving() {
        if let Some(services) = profile["nfServices"].as_array_mut() {
            services.push(ueid::nf_service(nf_instance_id, sbi_addr, sbi_port, scheme));
        }
    }
    nextgcore_sbi::nf_addressing::classify_profile_host(profile, sbi_addr)
}

/// Register NEF with NRF (PUT /nnrf-nfm/v1/nf-instances/{id}, nwdafd
/// pattern). Missing NRF URI skips registration; failure is reported to the
/// caller, which treats it as non-fatal.
async fn register_with_nrf(
    sbi_ctx: Arc<SbiContext>,
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
    sbi_scheme: nextgcore_sbi::types::UriScheme,
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

    let nf_profile = build_nf_profile(nf_instance_id, sbi_addr, sbi_port, sbi_scheme);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("NEF registered with NRF successfully (id={nf_instance_id})");
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&nf_profile);

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Nef,
            );
            nextgcore_sbi::nf_addressing::set_instance_host(&mut self_instance, sbi_addr);
            let mut svc = nextgcore_sbi::context::NfService::new(
                "nnef-eventexposure",
                nextgcore_sbi::types::SbiServiceType::NnefEventexposure,
            );
            svc.port = sbi_port;
            nextgcore_sbi::nf_addressing::set_service_host(&mut svc, sbi_addr);
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

    /// Serializes the tests that touch the process-global NEF context so
    /// they cannot race. The lock itself lives beside the global
    /// (`context::NEF_CONTEXT_TEST_LOCK`) so every test module shares it.
    fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
        crate::context::lock_nef_context_for_test()
    }

    /// Reset the process-global context to a fresh, initialized state.
    /// Callers must hold [`lock_globals`].
    fn reset_context() {
        reset_context_with_capacity(1024, 1024);
    }

    /// [`reset_context`] with explicit caps. Every test that re-initialises the
    /// context must come through here: re-running `nef_context_final` +
    /// `nef_context_init` by hand keeps the previous test's producer URIs
    /// (#548 — the capacity test inherited a dead AMF from a sibling and got 503
    /// instead of 201). Callers must hold [`lock_globals`].
    fn reset_context_with_capacity(max_subscriptions: usize, max_transactions: usize) {
        nef_context_final();
        nef_context_init(max_subscriptions, max_transactions);
        // #111: CLEAR the southbound producer URIs too. `nef_context_final` +
        // `nef_context_init` did not, so a test that pointed the context at a
        // producer leaked it into every later test -- which then attempted a real
        // HTTP call on a current-thread runtime with no IO driver and panicked
        // inside the SBI client. Six pre-existing tests failed that way the first
        // time this file set a producer URI. Same process-global-state shape as the
        // env-var races recorded in LEARNINGS: the hazard appears the moment a
        // second party touches the shared thing.
        if let Ok(mut c) = nef_self().write() {
            c.set_endpoints(None, None, None, None);
            c.set_udm_sdm_uri(None);
        }
    }

    /// Drive an async handler to completion on a fresh current-thread runtime.
    ///
    /// #111 enabled the IO and time drivers. The comment here used to say none were
    /// needed "since the handlers under test do no real I/O (no producer URIs are
    /// configured)" -- true until a test configured one, at which point the SBI
    /// client's `tokio::time::timeout` PANICKED with "timers are disabled" instead
    /// of returning a connection error. Enabling them costs nothing and removes the
    /// whole class, rather than leaving the next author to discover it.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
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

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-nefd"]);
        assert_eq!(args.sbi_addr, "127.0.0.1");
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
        let profile = build_nf_profile(
            "nef-test-1",
            "10.0.0.9",
            7817,
            nextgcore_sbi::types::UriScheme::Http,
        );
        assert_eq!(profile["nfType"], "NEF");
        assert_eq!(profile["nfStatus"], "REGISTERED");
        // #2141: the UCMF discovers the NEF to type a NEF provisioner.
        assert_eq!(
            profile["allowedNfTypes"],
            serde_json::json!(["AF", "AMF", "UDM", "SCP", "UCMF"])
        );
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
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &request,
            NorthboundApi::T8MonitoringEvent,
        ));
        assert_eq!(response.status, 400);
    }

    #[test]
    fn monitoring_create_missing_notification_destination_returns_400() {
        let request = monitoring_request(serde_json::json!({
            "monitoringType": "LOCATION_REPORTING",
        }));
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &request,
            NorthboundApi::T8MonitoringEvent,
        ));
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
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &request,
            NorthboundApi::T8MonitoringEvent,
        ));
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
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &request,
            NorthboundApi::T8MonitoringEvent,
        ));
        assert_eq!(response.status, 400, "missing monitoringType must be 400");
    }

    #[test]
    fn monitoring_create_unsupported_monitoring_type_returns_400() {
        let request = monitoring_request(serde_json::json!({
            "monitoringType": "AVAILABILITY_AFTER_DDN_FAILURE",
            "notificationDestination": "http://af.example.com/cb",
        }));
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &request,
            NorthboundApi::T8MonitoringEvent,
        ));
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
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &request,
            NorthboundApi::T8MonitoringEvent,
        ));
        assert_eq!(response.status, 400, "path-injecting identity must be 400");
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MANDATORY_IE_INCORRECT");
    }

    #[test]
    fn monitoring_create_at_capacity_returns_507() {
        let _guard = lock_globals();
        // Re-init with a cap of one subscription, and no producer URIs, so the
        // first create is DEFERRED (201) whatever a sibling test configured.
        reset_context_with_capacity(1, 1);

        let first = block_on(handle_monitoring_subscription_create(
            "af1",
            &monitoring_request(valid_monitoring_body()),
            NorthboundApi::T8MonitoringEvent,
        ));
        assert_eq!(first.status, 201);

        let second = block_on(handle_monitoring_subscription_create(
            "af1",
            &monitoring_request(valid_monitoring_body()),
            NorthboundApi::T8MonitoringEvent,
        ));
        assert_eq!(second.status, 507, "cap exhaustion must be 507");
        let body: serde_json::Value =
            serde_json::from_str(second.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MAX_SUBSCRIPTIONS_REACHED");

        // Restore the default test capacity for other tests.
        reset_context();
    }

    // ── Monitoring Event create: success path (acceptance: 201 + Location;
    //    no producer configured → southbound deferred) ───────────────────────
    #[test]
    fn monitoring_create_success_returns_201_with_location_and_stores() {
        let _guard = lock_globals();
        reset_context();

        let request = monitoring_request(valid_monitoring_body());
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &request,
            NorthboundApi::T8MonitoringEvent,
        ));
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
        let created = block_on(handle_monitoring_subscription_create(
            "af1",
            &create,
            NorthboundApi::T8MonitoringEvent,
        ));
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
        let created = block_on(handle_monitoring_subscription_create(
            "af1",
            &create,
            NorthboundApi::T8MonitoringEvent,
        ));
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
        // #111 FLIP: this asserted "TRIGGERED", so the test PINNED the fabricated
        // success. `TRIGGERED` is a positive TS 29.122 §5.10 lifecycle state -- the
        // trigger was accepted for delivery -- and no delivery leg exists, so the AF
        // could not tell "queued" from "silently dropped". `UNKNOWN` is the honest
        // value while the SMS/T4 path is absent.
        assert_eq!(body["deliveryResult"], DEVICE_TRIGGERING_STUB_RESULT);
        assert_ne!(
            body["deliveryResult"], "TRIGGERED",
            "no delivery leg exists, so a positive lifecycle state must not be reported"
        );

        let stored = nef_self()
            .read()
            .unwrap()
            .transaction_find(&txn_id)
            .expect("stored");
        assert_eq!(stored.scs_as_id, "af1");
        // The STORED result and the ECHOED result must agree: they were two separate
        // literals, so a fix to one could have left the other claiming success.
        assert_eq!(stored.delivery_result, DEVICE_TRIGGERING_STUB_RESULT);
        assert_eq!(
            stored.delivery_result,
            body["deliveryResult"].as_str().unwrap()
        );
    }

    // -----------------------------------------------------------------
    // #111: service-catalogue truth, honest failures, pending lifecycle
    // -----------------------------------------------------------------

    /// Point the context's southbound producer URIs somewhere. `None` leaves the
    /// leg DEFERRED; a URI makes it attempt and (against nothing listening) FAIL.
    fn set_producers(amf: Option<&str>, udm: Option<&str>) {
        if let Ok(mut c) = nef_self().write() {
            c.set_endpoints(
                amf.map(str::to_string),
                udm.map(str::to_string),
                Some("http://127.0.0.1:7817".to_string()),
                Some("nef-test".to_string()),
            );
        }
    }

    type Seen1877 = Arc<std::sync::Mutex<Vec<(String, String)>>>;

    /// How long [`amf_1877`] holds a DELETE before answering it (ms). Set only by
    /// tests that hold `lock_globals`, which the AMF stand-ins are used under.
    static DELETE_DELAY_1877: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A stand-in AMF: POST answered 201 with a Location after `post_delay`; DELETE
    /// answered with `delete` as it stands. Recorded as (method, uri).
    async fn amf_1877(
        post_delay: Duration,
        delete: Arc<std::sync::atomic::AtomicU16>,
    ) -> (nextgcore_sbi::server::SbiServer, String, Seen1877) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Seen1877 = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let (srv, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let sink = sink.clone();
                let delete = delete.load(Ordering::SeqCst);
                async move {
                    sink.lock()
                        .unwrap()
                        .push((req.header.method.clone(), req.header.uri.clone()));
                    if req.header.method == "DELETE" {
                        let held = DELETE_DELAY_1877.load(Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(held)).await;
                        return SbiResponse::with_status(delete);
                    }
                    tokio::time::sleep(post_delay).await;
                    SbiResponse::with_status(201)
                        .with_header("location", "/namf-evts/v1/subscriptions/s-1877")
                }
            })
            .await;
        (srv, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    /// #2128 (R42 minor 3): seconds the stand-in producers grant short of the
    /// expiry asked for (0: they grant it). Set only under `lock_globals`.
    static GRANT_CUT_2102: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// The expiry `asked` (RFC 3339) less [`GRANT_CUT_2102`].
    fn granted_2102(asked: &serde_json::Value) -> serde_json::Value {
        let cut = GRANT_CUT_2102.load(Ordering::SeqCst);
        match asked
            .as_str()
            .and_then(nextgcore_sbi::datetime::rfc3339_to_epoch)
        {
            Some(at) => serde_json::json!(nextgcore_sbi::datetime::epoch_to_rfc3339(
                at.saturating_sub(cut)
            )),
            None => asked.clone(),
        }
    }

    /// #2102: what a stand-in producer saw: (method, uri, JSON body).
    type Seen2102 = Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>;

    /// #2102: a stand-in AMF or UDM. A subscribe is answered 201 after
    /// `post_delay`, with a Location and the body it took (the expiry it asked
    /// for, confirmed); a PATCH with `patch` as it stands, echoing the expiry the
    /// patch set.
    async fn producer_2102(
        producer: SouthboundProducer,
        post_delay: Duration,
        patch: Arc<std::sync::atomic::AtomicU16>,
    ) -> (nextgcore_sbi::server::SbiServer, String, Seen2102) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Seen2102 = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let (srv, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let sink = sink.clone();
                let patch = patch.load(Ordering::SeqCst);
                async move {
                    let body: serde_json::Value = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|c| serde_json::from_str(c).ok())
                        .unwrap_or_default();
                    sink.lock().unwrap().push((
                        req.header.method.clone(),
                        req.header.uri.clone(),
                        body.clone(),
                    ));
                    match (req.header.method.as_str(), producer) {
                        ("PATCH", SouthboundProducer::Amf) => {
                            let expiry = granted_2102(&body[0]["value"]);
                            SbiResponse::with_status(patch)
                                .with_json_body(&serde_json::json!({
                                    "subscription": { "options": { "expiry": expiry } }
                                }))
                                .expect("json")
                        }
                        ("PATCH", SouthboundProducer::Udm) => SbiResponse::with_status(patch),
                        ("POST", SouthboundProducer::Amf) => {
                            tokio::time::sleep(post_delay).await;
                            let mut granted = body["subscription"].clone();
                            if let Some(at) = granted.pointer("/options/expiry").cloned() {
                                granted["options"]["expiry"] = granted_2102(&at);
                            }
                            SbiResponse::with_status(201)
                                .with_header("location", "/namf-evts/v1/subscriptions/s-2102")
                                .with_json_body(&serde_json::json!({
                                    "subscription": granted,
                                    "subscriptionId": "s-2102"
                                }))
                                .expect("json")
                        }
                        ("POST", SouthboundProducer::Udm) => {
                            tokio::time::sleep(post_delay).await;
                            SbiResponse::with_status(201)
                                .with_header(
                                    "location",
                                    "/nudm-ee/v1/imsi-001010000002102/ee-subscriptions/ee-2102",
                                )
                                .with_json_body(&body)
                                .expect("json")
                        }
                        _ => SbiResponse::with_status(204),
                    }
                }
            })
            .await;
        (srv, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    fn requests_2102(seen: &Seen2102, method: &str) -> Vec<(String, serde_json::Value)> {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(m, _, _)| m == method)
            .map(|(_, u, b)| (u.clone(), b.clone()))
            .collect()
    }

    fn epoch_2102(v: &serde_json::Value) -> u64 {
        nextgcore_sbi::datetime::rfc3339_to_epoch(v.as_str().expect("an RFC 3339 expiry"))
            .expect("a parsable expiry")
    }

    /// #2102 (split out of #2086): a create whose 3 s request timeout fires after
    /// the AMF took the subscription leaves an orphan the NEF cannot name. It is
    /// bounded: the subscribe asked for an expiry one lifetime ahead
    /// (`subscription.options.expiry`), the NEF holds no record of it, and no
    /// refresh sweep -- even one run just before that expiry -- ever extends it,
    /// so it lapses at the AMF on its own.
    ///
    /// REVERT-VERIFIED: with `with_requested_expiry` returning the body as built,
    /// the subscribe carries no expiry and this test fails (as does the live-leg
    /// test, at "the expiry asked for is the one recorded").
    #[test]
    fn a_timed_out_creates_orphan_is_bounded_and_never_refreshed_2102() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let (amf, amf_uri, seen) = producer_2102(
                SouthboundProducer::Amf,
                Duration::from_millis(SOUTHBOUND_REQUEST_TIMEOUT_SECS * 1000 + 500),
                Arc::new(std::sync::atomic::AtomicU16::new(200)),
            )
            .await;
            set_producers(Some(&amf_uri), None);
            let before = now_unix_secs();
            let resp = handle_monitoring_subscription_create(
                "af1",
                &monitoring_request(valid_monitoring_body()),
                NorthboundApi::T8MonitoringEvent,
            )
            .await;
            let after = now_unix_secs();
            // Let the AMF finish taking it (the orphan now exists there).
            tokio::time::sleep(Duration::from_millis(800)).await;
            let held = nef_self().read().unwrap().subscription_count();
            let posts = requests_2102(&seen, "POST");
            let asked = posts
                .first()
                .and_then(|(_, b)| b.pointer("/subscription/options/expiry").cloned());
            let lifetime = southbound_lifetime_secs();
            let mut sweeps = Vec::new();
            if let Some(expiry) = asked.as_ref().map(epoch_2102) {
                for now in [after, expiry.saturating_sub(1)] {
                    sweeps.push(refresh_live_subscriptions_at(now).await);
                }
            }
            let patches = requests_2102(&seen, "PATCH");
            amf.stop().await.ok();

            assert_eq!(resp.status, 503, "{:?}", resp.http.content);
            assert_eq!(held, 0, "the NEF holds no record of the orphan");
            assert_eq!(posts.len(), 1);
            let asked = asked.expect("the subscribe asked for an expiry");
            assert_eq!(
                posts[0].1.pointer("/subscription/options/trigger"),
                Some(&serde_json::json!("CONTINUOUS"))
            );
            let expiry = epoch_2102(&asked);
            assert!(
                (before + lifetime..=after + lifetime).contains(&expiry),
                "one lifetime ahead: {expiry} vs {before}+{lifetime}"
            );
            assert!(
                sweeps.iter().all(|r| *r == RefreshReport::default()),
                "{sweeps:?}"
            );
            assert!(
                patches.is_empty(),
                "the orphan is never refreshed: {patches:?}"
            );
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #2149: a UDM modify answered 200 with a PatchResult reporting a shortened
    /// grant gives the granted expiry; the other UDM forms still parse, and a
    /// PatchResult about another path gives none.
    ///
    /// REVERT-VERIFIED: with the PatchResult arm removed, the first assertion
    /// is `None`.
    #[test]
    fn a_udm_patch_result_reports_the_granted_expiry_2149() {
        let at = nextgcore_sbi::datetime::epoch_to_rfc3339(2_000_000_000);
        let answer = |body: serde_json::Value| {
            SbiResponse::with_status(200)
                .with_json_body(&body)
                .expect("json")
        };
        assert_eq!(
            confirmed_expiry(
                SouthboundProducer::Udm,
                &answer(serde_json::json!({ "report": [{
                    "path": "/reportingOptions/expiry", "reason": format!("granted {at}")
                }]}))
            ),
            Some(2_000_000_000)
        );
        assert_eq!(
            confirmed_expiry(
                SouthboundProducer::Udm,
                &answer(serde_json::json!({ "reportingOptions": { "expiry": at } }))
            ),
            Some(2_000_000_000)
        );
        assert_eq!(
            confirmed_expiry(
                SouthboundProducer::Udm,
                &answer(serde_json::json!({ "report": [{
                    "path": "/monitoringConfigurations", "reason": format!("granted {at}")
                }]}))
            ),
            None
        );
    }

    /// **#2133** (R42 on #2128): when the NEF removes an AF's subscription on its
    /// own initiative, the AF is told with a MonitoringNotification naming the
    /// subscription with `cancelInd: true` (TS 29.122): a leg gone at the
    /// producer (404 on refresh), a leg whose expiry passed before a refresh got
    /// through, and a deferred leg past its deadline. An AF-requested DELETE is
    /// not notified. The notification is detached, so the AF stub is polled.
    ///
    /// REVERT-VERIFIED, each site on its own: with the 404 arm, the lapsed arm
    /// (`remove_lapsed_leg`) or the pending-deadline arm back on a plain
    /// `subscription_remove`, that case's "the AF is told" assertion fails.
    #[test]
    fn a_subscription_the_nef_removes_is_cancelled_at_the_af_2133() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let af_seen: Seen2102 = Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = af_seen.clone();
            let (af, af_addr) =
                nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                    let sink = sink.clone();
                    async move {
                        let body = req
                            .http
                            .content
                            .as_deref()
                            .and_then(|c| serde_json::from_str(c).ok())
                            .unwrap_or_default();
                        sink.lock().unwrap().push((
                            req.header.method.clone(),
                            req.header.uri.clone(),
                            body,
                        ));
                        SbiResponse::with_status(204)
                    }
                })
                .await;
            let af_uri = format!("http://127.0.0.1:{}/af-2133", af_addr.port());
            let patch_status = Arc::new(std::sync::atomic::AtomicU16::new(404));
            let (producer, uri, _seen) =
                producer_2102(SouthboundProducer::Amf, Duration::ZERO, patch_status).await;
            set_producers(Some(&uri), None);
            let insert = |sub: NefMonitoringSubscription| {
                let id = sub.id.clone();
                nef_self()
                    .read()
                    .unwrap()
                    .subscription_insert(sub)
                    .expect("insert");
                id
            };
            let live = |expiry: u64, leg: &str| {
                let mut sub = NefMonitoringSubscription::new(
                    "af1",
                    "LOCATION_REPORTING",
                    af_uri.clone(),
                    "{}",
                );
                sub.southbound = Some(SouthboundRef {
                    producer: SouthboundProducer::Amf,
                    subscription_id: leg.to_string(),
                    delete_path: format!("/namf-evts/v1/subscriptions/{leg}"),
                    producer_base: Some(uri.clone()),
                });
                sub.southbound_expiry = Some(expiry);
                sub
            };
            let told = |id: &str| {
                let id = id.to_string();
                let seen = af_seen.clone();
                async move {
                    let want = serde_json::json!({
                        "subscription": format!("/3gpp-monitoring-event/v1/af1/subscriptions/{id}"),
                        "cancelInd": true,
                    });
                    for _ in 0..200 {
                        if seen
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|(m, _, b)| m == "POST" && *b == want)
                        {
                            return true;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    false
                }
            };

            // A leg the producer no longer holds (404 on refresh).
            let now = now_unix_secs();
            let gone = insert(live(now + 10, "s-2133-gone"));
            let report = refresh_live_subscriptions_at(now).await;
            assert_eq!(report.lapsed, 1, "{report:?}");
            assert!(told(&gone).await, "404 on refresh: the AF is told");

            // A leg whose expiry passed before a refresh got through.
            let lapsed = insert(live(now - 1, "s-2133-lapsed"));
            let report = refresh_live_subscriptions_at(now).await;
            assert_eq!(report.lapsed, 1, "{report:?}");
            assert!(told(&lapsed).await, "lapsed leg: the AF is told");

            // A deferred leg past its deadline (no AMF to retry at).
            set_producers(None, None);
            let mut deferred =
                NefMonitoringSubscription::new("af1", "LOCATION_REPORTING", af_uri.clone(), "{}");
            deferred.pending = Some(PendingSouthbound {
                producer: SouthboundProducer::Amf,
                path: "/namf-evts/v1/subscriptions".to_string(),
                body: serde_json::json!({}),
                since: now - 10,
            });
            let deferred = insert(deferred);
            std::env::set_var("NEF_PENDING_LEG_DEADLINE_SECS", "0");
            let report = reconcile_pending_subscriptions().await;
            std::env::remove_var("NEF_PENDING_LEG_DEADLINE_SECS");
            assert_eq!(report.expired, 1, "{report:?}");
            assert!(
                told(&deferred).await,
                "deferred leg past its deadline: the AF is told"
            );

            assert_eq!(
                af_seen.lock().unwrap().len(),
                3,
                "one cancellation per removal, and nothing else"
            );
            af.stop().await.ok();
            producer.stop().await.ok();
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// **#2163** (R42 on #2158): the old-udmd fallback is for the refusal of the
    /// member path only: a 400 whose `invalidParams` or `detail` names
    /// `/reportingOptions/expiry`. A 400 for anything else (an expiry already
    /// passed, a malformed subscription), another status, or a 400 without a
    /// ProblemDetails is a refusal of the refresh and is not retried.
    ///
    /// REVERT-VERIFIED: with `refuses_the_member_path` back to "any 400", the
    /// "a genuine refusal is not retried" cases are `true`.
    #[test]
    fn only_a_refusal_of_the_member_path_falls_back_2163() {
        let problem = |status: u16, body: serde_json::Value| {
            SbiResponse::with_status(status)
                .with_json_body(&body)
                .expect("json")
        };
        assert!(refuses_the_member_path(&problem(
            400,
            serde_json::json!({ "status": 400, "detail":
                "path \"/reportingOptions/expiry\" must address a top-level EeSubscription member" })
        )));
        assert!(refuses_the_member_path(&problem(
            400,
            serde_json::json!({ "status": 400, "invalidParams": [
                { "param": "/reportingOptions/expiry", "reason": "unsupported path" }
            ]})
        )));
        for (resp, what) in [
            (
                problem(
                    400,
                    serde_json::json!({ "status": 400, "detail":
                    "reportingOptions.expiry has already passed", "cause": "MANDATORY_IE_INCORRECT" }),
                ),
                "a genuine refusal is not retried",
            ),
            (
                problem(
                    400,
                    serde_json::json!({ "status": 400, "invalidParams": [
                        { "param": "/monitoringConfigurations" }
                    ]}),
                ),
                "a genuine refusal is not retried (another param)",
            ),
            (
                SbiResponse::with_status(400),
                "a 400 without a ProblemDetails",
            ),
            (
                problem(
                    403,
                    serde_json::json!({ "detail": "/reportingOptions/expiry" }),
                ),
                "another status",
            ),
        ] {
            assert!(!refuses_the_member_path(&resp), "{what}");
        }
    }

    /// **#2154** (R42 on #2152): TS 29.591 defines no cancellation indication,
    /// so a Nnef_EventExposure subscriber whose subscription the NEF removes is
    /// sent nothing, while a T8 one in the same sweep gets its `cancelInd`.
    /// Then the upgrade fallback: a UDM answering the member-form refresh 400 (a
    /// udmd from before #2133) is sent the whole-object form once, and the leg
    /// is refreshed.
    ///
    /// REVERT-VERIFIED: with the Nnef branch of `remove_and_tell_af` removed,
    /// the Nnef consumer is POSTed a T8 cancellation and "nothing for the Nnef
    /// consumer" fails; with the 400 fallback removed, the old UDM's leg is not
    /// refreshed and "the old UDM's leg is refreshed" fails.
    #[test]
    fn nnef_removals_send_nothing_and_an_old_udm_is_refreshed_2154() {
        let _guard = lock_globals();
        // Loopback plaintext stand-ins (the default profile is production).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let af_seen: Seen2102 = Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = af_seen.clone();
            let (af, af_addr) =
                nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                    let sink = sink.clone();
                    async move {
                        let body = req
                            .http
                            .content
                            .as_deref()
                            .and_then(|c| serde_json::from_str(c).ok())
                            .unwrap_or_default();
                        sink.lock().unwrap().push((
                            req.header.method.clone(),
                            req.header.uri.clone(),
                            body,
                        ));
                        SbiResponse::with_status(204)
                    }
                })
                .await;
            // A producer that answers every PATCH 404 at `/gone/...`, and at
            // `/old/...` behaves as a pre-#2133 udmd: 400 for a nested path,
            // 204 for the whole object.
            let patches: Seen2102 = Arc::new(std::sync::Mutex::new(Vec::new()));
            let psink = patches.clone();
            let (producer, paddr) =
                nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                    let psink = psink.clone();
                    async move {
                        let body: serde_json::Value = req
                            .http
                            .content
                            .as_deref()
                            .and_then(|c| serde_json::from_str(c).ok())
                            .unwrap_or_default();
                        psink.lock().unwrap().push((
                            req.header.method.clone(),
                            req.header.uri.clone(),
                            body.clone(),
                        ));
                        if req.header.uri.contains("/gone/") {
                            return SbiResponse::with_status(404);
                        }
                        if body[0]["path"] == "/reportingOptions/expiry" {
                            // What a udmd from before #2133 answers (#2163).
                            return nextgcore_sbi::server::send_bad_request(
                                "path \"/reportingOptions/expiry\" must address a top-level \
                                 EeSubscription member",
                                Some("INVALID_MSG_FORMAT"),
                            );
                        }
                        SbiResponse::with_status(204)
                    }
                })
                .await;
            let uri = format!("http://127.0.0.1:{}", paddr.port());
            set_producers(None, Some(&uri));
            let now = now_unix_secs();
            let leg = |api: NorthboundApi, scs: &str, path: &str| {
                let mut sub = NefMonitoringSubscription::new(
                    scs,
                    "LOSS_OF_CONNECTIVITY",
                    format!("http://127.0.0.1:{}/af-2154", af_addr.port()),
                    "{}",
                )
                .with_northbound_api(api);
                sub.southbound = Some(SouthboundRef {
                    producer: SouthboundProducer::Udm,
                    subscription_id: path.rsplit('/').next().unwrap().to_string(),
                    delete_path: path.to_string(),
                    producer_base: Some(uri.clone()),
                });
                sub.southbound_expiry = Some(now + 10);
                let id = sub.id.clone();
                nef_self()
                    .read()
                    .unwrap()
                    .subscription_insert(sub)
                    .expect("insert");
                id
            };
            let nnef_gone = leg(NorthboundApi::NnefEventExposure, "notif-2154", "/gone/n");
            let t8_gone = leg(NorthboundApi::T8MonitoringEvent, "af1", "/gone/t");
            let old = leg(NorthboundApi::T8MonitoringEvent, "af1", "/old/o");

            let report = refresh_live_subscriptions_at(now).await;
            assert_eq!((report.lapsed, report.refreshed), (2, 1), "{report:?}");
            let want_t8 = serde_json::json!({
                "subscription": format!("/3gpp-monitoring-event/v1/af1/subscriptions/{t8_gone}"),
                "cancelInd": true,
            });
            let mut t8_told = false;
            for _ in 0..200 {
                if af_seen
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(_, _, b)| *b == want_t8)
                {
                    t8_told = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(t8_told, "the T8 consumer gets its cancelInd");
            tokio::time::sleep(Duration::from_millis(100)).await;
            // One guard at a time: the message must not lock it again.
            let delivered = af_seen.lock().unwrap().clone();
            assert_eq!(
                delivered.len(),
                1,
                "nothing for the Nnef consumer ({nnef_gone}): {delivered:?}"
            );
            let old_patches: Vec<serde_json::Value> = patches
                .lock()
                .unwrap()
                .iter()
                .filter(|(m, u, _)| m == "PATCH" && u.contains("/old/"))
                .map(|(_, _, b)| b[0]["path"].clone())
                .collect();
            assert_eq!(
                old_patches,
                [
                    serde_json::json!("/reportingOptions/expiry"),
                    serde_json::json!("/reportingOptions")
                ],
                "the member form, then the whole object once"
            );
            assert!(
                nef_self()
                    .read()
                    .unwrap()
                    .subscription_find(&old)
                    .and_then(|s| s.southbound_expiry)
                    .is_some_and(|e| e > now + 10),
                "the old UDM's leg is refreshed"
            );
            af.stop().await.ok();
            producer.stop().await.ok();
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #2133 (R42 on #2128): the UDM refresh names `reportingOptions/expiry`
    /// for a leg made with reportingOptions, so RFC 6902 `add` does not
    /// replace the object's other members; a leg made before #2102 (none
    /// recorded) gets the whole object, as it has none to lose.
    ///
    /// REVERT-VERIFIED: with the UDM arm always sending `/reportingOptions`,
    /// the first assertion fails (and so does #2102's patch assertion).
    #[test]
    fn the_udm_refresh_adds_the_expiry_member_not_the_object_2133() {
        let at = nextgcore_sbi::datetime::epoch_to_rfc3339(2_000_000_000);
        assert_eq!(
            refresh_patch(SouthboundProducer::Udm, 2_000_000_000, true),
            serde_json::json!([{ "op": "add", "path": "/reportingOptions/expiry", "value": at }])
        );
        assert_eq!(
            refresh_patch(SouthboundProducer::Udm, 2_000_000_000, false),
            serde_json::json!([{
                "op": "add", "path": "/reportingOptions", "value": { "expiry": at }
            }])
        );
        assert_eq!(
            refresh_patch(SouthboundProducer::Amf, 2_000_000_000, true),
            refresh_patch(SouthboundProducer::Amf, 2_000_000_000, false),
            "the AMF's AmfUpdateEventOptionItem is a member replace either way"
        );
    }

    /// #2102: a live leg, AMF and UDM, is made with an expiry and refreshed
    /// before it lapses, by the spec modification: the AMF's
    /// AmfUpdateEventOptionItem `replace /options/expiry`, the UDM's PatchItem on
    /// `reportingOptions`. Not before it is due (more than half its lifetime
    /// left). The new expiry is recorded. A producer answering a refresh 404
    /// no longer holds it, so the subscription is removed. A leg whose expiry
    /// passed before any refresh got through is removed, and its DELETE is sent
    /// in case the producer ignored the expiry.
    ///
    /// REVERT-VERIFIED: with `refresh_live_subscriptions_at` skipping every leg,
    /// no PATCH is sent and the `refreshed when due` assertion fails; with the
    /// 404 arm counted as a failure, the 404 sweep lapses nothing and its
    /// `lapsed` assertion fails.
    #[test]
    fn a_live_leg_is_refreshed_before_it_lapses_2102() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        for producer in [SouthboundProducer::Amf, SouthboundProducer::Udm] {
            reset_context();
            block_on(async {
                let patch_status = Arc::new(std::sync::atomic::AtomicU16::new(200));
                let (srv, uri, seen) =
                    producer_2102(producer, Duration::ZERO, patch_status.clone()).await;
                let body = match producer {
                    SouthboundProducer::Amf => {
                        set_producers(Some(&uri), None);
                        valid_monitoring_body()
                    }
                    SouthboundProducer::Udm => {
                        set_producers(None, Some(&uri));
                        serde_json::json!({
                            "monitoringType": "LOSS_OF_CONNECTIVITY",
                            "notificationDestination": "http://af.example.com:8080/notifications",
                            "supi": "imsi-001010000002102",
                        })
                    }
                };
                let before = now_unix_secs();
                let resp = handle_monitoring_subscription_create(
                    "af1",
                    &monitoring_request(body),
                    NorthboundApi::T8MonitoringEvent,
                )
                .await;
                assert_eq!(resp.status, 201, "{producer:?}: {:?}", resp.http.content);
                let id = created_subscription_id(&resp).expect("id");
                let stored = || nef_self().read().unwrap().subscription_find(&id);
                let (lifetime, margin) =
                    (southbound_lifetime_secs(), southbound_refresh_margin_secs());
                let e0 = stored()
                    .and_then(|s| s.southbound_expiry)
                    .expect("an expiry");
                assert!(e0 >= before + lifetime, "{producer:?}: {e0}");
                let asked = match producer {
                    SouthboundProducer::Amf => "/subscription/options/expiry",
                    SouthboundProducer::Udm => "/reportingOptions/expiry",
                };
                let posts = requests_2102(&seen, "POST");
                assert_eq!(
                    posts[0].1.pointer(asked).map(epoch_2102),
                    Some(e0),
                    "{producer:?}: the expiry asked for is the one recorded"
                );

                // Not due yet.
                let early = refresh_live_subscriptions_at(e0 - margin - 1).await;
                assert_eq!(early, RefreshReport::default(), "{producer:?}");
                assert!(requests_2102(&seen, "PATCH").is_empty(), "{producer:?}");

                // Due: refreshed one lifetime past the sweep.
                let due = e0 - margin;
                let report = refresh_live_subscriptions_at(due).await;
                let patches = requests_2102(&seen, "PATCH");
                assert_eq!(report.refreshed, 1, "{producer:?}: refreshed when due");
                assert_eq!(patches.len(), 1, "{producer:?}");
                let (path, patch) = &patches[0];
                let e1 = due + lifetime;
                let at = serde_json::json!(nextgcore_sbi::datetime::epoch_to_rfc3339(e1));
                match producer {
                    SouthboundProducer::Amf => {
                        assert!(
                            path.ends_with("/namf-evts/v1/subscriptions/s-2102"),
                            "{path}"
                        );
                        assert_eq!(
                            patch,
                            &serde_json::json!([
                                { "op": "replace", "path": "/options/expiry", "value": at }
                            ])
                        );
                    }
                    SouthboundProducer::Udm => {
                        assert!(path.ends_with("/ee-subscriptions/ee-2102"), "{path}");
                        // #2133: the member, not the object, so the UDM's other
                        // reportingOptions members survive.
                        assert_eq!(
                            patch,
                            &serde_json::json!([{
                                "op": "add", "path": "/reportingOptions/expiry",
                                "value": at
                            }])
                        );
                    }
                }
                assert_eq!(stored().and_then(|s| s.southbound_expiry), Some(e1));

                // A 404 on refresh: the producer no longer holds it.
                patch_status.store(404, Ordering::SeqCst);
                let gone = refresh_live_subscriptions_at(e1 - margin).await;
                assert_eq!(gone.lapsed, 1, "{producer:?}");
                assert!(stored().is_none(), "{producer:?}: 404 removes it");
                srv.stop().await.ok();
            });
        }

        // An expiry that passed before a refresh got through.
        reset_context();
        block_on(async {
            let (srv, uri, seen) = producer_2102(
                SouthboundProducer::Amf,
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(503)),
            )
            .await;
            set_producers(Some(&uri), None);
            let resp = handle_monitoring_subscription_create(
                "af1",
                &monitoring_request(valid_monitoring_body()),
                NorthboundApi::T8MonitoringEvent,
            )
            .await;
            assert_eq!(resp.status, 201);
            let id = created_subscription_id(&resp).expect("id");
            let e0 = nef_self()
                .read()
                .unwrap()
                .subscription_find(&id)
                .and_then(|s| s.southbound_expiry)
                .expect("expiry");
            let failed = refresh_live_subscriptions_at(e0 - 1).await;
            assert_eq!(failed.failed, 1, "a 503 refresh is retried");
            assert!(nef_self().read().unwrap().subscription_find(&id).is_some());
            let lapsed = refresh_live_subscriptions_at(e0).await;
            // #2128: the DELETE goes out on its own task.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while requests_2102(&seen, "DELETE").is_empty()
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let deletes = requests_2102(&seen, "DELETE");
            srv.stop().await.ok();
            assert_eq!(lapsed.lapsed, 1);
            assert!(nef_self().read().unwrap().subscription_find(&id).is_none());
            assert_eq!(deletes.len(), 1, "its DELETE is sent: {deletes:?}");
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #2102: a leg restored from a snapshot written before #2102 has no
    /// recorded expiry (`southbound_expiry` defaults to `None`). The first sweep
    /// refreshes it, which bounds it, and the expiry it obtained survives a
    /// snapshot round trip.
    ///
    /// REVERT-VERIFIED: with `subscriptions_live` sorting but skipping legs with
    /// no expiry (`filter(.. && s.southbound_expiry.is_some())`), no PATCH is sent
    /// and the `bounded on the first sweep` assertion fails.
    #[test]
    fn a_restored_leg_without_an_expiry_is_bounded_on_the_first_sweep_2102() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let (amf, amf_uri, seen) = producer_2102(
                SouthboundProducer::Amf,
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(200)),
            )
            .await;
            set_producers(Some(&amf_uri), None);
            let mut legacy = serde_json::to_value(NefMonitoringSubscription::new(
                "af1",
                "LOCATION_REPORTING",
                "http://af.example.com/cb",
                "{}",
            ))
            .expect("serialize");
            legacy["southbound"] = serde_json::json!({
                "producer": "Amf",
                "subscription_id": "s-2102",
                "delete_path": "/namf-evts/v1/subscriptions/s-2102",
                "producer_base": amf_uri,
            });
            legacy.as_object_mut().unwrap().remove("southbound_expiry");
            let restored: NefMonitoringSubscription =
                serde_json::from_value(legacy).expect("a pre-#2102 record restores");
            assert_eq!(restored.southbound_expiry, None);
            let id = restored.id.clone();
            nef_self()
                .read()
                .unwrap()
                .subscription_insert(restored)
                .expect("insert");

            let now = now_unix_secs();
            let report = refresh_live_subscriptions_at(now).await;
            let patches = requests_2102(&seen, "PATCH");
            amf.stop().await.ok();
            assert_eq!(report.refreshed, 1, "bounded on the first sweep");
            assert_eq!(patches.len(), 1);
            let stored = nef_self().read().unwrap().subscription_find(&id).unwrap();
            let expiry = now + southbound_lifetime_secs();
            assert_eq!(stored.southbound_expiry, Some(expiry));
            let round: NefMonitoringSubscription =
                serde_json::from_value(serde_json::to_value(&stored).unwrap()).unwrap();
            assert_eq!(round.southbound_expiry, Some(expiry), "it is persisted");
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #2128: a stored subscription whose live leg is at `base`, expiring at
    /// `expiry`; its id.
    fn live_leg_2128(producer: SouthboundProducer, base: &str, id: &str, expiry: u64) -> String {
        let monitoring = match producer {
            SouthboundProducer::Amf => "LOCATION_REPORTING",
            SouthboundProducer::Udm => "LOSS_OF_CONNECTIVITY",
        };
        let mut sub =
            NefMonitoringSubscription::new("af1", monitoring, "http://af.example.com/cb", "{}");
        let delete_path = match producer {
            SouthboundProducer::Amf => format!("/namf-evts/v1/subscriptions/{id}"),
            SouthboundProducer::Udm => {
                format!("/nudm-ee/v1/imsi-001010000002128/ee-subscriptions/{id}")
            }
        };
        sub.southbound = Some(SouthboundRef {
            producer,
            subscription_id: id.to_string(),
            delete_path,
            producer_base: Some(base.to_string()),
        });
        sub.southbound_expiry = Some(expiry);
        let sub_id = sub.id.clone();
        nef_self()
            .read()
            .unwrap()
            .subscription_insert(sub)
            .expect("insert");
        sub_id
    }

    /// #2128 (R42 MAJOR): a blackholed producer does not starve a healthy one.
    /// Four AMF legs, due first, sit at an AMF that never answers a PATCH, and
    /// one UDM leg at a healthy UDM. One pass sends the AMF a single refresh
    /// (its timeout), skips its other legs, and refreshes the UDM leg, all within
    /// about one request timeout.
    ///
    /// REVERT-VERIFIED: with a failed producer tried again for each of its legs
    /// (`producer_failed` ignored), the AMF is sent four PATCHes and the pass
    /// takes four timeouts, and the `one refresh at the blackholed AMF` assertion
    /// fails.
    #[test]
    fn a_blackholed_producer_does_not_starve_a_healthy_one_2128() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            nextgcore_sbi::security::set_sbi_profile_override(
                nextgcore_sbi::security::SbiProfile::Dev,
            );
            let amf_patches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = amf_patches.clone();
            let (amf, amf_addr) =
                nextgcore_sbi::test_support::sbi_server_on_free_port(move |_req: SbiRequest| {
                    let count = count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(8)).await;
                        SbiResponse::with_status(204)
                    }
                })
                .await;
            let amf_uri = format!("http://127.0.0.1:{}", amf_addr.port());
            let (udm, udm_uri, udm_seen) = producer_2102(
                SouthboundProducer::Udm,
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(204)),
            )
            .await;
            let now = now_unix_secs();
            for n in 0..4 {
                live_leg_2128(
                    SouthboundProducer::Amf,
                    &amf_uri,
                    &format!("s-2128-{n}"),
                    now + 10 + n,
                );
            }
            let udm_leg = live_leg_2128(SouthboundProducer::Udm, &udm_uri, "ee-2128", now + 20);

            let started = std::time::Instant::now();
            let report = refresh_live_subscriptions_at(now).await;
            let took = started.elapsed();
            let udm_expiry = nef_self()
                .read()
                .unwrap()
                .subscription_find(&udm_leg)
                .and_then(|s| s.southbound_expiry);
            amf.stop().await.ok();
            udm.stop().await.ok();

            assert_eq!(
                amf_patches.load(Ordering::SeqCst),
                1,
                "one refresh at the blackholed AMF: {report:?}"
            );
            assert_eq!(report.skipped, 3, "{report:?}");
            assert_eq!(report.refreshed, 1, "the UDM leg is refreshed: {report:?}");
            assert_eq!(requests_2102(&udm_seen, "PATCH").len(), 1);
            assert_eq!(udm_expiry, Some(now + southbound_lifetime_secs()));
            assert!(
                took < Duration::from_secs(SOUTHBOUND_REQUEST_TIMEOUT_SECS * 2 + 1),
                "about one request timeout: {took:?}"
            );
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #2148 (R42 on #2128): lapsed legs' DELETEs are bounded. Five legs lapse
    /// at once at an AMF that never answers a DELETE. The pass sends one (its
    /// timeout) and stops; all five subscriptions are removed and all five
    /// DELETEs stay owed for the #1877 reconciler. Before, each lapsed leg
    /// spawned its own DELETE task, with no bound.
    ///
    /// REVERT-VERIFIED: with one detached `southbound_unsubscribe` per lapsed leg
    /// again, the AMF receives five DELETEs and the `one DELETE` assertion fails.
    #[test]
    fn lapsed_legs_deletes_are_bounded_2148() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            nextgcore_sbi::security::set_sbi_profile_override(
                nextgcore_sbi::security::SbiProfile::Dev,
            );
            let deletes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = deletes.clone();
            let (amf, amf_addr) =
                nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                    let count = count.clone();
                    async move {
                        if req.header.method == "DELETE" {
                            count.fetch_add(1, Ordering::SeqCst);
                        }
                        tokio::time::sleep(Duration::from_secs(8)).await;
                        SbiResponse::with_status(204)
                    }
                })
                .await;
            let amf_uri = format!("http://127.0.0.1:{}", amf_addr.port());
            let now = now_unix_secs();
            let ids: Vec<String> = (0..5)
                .map(|n| {
                    live_leg_2128(
                        SouthboundProducer::Amf,
                        &amf_uri,
                        &format!("s-2148-{n}"),
                        now - 1,
                    )
                })
                .collect();
            let started = std::time::Instant::now();
            let report = refresh_live_subscriptions_at(now).await;
            let took = started.elapsed();
            tokio::time::sleep(Duration::from_millis(500)).await;
            let sent = deletes.load(Ordering::SeqCst);
            let owed: Vec<String> = southbound_reconcile::parked()
                .into_iter()
                .map(|r| r.subscription_id)
                .filter(|id| id.starts_with("s-2148-"))
                .collect();
            let held = ids
                .iter()
                .filter(|id| nef_self().read().unwrap().subscription_find(id).is_some())
                .count();
            amf.stop().await.ok();

            assert_eq!(report.lapsed, 5, "{report:?}");
            assert_eq!(held, 0, "every lapsed subscription is removed");
            assert_eq!(sent, 1, "one DELETE at the dead AMF this pass");
            assert_eq!(owed.len(), 5, "all five stay owed: {owed:?}");
            assert!(
                took < Duration::from_secs(SOUTHBOUND_REQUEST_TIMEOUT_SECS * 2 + 1),
                "about one request timeout: {took:?}"
            );
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #2128 (R42 minor 2, #2086): the snapshot that removes a lapsed leg's
    /// subscription already carries its owed DELETE, so a restart straight
    /// after the removal still sends it.
    ///
    /// REVERT-VERIFIED: with the `owe` in `remove_lapsed_leg` dropped, the
    /// snapshot has no owed unsubscribe and the `owed in the same snapshot`
    /// assertion fails.
    #[test]
    fn a_lapsed_legs_removal_is_persisted_with_its_owed_delete_2128() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        let path = std::env::temp_dir().join(format!(
            "nefd-2128-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&path);
        nef_self()
            .write()
            .unwrap()
            .set_state_file(path.clone())
            .expect("first boot");
        let id = live_leg_2128(
            SouthboundProducer::Amf,
            "http://127.0.0.1:9",
            "s-2128-owed",
            1,
        );
        let southbound = nef_self()
            .read()
            .unwrap()
            .subscription_find(&id)
            .and_then(|s| s.southbound)
            .expect("leg");
        remove_lapsed_leg(&id, &southbound);
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        southbound_reconcile::clear_for_test();
        nef_self().write().unwrap().detach_state_file_for_test();
        let _ = std::fs::remove_file(&path);
        reset_context();

        assert_eq!(on_disk["subscriptions"].as_array().map(Vec::len), Some(0));
        let owed = on_disk["parkedUnsubscribes"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            owed.iter().any(|r| r["subscription_id"] == "s-2128-owed"),
            "owed in the same snapshot: {on_disk}"
        );
    }

    /// #2128 (R42 minor 3): the expiry recorded is the one the producer
    /// GRANTED, not the one asked for, on create and on refresh: this AMF grants
    /// ten minutes less than asked each time.
    ///
    /// REVERT-VERIFIED: with `requested` recorded instead of
    /// `confirmed_expiry(..)` on create, the `granted on create` assertion
    /// fails; on refresh, the `granted on refresh` assertion fails.
    #[test]
    fn the_granted_expiry_is_recorded_2128() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        GRANT_CUT_2102.store(600, Ordering::SeqCst);
        block_on(async {
            let (amf, amf_uri, seen) = producer_2102(
                SouthboundProducer::Amf,
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(200)),
            )
            .await;
            set_producers(Some(&amf_uri), None);
            let resp = handle_monitoring_subscription_create(
                "af1",
                &monitoring_request(valid_monitoring_body()),
                NorthboundApi::T8MonitoringEvent,
            )
            .await;
            assert_eq!(resp.status, 201, "{:?}", resp.http.content);
            let id = created_subscription_id(&resp).expect("id");
            let recorded = || {
                nef_self()
                    .read()
                    .unwrap()
                    .subscription_find(&id)
                    .and_then(|s| s.southbound_expiry)
                    .expect("an expiry")
            };
            let asked = requests_2102(&seen, "POST")[0]
                .1
                .pointer("/subscription/options/expiry")
                .map(epoch_2102)
                .expect("asked");
            let e0 = recorded();
            let due = e0 - southbound_refresh_margin_secs();
            let report = refresh_live_subscriptions_at(due).await;
            let e1 = recorded();
            amf.stop().await.ok();

            assert_eq!(e0, asked - 600, "granted on create");
            assert_eq!(report.refreshed, 1, "{report:?}");
            assert_eq!(
                e1,
                due + southbound_lifetime_secs() - 600,
                "granted on refresh"
            );
        });
        GRANT_CUT_2102.store(0, Ordering::SeqCst);
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #2128 (R42 minor 4): the refresh margin leaves at least two refresh
    /// ticks, and the lifetime at least four, whatever
    /// `NEF_SOUTHBOUND_LIFETIME_SECS` says: at the 60 s minimum with the shipped
    /// 30 s tick, the lifetime is raised to 120 s and the margin is 60 s.
    ///
    /// REVERT-VERIFIED: with the four-tick floor dropped, a 60 s lifetime keeps
    /// a 30 s margin and the `two ticks` assertion fails.
    #[test]
    fn the_refresh_margin_leaves_two_ticks_2128() {
        for (configured, interval) in [
            (Some(60), 30),
            (Some(60), 1),
            (None, 30),
            (Some(100), 300),
            (Some(0), 30),
        ] {
            let (lifetime, margin) = refresh_timing(configured, interval);
            assert!(lifetime >= 60, "{configured:?}/{interval}");
            assert!(
                margin >= 2 * interval,
                "two ticks: {configured:?}/{interval}: {margin}"
            );
            assert!(margin < lifetime, "{configured:?}/{interval}");
        }
        assert_eq!(refresh_timing(Some(60), 30), (120, 60));
        assert_eq!(refresh_timing(None, 30), (3600, 1800));
    }

    fn deletes_1877(seen: &Seen1877) -> usize {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(m, u)| m == "DELETE" && u.ends_with("/subscriptions/s-1877"))
            .count()
    }

    /// #1877: a create the AF drops while the AMF's subscribe is out leaves no AMF
    /// subscription behind and no record: the create finishes on its own task, and
    /// the 201 nobody read is removed with its producer leg.
    ///
    /// REVERT-VERIFIED: with the create awaited inline again, this fails: the AMF
    /// subscription is never deleted.
    #[test]
    fn a_create_dropped_mid_subscribe_leaves_no_amf_subscription_1877() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let (amf, amf_uri, seen) = amf_1877(
                Duration::from_millis(300),
                Arc::new(std::sync::atomic::AtomicU16::new(204)),
            )
            .await;
            set_producers(Some(&amf_uri), None);
            let request = monitoring_request(valid_monitoring_body());
            {
                let mut create = Box::pin(handle_monitoring_subscription_create(
                    "af1",
                    &request,
                    NorthboundApi::T8MonitoringEvent,
                ));
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                while !seen.lock().unwrap().iter().any(|(m, _)| m == "POST") {
                    assert!(tokio::time::Instant::now() < deadline, "never subscribed");
                    if tokio::time::timeout(Duration::from_millis(5), &mut create)
                        .await
                        .is_ok()
                    {
                        panic!("answered before the subscribe was out");
                    }
                }
                // Dropped here: the AF went away.
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while deletes_1877(&seen) == 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let held = nef_self().read().unwrap().subscription_count();
            let deleted = deletes_1877(&seen);
            amf.stop().await.ok();
            assert_eq!(deleted, 1, "the AMF subscription is deleted");
            assert_eq!(held, 0, "and the NEF holds no record of it");
        });
        reset_context();
    }

    /// #1877 (R27 #1947): a create that finished, whose 201 the AF never read, is
    /// removed with its AMF subscription: the AF holds no `self` link to delete it by.
    ///
    /// REVERT-VERIFIED: with `CreateHandoff::abandon` ignoring a finished 201, this
    /// fails: the record and the AMF subscription stay.
    #[test]
    fn a_create_whose_201_is_never_read_is_removed_1877() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let (amf, amf_uri, seen) = amf_1877(
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(204)),
            )
            .await;
            set_producers(Some(&amf_uri), None);
            let request = monitoring_request(valid_monitoring_body());
            {
                let mut create = Box::pin(handle_monitoring_subscription_create(
                    "af1",
                    &request,
                    NorthboundApi::T8MonitoringEvent,
                ));
                // Polled once (enough to start it), then never read.
                let _ = tokio::time::timeout(Duration::from_millis(1), &mut create).await;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                while nef_self().read().unwrap().subscription_count() == 0 {
                    assert!(tokio::time::Instant::now() < deadline, "never stored");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                // Dropped here: the 201 is built and nobody reads it.
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while deletes_1877(&seen) == 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let held = nef_self().read().unwrap().subscription_count();
            let deleted = deletes_1877(&seen);
            amf.stop().await.ok();
            assert_eq!(held, 0, "the record is removed");
            assert_eq!(deleted, 1, "with its AMF subscription");
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #1877 (R27 #1947): an AF delete dropped while the AMF holds its producer
    /// DELETE does not lose it. The DELETE runs on its own task, so when the AMF then
    /// fails it the failure is still parked for the reconciler; the record it would
    /// be found by is already gone, so nothing else would retry it.
    ///
    /// REVERT-VERIFIED: with the producer DELETE awaited inline again, this fails:
    /// the dropped request takes the DELETE's outcome with it and nothing is parked.
    #[test]
    fn a_delete_dropped_mid_producer_delete_still_reconciles_it_1877() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let status = Arc::new(std::sync::atomic::AtomicU16::new(204));
            let (amf, amf_uri, seen) = amf_1877(Duration::ZERO, status.clone()).await;
            set_producers(Some(&amf_uri), None);
            let created = handle_monitoring_subscription_create(
                "af1",
                &monitoring_request(valid_monitoring_body()),
                NorthboundApi::T8MonitoringEvent,
            )
            .await;
            let sub_id = created_subscription_id(&created).expect("id");
            // The AMF now holds a DELETE 300 ms, then fails it.
            status.store(503, Ordering::SeqCst);
            DELETE_DELAY_1877.store(300, Ordering::SeqCst);
            let request = SbiRequest::delete(format!(
                "/3gpp-monitoring-event/v1/af1/subscriptions/{sub_id}"
            ));
            {
                let mut delete = Box::pin(handle_monitoring_subscription_delete(
                    "af1", &sub_id, &request,
                ));
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                while deletes_1877(&seen) == 0 {
                    assert!(tokio::time::Instant::now() < deadline, "DELETE never sent");
                    let _ = tokio::time::timeout(Duration::from_millis(5), &mut delete).await;
                }
                // Dropped here, while the AMF holds the DELETE: the AF went away.
            }
            let ours = |r: &SouthboundRef| r.subscription_id == "s-1877";
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while !southbound_reconcile::parked().iter().any(ours)
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let parked = southbound_reconcile::parked().iter().any(ours);
            let held = nef_self().read().unwrap().subscription_count();
            DELETE_DELAY_1877.store(0, Ordering::SeqCst);
            amf.stop().await.ok();
            assert_eq!(held, 0, "the record is gone");
            assert!(parked, "and the failed DELETE is parked for the reconciler");
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #1877 (R27 #1947 minor): a parked producer DELETE goes to the producer the
    /// subscription was made at, not to whichever AMF is configured when it is
    /// retried (the new one answers 404 while the old one keeps the subscription).
    ///
    /// REVERT-VERIFIED: with the configured URI used instead of `producer_base`, this
    /// fails: the retry goes to the new AMF.
    #[test]
    fn a_retried_unsubscribe_goes_to_the_producer_it_was_made_at_1877() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let status = Arc::new(std::sync::atomic::AtomicU16::new(503));
            let (old_amf, old_uri, old_seen) = amf_1877(Duration::ZERO, status.clone()).await;
            let (new_amf, new_uri, new_seen) = amf_1877(
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(404)),
            )
            .await;
            set_producers(Some(&old_uri), None);
            let created = handle_monitoring_subscription_create(
                "af1",
                &monitoring_request(valid_monitoring_body()),
                NorthboundApi::T8MonitoringEvent,
            )
            .await;
            let sub_id = created_subscription_id(&created).expect("id");
            let request = SbiRequest::delete(format!(
                "/3gpp-monitoring-event/v1/af1/subscriptions/{sub_id}"
            ));
            handle_monitoring_subscription_delete("af1", &sub_id, &request).await;
            // The operator re-points the NEF at another AMF; the old one recovers.
            set_producers(Some(&new_uri), None);
            status.store(204, Ordering::SeqCst);
            southbound_reconcile::reconcile_once().await;
            let (to_old, to_new) = (deletes_1877(&old_seen), deletes_1877(&new_seen));
            old_amf.stop().await.ok();
            new_amf.stop().await.ok();
            assert_eq!(
                to_old, 2,
                "failed once, then delivered at the AMF it was made at"
            );
            assert_eq!(to_new, 0, "never sent to the AMF configured later");
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #1877 (R30 #1954): a parked unsubscribe toward a blackholed producer does
    /// not starve one toward a healthy producer behind it. The one tried and failed
    /// goes to the back, the untried keeps its turn, so the healthy one is sent on
    /// the next pass.
    ///
    /// REVERT-VERIFIED: with every entry re-parked at the front in order, as before,
    /// this fails: the healthy producer's DELETE is never sent.
    #[test]
    fn a_blackholed_producer_does_not_starve_a_healthy_one_1877() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            nextgcore_sbi::security::set_sbi_profile_override(
                nextgcore_sbi::security::SbiProfile::Dev,
            );
            let blackhole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let hole = blackhole.local_addr().unwrap();
            let held = tokio::spawn(async move {
                let mut conns = Vec::new();
                while let Ok((c, _)) = blackhole.accept().await {
                    conns.push(c);
                }
            });
            let (amf, amf_uri, seen) = amf_1877(
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(204)),
            )
            .await;
            let at = |base: String, id: &str| SouthboundRef {
                producer: SouthboundProducer::Amf,
                subscription_id: id.to_string(),
                delete_path: format!("/namf-evts/v1/subscriptions/{id}"),
                producer_base: Some(base),
            };
            southbound_reconcile::park(at(format!("http://{hole}"), "dead-1877"));
            southbound_reconcile::park(at(amf_uri.clone(), "s-1877"));

            southbound_reconcile::reconcile_once().await;
            southbound_reconcile::reconcile_once().await;
            let delivered = deletes_1877(&seen);
            let dead_parked = southbound_reconcile::parked()
                .iter()
                .any(|r| r.subscription_id == "dead-1877");
            held.abort();
            amf.stop().await.ok();
            assert_eq!(delivered, 1, "the healthy producer's DELETE is sent");
            assert!(dead_parked, "the blackholed one stays parked");
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #1877 (R27 #1972): several unsubscribes toward one failing producer cost one
    /// attempt per pass, not one each (the rest of that producer's are skipped for
    /// the pass), and a healthy producer behind them is still served in that pass.
    /// A second pass inside the producer's backoff tries it not at all.
    ///
    /// REVERT-VERIFIED: with the backoff disabled, this fails: three attempts at the
    /// failing producer in one pass.
    #[test]
    fn a_failing_producer_costs_one_attempt_per_pass_and_backs_off_1877() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            nextgcore_sbi::security::set_sbi_profile_override(
                nextgcore_sbi::security::SbiProfile::Dev,
            );
            let (dead, dead_uri, dead_seen) = amf_1877(
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(503)),
            )
            .await;
            let (live, live_uri, live_seen) = amf_1877(
                Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicU16::new(204)),
            )
            .await;
            let at = |base: &str, id: &str| SouthboundRef {
                producer: SouthboundProducer::Amf,
                subscription_id: id.to_string(),
                delete_path: format!("/namf-evts/v1/subscriptions/{id}"),
                producer_base: Some(base.to_string()),
            };
            for n in 0..3 {
                southbound_reconcile::park(at(&dead_uri, &format!("dead-{n}")));
            }
            southbound_reconcile::park(at(&live_uri, "s-1877"));
            let attempts = |seen: &Seen1877| {
                seen.lock()
                    .unwrap()
                    .iter()
                    .filter(|(m, _)| m == "DELETE")
                    .count()
            };

            southbound_reconcile::reconcile_once().await;
            let first = (attempts(&dead_seen), deletes_1877(&live_seen));
            southbound_reconcile::reconcile_once().await;
            let second = attempts(&dead_seen);
            tokio::time::sleep(southbound_reconcile::BACKOFF_BASE + Duration::from_millis(100))
                .await;
            southbound_reconcile::reconcile_once().await;
            let third = attempts(&dead_seen);
            dead.stop().await.ok();
            live.stop().await.ok();

            assert_eq!(
                first,
                (1, 1),
                "one attempt at the failing producer, the healthy one served"
            );
            assert_eq!(second, 1, "none inside its backoff");
            assert_eq!(third, 2, "one again once the backoff ran out");
        });
        southbound_reconcile::clear_for_test();
        reset_context();
    }

    /// #1994: a pass forgets the backoff of a producer with nothing parked, and
    /// keeps that of one still holding parked unsubscribes.
    ///
    /// REVERT-VERIFIED: with `prune_backoff` a no-op, this fails: the producer
    /// with nothing parked keeps its backoff.
    #[test]
    fn a_producer_with_nothing_parked_is_pruned_1994() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        // Neither is contacted: one has nothing parked, the other is backing off.
        let gone = "http://127.0.0.1:9/gone-1994";
        let kept = "http://127.0.0.1:9/kept-1994";
        southbound_reconcile::note_failure_for_test(gone);
        southbound_reconcile::note_failure_for_test(kept);
        southbound_reconcile::park(SouthboundRef {
            producer: SouthboundProducer::Amf,
            subscription_id: "kept-1994".to_string(),
            delete_path: "/namf-evts/v1/subscriptions/kept-1994".to_string(),
            producer_base: Some(kept.to_string()),
        });

        block_on(southbound_reconcile::reconcile_once());
        let after = (
            southbound_reconcile::backoff_of(gone),
            southbound_reconcile::backoff_of(kept),
        );
        southbound_reconcile::clear_for_test();
        reset_context();

        assert_eq!(after.0, None, "nothing parked: pruned");
        assert_eq!(
            after.1,
            Some(southbound_reconcile::BACKOFF_BASE),
            "still parked: kept"
        );
    }

    /// #1877: an AF delete whose AMF unsubscribe fails is parked and retried until
    /// the AMF takes it; the record is gone at once.
    ///
    /// REVERT-VERIFIED: with `southbound_unsubscribe` not parking a failure, this
    /// fails: nothing is parked and the AMF keeps the subscription.
    #[test]
    fn a_failed_unsubscribe_is_reconciled_1877() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        block_on(async {
            let status = Arc::new(std::sync::atomic::AtomicU16::new(503));
            let (amf, amf_uri, seen) = amf_1877(Duration::ZERO, status.clone()).await;
            set_producers(Some(&amf_uri), None);
            let created = handle_monitoring_subscription_create(
                "af1",
                &monitoring_request(valid_monitoring_body()),
                NorthboundApi::T8MonitoringEvent,
            )
            .await;
            assert_eq!(created.status, 201);
            let sub_id = created_subscription_id(&created).expect("id");
            let deleted = handle_monitoring_subscription_delete(
                "af1",
                &sub_id,
                &SbiRequest::delete(format!(
                    "/3gpp-monitoring-event/v1/af1/subscriptions/{sub_id}"
                )),
            )
            .await;
            let ours = |r: &SouthboundRef| r.subscription_id == "s-1877";
            let parked_after_delete = southbound_reconcile::parked().iter().any(ours);
            let held = nef_self().read().unwrap().subscription_count();
            status.store(204, Ordering::SeqCst);
            southbound_reconcile::reconcile_once().await;
            let parked_after = southbound_reconcile::parked().iter().any(ours);
            let tries = deletes_1877(&seen);
            amf.stop().await.ok();
            southbound_reconcile::clear_for_test();

            assert_eq!(deleted.status, 204);
            assert_eq!(held, 0, "the record goes at once");
            assert!(parked_after_delete, "the failed unsubscribe is parked");
            assert!(!parked_after, "and delivered once the AMF answers");
            assert_eq!(tries, 2, "once at delete, once reconciled");
        });
        reset_context();
    }

    /// #2086 (R30's audit): with a state file, the unsubscribe a deleted
    /// subscription owes survives a restart. Right after the AF's DELETE (the
    /// AMF answering 503), the snapshot on disk no longer holds the subscription
    /// and does hold the owed AMF unsubscribe; a NEF restarted from that file
    /// parks it again, and its reconciler delivers it once the AMF answers.
    ///
    /// REVERT-VERIFIED: with the owed set left out of the snapshot, the
    /// restarted NEF parks nothing and the AMF keeps the subscription.
    #[test]
    fn an_owed_unsubscribe_survives_a_restart_2086() {
        let _guard = lock_globals();
        southbound_reconcile::clear_for_test();
        reset_context();
        let path = std::env::temp_dir().join(format!(
            "nefd-2086-{}-{}.json",
            std::process::id(),
            now_unix_secs()
        ));
        let _ = std::fs::remove_file(&path);
        nef_self()
            .write()
            .unwrap()
            .set_state_file(path.clone())
            .expect("first boot");
        block_on(async {
            let status = Arc::new(std::sync::atomic::AtomicU16::new(503));
            let (amf, amf_uri, seen) = amf_1877(Duration::ZERO, status.clone()).await;
            set_producers(Some(&amf_uri), None);
            let created = handle_monitoring_subscription_create(
                "af1",
                &monitoring_request(valid_monitoring_body()),
                NorthboundApi::T8MonitoringEvent,
            )
            .await;
            assert_eq!(created.status, 201);
            let sub_id = created_subscription_id(&created).expect("id");
            let deleted = handle_monitoring_subscription_delete(
                "af1",
                &sub_id,
                &SbiRequest::delete(format!(
                    "/3gpp-monitoring-event/v1/af1/subscriptions/{sub_id}"
                )),
            )
            .await;
            assert_eq!(deleted.status, 204);
            let on_disk: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(on_disk["subscriptions"].as_array().map(Vec::len), Some(0));
            let owed = on_disk["parkedUnsubscribes"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert!(
                owed.iter().any(|r| r["subscription_id"] == "s-1877"),
                "the owed unsubscribe is on disk: {on_disk}"
            );

            // The restart: the in-memory set is gone; the file restores it.
            southbound_reconcile::clear_for_test();
            let mut restarted = context::NefContext::new();
            restarted.init(16, 16);
            restarted.set_state_file(path.clone()).expect("restored");
            let ours = |r: &SouthboundRef| r.subscription_id == "s-1877";
            assert!(
                southbound_reconcile::parked().iter().any(ours),
                "the restarted NEF owes it again"
            );
            status.store(204, Ordering::SeqCst);
            southbound_reconcile::reconcile_once().await;
            assert!(!southbound_reconcile::parked().iter().any(ours));
            assert_eq!(
                deletes_1877(&seen),
                2,
                "once at delete, once after the restart"
            );
            amf.stop().await.ok();
        });
        southbound_reconcile::clear_for_test();
        nef_self().write().unwrap().detach_state_file_for_test();
        let _ = std::fs::remove_file(&path);
        reset_context();
    }

    /// **Issue #111, criterion 1.** Every `serviceName` in the NRF profile resolves
    /// to a real northbound route, not to the router's `send_not_found`.
    ///
    /// The profile advertised `nnef-eventexposure` while the only thing mounted
    /// under that API root was the internal producer notification SINK, so an
    /// interop partner that discovered this NEF for `Nnef_EventExposure` got a 404
    /// from the fallthrough. This asserts the catalogue and the router agree.
    #[test]
    fn every_advertised_service_name_has_a_northbound_route() {
        let _guard = lock_globals();
        reset_context();

        let profile = build_nf_profile(
            "nef-test",
            "127.0.0.1",
            7817,
            nextgcore_sbi::types::UriScheme::Http,
        );
        let names: Vec<String> = profile["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .filter_map(|s| s["serviceName"].as_str().map(str::to_string))
            .collect();
        assert!(!names.is_empty(), "the profile must advertise something");

        for name in &names {
            // The advertised service's subscription resource must not 404. A
            // deliberately-invalid body is used so this asserts ROUTING, not
            // validation: a 400 proves the route exists and rejected the body,
            // where a 404 would prove nothing is mounted.
            let request = SbiRequest::post(format!("/{name}/v1/subscriptions"))
                .with_json_body(&serde_json::json!({}))
                .expect("serialize");
            let response = block_on(nef_sbi_request_handler(request));
            assert_ne!(
                response.status, 404,
                "advertised service '{name}' has no northbound route (got 404)"
            );
        }
    }

    /// **Issue #111, criterion 2.** The advertised `Nnef_EventExposure` subscribe
    /// works, and an event this NEF cannot serve is refused BY NAME rather than
    /// accepted.
    #[test]
    fn nnef_event_exposure_subscribe_is_served_and_unsupported_events_are_refused() {
        let _guard = lock_globals();
        reset_context();
        set_producers(None, None);

        let body = serde_json::json!({
            "notifUri": "http://af.example.com:8080/notifications",
            "notifId": "af-corr-1",
            "nefEventSubs": [{ "eventId": "LOCATION_REPORT", "supi": "imsi-001010000000001" }],
        });
        let request = SbiRequest::post("/nnef-eventexposure/v1/subscriptions")
            .with_json_body(&body)
            .expect("serialize");
        let response = block_on(nef_sbi_request_handler(request));
        assert_eq!(
            response.status, 201,
            "the advertised operation must be served"
        );
        let location = response
            .http
            .get_header("location")
            .expect("201 must carry Location")
            .clone();
        assert!(
            location.starts_with("/nnef-eventexposure/v1/subscriptions/"),
            "the created resource must live under the API it was created on, got {location}"
        );

        // The subscription really exists and is DELETE-able through the same API.
        let sub_id = location.rsplit('/').next().unwrap().to_string();
        // #2154: and it is recorded as made on Nnef_EventExposure, which decides
        // the shape of its notifications.
        assert_eq!(
            nef_self()
                .read()
                .unwrap()
                .subscription_find(&sub_id)
                .map(|s| s.northbound_api),
            Some(NorthboundApi::NnefEventExposure)
        );
        let delete = SbiRequest::delete(format!("/nnef-eventexposure/v1/subscriptions/{sub_id}"));
        assert_eq!(block_on(nef_sbi_request_handler(delete)).status, 204);

        // An eventId outside the served set is 501 naming it -- not a 201 for an
        // event that would never fire.
        let unsupported = serde_json::json!({
            "notifUri": "http://af.example.com:8080/notifications",
            "notifId": "af-corr-2",
            "nefEventSubs": [{ "eventId": "PDN_CONNECTIVITY_STATUS", "supi": "imsi-001010000000001" }],
        });
        let request = SbiRequest::post("/nnef-eventexposure/v1/subscriptions")
            .with_json_body(&unsupported)
            .expect("serialize");
        let response = block_on(nef_sbi_request_handler(request));
        assert_eq!(response.status, 501);
        assert!(
            response
                .http
                .content
                .as_deref()
                .unwrap_or("")
                .contains("PDN_CONNECTIVITY_STATUS"),
            "the refusal must name the event so the consumer knows what to change"
        );

        // Mandatory IEs are enforced.
        for missing in ["notifUri", "notifId", "nefEventSubs"] {
            let mut partial = body.clone();
            partial.as_object_mut().unwrap().remove(missing);
            let request = SbiRequest::post("/nnef-eventexposure/v1/subscriptions")
                .with_json_body(&partial)
                .expect("serialize");
            assert_eq!(
                block_on(nef_sbi_request_handler(request)).status,
                400,
                "a body with no {missing} must be rejected"
            );
        }
    }

    /// **Issue #111, criterion 4.** A monitoring create whose southbound producer
    /// cannot be reached does NOT return 201.
    ///
    /// Before this, `attempt_southbound_subscribe` returned `None` for four
    /// different reasons -- unconfigured, unparseable URI, producer rejected,
    /// transport error -- and the caller turned all four into `201 Created` with a
    /// `self` link, so the AF believed it held a live subscription that could never
    /// notify, with no error to drive a retry.
    #[test]
    fn a_southbound_failure_is_not_reported_as_created() {
        let _guard = lock_globals();
        reset_context();

        // An unreachable producer is a retryable dependency failure -> 503, and
        // above all NOT 201. This is the case that used to be indistinguishable
        // from success.
        // `refused_port`, not `free_port`: a free port can be handed to a sibling test's
        // `bind(:0)`, and then the "dead" peer answers. See `refused_port`.
        let dead_port = nextgcore_sbi::test_support::refused_port();
        set_producers(Some(&format!("http://127.0.0.1:{dead_port}")), None);
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &monitoring_request(valid_monitoring_body()),
            NorthboundApi::T8MonitoringEvent,
        ));
        assert_ne!(
            response.status, 201,
            "a failed leg must never be reported as created"
        );
        assert_eq!(
            response.status, 503,
            "an unreachable producer is a transient dependency failure"
        );
        assert!(response
            .http
            .content
            .as_deref()
            .unwrap_or("")
            .contains("SUBSCRIPTION_NOT_ESTABLISHED"));
        assert_eq!(
            nef_self().read().unwrap().subscription_count(),
            0,
            "a rejected create must not leave a subscription behind"
        );

        // A syntactically odd URI is NOT the non-retryable case: `parse_host_port`
        // accepts it (host with a default port) and the connect then fails, so it
        // lands on the same 503. Asserted rather than assumed -- the first draft of
        // this test expected 500 and was wrong about which branch it exercised.
        set_producers(Some("not a uri"), None);
        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &monitoring_request(valid_monitoring_body()),
            NorthboundApi::T8MonitoringEvent,
        ));
        assert_eq!(response.status, 503);
        assert_eq!(nef_self().read().unwrap().subscription_count(), 0);
    }

    /// **Issue #111.** The retryable/non-retryable split maps to distinct statuses.
    ///
    /// Tested on the mapping directly because the non-retryable branch needs a
    /// producer that ANSWERS unusably (a non-2xx, or a 201 with no extractable
    /// subscription id), which needs a stub server; asserting the mapping here keeps
    /// the claim honest without one, and the wire test above covers 503 end to end.
    #[test]
    fn southbound_failure_statuses_distinguish_transient_from_unusable() {
        let transient = SouthboundOutcome::failure_response(true, "AMF unreachable");
        assert_eq!(transient.status, 503, "a dependency that may return");
        let unusable = SouthboundOutcome::failure_response(false, "AMF returned status 403");
        assert_eq!(unusable.status, 500, "a producer that answered unusably");
        for response in [transient, unusable] {
            let body = response.http.content.as_deref().unwrap_or("");
            assert!(
                body.contains("SUBSCRIPTION_NOT_ESTABLISHED"),
                "the cause must name what failed, got {body}"
            );
            assert_ne!(response.status, 201);
        }
    }

    /// #1518: a stored subscription with a live leg at `producer`, and its token.
    fn insert_sub_1518(
        id: &str,
        producer: Option<SouthboundProducer>,
        tokened: bool,
    ) -> Option<String> {
        let mut sub = NefMonitoringSubscription::new(
            "af-1518",
            "UE_REACHABILITY",
            "http://127.0.0.1:9/cb",
            "{}",
        );
        sub.id = id.to_string();
        sub.southbound = producer.map(|producer| crate::context::SouthboundRef {
            producer,
            subscription_id: format!("p-{id}"),
            delete_path: format!("/x/{id}"),
            producer_base: None,
        });
        if !tokened {
            sub.notify_token = None;
        }
        let token = sub.notify_token.as_ref().map(|t| t.as_str().to_string());
        nef_self()
            .read()
            .unwrap()
            .subscription_insert(sub)
            .expect("insert");
        token
    }

    /// #1518: the composition root registers the tokened producer route, behind a
    /// verified peer, and nothing else.
    #[test]
    fn the_nef_registers_its_callback_exemption_1518() {
        let routes: Vec<String> = oauth2_callback_exemptions()
            .iter()
            .map(|e| e.route())
            .collect();
        assert_eq!(
            routes,
            ["POST /nnef-eventexposure/v1/notify/{var}/nef-ee-notify/{token}"]
        );
    }

    /// #1518: whatever admitted it, a producer notification reaches the handler only
    /// with its subscription's current token, or token-less for a subscription
    /// persisted from before #1518. A body-less POST tells them apart: the handler
    /// answers 400, the gate 404.
    ///
    /// REVERT-VERIFIED: with `admits_notify` always true, the forged,
    /// cross-subscription and token-less cases reach the handler; with the
    /// token-less rule per NEF rather than per subscription, the tokened one's
    /// token-less URI does.
    #[test]
    fn a_producer_notification_is_acted_on_only_on_its_token_1518() {
        let _guard = lock_globals();
        reset_context();
        let a = insert_sub_1518("sub-1518-a", Some(SouthboundProducer::Amf), true).unwrap();
        let b = insert_sub_1518("sub-1518-b", Some(SouthboundProducer::Amf), true).unwrap();
        insert_sub_1518("sub-1518-l", Some(SouthboundProducer::Amf), false);
        let status =
            |path: String| block_on(nef_sbi_request_handler(SbiRequest::post(path))).status;
        let base = "/nnef-eventexposure/v1/notify";
        assert_eq!(status(format!("{base}/sub-1518-a/nef-ee-notify/{a}")), 400);
        for path in [
            format!("{base}/sub-1518-a/nef-ee-notify/0123456789abcdef0123456789abcdef"),
            format!("{base}/sub-1518-a/nef-ee-notify/{b}"),
            format!("{base}/sub-1518-b/nef-ee-notify/{a}"),
            format!("{base}/sub-1518-a"),
            format!("{base}/sub-1518-l/nef-ee-notify/{a}"),
            format!("{base}/sub-1518-a/other-notify/{a}"),
            format!("{base}/no-such/nef-ee-notify/{a}"),
        ] {
            assert_eq!(status(path.clone()), 404, "{path}");
        }
        assert_eq!(
            status(format!("{base}/sub-1518-l")),
            400,
            "the pre-#1518 subscription"
        );
    }

    /// #1518: the route admits, without a bearer, only a verified certificate of a
    /// type that notifies for that subscription (an AMF leg: AMF; a UDM leg: UDM or
    /// AMF) with its current token. Over plaintext on an OAuth2-required listener the
    /// right token is therefore still 401.
    ///
    /// REVERT-VERIFIED: without the NF-type check the SMF and untyped certificates
    /// are admitted; with the UDM leg admitting only a UDM, the AMF is refused there;
    /// registered token-only, the plaintext right-token request is not 401.
    #[test]
    fn the_producer_route_admits_only_its_notifiers_1518() {
        use nextgcore_sbi::callback_auth::VerifiedPeer;
        let _guard = lock_globals();
        reset_context();
        let a = insert_sub_1518("sub-1518-pa", Some(SouthboundProducer::Amf), true).unwrap();
        let u = insert_sub_1518("sub-1518-pu", Some(SouthboundProducer::Udm), true).unwrap();
        let n = insert_sub_1518("sub-1518-pn", None, true).unwrap();
        insert_sub_1518("sub-1518-pl", Some(SouthboundProducer::Amf), false);
        let exemptions = oauth2_callback_exemptions();
        let admits = |path: String, types: Option<&[&str]>| {
            let peer = types.map(|t| VerifiedPeer {
                nf_instance_id: "4e3c1518-0000-4000-8000-0000000000ee".to_string(),
                nf_types: t.iter().map(|s| s.to_string()).collect(),
            });
            block_on(nextgcore_sbi::callback_auth::admits_without_bearer_from(
                &exemptions,
                "POST",
                &path,
                peer.as_ref(),
            ))
        };
        let p = |id: &str, t: &str| format!("/nnef-eventexposure/v1/notify/{id}/nef-ee-notify/{t}");
        assert!(admits(p("sub-1518-pa", &a), Some(&["AMF"])));
        assert!(!admits(p("sub-1518-pa", &a), Some(&["UDM"])));
        assert!(!admits(p("sub-1518-pa", &a), Some(&[])));
        assert!(!admits(p("sub-1518-pa", &a), None));
        assert!(admits(p("sub-1518-pu", &u), Some(&["UDM"])));
        assert!(admits(p("sub-1518-pu", &u), Some(&["AMF"])));
        assert!(!admits(p("sub-1518-pu", &u), Some(&["SMF"])));
        assert!(
            !admits(p("sub-1518-pn", &n), Some(&["AMF"])),
            "no leg, no notifier"
        );
        assert!(
            !admits(p("sub-1518-pa", &u), Some(&["AMF"])),
            "another's token"
        );
        assert!(!admits(
            p("sub-1518-pa", "0123456789abcdef0123456789abcdef"),
            Some(&["AMF"])
        ));
        assert!(!admits(p("sub-1518-pl", &a), Some(&["AMF"])));
        assert!(!admits(
            "/nnef-eventexposure/v1/notify/sub-1518-pl".to_string(),
            Some(&["AMF"])
        ));

        // Real HTTP: an OAuth2-required listener with an empty JWKS and the
        // exemption. Plaintext carries no certificate, so everything is 401.
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
                let mut cfg = SbiServerConfig::new(addr)
                    .with_oauth2_callback_exemptions(oauth2_callback_exemptions());
                cfg.require_oauth2 = true;
                cfg.oauth2_jwks = Some(serde_json::json!({"keys": []}));
                let server = SbiServer::on_listener(cfg, listener);
                server.start(nef_sbi_request_handler).await.expect("start");
                let client =
                    nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
                let mut got = Vec::new();
                for path in [
                    p("sub-1518-pa", &a),
                    p("sub-1518-pa", "0123456789abcdef0123456789abcdef"),
                    "/nnef-eventexposure/v1/notify/sub-1518-pl".to_string(),
                ] {
                    let req = SbiRequest::post(path.clone())
                        .with_body("{}".to_string(), "application/json");
                    let status =
                        tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
                            .await
                            .expect("bounded")
                            .expect("response")
                            .status;
                    got.push((path, status));
                }
                server.stop().await.ok();
                for (path, status) in got {
                    assert_eq!(status, 401, "{path}");
                }
            });
    }

    /// #1518: a subscription record persisted before #1518 (no `notify_token`)
    /// restores token-less, and a rewrite keeps it so; one made since round-trips
    /// its token. Debug output carries no token.
    #[test]
    fn a_pre_1518_subscription_restores_token_less_1518() {
        let sub = NefMonitoringSubscription::new("af", "T", "http://af/n", "{}");
        let token = sub.notify_token.clone().unwrap();
        assert!(!format!("{sub:?}").contains(token.as_str()));
        let mut json = serde_json::to_value(&sub).unwrap();
        let back: NefMonitoringSubscription = serde_json::from_value(json.clone()).unwrap();
        assert!(back.admits_notify(Some(token.as_str())));
        json.as_object_mut().unwrap().remove("notify_token");
        let old: NefMonitoringSubscription = serde_json::from_value(json).unwrap();
        assert!(old.notify_token.is_none());
        assert!(old.admits_notify(None));
        let rewritten: NefMonitoringSubscription =
            serde_json::from_value(serde_json::to_value(&old).unwrap()).unwrap();
        assert!(rewritten.admits_notify(None) && !rewritten.admits_notify(Some(token.as_str())));
        assert!(!back.admits_notify(None));
    }

    /// **Issue #111, criteria 4 + 5.** With no producer configured the leg is
    /// DEFERRED: the create is accepted, the subscription is marked pending, and the
    /// reconciler later promotes or expires it -- never leaves it accepted and
    /// permanently un-notifiable.
    #[test]
    fn a_deferred_leg_is_pending_and_the_reconciler_expires_it() {
        let _guard = lock_globals();
        reset_context();
        set_producers(None, None);

        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &monitoring_request(valid_monitoring_body()),
            NorthboundApi::T8MonitoringEvent,
        ));
        assert_eq!(
            response.status, 201,
            "an unconfigured producer is a deployment state, not a request error"
        );
        let subs = nef_self().read().unwrap().subscriptions_pending();
        assert_eq!(subs.len(), 1, "the leg must be retained for retry");
        let pending = subs[0].pending.as_ref().expect("pending leg");
        assert!(
            subs[0].southbound.is_none(),
            "pending and live are exclusive"
        );
        assert!(
            !pending.path.is_empty(),
            "the retry request must be retained"
        );
        // #1518: the retained body names the subscription's tokened callback, so a
        // promotion hands the producer the URI the router admits.
        let token = subs[0].notify_token.clone().expect("tokened");
        assert!(
            pending.body["subscription"]["eventNotifyUri"]
                .as_str()
                .unwrap_or_default()
                .ends_with(&format!(
                    "/nnef-eventexposure/v1/notify/{}/nef-ee-notify/{}",
                    subs[0].id,
                    token.as_str()
                )),
            "{}",
            pending.body
        );

        // A sweep inside the deadline leaves it pending -- it is retried, not
        // discarded on the first failure.
        std::env::set_var("NEF_PENDING_LEG_DEADLINE_SECS", "3600");
        let report = block_on(reconcile_pending_subscriptions());
        assert_eq!(
            report,
            ReconcileReport {
                promoted: 0,
                expired: 0,
                still_pending: 1
            }
        );
        assert_eq!(nef_self().read().unwrap().subscription_count(), 1);

        // Past the deadline it is EXPIRED and removed: an AF whose subscription is
        // gone can re-create it, whereas one holding an un-notifiable subscription
        // has no signal at all.
        std::env::set_var("NEF_PENDING_LEG_DEADLINE_SECS", "0");
        let report = block_on(reconcile_pending_subscriptions());
        std::env::remove_var("NEF_PENDING_LEG_DEADLINE_SECS");
        assert_eq!(report.expired, 1, "a leg past its deadline must be expired");
        assert_eq!(
            nef_self().read().unwrap().subscription_count(),
            0,
            "an expired subscription must not be left accepted-and-dead"
        );

        // And a sweep with nothing pending is a no-op.
        assert_eq!(
            block_on(reconcile_pending_subscriptions()),
            ReconcileReport::default()
        );
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
        let response = block_on(handle_producer_notification("absent", None, &request));
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
        let notification = build_monitoring_notification(&sub, &producer_body)
            .expect("a REACHABILITY_REPORT on a UE_REACHABILITY subscription is forwarded");
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

    /// **#2154** (R42 on #2152): a Nnef_EventExposure subscriber is notified in
    /// the TS 29.591 NefEventExposureNotif shape (notifId, eventNotifs[{event,
    /// timeStamp}]), with the eventId it subscribed to, not the T8
    /// MonitoringNotification; a T8 subscriber still gets T8.
    ///
    /// REVERT-VERIFIED: with the API branch removed, the Nnef subscriber gets the
    /// T8 body and the `notifId` assertion fails.
    #[test]
    fn a_nnef_subscriber_is_notified_in_the_ts_29_591_shape_2154() {
        let producer_body = serde_json::json!({
            "reportList": [{
                "type": "REACHABILITY_REPORT",
                "reachability": "REACHABLE",
                "timeStamp": "2026-11-20T03:00:00Z",
            }]
        });
        let nnef = NefMonitoringSubscription::new(
            "consumer-notif-2154",
            "UE_REACHABILITY",
            "http://consumer.example.com/cb",
            "{}",
        )
        .with_northbound_api(NorthboundApi::NnefEventExposure);
        assert_eq!(
            build_monitoring_notification(&nnef, &producer_body),
            Some(serde_json::json!({
                "notifId": "consumer-notif-2154",
                "eventNotifs": [{ "event": "UE_REACHABILITY", "timeStamp": "2026-11-20T03:00:00Z" }],
            }))
        );
        let t8 = NefMonitoringSubscription::new(
            "af1",
            "UE_REACHABILITY",
            "http://af.example.com/cb",
            "{}",
        );
        let body = build_monitoring_notification(&t8, &producer_body).expect("T8");
        assert_eq!(
            body["monitoringEventReports"][0]["monitoringType"],
            "UE_REACHABILITY"
        );
        assert!(body.get("notifId").is_none());
        // LOCATION_REPORTING maps back to the eventId LOCATION_REPORT.
        let loc = NefMonitoringSubscription {
            monitoring_type: "LOCATION_REPORTING".to_string(),
            ..nnef.clone()
        };
        let body = build_monitoring_notification(
            &loc,
            &serde_json::json!({ "reportList": [{ "type": "LOCATION_REPORT", "location": {} }] }),
        )
        .expect("a location report");
        assert_eq!(body["eventNotifs"][0]["event"], "LOCATION_REPORT");
        assert!(body["eventNotifs"][0]["timeStamp"].is_string(), "{body}");
    }

    #[test]
    fn build_monitoring_notification_location_report() {
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
        let notification = build_monitoring_notification(&sub, &producer_body)
            .expect("a LOCATION_REPORT on a LOCATION_REPORTING subscription is forwarded");
        let report = &notification["monitoringEventReports"][0];
        assert_eq!(report["monitoringType"], "LOCATION_REPORTING");
        assert_eq!(
            report["locationInfo"],
            serde_json::json!({"nrLocation": {"tai": {}}})
        );
    }

    /// **Issue #1439.** A report is labelled with ITS OWN event type, and a report
    /// of another type is dropped and counted, never relabelled with the
    /// subscription's type. A body with nothing left yields no notification at all
    /// (it used to yield one bare report of the subscribed type).
    ///
    /// The bodies are the shapes udmd and amfd actually send: udmd
    /// `notify::build_monitoring_report` (`reportList[].eventType`) and amfd
    /// `fire_ue_event` (`reportList[].type`).
    ///
    /// Revert-verified: stamping `sub.monitoring_type` on every report again (the
    /// pre-#1439 builder) fails the mismatch assertions.
    #[test]
    fn build_monitoring_notification_keeps_the_reported_type_and_drops_mismatches() {
        let sub = NefMonitoringSubscription::new(
            "af3",
            "LOSS_OF_CONNECTIVITY",
            "http://af.example.com/cb",
            "{}",
        )
        .with_af_target(Some(AfTarget::Msisdn("491700000003".to_string())));
        let udm = |event: &str| {
            serde_json::json!({
                "reportList": [{
                    "referenceId": "1",
                    "eventType": event,
                    "report": {"supi": "imsi-001010000000003", "timeStamp": "2026-11-12T00:00:00Z"},
                }]
            })
        };
        let mismatched = DROPPED_PRODUCER_REPORTS.get(&["mismatched_type"]);
        let unrecognised = DROPPED_PRODUCER_REPORTS.get(&["unrecognised_type"]);

        // The UE re-registered, and set up a PDU session: neither is a loss of
        // connectivity, and the AF hears nothing.
        assert_eq!(
            build_monitoring_notification(&sub, &udm("UE_REACHABILITY_FOR_DATA")),
            None
        );
        assert_eq!(
            build_monitoring_notification(&sub, &udm("PDN_CONNECTIVITY_STATUS")),
            None
        );
        // An empty or untyped body is not an event either.
        assert_eq!(
            build_monitoring_notification(&sub, &serde_json::json!({})),
            None
        );
        assert_eq!(
            build_monitoring_notification(
                &sub,
                &serde_json::json!({"reportList": [{"supi": "imsi-001010000000003"}]})
            ),
            None
        );
        // Two reports of another type and one untyped report were dropped (the
        // empty body has no report to count). The counter is process-global and
        // other tests drop reports too, so assert at-least deltas.
        assert!(DROPPED_PRODUCER_REPORTS.get(&["mismatched_type"]) >= mismatched + 2);
        assert!(DROPPED_PRODUCER_REPORTS.get(&["unrecognised_type"]) > unrecognised);

        // The real loss of connectivity from the UDM is forwarded, with its
        // TS 29.503 LossConnectivityReport reason.
        let mut loc = udm("LOSS_OF_CONNECTIVITY");
        loc["reportList"][0]["report"]["lossOfConnectReason"] = serde_json::json!("DEREGISTERED");
        let notification =
            build_monitoring_notification(&sub, &loc).expect("a matching UDM report is forwarded");
        let reports = notification["monitoringEventReports"].as_array().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["monitoringType"], "LOSS_OF_CONNECTIVITY");
        // TS 29.122 lossOfConnectReason is an integer; DEREGISTERED is 6
        // (TS 29.522 §4.4.2), never the TS 29.518 string (#1444).
        assert_eq!(reports[0]["lossOfConnectReason"], 6);
        assert_eq!(reports[0]["msisdn"], "491700000003");

        // An AMF body mixing types keeps only the matching report, with the AMF's
        // top-level reason.
        let amf = serde_json::json!({
            "notifyCorrelationId": "c1",
            "reportList": [
                {"type": "REACHABILITY_REPORT", "state": {"active": true}, "reachability": "REACHABLE"},
                {"type": "LOSS_OF_CONNECTIVITY", "state": {"active": true},
                 "lossOfConnectReason": "MAX_DETECTION_TIME_EXPIRED"},
            ]
        });
        let notification =
            build_monitoring_notification(&sub, &amf).expect("the LoC report is forwarded");
        let reports = notification["monitoringEventReports"].as_array().unwrap();
        assert_eq!(
            reports.len(),
            1,
            "the reachability report is dropped: {notification}"
        );
        assert_eq!(reports[0]["monitoringType"], "LOSS_OF_CONNECTIVITY");
        assert_eq!(reports[0]["lossOfConnectReason"], 7);
        assert!(reports[0].get("reachabilityType").is_none());
    }

    /// **Issue #1444**: every TS 29.518 LossOfConnectivityReason, from an AMF
    /// report and a UDM one, reaches the AF as its TS 29.522 §4.4.2 integer.
    /// A reason with no code (UNAVAILABLE_PERIOD without the _5G feature, an
    /// unknown string, a non-string) is omitted, and the report still goes out.
    #[test]
    fn loss_of_connect_reason_is_the_ts_29522_integer() {
        let sub = NefMonitoringSubscription::new(
            "af1444",
            "LOSS_OF_CONNECTIVITY",
            "http://af.example.com/cb",
            "{}",
        );
        let cases = [
            (serde_json::json!("DEREGISTERED"), Some(6)),
            (serde_json::json!("MAX_DETECTION_TIME_EXPIRED"), Some(7)),
            (serde_json::json!("PURGED"), Some(8)),
            (serde_json::json!("UNAVAILABLE_PERIOD"), None),
            (serde_json::json!("SOMETHING_NEW"), None),
            (serde_json::json!(6), None),
        ];
        for (reason, want) in cases {
            let amf = serde_json::json!({"reportList": [{"type": "LOSS_OF_CONNECTIVITY",
                "state": {"active": true}, "lossOfConnectReason": reason}]});
            let udm = serde_json::json!({"reportList": [{"referenceId": "1",
                "eventType": "LOSS_OF_CONNECTIVITY", "timeStamp": "2026-11-16T00:00:00Z",
                "report": {"lossOfConnectReason": reason}}]});
            for body in [amf, udm] {
                let notification = build_monitoring_notification(&sub, &body)
                    .unwrap_or_else(|| panic!("a LoC report is forwarded: {body}"));
                let report = &notification["monitoringEventReports"][0];
                assert_eq!(report["monitoringType"], "LOSS_OF_CONNECTIVITY");
                match want {
                    Some(code) => {
                        assert!(report["lossOfConnectReason"].is_u64(), "{report}");
                        assert_eq!(report["lossOfConnectReason"], code, "{body}");
                    }
                    None => assert!(
                        report.get("lossOfConnectReason").is_none(),
                        "{reason} has no T8 code: {report}"
                    ),
                }
            }
        }
    }

    /// **Issue #1439, the reverse direction.** UDM reachability event types map to
    /// TS 29.122 `UE_REACHABILITY` with their own reachability type, and a LoC
    /// report on a reachability subscription is dropped.
    #[test]
    fn build_monitoring_notification_maps_udm_reachability() {
        let sub = NefMonitoringSubscription::new(
            "af4",
            "UE_REACHABILITY",
            "http://af.example.com/cb",
            "{}",
        );
        for (event, reachability) in [
            ("UE_REACHABILITY_FOR_DATA", "DATA"),
            ("UE_REACHABILITY_FOR_SMS", "SMS"),
        ] {
            let body =
                serde_json::json!({"reportList": [{"referenceId": "1", "eventType": event}]});
            let notification = build_monitoring_notification(&sub, &body)
                .unwrap_or_else(|| panic!("{event} is a UE_REACHABILITY report"));
            let report = &notification["monitoringEventReports"][0];
            assert_eq!(report["monitoringType"], "UE_REACHABILITY");
            assert_eq!(report["reachabilityType"], reachability);
        }
        let loc = serde_json::json!({"reportList": [{"referenceId": "1", "eventType": "LOSS_OF_CONNECTIVITY",
            "report": {"lossOfConnectReason": "DEREGISTERED"}}]});
        assert_eq!(build_monitoring_notification(&sub, &loc), None);
    }

    /// **Issue #1443**: an AMF REACHABILITY_REPORT is forwarded as T8
    /// UE_REACHABILITY only when the UE is REACHABLE, with reachabilityType DATA.
    /// UNREACHABLE, REGULATORY_ONLY and a report with no state are dropped and
    /// counted, never sent to the AF without a reachabilityType.
    #[test]
    fn only_a_reachable_amf_report_is_ue_reachability() {
        let sub = NefMonitoringSubscription::new(
            "af1443",
            "UE_REACHABILITY",
            "http://af.example.com/cb",
            "{}",
        );
        let amf = |reachability: Option<&str>| {
            let mut report = serde_json::json!({"type": "REACHABILITY_REPORT",
                "state": {"active": true}, "supi": "imsi-001010000001443"});
            if let Some(r) = reachability {
                report["reachability"] = serde_json::json!(r);
            }
            serde_json::json!({"notifyCorrelationId": "c1443", "reportList": [report]})
        };
        for state in [Some("UNREACHABLE"), Some("REGULATORY_ONLY"), None] {
            let before = DROPPED_PRODUCER_REPORTS.get(&["not_reachable"]);
            assert_eq!(
                build_monitoring_notification(&sub, &amf(state)),
                None,
                "{state:?} is not the UE becoming reachable"
            );
            // Process-global counter shared with other tests: at-least delta.
            assert!(
                DROPPED_PRODUCER_REPORTS.get(&["not_reachable"]) > before,
                "{state:?} is counted"
            );
        }
        let notification = build_monitoring_notification(&sub, &amf(Some("REACHABLE")))
            .expect("a REACHABLE report is forwarded");
        let reports = notification["monitoringEventReports"].as_array().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["monitoringType"], "UE_REACHABILITY");
        assert_eq!(reports[0]["reachabilityType"], "DATA");

        // In one body, only the reachable report survives.
        let mixed = serde_json::json!({"reportList": [
            {"type": "REACHABILITY_REPORT", "state": {"active": true}, "reachability": "UNREACHABLE"},
            {"type": "REACHABILITY_REPORT", "state": {"active": true}, "reachability": "REACHABLE"},
            {"type": "REACHABILITY_REPORT", "state": {"active": true}, "reachability": "REGULATORY_ONLY"},
        ]});
        let notification =
            build_monitoring_notification(&sub, &mixed).expect("the reachable one is forwarded");
        let reports = notification["monitoringEventReports"].as_array().unwrap();
        assert_eq!(reports.len(), 1, "{notification}");
        assert_eq!(reports[0]["reachabilityType"], "DATA");
    }

    /// **Issue #1443, over the wire**: the AMF's UNREACHABLE and REGULATORY_ONLY
    /// reachability notifications are answered 204 and forward nothing; the
    /// REACHABLE one that follows is the AF stub's first and only delivery, as
    /// UE_REACHABILITY with reachabilityType DATA. A dropped body never spawns a
    /// forward, so no fixed sleep is needed to show the drops sent nothing.
    #[test]
    fn amf_unreachable_notifications_never_reach_the_af() {
        let _guard = lock_globals();
        reset_context();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                nextgcore_sbi::security::set_sbi_profile_override(
                    nextgcore_sbi::security::SbiProfile::Dev,
                );
                let seen: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Arc::default();
                let sink = Arc::clone(&seen);
                let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
                let af = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
                af.start(move |req: SbiRequest| {
                    let sink = Arc::clone(&sink);
                    async move {
                        if let Some(v) = req
                            .http
                            .content
                            .as_deref()
                            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                        {
                            sink.lock().expect("sink").push(v);
                        }
                        SbiResponse::with_status(204)
                    }
                })
                .await
                .expect("AF stub starts");
                for _ in 0..200 {
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }

                let mut sub = NefMonitoringSubscription::new(
                    "af-1443",
                    "UE_REACHABILITY",
                    format!("http://127.0.0.1:{}/t8/cb", addr.port()),
                    "{}",
                )
                .with_af_target(Some(AfTarget::Msisdn("491700001443".to_string())));
                sub.id = "sub-1443".to_string();
                let token = sub.notify_token.clone().expect("tokened");
                nef_self()
                    .read()
                    .expect("ctx")
                    .subscription_insert(sub)
                    .expect("insert");

                let post = |reachability: &str| {
                    SbiRequest::post("/nnef-eventexposure/v1/notify/sub-1443")
                        .with_json_body(&serde_json::json!({
                            "notifyCorrelationId": "sub-1443",
                            "reportList": [{
                                "type": "REACHABILITY_REPORT",
                                "state": {"active": true},
                                "timeStamp": "2026-11-16T00:00:00Z",
                                "supi": "imsi-001010000001443",
                                "reachability": reachability,
                            }]
                        }))
                        .expect("serialize")
                };
                for state in ["UNREACHABLE", "REGULATORY_ONLY"] {
                    let response = handle_producer_notification(
                        "sub-1443",
                        Some(token.as_str()),
                        &post(state),
                    )
                    .await;
                    assert_eq!(response.status, 204, "{state}");
                }
                let response = handle_producer_notification(
                    "sub-1443",
                    Some(token.as_str()),
                    &post("REACHABLE"),
                )
                .await;
                assert_eq!(response.status, 204);

                let mut delivered = Vec::new();
                for _ in 0..500 {
                    delivered = seen.lock().expect("sink").clone();
                    if !delivered.is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert_eq!(delivered.len(), 1, "exactly one delivery: {delivered:?}");
                let reports = delivered[0]["monitoringEventReports"].as_array().unwrap();
                assert_eq!(reports.len(), 1);
                assert_eq!(reports[0]["monitoringType"], "UE_REACHABILITY");
                assert_eq!(reports[0]["reachabilityType"], "DATA");
                assert_eq!(reports[0]["msisdn"], "491700001443");
                drop(af);
            });
    }

    /// **nextgsim#480**: a T8 request naming the UE by `externalId` (what UE ID
    /// retrieval hands the AF) is resolved through the UDM's
    /// id-translation-result keyed by the `extid-` GPSI, and the southbound
    /// Nudm_EE subscription targets the SUPI the UDM answered. Before this test
    /// nothing exercised a successful GPSI resolution.
    #[test]
    fn a_t8_request_by_external_id_resolves_through_the_udm() {
        let _guard = lock_globals();
        reset_context();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                nextgcore_sbi::security::set_sbi_profile_override(
                    nextgcore_sbi::security::SbiProfile::Dev,
                );
                let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
                let sink = Arc::clone(&seen);
                let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
                let udm = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
                udm.start(move |req: SbiRequest| {
                    let sink = Arc::clone(&sink);
                    async move {
                        let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                        sink.lock().expect("seen").push(path.clone());
                        if path == "/nudm-sdm/v2/extid-ue480@fl.nextg/id-translation-result" {
                            SbiResponse::with_status(200)
                                .with_json_body(&serde_json::json!({
                                    "supi": "imsi-999700000000480",
                                    "gpsi": "extid-ue480@fl.nextg"
                                }))
                                .expect("json")
                        } else if path == "/nudm-ee/v1/imsi-999700000000480/ee-subscriptions" {
                            SbiResponse::with_status(201).with_header(
                                "Location",
                                "/nudm-ee/v1/imsi-999700000000480/ee-subscriptions/ee-480",
                            )
                        } else {
                            SbiResponse::with_status(404)
                        }
                    }
                })
                .await
                .expect("UDM stub starts");
                let udm_uri = format!("http://127.0.0.1:{}", addr.port());
                if let Ok(mut c) = nef_self().write() {
                    c.set_endpoints(
                        None,
                        Some(udm_uri.clone()),
                        Some("http://127.0.0.1:7817".to_string()),
                        Some("nef-480".to_string()),
                    );
                    c.set_udm_sdm_uri(Some(udm_uri));
                }
                let response = handle_monitoring_subscription_create(
                    "fl-af",
                    &monitoring_request(serde_json::json!({
                        "monitoringType": "LOSS_OF_CONNECTIVITY",
                        "externalId": "ue480@fl.nextg",
                        "notificationDestination": "http://127.0.0.1:9/fl-af/v1/t8-notify/x"
                    })),
                    NorthboundApi::T8MonitoringEvent,
                )
                .await;
                assert_eq!(response.status, 201, "{:?}", response.http.content);
                assert_eq!(
                    seen.lock().expect("seen").clone(),
                    vec![
                        "/nudm-sdm/v2/extid-ue480@fl.nextg/id-translation-result".to_string(),
                        "/nudm-ee/v1/imsi-999700000000480/ee-subscriptions".to_string(),
                    ]
                );
                let echoed: serde_json::Value =
                    serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
                assert!(
                    !echoed.to_string().contains("imsi-"),
                    "the SUPI never reaches the AF: {echoed}"
                );
                drop(udm);
            });
        reset_context();
    }

    /// **#2132 (R41 on #2159)**: under northbound mTLS + OAuth2 enforcement, a
    /// caller whose credentials are no identity (a certificate and a token
    /// naming different instances, or a relay's certificate with no token) is
    /// refused 403 FIRST: the monitoring create makes no southbound UDM GPSI
    /// lookup and stores nothing, and the Nnef unsubscribe answers the same 403
    /// for a subscription that exists and one that does not, so neither route
    /// tells a 404 from a 403.
    ///
    /// REVERT-VERIFIED: with the create's identity check moved back after the
    /// GPSI resolution, the UDM stub sees an id-translation-result request and
    /// the "no southbound call" assertion fails; with the Nnef delete's check
    /// removed, the unknown subscription answers 404.
    #[test]
    fn a_caller_with_no_identity_is_refused_before_any_lookup_2132() {
        let _guard = lock_globals();
        reset_context();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                nextgcore_sbi::security::set_sbi_profile_override(
                    nextgcore_sbi::security::SbiProfile::Dev,
                );
                let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
                let sink = Arc::clone(&seen);
                let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
                let udm = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
                udm.start(move |req: SbiRequest| {
                    let sink = Arc::clone(&sink);
                    async move {
                        sink.lock().expect("seen").push(req.header.uri.clone());
                        SbiResponse::with_status(404)
                    }
                })
                .await
                .expect("UDM stub starts");
                let udm_uri = format!("http://127.0.0.1:{}", addr.port());
                if let Ok(mut c) = nef_self().write() {
                    c.set_endpoints(None, Some(udm_uri.clone()), None, None);
                    c.set_udm_sdm_uri(Some(udm_uri));
                }
                let enforced = NorthboundAuth {
                    oauth2: true,
                    mtls: true,
                };
                let mismatch = |mut r: SbiRequest| {
                    r.peer_cert_nf_instance_id =
                        Some("aaaaaaaa-2132-4000-8000-00000000000a".into());
                    r.peer_cert_nf_types = vec!["AF".into()];
                    r.oauth2_subject = Some("bbbbbbbb-2132-4000-8000-00000000000b".into());
                    r
                };
                let relay_alone = |mut r: SbiRequest| {
                    r.peer_cert_nf_instance_id =
                        Some("55555555-2132-4000-8000-000000000005".into());
                    r.peer_cert_nf_types = vec!["SCP".into()];
                    r
                };
                for (what, credentials) in [
                    ("mismatch", &mismatch as &dyn Fn(SbiRequest) -> SbiRequest),
                    ("relay alone", &relay_alone),
                ] {
                    let create = credentials(monitoring_request(serde_json::json!({
                        "monitoringType": "LOSS_OF_CONNECTIVITY",
                        "externalId": "ue2132@fl.nextg",
                        "notificationDestination": "http://127.0.0.1:9/af/v1/notify/x"
                    })));
                    let response = TEST_NORTHBOUND_AUTH
                        .scope(
                            enforced,
                            handle_monitoring_subscription_create(
                                "af-2132",
                                &create,
                                NorthboundApi::T8MonitoringEvent,
                            ),
                        )
                        .await;
                    assert_eq!(response.status, 403, "{what}: {:?}", response.http.content);
                    assert!(
                        seen.lock().expect("seen").is_empty(),
                        "{what}: no southbound call before the identity check"
                    );
                    assert_eq!(
                        nef_self().read().unwrap().subscription_count(),
                        0,
                        "{what}: nothing stored"
                    );
                }

                // The Nnef unsubscribe: an existing subscription and an unknown
                // one get the same 403.
                let stored = NefMonitoringSubscription::new(
                    "notif-2132",
                    "LOSS_OF_CONNECTIVITY",
                    "http://127.0.0.1:9/af/v1/notify/x",
                    "{}",
                );
                let stored_id = stored.id.clone();
                nef_self()
                    .read()
                    .unwrap()
                    .subscription_insert(stored)
                    .expect("stored");
                for id in [stored_id.as_str(), "no-such-subscription-2132"] {
                    let del = mismatch(SbiRequest::delete(format!(
                        "/nnef-eventexposure/v1/subscriptions/{id}"
                    )));
                    let response = TEST_NORTHBOUND_AUTH
                        .scope(enforced, handle_nnef_event_exposure_delete(id, &del))
                        .await;
                    assert_eq!(response.status, 403, "{id}: {:?}", response.http.content);
                }
                assert!(nef_self()
                    .read()
                    .unwrap()
                    .subscription_find(&stored_id)
                    .is_some());
                drop(udm);
            });
        reset_context();
    }

    /// **Issue #1439, at the handler.** A producer notification whose reports are
    /// all of another type is answered 204 and forwards NOTHING to the AF; the
    /// matching one is delivered to the AF's notificationDestination over the
    /// wire, labelled with its own type and carrying the reason.
    ///
    /// The mismatched bodies are sent first. Since a dropped body never spawns a
    /// forward, the stub's first and only delivery being the LoC report shows the
    /// drops sent nothing, without a fixed sleep.
    #[test]
    fn producer_notification_forwards_only_the_subscribed_event_to_the_af() {
        let _guard = lock_globals();
        reset_context();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                // A loopback plaintext AF stub: declare the dev profile rather than
                // inherit whatever the process last set.
                nextgcore_sbi::security::set_sbi_profile_override(
                    nextgcore_sbi::security::SbiProfile::Dev,
                );
                let seen: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Arc::default();
                let sink = Arc::clone(&seen);
                let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
                let af = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
                af.start(move |req: SbiRequest| {
                    let sink = Arc::clone(&sink);
                    async move {
                        if let Some(v) = req
                            .http
                            .content
                            .as_deref()
                            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                        {
                            sink.lock().expect("sink").push(v);
                        }
                        SbiResponse::with_status(204)
                    }
                })
                .await
                .expect("AF stub starts");
                for _ in 0..200 {
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }

                let mut sub = NefMonitoringSubscription::new(
                    "af-1439",
                    "LOSS_OF_CONNECTIVITY",
                    format!("http://127.0.0.1:{}/t8/cb", addr.port()),
                    "{}",
                )
                .with_af_target(Some(AfTarget::Msisdn("491700001439".to_string())));
                sub.id = "sub-1439".to_string();
                let token = sub.notify_token.clone().expect("tokened");
                nef_self()
                    .read()
                    .expect("ctx")
                    .subscription_insert(sub)
                    .expect("insert");

                let post = |event: &str, reason: Option<&str>| {
                    let mut report = serde_json::json!({
                        "referenceId": "1",
                        "eventType": event,
                        "report": {"supi": "imsi-001010000001439", "timeStamp": "2026-11-12T00:00:00Z"},
                    });
                    if let Some(r) = reason {
                        report["report"]["lossOfConnectReason"] = serde_json::json!(r);
                    }
                    SbiRequest::post("/nnef-eventexposure/v1/notify/sub-1439")
                        .with_json_body(&serde_json::json!({"reportList": [report]}))
                        .expect("serialize")
                };
                for event in ["UE_REACHABILITY_FOR_DATA", "PDN_CONNECTIVITY_STATUS"] {
                    let response = handle_producer_notification("sub-1439", Some(token.as_str()), &post(event, None)).await;
                    assert_eq!(response.status, 204, "{event}");
                }
                let response = handle_producer_notification(
                    "sub-1439",
                    Some(token.as_str()),
                    &post("LOSS_OF_CONNECTIVITY", Some("DEREGISTERED")),
                )
                .await;
                assert_eq!(response.status, 204);

                let mut delivered = Vec::new();
                for _ in 0..500 {
                    delivered = seen.lock().expect("sink").clone();
                    if !delivered.is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert_eq!(delivered.len(), 1, "exactly one delivery: {delivered:?}");
                let reports = delivered[0]["monitoringEventReports"].as_array().unwrap();
                assert_eq!(reports.len(), 1);
                assert_eq!(reports[0]["monitoringType"], "LOSS_OF_CONNECTIVITY");
                assert_eq!(reports[0]["lossOfConnectReason"], 6, "TS 29.522 §4.4.2");
                assert_eq!(reports[0]["msisdn"], "491700001439");
                assert_eq!(
                    delivered[0]["subscription"],
                    "/3gpp-monitoring-event/v1/af-1439/subscriptions/sub-1439"
                );
                drop(af);
            });
        reset_context();
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
                    NorthboundApi::T8MonitoringEvent,
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
                NorthboundApi::T8MonitoringEvent,
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
            NorthboundApi::T8MonitoringEvent,
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
        // Every shape that FORWARDS on a UE_REACHABILITY subscription: AMF and UDM
        // reachability reports, each carrying the SUPI (#1439 removed the bare
        // fallback, so a body that forwards nothing cannot leak anything).
        let producer_bodies = [
            serde_json::json!({"reportList": [{"type": "REACHABILITY_REPORT",
                "supi": "imsi-001010000000001", "reachability": "REACHABLE"}]}),
            serde_json::json!({"reportList": [{"type": "REACHABILITY_REPORT",
                "supi": "imsi-001010000000001", "reachability": "REACHABLE",
                "location": {"nrLocation": {}}}]}),
            serde_json::json!({"reportList": [{"eventType": "UE_REACHABILITY_FOR_DATA",
                "report": {"supi": "imsi-001010000000001"}}]}),
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
                let notification = build_monitoring_notification(&sub, producer_body)
                    .expect("every body here forwards");
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

    /// The identity is only what this process verified: the `sub` the server
    /// set after verifying the token, never a claim read from the raw header,
    /// and each only under its own enforcement.
    ///
    /// REVERT-VERIFIED: with the `auth.oauth2` guard dropped, the
    /// "enforcement off" case gets `client-a` and fails.
    #[test]
    fn a_bearer_subject_is_trusted_only_under_enforcement() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let both = NorthboundAuth {
            oauth2: true,
            mtls: true,
        };
        let claims = URL_SAFE_NO_PAD.encode(br#"{"sub":"client-a","aud":"NEF"}"#);
        let token = format!("aGRy.{claims}.c2ln");
        // An unverified bearer: the header is present, the server set no `sub`.
        let unverified = SbiRequest::post("/3gpp-monitoring-event/v1/af1/subscriptions")
            .with_header("Authorization", format!("Bearer {token}"));
        for production in [true, false] {
            assert_eq!(
                authenticated_client_id_with(&unverified, both, production),
                Ok(None),
                "a claim the server did not verify is never an identity"
            );
        }
        let mut verified = unverified.clone();
        verified.oauth2_subject = Some("client-a".to_string());
        let oauth2_only = NorthboundAuth {
            oauth2: true,
            mtls: false,
        };
        assert_eq!(
            authenticated_client_id_with(&verified, oauth2_only, true),
            Ok(Some("client-a".to_string())),
            "the verified sub is the identity"
        );
        assert_eq!(
            authenticated_client_id_with(&verified, NorthboundAuth::default(), true),
            Ok(None),
            "enforcement off: nothing was verified, so nothing is an identity"
        );
    }

    /// **#2132**: the caller identity is the shared `owner_binding` rule, not
    /// "any verified certificate". A typed consumer certificate is the caller;
    /// a relay's (SCP/SEPP) never is, the relayed token decides; a certificate
    /// and token naming different instances refuse; under production an
    /// untyped certificate alone is no identity (#2065), under dev it still is.
    ///
    /// REVERT-VERIFIED: with `authenticated_client_id_with` back to "any
    /// verified certificate's id, else the token" (the pre-#2132 rule), the
    /// test fails on its first relay case, "an SCP certificate alone is no
    /// identity".
    #[test]
    fn the_caller_is_the_shared_verified_identity_2132() {
        let mtls = NorthboundAuth {
            oauth2: true,
            mtls: true,
        };
        let req = |cert: Option<&str>, types: &[&str], sub: Option<&str>| {
            let mut r = SbiRequest::post("/3gpp-monitoring-event/v1/af1/subscriptions");
            r.peer_cert_nf_instance_id = cert.map(str::to_string);
            r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            r.oauth2_subject = sub.map(str::to_string);
            r
        };
        const AF: &str = "aaaaaaaa-2132-4000-8000-00000000000a";
        const SCP: &str = "55555555-2132-4000-8000-000000000005";
        for production in [true, false] {
            let id = |r: SbiRequest| authenticated_client_id_with(&r, mtls, production);
            assert_eq!(id(req(Some(AF), &["AF"], None)), Ok(Some(AF.into())));
            for relay in ["SCP", "SEPP"] {
                assert!(
                    id(req(Some(SCP), &[relay], None))
                        .unwrap_err()
                        .contains("is a relay's"),
                    "a {relay} certificate alone is no identity, and is refused rather \
                     than taken as anonymous (production={production})"
                );
            }
            assert_eq!(
                id(req(Some(SCP), &["SCP"], Some(AF))),
                Ok(Some(AF.into())),
                "through an SCP the relayed token decides"
            );
            assert!(
                id(req(Some(SCP), &["AF"], Some(AF))).is_err(),
                "a certificate and a token naming different instances refuse"
            );
        }
        assert!(
            authenticated_client_id_with(&req(Some(AF), &[], None), mtls, true)
                .unwrap_err()
                .contains("names no NF type"),
            "production: an untyped certificate alone is no identity"
        );
        assert_eq!(
            authenticated_client_id_with(&req(Some(AF), &[], Some(AF)), mtls, true),
            Ok(Some(AF.into())),
            "production: with a token, the token's sub"
        );
        assert_eq!(
            authenticated_client_id_with(&req(Some(AF), &[], None), mtls, false),
            Ok(Some(AF.into())),
            "dev: as before"
        );
        // Without mTLS enforcement the certificate is not read at all.
        let oauth2_only = NorthboundAuth {
            oauth2: true,
            mtls: false,
        };
        assert_eq!(
            authenticated_client_id_with(&req(Some(AF), &["AF"], None), oauth2_only, true),
            Ok(None)
        );
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
        // #548: re-initialising the shared context must happen under the same
        // lock `mod tests` uses, or it can land inside another test's
        // final->init window and change that test's capacity.
        {
            let _guard = crate::context::lock_nef_context_for_test();
            super::nef_context_init(256, 256);
        }
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Nef);
        let server = SbiServer::on_listener(cfg, port_listener);
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
        assert_eq!(resp.status, 403, "wrong-audience token must be 403 (#1766)");
        // #1779 review m2: the gate's claim mismatch, not a handler's own 403.
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
        assert_eq!(problem["cause"], "ACCESS_TOKEN_CLAIM_MISMATCH", "{problem}");
        assert_eq!(problem["invalidParams"][0]["param"], "aud", "{problem}");
        server.stop().await.expect("stop");
    }
}

/// #1322: no wildcard reaches the notify base.
#[cfg(test)]
mod tests_notify_base_1322 {
    use super::nef_notify_base;
    use nextgcore_core::sockaddr::SbiEndpoint;

    fn ep(host: &str, advertise: Option<&str>) -> SbiEndpoint {
        SbiEndpoint {
            host: host.into(),
            port: 7817,
            advertise: advertise.map(str::to_string),
        }
    }

    #[test]
    fn the_notify_base_is_never_a_wildcard() {
        assert_eq!(
            nef_notify_base(None, &ep("0.0.0.0", Some("10.0.0.7"))).unwrap(),
            "http://10.0.0.7:7817"
        );
        assert_eq!(
            nef_notify_base(Some("http://nef.example:80/"), &ep("0.0.0.0", None)).unwrap(),
            "http://nef.example:80"
        );
        for wildcard in ["0.0.0.0", "::"] {
            let e = nef_notify_base(None, &ep(wildcard, None)).unwrap_err();
            assert!(e.starts_with("refusing to start"), "{e}");
        }
        for bad in ["http://0.0.0.0:7817", "http://[::]:7817", "nef.example"] {
            assert!(nef_notify_base(Some(bad), &ep("10.0.0.7", Some("10.0.0.7"))).is_err());
        }
    }
}

/// #1324: the NFProfile carries its host where its type belongs (TS 29.510
/// §6.1.6.2.2): IPv4 in ipv4Addresses, IPv6 in ipv6Addresses, an FQDN as fqdn, and
/// the service ipEndPoints likewise.
#[cfg(test)]
mod tests_nf_profile_host_kind_1324 {
    use super::*;

    #[test]
    fn the_nf_profile_carries_its_host_by_type() {
        for host in nextgcore_sbi::nf_addressing::SAMPLE_HOSTS {
            let profile = build_nf_profile("id", host, 7777, nextgcore_sbi::types::UriScheme::Http);
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}

/// #1661: the NEF's southbound service requests carry the NRF-issued token, so
/// they pass OAuth2-required producers. The stand-ins are gated by nextgcore-sbi's
/// own check (JWKS, audience), so a recorded request passed it.
#[cfg(test)]
mod southbound_oauth2_1661_tests {
    use super::*;
    use context::{SouthboundProducer, SouthboundRef};
    use nextgcore_sbi::test_support::oauth2 as stand_in;
    use nextgcore_sbi::types::NfType;

    const NRF: &str = "http://127.0.0.10:7777";

    /// The production profile installs the client without the knob (#1665's rule,
    /// now for the NEF too), and dev without the knob installs none.
    #[test]
    fn the_production_profile_installs_the_outbound_oauth2_client_without_the_knob() {
        use nextgcore_sbi::security::SbiProfile;
        let oauth2 = outbound_oauth2_client(SbiProfile::Production, false, Some(NRF))
            .expect("production profile, knob off: the outbound OAuth2 client is installed");
        assert_eq!(oauth2.self_consumer().nf_type, NfType::Nef);
        assert_eq!(oauth2.nrf_uri(), NRF);
        assert!(outbound_oauth2_client(SbiProfile::Dev, true, Some(NRF)).is_some());
        assert!(outbound_oauth2_client(SbiProfile::Dev, false, Some(NRF)).is_none());
    }

    /// #1661, failure-path property 1 (a failed request applies nothing): when
    /// the token cannot be obtained, the GPSI resolution, the southbound subscribe
    /// and its unsubscribe are not sent, not even bare. The subscribe is not
    /// Live, so no southbound reference is stored for it. The recorder here is
    /// UNGATED, so it would see a bare send.
    #[allow(clippy::await_holding_lock)] // the NEF state lock, held across the test (#1877)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_token_fetch_sends_nothing_1661() {
        // #1877: its unsubscribe fails and parks into the NEF's global set.
        let _globals = crate::context::lock_nef_context_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink = std::sync::Arc::clone(&seen);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let recorder = nextgcore_sbi::server::SbiServer::on_listener(
            nextgcore_sbi::server::SbiServerConfig::new(addr),
            listener,
        );
        recorder
            .start(move |_req| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    nextgcore_sbi::message::SbiResponse::with_status(201)
                        .with_header("location", "/x/v1/subscriptions/s-1")
                }
            })
            .await
            .expect("recorder starts");
        let uri = format!("http://127.0.0.1:{}", addr.port());
        let subscribe = SouthboundSubscribe {
            producer: SouthboundProducer::Amf,
            path: "/namf-evts/v1/subscriptions".to_string(),
            body: serde_json::json!({ "subscription": {} }),
        };
        // Port 1 on loopback: nothing listens, so the token request fails.
        let (gpsi, sub) = TEST_OAUTH2_CLIENT
            .scope(stand_in::oauth2_client_for(1, NfType::Nef), async {
                let gpsi = resolve_gpsi_to_supi(Some(uri.clone()), "msisdn-1661").await;
                let sub = attempt_southbound_subscribe(Some(uri.clone()), &subscribe).await;
                southbound_unsubscribe(
                    Some(uri.clone()),
                    SouthboundRef {
                        producer: SouthboundProducer::Amf,
                        subscription_id: "s-1".to_string(),
                        delete_path: "/namf-evts/v1/subscriptions/s-1".to_string(),
                        producer_base: None,
                    },
                )
                .await;
                (gpsi, sub)
            })
            .await;

        assert_eq!(gpsi, None);
        assert!(!matches!(sub, SouthboundOutcome::Live(..)), "{sub:?}");
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no token: nothing is sent, not even bare"
        );
    }

    /// #1661: the GPSI resolution (UDM), and the AMF and UDM southbound
    /// subscriptions and their unsubscribes, pass OAuth2-required producers of the
    /// right NF type with the installed client, and are refused 401 without one.
    #[allow(clippy::await_holding_lock)] // the NEF state lock, held across the test (#1877)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gpsi_resolution_and_the_amf_and_udm_subscriptions_pass_oauth2_required_producers_1661()
    {
        // #1877: an unsubscribe that fails parks into the NEF's global set.
        let _globals = crate::context::lock_nef_context_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (_nrf, nrf_port) = stand_in::token_nrf(sk.clone()).await;
        let (_udm, udm_port, udm_seen) =
            stand_in::oauth2_producer(&sk, NfType::Udm, |req| match req.header.method.as_str() {
                "DELETE" => SbiResponse::with_status(204),
                "POST" => SbiResponse::with_status(201).with_header(
                    "location",
                    "/nudm-ee/v1/imsi-001010000001661/ee-subscriptions/ee-1661",
                ),
                _ => SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({ "supi": "imsi-001010000001661" }))
                    .expect("json"),
            })
            .await;
        let (_amf, amf_port, amf_seen) = stand_in::oauth2_producer(&sk, NfType::Amf, |req| {
            if req.header.method == "DELETE" {
                SbiResponse::with_status(204)
            } else {
                SbiResponse::with_status(201)
                    .with_header("location", "/namf-evts/v1/subscriptions/s-1661")
            }
        })
        .await;
        let udm_uri = format!("http://127.0.0.1:{udm_port}");
        let amf_uri = format!("http://127.0.0.1:{amf_port}");
        let subscribe = SouthboundSubscribe {
            producer: SouthboundProducer::Amf,
            path: "/namf-evts/v1/subscriptions".to_string(),
            body: serde_json::json!({ "subscription": {} }),
        };
        let udm_subscribe = SouthboundSubscribe {
            producer: SouthboundProducer::Udm,
            path: "/nudm-ee/v1/imsi-001010000001661/ee-subscriptions".to_string(),
            body: serde_json::json!({ "callbackReference": "http://nef/cb" }),
        };

        let bare_gpsi = resolve_gpsi_to_supi(Some(udm_uri.clone()), "msisdn-1661").await;
        let bare_sub = attempt_southbound_subscribe(Some(amf_uri.clone()), &subscribe).await;
        let bare_udm_sub =
            attempt_southbound_subscribe(Some(udm_uri.clone()), &udm_subscribe).await;
        let (gpsi, sub, udm_sub) = TEST_OAUTH2_CLIENT
            .scope(stand_in::oauth2_client_for(nrf_port, NfType::Nef), async {
                let gpsi = resolve_gpsi_to_supi(Some(udm_uri.clone()), "msisdn-1661").await;
                let sub = attempt_southbound_subscribe(Some(amf_uri.clone()), &subscribe).await;
                if let SouthboundOutcome::Live(southbound, _) = &sub {
                    southbound_unsubscribe(Some(amf_uri.clone()), southbound.clone()).await;
                }
                let udm_sub =
                    attempt_southbound_subscribe(Some(udm_uri.clone()), &udm_subscribe).await;
                if let SouthboundOutcome::Live(southbound, _) = &udm_sub {
                    southbound_unsubscribe(Some(udm_uri.clone()), southbound.clone()).await;
                }
                (gpsi, sub, udm_sub)
            })
            .await;

        assert_eq!(bare_gpsi, None, "refused 401 without a token");
        assert!(
            !matches!(bare_sub, SouthboundOutcome::Live(..)),
            "{bare_sub:?}"
        );
        assert!(
            !matches!(bare_udm_sub, SouthboundOutcome::Live(..)),
            "{bare_udm_sub:?}"
        );
        match udm_sub {
            SouthboundOutcome::Live(
                SouthboundRef {
                    subscription_id, ..
                },
                _,
            ) => {
                assert_eq!(subscription_id, "ee-1661")
            }
            other => panic!("the tokened UDM subscribe must be live: {other:?}"),
        }
        assert_eq!(
            stand_in::bearer_requests(&udm_seen, "POST", "/ee-subscriptions"),
            1
        );
        assert_eq!(
            stand_in::bearer_requests(&udm_seen, "DELETE", "/ee-subscriptions/ee-1661"),
            1
        );
        assert_eq!(gpsi.as_deref(), Some("imsi-001010000001661"));
        match sub {
            SouthboundOutcome::Live(
                SouthboundRef {
                    subscription_id, ..
                },
                _,
            ) => {
                assert_eq!(subscription_id, "s-1661")
            }
            other => panic!("the tokened subscribe must be live: {other:?}"),
        }
        assert_eq!(
            stand_in::bearer_requests(&udm_seen, "GET", "/id-translation-result"),
            1
        );
        assert_eq!(
            stand_in::bearer_requests(&amf_seen, "POST", "/namf-evts/v1/subscriptions"),
            1
        );
        assert_eq!(
            stand_in::bearer_requests(&amf_seen, "DELETE", "/namf-evts/v1/subscriptions/s-1661"),
            1
        );
    }
}

/// #1791: the registered NFProfile advertises, in every `nfServices[].scheme`,
/// the scheme this NF's SBI listener serves (TS 29.510 §6.1.6.2.3
/// `NFService.scheme`): `http` for the cleartext listener, `https` once `--tls`
/// makes it TLS. This listener ignores NEXTGCORE_SBI_PROFILE (it serves TLS only with `--tls`; #1795), so `--tls` alone decides. `main` passes the listener config's scheme in; the
/// nextgcore-sbi source guard `every_nf_advertises_its_listener_scheme_1791`
/// pins that wiring.
///
/// REVERT-VERIFIED: with the builder advertising `"http"` again, the TLS case
/// fails here.
#[cfg(test)]
mod tests_advertised_scheme_1791 {
    use super::*;

    #[test]
    fn the_nf_profile_advertises_the_listener_scheme_1791() {
        let addr: std::net::SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let plain = nextgcore_sbi::server::SbiServerConfig::new(addr);
        let tls = nextgcore_sbi::server::SbiServerConfig::new(addr).with_tls("tls.key", "tls.crt");
        for (cfg, want) in [(plain, "http"), (tls, "https")] {
            let profile = build_nf_profile("nef-1791", "10.0.0.1", 7777, cfg.scheme);
            let services = profile["nfServices"].as_array().expect("nfServices");
            assert!(!services.is_empty(), "the profile offers services");
            for svc in services {
                assert_eq!(
                    svc["scheme"], want,
                    "{} must advertise the listener's scheme",
                    svc["serviceName"]
                );
            }
        }
    }
}

/// #1795: the listener `main` builds follows the SBI security profile.
#[cfg(test)]
mod sbi_profile_tests_1795 {
    /// REVERT-VERIFIED: with `sbi_listener_config` returning its input, the
    /// production half serves cleartext and the helper fails naming NEF.
    #[test]
    fn the_listener_follows_the_sbi_profile_1795() {
        nextgcore_sbi::test_support::assert_listener_follows_sbi_profile(
            nextgcore_sbi::types::NfType::Nef,
            super::sbi_listener_config,
        );
    }
}
