//! NextGCore LMF (Location Management Function)
//!
//! The LMF is a 5G core NF responsible for (TS 23.273):
//! - UE positioning via NLs interface (AMF <-> LMF)
//! - NRPPa protocol for positioning information exchange (gNB <-> LMF)
//! - Positioning methods: ECID, OTDOA, NR-based (DL-TDOA, UL-TDOA, Multi-RTT), GNSS
//! - Measurement request/report procedures

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{ProblemDetails, SbiRequest, SbiResponse};
use nextgcore_sbi::owner_binding;
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
mod amf_unsubscribe; // #2085: the reconciler for failed AMF unsubscribes
mod broadcast_exposure; // #104: Nlmf_Broadcast + Nlmf_DataExposure
mod codec_glue;
mod context;
mod dl_prs_assistance; // #911: NR DL-PRS assistance data for Multi-RTT and DL-TDOA
#[cfg(test)]
mod lpp_equivalence_tests;
// #515: the pre-migration LPP code, kept as the equivalence oracle.
#[cfg(test)]
mod lpp_fixtures; // #515: generated-codec LPP test fixtures
                  // A2: lmfd → AMF Namf_Communication client leg (NRF discovery of the serving
                  // AMF, N1N2MessageSubscribe registration, multipart N1N2MessageTransfer POST).
mod multi_rtt; // #807: the gNB half of Multi-RTT (TS 38.305 §8.10.3)
mod namf_client;
mod nlmf;
mod nrppa_downlink; // #103: LMF-initiated NRPPa toward NG-RAN
mod nrppa_positioning; // #807: NRPPa answers of the Multi-RTT procedures
mod nrppa_uplink; // #515: E-CID Measurement Report on the generated codec, TS 38.455 §10
                  // lmfd-08: real multilateration solvers (ECID / Multi-RTT / TDOA / AoA).
                  // Wired into `context::compute_location`; solve_tdoa remains available for
                  // lmfd-05/06 (NRPPa TDOA) but is not yet called (dead_code = "allow").
mod positioning;
mod site_config;
mod slpp; // #557: SLPP sidelink positioning (TS 38.355, TS 38.305 §8.15.2) // #103: cell/TRP coordinates from configuration

// #2260: the Application Layer IDs the 5GC maps to a UE.
mod nudr_client;

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

    #[arg(short = 'e', long)]
    log_level: Option<String>,

    #[arg(short = 'm', long)]
    no_color: bool,

    /// Without it, `lmf.sbi.server[0].address` from the config file, else
    /// 127.0.0.1 (#1308, #1312). The port likewise defaults to the file, else 7816.
    #[arg(long)]
    sbi_addr: Option<String>,

    /// The SBI host advertised in the NRF NFProfile and callback URIs. Without it,
    /// `NEXTGCORE_SBI_ADVERTISE`, else `lmf.sbi.server[0].advertise`, else the
    /// bind address; a wildcard is never advertised (#1312).
    #[arg(long)]
    sbi_advertise: Option<String>,

    #[arg(long)]
    sbi_port: Option<u16>,

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
    nextgcore_core::log::nf_log_builder(level).init();
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

/// #1665: the outbound OAuth2 client this LMF installs at startup: under the
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
        nextgcore_sbi::types::NfType::Lmf,
    )
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

/// Apply OAuth2 producer enforcement to `cfg` (Wave-6 H8). The outbound client
/// is installed apart from it, by [`outbound_oauth2_client`] (#1665). The server verifies incoming Bearer tokens against the
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
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

/// The AMF notify callbacks admitted without an OAuth2 bearer when the listener
/// requires one (#1518): a notification carries no access token (TS 33.501
/// §13.4.1, TS 29.500 §6.10.7 NOTE). Each is admitted on its subscription's token
/// alone, because no third party can read the URI back: an N1N2 subscription
/// (TS 29.518 §6.1.3.4) and a non-UE N2 information subscription (§6.1.3.10) have
/// no GET, and neither is part of `UeContext`.
fn oauth2_callback_exemptions() -> Vec<nextgcore_sbi::server::OAuth2CallbackExemption> {
    [
        (namf_client::N1_NOTIFY_SEGMENT, context::NotifyKind::N1),
        (namf_client::N2_NOTIFY_SEGMENT, context::NotifyKind::N2),
    ]
    .into_iter()
    .map(|(segment, kind)| {
        nextgcore_sbi::server::OAuth2CallbackExemption::new(
            "POST",
            format!("{}/{segment}/{{token}}", namf_client::NOTIFY_PREFIX),
            move |cb| {
                lmf_self()
                    .read()
                    .is_ok_and(|c| c.notify_subscriber(kind, cb.token).is_some())
            },
        )
    })
    .collect()
}

/// #1795: the LMF's SBI listener under the SBI security profile. Under
/// `production`: TLS from `policy`'s certificate paths (whatever `--tls` or the
/// config file said), the client certificate verified against its CA, and an
/// access token required, with LMF as the audience and the NRF's JWKS unless
/// the NF configured its own (TS 33.501 §13.1.0, §13.3, §13.4.1). A missing
/// certificate fails startup, naming it, rather than serving cleartext. Under
/// `dev` the config is left as the NF's own settings made it.
fn sbi_listener_config(
    config: NextgcoreSbiServerConfig,
    profile: nextgcore_sbi::security::SbiProfile,
    policy: &nextgcore_sbi::security::SbiSecurityPolicy,
    nrf_uri: &str,
) -> nextgcore_sbi::SbiResult<NextgcoreSbiServerConfig> {
    nextgcore_sbi::security::apply_sbi_security_policy(
        config,
        profile,
        policy,
        nextgcore_sbi::types::NfType::Lmf,
        nrf_uri,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // #1312: the command line, else `lmf.sbi.server[0]` in the config file,
    // else loopback.
    let sbi = nextgcore_core::sockaddr::SbiEndpoint::resolve_from_file(
        args.sbi_addr.as_deref(),
        args.sbi_port,
        args.sbi_advertise.as_deref(),
        &args.config,
        "lmf",
        7816,
    )
    .map_err(|e| anyhow::anyhow!("SBI listen address: {e}"))?;
    let (sbi_addr, sbi_port) = (sbi.host.clone(), sbi.port);
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

    log::info!("NextGCore LMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Location Management Function (3GPP TS 23.273)");

    lmf_context_init(args.max_measurements);

    // #834 review: reap positioning sessions whose DetermineLocation went away
    // without expiring them. Twice the hard response-time cap, so no live
    // session is ever reaped.
    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            if let Ok(context) = lmf_self().read() {
                context.positioning_session_reap(SESSION_REAP_AGE);
            }
        }
    });

    // #103: load the cell/TRP reference points BEFORE the SBI server accepts a
    // DetermineLocation, so no request is answered against a half-filled registry.
    // Every geometric solver reads this; before #103 the only writer was test code,
    // so a deployed LMF could never produce a fix.
    let site_config = site_config::load_into_context(&args.config);
    // #103: the NRPPa downlink is new external N2 signalling, so it is gated and
    // resolved once before anything can be served.
    nrppa_downlink::init_from_env();
    // One line an operator can act on, stated once at startup rather than discovered
    // per request: with no reference points, DetermineLocation refuses (it does not
    // fabricate), and with fewer than three no multilateration method is selectable
    // however high the requested accuracy.
    if site_config.is_empty() {
        log::warn!(
            "LMF positioning is NON-FUNCTIONAL: no reference points configured, so every \
             DetermineLocation will be refused with 500 POSITIONING_FAILED"
        );
    } else if site_config.len() < crate::codec_glue::MIN_POINTS_FOR_MULTILATERATION {
        log::warn!(
            "LMF positioning has {} reference point(s): fewer than {} means only E-CID is \
             selectable, so a high-accuracy LCS QoS will be answered by a Timing-Advance ring",
            site_config.len(),
            crate::codec_glue::MIN_POINTS_FOR_MULTILATERATION
        );
    }

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

    let nf_instance_id =
        nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Lmf)
            .to_string();

    // A2: advertise our identity + notify-callback base for the outbound
    // Namf_Communication leg (subscription callback URIs must be reachable
    // by the AMF, so they use the advertised host, #1312).
    {
        // #1312: the advertised host; loopback only when the SBI binds a
        // wildcard and nothing reachable is configured.
        let advertised_host = sbi.advertise.as_deref().unwrap_or("127.0.0.1");
        if let Ok(context) = lmf_self().read() {
            context.set_nf_instance_id(nf_instance_id.clone());
            context.set_callback_base(format!(
                "http://{}",
                nextgcore_sbi::uri_encode::uri_authority(advertised_host, sbi_port)
            ));
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = nextgcore_core::sockaddr::parse_listen_addr(&sbi_addr, sbi_port)
        .context("Invalid SBI address")?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    nextgcore_core::sockaddr::warn_if_loopback_listener("SBI", &addr, "--sbi-addr");

    let mut sbi_server_config = NextgcoreSbiServerConfig::new(addr)
        .with_oauth2_callback_exemptions(oauth2_callback_exemptions());
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
    let require_oauth2 = oauth2_required(&args.config);
    // #1665: the outbound token client follows the SBI security profile as well
    // as the knob. The production profile's AMF/AUSF/SMF/UDM demand a token on
    // every service request (TS 33.501 §13.4.1.1.2), whatever this listener asks.
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    let _ = OAUTH2_CLIENT.set(outbound_oauth2_client(
        sbi_profile,
        require_oauth2,
        Some(&args.nrf_uri),
    ));
    // #1667: the same client gives this NF's own NRF calls their access token.
    nextgcore_sbi::nrf_tls::set_nrf_oauth2_client(OAUTH2_CLIENT.get().cloned().flatten());
    if require_oauth2 {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config, &args.nrf_uri);
    }

    // #1795: the listener follows the SBI security profile.

    let sbi_server_config = sbi_listener_config(
        sbi_server_config,
        sbi_profile,
        &nextgcore_sbi::security::SbiSecurityPolicy::for_profile(sbi_profile),
        &args.nrf_uri,
    )
    .map_err(|e| anyhow::anyhow!("SBI security profile: {e}"))?;

    // #1791: the NFProfile advertises the scheme this listener serves.
    let sbi_scheme = sbi_server_config.scheme;
    let sbi_server = SbiServer::new(sbi_server_config);
    log::info!("Starting LMF SBI server on {addr}");
    sbi_server
        .start(lmf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    // #1482: a failed attempt is retried in the background, and the heartbeat
    // starts after the one that succeeds.
    match sbi.registration_host() {
        Ok(host) => {
            let (host, id) = (host.to_string(), nf_instance_id.clone());
            nextgcore_sbi::heartbeat::register_or_retry(
                "LMF",
                Default::default(),
                move || {
                    let (host, id) = (host.clone(), id.clone());
                    async move {
                        register_with_nrf(&host, sbi_port, &id, sbi_scheme)
                            .await
                            .map(|()| Some(id))
                    }
                },
                |nf_instance_id| {
                    // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
                    // (active positioning sessions, saturated at 100;
                    // TS 29.510 §5.2.2.3.2). Honest session-count proxy — no
                    // fabricated CPU numbers.
                    nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                        nf_instance_id,
                        5,
                        || {
                            let load = lmf_self()
                                .read()
                                .map(|c| c.positioning_session_count())
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

    // #2085: failed AMF unsubscribes are retried until the AMF answers.
    let _unsubscribe_reconciler = amf_unsubscribe::spawn_reconciler();

    log::info!("NextGCore LMF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes
    // away, so the NRF stops handing this profile to consumers instead of
    // waiting out its supervision timer. Stopping the server first would
    // open the bad window: not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;
    // #2085: unsubscribe at the AMFs before the context is cleared. amfd's
    // non-UE N2 subscriptions never expire, so each one left here would outlive
    // this LMF, one per AMF per restart.
    // #2104 (R30 on #2111): the parked unsubscribes too, even when no live one is
    // held, so the pass runs when either set is not empty.
    let held = lmf_self()
        .read()
        .map(|c| c.amf_subscriptions_take_created())
        .unwrap_or_default();
    if let Some((done, n)) =
        amf_unsubscribe::unsubscribe_at_shutdown(held, SHUTDOWN_UNSUBSCRIBE_BUDGET).await
    {
        log::info!("Unsubscribed {done} of {n} AMF subscription(s) at shutdown");
    }
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    lmf_context_final();
    log::info!("LMF shutdown complete");

    Ok(())
}

/// #2085: how long shutdown waits for the AMFs to answer its unsubscribes.
const SHUTDOWN_UNSUBSCRIBE_BUDGET: Duration = Duration::from_secs(3);

/// LMF SBI request handler
async fn lmf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!(
        "LMF SBI: {method} {}",
        nextgcore_sbi::log_redact::redact_callback_tokens(uri)
    );

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
        // Capabilities. #104: gated like the other non-TS 29.572 routes above.
        // It is a bespoke endpoint (there is no `/capabilities` resource in
        // TS 29.572 §6.1), it discloses this NF's positioning posture, and it was
        // the ONE bespoke route left ungated.
        ["nlmf-loc", "v1", "capabilities"] if debug_endpoints_enabled() => match method {
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
            "DELETE" => handle_up_unsubscribe(subscription_id, &request).await,
            _ => send_method_not_allowed(method, "up-subscriptions/{subscriptionId}"),
        },
        // A4: Namf_Communication notify callbacks (TS 29.518 §5.2.2.3.5
        // N1MessageNotify / §5.2.2.3.6 N2InfoNotify, §5.2.2.4.4 NonUeN2InfoNotify). These are consumer-chosen
        // callback URIs — NOT TS 29.572 resources — registered by the A2
        // N1N2MessageSubscribe and NonUeN2InfoSubscribe, each carrying its
        // subscription's token (#1518, namf_client::notify_path). They correlate
        // an uplink LPP (N1) / NRPPa (N2) report to a pending DetermineLocation
        // session (A2) and complete it (fail-closed: an unknown correlation is
        // never ingested). A token no subscription holds is 404 and changes
        // nothing, whatever admitted the request. The token-less URIs of before
        // #1518 are gone: subscriptions are held in memory only, so none made
        // before a restart is honoured anyway.
        ["nlmf-loc", "v1", "notify", segment, token]
            if *segment == namf_client::N1_NOTIFY_SEGMENT
                || *segment == namf_client::N2_NOTIFY_SEGMENT =>
        {
            let kind = if *segment == namf_client::N1_NOTIFY_SEGMENT {
                context::NotifyKind::N1
            } else {
                context::NotifyKind::N2
            };
            if method != "POST" {
                return send_method_not_allowed(method, segment);
            }
            let Some(owner) = lmf_self()
                .read()
                .ok()
                .and_then(|c| c.notify_subscriber(kind, token))
            else {
                return send_not_found("No subscription holds this callback", None);
            };
            match kind {
                context::NotifyKind::N1 => handle_n1_message_notify(&request, &owner).await,
                context::NotifyKind::N2 => handle_n2_info_notify(&request, &owner).await,
            }
        }
        // ---- #104: Nlmf_Broadcast (TS 29.572 §5.3) --------------------------
        ["nlmf-broadcast", "v1", "cipher-key-data"] => match method {
            "POST" => handle_cipher_key_data(&request).await,
            _ => send_method_not_allowed(method, "cipher-key-data"),
        },
        // ---- #104: Nlmf_DataExposure (TS 29.572 §5.4) -----------------------
        ["nlmf-dataexposure", "v1", "subscriptions"] => match method {
            "POST" => handle_exposure_subscribe(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["nlmf-dataexposure", "v1", "subscriptions", subscription_id] => match method {
            "PATCH" => handle_exposure_modify(subscription_id, &request).await,
            "DELETE" => handle_exposure_unsubscribe(subscription_id, &request).await,
            _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
        },
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

// ---------------------------------------------------------------------------
// #104: Nlmf_Broadcast + Nlmf_DataExposure handlers
// ---------------------------------------------------------------------------

/// Resource collection path for LMF data-exposure subscriptions.
const EXPOSURE_SUBSCRIPTIONS_PATH: &str = "/nlmf-dataexposure/v1/subscriptions";

/// `POST /nlmf-broadcast/v1/cipher-key-data` — `CipheringKeyData`
/// (TS 29.572 §5.3), #104.
///
/// The AMF asks the LMF for broadcast-assistance ciphering key data and supplies
/// the callback the LMF will notify on. `amfCallBackURI` is the yaml's sole
/// required member.
///
/// The response is `CIPHERING_KEY_DATA_NOT_AVAILABLE` whenever this LMF holds no
/// ciphering key sets, which is always today: nothing provisions them (there is no
/// LCS ciphering-key source in this tree, and they cannot be invented — a
/// fabricated key would make a UE decipher assistance data into noise). That is
/// exactly what `dataAvailability` exists to say, so the answer is conformant
/// rather than a stub: the AMF learns not to wait for a notification.
async fn handle_cipher_key_data(request: &SbiRequest) -> SbiResponse {
    let Some(body) = request.http.content.as_deref() else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "Missing CipherRequestData body",
        );
    };
    let data: broadcast_exposure::CipherRequestData = match serde_json::from_str(body) {
        Ok(d) => d,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed CipherRequestData: {e}"),
            )
        }
    };
    if data.amf_call_back_uri.trim().is_empty() {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "amfCallBackURI is mandatory (TS29572_Nlmf_Broadcast.yaml CipherRequestData)",
        );
    }

    // No ciphering-key source exists, so report unavailability rather than
    // promising a notification that will never come.
    log::info!(
        "Nlmf_Broadcast CipheringKeyData request from {}: no ciphering key data held",
        data.amf_call_back_uri
    );
    let response = broadcast_exposure::CipherResponseData {
        data_availability: broadcast_exposure::data_availability::NOT_AVAILABLE.to_string(),
    };
    SbiResponse::with_status(200)
        .with_json_body(&response)
        .unwrap_or_else(|_| {
            problem(
                500,
                nlmf::cause::UNSPECIFIED,
                "Failed to encode CipherResponseData",
            )
        })
}

/// `POST /nlmf-dataexposure/v1/subscriptions` — `CreateSubscription`
/// (TS 29.572 §5.4), #104. `201` + `Location` + the echoed resource.
async fn handle_exposure_subscribe(request: &SbiRequest) -> SbiResponse {
    // #1865: bound to the verified identity of its creator, checked before the
    // body is read or anything is stored.
    let owner = match owner_binding::owner_for_new_resource(request, "CreateSubscription") {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
    let Some(body) = request.http.content.as_deref() else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "Missing LmfDataExposureSubscription body",
        );
    };
    let sub: broadcast_exposure::LmfDataExposureSubscription = match serde_json::from_str(body) {
        Ok(d) => d,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed LmfDataExposureSubscription: {e}"),
            )
        }
    };
    if let Some(missing) = sub.validate() {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            &format!("{missing} is mandatory (LmfDataExposureSubscription required)"),
        );
    }

    let Some(id) = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.exposure_subscription_insert(sub.clone(), owner))
    else {
        return problem(
            500,
            nlmf::cause::UNSPECIFIED,
            "Failed to store the data-exposure subscription",
        );
    };
    log::info!("Nlmf_DataExposure subscription created: id={id}");
    SbiResponse::with_status(201)
        .with_header("Location", format!("{EXPOSURE_SUBSCRIPTIONS_PATH}/{id}"))
        .with_json_body(&sub)
        .unwrap_or_else(|_| {
            problem(
                500,
                nlmf::cause::UNSPECIFIED,
                "Failed to encode LmfDataExposureSubscription",
            )
        })
}

/// `PATCH /nlmf-dataexposure/v1/subscriptions/{id}` — `ModifySubscription`, #104.
///
/// The yaml's body is an array of TS 29.571 `PatchItem`s (RFC 6902 JSON Patch) and
/// the success response is `204`. Only `replace` on a top-level member is applied;
/// anything else is refused rather than silently ignored, because a consumer whose
/// patch was dropped believes its subscription changed.
async fn handle_exposure_modify(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(existing) = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.exposure_subscription_find(subscription_id))
    else {
        return problem(
            404,
            nlmf::cause::SUBSCRIPTION_NOT_FOUND,
            &format!("No data-exposure subscription {subscription_id}"),
        );
    };
    // #1865: only the consumer that created the subscription may modify it,
    // checked before the body is read or anything is stored.
    if let Some(refused) = exposure_owner_refusal(subscription_id, request, "ModifySubscription") {
        return refused;
    }
    let Some(body) = request.http.content.as_deref() else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "Missing PatchItem array body",
        );
    };
    let patches: Vec<serde_json::Value> = match serde_json::from_str(body) {
        Ok(serde_json::Value::Array(items)) => items,
        Ok(_) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                "ModifySubscription takes an array of PatchItem (RFC 6902)",
            )
        }
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed PatchItem array: {e}"),
            )
        }
    };

    let mut document = match serde_json::to_value(&existing) {
        Ok(v) => v,
        Err(_) => {
            return problem(
                500,
                nlmf::cause::UNSPECIFIED,
                "Failed to serialize the stored subscription",
            )
        }
    };
    for patch in &patches {
        let op = patch.get("op").and_then(|v| v.as_str()).unwrap_or_default();
        let path = patch
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // Only a top-level `/member` replace is supported. A nested pointer or an
        // add/remove/move is refused: applying part of a patch is worse than
        // refusing all of it, because the consumer cannot tell which part landed.
        let member = path.strip_prefix('/').filter(|m| !m.contains('/'));
        match (op, member, patch.get("value")) {
            ("replace", Some(member), Some(value)) => {
                if let Some(obj) = document.as_object_mut() {
                    obj.insert(member.to_string(), value.clone());
                }
            }
            _ => {
                return problem(
                    400,
                    nlmf::cause::INVALID_MSG_FORMAT,
                    &format!(
                        "Unsupported patch operation (op={op:?}, path={path:?}): only a \
                         top-level `replace` with a value is applied"
                    ),
                )
            }
        }
    }
    let updated: broadcast_exposure::LmfDataExposureSubscription =
        match serde_json::from_value(document) {
            Ok(u) => u,
            Err(e) => {
                return problem(
                    400,
                    nlmf::cause::INVALID_MSG_FORMAT,
                    &format!("The patched subscription is not a valid resource: {e}"),
                )
            }
        };
    if let Some(missing) = updated.validate() {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            &format!("The patch would remove the mandatory {missing}"),
        );
    }
    if lmf_self()
        .read()
        .ok()
        .map(|c| c.exposure_subscription_replace(subscription_id, updated))
        != Some(true)
    {
        return problem(
            500,
            nlmf::cause::UNSPECIFIED,
            "Failed to store the patched subscription",
        );
    }
    log::info!("Nlmf_DataExposure subscription modified: id={subscription_id}");
    SbiResponse::no_content()
}

/// `DELETE /nlmf-dataexposure/v1/subscriptions/{id}` — `DeleteSubscription`, #104.
/// `204` when it existed, `404` when it did not, `403` when the caller is not
/// the consumer that created it (#1865; nothing is removed).
async fn handle_exposure_unsubscribe(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    if let Some(refused) = exposure_owner_refusal(subscription_id, request, "DeleteSubscription") {
        return refused;
    }
    match lmf_self()
        .read()
        .ok()
        .and_then(|c| c.exposure_subscription_remove(subscription_id))
    {
        Some(_) => {
            log::info!("Nlmf_DataExposure subscription deleted: id={subscription_id}");
            SbiResponse::no_content()
        }
        None => problem(
            404,
            nlmf::cause::SUBSCRIPTION_NOT_FOUND,
            &format!("No data-exposure subscription {subscription_id}"),
        ),
    }
}

/// #1865: the `403` for a caller that did not create data-exposure
/// subscription `subscription_id`; `None` when it may act, or when the id is
/// unknown (the handler answers that 404 itself).
fn exposure_owner_refusal(
    subscription_id: &str,
    request: &SbiRequest,
    operation: &str,
) -> Option<SbiResponse> {
    let owner = lmf_self()
        .read()
        .ok()?
        .exposure_subscription_owner(subscription_id)?;
    owner_binding::refuse_non_owner(owner.as_deref(), request, operation)
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

    // #103 criterion 2: refuse LOUDLY when no reference points are configured, before
    // spending an AMF discovery, an LPP transfer and the whole wait budget to arrive
    // at the same answer. Every geometric solver reads the registry, so with it empty
    // no fix is possible for any UE, any method and any amount of waiting. The problem
    // detail names the configuration rather than saying "positioning failed", because
    // the operator's action is to provision coordinates.
    //
    // AFTER the target-identity check, not before: a request carrying no target is a
    // 400 whatever the deployment looks like, and validating the REQUEST before the
    // DEPLOYMENT is the order a consumer can reason about. Putting this first made
    // `test_determine_location_no_target_identity_400` answer 500 whenever no sibling
    // test had seeded coordinates -- a real ordering bug, caught by a 20-run loop
    // rather than by the single green run that preceded it.
    let reference_points = match lmf_self().read() {
        Ok(context) => context.reference_point_count(),
        Err(_) => 0,
    };
    if reference_points == 0 {
        log::error!(
            "DetermineLocation refused: the cell/TRP reference-point registry is EMPTY, so no \
             location fix can be solved. Provision lmf.positioning.cells / .trps."
        );
        return Err(Box::new(problem(
            500,
            nlmf::cause::POSITIONING_FAILED,
            "No cell or TRP reference points are configured (lmf.positioning.cells / .trps), so              no location fix can be solved for any UE",
        )));
    }

    // Serving-AMF discovery (TS 29.510). Fail-closed: unreachable NRF or no
    // AMF instance means the user cannot be reached for positioning.
    let Some(amf) = namf_client::discover_amf(input.amf_id.as_deref()).await else {
        return Err(Box::new(problem(
            504,
            nlmf::cause::UNREACHABLE_USER,
            "No serving AMF with namf-comm discoverable via the NRF",
        )));
    };

    let lmf_id = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.nf_instance_id())
        .unwrap_or_else(|| "nextgcore-lmf".to_string());
    // A3 subscription first (uplink notify registration), then any transfer: the
    // UE's answers to the capability request and to the location request both
    // come back through it.
    namf_client::ensure_n1n2_subscription(&amf, target).await;

    // #906: the method is chosen on the UE's capabilities, so they are asked for
    // (LPP Capability Transfer, TS 37.355 §5.1.1) before the first request to a
    // UE whose capabilities are not known. The wait counts against the budget.
    let started = std::time::Instant::now();
    if let Some(supi) = input.supi.as_deref() {
        request_ue_capabilities(
            &amf,
            target,
            supi,
            &lmf_id,
            capability_wait(wait_budget(input)),
        )
        .await;
    }

    // #103 criterion 4: the requested method now follows the LCS QoS, the number of
    // configured reference points and the UE's reported LPP capability, instead of
    // being E-CID unconditionally.
    let qos = positioning_qos_from_input(input);
    let capability = match (input.supi.as_deref(), lmf_self().read()) {
        (Some(supi), Ok(context)) => context.ue_lpp_capability(supi),
        _ => crate::codec_glue::UeLppCapability::Unknown,
    };
    let access =
        crate::codec_glue::AccessRat::from_serving_cell(input.ncgi.is_some(), input.ecgi.is_some());
    let flavours = match (input.supi.as_deref(), lmf_self().read()) {
        (Some(supi), Ok(context)) => context.ue_ecid_flavours(supi),
        _ => crate::codec_glue::EcidFlavours::default(),
    };
    let nr = match (input.supi.as_deref(), lmf_self().read()) {
        (Some(supi), Ok(context)) => context.ue_nr_methods(supi),
        _ => crate::codec_glue::NrMethods::default(),
    };
    let budget = wait_budget(input).saturating_sub(started.elapsed());
    let gnb_half_ready = crate::codec_glue::multi_rtt_gnb_half_ready(
        nrppa_downlink::enabled(),
        lmf_self()
            .read()
            .map(|c| c.ng_ran_nodes().len())
            .unwrap_or(0),
    ) && !budget.is_zero();
    let mut method = crate::codec_glue::select_lpp_method(
        qos,
        reference_points,
        capability,
        access,
        flavours,
        nr,
        gnb_half_ready,
    );
    // What is asked for when the gNB half of Multi-RTT cannot be set up: the
    // choice without it, so the UE's capabilities still decide (#906).
    let without_gnb_half = crate::codec_glue::select_lpp_method(
        qos,
        reference_points,
        capability,
        access,
        flavours,
        nr,
        false,
    );
    // The DL-TDOA set rides along with Multi-RTT only for a UE that may support it.
    let also_dl_tdoa = crate::codec_glue::ue_nr_methods(capability, nr).dl_tdoa;
    log::info!(
        "DetermineLocation: selected LPP method {} (qos={qos:?}, {reference_points} reference \
         point(s), UE capability {capability:?} {nr:?}, access {access:?})",
        method.as_spec_str()
    );

    let txn = LPP_TRANSACTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // Measurement-store entry + correlation session, registered BEFORE the
    // POST (TS 29.572 CorrelationID minted inside; TS 37.355 txn indexed).
    // `PositioningMethod` (TS 23.273 6.1, the measurement-store enum) has one
    // `NrBased` variant covering DL-TDOA/UL-TDOA/DL-AoD/UL-AoA/Multi-RTT, so both
    // multilateration methods map onto it. The finer distinction lives in
    // `LppMethod`, which is what the request body and the response's
    // `positioningMethod` are built from.
    let stored_method = match method {
        crate::codec_glue::LppMethod::Ecid | crate::codec_glue::LppMethod::NrEcid => {
            PositioningMethod::Ecid
        }
        crate::codec_glue::LppMethod::MultiRtt | crate::codec_glue::LppMethod::DlTdoa => {
            PositioningMethod::NrBased
        }
    };
    let registered = match lmf_self().read() {
        Ok(context) => context
            .measurement_request(0, stored_method, None, None, qos)
            .map(|req| {
                context.positioning_session_register_for(
                    Some(target.to_string()),
                    input.supi.clone(),
                    txn,
                    req.request_id,
                )
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

    // #103 criterion 3: solicit the gNB half of the measurement over NRPPa, BEFORE
    // the LPP transfer asks the UE for its half — TS 23.273 §6.11.2 has the LMF
    // initiate the E-CID measurement toward NG-RAN, and a report that arrives before
    // the request was sent cannot be correlated.
    //
    // Best-effort and deliberately not fatal: the NRPPa leg IMPROVES a fix (the gNB's
    // Rx-Tx half, the TA, the serving cell as NG-RAN sees it) while the LPP leg is
    // what asks for the measurements a fix needs at all. A gNB that declines NRPPa
    // must not fail a request the UE could still answer.
    //
    // #715 review: an E-CID fix needs this leg's timing term (NR E-CID over LPP
    // carries none), so an E-CID session waits for it as well as for the LPP
    // report before it is solved. The leg is expected BEFORE it is solicited, and
    // withdrawn when the solicitation fails, so a gNB that cannot be reached costs
    // no wait.
    let ecid_session = matches!(
        method,
        crate::codec_glue::LppMethod::Ecid | crate::codec_glue::LppMethod::NrEcid
    );
    if nrppa_downlink::enabled() {
        if let Ok(context) = lmf_self().read() {
            context.positioning_session_set_nrppa_peer(
                &corr,
                crate::context::NrppaPeer {
                    amf: amf.clone(),
                    ue_context_id: target.to_string(),
                },
            );
            if ecid_session {
                context.positioning_session_expect_leg(&corr, MeasurementLeg::NrppaEcid);
            }
        }
        let sent = match nrppa_downlink::build_ecid_measurement_initiation(NRPPA_UE_MEASUREMENT_ID)
        {
            Ok((nrppa_txn, nrppa_pdu)) => {
                let outcome =
                    namf_client::send_n2_nrppa_transfer(&amf, target, &corr, &lmf_id, nrppa_pdu)
                        .await;
                log::info!(
                    "NRPPa E-CID Measurement Initiation (transaction {nrppa_txn:?}) toward the \
                     serving gNB: {outcome:?}"
                );
                outcome == namf_client::TransferOutcome::Initiated
            }
            Err(e) => {
                log::warn!("NRPPa E-CID Measurement Initiation not sent: {e}");
                false
            }
        };
        if !sent && ecid_session {
            if let Ok(context) = lmf_self().read() {
                context.positioning_session_withdraw_leg(&corr, MeasurementLeg::NrppaEcid);
            }
        }
    }

    // #911: the DL-PRS assistance data (TS 38.305 §8.10.3.2 step 7, §8.12), built
    // from the TRP Information of the configured NG-RAN nodes. It names each TRP
    // by a DL-PRS ID this LMF assigns, so the gNB half below is measured on, and
    // the UE's measurements are keyed by, the TRP rather than its PCI.
    let multilateration = matches!(
        method,
        crate::codec_glue::LppMethod::MultiRtt | crate::codec_glue::LppMethod::DlTdoa
    );
    let step = (budget / 5).min(Duration::from_secs(2));
    let transport = AmfNrppa {
        amf: amf.clone(),
        ue_context_id: target.to_string(),
        corr: corr.clone(),
        lmf_id: lmf_id.clone(),
    };
    let assistance = if multilateration
        && nrppa_downlink::enabled()
        && lmf_self()
            .read()
            .is_ok_and(|c| !c.ng_ran_nodes().is_empty())
        && !step.is_zero()
    {
        namf_client::ensure_non_ue_nrppa_subscription(&amf, &lmf_id).await;
        crate::multi_rtt::prepare_assistance(&transport, step, input.ncgi.as_ref()).await
    } else {
        None
    };
    let assisted = assistance
        .as_ref()
        .map(|a| a.trps.clone())
        .unwrap_or_default();

    // #807: the gNB half of Multi-RTT, set up before the UE is asked (TS 38.305
    // §8.10.3.2 steps 1-6 precede step 8). When it cannot be set up, the UE is
    // asked for DL-TDOA instead, which needs no gNB measurement, rather than for
    // UE halves that could never be ranged.
    if method == crate::codec_glue::LppMethod::MultiRtt {
        if let Ok(context) = lmf_self().read() {
            context.positioning_session_expect_leg(&corr, MeasurementLeg::NrppaTrp);
        }
        let setup_started = std::time::Instant::now();
        namf_client::ensure_non_ue_nrppa_subscription(&amf, &lmf_id).await;
        match crate::multi_rtt::prepare(&transport, step, budget.as_millis() as u32, &assisted)
            .await
        {
            Ok(prepared) => {
                let request_id = lmf_self()
                    .read()
                    .ok()
                    .and_then(|c| c.positioning_session_find(&corr))
                    .map(|i| i.request_id);
                // What is left of the budget after the setup, less a margin for
                // the solve, is how long the gNBs' answers are waited for.
                let collect_for = budget.saturating_sub(setup_started.elapsed()).mul_f32(0.75);
                tokio::spawn(async move {
                    let cells = crate::multi_rtt::collect(&transport, prepared, collect_for).await;
                    log::info!("Multi-RTT: {} gNB half/halves collected", cells.len());
                    if let (Some(request_id), Ok(context)) = (request_id, lmf_self().read()) {
                        context.measurement_leg_report(request_id, MeasurementLeg::NrppaTrp, cells);
                    }
                });
            }
            Err(e) => {
                log::warn!(
                    "Multi-RTT: the gNB half cannot be obtained ({e}); asking the UE for NR \
                     DL-TDOA instead"
                );
                if let Ok(context) = lmf_self().read() {
                    context.positioning_session_withdraw_leg(&corr, MeasurementLeg::NrppaTrp);
                }
                method = method_after_gnb_leg(method, false, without_gnb_half);
            }
        }
    }

    // #911: the assistance data goes before the request (step 7 before step 8),
    // in the body of each method the request asks for. Only once it has been
    // delivered are the session's measurements keyed by its DL-PRS IDs; a UE that
    // never got it names TRPs by its posSIBs' IDs. Not for a session that fell
    // back to E-CID (#906: a UE without DL-TDOA whose gNB half failed).
    let multi_rtt = method == crate::codec_glue::LppMethod::MultiRtt;
    let dl_tdoa = method == crate::codec_glue::LppMethod::DlTdoa || (multi_rtt && also_dl_tdoa);
    if let Some(a) = assistance.as_ref().filter(|_| multi_rtt || dl_tdoa) {
        let ad_txn = LPP_TRANSACTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match crate::dl_prs_assistance::provide_assistance_data(
            ad_txn,
            &a.built.data,
            multi_rtt,
            dl_tdoa,
        ) {
            Ok(pdu) => {
                let outcome =
                    namf_client::send_n1n2_transfer(&amf, target, &corr, &lmf_id, pdu).await;
                if outcome == namf_client::TransferOutcome::Initiated {
                    if let Ok(context) = lmf_self().read() {
                        context.positioning_session_set_dl_prs_keys(&corr, a.keys.clone());
                    }
                } else {
                    log::warn!("LPP ProvideAssistanceData not delivered: {outcome:?}");
                }
            }
            Err(e) => log::warn!("LPP ProvideAssistanceData not sent: {e}"),
        }
    }

    let lpp_pdu = match lpp_request_for(method, txn, also_dl_tdoa) {
        Ok(pdu) => pdu,
        Err(e) => {
            if let Ok(context) = lmf_self().read() {
                context.positioning_session_expire(&corr);
            }
            return Err(Box::new(problem(
                500,
                nlmf::cause::POSITIONING_FAILED,
                &format!("LPP RequestLocationInformation encode failed: {e}"),
            )));
        }
    };

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

/// The `LMF-UE-MeasurementID` this LMF uses for its NRPPa E-CID measurements (#103).
///
/// Fixed at 1 rather than allocated per session: TS 38.455 constrains the IE to
/// 1..=15, and this LMF has one outstanding NRPPa E-CID measurement per UE at a time
/// (the request is sent inside `initiate_positioning`, which is per-request). A
/// per-session allocator over 15 values would need a free-list and a release path,
/// which nothing here has, and exhausting it would fail requests that currently
/// succeed. The consequence — two concurrent positioning requests for DIFFERENT UEs
/// share the id — is safe because the id is scoped to the NG-RAN/UE association, not
/// to the LMF.
const NRPPA_UE_MEASUREMENT_ID: u16 = 1;

/// The LPP method once the gNB half's setup is known (#807): Multi-RTT stays
/// only when the gNB half was set up; otherwise the UE is asked for
/// `without_gnb_half`, the selection made with no gNB half (#906: DL-TDOA, or
/// E-CID for a UE that reported Multi-RTT but not DL-TDOA).
fn method_after_gnb_leg(
    method: crate::codec_glue::LppMethod,
    gnb_leg_prepared: bool,
    without_gnb_half: crate::codec_glue::LppMethod,
) -> crate::codec_glue::LppMethod {
    match method {
        crate::codec_glue::LppMethod::MultiRtt if !gnb_leg_prepared => without_gnb_half,
        m => m,
    }
}

/// The LPP request for `method` (#903 review): a Multi-RTT request also asks for
/// DL-TDOA, so that a gNB that fails or never answers the Measurement procedure
/// after it was sent leaves a fix to fall back to, not a 500. Not for a UE that
/// reported no DL-TDOA support (`also_dl_tdoa` false, #906).
fn lpp_request_for(
    method: crate::codec_glue::LppMethod,
    txn: u8,
    also_dl_tdoa: bool,
) -> Result<Vec<u8>, String> {
    match method {
        crate::codec_glue::LppMethod::MultiRtt if also_dl_tdoa => {
            crate::codec_glue::build_lpp_multi_rtt_with_dl_tdoa_request(txn)
        }
        m => crate::codec_glue::build_lpp_request(m, txn),
    }
}

/// How long a positioning request waits for the UE's capabilities (#906): a
/// quarter of its budget, at most 2 s. An LPP round trip through the AMF is
/// tens of milliseconds; a UE that takes longer is positioned on what is known.
fn capability_wait(budget: Duration) -> Duration {
    (budget / 4).min(Duration::from_secs(2))
}

/// LPP Capability Transfer (#906; TS 37.355 §5.1.1): send `supi` a
/// `RequestCapabilities` through the serving AMF and wait up to `wait` for its
/// `ProvideCapabilities`, which the N1 notify records. Does nothing when the UE
/// has reported already, was asked recently without answering, or there is no
/// time. A concurrent request for the same UE waits on the same exchange rather
/// than sending a second one. Never fails the positioning request: without an
/// answer the method is chosen as for an `Unknown` capability.
async fn request_ue_capabilities(
    amf: &namf_client::DiscoveredAmf,
    target: &str,
    supi: &str,
    lmf_id: &str,
    wait: Duration,
) {
    if wait.is_zero() {
        return;
    }
    let txn = LPP_TRANSACTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let Some((corr, rx, started)) = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.capability_exchange_begin(supi, txn))
    else {
        return;
    };
    let abandon = |why: &str| {
        log::warn!("LPP RequestCapabilities to {supi}: {why}; positioning on what is known");
        if let Ok(c) = lmf_self().read() {
            c.capability_exchange_abandon(&corr);
        }
    };
    if started {
        let pdu = match crate::codec_glue::build_lpp_request_capabilities(txn) {
            Ok(pdu) => pdu,
            Err(e) => return abandon(&e),
        };
        let outcome = namf_client::send_n1n2_transfer(amf, target, &corr, lmf_id, pdu).await;
        if outcome != namf_client::TransferOutcome::Initiated {
            return abandon(&format!("not delivered ({outcome:?})"));
        }
        log::info!("LPP RequestCapabilities (transaction {txn}) sent to {supi}");
    }
    match tokio::time::timeout(wait, rx).await {
        Ok(Ok(())) => {}
        _ if started => abandon(&format!("no ProvideCapabilities within {wait:?}")),
        // A request that joined another's exchange leaves the abandoning to it.
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// #557: SLPP sidelink ranging (TS 38.355, TS 38.305 §8.15.2, TS 23.586)
// ---------------------------------------------------------------------------

/// Whether `input` asks for a sidelink range, and to which UE: the request
/// must name `RANGING` in `requestedRangingSlResult` and at least one
/// `relatedUes` entry (TS 29.572 InputData, TS29572_Nlmf_Location.yaml:574-583).
fn sl_ranging_peer(input: &nlmf::InputData) -> Option<&str> {
    input
        .requested_ranging_sl_result
        .as_ref()?
        .iter()
        .any(|r| r == nlmf::RANGING_SL_RESULT_RANGING)
        .then_some(())?;
    input
        .related_ues
        .as_ref()?
        .first()
        .map(|u| u.applicationlayer_id.as_str())
}

/// One SLPP transaction to `target` in location `session`: send what `build`
/// makes on a fresh transaction and wait until `deadline` for the UE's answer
/// on it. Nothing is left waiting on any exit: the exchange guard removes the
/// waiter when this future ends or is dropped.
async fn slpp_exchange(
    amf: &namf_client::DiscoveredAmf,
    target: &str,
    session: &slpp::SessionGuard,
    lmf_id: &str,
    build: fn(u8, Option<u8>) -> Result<Vec<u8>, String>,
    deadline: tokio::time::Instant,
) -> Option<slpp::Uplink> {
    let tid = slpp::next_transaction();
    let Some((_guard, rx)) = slpp::exchanges().begin(target, tid) else {
        log::warn!("SLPP: no exchange slot for {target} transaction {tid}");
        return None;
    };
    let corr = session.correlation_id();
    let pdu = match build(tid, slpp::sequences().next_sequence(target, Some(corr))) {
        Ok(pdu) => pdu,
        Err(e) => {
            log::warn!("SLPP: {e}");
            return None;
        }
    };
    let outcome =
        namf_client::send_n1_transfer(amf, target, corr, lmf_id, namf_client::N1Class::Slpp, pdu)
            .await;
    if outcome != namf_client::TransferOutcome::Initiated {
        log::warn!("SLPP to {target} (transaction {tid}) not delivered: {outcome:?}");
        return None;
    }
    match tokio::time::timeout_at(deadline, rx).await {
        Ok(Ok(answer)) => Some(answer),
        _ => {
            log::warn!("SLPP: no answer from {target} on transaction {tid}");
            None
        }
    }
}

/// SL-RTT ranging between the target UE and `peer` (TS 38.305 §8.15.2.2):
/// - capability transfer (TS 38.355 §5.1), which needs SL-RTT in the
///   sl-TargetUE-Assisted mode;
/// - location information transfer (§5.3) for range measurements;
/// - the range, from the target's half and the peer's (held from the peer's
///   own report).
///
/// `None` when any step fails or the peer's half is not held, and why is logged.
async fn sl_rtt_range(input: &nlmf::InputData, peer: &str, budget: Duration) -> Option<f64> {
    let target = input
        .supi
        .as_deref()
        .or(input.gpsi.as_deref())
        .or(input.pei.as_deref())?;
    if budget.is_zero() {
        log::warn!("SLPP ranging for {target}: no response-time budget left");
        return None;
    }
    let deadline = tokio::time::Instant::now() + budget;
    // #2260: the Application Layer IDs the 5GC maps to the target (TS 23.586
    // §4.3.5, TS 29.519 §6.2.26), read for its GPSI before anything is asked of
    // it. Only a report under one of them is held, and only it yields a range.
    let Some(gpsi) = input.gpsi.as_deref() else {
        log::warn!(
            "SLPP ranging for {target}: no GPSI in the request, so no Application Layer \
             ID can be authorised for it (TS 23.586 §4.3.5)"
        );
        return None;
    };
    let Some(ids) = nudr_client::authorised_app_layer_ids(gpsi).await else {
        log::warn!("SLPP ranging for {target}: its Application Layer IDs could not be read");
        return None;
    };
    if ids.is_empty() {
        log::warn!("SLPP ranging for {target}: the UDR maps no Application Layer ID to it");
        return None;
    }
    slpp::app_id_bindings().authorise(target, &ids);
    let amf = namf_client::discover_amf(input.amf_id.as_deref()).await?;
    let lmf_id = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.nf_instance_id())
        .unwrap_or_else(|| "nextgcore-lmf".to_string());
    namf_client::ensure_n1n2_subscription(&amf, target).await;
    // One location session for the whole run: both transactions travel under
    // its LCS correlation identifier, and its sequence numbers are deleted when
    // the run ends (TS 38.355 §4.3.2).
    let Some(session) = slpp::SessionGuard::begin(target) else {
        log::warn!("SLPP ranging for {target}: too many SLPP location sessions are live");
        return None;
    };

    match slpp_exchange(
        &amf,
        target,
        &session,
        &lmf_id,
        slpp::build_request_capabilities,
        deadline,
    )
    .await?
    {
        slpp::Uplink::Capabilities {
            sl_rtt_ue_assisted: true,
            ..
        } => {}
        other => {
            log::warn!("SLPP ranging for {target}: no UE-assisted SL-RTT capability ({other:?})");
            return None;
        }
    }
    let reporter = match slpp_exchange(
        &amf,
        target,
        &session,
        &lmf_id,
        slpp::build_request_location_information,
        deadline,
    )
    .await?
    {
        slpp::Uplink::Location {
            app_id: Some(app_id),
            ..
        } => app_id,
        other => {
            log::warn!("SLPP ranging for {target}: no SL-RTT report with an ID ({other:?})");
            return None;
        }
    };
    let range = slpp::range_for(target, &reporter, peer.as_bytes());
    if range.is_none() {
        log::warn!(
            "SLPP ranging for {target}: SL-RTT needs both UEs' Rx-Tx (TS 38.305 §8.15.2); \
             the half measured by {peer} on this UE is not held"
        );
    }
    range
}

/// Add the SL-RTT range to a 200 LocationData when `input` asks for one
/// (TS 29.572 LocationData `relatedApplicationlayerId` and
/// `distanceDirection.distance`, TS29572_Nlmf_Location.yaml:785-788, 1848-1857).
/// A range that cannot be measured leaves the location result as it was:
/// locationEstimate is the mandatory part of LocationData, and a missing
/// distance is reported by its absence, never by an invented value.
async fn with_sl_ranging(
    input: &nlmf::InputData,
    resp: SbiResponse,
    budget: Duration,
) -> SbiResponse {
    let Some(peer) = sl_ranging_peer(input) else {
        return resp;
    };
    if resp.status != 200 {
        return resp;
    }
    let Some(distance) = sl_rtt_range(input, peer, budget).await else {
        return resp;
    };
    let Some(mut body) = resp
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
    else {
        return resp;
    };
    body["relatedApplicationlayerId"] = serde_json::Value::String(peer.to_string());
    body["distanceDirection"] = serde_json::json!({ "distance": distance });
    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or(resp)
}

/// An uplink SLPP message (#557), on `owner`'s N1 subscription.
///
/// - SL-RTT halves are recorded under the reporter's applicationLayerID.
/// - An answer completes the exchange waiting on its transaction.
/// - A RequestAssistanceData is answered with ProvideAssistanceData (TS 38.355
///   §5.2.1).
/// - An undecodable message is answered with Error (§5.4.3).
async fn handle_slpp_uplink(
    owner: &context::NotifyOwner,
    lcs_correlation_id: Option<&str>,
    bytes: Vec<u8>,
) -> SbiResponse {
    let Some(ue) = owner.ue_context_id.clone() else {
        return problem(
            404,
            nlmf::cause::LOCATION_SESSION_UNKNOWN,
            "SLPP arrived on a subscription that belongs to no UE",
        );
    };
    let corr = lcs_correlation_id.map(str::to_string);
    let answers = slpp_uplink_answers(&ue, lcs_correlation_id, &bytes);
    if !answers.is_empty() {
        spawn_slpp_downlink(ue, corr, answers);
    }
    SbiResponse::no_content()
}

/// Act on one uplink SLPP message from `ue` in location session `session`
/// (the notification's LCS correlation identifier) and return the SLPP
/// messages that answer it, in sending order.
///
/// - A requested acknowledgement comes first, and it is sent even for a
///   duplicate or an undecodable body (TS 38.355 §4.3.3, §4.3.4.2 step 4).
/// - A repeat of the session's last sequence number is then discarded (§4.3.2).
/// - An undecodable message gets Error (§5.4.3), and RequestAssistanceData gets
///   ProvideAssistanceData (§5.2.5). Anything else completes the exchange
///   waiting on its transaction.
fn slpp_uplink_answers(ue: &str, session: Option<&str>, bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut answers = Vec::new();
    let header = slpp::uplink_header(bytes).unwrap_or_default();
    if let Some(acked) = header.ack_for {
        match slpp::build_ack(acked) {
            Ok(pdu) => answers.push(pdu),
            Err(e) => log::warn!("SLPP acknowledgement for {ue}: {e}"),
        }
    }
    if slpp::sequences().is_duplicate(ue, session, header.seq) {
        log::info!(
            "SLPP from {ue}: duplicate sequence number {:?} discarded",
            header.seq
        );
        return answers;
    }
    match slpp::decode_uplink(bytes) {
        Err(e) => {
            log::warn!(
                "SLPP from {ue}: {} -- answering Error {:?}",
                e.detail,
                e.cause
            );
            let seq = slpp::sequences().next_sequence(ue, session);
            match slpp::build_error(e.tid, seq, e.cause) {
                Ok(pdu) => answers.push(pdu),
                Err(e) => log::warn!("SLPP Error for {ue}: {e}"),
            }
        }
        Ok(slpp::Uplink::AssistanceRequest { tid }) => {
            let seq = slpp::sequences().next_sequence(ue, session);
            match slpp::build_provide_assistance_data(tid, header.session_id, seq) {
                Ok(pdu) => answers.push(pdu),
                Err(e) => log::warn!("SLPP ProvideAssistanceData for {ue}: {e}"),
            }
        }
        Ok(uplink) => {
            // R45 M1 on #2254: only an answer to an exchange this LMF started adds
            // halves, and only under the ID of the UE it arrived from. #2260: that
            // ID is one the 5GC maps to the UE (bound before the run began), never
            // one the UE claims for itself.
            let solicited = slpp::exchanges().is_waiting(ue, uplink.transaction());
            let app_id = match &uplink {
                slpp::Uplink::Capabilities { app_id, .. }
                | slpp::Uplink::Location { app_id, .. } => app_id.as_deref(),
                _ => None,
            };
            let owns_id =
                solicited && app_id.is_some_and(|a| slpp::app_id_bindings().is_bound_to(a, ue));
            if solicited && app_id.is_some() && !owns_id {
                log::warn!(
                    "SLPP from {ue}: its applicationLayerID is not one the network maps to \
                     it (TS 23.586 §4.3.5); its report is not held"
                );
            }
            if let slpp::Uplink::Location {
                app_id: Some(app_id),
                halves,
                ..
            } = &uplink
            {
                if !halves.is_empty() && owns_id {
                    log::info!(
                        "SLPP SL-RTT report from {ue}: {} peer measurement(s) held",
                        halves.len()
                    );
                    slpp::sl_rtt_store().note(app_id, halves);
                } else if !halves.is_empty() && !solicited {
                    log::info!("SLPP from {ue}: an unsolicited SL-RTT report is not held");
                }
            }
            if !slpp::exchanges().complete(ue, uplink.clone()) {
                log::info!("SLPP from {ue} answers no waiting transaction: {uplink:?}");
            }
        }
    }
    answers
}

/// Send SLPP answers to `ue`, in order, on their own task, so the notification
/// is acknowledged without waiting for the AMF.
fn spawn_slpp_downlink(ue: String, corr: Option<String>, pdus: Vec<Vec<u8>>) {
    tokio::spawn(async move {
        // R45 m1 on #2254: the UE's serving AMF, the one its subscription is on.
        let serving = lmf_self().read().ok().and_then(|c| c.amf_for_ue(&ue));
        let amf = match serving {
            Some(amf) => amf,
            None => match namf_client::discover_amf(None).await {
                Some(amf) => amf,
                None => {
                    log::warn!("SLPP answer to {ue}: no AMF discoverable");
                    return;
                }
            },
        };
        let lmf_id = lmf_self()
            .read()
            .ok()
            .and_then(|c| c.nf_instance_id())
            .unwrap_or_else(|| "nextgcore-lmf".to_string());
        let corr = corr.unwrap_or_else(|| format!("slpp-answer-{ue}"));
        for pdu in pdus {
            let outcome = namf_client::send_n1_transfer(
                &amf,
                &ue,
                &corr,
                &lmf_id,
                namf_client::N1Class::Slpp,
                pdu,
            )
            .await;
            if outcome != namf_client::TransferOutcome::Initiated {
                log::warn!("SLPP answer to {ue} not delivered: {outcome:?}");
            }
        }
    });
}

/// NRPPa through the serving AMF (#807): UE-associated over N1N2MessageTransfer,
/// non-UE-associated over NonUeN2MessageTransfer.
struct AmfNrppa {
    amf: namf_client::DiscoveredAmf,
    ue_context_id: String,
    corr: String,
    lmf_id: String,
}

impl crate::multi_rtt::NrppaTransport for AmfNrppa {
    fn session(&self) -> Option<String> {
        Some(self.corr.clone())
    }

    async fn send_ue(&self, pdu: Vec<u8>) -> bool {
        namf_client::send_n2_nrppa_transfer(
            &self.amf,
            &self.ue_context_id,
            &self.corr,
            &self.lmf_id,
            pdu,
        )
        .await
            == namf_client::TransferOutcome::Initiated
    }

    async fn send_non_ue(&self, node: &crate::site_config::NgRanNode, pdu: Vec<u8>) -> bool {
        match namf_client::send_non_ue_nrppa_transfer(&self.amf, node, &self.lmf_id, pdu).await {
            namf_client::TransferOutcome::Initiated => true,
            other => {
                log::warn!("Multi-RTT: non-UE NRPPa to {node:?}: {other:?}");
                false
            }
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

/// A positioning session older than this is reaped (#834 review): twice the
/// hard cap of [`wait_budget`].
const SESSION_REAP_AGE: Duration = Duration::from_secs(40);

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
    await_positioning_outcome_within(input, corr, rx, wait_budget(input)).await
}

/// [`await_positioning_outcome`] with what is left of the budget (#903 review):
/// the Multi-RTT gNB-half setup runs before the wait starts, and it counts
/// against `maxRespTime`.
async fn await_positioning_outcome_within(
    input: &nlmf::InputData,
    corr: String,
    rx: tokio::sync::oneshot::Receiver<PositioningOutcome>,
    budget: Duration,
) -> SbiResponse {
    match tokio::time::timeout(budget, rx).await {
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
            // #715 review: a leg that reported is used; only a session that heard from
            // nobody is unreachable.
            let solved = lmf_self()
                .read()
                .ok()
                .and_then(|c| c.positioning_session_solve_now(&corr));
            match solved {
                Some(PositioningOutcome::Fix(est)) => encode_location_response(input, &est, 0),
                Some(PositioningOutcome::SolverFailed) => problem(
                    500,
                    nlmf::cause::POSITIONING_FAILED,
                    "The measurements received within the response-time budget give no \
                     location fix",
                ),
                None => {
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
    handle_determine_location_with(request, owner_binding::identity_required()).await
}

/// [`handle_determine_location`] under an explicit SBI profile (#2214): the
/// profile is read once, and the same value decides the NF-type gate, the new
/// LDR's owner and the owner check of an LDR it would replace. That also lets a
/// test drive the production path without the process-wide override.
async fn handle_determine_location_with(request: &SbiRequest, production: bool) -> SbiResponse {
    log::info!("Determine Location");

    // #2214: DetermineLocation is the AMF's (TS 23.273 Table 8.3.1-1, and every
    // procedure there that invokes it: "The AMF invokes the
    // Nlmf_Location_DetermineLocation service operation"; the GMLC reaches the
    // LMF through the AMF, and is the EventNotify target, not a caller here). The
    // shared verified-NF-type gate decides before anything is read, so a caller
    // that is not shown to be an AMF learns nothing and starts no positioning:
    // a typed certificate must name AMF as its one NF type, and a token must
    // belong to an instance the NRF lists as an AMF. Under production an
    // anonymous caller is refused too. Under dev an unidentified plaintext
    // caller is still served, as every dev resource is.
    if let Some(refused) = owner_binding::nf_type_refusal_with(
        request,
        nextgcore_sbi::types::NfType::Amf,
        "DetermineLocation",
        production,
    )
    .await
    {
        return refused;
    }

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
        return handle_mo_lr_assistance_data(request, &input).await;
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
        // #103 criterion 6: an area- or motion-event LDR is REFUSED rather than
        // registered and answered 200.
        //
        // It used to be registered and answered 200 while nothing ever armed it in
        // the UE and nothing ever reported it — "the worst failure mode for a
        // location service, because the AMF/GMLC believe the request succeeded",
        // which is #103's own description of the defect. Arming it needs UE-side
        // event detection over LPP that does not exist here, and the alternative to
        // building it is to say so.
        //
        // 501 with `UNSUPPORTED_EVENT_TYPE` is the spec's own answer for exactly
        // this: TS 29.572 Table 6.1.7.3-1 defines it as "the request for creation of
        // a subscription is rejected because none of the events is supported by the
        // LMF". Not a 400 (the request is well-formed) and not a 403 (nothing is
        // forbidden) — the LMF has not implemented it.
        if matches!(
            ldr_type,
            nlmf::ldr_type::ENTERING_INTO_AREA
                | nlmf::ldr_type::LEAVING_FROM_AREA
                | nlmf::ldr_type::BEING_INSIDE_AREA
                | nlmf::ldr_type::MOTION
        ) {
            log::warn!(
                "deferred LDR [{ldr_ref}] of type {ldr_type} refused: this LMF cannot arm \
                 area- or motion-event triggers (no UE-side event detection), so accepting it \
                 would promise reports that never arrive"
            );
            return problem(
                501,
                nlmf::cause::UNSUPPORTED_EVENT_TYPE,
                &format!(
                    "ldrType {ldr_type} requires UE-side event detection that this LMF does not                      implement; PERIODIC deferred location is supported"
                ),
            );
        }
        let periodic = periodic_reporting_from_input(&input);
        // #2077: the LDR belongs to its verified creator, and an existing one
        // is replaced only by its owner, so no other NF can re-point a UE's
        // deferred location at its own hgmlcCallBackURI.
        let owner = match owner_binding::owner_for_new_resource_with(
            request,
            "DetermineLocation",
            production,
        ) {
            Ok(owner) => owner,
            Err(refused) => return *refused,
        };
        if let Some(refused) = register_owned_ldr_with(
            LdrContext {
                ldr_reference: ldr_ref.to_string(),
                ldr_type: ldr_type.to_string(),
                hgmlc_callback_uri: input.hgmlc_call_back_uri.clone(),
                supi: input.supi.clone(),
                periodic_event_info: periodic,
                owner,
            },
            request,
            "DetermineLocation",
            production,
        ) {
            return refused;
        }
        // A8: only PERIODIC + periodicEventInfo + a reachable H-GMLC callback +
        // a target SUPI drives the trigger scheduler. The area- and motion-event
        // types no longer reach here at all — #103 refuses them above — so what
        // remains unarmed is `UE_AVAILABLE`, which registers the context only. That
        // one is left registered rather than refused because its trigger source is a
        // DIFFERENT NF: TS 23.273 has the AMF report UE reachability, so the LMF
        // waiting for it is the right shape and the gap is the AMF subscription, not
        // a missing UE capability. Named here rather than left to be discovered.
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
                let resp = encode_location_response(&input, &fix, age_min);
                return with_sl_ranging(&input, resp, wait_budget(&input)).await;
            }
            log::debug!(
                "stored fix for [{supi}] has no capture timestamp; \
                 running the live positioning procedure instead"
            );
        }
    }

    // A2: the live 5GC-MT-LR procedure — LPP request → Namf N1N2 POST to the
    // serving AMF → bounded wait on THIS session's completion channel.
    let started = std::time::Instant::now();
    let (corr, rx) = match initiate_positioning(&input).await {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    let left = wait_budget(&input).saturating_sub(started.elapsed());
    let resp = await_positioning_outcome_within(&input, corr, rx, left).await;
    let left = wait_budget(&input).saturating_sub(started.elapsed());
    with_sl_ranging(&input, resp, left).await
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
/// MO-LR requesting **location assistance data** (#103 criterion 5, TS 23.273 §6.2,
/// TS 37.355 §5.2).
///
/// Before #103 this logged a line and answered 204 without looking at the UE's PDU:
/// a UE asking for assistance data got a success carrying nothing, which is the
/// worst failure mode for a location service because the UE believes it was served.
///
/// Now: decode the UE's `RequestAssistanceData`, build a real
/// `ProvideAssistanceData` carrying a GNSS reference location derived from the
/// configured reference points, and deliver it over the same N1 path the
/// network-initiated leg uses. 204 remains the answer to the AMF — the assistance
/// data goes to the UE, not into the DetermineLocation response — but it is a 204
/// that means something happened.
///
/// A UE that supplied no PDU still gets assistance: TS 23.273 §6.2 has the request
/// arrive over NAS, and a consumer that sets `ueLocationServiceInd` without attaching
/// the UE's LPP message is asking on the UE's behalf. In that case the LMF answers on
/// transaction 0 rather than refusing, and says so.
async fn handle_mo_lr_assistance_data(
    request: &SbiRequest,
    input: &nlmf::InputData,
) -> SbiResponse {
    // #103 criterion 2 applies here too: assistance data IS a reference location, so
    // with no reference points there is nothing to send.
    let reference = match lmf_self().read() {
        Ok(context) => context.reference_centroid(),
        Err(_) => None,
    };
    let Some((lat, lon, spread_m)) = reference else {
        log::error!(
            "MO-LR assistance data refused: no cell/TRP reference points are configured, so \
             there is no reference location to provide"
        );
        return problem(
            500,
            nlmf::cause::POSITIONING_FAILED,
            "No cell or TRP reference points are configured (lmf.positioning.cells / .trps), so              no GNSS reference location can be provided",
        );
    };

    // Decode the UE's request when one was attached, so the response answers the
    // right transaction. A body that is present but is NOT a RequestAssistanceData is
    // a client error: answering it with assistance data would be answering a question
    // that was not asked.
    let txn = match input
        .lpp_message
        .as_ref()
        .and_then(|r| find_binary_part(request, &r.content_id))
    {
        Some(bytes) => match crate::codec_glue::decode_lpp_request_assistance_data(&bytes) {
            Ok(txn) => txn,
            Err(e) => {
                return problem(
                    400,
                    nlmf::cause::MANDATORY_IE_INCORRECT,
                    &format!("InputData.lppMessage is not an LPP RequestAssistanceData: {e}"),
                )
            }
        },
        None => {
            log::info!(
                "MO-LR assistance data: no UE LPP message attached; answering on transaction 0"
            );
            0
        }
    };

    let pdu = match crate::codec_glue::build_lpp_provide_assistance_data(txn, lat, lon, spread_m) {
        Ok(pdu) => pdu,
        Err(e) => {
            return problem(
                500,
                nlmf::cause::POSITIONING_FAILED,
                &format!("LPP ProvideAssistanceData encode failed: {e}"),
            )
        }
    };

    // Deliver it to the UE over the same N1 path the network-initiated leg uses. A
    // failure here is reported rather than swallowed: a 204 for assistance data that
    // never left the LMF is the defect being removed.
    let Some(target) = input
        .supi
        .as_deref()
        .or(input.gpsi.as_deref())
        .or(input.pei.as_deref())
    else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "InputData carries no target UE identity (supi, gpsi or pei)",
        );
    };
    let Some(amf) = namf_client::discover_amf(input.amf_id.as_deref()).await else {
        return problem(
            504,
            nlmf::cause::UNREACHABLE_USER,
            "No serving AMF with namf-comm discoverable via the NRF",
        );
    };
    let lmf_id = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.nf_instance_id())
        .unwrap_or_else(|| "nextgcore-lmf".to_string());
    let corr = format!("assist-{}", uuid::Uuid::new_v4());
    match namf_client::send_n1n2_transfer(&amf, target, &corr, &lmf_id, pdu).await {
        namf_client::TransferOutcome::Initiated => {
            log::info!(
                "MO-LR assistance data delivered: GNSS reference location                  ({lat:.6}, {lon:.6}) ±{spread_m:.0} m on LPP transaction {txn}"
            );
            SbiResponse::no_content()
        }
        namf_client::TransferOutcome::UeNotReachable => problem(
            504,
            nlmf::cause::UNREACHABLE_USER,
            "The serving AMF reports the target UE is not reachable (UE_NOT_REACHABLE)",
        ),
        namf_client::TransferOutcome::Failed(e) => problem(
            504,
            nlmf::cause::UNREACHABLE_USER,
            &format!("Assistance-data N1N2MessageTransfer failed: {e}"),
        ),
    }
}

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
        nextgcore_sbi::security::sbi_peer_client_config(&host, port)
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

    // #104: an ASSURED lcsQosClass whose accuracy is NOT met discards the estimate
    // and fails (TS 29.572 §6.1.6.2.7). It used to be answered `200` with
    // `NOT_FULFILLED`, which is the BEST_EFFORT semantics applied to a request that
    // explicitly asked for the opposite — a consumer that needs an assured fix (an
    // emergency or regulatory one) got a worse fix labelled as a success.
    //
    // The member itself did not exist on `LocationQoS` before, so the class could
    // not even be read.
    let assured = input
        .location_qos
        .as_ref()
        .and_then(|q| q.lcs_qos_class.as_deref())
        .is_some_and(|c| c.eq_ignore_ascii_case(nlmf::lcs_qos_class::ASSURED));
    if assured && accuracy_fulfilment_indicator == nlmf::accuracy_fulfilment::NOT_FULFILLED {
        let requested = input
            .location_qos
            .as_ref()
            .and_then(|q| q.h_accuracy)
            .unwrap_or(0.0);
        log::warn!(
            "ASSURED lcsQosClass requested {requested} m horizontal accuracy; achieved \
             {} m — discarding the estimate (TS 29.572 §6.1.6.2.7)",
            est.horizontal_accuracy
        );
        return problem(
            500,
            nlmf::cause::POSITIONING_FAILED,
            &format!(
                "ASSURED lcsQosClass: requested horizontal accuracy {requested} m could not be \
                 met (achieved {} m); the estimate is discarded rather than reported as \
                 NOT_FULFILLED",
                est.horizontal_accuracy
            ),
        );
    }

    // #104: velocity, when asked for AND derivable. `velocityRequested` was not a
    // member of `LocationQoS` before, and `velocity_estimate` was hardcoded `None`.
    //
    // Derivable here means a previous stored fix for this UE with an earlier
    // timestamp: these solvers produce position only, so two fixes are the sole
    // basis for a velocity. When there is no previous fix the member is omitted
    // rather than sent as zero — a stationary UE and an unknown velocity are not
    // the same claim.
    let velocity_estimate = input
        .location_qos
        .as_ref()
        .and_then(|q| q.velocity_requested)
        .unwrap_or(false)
        .then(|| {
            // The fix BEFORE the one being reported. `last_location` is the
            // current fix, so deriving against it would give a zero time delta and
            // no velocity — which is how the first version of this failed.
            let previous = input.supi.as_deref().and_then(|supi| {
                lmf_self()
                    .read()
                    .ok()
                    .and_then(|c| c.ue_location_get(supi))
                    .and_then(|ctx| ctx.previous_location)
            })?;
            nlmf::derive_velocity(
                previous.latitude,
                previous.longitude,
                previous.timestamp,
                est.latitude,
                est.longitude,
                est.timestamp,
            )
        })
        .flatten();
    if velocity_estimate.is_none()
        && input
            .location_qos
            .as_ref()
            .and_then(|q| q.velocity_requested)
            .unwrap_or(false)
    {
        log::info!(
            "velocityRequested set but no velocity is derivable (no earlier fix for this UE); \
             omitting velocityEstimate rather than reporting a fabricated zero"
        );
    }

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
            velocity_estimate,
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

/// #2077: register `ldr` unless an LDR with its reference exists and belongs to
/// another NF instance than the caller's verified one (or, under production,
/// to nobody). `Some` is the `403` to send; nothing changed.
fn register_owned_ldr(
    ldr: LdrContext,
    request: &SbiRequest,
    operation: &str,
) -> Option<SbiResponse> {
    register_owned_ldr_with(ldr, request, operation, owner_binding::identity_required())
}

/// [`register_owned_ldr`] under an explicit SBI profile (#2214).
fn register_owned_ldr_with(
    ldr: LdrContext,
    request: &SbiRequest,
    operation: &str,
    production: bool,
) -> Option<SbiResponse> {
    let reference = ldr.ldr_reference.clone();
    let result = match lmf_self().read() {
        Ok(c) => c.register_ldr_unless(ldr, |owner| {
            owner_binding::refuse_non_owner_with(owner, request, operation, production)
        }),
        Err(_) => Err(None),
    };
    match result {
        Ok(()) => None,
        Err(Some(refused)) => {
            log::debug!("{operation} of LDR [{reference}] refused: not its owner");
            Some(refused)
        }
        Err(None) => Some(problem(
            500,
            nlmf::cause::UNSPECIFIED,
            "the LDR store is unavailable",
        )),
    }
}

/// #2077 / #2099: why the requester is not shown to be an `nf_type`, or `None`
/// when it is: the shared verified-NF-type rule
/// (`owner_binding::verified_nf_type`: the consumer certificate's NFTypes,
/// else the NRF profile of the verified token subject, cached, failing closed).
async fn verified_type_refusal(
    request: &SbiRequest,
    nf_type: nextgcore_sbi::types::NfType,
) -> Option<String> {
    owner_binding::verified_nf_type(request, nf_type)
        .await
        .err()
}

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
    // #2077: only the LDR's owner cancels it, checked under the removal's lock.
    let removed = match lmf_self().read() {
        Ok(c) => c.cancel_ldr_unless(&data.ldr_reference, |owner| {
            owner_binding::refuse_non_owner(owner, request, "CancelLocation")
        }),
        Err(_) => Ok(false),
    };
    let removed = match removed {
        Ok(removed) => removed,
        Err(refused) => return refused,
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
    //
    // #104 asked for `DUMMY` to be rejected as "a placeholder value that has no
    // spec meaning". It is NOT rejected, because the premise is wrong:
    // `TS29572_Nlmf_Location.yaml`'s `EventClass` enumerates exactly
    // `[SUPPLEMENTARY_SERVICES, DUMMY]` (plus the open-enumeration string branch).
    // `DUMMY` is a spec-defined member — 3GPP uses it to keep a single-valued
    // enumeration extensible — so refusing it would make this LMF reject a
    // conformant peer. The vendored OpenAPI outranks the issue text.
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

    // #104: restore the periodic parameters from the transferred context, and
    // RE-ARM the scheduler.
    //
    // `periodic_event_info` was hardcoded `None` here, so a relocated PERIODIC
    // deferred LDR was stored as a record whose trigger never restarted: periodic
    // reporting stopped silently at AMF relocation, which is a routine mobility
    // event. The record's presence made it look live.
    let periodic = periodic_reporting_from_event_content(&data.event_report_message.event_content);
    let is_periodic = data.ldr_type.eq_ignore_ascii_case("PERIODIC");

    // #2077 (R31 M1 on #2094): an LDR context is transferred by the OLD LMF
    // (TS 29.572 §5.2.2.5.2 "the NF service consumer (e.g. the old LMF)";
    // TS 23.273 §6.4 step 6, §6.7.2 step 3: LMF1 -> LMF2; the AMF identity is
    // only an input IE, §8.3.2.5), so the caller must be shown to be an LMF --
    // otherwise any NF could transfer in an LDR for any SUPI with its own
    // hgmlcCallBackURI -- and it replaces an existing LDR only if it owns it.
    // Checked before anything is stored or armed. An anonymous transfer is
    // refused under production by `owner_for_new_resource`; under `dev` it is
    // admitted ownerless, as every unbound dev resource is.
    //
    // Limit (R31 on #2094): `hgmlcCallBackURI` is fixed for the LDR's life, so a
    // GMLC failover within its NF set reaches the reports only if that URI names
    // the set (an FQDN), not one instance.
    let owner = match owner_binding::owner_for_new_resource(request, "LocationContextTransfer") {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
    if owner.is_some() {
        if let Some(why) = verified_type_refusal(request, nextgcore_sbi::types::NfType::Lmf).await {
            log::debug!(
                "LocationContextTransfer [{}] refused: {why}",
                data.ldr_reference
            );
            return nextgcore_sbi::server::send_forbidden(
                &format!("LocationContextTransfer: {why}"),
                None,
            );
        }
    }
    if let Some(refused) = register_owned_ldr(
        LdrContext {
            ldr_reference: data.ldr_reference.clone(),
            ldr_type: data.ldr_type.clone(),
            hgmlc_callback_uri: Some(data.hgmlc_call_back_uri.clone()),
            supi: data.supi.clone(),
            periodic_event_info: periodic,
            owner,
        },
        request,
        "LocationContextTransfer",
    ) {
        return refused;
    }

    match (is_periodic, periodic, data.supi.as_deref()) {
        (true, Some(params), Some(supi)) => {
            spawn_periodic_ldr(
                data.ldr_reference.clone(),
                supi.to_string(),
                data.hgmlc_call_back_uri.clone(),
                params,
            );
            log::info!(
                "A8/#104: periodic reporting RE-ARMED for transferred LDR [{}]",
                data.ldr_reference
            );
        }
        // A PERIODIC LDR we cannot re-arm is the case the old code produced for
        // every transfer. It is stored either way -- cancel-location must still
        // find it -- but the operator is told reporting will not resume, and why,
        // rather than being left with a record that looks live.
        (true, None, _) => log::warn!(
            "transferred PERIODIC LDR [{}] carries no periodicEventInfo in \
             eventReportMessage.eventContent: reporting canNOT resume at this LMF. The source \
             LMF must include reportingAmount/reportingInterval for the trigger to be re-armed.",
            data.ldr_reference
        ),
        (true, Some(_), None) => log::warn!(
            "transferred PERIODIC LDR [{}] carries no supi: reporting cannot resume (the \
             EventNotify needs a UE identity to report about)",
            data.ldr_reference
        ),
        (false, _, _) => {}
    }

    SbiResponse::no_content()
}

/// Recover `PeriodicEventInfo` from a transferred `eventReportMessage.eventContent`
/// (#104).
///
/// `eventContent` is a passthrough `serde_json::Value` in this tree, so the
/// parameters are looked for under `periodicEventInfo`, at the top level or nested
/// one level down (a source LMF may wrap them in the event body). The member names
/// are the vendored `PeriodicEventInfo` ones: `reportingAmount` and
/// `reportingInterval` are required there, `reportingIntervalMs` optional.
///
/// `None` when they are absent, which the caller reports rather than papering over
/// with a default cadence — inventing an interval would make this LMF report at a
/// rate the requester never asked for.
fn periodic_reporting_from_event_content(content: &serde_json::Value) -> Option<PeriodicReporting> {
    let info = content.get("periodicEventInfo").or_else(|| {
        content
            .as_object()?
            .values()
            .find_map(|v| v.get("periodicEventInfo"))
    })?;
    let amount = info.get("reportingAmount")?.as_u64()? as u32;
    let interval = info.get("reportingInterval")?.as_u64()? as u32;
    Some(PeriodicReporting {
        // Clamped to >= 1 for the same reason `periodic_reporting_from_input`
        // clamps: a scheduler must make forward progress.
        reporting_amount: amount.max(1),
        reporting_interval_secs: interval,
        reporting_interval_ms: info
            .get("reportingIntervalMs")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
    })
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
    // #104: persist it. This used to validate and discard, so a consumer that
    // configured UP reporting and then asked what the LMF held got nothing back —
    // fabricated success with no way to detect the divergence.
    match lmf_self().read().ok().and_then(|c| c.up_config_store(data)) {
        Some(key) => {
            log::info!("UP location configuration stored for {key}");
            SbiResponse::no_content()
        }
        None => problem(
            500,
            nlmf::cause::UNSPECIFIED,
            "Failed to store the UP location configuration",
        ),
    }
}

/// POST /nlmf-loc/v1/up-subscriptions (TS 29.572 §6.1.4.8).
///
/// Creates a UP location reporting subscription. Returns 201 Created with the
/// subscription resource location header and the subscription body.
async fn handle_up_subscribe(request: &SbiRequest) -> SbiResponse {
    // #1865: bound to the verified identity of its creator, checked before the
    // body is read or anything is stored.
    let owner = match owner_binding::owner_for_new_resource(request, "Subscribe") {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
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
    // #104: STORE it. The id used to be minted, echoed in `Location`, and
    // dropped, so the subscription existed only in the consumer's belief.
    let Some(id) = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.up_subscription_insert(sub.clone(), owner))
    else {
        return problem(
            500,
            nlmf::cause::UNSPECIFIED,
            "Failed to store the UP location subscription",
        );
    };
    let location = format!("/nlmf-loc/v1/up-subscriptions/{id}");
    log::info!("UP location subscription created: id={id}");
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
/// `204` when the subscription existed and was removed, `404` when it did not
/// (#104).
///
/// This used to ignore the id entirely and always answer `204`, so a consumer
/// reconciling its state by deleting a stale subscription was told the delete
/// succeeded against an LMF that had never held one. §6.1.4.9 requires the 404,
/// and the distinction is the only way a consumer can detect the divergence.
///
/// #1865: only the consumer that subscribed may unsubscribe; another caller gets
/// `403` and the subscription stays.
async fn handle_up_unsubscribe(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    let owner = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.up_subscription_owner(subscription_id));
    if let Some(owner) = owner {
        if let Some(refused) =
            owner_binding::refuse_non_owner(owner.as_deref(), request, "Unsubscribe")
        {
            return refused;
        }
    }
    match lmf_self()
        .read()
        .ok()
        .and_then(|c| c.up_subscription_remove(subscription_id))
    {
        Some(_) => {
            log::info!("UP location subscription deleted: id={subscription_id}");
            SbiResponse::no_content()
        }
        None => problem(
            404,
            nlmf::cause::SUBSCRIPTION_NOT_FOUND,
            &format!("No UP location subscription {subscription_id}"),
        ),
    }
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
                    nr_ecid: None,
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
                    ue_rx_tx_ns: c.get("ueRxTxNs").and_then(|v| v.as_f64()),
                    rstd_reference: None,
                    ecid_rtt_ns: c.get("ecidRttNs").and_then(|v| v.as_f64()),
                    ecid_rtt_width_ns: None,
                    gnb_rx_tx_ns: c.get("gnbRxTxNs").and_then(|v| v.as_f64()),
                    meas_time: None,
                    dl_prs_id: None,
                    eutra: false,
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
/// The SUPI a notification belongs to, resolved the same way
/// [`resolve_notify_session`] resolves the session (nextgsim #138).
///
/// Separate function rather than a widened return type: the session resolution is on
/// the hot path of every notify, and a caller that wants the request id must not be
/// made to care about a SUPI that may legitimately be absent.
/// The pending positioning session a notification names, by its
/// `lcsCorrelationId`, else by its LPP transaction, and only if it is `owner`'s
/// UE's (#1518): a subscription's notification never acts on another UE's
/// session, however it guessed the correlation.
fn resolve_notify_info(
    lcs_correlation_id: Option<&str>,
    lpp_txn: Option<u8>,
    owner: &context::NotifyOwner,
) -> Option<context::PositioningSessionInfo> {
    let ctx = lmf_self();
    let context = ctx.read().ok()?;
    let serves =
        |info: &context::PositioningSessionInfo| owner.serves(info.ue_context_id.as_deref());
    if let Some(corr) = lcs_correlation_id {
        if let Some(info) = context.positioning_session_find(corr).filter(serves) {
            return Some(info);
        }
    }
    let txn = lpp_txn?;
    let corr = context.positioning_session_find_by_transaction(txn)?;
    context.positioning_session_find(&corr).filter(serves)
}

fn resolve_notify_supi(
    lcs_correlation_id: Option<&str>,
    lpp_txn: Option<u8>,
    owner: &context::NotifyOwner,
) -> Option<String> {
    resolve_notify_info(lcs_correlation_id, lpp_txn, owner)?.supi
}

fn resolve_notify_session(
    lcs_correlation_id: Option<&str>,
    lpp_txn: Option<u8>,
    owner: &context::NotifyOwner,
) -> Option<u64> {
    Some(resolve_notify_info(lcs_correlation_id, lpp_txn, owner)?.request_id)
}

/// Send an NRPPa ERROR INDICATION to the gNB that sent an erroneous report
/// (#515, TS 38.455 §10), through the AMF and UE context the session's NRPPa leg
/// used. Best effort: a session with no NRPPa leg recorded (the report arrived
/// unsolicited, or the session is gone) has nowhere to send it, which is logged.
async fn send_nrppa_error_indication(lcs_correlation_id: Option<&str>, pdu: Vec<u8>) {
    let peer = lcs_correlation_id.and_then(|corr| {
        lmf_self()
            .read()
            .ok()
            .and_then(|c| c.positioning_session_find(corr))
            .and_then(|info| info.nrppa_peer)
    });
    let Some(peer) = peer else {
        log::warn!(
            "NRPPa ERROR INDICATION not sent: no NRPPa leg recorded for lcsCorrelationId \
             {lcs_correlation_id:?}"
        );
        return;
    };
    let lmf_id = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.nf_instance_id())
        .unwrap_or_else(|| "nextgcore-lmf".to_string());
    let outcome = namf_client::send_n2_nrppa_transfer(
        &peer.amf,
        &peer.ue_context_id,
        lcs_correlation_id.unwrap_or_default(),
        &lmf_id,
        pdu,
    )
    .await;
    log::info!("NRPPa ERROR INDICATION toward the serving gNB: {outcome:?}");
}

/// Callback: `POST /nlmf-loc/v1/notify/n1-message-notify/{token}` — Namf_Communication N1MessageNotify
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
///
/// #1518: reached only on a token a subscription holds, and `owner` is that
/// subscription. A report acts only for its UE: a session, capability exchange or
/// SLPP exchange of another UE is not touched.
async fn handle_n1_message_notify(
    request: &SbiRequest,
    owner: &context::NotifyOwner,
) -> SbiResponse {
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

    // #557: SLPP (TS 38.355) arrives on the same N1 callback, typed by
    // n1MessageClass "SLPP" (payload container type 12, TS 24.501 k00
    // §5.4.5.2.5 c1). It is never decoded as LPP.
    if notification
        .pointer("/n1MessageContainer/n1MessageClass")
        .and_then(serde_json::Value::as_str)
        == Some(slpp::N1_MESSAGE_CLASS_SLPP)
    {
        return handle_slpp_uplink(owner, lcs_correlation_id, lpp_bytes).await;
    }

    // Decode the uplink LPP; keep the result so its transactionID can seed the
    // correlation fallback.
    let decoded = codec_glue::decode_lpp_provide_report(&lpp_bytes);
    let lpp_txn = decoded.as_ref().ok().map(|(rid, _)| *rid as u8);

    // #998: an LPP Abort or Error on a RequestCapabilities transaction ends that
    // Capability Transfer at once (TS 37.355 §5.4), rather than letting the
    // positioning request wait out its capability wait. The UE is backed off as
    // for no answer. On any other transaction it is the location request's.
    if let Some((txn, what)) = codec_glue::decode_lpp_abort_or_error(&lpp_bytes) {
        let exchange = lmf_self().read().ok().and_then(|c| {
            c.capability_exchange_on(lcs_correlation_id, txn)
                .filter(|corr| {
                    owner.serves(c.capability_exchange_supi(Some(corr), None).as_deref())
                })
        });
        if let Some(corr) = exchange {
            log::warn!(
                "LPP {what} on the RequestCapabilities transaction {txn}: the Capability \
                 Transfer ends; positioning on what is known"
            );
            if let Ok(c) = lmf_self().read() {
                c.capability_exchange_abandon(&corr);
            }
            return SbiResponse::no_content();
        }
    }

    // #834 review: a ProvideCapabilities is what the method selection reads
    // (capability class, E-CID flavours and, since #906, the NR methods). It was
    // decoded nowhere on the uplink, so the stored capability was always Unknown.
    //
    // #906: it is normally the answer to this LMF's RequestCapabilities, found by
    // the lcsCorrelationId that request was sent with, else by its LPP
    // transaction (TS 37.355 §5.1.1). An unsolicited one (§5.1.2) is filed
    // against the positioning session's UE, as before.
    if let Some(caps) = codec_glue::decode_lpp_provide_capabilities(&lpp_bytes) {
        let mine = |supi: &String| owner.serves(Some(supi));
        let supi = lmf_self()
            .read()
            .ok()
            .and_then(|c| c.capability_exchange_supi(lcs_correlation_id, None))
            .filter(mine)
            .or_else(|| resolve_notify_supi(lcs_correlation_id, lpp_txn, owner))
            .or_else(|| {
                lmf_self()
                    .read()
                    .ok()
                    .and_then(|c| c.capability_exchange_supi(None, caps.transaction))
                    .filter(mine)
            });
        match supi {
            Some(supi) => {
                if let Ok(context) = lmf_self().read() {
                    log::info!(
                        "LPP ProvideCapabilities from {supi}: {:?}, E-CID {:?}, NR {:?}",
                        caps.class,
                        caps.ecid,
                        caps.nr
                    );
                    context.note_ue_capabilities(&supi, &caps);
                }
            }
            None => log::warn!(
                "LPP ProvideCapabilities with no SUPI to file it against \
                 (lcsCorrelationId={lcs_correlation_id:?})"
            ),
        }
        // #907 review: a capability report is not a measurement report. Counted
        // as the session's LPP leg, an unsolicited one completed the session as a
        // 500 and the real report then found no session (404).
        return SbiResponse::no_content();
    }

    let Some(request_id) = resolve_notify_session(lcs_correlation_id, lpp_txn, owner) else {
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
        context.measurement_leg_report(request_id, MeasurementLeg::Lpp, cells);
    }
    SbiResponse::no_content()
}

/// Callback: `POST /nlmf-loc/v1/notify/n2-info-notify/{token}` — Namf_Communication N2InfoNotify
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
///
/// #1518: reached only on a token a subscription holds, and `owner` is that
/// subscription. A UE-associated report acts only on its UE's session. The answer
/// to a waiting NRPPa exchange is taken on any of this LMF's N2 callbacks: it is
/// matched to its exchange by procedure and transaction, and amfd relays a non-UE
/// answer through a UE's N2 subscription when this LMF has no non-UE one
/// (`n1n2_subscription_find_any_n2`).
async fn handle_n2_info_notify(request: &SbiRequest, owner: &context::NotifyOwner) -> SbiResponse {
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

    // #807: the answer to an NRPPa exchange this LMF is waiting on (TRP
    // Information, Positioning Information, Positioning Activation, Measurement)
    // goes to its waiter, matched by procedure code and transaction id. A non-UE-
    // associated answer names no session, so this comes before the session lookup.
    // A UE-associated one is taken only on its own UE's subscription (#1518).
    if let Some((kind, procedure, txn)) = crate::nrppa_positioning::header(&nrppa_bytes) {
        if kind != crate::nrppa_positioning::Kind::Initiating {
            let delivered = lmf_self()
                .read()
                .map(|c| {
                    c.nrppa_deliver(
                        procedure,
                        txn,
                        lcs_correlation_id,
                        owner,
                        nrppa_bytes.clone(),
                    )
                })
                .unwrap_or(false);
            if delivered {
                return SbiResponse::no_content();
            }
        }
    }

    let Some(request_id) = resolve_notify_session(lcs_correlation_id, None, owner) else {
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
    // is not consulted for routing (only the measurements are used). TS 38.455 §10
    // (via TS 38.413 §10.3.4.2): a report carrying a reject IE, or missing a
    // reject IE, is not used; a notify or reject finding goes back to the gNB in
    // an NRPPa ERROR INDICATION, relayed the way the measurement was requested.
    let (cells, error_indication) = match crate::nrppa_uplink::decode_ecid_report(&nrppa_bytes) {
        Ok(crate::nrppa_uplink::EcidReportOutcome::Accepted {
            cells,
            error_indication,
            ..
        }) => (cells, error_indication),
        Ok(crate::nrppa_uplink::EcidReportOutcome::Rejected {
            error_indication,
            reason,
        }) => {
            log::warn!("N2InfoNotify NRPPa report not used (request_id {request_id}): {reason}");
            (Vec::new(), Some(error_indication))
        }
        Err(e) => {
            log::warn!(
                "N2InfoNotify NRPPa decode failed for session (request_id {request_id}): {e}"
            );
            (Vec::new(), None)
        }
    };
    if let Some(ei) = error_indication {
        send_nrppa_error_indication(lcs_correlation_id, ei).await;
    }
    if let Ok(context) = lmf_self().read() {
        context.measurement_leg_report(request_id, MeasurementLeg::NrppaEcid, cells);
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

/// Build the `/capabilities` body from a context (#104).
///
/// A **pure function of the context**, not of process-global state, so both
/// branches are testable: the process-global LMF context is shared with every
/// other test in this binary and any sibling that wires a cell coordinate makes
/// the "no measurement source" branch unobservable through the handler.
///
/// `nrppaSupported` / `nlsInterfaceSupported` used to be hardcoded `true` while
/// the mainline measure-location path answered `403
/// LOCATION_MEASUREMENT_UNKNOWN` for want of a measurement source — so an interop
/// partner selected an NRPPa/NLs method on the strength of this advertisement and
/// had every request fail. They now track whether this LMF has cell/TRP
/// coordinates to solve against.
fn capabilities_body(context: &context::LmfContext) -> serde_json::Value {
    let methods: Vec<String> = context
        .supported_methods()
        .iter()
        .map(|m| format!("{m:?}"))
        .collect();
    let measurement_source = context.measurement_source_available();
    serde_json::json!({
        "supportedMethods": methods,
        "nrppaSupported": measurement_source,
        "nlsInterfaceSupported": measurement_source,
    })
}

/// Handle capabilities query
async fn handle_capabilities() -> SbiResponse {
    let body = match lmf_self().read() {
        Ok(context) => capabilities_body(&context),
        Err(_) => return problem(500, nlmf::cause::UNSPECIFIED, "LMF context lock poisoned"),
    };
    SbiResponse::with_status(200)
        .with_json_body(&body)
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

/// Every Nlmf service this LMF serves, with the NF types allowed to consume it
/// (TS 29.510 §6.1.6.2.3 `NFService.allowedNfTypes`).
///
/// ONE table (#392), consumed by both [`build_lmf_nf_instance`] (the typed self
/// instance) and [`build_lmf_nf_profile`] (the NFProfile PUT to the NRF). #104
/// had already fixed the profile to advertise all three services TS 23.501
/// Table 7.2.25-1 lists, but the self instance was still built with `nlmf-loc`
/// alone, so the two disagreed about what this LMF serves.
const LMF_SERVICES: &[(nextgcore_sbi::types::SbiServiceType, &[&str])] = &[
    // TS 29.572 Nlmf_Location, consumed by the AMF (and the GMLC via the AMF).
    (
        nextgcore_sbi::types::SbiServiceType::NlmfLoc,
        &["AMF", "GMLC", "SCP"],
    ),
    // TS 29.572 Nlmf_Broadcast: ciphering-key provision toward the AMF.
    (
        nextgcore_sbi::types::SbiServiceType::NlmfBroadcast,
        &["AMF", "SCP"],
    ),
    // TS 29.572 LMF data exposure, consumed by analytics/exposure NFs.
    (
        nextgcore_sbi::types::SbiServiceType::NlmfDataexposure,
        &["NWDAF", "DCCF", "NEF", "AMF", "SCP"],
    ),
];

/// Build this LMF's typed self NF instance from [`LMF_SERVICES`].
fn build_lmf_nf_instance(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
) -> nextgcore_sbi::context::NfInstance {
    let mut self_instance =
        nextgcore_sbi::context::NfInstance::new(nf_instance_id, nextgcore_sbi::types::NfType::Lmf);
    nextgcore_sbi::nf_addressing::set_instance_host(&mut self_instance, sbi_addr);
    self_instance.heartbeat_interval = 10;
    for (service_type, _allowed) in LMF_SERVICES {
        let mut svc = nextgcore_sbi::context::NfService::new(service_type.to_name(), *service_type);
        svc.port = sbi_port;
        nextgcore_sbi::nf_addressing::set_service_host(&mut svc, sbi_addr);
        self_instance.add_service(svc);
    }
    self_instance
}

/// Build the NFProfile registered with the NRF (TS 29.510 §6.1.6.2.2), #104.
///
/// Extracted from `register_with_nrf` so the advertised service list is
/// assertable: it was inline, and it was wrong — TS 23.501 Table 7.2.25-1 lists
/// three LMF services and only `nlmf-loc` appeared, so a consumer discovering
/// this LMF could not find the other two even once they existed.
///
/// #392: now rendered from [`LMF_SERVICES`], with per-service `allowedNfTypes`
/// and an NF-level union, so the profile and the self instance cannot drift.
fn build_lmf_nf_profile(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    scheme: nextgcore_sbi::types::UriScheme,
) -> serde_json::Value {
    let services: Vec<serde_json::Value> = LMF_SERVICES
        .iter()
        .map(|(service_type, allowed)| {
            let name = service_type.to_name();
            serde_json::json!({
                "serviceInstanceId": format!("{nf_instance_id}-{name}"),
                "serviceName": name,
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": scheme.as_str(),
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
                "allowedNfTypes": allowed,
            })
        })
        .collect();

    let mut nf_allowed: Vec<&str> = Vec::new();
    for (_, allowed) in LMF_SERVICES {
        for t in *allowed {
            if !nf_allowed.contains(t) {
                nf_allowed.push(t);
            }
        }
    }

    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "LMF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": services,
            "allowedNfTypes": nf_allowed,
            "heartBeatTimer": 10
        }),
        sbi_addr,
    )
}

/// Register LMF with NRF
async fn register_with_nrf(
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
    sbi_scheme: nextgcore_sbi::types::UriScheme,
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

    // #104: built by `build_lmf_nf_profile` so a test can assert what this NF
    // advertises. It was inline here, which made the advertised service list
    // unassertable — and the list was wrong (one service of three).
    let nf_profile = build_lmf_nf_profile(nf_instance_id, sbi_addr, sbi_port, sbi_scheme);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("LMF registered with NRF successfully (id={nf_instance_id})");
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&nf_profile);

            // From the SAME table the profile came from: it used to be built here
            // with `nlmf-loc` alone, so the self instance claimed one service
            // while the registered profile claimed three (#392).
            sbi_ctx
                .set_self_instance(build_lmf_nf_instance(nf_instance_id, sbi_addr, sbi_port))
                .await;

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

/// Test-only: the subscription an AMF would have sent `request` on, i.e. that of
/// the UE it names (its `supi`), else of the UE whose session its
/// `lcsCorrelationId` names. Tests of the token gate itself go through the router
/// with a real subscription (`a_notification_acts_only_on_its_subscriptions_token_1518`).
#[cfg(test)]
fn test_owner(request: &SbiRequest) -> context::NotifyOwner {
    let body: serde_json::Value = request
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or_default();
    let named = body
        .get("supi")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let ue_context_id = named.or_else(|| {
        let corr = body.get("lcsCorrelationId")?.as_str()?;
        lmf_self()
            .read()
            .ok()?
            .positioning_session_find(corr)?
            .ue_context_id
    });
    context::NotifyOwner { ue_context_id }
}

/// Test-only: [`handle_n1_message_notify`] on the subscription [`test_owner`] names.
#[cfg(test)]
async fn notify_n1(request: &SbiRequest) -> SbiResponse {
    handle_n1_message_notify(request, &test_owner(request)).await
}

/// Test-only: [`handle_n2_info_notify`] on the subscription [`test_owner`] names.
#[cfg(test)]
async fn notify_n2(request: &SbiRequest) -> SbiResponse {
    handle_n2_info_notify(request, &test_owner(request)).await
}

/// #2214: the AMF the tests' DetermineLocation requests come from. The handler
/// admits only a verified AMF (TS 23.273 Table 8.3.1-1). Under the default
/// production profile an anonymous request is refused, so a test that drives
/// positioning as a plain caller would pass only after a sibling set Dev (the
/// #2157 trap). It calls as this AMF instead: a token the NRF lists as an AMF
/// (seeded), valid under both profiles.
#[cfg(test)]
const TEST_AMF_2214: &str = "aaaaaaaa-2214-4000-8000-0000000000a1";

/// `request` as [`TEST_AMF_2214`], unless it already carries an identity (a
/// test of another caller sets its own).
#[cfg(test)]
fn as_test_amf(mut request: SbiRequest) -> SbiRequest {
    owner_binding::seed_nf_type_for_test(TEST_AMF_2214, nextgcore_sbi::types::NfType::Amf);
    if request.peer_cert_nf_instance_id.is_none() && request.oauth2_subject.is_none() {
        request.oauth2_subject = Some(TEST_AMF_2214.to_string());
    }
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2214: [`super::handle_determine_location`] as [`as_test_amf`]'s AMF.
    /// Shadows the glob import, so every positioning test here calls as the
    /// AMF. The gate's own tests call `handle_determine_location_with`
    /// directly.
    async fn handle_determine_location(request: &SbiRequest) -> SbiResponse {
        super::handle_determine_location(&as_test_amf(request.clone())).await
    }

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-lmfd"]);
        assert_eq!(args.sbi_addr, None);
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-lmfd"]);
        assert_eq!(args.config, "/etc/nextgcore/lmf.yaml");
        assert_eq!(args.sbi_port, None);
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
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

    /// #104: seed a fix at an explicit position AND timestamp, so a test can build
    /// the two-fix history a velocity is derived from.
    fn seed_fix_displaced(supi: &str, latitude: f64, longitude: f64, timestamp: u64) {
        let loc = LocationEstimate {
            latitude,
            longitude,
            horizontal_accuracy: 20.0,
            method_used: Some(nlmf::positioning_method::ECID.to_string()),
            timestamp,
            ..Default::default()
        };
        assert!(lmf_self().read().unwrap().ue_location_update(supi, loc));
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
        // #1884: the fix it seeds is process state a sibling's `lmf_context_init`
        // now clears, so it holds the lock between seeding and reading.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // A real measurement-derived fix must exist for a non-fabricating 200.
        seed_fix("imsi-001010000000099", 40.0);
        let req = as_test_amf(
            SbiRequest::post("/nlmf-loc/v1/determine-location")
                .with_body(r#"{"supi":"imsi-001010000000099"}"#, "application/json"),
        );
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);

        // The bespoke/debug routes, each with the method it normally handles.
        // `/capabilities` joined them in #104: it is not a TS 29.572 resource, it
        // discloses this NF's positioning posture, and it was the one bespoke route
        // left ungated. Added to THIS test rather than a second toggling one,
        // because two tests toggling the same process-global gate is the
        // disjoint-agreement hazard the comment above warns about.
        let normal: [(&str, &str); 8] = [
            ("POST", "/nlmf-loc/v1/measurements"),
            ("GET", "/nlmf-loc/v1/measurements/abc"),
            ("POST", "/nlmf-loc/v1/nrppa-reports"),
            ("POST", "/nlmf-loc/v1/nrppa-binary-reports"),
            ("POST", "/nlmf-loc/v1/lpp-binary-reports"),
            ("GET", "/nlmf-loc/v1/ue-locations/imsi-001010000000777"),
            ("PUT", "/nlmf-loc/v1/ue-locations/imsi-001010000000777"),
            ("GET", "/nlmf-loc/v1/capabilities"),
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
        let reachable: [&str; 7] = [
            "/nlmf-loc/v1/measurements",
            "/nlmf-loc/v1/measurements/abc",
            "/nlmf-loc/v1/nrppa-reports",
            "/nlmf-loc/v1/nrppa-binary-reports",
            "/nlmf-loc/v1/lpp-binary-reports",
            "/nlmf-loc/v1/ue-locations/imsi-001010000000777",
            "/nlmf-loc/v1/capabilities",
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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

    /// #104 acceptance: an `ASSURED` `lcsQosClass` whose accuracy is NOT met is
    /// REFUSED — the estimate is discarded — while `BEST_EFFORT` (and an unstated
    /// class) still answers `200 NOT_FULFILLED`.
    ///
    /// Both branches in one test against the same seeded fix, because the defect
    /// was that they were the SAME branch: `lcsQosClass` was not a member of
    /// `LocationQoS`, so an assured request got best-effort semantics and a worse
    /// fix labelled as a success. A consumer that needs an assured fix (an
    /// emergency or regulatory one) could not tell.
    #[tokio::test]
    async fn test_assured_qos_class_refuses_an_unmet_accuracy() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // 200 m achieved accuracy against a 10 m request: not fulfillable.
        seed_fix("imsi-001010000000101", 200.0);
        let request = |qos: &str| {
            let body = format!(
                r#"{{"supi":"imsi-001010000000101","locationQoS":{qos},
                     "supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"]}}"#
            );
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json")
        };

        // BEST_EFFORT: 200 with NOT_FULFILLED (unchanged behaviour).
        let resp = handle_determine_location(&request(
            r#"{"hAccuracy":10.0,"lcsQosClass":"BEST_EFFORT"}"#,
        ))
        .await;
        assert_eq!(resp.status, 200);
        let ext: nlmf::LocationDataExt =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            ext.location_data.accuracy_fulfilment_indicator.as_deref(),
            Some("REQUESTED_ACCURACY_NOT_FULFILLED")
        );

        // No class at all behaves as best effort, so a pre-#104 consumer is
        // unaffected.
        let resp = handle_determine_location(&request(r#"{"hAccuracy":10.0}"#)).await;
        assert_eq!(resp.status, 200);

        // ASSURED: refused, and the response carries NO location estimate.
        let resp =
            handle_determine_location(&request(r#"{"hAccuracy":10.0,"lcsQosClass":"ASSURED"}"#))
                .await;
        assert_eq!(
            resp.status, 500,
            "an ASSURED request whose accuracy cannot be met must not be a 200"
        );
        let content = resp.http.content.as_deref().unwrap_or("");
        assert!(
            content.contains("POSITIONING_FAILED"),
            "the cause must say the positioning failed, got {content}"
        );
        assert!(
            !content.contains("locationEstimate"),
            "the estimate must be DISCARDED, not returned alongside the error: {content}"
        );

        // ASSURED whose accuracy IS met still succeeds — the refusal is about the
        // accuracy, not about the class.
        seed_fix("imsi-001010000000102", 5.0);
        let met = SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(
            r#"{"supi":"imsi-001010000000102","locationQoS":{"hAccuracy":10.0,
                "lcsQosClass":"ASSURED"},"supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"]}"#,
            "application/json",
        );
        assert_eq!(handle_determine_location(&met).await.status, 200);
    }

    /// #104 acceptance: `velocityRequested` populates `velocityEstimate` when a
    /// previous fix makes it derivable, and omits it when it does not.
    #[tokio::test]
    async fn test_velocity_requested_populates_the_estimate_when_derivable() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // TWO fixes for the same UE, 10 s and ~111 m apart. The first is displaced
        // into `previous_location` by the second, which is the two-fix history the
        // derivation needs — a single fix has no velocity.
        seed_fix_displaced("imsi-001010000000103", 37.5000, -122.3, 1_000);
        seed_fix_displaced("imsi-001010000000103", 37.5010, -122.3, 1_010);

        let request = SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(
            r#"{"supi":"imsi-001010000000103","locationQoS":{"hAccuracy":100.0,
                "velocityRequested":true},"supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"]}"#,
            "application/json",
        );
        let resp = handle_determine_location(&request).await;
        assert_eq!(resp.status, 200);
        let ext: nlmf::LocationDataExt =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let velocity = ext
            .location_data
            .velocity_estimate
            .expect("velocityRequested with two timestamped fixes must produce a velocityEstimate");
        let speed = velocity["hSpeed"].as_f64().expect("hSpeed");
        assert!(
            (10.0..13.0).contains(&speed),
            "~111 m in 10 s is ~11 m/s, got {speed}"
        );
        assert_eq!(velocity["bearing"], 0, "due north");

        // Not requested => omitted, so an existing consumer's body is unchanged.
        let no_velocity = SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(
            r#"{"supi":"imsi-001010000000103","locationQoS":{"hAccuracy":100.0},
                "supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"]}"#,
            "application/json",
        );
        let ext: nlmf::LocationDataExt = serde_json::from_str(
            handle_determine_location(&no_velocity)
                .await
                .http
                .content
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        assert!(ext.location_data.velocity_estimate.is_none());
    }

    // -- lmfd-04: shape negotiation honors supportedGADShapes ----------------
    #[tokio::test]
    async fn test_determine_location_negotiates_ellipse_shape() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // #103: seed a reference point, because the live procedure now refuses with
        // 500 BEFORE AMF discovery when the registry is empty. This test used to reach
        // AMF discovery only because a SIBLING happened to have seeded coordinates --
        // neither `init` nor `fini` clears the registry -- so it was ordering-coupled
        // and #103's own registry-clearing test exposed it. Seeded here so it fails at
        // AMF discovery for its own reason.
        lmf_context_init(1024);
        {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard.set_cell_coord(
                "amf-unreachable-cell",
                crate::positioning::TrpCoord::new(37.5, 126.9, 0.0),
            );
        }
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        // #103: seed a reference point, for the same reason as
        // `test_determine_location_never_serves_another_ues_report` -- the live
        // procedure refuses with 500 before AMF discovery on an empty registry, and
        // this test asserts the 504 it gets AFTER discovery fails.
        {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard.set_cell_coord(
                "ageless-fix-cell",
                crate::positioning::TrpCoord::new(37.5, 126.9, 0.0),
            );
        }
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        // #103: seed a reference point. The live procedure now refuses with 500 BEFORE
        // AMF discovery when the registry is empty, and neither `init` nor `fini`
        // clears the registry -- so this test used to reach AMF discovery only because
        // a SIBLING had seeded coordinates. That coupling made it fail about 1 run in
        // 8 once #103 added a test that clears the registry.
        {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard.set_cell_coord(
                "mt-lr-isolation-cell",
                crate::positioning::TrpCoord::new(37.5, 126.9, 0.0),
            );
        }
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
                    nr_ecid: None,
                    nr_cgi: "001-01-424242-01".to_string(),
                    rsrp: Some(-70),
                    rsrq: Some(-9),
                    timing_advance: Some(50),
                    aoa: None,
                    rtt_ns: None,
                    rstd_ns: None,
                    ue_rx_tx_ns: None,
                    rstd_reference: None,
                    ecid_rtt_ns: None,
                    ecid_rtt_width_ns: None,
                    gnb_rx_tx_ns: None,
                    meas_time: None,
                    dl_prs_id: None,
                    eutra: false,
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let body = r#"{}"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/measure-location").with_body(body, "application/json");
        let resp = handle_measure_location(&req).await;
        assert_eq!(resp.status, 403);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "LOCATION_MEASUREMENT_UNKNOWN");
    }

    // -- lmfd#0: location-context-transfer ------------------------------------

    /// #2157: the NF instance the LDR tests below call as. They used to call
    /// with no identity, which only a dev deployment admits (#2077:
    /// `owner_for_new_resource`, `refuse_non_owner`), so each passed only after
    /// a sibling had set the Dev override and failed 403 alone. A production
    /// peer proves who it is, so these tests now do too and pass under either
    /// profile, with the LDR bound to that caller.
    const PEER_2157: &str = "cccccccc-2157-4000-8000-00000000000c";

    /// `request` from [`PEER_2157`], proven by its token.
    fn from_peer_2157(mut request: SbiRequest) -> SbiRequest {
        request.oauth2_subject = Some(PEER_2157.to_string());
        request
    }

    /// `request` from [`PEER_2157`] as the old LMF a LocationContextTransfer
    /// comes from (TS 29.572 §5.2.2.5.2): the NRF lists it as an LMF.
    fn from_lmf_2157(request: SbiRequest) -> SbiRequest {
        owner_binding::seed_nf_type_for_test(PEER_2157, nextgcore_sbi::types::NfType::Lmf);
        from_peer_2157(request)
    }

    /// #2214: the test AMF (`super::TEST_AMF_2214`), the verified AMF a
    /// DetermineLocation must come from (TS 23.273 Table 8.3.1-1).
    const AMF_2214: &str = super::TEST_AMF_2214;

    /// `request` from [`AMF_2214`], proven by its token.
    fn from_amf_2214(request: SbiRequest) -> SbiRequest {
        as_test_amf(request)
    }

    #[tokio::test]
    async fn test_location_context_transfer_204() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let body = r#"{
            "amfId": "amf-01",
            "ldrType": "PERIODIC",
            "hgmlcCallBackURI": "http://gmlc/ctx-cb",
            "ldrReference": "aa01",
            "eventReportMessage": { "eventClass": "SUPPLEMENTARY_SERVICES", "eventContent": {} }
        }"#;
        let req = from_lmf_2157(
            SbiRequest::post("/nlmf-loc/v1/location-context-transfer")
                .with_body(body, "application/json"),
        );
        let resp = handle_location_context_transfer(&req).await;
        assert_eq!(resp.status, 204, "{:?}", resp.http.content);
        // LDR context must be registered, and bound to the LMF that sent it.
        let found = lmf_self().read().unwrap().ldr_find("aa01");
        let found = found.expect("LDR context not registered");
        assert_eq!(found.ldr_type, "PERIODIC");
        assert_eq!(found.owner.as_deref(), Some(PEER_2157));
    }

    #[tokio::test]
    async fn test_location_context_transfer_bad_event_class_403() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // Seed an LDR session directly.
        lmf_self().read().unwrap().register_ldr(LdrContext {
            ldr_reference: "bb01".to_string(),
            ldr_type: "UE_AVAILABLE".to_string(),
            hgmlc_callback_uri: Some("http://gmlc/cb".to_string()),
            supi: None,
            periodic_event_info: None,
            owner: Some(PEER_2157.to_string()),
        });

        // First cancel, by the LDR's owner -> 204.
        let body = r#"{"hgmlcCallBackURI":"http://gmlc/cb","ldrReference":"bb01"}"#;
        let req = from_peer_2157(
            SbiRequest::post("/nlmf-loc/v1/cancel-location").with_body(body, "application/json"),
        );
        let resp = handle_cancel_location(&req).await;
        assert_eq!(resp.status, 204, "{:?}", resp.http.content);
        assert!(lmf_self().read().unwrap().ldr_find("bb01").is_none());

        // Second cancel -> 403 LOCATION_SESSION_UNKNOWN.
        let req2 = from_peer_2157(
            SbiRequest::post("/nlmf-loc/v1/cancel-location").with_body(body, "application/json"),
        );
        let resp2 = handle_cancel_location(&req2).await;
        assert_eq!(resp2.status, 403);
        let v = body_json(&resp2);
        assert_eq!(v["cause"], "LOCATION_SESSION_UNKNOWN");
    }

    // -- #2077: an LDR is bound to its verified owner -------------------------

    fn transfer_2077(reference: &str, callback: &str) -> SbiRequest {
        let body = serde_json::json!({
            "amfId": "amf-01",
            "ldrType": "UE_AVAILABLE",
            "hgmlcCallBackURI": callback,
            "ldrReference": reference,
            "supi": "imsi-001010000002077",
            "eventReportMessage": { "eventClass": "SUPPLEMENTARY_SERVICES", "eventContent": {} }
        });
        SbiRequest::post("/nlmf-loc/v1/location-context-transfer")
            .with_body(body.to_string(), "application/json")
    }

    fn cancel_2077(reference: &str) -> SbiRequest {
        let body =
            serde_json::json!({ "hgmlcCallBackURI": "http://gmlc/cb", "ldrReference": reference });
        SbiRequest::post("/nlmf-loc/v1/cancel-location")
            .with_body(body.to_string(), "application/json")
    }

    /// **#2077**: an LDR transferred in by an LMF is that LMF's. Every other
    /// caller -- another LMF's token or certificate, an anonymous one, and one
    /// whose certificate and token disagree -- is refused 403 when it transfers
    /// the same `ldrReference` with its own `hgmlcCallBackURI` (the location
    /// redirect) and when it cancels it, and nothing changes. The owner then
    /// cancels it.
    ///
    /// REVERT-VERIFIED: with `register_owned_ldr`'s owner check removed, the
    /// foreign transfer is answered 204 and "refused: transfer by foreign token"
    /// fails; with `cancel_ldr_unless`'s check removed, "refused: cancel by
    /// foreign certificate" fails.
    #[tokio::test]
    async fn an_ldr_is_replaced_and_cancelled_only_by_its_owner_2077() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        // Both are LMFs, so what refuses the stranger is the owner check.
        owner_binding::seed_nf_type_for_test(OWNER_1865, nextgcore_sbi::types::NfType::Lmf);
        owner_binding::seed_nf_type_for_test(OTHER_1865, nextgcore_sbi::types::NfType::Lmf);
        let reference = "cc2077";
        let resp = handle_location_context_transfer(&owned_1865(transfer_2077(
            reference,
            "http://gmlc/owner",
        )))
        .await;
        assert_eq!(resp.status, 204, "{:?}", resp.http.content);
        let ldr = lmf_self()
            .read()
            .unwrap()
            .ldr_find(reference)
            .expect("registered");
        assert_eq!(ldr.owner.as_deref(), Some(OWNER_1865));

        for (who, req) in strangers_1865(|| transfer_2077(reference, "http://evil/cb")) {
            let resp = handle_location_context_transfer(&req).await;
            assert_eq!(resp.status, 403, "refused: transfer by {who}");
            let ldr = lmf_self()
                .read()
                .unwrap()
                .ldr_find(reference)
                .expect("kept");
            assert_eq!(
                ldr.hgmlc_callback_uri.as_deref(),
                Some("http://gmlc/owner"),
                "{who}"
            );
            assert_eq!(ldr.owner.as_deref(), Some(OWNER_1865), "{who}");
        }
        for (who, req) in strangers_1865(|| cancel_2077(reference)) {
            let resp = handle_cancel_location(&req).await;
            assert_eq!(resp.status, 403, "refused: cancel by {who}");
            assert!(
                lmf_self().read().unwrap().ldr_find(reference).is_some(),
                "{who}: still registered"
            );
        }
        assert_eq!(
            handle_cancel_location(&owned_1865(cancel_2077(reference)))
                .await
                .status,
            204
        );
        assert!(lmf_self().read().unwrap().ldr_find(reference).is_none());
    }

    /// #2162: the exact refusal of a certificate naming no NF types and no
    /// token under the `dev` profile (#2099's typeless check, `owner_binding`).
    /// Production's sentence (#2065) is pinned in owner_binding's own tests,
    /// which pass the profile explicitly.
    fn typeless_reason_2162(want: &str) -> String {
        format!(
            "the requester's certificate names no NF types and it sent no access token, \
             so it cannot be shown to be an {want}"
        )
    }

    /// **#2077** (R31 M1 on #2094): a LocationContextTransfer comes from the old
    /// LMF (TS 29.572 §5.2.2.5.2, TS 23.273 §6.4 step 6: LMF1 -> LMF2), and the
    /// caller must be shown to be an LMF (CONVENTIONS: the verified NF type).
    /// Refused, with nothing registered: a token the NRF does not list as an
    /// LMF's (an AMF's), that token through an SCP, a certificate without NF
    /// types and no token (even for a listed LMF), an AMF certificate and a GMLC
    /// certificate. Admitted, LMF to LMF: a certificate naming LMF, an SCP with a
    /// listed LMF's token, and a listed LMF's token alone.
    ///
    /// #2099: on the shared `owner_binding::verified_nf_type`, whose own
    /// reverts this test also catches (with its typeless refusal reverted,
    /// "refused: typeless" fails).
    ///
    /// REVERT-VERIFIED: with the `verified_type_refusal` call removed, the
    /// unlisted token's transfer is answered 204 and "refused: token only" fails;
    /// with the expected type back at AMF (the #2077 first cut), the listed
    /// AMF's token is admitted and "refused: token only" fails (and the owner
    /// test's LMF is refused its own transfer).
    #[tokio::test]
    async fn a_location_context_transfer_needs_a_verified_lmf_2077() {
        // #2162 (R42 on #2173): the profile is set at the start, not read: sibling tests
        // set the Dev override concurrently (none sets production), so a
        // reading taken here could differ from the handler's. Under dev the
        // handler applies #2099's typeless check, whose exact sentence this
        // pins; production's is pinned in owner_binding's tests.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        const DIRECT: &str = "dddddddd-2077-4000-8000-00000000000d";
        const VIA_SCP: &str = "eeeeeeee-2077-4000-8000-00000000000e";
        const TOKEN: &str = "ffffffff-2077-4000-8000-00000000000f";
        const AN_AMF: &str = "99999999-2077-4000-8000-000000000009";
        const SCP: &str = "55555555-2077-4000-8000-000000000005";
        for id in [DIRECT, VIA_SCP, TOKEN] {
            owner_binding::seed_nf_type_for_test(id, nextgcore_sbi::types::NfType::Lmf);
        }
        // An AMF, listed as one: still not the LMF a transfer comes from.
        owner_binding::seed_nf_type_for_test(AN_AMF, nextgcore_sbi::types::NfType::Amf);
        let with = |reference: &str, cert: Option<(&str, &[&str])>, token: Option<&str>| {
            let mut req = transfer_2077(reference, "http://gmlc/cb");
            if let Some((id, types)) = cert {
                req.peer_cert_nf_instance_id = Some(id.to_string());
                req.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            }
            req.oauth2_subject = token.map(str::to_string);
            req
        };
        let typeless_reason = typeless_reason_2162("LMF");
        for (what, req, expect) in [
            (
                "token only",
                with("x2077-1", None, Some(AN_AMF)),
                "does not list",
            ),
            (
                "SCP",
                with("x2077-2", Some((SCP, &["SCP"])), Some(AN_AMF)),
                "does not list",
            ),
            (
                "typeless",
                with("x2077-3", Some((DIRECT, &[])), None),
                typeless_reason.as_str(),
            ),
            (
                "GMLC",
                with("x2077-4", Some((AN_AMF, &["GMLC"])), None),
                "not LMF",
            ),
            (
                "AMF certificate",
                with("x2077-5", Some((AN_AMF, &["AMF"])), None),
                "not LMF",
            ),
        ] {
            let resp = handle_location_context_transfer(&req).await;
            assert_eq!(resp.status, 403, "refused: {what}");
            let detail = body_json(&resp)["detail"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(detail.contains(expect), "{what}: {detail}");
        }
        for r in ["x2077-1", "x2077-2", "x2077-3", "x2077-4", "x2077-5"] {
            assert!(
                lmf_self().read().unwrap().ldr_find(r).is_none(),
                "{r} not registered"
            );
        }
        for (what, req, reference, owner) in [
            (
                "direct",
                with("y2077-1", Some((DIRECT, &["LMF"])), None),
                "y2077-1",
                DIRECT,
            ),
            (
                "SCP",
                with("y2077-2", Some((SCP, &["SCP"])), Some(VIA_SCP)),
                "y2077-2",
                VIA_SCP,
            ),
            (
                "token only",
                with("y2077-3", None, Some(TOKEN)),
                "y2077-3",
                TOKEN,
            ),
        ] {
            let resp = handle_location_context_transfer(&req).await;
            assert_eq!(
                resp.status, 204,
                "admitted: {what}: {:?}",
                resp.http.content
            );
            let ldr = lmf_self()
                .read()
                .unwrap()
                .ldr_find(reference)
                .expect("registered");
            assert_eq!(ldr.owner.as_deref(), Some(owner), "{what}");
        }
    }

    // -- lmfd#0: up-subscriptions 201 + unsubscribe 204 ----------------------

    #[tokio::test]
    async fn test_up_subscribe_201_and_unsubscribe_204() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let body = r#"{
            "upNotifyCallBackUri": "http://af/up",
            "notifCorrelationId": "nc-sub-1",
            "supi": "imsi-001010000000080"
        }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/up-subscriptions").with_body(body, "application/json");
        let resp = handle_up_subscribe(&owned_1865(req)).await;
        assert_eq!(resp.status, 201);
        let location = resp
            .http
            .get_header("Location")
            .cloned()
            .expect("Location header missing on 201");
        let id = location.rsplit('/').next().unwrap().to_string();

        // #104: the subscription is RETRIEVABLE, which is what makes the 201
        // more than an echo. It used to be minted and dropped.
        let stored = lmf_self()
            .read()
            .ok()
            .and_then(|c| c.up_subscription_find(&id))
            .expect("the subscription must be stored under the id in Location");
        assert_eq!(stored.notif_correlation_id, "nc-sub-1");
        assert_eq!(stored.supi, "imsi-001010000000080");
        assert_eq!(stored.up_notify_call_back_uri, "http://af/up");

        // #104: 201 -> 204 -> 404. This assertion is INVERTED from what it was.
        // It previously read "DELETE any subscriptionId -> 204" and passed an
        // arbitrary id, pinning the defect AS the requirement: TS 29.572 §6.1.4.9
        // requires a 404 for a subscription that does not exist, and answering 204
        // told a consumer reconciling its state that a delete had succeeded against
        // an LMF that never held the subscription.
        assert_eq!(
            handle_up_unsubscribe(&id, &owned_1865(SbiRequest::delete("/")))
                .await
                .status,
            204
        );
        assert_eq!(
            handle_up_unsubscribe(&id, &owned_1865(SbiRequest::delete("/")))
                .await
                .status,
            404,
            "a second delete of the same id must be 404, not another 204"
        );
        assert_eq!(
            handle_up_unsubscribe("sub-never-existed", &owned_1865(SbiRequest::delete("/")))
                .await
                .status,
            404,
            "an id that was never issued must be 404"
        );
    }

    const OWNER_1865: &str = "aaaaaaaa-1865-4000-8000-00000000000a";
    const OTHER_1865: &str = "bbbbbbbb-1865-4000-8000-00000000000b";

    /// #1865: `request` from the consumer [`OWNER_1865`], proven by its token.
    fn owned_1865(mut request: SbiRequest) -> SbiRequest {
        request.oauth2_subject = Some(OWNER_1865.to_string());
        request
    }

    /// #1865: every caller that is not the creator, each with how it fails to be.
    fn strangers_1865(request: impl Fn() -> SbiRequest) -> Vec<(&'static str, SbiRequest)> {
        let mut foreign_cert = request();
        foreign_cert.peer_cert_nf_instance_id = Some(OTHER_1865.to_string());
        // #2065: typed, as a consumer's certificate is (RFC 9310).
        foreign_cert.peer_cert_nf_types = vec!["AMF".into()];
        let mut foreign_token = request();
        foreign_token.oauth2_subject = Some(OTHER_1865.to_string());
        let mut mismatch = request();
        mismatch.peer_cert_nf_instance_id = Some(OWNER_1865.to_string());
        // #2065: typed, as a consumer's certificate is (RFC 9310).
        mismatch.peer_cert_nf_types = vec!["AMF".into()];
        mismatch.oauth2_subject = Some(OTHER_1865.to_string());
        vec![
            ("foreign certificate", foreign_cert),
            ("foreign token", foreign_token),
            ("anonymous", request()),
            ("certificate/token mismatch", mismatch),
        ]
    }

    /// #1865: an Nlmf_DataExposure subscription is modified and deleted only by
    /// the consumer that created it; every other caller gets 403 and nothing
    /// changes. REVERT-VERIFIED: with the PATCH check removed the foreign PATCH
    /// returns 204; with the DELETE check removed the foreign DELETE returns
    /// 204; with the owner not recorded at create (`None` passed to the insert)
    /// the bound-owner assertion fails; with the create check ignored the
    /// mismatched create returns 201.
    #[tokio::test]
    async fn data_exposure_subscriptions_are_managed_by_their_creator_1865() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let body = r#"{"notificationUri":"http://nwdaf/x","notifyCorrelationId":"c-1865",
            "aoi":{"praId":"pra-1"},"numOfSamples":10}"#;
        let create = || {
            SbiRequest::post("/nlmf-dataexposure/v1/subscriptions")
                .with_body(body, "application/json")
        };
        let resp = lmf_sbi_request_handler(owned_1865(create())).await;
        assert_eq!(resp.status, 201);
        let id = resp
            .http
            .get_header("Location")
            .and_then(|l| l.rsplit('/').next().map(str::to_string))
            .expect("Location");
        let uri = format!("{EXPOSURE_SUBSCRIPTIONS_PATH}/{id}");
        assert_eq!(
            lmf_self().read().unwrap().exposure_subscription_owner(&id),
            Some(Some(OWNER_1865.to_string())),
            "bound to the verified creator"
        );
        let samples = || {
            lmf_self()
                .read()
                .unwrap()
                .exposure_subscription_find(&id)
                .and_then(|s| s.num_of_samples)
        };
        let patch = || {
            SbiRequest::patch(uri.clone()).with_body(
                r#"[{"op":"replace","path":"/numOfSamples","value":99}]"#,
                "application/json",
            )
        };
        for (who, req) in strangers_1865(patch) {
            assert_eq!(
                lmf_sbi_request_handler(req).await.status,
                403,
                "{who} PATCH"
            );
            assert_eq!(samples(), Some(10), "{who}: the PATCH applied nothing");
        }
        for (who, req) in strangers_1865(|| SbiRequest::delete(uri.clone())) {
            assert_eq!(
                lmf_sbi_request_handler(req).await.status,
                403,
                "{who} DELETE"
            );
            assert_eq!(
                samples(),
                Some(10),
                "{who}: the subscription is still stored"
            );
        }
        // The owner, proven by its certificate this time.
        let mut by_cert = patch();
        by_cert.peer_cert_nf_instance_id = Some(OWNER_1865.to_uppercase());
        // #2065: typed, as a consumer's certificate is (RFC 9310).
        by_cert.peer_cert_nf_types = vec!["AMF".into()];
        assert_eq!(lmf_sbi_request_handler(by_cert).await.status, 204);
        assert_eq!(samples(), Some(99));
        assert_eq!(
            lmf_sbi_request_handler(owned_1865(SbiRequest::delete(uri.clone())))
                .await
                .status,
            204
        );
        assert_eq!(samples(), None);

        // A caller whose certificate and token disagree stores nothing.
        let before = lmf_self().read().unwrap().exposure_subscription_count();
        let mut mixed = create();
        mixed.peer_cert_nf_instance_id = Some(OWNER_1865.to_string());
        // #2065: typed, as a consumer's certificate is (RFC 9310).
        mixed.peer_cert_nf_types = vec!["AMF".into()];
        mixed.oauth2_subject = Some(OTHER_1865.to_string());
        assert_eq!(lmf_sbi_request_handler(mixed).await.status, 403);
        assert_eq!(
            lmf_self().read().unwrap().exposure_subscription_count(),
            before
        );
    }

    /// #1865: a UP-location subscription is deleted only by the consumer that
    /// created it. REVERT-VERIFIED: with the DELETE check removed every
    /// stranger's DELETE returns 204; with the create check removed the
    /// mismatched create returns 201 and the count grows.
    #[tokio::test]
    async fn up_subscriptions_are_deleted_by_their_creator_only_1865() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let create = || {
            SbiRequest::post("/nlmf-loc/v1/up-subscriptions").with_body(
                r#"{"upNotifyCallBackUri":"http://af/up","notifCorrelationId":"nc-1865",
                    "supi":"imsi-001010000001865"}"#,
                "application/json",
            )
        };
        let resp = lmf_sbi_request_handler(owned_1865(create())).await;
        assert_eq!(resp.status, 201);
        let id = resp
            .http
            .get_header("Location")
            .and_then(|l| l.rsplit('/').next().map(str::to_string))
            .expect("Location");
        let uri = format!("/nlmf-loc/v1/up-subscriptions/{id}");
        for (who, req) in strangers_1865(|| SbiRequest::delete(uri.clone())) {
            assert_eq!(lmf_sbi_request_handler(req).await.status, 403, "{who}");
            assert!(
                lmf_self()
                    .read()
                    .unwrap()
                    .up_subscription_find(&id)
                    .is_some(),
                "{who}: the subscription is still stored"
            );
        }
        assert_eq!(
            lmf_sbi_request_handler(owned_1865(SbiRequest::delete(uri.clone())))
                .await
                .status,
            204
        );

        let before = lmf_self().read().unwrap().up_subscription_count();
        let mut mixed = create();
        mixed.peer_cert_nf_instance_id = Some(OWNER_1865.to_string());
        // #2065: typed, as a consumer's certificate is (RFC 9310).
        mixed.peer_cert_nf_types = vec!["AMF".into()];
        mixed.oauth2_subject = Some(OTHER_1865.to_string());
        assert_eq!(lmf_sbi_request_handler(mixed).await.status, 403);
        assert_eq!(lmf_self().read().unwrap().up_subscription_count(), before);
    }

    /// #104: `configure-up` PERSISTS the configuration; it used to validate and
    /// discard, so a consumer could not tell a stored configuration from a
    /// forgotten one.
    #[tokio::test]
    async fn test_configure_up_persists_the_configuration() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let body = r#"{
            "upNotifyCallBackUri": "http://af/up-cfg",
            "notifCorrelationId": "nc-cfg-1",
            "supi": "imsi-001010000000081",
            "amfReallocationInd": true
        }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/configure-up").with_body(body, "application/json");
        assert_eq!(handle_configure_up(&req).await.status, 204);

        let stored = lmf_self()
            .read()
            .ok()
            .and_then(|c| c.up_config_find("imsi-001010000000081"))
            .expect("the configuration must be stored under the UE identity");
        assert_eq!(stored.notif_correlation_id, "nc-cfg-1");
        assert_eq!(stored.up_notify_call_back_uri, "http://af/up-cfg");
        assert_eq!(stored.amf_reallocation_ind, Some(true));

        // Neither supi nor gpsi is still a 400 (unchanged).
        let bad = SbiRequest::post("/nlmf-loc/v1/configure-up").with_body(
            r#"{"upNotifyCallBackUri":"http://af/x","notifCorrelationId":"n"}"#,
            "application/json",
        );
        assert_eq!(handle_configure_up(&bad).await.status, 400);
    }

    /// #104: `measurement_source_available` is false until a measurement source is
    /// wired, and true after.
    ///
    /// Tested against a FRESH `LmfContext`, not the process-global one: the global
    /// context is shared with every other test in this binary and a sibling that
    /// wires a cell coordinate makes the "no source" case unobservable. That is
    /// how the first version of this test failed — passing alone, failing in the
    /// suite.
    #[test]
    fn test_measurement_source_availability_tracks_the_cell_registry() {
        let ctx = context::LmfContext::new();
        assert!(
            !ctx.measurement_source_available(),
            "a context with no cell/TRP coordinates has no real measurement source"
        );
        ctx.set_cell_coord(
            "001-01-0x1000-1",
            positioning::TrpCoord {
                lat_deg: 52.5,
                lon_deg: 13.4,
                height_m: 0.0,
            },
        );
        assert!(
            ctx.measurement_source_available(),
            "a wired coordinate is what makes the measurement path able to solve"
        );
    }

    /// #104 acceptance: the `/capabilities` flags are DERIVED from whether a
    /// measurement source is wired — both branches, on fresh contexts.
    ///
    /// Pure, not through the handler: the process-global context is shared with
    /// every other test in this binary, and a sibling that wires a cell coordinate
    /// makes the `false` branch unobservable. The first version of this test went
    /// through the handler and **passed with the flags hardcoded back to `true`**,
    /// because it had wired a coordinate itself — a guard that proved nothing.
    #[test]
    fn test_capabilities_flags_track_the_real_measurement_source() {
        // No measurement source: both flags false.
        let bare = context::LmfContext::new();
        let body = capabilities_body(&bare);
        assert_eq!(
            body["nrppaSupported"], false,
            "with no measurement source the flag must be false, not hardcoded true"
        );
        assert_eq!(body["nlsInterfaceSupported"], false);
        assert!(
            body["supportedMethods"]
                .as_array()
                .is_some_and(|m| !m.is_empty()),
            "the method list is unrelated to the measurement source and stays populated"
        );

        // Wire one: both flags flip.
        bare.set_cell_coord(
            "001-01-0xcap01-1",
            positioning::TrpCoord {
                lat_deg: 52.5,
                lon_deg: 13.4,
                height_m: 0.0,
            },
        );
        let body = capabilities_body(&bare);
        assert_eq!(body["nrppaSupported"], true);
        assert_eq!(body["nlsInterfaceSupported"], true);
    }

    /// #104: the handler serves `capabilities_body` for the live context — the
    /// wiring the pure test above cannot cover.
    ///
    /// Asserts equality against the body computed from the same context rather than
    /// against a literal, so it holds whatever state a sibling test has left behind.
    #[tokio::test]
    async fn test_capabilities_handler_serves_the_derived_body() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let resp = handle_capabilities().await;
        assert_eq!(resp.status, 200);
        let served: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let expected = lmf_self()
            .read()
            .map(|c| capabilities_body(&c))
            .expect("context readable");
        assert_eq!(
            served, expected,
            "the handler must serve the derived body, not a body of its own"
        );
    }

    /// #104 acceptance: `Nlmf_Broadcast` is routed and answers per
    /// `TS29572_Nlmf_Broadcast.yaml`.
    ///
    /// `CIPHERING_KEY_DATA_NOT_AVAILABLE` is the conformant answer, not a stub:
    /// nothing provisions ciphering key sets in this tree, and `dataAvailability`
    /// exists precisely to tell the AMF not to wait for a notification. Inventing a
    /// key would make a UE decipher assistance data into noise.
    #[tokio::test]
    async fn test_nlmf_broadcast_cipher_key_data() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);

        let req = SbiRequest::post("/nlmf-broadcast/v1/cipher-key-data").with_body(
            r#"{"amfCallBackURI":"http://amf/cipher-notify"}"#,
            "application/json",
        );
        let resp = lmf_sbi_request_handler(req).await;
        assert_ne!(resp.status, 404, "the service must be routed");
        assert_eq!(resp.status, 200);
        let body: broadcast_exposure::CipherResponseData =
            serde_json::from_str(resp.http.content.as_deref().unwrap())
                .expect("a conformant CipherResponseData");
        assert_eq!(
            body.data_availability,
            broadcast_exposure::data_availability::NOT_AVAILABLE
        );

        // The sole mandatory IE is enforced, including present-but-empty.
        for body in [r#"{}"#, r#"{"amfCallBackURI":""}"#] {
            let bad = SbiRequest::post("/nlmf-broadcast/v1/cipher-key-data")
                .with_body(body, "application/json");
            assert_eq!(
                lmf_sbi_request_handler(bad).await.status,
                400,
                "body {body}"
            );
        }

        // Wrong method on a routed path is 405, not 404 — which is what proves the
        // arm matched rather than falling through.
        let wrong = SbiRequest::get("/nlmf-broadcast/v1/cipher-key-data");
        assert_eq!(lmf_sbi_request_handler(wrong).await.status, 405);
    }

    /// #104 acceptance: `Nlmf_DataExposure` CRUD per
    /// `TS29572_Nlmf_DataExposure.yaml`.
    #[tokio::test]
    async fn test_nlmf_dataexposure_subscription_crud() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);

        let body = r#"{
            "notificationUri": "http://nwdaf/lmf-exposure",
            "notifyCorrelationId": "corr-exp-1",
            "aoi": {"praId": "pra-1"},
            "dataSources": ["NG_RAN"],
            "numOfSamples": 10
        }"#;
        let req = SbiRequest::post("/nlmf-dataexposure/v1/subscriptions")
            .with_body(body, "application/json");
        let resp = lmf_sbi_request_handler(owned_1865(req)).await;
        assert_ne!(resp.status, 404, "the service must be routed");
        assert_eq!(resp.status, 201);
        let location = resp
            .http
            .get_header("Location")
            .cloned()
            .expect("Location is required: true in the yaml");
        assert!(
            location.starts_with(EXPOSURE_SUBSCRIPTIONS_PATH),
            "got {location}"
        );
        let id = location.rsplit('/').next().unwrap().to_string();
        let echoed: broadcast_exposure::LmfDataExposureSubscription =
            serde_json::from_str(resp.http.content.as_deref().unwrap())
                .expect("the 201 echoes the resource");
        assert_eq!(echoed.notify_correlation_id, "corr-exp-1");

        // Retrievable: the 201 is not just an echo.
        assert!(lmf_self()
            .read()
            .ok()
            .and_then(|c| c.exposure_subscription_find(&id))
            .is_some());

        // PATCH a top-level member -> 204, and the change is observable.
        let patch = SbiRequest::patch(format!("{EXPOSURE_SUBSCRIPTIONS_PATH}/{id}")).with_body(
            r#"[{"op":"replace","path":"/numOfSamples","value":42}]"#,
            "application/json",
        );
        assert_eq!(lmf_sbi_request_handler(owned_1865(patch)).await.status, 204);
        assert_eq!(
            lmf_self()
                .read()
                .ok()
                .and_then(|c| c.exposure_subscription_find(&id))
                .and_then(|s| s.num_of_samples),
            Some(42),
            "the patch must be applied, not accepted and dropped"
        );

        // A patch that would remove a mandatory member, and an unsupported
        // operation, are both refused rather than silently ignored.
        for patch_body in [
            r#"[{"op":"replace","path":"/notificationUri","value":""}]"#,
            r#"[{"op":"remove","path":"/numOfSamples"}]"#,
        ] {
            let bad = SbiRequest::patch(format!("{EXPOSURE_SUBSCRIPTIONS_PATH}/{id}"))
                .with_body(patch_body, "application/json");
            assert_eq!(
                lmf_sbi_request_handler(owned_1865(bad)).await.status,
                400,
                "patch {patch_body}"
            );
        }

        // DELETE -> 204, then 404: the same honesty as up-unsubscribe.
        let del = SbiRequest::delete(format!("{EXPOSURE_SUBSCRIPTIONS_PATH}/{id}"));
        assert_eq!(lmf_sbi_request_handler(owned_1865(del)).await.status, 204);
        let del_again = SbiRequest::delete(format!("{EXPOSURE_SUBSCRIPTIONS_PATH}/{id}"));
        assert_eq!(
            lmf_sbi_request_handler(owned_1865(del_again)).await.status,
            404
        );
        // PATCH on an unknown id is 404, not a create at a consumer-chosen id.
        let patch_unknown = SbiRequest::patch(format!("{EXPOSURE_SUBSCRIPTIONS_PATH}/{id}"))
            .with_body(
                r#"[{"op":"replace","path":"/numOfSamples","value":1}]"#,
                "application/json",
            );
        assert_eq!(
            lmf_sbi_request_handler(owned_1865(patch_unknown))
                .await
                .status,
            404
        );

        // Each mandatory member is enforced on create.
        for (body, why) in [
            (
                r#"{"notifyCorrelationId":"c","aoi":{}}"#,
                "no notificationUri",
            ),
            (
                r#"{"notificationUri":"http://x","aoi":{}}"#,
                "no notifyCorrelationId",
            ),
            (
                r#"{"notificationUri":"http://x","notifyCorrelationId":"c"}"#,
                "no aoi",
            ),
        ] {
            let req = SbiRequest::post("/nlmf-dataexposure/v1/subscriptions")
                .with_body(body, "application/json");
            assert_eq!(
                lmf_sbi_request_handler(owned_1865(req)).await.status,
                400,
                "must be 400: {why}"
            );
        }
    }

    /// #104 acceptance: all three LMF services are advertised to the NRF
    /// (TS 23.501 Table 7.2.25-1). Only `nlmf-loc` used to be.
    #[test]
    fn test_nf_profile_advertises_all_three_lmf_services() {
        let profile = build_lmf_nf_profile(
            "lmf-1",
            "127.0.0.1",
            7816,
            nextgcore_sbi::types::UriScheme::Http,
        );
        let names: Vec<&str> = profile["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .filter_map(|s| s["serviceName"].as_str())
            .collect();
        for expected in ["nlmf-loc", "nlmf-broadcast", "nlmf-dataexposure"] {
            assert!(
                names.contains(&expected),
                "{expected} must be advertised, got {names:?}"
            );
        }

        // #392: each service carries its own endpoint and consumer set. Without
        // ipEndPoints a consumer that discovers the service has no port to dial,
        // only the NF-level ipv4Addresses.
        for svc in profile["nfServices"].as_array().expect("nfServices") {
            let name = svc["serviceName"].as_str().unwrap_or_default();
            let eps = svc["ipEndPoints"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} carries no ipEndPoints"));
            assert_eq!(
                eps[0]["port"].as_u64(),
                Some(7816),
                "{name} must advertise the port passed to the builder"
            );
            assert_eq!(eps[0]["ipv4Address"].as_str(), Some("127.0.0.1"));
            assert!(
                svc["allowedNfTypes"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
                "{name} must state its allowedNfTypes (TS 29.510 §6.1.6.2.3)"
            );
        }
    }

    /// #392: the typed self instance and the registered profile advertise the SAME
    /// surface, because both render `LMF_SERVICES`.
    ///
    /// #104 had already fixed the PROFILE to carry all three services TS 23.501
    /// Table 7.2.25-1 lists, but the self instance was still built with
    /// `nlmf-loc` alone — so this LMF held two different answers to "what do I
    /// serve", and which one a caller saw depended on which it read.
    #[test]
    fn the_lmf_self_instance_matches_the_registered_profile() {
        let instance = build_lmf_nf_instance("lmf-test-instance", "10.45.0.13", 7777);
        let profile = build_lmf_nf_profile(
            "lmf-test-instance",
            "10.45.0.13",
            7777,
            nextgcore_sbi::types::UriScheme::Http,
        );

        let mut from_instance: Vec<String> =
            instance.services.iter().map(|s| s.name.clone()).collect();
        let mut from_profile: Vec<String> = profile["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .map(|s| s["serviceName"].as_str().unwrap_or_default().to_string())
            .collect();
        from_instance.sort();
        from_profile.sort();

        assert_eq!(
            from_instance, from_profile,
            "the self instance carried nlmf-loc alone while the profile carried three"
        );
        assert_eq!(from_instance.len(), LMF_SERVICES.len());
    }

    /// #104 acceptance: a transferred PERIODIC deferred LDR RESUMES periodic
    /// reporting. `periodic_event_info` was hardcoded `None`, so the record was
    /// stored and its trigger never restarted: reporting stopped silently at AMF
    /// relocation, and the stored record made it look live.
    #[tokio::test]
    async fn test_context_transfer_rearms_periodic_reporting() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);

        let body = serde_json::json!({
            "amfId": "amf-1",
            "ldrType": "PERIODIC",
            "hgmlcCallBackURI": "http://gmlc/event-notify",
            "ldrReference": "ldr-transfer-1",
            "supi": "imsi-001010000000090",
            "eventReportMessage": {
                "eventClass": "SUPPLEMENTARY_SERVICES",
                "eventContent": {
                    "periodicEventInfo": {"reportingAmount": 5, "reportingInterval": 60}
                }
            }
        })
        .to_string();
        let req = from_lmf_2157(
            SbiRequest::post("/nlmf-loc/v1/location-context-transfer")
                .with_body(body, "application/json"),
        );
        assert_eq!(lmf_sbi_request_handler(req).await.status, 204);

        // The restored parameters are on the stored LDR...
        let stored = lmf_self()
            .read()
            .ok()
            .and_then(|c| c.ldr_find("ldr-transfer-1"))
            .expect("the LDR is registered");
        assert_eq!(
            stored.owner.as_deref(),
            Some(PEER_2157),
            "bound to the old LMF"
        );
        let periodic = stored
            .periodic_event_info
            .expect("the transferred periodicEventInfo must be restored, not dropped");
        assert_eq!(periodic.reporting_amount, 5);
        assert_eq!(periodic.reporting_interval_secs, 60);

        // ...and the scheduler is ARMED, which is the half that was missing. The
        // task registry is what `cancel-location` and `fini` abort, so a live entry
        // keyed on THIS ldrReference is the observable proof the trigger restarted
        // (a count could not tell it from another test's LDR still ticking).
        assert!(
            lmf_self()
                .read()
                .ok()
                .map(|c| c.ldr_task_is_running("ldr-transfer-1"))
                .unwrap_or(false),
            "a transferred PERIODIC LDR must have its trigger re-armed"
        );

        // Stop the spawned task so it does not tick through other tests.
        if let Ok(c) = lmf_self().read() {
            c.cancel_ldr("ldr-transfer-1");
        }
    }

    /// #104: a transferred PERIODIC LDR with NO periodicEventInfo is still stored
    /// (cancel-location must find it) but is not armed, and no cadence is invented.
    /// The honest half of the same change.
    #[tokio::test]
    async fn test_context_transfer_without_periodic_info_does_not_invent_a_cadence() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);

        let body = serde_json::json!({
            "amfId": "amf-1",
            "ldrType": "PERIODIC",
            "hgmlcCallBackURI": "http://gmlc/event-notify",
            "ldrReference": "ldr-transfer-2",
            "supi": "imsi-001010000000091",
            "eventReportMessage": {"eventClass": "SUPPLEMENTARY_SERVICES", "eventContent": {}}
        })
        .to_string();
        let req = from_lmf_2157(
            SbiRequest::post("/nlmf-loc/v1/location-context-transfer")
                .with_body(body, "application/json"),
        );
        assert_eq!(lmf_sbi_request_handler(req).await.status, 204);

        let stored = lmf_self()
            .read()
            .ok()
            .and_then(|c| c.ldr_find("ldr-transfer-2"))
            .expect("the LDR is still registered so cancel-location can find it");
        assert!(
            stored.periodic_event_info.is_none(),
            "no cadence may be invented when the source LMF sent none"
        );
        assert!(
            !lmf_self()
                .read()
                .ok()
                .map(|c| c.ldr_task_is_running("ldr-transfer-2"))
                .unwrap_or(false),
            "nothing to arm without parameters"
        );
    }

    /// #104, **declined criterion**: `DUMMY` is a SPEC-DEFINED `EventClass` value
    /// and is therefore still accepted.
    ///
    /// The issue asks for it to be rejected as "a placeholder value that has no
    /// spec meaning". `TS29572_Nlmf_Location.yaml`'s `EventClass` enumerates
    /// exactly `[SUPPLEMENTARY_SERVICES, DUMMY]`, so rejecting it would make this
    /// LMF refuse a conformant peer. This test pins the acceptance so a later
    /// reader of the issue does not "fix" it.
    #[tokio::test]
    async fn test_dummy_event_class_is_accepted_because_the_yaml_defines_it() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);

        let transfer = |event_class: &str, reference: &str| {
            let body = serde_json::json!({
                "amfId": "amf-1",
                "ldrType": "UE_AVAILABLE",
                "hgmlcCallBackURI": "http://gmlc/event-notify",
                "ldrReference": reference,
                "eventReportMessage": {"eventClass": event_class, "eventContent": {}}
            })
            .to_string();
            from_lmf_2157(
                SbiRequest::post("/nlmf-loc/v1/location-context-transfer")
                    .with_body(body, "application/json"),
            )
        };

        assert_eq!(
            lmf_sbi_request_handler(transfer("DUMMY", "ldr-dummy-1"))
                .await
                .status,
            204,
            "DUMMY is in the vendored EventClass enum; refusing it would reject a \
             conformant peer"
        );
        assert!(
            lmf_self().read().unwrap().ldr_find("ldr-dummy-1").is_some(),
            "the DUMMY transfer must register its LDR"
        );
        // An eventClass that is NOT in the enumeration is still refused, for THAT
        // reason (#2157: a bare 403 was also what the owner check answers).
        let refused = lmf_sbi_request_handler(transfer("NOT_A_CLASS", "ldr-dummy-2")).await;
        assert_eq!(refused.status, 403);
        assert_eq!(body_json(&refused)["cause"], "EVENT_REPORT_UNRECOGNIZED");
        assert!(lmf_self().read().unwrap().ldr_find("ldr-dummy-2").is_none());
    }

    /// #104 acceptance: `lcsQosClass` and `velocityRequested` deserialise.
    #[test]
    fn test_location_qos_parses_lcs_qos_class_and_velocity_requested() {
        let qos: nlmf::LocationQoS = serde_json::from_str(
            r#"{"hAccuracy":10.0,"lcsQosClass":"ASSURED","velocityRequested":true}"#,
        )
        .expect("parses");
        assert_eq!(qos.h_accuracy, Some(10.0));
        assert_eq!(
            qos.lcs_qos_class.as_deref(),
            Some(nlmf::lcs_qos_class::ASSURED)
        );
        assert_eq!(qos.velocity_requested, Some(true));

        // Both absent-tolerant, so a request that names neither is unchanged from
        // before #104.
        let plain: nlmf::LocationQoS = serde_json::from_str(r#"{"hAccuracy":50.0}"#).unwrap();
        assert_eq!(plain.lcs_qos_class, None);
        assert_eq!(plain.velocity_requested, None);

        // The wire spelling round-trips.
        let json = serde_json::to_string(&qos).unwrap();
        assert!(json.contains(r#""lcsQosClass":"ASSURED""#), "got {json}");
        assert!(json.contains(r#""velocityRequested":true"#), "got {json}");
    }

    /// #104 acceptance: velocity is derived from two successive fixes, and is
    /// `None` when it is not derivable — never a fabricated zero.
    #[test]
    fn test_velocity_derivation() {
        // ~111 m north in 10 s => ~11 m/s, bearing 0 (due north).
        let v = nlmf::derive_velocity(52.5000, 13.4000, 1000, 52.5010, 13.4000, 1010)
            .expect("two fixes with a positive dt are derivable");
        let speed = v["hSpeed"].as_f64().expect("hSpeed");
        assert!(
            (10.0..13.0).contains(&speed),
            "expected ~11 m/s for 111 m in 10 s, got {speed}"
        );
        assert_eq!(v["bearing"], 0, "due north");
        assert_eq!(v["velocityType"], "HORIZONTAL");

        // Eastward movement bears 090.
        assert_eq!(
            nlmf::derive_velocity(0.0, 0.0, 0, 0.0, 0.001, 10).expect("derivable")["bearing"],
            90
        );

        // Not derivable: no time passed, time going backwards, or an implausible
        // speed (a bad fix pair, not a velocity).
        assert!(nlmf::derive_velocity(52.5, 13.4, 1000, 52.6, 13.4, 1000).is_none());
        assert!(nlmf::derive_velocity(52.5, 13.4, 1000, 52.6, 13.4, 900).is_none());
        assert!(
            nlmf::derive_velocity(0.0, 0.0, 0, 10.0, 0.0, 1).is_none(),
            "1100 km in 1 s is not a UE velocity"
        );
    }

    // -- #103: config-loaded coordinates, method selection, LDR refusal --------

    /// #103 criteria 1 and 7: coordinates loaded from CONFIGURATION reach the solver,
    /// with no `#[cfg(test)]` writer involved.
    ///
    /// The registry is filled by `site_config::load_into_context` reading a real file,
    /// and the fix is then produced by `measurement_report` — the same runtime path a
    /// DetermineLocation drives. Before #103 the only writer was test code, so a
    /// deployed LMF's registry was always empty.
    #[tokio::test]
    async fn coordinates_from_a_config_file_reach_the_solver() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        lmf_self()
            .read()
            .expect("context")
            .clear_cell_registry_for_test();

        // A real file, read by the real loader. Three cells so the E-CID solver has a
        // serving cell and the registry has a usable origin.
        let path = std::env::temp_dir().join(format!(
            "nextgcore-lmf-site-{}-{}.yaml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(
            &path,
            r#"
lmf:
  positioning:
    cells:
      - id: pci-501
        lat: 37.5000
        lon: 126.9000
      - id: pci-502
        lat: 37.5050
        lon: 126.9100
    trps:
      - id: pci-503
        lat: 37.5100
        lon: 126.9200
"#,
        )
        .expect("write config");

        let cfg = site_config::load_into_context(&path.to_string_lossy());
        let _ = std::fs::remove_file(&path);
        assert!(cfg.rejected.is_empty(), "{:?}", cfg.rejected);
        assert_eq!(cfg.cells.len(), 2);
        assert_eq!(cfg.trps.len(), 1);

        let count = lmf_self().read().expect("context").reference_point_count();
        assert_eq!(
            count, 3,
            "cells AND trps both land in the registry the solvers read"
        );

        // The runtime path: a measurement report against a configured cell yields a
        // real fix. No test-only writer touched the registry.
        let request_id = {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard
                .measurement_request(
                    0,
                    PositioningMethod::Ecid,
                    None,
                    None,
                    PositioningQos::BestEffort,
                )
                .expect("measurement store has room")
                .request_id
        };
        let fix = lmf_self()
            .read()
            .expect("context")
            .measurement_report(
                request_id,
                vec![context::CellMeasurement {
                    nr_ecid: None,
                    nr_cgi: "pci-501".to_string(),
                    rsrp: Some(-80),
                    rsrq: None,
                    timing_advance: Some(4),
                    aoa: None,
                    rtt_ns: None,
                    rstd_ns: None,
                    ue_rx_tx_ns: None,
                    rstd_reference: None,
                    ecid_rtt_ns: None,
                    ecid_rtt_width_ns: None,
                    gnb_rx_tx_ns: None,
                    meas_time: None,
                    dl_prs_id: None,
                    eutra: false,
                }],
            )
            .expect(
                "a report against a CONFIGURED cell must produce a fix -- this is the whole \
                 point of #103 criterion 1",
            );
        assert!(
            (fix.latitude - 37.5).abs() < 0.5 && (fix.longitude - 126.9).abs() < 0.5,
            "the fix must be near the configured cell, got ({}, {})",
            fix.latitude,
            fix.longitude
        );
        assert_ne!(
            (fix.latitude, fix.longitude),
            (0.0, 0.0),
            "lat/lon 0,0 is the heuristic placeholder's signature and must never appear"
        );
    }

    /// The ordering interlock: a request with NO target identity is a 400 even with an
    /// empty registry.
    ///
    /// The registry check ran first in the first draft, which made this answer 500
    /// whenever no sibling test had seeded coordinates -- a real ordering bug that a
    /// single green run hid and a 20-run loop caught. Validating the REQUEST before the
    /// DEPLOYMENT is the order a consumer can reason about, and this pins it.
    #[tokio::test]
    async fn a_request_with_no_target_is_400_even_with_an_empty_registry() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        lmf_self()
            .read()
            .expect("context")
            .clear_cell_registry_for_test();

        let req = SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(
            r#"{"externalClientType":"EMERGENCY_SERVICES"}"#,
            "application/json",
        );
        let resp = handle_determine_location(&req).await;
        assert_eq!(
            resp.status, 400,
            "a malformed request is a client error whatever the deployment looks like"
        );
    }

    /// #103 criterion 2: with no coordinates configured, DetermineLocation fails
    /// LOUDLY and names the configuration, instead of returning a placeholder.
    #[tokio::test]
    async fn determine_location_with_no_reference_points_refuses_and_says_why() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        lmf_self()
            .read()
            .expect("context")
            .clear_cell_registry_for_test();

        let body = r#"{"supi":"imsi-001010000000103","locationQoS":{"hAccuracy":5.0}}"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 500);
        let detail = resp.http.content.clone().unwrap_or_default();
        assert!(
            detail.contains("POSITIONING_FAILED"),
            "TS 29.572 Table 6.1.7.3-1 cause, got {detail}"
        );
        assert!(
            detail.contains("lmf.positioning.cells"),
            "the detail must name the configuration to provision, not just say 'failed'; got \
             {detail}"
        );
    }

    /// #1884: a test's context init forgets the UEs' last fixes. A fix cached
    /// before the init (here, what the velocity test leaves for its SUPI) must not
    /// answer a DetermineLocation made after it. That is the order that turned
    /// `determine_location_with_no_reference_points_refuses_and_says_why`'s 500
    /// into a 200 under `--shuffle`.
    ///
    /// REVERT-VERIFIED: without the `ue_locations` clear in `lmf_context_init`,
    /// this fails "the fix cached before the init is gone".
    #[tokio::test]
    async fn a_test_s_context_init_forgets_the_cached_fixes_1884() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let supi = "imsi-001010000001884";
        lmf_context_init(1024);
        seed_fix_displaced(supi, 37.5000, -122.3, 1_000);
        seed_fix_displaced(supi, 37.5010, -122.3, 1_010);
        assert!(lmf_self().read().unwrap().ue_location_get(supi).is_some());

        lmf_context_init(1024);
        lmf_self()
            .read()
            .expect("context")
            .clear_cell_registry_for_test();
        assert!(
            lmf_self().read().unwrap().ue_location_get(supi).is_none(),
            "the fix cached before the init is gone"
        );
        let body = format!(r#"{{"supi":"{supi}","locationQoS":{{"hAccuracy":5.0}}}}"#);
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(&body, "application/json");
        assert_eq!(
            handle_determine_location(&req).await.status,
            500,
            "no reference points and no cache: the request is refused"
        );
    }

    /// #903 review MAJOR 2: a Multi-RTT request also asks for DL-TDOA, and a
    /// Multi-RTT session whose gNB half could not be set up asks for what was
    /// selected without it. #906: neither asks a UE for DL-TDOA it reported it
    /// does not support.
    #[test]
    fn a_multi_rtt_request_carries_its_dl_tdoa_fallback() {
        use crate::codec_glue::LppMethod;
        assert_eq!(
            method_after_gnb_leg(LppMethod::MultiRtt, false, LppMethod::DlTdoa),
            LppMethod::DlTdoa
        );
        assert_eq!(
            method_after_gnb_leg(LppMethod::MultiRtt, false, LppMethod::NrEcid),
            LppMethod::NrEcid,
            "a UE without DL-TDOA falls back to E-CID"
        );
        assert_eq!(
            method_after_gnb_leg(LppMethod::MultiRtt, true, LppMethod::DlTdoa),
            LppMethod::MultiRtt
        );
        assert_eq!(
            method_after_gnb_leg(LppMethod::NrEcid, false, LppMethod::DlTdoa),
            LppMethod::NrEcid
        );
        let bytes = lpp_request_for(LppMethod::MultiRtt, 3, true).unwrap();
        let msg = nextgcore_lpp_gen::decode(&bytes).unwrap();
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("nr_multi_rtt_request_location_information_r16: Some("));
        assert!(dbg.contains("nr_dl_tdoa_request_location_information_r16: Some("));
        assert_eq!(
            lpp_request_for(LppMethod::MultiRtt, 3, false).unwrap(),
            codec_glue::build_lpp_request(LppMethod::MultiRtt, 3).unwrap(),
            "no DL-TDOA set for a UE that reported none"
        );
        assert_eq!(
            lpp_request_for(LppMethod::DlTdoa, 3, true).unwrap(),
            codec_glue::build_lpp_request(LppMethod::DlTdoa, 3).unwrap()
        );
    }

    /// #906: a UE that reported its NR methods is asked only for one it
    /// supports. Each case differs from the `Unknown` baseline (Multi-RTT with the
    /// gNB half, DL-TDOA without) only in what the UE reported.
    #[test]
    fn the_positioning_method_follows_the_reported_nr_methods() {
        use crate::codec_glue::{
            select_lpp_method, AccessRat, EcidFlavours, LppMethod, NrMethods, UeLppCapability,
        };
        let pick = |cap, nr, ready| {
            select_lpp_method(
                PositioningQos::HighAccuracy,
                3,
                cap,
                AccessRat::Nr,
                EcidFlavours::default(),
                nr,
                ready,
            )
        };
        let adv = UeLppCapability::AdvancedMethods;
        let only_tdoa = NrMethods {
            multi_rtt: false,
            dl_tdoa: true,
        };
        let only_rtt = NrMethods {
            multi_rtt: true,
            dl_tdoa: false,
        };
        // Baseline: nothing reported.
        assert_eq!(
            pick(UeLppCapability::Unknown, NrMethods::default(), true),
            LppMethod::MultiRtt
        );
        assert_eq!(
            pick(UeLppCapability::Unknown, NrMethods::default(), false),
            LppMethod::DlTdoa
        );
        // DL-TDOA only: never Multi-RTT, even with the gNB half to hand.
        assert_eq!(pick(adv, only_tdoa, true), LppMethod::DlTdoa);
        // Multi-RTT only: Multi-RTT with the gNB half; without it, Multi-RTT
        // cannot range and DL-TDOA is unsupported, so E-CID.
        assert_eq!(pick(adv, only_rtt, true), LppMethod::MultiRtt);
        assert_eq!(pick(adv, only_rtt, false), LppMethod::NrEcid);
    }

    /// #103 criterion 4: a high-accuracy QoS selects a NON-E-CID method, and E-CID is
    /// only the fallback.
    ///
    /// Every branch of the rule is exercised as the SOLE reason for its outcome, so a
    /// branch that is written and then ignored fails this rather than passing on
    /// another branch's work.
    #[test]
    fn the_positioning_method_follows_qos_capability_and_the_registry() {
        use crate::codec_glue::{select_lpp_method, AccessRat, LppMethod, UeLppCapability};
        let nr = AccessRat::Nr;
        let none = crate::codec_glue::EcidFlavours::default();

        // High accuracy, enough reference points, capability unknown, and no gNB
        // half to be had (NRPPa downlink off or no NG-RAN node configured) -> a
        // multilateration method the UE measures alone: DL-TDOA, not Multi-RTT,
        // which cannot range without the gNB Rx-Tx half (TS 38.305 §8.10, #713).
        for access in [AccessRat::Nr, AccessRat::Eutra] {
            assert_eq!(
                select_lpp_method(
                    PositioningQos::HighAccuracy,
                    3,
                    UeLppCapability::Unknown,
                    access,
                    none,
                    crate::codec_glue::NrMethods::default(),
                    false
                ),
                LppMethod::DlTdoa,
                "answering a <=10 m request with E-CID commits to an accuracy a TA ring cannot \
                 deliver, and Multi-RTT without the gNB half cannot range at all"
            );
        }
        assert_eq!(
            select_lpp_method(
                PositioningQos::Emergency,
                5,
                UeLppCapability::Unknown,
                nr,
                none,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::DlTdoa,
            "an emergency fix is a high-accuracy fix"
        );
        assert_eq!(
            select_lpp_method(
                PositioningQos::HighAccuracy,
                3,
                UeLppCapability::AdvancedMethods,
                nr,
                none,
                crate::codec_glue::NrMethods {
                    multi_rtt: true,
                    dl_tdoa: true
                },
                false
            ),
            LppMethod::DlTdoa
        );

        // #807: with the gNB half obtainable, high accuracy and emergency select
        // Multi-RTT again. The readiness flag is the sole difference.
        const { assert!(crate::codec_glue::MULTI_RTT_GNB_HALF_AVAILABLE) };
        for qos in [PositioningQos::HighAccuracy, PositioningQos::Emergency] {
            assert_eq!(
                select_lpp_method(
                    qos,
                    3,
                    UeLppCapability::Unknown,
                    nr,
                    none,
                    crate::codec_glue::NrMethods::default(),
                    true
                ),
                LppMethod::MultiRtt,
                "its two-sided measurement cancels the UE-gNB clock offset"
            );
        }
        // ... but readiness never overrides the other branches.
        assert_eq!(
            select_lpp_method(
                PositioningQos::HighAccuracy,
                2,
                UeLppCapability::Unknown,
                nr,
                none,
                crate::codec_glue::NrMethods::default(),
                true
            ),
            LppMethod::NrEcid
        );
        assert_eq!(
            select_lpp_method(
                PositioningQos::HighAccuracy,
                3,
                UeLppCapability::EcidOnly,
                nr,
                none,
                crate::codec_glue::NrMethods::default(),
                true
            ),
            LppMethod::NrEcid
        );
        assert_eq!(
            select_lpp_method(
                PositioningQos::BestEffort,
                9,
                UeLppCapability::Unknown,
                nr,
                none,
                crate::codec_glue::NrMethods::default(),
                true
            ),
            LppMethod::NrEcid
        );
        // Readiness needs both the NRPPa downlink and an NG-RAN node to measure on.
        use crate::codec_glue::multi_rtt_gnb_half_ready as ready;
        assert!(ready(true, 1));
        assert!(!ready(false, 1), "no NRPPa downlink, no gNB half");
        assert!(
            !ready(true, 0),
            "no NG-RAN node to send the Measurement Request to"
        );

        // Same QoS, TOO FEW reference points -> E-CID fallback, of the UE's access
        // (#715): NR E-CID on NR, E-UTRA E-CID on an ng-eNB.
        assert_eq!(
            select_lpp_method(
                PositioningQos::HighAccuracy,
                2,
                UeLppCapability::Unknown,
                nr,
                none,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::NrEcid,
            "two known positions cannot be multilaterated against, whatever the QoS asks"
        );
        assert_eq!(
            select_lpp_method(
                PositioningQos::HighAccuracy,
                2,
                UeLppCapability::Unknown,
                AccessRat::Eutra,
                none,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::Ecid
        );

        // Same QoS, enough points, UE says E-CID only -> E-CID. Capability is the sole
        // difference.
        assert_eq!(
            select_lpp_method(
                PositioningQos::HighAccuracy,
                3,
                UeLppCapability::EcidOnly,
                nr,
                none,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::NrEcid,
            "asking a UE for a method it has said it cannot perform gets an empty report"
        );

        // #834 review: a UE that reported only one E-CID flavour is asked for that
        // one whatever the access; with both or neither, the access decides.
        use crate::codec_glue::EcidFlavours;
        let eutra_only = EcidFlavours {
            eutra: true,
            nr: false,
        };
        let nr_only = EcidFlavours {
            eutra: false,
            nr: true,
        };
        let both = EcidFlavours {
            eutra: true,
            nr: true,
        };
        assert_eq!(
            select_lpp_method(
                PositioningQos::BestEffort,
                9,
                UeLppCapability::EcidOnly,
                nr,
                eutra_only,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::Ecid,
            "nextgsim #330: a UE with only E-UTRA E-CID on NR access"
        );
        assert_eq!(
            select_lpp_method(
                PositioningQos::BestEffort,
                9,
                UeLppCapability::EcidOnly,
                AccessRat::Eutra,
                nr_only,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::NrEcid
        );
        assert_eq!(
            select_lpp_method(
                PositioningQos::BestEffort,
                9,
                UeLppCapability::EcidOnly,
                nr,
                both,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::NrEcid
        );

        // Low latency prefers the cheapest measurement, not the most accurate.
        assert_eq!(
            select_lpp_method(
                PositioningQos::LowLatency,
                9,
                UeLppCapability::Unknown,
                nr,
                none,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::NrEcid,
            "LOW_DELAY is a statement about time, and PRS scheduling is not fast"
        );
        assert_eq!(
            select_lpp_method(
                PositioningQos::BestEffort,
                9,
                UeLppCapability::Unknown,
                nr,
                none,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::NrEcid
        );
        assert_eq!(
            select_lpp_method(
                PositioningQos::BestEffort,
                9,
                UeLppCapability::Unknown,
                AccessRat::Eutra,
                none,
                crate::codec_glue::NrMethods::default(),
                false
            ),
            LppMethod::Ecid
        );

        // The serving cell in InputData decides the access.
        assert_eq!(AccessRat::from_serving_cell(true, false), AccessRat::Nr);
        assert_eq!(AccessRat::from_serving_cell(true, true), AccessRat::Nr);
        assert_eq!(AccessRat::from_serving_cell(false, true), AccessRat::Eutra);
        assert_eq!(AccessRat::from_serving_cell(false, false), AccessRat::Nr);

        // The selected method changes the ENCODED REQUEST, not just a log line.
        let ecid = crate::codec_glue::build_lpp_request(LppMethod::Ecid, 1).expect("encode");
        let nr_ecid = crate::codec_glue::build_lpp_request(LppMethod::NrEcid, 1).expect("encode");
        assert_ne!(ecid, nr_ecid, "NR E-CID must not encode as E-UTRA E-CID");
        let multi = crate::codec_glue::build_lpp_request(LppMethod::MultiRtt, 1).expect("encode");
        let tdoa = crate::codec_glue::build_lpp_request(LppMethod::DlTdoa, 1).expect("encode");
        assert_ne!(ecid, multi, "a Multi-RTT request must not encode as E-CID");
        assert_ne!(multi, tdoa);
        assert_ne!(ecid, tdoa);
    }

    /// #103 criterion 6: an area- or motion-event LDR is refused with a
    /// spec-compliant error, not accepted and never reported.
    #[tokio::test]
    async fn area_and_motion_ldrs_are_refused_with_unsupported_event_type() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard.clear_cell_registry_for_test();
            // Coordinates present, so a refusal cannot be mistaken for criterion 2's.
            guard.set_cell_coord(
                "ldr-cell",
                crate::positioning::TrpCoord::new(37.5, 126.9, 0.0),
            );
        }

        for ldr_type in [
            nlmf::ldr_type::ENTERING_INTO_AREA,
            nlmf::ldr_type::LEAVING_FROM_AREA,
            nlmf::ldr_type::BEING_INSIDE_AREA,
            nlmf::ldr_type::MOTION,
        ] {
            let body = format!(
                r#"{{"supi":"imsi-001010000000103","ldrType":"{ldr_type}","ldrReference":"ldr-1"}}"#
            );
            let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
                .with_body(body, "application/json");
            let resp = handle_determine_location(&req).await;
            assert_eq!(
                resp.status, 501,
                "{ldr_type} must be 501 Not Implemented (TS 29.572 UNSUPPORTED_EVENT_TYPE), not \
                 a 200 promising reports that never arrive"
            );
            let detail = resp.http.content.clone().unwrap_or_default();
            assert!(
                detail.contains("UNSUPPORTED_EVENT_TYPE"),
                "{ldr_type}: got {detail}"
            );
            // And it must NOT have been registered: a refused request that left a
            // context behind would be cancellable and reportable, which is the
            // half-accepted state this replaces.
            assert!(
                lmf_self()
                    .read()
                    .expect("context")
                    .ldr_find("ldr-1")
                    .is_none(),
                "{ldr_type} was refused, so no LDR context may remain"
            );
        }
    }

    /// The interlock: a PERIODIC LDR is still accepted. Without this, "refuse the
    /// unarmed types" could be satisfied by refusing every deferred LDR, which would
    /// break the one deferred flow that genuinely works.
    #[tokio::test]
    async fn a_periodic_ldr_is_still_accepted() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard.clear_cell_registry_for_test();
            guard.set_cell_coord(
                "periodic-cell",
                crate::positioning::TrpCoord::new(37.5, 126.9, 0.0),
            );
        }
        let body = r#"{"supi":"imsi-001010000000104","ldrType":"PERIODIC","ldrReference":"ldr-p"}"#;
        let req = from_amf_2214(
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json"),
        );
        let resp = handle_determine_location(&req).await;
        assert_ne!(
            resp.status, 501,
            "PERIODIC deferred location works and must not be swept up in the refusal"
        );
        assert!(
            lmf_self()
                .read()
                .expect("context")
                .ldr_find("ldr-p")
                .is_some(),
            "a PERIODIC LDR must still register its reporting context"
        );
        assert_eq!(
            lmf_self()
                .read()
                .expect("context")
                .ldr_find("ldr-p")
                .and_then(|l| l.owner)
                .as_deref(),
            Some(AMF_2214),
            "bound to its verified creator"
        );
    }

    // -- #103: the assistance-data branch now DELIVERS something ---------------
    //
    // This replaces `test_determine_location_assistance_data_204`, which asserted a
    // bare 204 with NO coordinates configured. That 204 was the defect #103 names:
    // "callers receive 2xx success for MO-LR assistance-data requests that silently
    // did nothing". Pinning it would have pinned the bug, so the assertion changed
    // direction rather than being deleted -- the two tests below cover both sides.

    /// With no reference points configured there is no reference location to
    /// provide, so the request is refused LOUDLY instead of answered 204.
    #[tokio::test]
    async fn assistance_data_with_no_reference_points_is_refused() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        // Neither init nor fini clears the cell registry, so a sibling's scene has to
        // be removed explicitly -- see `PROCESS_STATE_TEST_LOCK`'s correction note.
        lmf_self()
            .read()
            .expect("context")
            .clear_cell_registry_for_test();
        let body =
            r#"{"supi":"imsi-001010000000012","ueLocationServiceInd":"LOCATION_ASSISTANCE_DATA"}"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(
            resp.status, 500,
            "a 204 here would tell the AMF the UE was served assistance data that does not exist"
        );
        let detail = resp.http.content.clone().unwrap_or_default();
        assert!(
            detail.contains("reference points"),
            "the problem detail must name the configuration an operator has to fix, got {detail}"
        );
    }

    /// #103 criterion 5: with coordinates configured, the request produces a
    /// NON-EMPTY LPP `ProvideAssistanceData` rather than a bare 204.
    ///
    /// Asserted on the encoded PDU rather than through the SBI handler, because the
    /// delivery leg needs an AMF and the criterion is about the payload. The handler's
    /// refusal path is covered above, and the encode is what "non-empty
    /// assistance-data response" means.
    #[tokio::test]
    async fn assistance_data_encodes_a_reference_location_from_the_configured_cells() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard.clear_cell_registry_for_test();
            guard.set_cell_coord(
                "assist-cell-1",
                crate::positioning::TrpCoord::new(37.5000, 126.9000, 0.0),
            );
            guard.set_cell_coord(
                "assist-cell-2",
                crate::positioning::TrpCoord::new(37.5100, 126.9200, 0.0),
            );
        }
        let (lat, lon, spread) = lmf_self()
            .read()
            .expect("context")
            .reference_centroid()
            .expect("two cells are configured, so there is a centroid");
        assert!(
            (lat - 37.505).abs() < 1e-6 && (lon - 126.91).abs() < 1e-6,
            "the centroid must be the mean of the configured points, got ({lat}, {lon})"
        );
        assert!(
            spread > 0.0,
            "two separated points have a non-zero spread, which is the honest uncertainty"
        );

        let pdu = crate::codec_glue::build_lpp_provide_assistance_data(9, lat, lon, spread)
            .expect("encode");
        assert!(
            !pdu.is_empty(),
            "the criterion is a NON-EMPTY assistance-data response"
        );

        // Decoded, so the assertion is about the message rather than about some bytes.
        let decoded = nextgcore_lpp_gen::decode(&pdu).expect("the emitted PDU must decode");
        assert_eq!(
            decoded
                .transaction_id
                .as_ref()
                .map(|t| t.transaction_number.0),
            Some(9),
            "the response must answer the UE's transaction, or the UE discards it"
        );
        use nextgcore_lpp_gen::generated as lpp;
        let Some(lpp::LPP_MessageBody::C1(lpp::LPP_MessageBody_c1::ProvideAssistanceData(pad))) =
            decoded.lpp_message_body
        else {
            panic!("expected ProvideAssistanceData");
        };
        let lpp::ProvideAssistanceDataCriticalExtensions::C1(
            lpp::ProvideAssistanceDataCriticalExtensions_c1::ProvideAssistanceData_r9(ies),
        ) = pad.critical_extensions
        else {
            panic!("expected the -r9 IEs");
        };
        let a_gnss = ies
            .a_gnss_provide_assistance_data
            .expect("a-gnss assistance is present");
        let common = a_gnss
            .gnss_common_assist_data
            .expect("gnssCommonAssistData is present");
        let reference = common
            .gnss_reference_location
            .expect("the reference LOCATION is the assistance this LMF can honestly provide");
        assert_ne!(
            reference.three_dlocation.degrees_latitude.0, 0,
            "a zero latitude would mean the centroid never reached the encoder"
        );
        assert_eq!(
            reference.three_dlocation.confidence.0, 68,
            "one standard deviation, matching the northbound encoder's convention"
        );
    }

    /// A body that is present but is not a `RequestAssistanceData` is a client error.
    /// Answering it with assistance data would be answering a question nobody asked.
    #[test]
    fn a_non_assistance_lpp_body_is_not_treated_as_a_request() {
        let request_location =
            crate::codec_glue::build_lpp_request(crate::codec_glue::LppMethod::Ecid, 5)
                .expect("encode");
        let err = crate::codec_glue::decode_lpp_request_assistance_data(&request_location)
            .expect_err("a RequestLocationInformation is not a RequestAssistanceData");
        assert!(
            err.contains("RequestLocationInformation"),
            "the error must say what arrived instead, got {err}"
        );
    }

    // -- lmfd#1: deferred LDR registers context and is cancellable -----------

    #[tokio::test]
    async fn test_determine_location_deferred_ldr_registers_and_cancellable() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        seed_fix("imsi-001010000000013", 40.0);
        let body = r#"{
            "supi": "imsi-001010000000013",
            "ldrType": "PERIODIC",
            "ldrReference": "cc01",
            "hgmlcCallBackURI": "http://gmlc/cb"
        }"#;
        let req = from_amf_2214(
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json"),
        );
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
        assert_eq!(
            found.owner.as_deref(),
            Some(AMF_2214),
            "bound to its creator"
        );
    }

    /// A deferred (PERIODIC) DetermineLocation body for `supi` and `reference`.
    fn deferred_2214(supi: &str, reference: &str) -> SbiRequest {
        let body = serde_json::json!({
            "supi": supi,
            "ldrType": "PERIODIC",
            "ldrReference": reference,
            "hgmlcCallBackURI": "http://gmlc/cb",
        });
        SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(body.to_string(), "application/json")
    }

    /// **#2214**: DetermineLocation is the AMF's (TS 23.273 Table 8.3.1-1).
    /// Through `handle_determine_location_with` under **both** profiles, every
    /// other verified NF type is refused 403 and registers no LDR: a GMLC, SMF,
    /// NEF or LMF certificate, a mixed `[AMF, SMF]` certificate (#2218), and the
    /// token of an instance the NRF lists as a GMLC, directly and through an SCP.
    /// Admitted, with the LDR bound to the caller: an AMF certificate, an
    /// `[AMF, SCP]` certificate, an AMF's token alone, and an AMF's token relayed
    /// through an SCP.
    ///
    /// #2237: the GMLC token is refused by the TYPE rule. Its instance is seeded
    /// as a GMLC, so the lookup answers "listed, not as an AMF" and the refusal
    /// says so. Before, the seed was never read (a seed only answers for its own
    /// type), and the token was refused because no NRF was configured.
    ///
    /// REVERT-VERIFIED: with the `nf_type_refusal_with` gate removed, the GMLC
    /// certificate is 200 and "refused: GMLC certificate" fails. With the GMLC
    /// seed removed, "the GMLC token is refused by its type" fails: the refusal
    /// is "no NRF is configured". With a multi-type certificate admitted when
    /// one of its types is AMF (#2218's rule off), the `[AMF, SMF]` certificate
    /// is 200.
    #[tokio::test]
    async fn determine_location_admits_only_a_verified_amf_2214() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        const GMLC: &str = "bbbbbbbb-2214-4000-8000-0000000000b1";
        const CERT: &str = "cccccccc-2214-4000-8000-0000000000c1";
        const SCP: &str = "55555555-2214-4000-8000-000000000005";
        owner_binding::seed_nf_type_for_test(AMF_2214, nextgcore_sbi::types::NfType::Amf);
        owner_binding::seed_nf_type_for_test(GMLC, nextgcore_sbi::types::NfType::Gmlc);
        let supi = "imsi-001010000022140";
        seed_fix(supi, 40.0);
        let with = |reference: &str, cert: Option<(&str, &[&str])>, token: Option<&str>| {
            let mut r = deferred_2214(supi, reference);
            if let Some((id, types)) = cert {
                r.peer_cert_nf_instance_id = Some(id.to_string());
                r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            }
            r.oauth2_subject = token.map(str::to_string);
            r
        };
        let registered = |reference: &str| lmf_self().read().unwrap().ldr_find(reference);
        for production in [true, false] {
            let p = u8::from(production);
            for (what, cert, token) in [
                ("GMLC certificate", Some((CERT, &["GMLC"][..])), None),
                ("SMF certificate", Some((CERT, &["SMF"][..])), None),
                ("NEF certificate", Some((CERT, &["NEF"][..])), None),
                ("LMF certificate", Some((CERT, &["LMF"][..])), None),
                (
                    "[AMF, SMF] certificate",
                    Some((CERT, &["AMF", "SMF"][..])),
                    None,
                ),
                ("GMLC token", None, Some(GMLC)),
                (
                    "GMLC token through an SCP",
                    Some((SCP, &["SCP"][..])),
                    Some(GMLC),
                ),
            ] {
                let reference = format!("x2214-{p}-{}", what.replace([' ', ',', '[', ']'], ""));
                let resp =
                    handle_determine_location_with(&with(&reference, cert, token), production)
                        .await;
                assert_eq!(
                    resp.status, 403,
                    "refused: {what} (production {production}): {:?}",
                    resp.http.content
                );
                assert!(
                    resp.http
                        .content
                        .as_deref()
                        .unwrap_or("")
                        .contains("DetermineLocation"),
                    "{what}: the refusal names the operation"
                );
                if token == Some(GMLC) {
                    let body = resp.http.content.as_deref().unwrap_or("");
                    assert!(
                        body.contains(&format!("the NRF does not list {GMLC} as an AMF"))
                            && !body.contains("no NRF is configured"),
                        "{what}: the GMLC token is refused by its type: {body}"
                    );
                }
                assert!(registered(&reference).is_none(), "{what}: no LDR");
            }
            for (what, cert, token, owner) in [
                ("AMF certificate", Some((CERT, &["AMF"][..])), None, CERT),
                (
                    "[AMF, SCP] certificate",
                    Some((CERT, &["AMF", "SCP"][..])),
                    None,
                    CERT,
                ),
                ("AMF token", None, Some(AMF_2214), AMF_2214),
                (
                    "AMF token through an SCP",
                    Some((SCP, &["SCP"][..])),
                    Some(AMF_2214),
                    AMF_2214,
                ),
            ] {
                let reference = format!("ok2214-{p}-{}", what.replace([' ', ',', '[', ']'], ""));
                let resp =
                    handle_determine_location_with(&with(&reference, cert, token), production)
                        .await;
                assert_eq!(
                    resp.status, 200,
                    "admitted: {what} (production {production}): {:?}",
                    resp.http.content
                );
                let ldr = registered(&reference).expect("registered");
                assert_eq!(
                    ldr.owner.as_deref(),
                    Some(owner),
                    "{what}: bound to the caller"
                );
                if let Ok(c) = lmf_self().read() {
                    c.cancel_ldr(&reference);
                }
            }
        }
    }

    /// **#2237** (R45 on #2233): the DetermineLocation amfd actually sends gets
    /// through lmfd's gate and is served. The body is amfd's own
    /// (`nextgcore_amfd::sbi_path::determine_location_input`, which
    /// `call_lmf_determine_location` posts as JSON), and the caller is proven an
    /// AMF the two ways amfd's client can prove it: its certificate (`[AMF]`)
    /// and its token. Both profiles. Seeded fixes stand in for the positioning.
    ///
    /// REVERT-VERIFIED: with amfd's body naming the SUPI under another member,
    /// lmfd answers 400 and "amfd's request with its certificate" fails, so the
    /// test reads amfd's body, not a copy.
    #[tokio::test]
    async fn amfds_own_determine_location_passes_the_gate_2237() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        const CERT: &str = "cccccccc-2237-4000-8000-0000000000c1";
        owner_binding::seed_nf_type_for_test(AMF_2214, nextgcore_sbi::types::NfType::Amf);
        let supi = "imsi-001010000022370";
        seed_fix(supi, 40.0);
        let mut ue = nextgcore_amfd::context::AmfUe::new(2237, 2237);
        ue.supi = Some(supi.to_string());
        ue.nr_cgi.plmn_id = nextgcore_amfd::context::PlmnId::new("001", "01");
        ue.nr_cgi.cell_id = 0x0_0223_7001;
        // A GMLC RequestPosInfo, as amfd's ProvidePositioningInfo receives it.
        let request_pos_info = serde_json::json!({
            "lcsClientType": "EMERGENCY_SERVICES",
            "locationQoS": { "hAccuracy": 50.0 },
            "supportedGADShapes": ["POINT", "POINT_UNCERTAINTY_CIRCLE"],
        });
        let input =
            nextgcore_amfd::sbi_path::determine_location_input(&ue, supi, &request_pos_info);
        assert_eq!(input["supi"], supi, "the fixture is amfd's body");
        assert!(input["ncgi"]["nrCellId"].is_string());
        let amfds = |cert: bool| {
            let mut r = SbiRequest::post("/nlmf-loc/v1/determine-location")
                .with_json_body(&input)
                .expect("json");
            if cert {
                r.peer_cert_nf_instance_id = Some(CERT.to_string());
                r.peer_cert_nf_types = vec!["AMF".to_string()];
            } else {
                r.oauth2_subject = Some(AMF_2214.to_string());
            }
            r
        };
        for production in [true, false] {
            for (what, cert) in [
                ("amfd's request with its certificate", true),
                ("amfd's request with its token", false),
            ] {
                let resp = handle_determine_location_with(&amfds(cert), production).await;
                assert_eq!(
                    resp.status, 200,
                    "{what} (production {production}): {:?}",
                    resp.http.content
                );
                let body: serde_json::Value =
                    serde_json::from_str(resp.http.content.as_deref().unwrap_or("")).expect("json");
                assert!(
                    body["locationEstimate"].is_object(),
                    "{what}: a LocationData: {body}"
                );
            }
        }
    }

    /// **#2214** (R44 on #2190): anonymous callers at the handler, until now
    /// covered only by `owner_binding`'s own tests. Under production:
    /// - an anonymous immediate DetermineLocation (no LDR) is refused 403 by
    ///   the NF-type gate before anything is read;
    /// - an anonymous deferred one, which would create an LDR, is refused 403
    ///   and no LDR exists. Both the gate and `owner_for_new_resource` refuse
    ///   it, so no single revert reaches this case.
    ///
    /// Under dev the deferred request is served and its LDR is ownerless, as
    /// every unbound dev resource is.
    ///
    /// REVERT-VERIFIED: with the `nf_type_refusal_with` gate removed, the
    /// immediate request is 200 and "production: anonymous immediate" fails.
    #[tokio::test]
    async fn an_anonymous_determine_location_is_refused_under_production_2214() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let supi = "imsi-001010000022141";
        seed_fix(supi, 40.0);
        let immediate = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(format!(r#"{{"supi":"{supi}"}}"#), "application/json");
        let resp = handle_determine_location_with(&immediate, true).await;
        assert_eq!(
            resp.status, 403,
            "production: anonymous immediate: {:?}",
            resp.http.content
        );
        let resp = handle_determine_location_with(&deferred_2214(supi, "anon2214-p"), true).await;
        assert_eq!(
            resp.status, 403,
            "production: anonymous: {:?}",
            resp.http.content
        );
        assert!(lmf_self().read().unwrap().ldr_find("anon2214-p").is_none());
        let resp = handle_determine_location_with(&deferred_2214(supi, "anon2214-d"), false).await;
        assert_eq!(resp.status, 200, "dev: anonymous: {:?}", resp.http.content);
        let ldr = lmf_self()
            .read()
            .unwrap()
            .ldr_find("anon2214-d")
            .expect("dev: registered");
        assert_eq!(ldr.owner, None, "dev: ownerless");
        if let Ok(c) = lmf_self().read() {
            c.cancel_ldr("anon2214-d");
        }
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
        crate::lpp_fixtures::multi_rtt_lpp(cells, txn)
    }

    /// Seed the global TRP registry with a solvable 4-TRP NR DL-TDOA scene and build
    /// the matching UE LPP ProvideLocationInformation: DL-PRS ID 1 is the
    /// reference, and three neighbours report their PCI. The registry is keyed by
    /// PCI throughout, so the reference is not found by its key (#714). Each RSTD is the true
    /// range difference over c, as a k0 code `(RSTD/T_c) + 985024`
    /// (TS 38.133 §10.1.23.3).
    ///
    /// DL-TDOA rather than Multi-RTT: a UE's report alone can be solved only for
    /// DL-TDOA. A Multi-RTT range also needs the gNB Rx-Tx half (#713).
    fn seed_scene_and_build_dl_tdoa_lpp(txn: u8) -> Vec<u8> {
        use crate::positioning::{enu_to_geodetic, EnuPoint, TrpCoord, SPEED_OF_LIGHT_M_S};
        // T_c ns, matching codec_glue::TC_NS (TS 38.211 §4.1).
        const TC_NS: f64 = 1_000_000_000.0 / (480_000.0 * 4_096.0);
        let origin = TrpCoord::new(37.7749, -122.4194, 0.0);
        // (registry key, DL-PRS ID, PCI, east, north)
        let trps = [
            // The registry keys every TRP by PCI, the reference included, as
            // operators do. The UE can only name the reference by its DL-PRS ID
            // (`DL-PRS-ID-Info-r16` has no PCI), so it is found only through the
            // #714 rebase on a neighbour: this pins #713's DL-TDOA selection
            // together with #714 (#812 review).
            ("pci-201", 1u8, None, 0.0f64, 0.0f64),
            ("pci-202", 2, Some(202u16), 1000.0, 0.0),
            ("pci-203", 3, Some(203), 0.0, 1000.0),
            ("pci-204", 4, Some(204), 1000.0, 1000.0),
        ];
        let (ue_e, ue_n) = (350.0f64, 600.0f64);
        let range = |e: f64, n: f64| (ue_e - e).hypot(ue_n - n);
        let reference_range = range(trps[0].3, trps[0].4);

        let ctx = lmf_self();
        let guard = ctx.read().unwrap();
        for (key, _, _, e, n) in trps.iter() {
            guard.set_cell_coord(
                *key,
                enu_to_geodetic(
                    EnuPoint {
                        e: *e,
                        n: *n,
                        u: 0.0,
                    },
                    origin,
                ),
            );
        }
        let neighbours: Vec<(u8, Option<u16>, u32)> = trps[1..]
            .iter()
            .map(|(_, prs, pci, e, n)| {
                let rstd_ns = (range(*e, *n) - reference_range) / SPEED_OF_LIGHT_M_S * 1e9;
                (*prs, *pci, ((rstd_ns / TC_NS).floor() + 985_025.0) as u32)
            })
            .collect();
        crate::lpp_fixtures::dl_tdoa_lpp(trps[0].1, &neighbours, txn)
    }

    /// Seed the same four positions as PCI-keyed cells and build a UE-only
    /// nr-Multi-RTT report for them (UE Rx-Tx k0 codes around the midpoint).
    fn seed_scene_and_build_multi_rtt_lpp(txn: u8) -> Vec<u8> {
        use crate::positioning::{enu_to_geodetic, EnuPoint, TrpCoord};
        let origin = TrpCoord::new(37.7749, -122.4194, 0.0);
        let trps = [
            (201u16, 0.0f64, 0.0f64),
            (202, 1000.0, 0.0),
            (203, 0.0, 1000.0),
            (204, 1000.0, 1000.0),
        ];
        let ctx = lmf_self();
        let guard = ctx.read().unwrap();
        for (pci, e, n) in trps.iter() {
            guard.set_cell_coord(
                format!("pci-{pci}"),
                enu_to_geodetic(
                    EnuPoint {
                        e: *e,
                        n: *n,
                        u: 0.0,
                    },
                    origin,
                ),
            );
        }
        let cells: Vec<(u16, u32)> = trps
            .iter()
            .map(|(pci, _, _)| (*pci, 985_024 + 3_000))
            .collect();
        build_multi_rtt_lpp(&cells, txn)
    }

    // -- A5 acceptance: LPP bytes reach the decode adapter -> a real fix ------
    #[tokio::test]
    async fn test_determine_location_multipart_lpp_produces_fix_200() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let lpp = seed_scene_and_build_dl_tdoa_lpp(55);
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
        // And at the UE, (350, 600) m from the scene origin, to within a metre:
        // a wrong reference would still land in the box above.
        let p = crate::positioning::geodetic_to_enu(
            crate::positioning::TrpCoord::new(lat, lon, 0.0),
            crate::positioning::TrpCoord::new(37.7749, -122.4194, 0.0),
        );
        let err = (p.e - 350.0).hypot(p.n - 600.0);
        assert!(err < 1.0, "DL-TDOA fix is {err:.2} m from the UE");
        // #714: a DL-TDOA fix says so (TS 29.572 PositioningMethod), not UL_TDOA.
        assert_eq!(v["positioningDataList"][0]["method"], "DL_TDOA");
    }

    /// #713: a UE's Multi-RTT report on its own carries UE Rx-Tx halves only. With
    /// no gNB Rx-Tx to pair them with there is no range, so no fix: 500
    /// POSITIONING_FAILED, where the old code ranged the UE half alone.
    #[tokio::test]
    async fn test_determine_location_ue_only_multi_rtt_is_not_ranged_500() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let lpp = seed_scene_and_build_multi_rtt_lpp(56);
        let input = r#"{"supi":"imsi-001010000000507","lppMessage":{"contentId":"lpp-1"}}"#;
        let req = multipart_lpp_request(input, &[("lpp-1", lpp)]);
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 500);
        assert_eq!(body_json(&resp)["cause"], "POSITIONING_FAILED");
    }

    // -- A5: decode happens but no solvable fix -> 500 (not the network 504) --
    // A single Multi-RTT cell for a UN-seeded PCI: the bytes ARE decoded (a
    // non-empty measurement set), fed to the solver, which fails -> 500
    // POSITIONING_FAILED. If the parts had been ignored, the handler would have
    // fallen through to the network path (504). 500-vs-504 is the discriminator.
    #[tokio::test]
    async fn test_determine_location_multipart_lpp_no_fix_500() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        use bytes::Bytes;
        use nextgcore_sbi::message::SbiPart;
        use nextgcore_sbi::multipart;
        lmf_context_init(1024);
        let lpp = seed_scene_and_build_dl_tdoa_lpp(57);
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
        crate::lpp_fixtures::ecid_lpp(pci, rsrp_result, ue_rx_tx, txn)
    }

    /// Encode an NRPPa E-CID Measurement Report (serving cell + TA + RSRP), on the
    /// generated codec.
    fn build_nrppa_ecid_report() -> Vec<u8> {
        use crate::nrppa_uplink::test_support::{ecid_report, nr_cgi, rsrp, ta1};
        ecid_report(
            1,
            42,
            7,
            nr_cgi([0x02, 0xF8, 0x39], 0x000000001),
            [0x00, 0x12, 0x34],
            Some(vec![ta1(500), rsrp(&[60])]),
        )
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let resp = notify_n1(&req).await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let resp = notify_n1(&req).await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let json = "{\"n1MessageContainer\":{\"n1MessageClass\":\"LPP\",\
             \"n1MessageContent\":{\"contentId\":\"n1-lpp\"}},\
             \"lcsCorrelationId\":\"corr-whatever\"}";
        // No binary part attached at all.
        let mut req = SbiRequest::post("/nlmf-loc/v1/notify/n1");
        req.http.set_content(json.to_string());
        let resp = notify_n1(&req).await;
        assert_eq!(resp.status, 400);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_MISSING");
    }

    // -- A4: N2InfoNotify (NRPPa) correlates on lcsCorrelationId and feeds the
    // session's NRPPa leg; with the LPP leg in, the session completes and the
    // report is attached to the session's request_id.
    #[tokio::test]
    async fn test_n2_info_notify_completes_session() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let resp = notify_n2(&req).await;
        assert_eq!(resp.status, 204, "successful N2InfoNotify callback → 204");
        // #715 review: the NRPPa leg alone does not end a session that also waits
        // for the UE's LPP report; that report completes it.
        let mut rx = rx;
        assert!(
            rx.try_recv().is_err(),
            "the NRPPa leg alone must not end the session"
        );
        lmf_self().read().unwrap().measurement_leg_report(
            request_id,
            crate::context::MeasurementLeg::Lpp,
            Vec::new(),
        );

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

    // -- #859: a real NR gNB's E-CID answer (NR-TADV, SS-RSRP) arrives over
    // N2InfoNotify, and with the UE's LPP leg in, the session ends in an NR_ECID
    // fix ranged from the NR-TADV (TS 38.133 §13.5.1). Before #859 it ended in
    // SolverFailed (500 POSITIONING_FAILED).
    #[tokio::test]
    async fn test_n2_info_notify_nr_tadv_gives_an_nr_ecid_fix() {
        use crate::nrppa_uplink::test_support::{ecid_report, nr_cgi, nr_tadv, ss_rsrp};
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let supi = "imsi-001010000000859";
        let ctx = lmf_self();
        let (corr, rx, request_id) = {
            let guard = ctx.read().unwrap();
            guard.set_cell_coord(
                "02f839-000000859",
                crate::positioning::TrpCoord::new(40.0, -74.0, 0.0),
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
            let (corr, rx) =
                guard.positioning_session_register(Some(supi.to_string()), 189, req.request_id);
            guard.positioning_session_expect_leg(&corr, crate::context::MeasurementLeg::NrppaEcid);
            (corr, rx, req.request_id)
        };
        let nrppa = ecid_report(
            1,
            42,
            7,
            nr_cgi([0x02, 0xF8, 0x39], 0x859),
            [0x00, 0x12, 0x34],
            Some(vec![nr_tadv(1000), ss_rsrp(&[(7, 620_000, Some(80))])]),
        );
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
        assert_eq!(notify_n2(&req).await.status, 204);
        lmf_self().read().unwrap().measurement_leg_report(
            request_id,
            crate::context::MeasurementLeg::Lpp,
            Vec::new(),
        );
        let outcome = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("session completed within budget")
            .expect("completion sender was not dropped");
        let crate::context::PositioningOutcome::Fix(fix) = outcome else {
            panic!("an NR-TADV must give a fix, got {outcome:?}");
        };
        assert_eq!(fix.method_used.as_deref(), Some("NR_ECID"));
        assert_eq!((fix.latitude, fix.longitude), (40.0, -74.0));
        // 1000 -> a 128064 T_c round trip: about 9.8 km, plus a quarter bin.
        let tc = 1.0 / (480_000.0 * 4_096.0);
        let c = crate::positioning::SPEED_OF_LIGHT_M_S;
        let want = c * 128_064.0 * tc / 2.0 + c * 128.0 * tc / 4.0;
        assert!((fix.horizontal_accuracy - want).abs() < 0.01, "{fix:?}");
    }

    // -- A4: N2InfoNotify with an unknown lcsCorrelationId → 404.
    #[tokio::test]
    async fn test_n2_info_notify_unknown_correlation_404() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let resp = notify_n2(&req).await;
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
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Lmf);
        let server = SbiServer::on_listener(cfg, port_listener);
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
        // `start_server` re-initialises the process-global LMF context, which
        // empties the cell registry: without the lock that raced every test
        // that seeds coordinates (the a_capability_report_is_recorded_and_is_not_
        // the_lpp_leg CI flake).
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
    async fn test_oauth2_wrong_audience_rejected_403() {
        // `start_server` re-initialises the process-global LMF context, which
        // empties the cell registry: without the lock that raced every test
        // that seeds coordinates (the a_capability_report_is_recorded_and_is_not_
        // the_lpp_leg CI flake).
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        assert_eq!(resp.status, 403, "wrong-audience token must be 403 (#1766)");
        // #1779 review m2: the gate's claim mismatch, not a handler's own 403.
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
        assert_eq!(problem["cause"], "ACCESS_TOKEN_CLAIM_MISMATCH", "{problem}");
        assert_eq!(problem["invalidParams"][0]["param"], "aud", "{problem}");
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_valid_token_reaches_handler() {
        // `start_server` re-initialises the process-global LMF context, which
        // empties the cell registry: without the lock that raced every test
        // that seeds coordinates (the a_capability_report_is_recorded_and_is_not_
        // the_lpp_leg CI flake).
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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

    /// The H-GMLC sink is a loopback plaintext peer, and the notification client
    /// follows the SBI profile (#1666), so every test that POSTs to it runs as a
    /// dev deployment. Before #1884 only `test_post_event_notify_strict_peer_204`
    /// set the override itself. The three periodic-LDR tests passed only when a
    /// sibling had already set it, and alone each got no callback at all.
    async fn start_sink() -> (SbiServer, u16) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        let server = SbiServer::on_listener(cfg, port_listener);
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
        // #1666: the notification client follows the SBI profile, and this
        // drives it at a loopback plaintext peer, i.e. a dev deployment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
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

    /// #2214: as in `tests`, DetermineLocation is called as the test AMF.
    async fn handle_determine_location(request: &SbiRequest) -> SbiResponse {
        super::handle_determine_location(&as_test_amf(request.clone())).await
    }
    use nextgcore_amfd::context::{amf_self, PositioningDlKind, NEXTGCORE_INVALID_POOL_ID};
    use nextgcore_sbi::multipart;
    use nextgcore_sbi::server::SbiServerConfig;

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
        let mut ue = g.amf_ue_add(ran_ue.id).expect("amf_ue_add");
        // #341: published into amfd's LIVE UE store, which is what its Namf
        // handlers now resolve against. `amf_ue_set_supi` wrote a SUPI index that
        // only tests ever wrote, which is the defect #341 removed.
        ue.supi = Some(supi.to_string());
        g.amf_ue_publish(&ue, ngap_id as u32, 900_100);
        g.amf_ue_update(&ue);
        g.amf_ue_associate_ran_ue(ue.id, ran_ue.id);
    }

    /// Record that `supi` has reported its LPP capabilities, with nothing this LMF
    /// can request in them (class `Unknown`), so `initiate_positioning` does not
    /// open a Capability Transfer (#906) and selects as it did before #906.
    fn seed_capabilities_reported(supi: &str) {
        let caps = codec_glue::decode_lpp_provide_capabilities(
            &crate::lpp_equivalence_tests::unhex("92030840"),
        )
        .expect("a ProvideCapabilities");
        lmf_self().read().unwrap().note_ue_capabilities(supi, &caps);
    }

    /// The scripted UE's side of the LPP Capability Transfer (#906, TS 37.355
    /// §5.1.1): the first downlink is lmfd's RequestCapabilities, relayed by amfd
    /// byte-exact; the UE answers on its transaction with an E-CID-only
    /// ProvideCapabilities through amfd's real notify producer.
    async fn answer_capability_request(
        tap_rx: &mut tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
        supi: &str,
        eutra: bool,
        nr: bool,
    ) {
        let (corr, dl) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("lmfd asked for capabilities within budget")
            .expect("harness captured the RequestCapabilities");
        let txn = nextgcore_lpp_gen::decode(&dl)
            .expect("DL LPP decodes")
            .transaction_id
            .expect("a transactionID")
            .transaction_number
            .0;
        assert_eq!(
            dl,
            codec_glue::build_lpp_request_capabilities(txn).unwrap(),
            "the first downlink is lmfd's RequestCapabilities, relayed byte-exact"
        );
        let caps = crate::lpp_fixtures::ecid_capabilities(txn, eutra, nr);
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, supi, &caps))
                .await
                .status,
            204
        );
    }

    /// Seed a CM-IDLE UE (SUPI known, no RAN association) so the relay
    /// fail-closes with 504 UE_NOT_REACHABLE.
    fn seed_amf_idle_ue(supi: &str) -> u64 {
        nextgcore_amfd::test_support::init_context();
        let ctx = amf_self();
        let g = ctx.read().expect("amf ctx");
        let _ = g.positioning_dl_drain();
        let mut ue = g.amf_ue_add(NEXTGCORE_INVALID_POOL_ID).expect("amf_ue_add");
        // #341: see `seed_amf_connected_ue`. `ran_ue_id` stays invalid, which is
        // what makes this UE CM-IDLE. Published on the association its last NG
        // connection was on, as a released UE's record is: that is what makes it
        // pageable (#1087; a record with no association is not).
        ue.supi = Some(supi.to_string());
        ue.ran_ue_id = NEXTGCORE_INVALID_POOL_ID;
        g.amf_ue_publish(&ue, 0, 1);
        g.amf_ue_update(&ue);
        ue.id
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
        crate::lpp_fixtures::ecid_lpp(pci, rsrp_result, ue_rx_tx, txn)
    }

    /// Build the scripted UE's N1MessageNotify request the way amfd's REAL
    /// producer builds it (H1 import), routed through the SAME nextgcore-sbi
    /// multipart codec the wire uses, and re-materialised as the inbound
    /// `SbiRequest` lmfd's server hands its callback handler. Asserts the LPP
    /// PDU survives the amfd→lmfd relay byte-exact (transparent relay).
    fn amfd_notify_request(corr: &str, supi: &str, lpp: &[u8]) -> SbiRequest {
        let amf_req = nextgcore_amfd::namf_server::build_n1_message_notify_request(
            "/nlmf-loc/v1/notify/n1-message-notify/test",
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
        let mut req = SbiRequest::post("/nlmf-loc/v1/notify/n1-message-notify/test");
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
        let (amf, nrf, _udr, rx) = start_positioning_harness_with_udr(supi, None).await;
        (amf, nrf, rx)
    }

    /// #2260: [`start_positioning_harness`], plus, when `ueid_mappings` is given,
    /// a UDR the NRF also returns, whose `nudr-dr` answers
    /// `GET /application-data/ueid-mappings?gpsis=..` (TS 29.519 §6.2.26) with the
    /// `UeIdMappingInfo` entries of `ueid_mappings` for those GPSIs.
    async fn start_positioning_harness_with_udr(
        supi: String,
        ueid_mappings: Option<serde_json::Value>,
    ) -> (
        SbiServer,
        SbiServer,
        Option<SbiServer>,
        tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    ) {
        let mut udr_instance = None;
        let mut udr_server = None;
        if let Some(table) = ueid_mappings {
            let (udr_listener, udr_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let server = SbiServer::on_listener(SbiServerConfig::new(udr_addr), udr_listener);
            server
                .start(move |req: SbiRequest| {
                    let table = table.clone();
                    async move {
                        let path = req.header.uri.split('?').next().unwrap_or("");
                        if req.header.method != "GET"
                            || path != "/nudr-dr/v2/application-data/ueid-mappings"
                        {
                            return SbiResponse::with_status(404);
                        }
                        // By `gpsis` or by `app-layer-ids` (TS 29.519 Table 6.2.26.3.1-1).
                        let (member, query) = match req.http.params.get("gpsis") {
                            Some(q) => ("gpsi", q.clone()),
                            None => (
                                "appLayerId",
                                req.http
                                    .params
                                    .get("app-layer-ids")
                                    .cloned()
                                    .unwrap_or_default(),
                            ),
                        };
                        let wanted: Vec<&str> = query.split(',').collect();
                        let hits: Vec<serde_json::Value> = table
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter(|m| {
                                m["rsUeIdMappingInfo"][member]
                                    .as_str()
                                    .is_some_and(|g| wanted.contains(&g))
                            })
                            .cloned()
                            .collect();
                        SbiResponse::ok().with_body(
                            serde_json::Value::Array(hits).to_string(),
                            "application/json",
                        )
                    }
                })
                .await
                .expect("udr stub start");
            udr_instance = Some(serde_json::json!({
                "nfInstanceId": "udr-2260",
                "nfServices": [{
                    "serviceName": "nudr-dr",
                    "scheme": "http",
                    "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": udr_addr.port() }]
                }]
            }));
            udr_server = Some(server);
        }
        let (tap_tx, tap_rx) = tokio::sync::mpsc::channel::<(String, Vec<u8>)>(4);

        let (amf_listener, amf_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let amf_port = amf_addr.port();
        let amf_server = SbiServer::on_listener(SbiServerConfig::new(amf_addr), amf_listener);
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
                                    // #557: an SLPP downlink is captured the same way;
                                    // its first octets tell the two apart.
                                    let lpp =
                                        g.positioning_dl_drain().into_iter().find_map(|d| match d
                                            .kind
                                        {
                                            PositioningDlKind::LppToUe { lpp_pdu, .. } => {
                                                Some(lpp_pdu)
                                            }
                                            PositioningDlKind::SlppToUe { slpp_pdu, .. } => {
                                                Some(slpp_pdu)
                                            }
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

        let (nrf_listener, nrf_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let nrf_port = nrf_addr.port();
        let nrf_server = SbiServer::on_listener(SbiServerConfig::new(nrf_addr), nrf_listener);
        let mut instances = vec![serde_json::json!({
            "nfInstanceId": "amf-strict-peer",
            "nfServices": [{
                "serviceName": "namf-comm",
                "scheme": "http",
                "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": amf_port }]
            }]
        })];
        instances.extend(udr_instance);
        let search = serde_json::json!({ "nfInstances": instances }).to_string();
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

        (amf_server, nrf_server, udr_server, tap_rx)
    }

    // =======================================================================
    // #515 — an erroneous NRPPa E-CID report is answered with an NRPPa ERROR
    // INDICATION that reaches amfd's REAL Namf consumer and is queued for the gNB.
    // =======================================================================

    /// TS 38.455 §10 / TS 38.413 §10.3.4.2: the gNB's E-CID Measurement Report
    /// carries an unknown IE marked reject. lmfd's real N2 notify handler must
    /// not use the report, and must send an ERROR INDICATION back through the
    /// AMF and UE context its NRPPa leg went through -- here amfd's real
    /// handler, which queues it toward the serving gNB.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_an_erroneous_nrppa_report_is_answered_with_an_error_indication_via_real_amfd() {
        use crate::nrppa_uplink::test_support::{ecid_report, nr_cgi, rsrp, splice_ie};
        use nextgcore_nrppa_gen::generated as gen;

        // #1884: amfd's Namf consumer is a loopback plaintext peer, i.e. a dev
        // deployment. Without the override it relied on a sibling having set it.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _serial = chain_lock().lock().await;
        lmf_context_init(1024);
        prime_lmf_self();
        let supi = "imsi-001010000000751";
        seed_amf_connected_ue(supi);

        // amfd's real Namf consumer behind a loopback server.
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(|req: SbiRequest| async move { nextgcore_amfd::namf_request_handler(req).await })
            .await
            .expect("amf server start");

        let lmf = lmf_self();
        let (corr, request_id) = {
            let guard = lmf.read().unwrap();
            let req = guard
                .measurement_request(
                    0,
                    PositioningMethod::Ecid,
                    None,
                    None,
                    PositioningQos::BestEffort,
                )
                .expect("measurement request");
            let (corr, _rx) =
                guard.positioning_session_register(Some(supi.to_string()), 199, req.request_id);
            guard.positioning_session_set_nrppa_peer(
                &corr,
                crate::context::NrppaPeer {
                    amf: namf_client::DiscoveredAmf {
                        host: "127.0.0.1".to_string(),
                        port: addr.port(),
                        scheme: "http".to_string(),
                        nf_instance_id: Some("amf-strict-peer".to_string()),
                    },
                    ue_context_id: supi.to_string(),
                },
            );
            (corr, req.request_id)
        };

        // A valid report plus one unknown IE marked reject (criticality 0).
        let nrppa = splice_ie(
            &ecid_report(
                77,
                1,
                5,
                nr_cgi([0x02, 0xf8, 0x39], 1),
                [0x00, 0x00, 0x01],
                Some(vec![rsrp(&[60])]),
            ),
            9999,
            0,
        );

        let json = format!(
            "{{\"n2NotifySubscriptionId\":\"sub-515\",\
             \"n2InfoContainer\":{{\"n2InformationClass\":\"NRPPa\",\
             \"nrppaInfo\":{{\"nrppaPdu\":{{\"ngapIeType\":\"NRPPA_PDU\",\
             \"ngapData\":{{\"contentId\":\"nrppa\"}}}}}}}},\
             \"lcsCorrelationId\":\"{corr}\"}}"
        );
        let mut req = SbiRequest::post("/nlmf-loc/v1/notify/n2");
        req.http.set_content(json);
        req.http
            .add_part(nextgcore_sbi::message::SbiPart::with_content(
                "nrppa",
                "application/vnd.3gpp.ngap",
                bytes::Bytes::from(nrppa),
            ));
        let resp = notify_n2(&req).await;
        assert_eq!(resp.status, 204);
        assert!(
            lmf_self()
                .read()
                .unwrap()
                .report_find(request_id)
                .is_none_or(|r| r.cell_measurements.is_empty()),
            "a report TS 38.413 §10.3.4.2 says to reject must contribute no measurement"
        );

        // amfd queued exactly one NRPPa PDU toward the gNB: our ERROR INDICATION.
        let queued: Vec<Vec<u8>> = amf_self()
            .read()
            .unwrap()
            .positioning_dl_drain()
            .into_iter()
            .filter_map(|d| match d.kind {
                PositioningDlKind::NrppaToGnb { nrppa_pdu, .. } => Some(nrppa_pdu),
                _ => None,
            })
            .collect();
        assert_eq!(queued.len(), 1, "one ERROR INDICATION, relayed by amfd");
        let gen::NRPPA_PDU::InitiatingMessage(m) =
            nextgcore_nrppa_gen::decode(&queued[0]).expect("a valid NRPPa PDU")
        else {
            panic!("not an initiating message");
        };
        assert_eq!(m.procedure_code.0, gen::ID_ERROR_INDICATION);
        assert_eq!(
            m.nrppatransaction_id.0, 77,
            "it answers the report's transaction"
        );
        let gen::InitiatingMessageValue::Id_errorIndication(ei) = m.value else {
            panic!("not an ERROR INDICATION");
        };
        assert!(ei.protocol_i_es.0.iter().any(|ie| matches!(
            &ie.value,
            gen::ErrorIndicationProtocolIEs_EntryValue::Id_Cause(gen::Cause::Protocol(c))
                if c.0 == gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT
        )));
        let _ = server.stop().await;
    }

    // =======================================================================
    // A9 — full chain: DetermineLocation → N1N2 → (fixture) → notify → 200.
    // =======================================================================

    /// The wave's CRITICAL falsifier: a conformant MT-LR DetermineLocation
    /// returns a measurement-derived fix, driven end-to-end across BOTH real NFs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_returns_200_computed_fix_via_real_amfd() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // Drives REAL amfd peer-call code against a loopback PLAINTEXT stub, i.e.
        // describes a dev-profile deployment (issue #63). Declared, not inherited.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
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
        // The UE is served by an ng-eNB (ecgi, TS 29.572 InputData), so lmfd asks
        // for E-UTRA E-CID, whose UE Rx-Tx is the timing term (#715).
        let body = format!(
            r#"{{"supi":"{supi}","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "ecgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"eutraCellId":"0000001"}}}}"#
        );
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });

        // #906: lmfd asks the UE for its capabilities first; the UE reports
        // E-UTRA E-CID only.
        answer_capability_request(&mut tap_rx, &supi, true, false).await;
        assert_eq!(
            lmf_self().read().unwrap().ue_lpp_capability(&supi),
            crate::codec_glue::UeLppCapability::EcidOnly
        );

        // The fixture receives the DL LPP the instant amfd accepts lmfd's POST.
        let (corr, dl_lpp) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("amfd accepted the N1N2MessageTransfer within budget")
            .expect("harness captured the correlation + downlink LPP");
        // #2256: lmfd names its nfId in the LPP N1 container (TS 29.518 Table
        // 6.1.6.2.17-1), so amfd binds the correlation to this LMF, not to no
        // identity that another caller's declaration could take over.
        // Revert-verified: with lmfd's N1 nfId removed, the binding names no
        // LMF and this assertion fails.
        assert_eq!(
            amf_self()
                .read()
                .ok()
                .and_then(|g| g.lcs_uplink_route_find(&supi, &corr))
                .and_then(|r| r.lmf_id)
                .as_deref(),
            Some("lmf-strict-peer"),
            "amfd binds lmfd's correlation to lmfd"
        );

        // Transparent-relay proof (DL leg): amfd extracted EXACTLY lmfd's encoder
        // output. Decode the relayed PDU for its LPP transactionID, then re-encode
        // lmfd's own builder for that txn and compare byte-for-byte.
        let dl_msg = nextgcore_lpp_gen::decode(&dl_lpp).expect("DL LPP decodes");
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
        let notify_resp = notify_n1(&notify).await;
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
        // E-UTRA E-CID (TS 29.572 ECID, #715) + honest freshly-computed age.
        assert_eq!(v["positioningDataList"][0]["method"], "ECID");
        assert_eq!(v["ageOfLocationEstimate"], 0);

        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// The scripted UE's SLPP answer, given as `golden` (an UPER SLPP-Message from
    /// nextgcore-slpp-gen's hand-derived vectors), moved onto transaction `tid`
    /// and sent through amfd's real N1MessageNotify producer with class "SLPP".
    async fn answer_slpp(corr: &str, supi: &str, golden: &[u8], tid: u8) {
        let mut msg = nextgcore_slpp_gen::decode(golden).expect("golden decodes");
        msg.transaction_id = Some(nextgcore_slpp_gen::generated::SLPP_MessageTransactionID(
            tid,
        ));
        let ul = nextgcore_slpp_gen::encode(&msg).expect("re-encodes");
        let amf_req = nextgcore_amfd::namf_server::build_n1_message_notify_request(
            "/nlmf-loc/v1/notify/n1-message-notify/test",
            Some("sub-strict-peer"),
            nextgcore_amfd::namf_server::N1_MESSAGE_CLASS_SLPP,
            Some(corr),
            Some(supi),
            &ul,
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
        assert_eq!(decoded.parts[0].data.as_ref(), ul, "relayed byte-exact");
        let mut req = SbiRequest::post("/nlmf-loc/v1/notify/n1-message-notify/test");
        req.http.set_content(decoded.json.expect("jsonData root"));
        req.http.set_header("Content-Type", ct);
        for p in decoded.parts {
            req.http.add_part(p);
        }
        assert_eq!(notify_n1(&req).await.status, 204);
    }

    /// #557, the acceptance criterion: a sidelink range reaches the LMF via SLPP.
    ///
    /// DetermineLocation asks for RANGING to related UE "ZZZ" (octets 5A 5A 5A).
    /// After the E-CID fix, lmfd runs SLPP through amfd's REAL Namf handler.
    /// RequestCapabilities, then RequestLocationInformation, are relayed
    /// byte-exact as SLPP downlinks, each with its own sequence number
    /// (TS 38.355 §4.3.2). The UE answers with the octets nextgsim's UE
    /// produces for them, which nextgsim #592 pins in
    /// `nas::slpp::tests::the_lmf_*_is_answered_with_the_hand_derived_octets`.
    /// The answer carries its SL-RTT half on 5A5A5A for a 50 m peer.
    ///
    /// The peer's half, 326 Tc measured by 5A5A5A on A5A5A5, is seeded as the
    /// peer's own report would have left it. The range is c * (sum) / 2, about
    /// 50 m.
    ///
    /// What this does not prove: that a running nextgsim UE emits those octets
    /// over NAS and the RAN. The nightly cross-repo E2E covers that.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_sl_rtt_range_reaches_the_lmf_via_slpp_through_real_amfd() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _slpp = crate::slpp::SLPP_GLOBALS_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000557".to_string();
        lmf_context_init(1024);
        prime_lmf_self();
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            g.set_cell_coord(
                "pci-77".to_string(),
                crate::positioning::TrpCoord::new(40.1, -74.5, 0.0),
            );
        }
        seed_amf_connected_ue(&supi);
        // #2260: the UE's Application Layer ID is the one the UDR maps to its
        // GPSI. The golden's A5A5A5 octets are no UTF-8 string, so no
        // ApplicationlayerId can name them; the UE here reports as "ue-557".
        let me: &[u8] = b"ue-557";
        crate::slpp::app_id_bindings().forget(me);
        crate::slpp::sl_rtt_store().note(
            b"ZZZ",
            &[crate::slpp::SlRttHalf {
                peer: me.to_vec(),
                rx_tx_tc: 326.0,
            }],
        );
        let (amf_server, nrf_server, _udr, mut tap_rx) = start_positioning_harness_with_udr(
            supi.clone(),
            Some(serde_json::json!([
                {"rsUeIdMappingInfo": {"appLayerId": "ue-557", "gpsi": "msisdn-10557"}}
            ])),
        )
        .await;
        let located_as_me = {
            let mut m = nextgcore_slpp_gen::decode(
                &crate::slpp::golden::NEXTGSIM_UE_PROVIDE_LOCATION_INFORMATION,
            )
            .unwrap();
            m.application_layer_id =
                Some(nextgcore_slpp_gen::generated::SLPP_MessageApplicationLayerID(me.to_vec()));
            nextgcore_slpp_gen::encode(&m).unwrap()
        };

        let body = format!(
            r#"{{"supi":"{supi}","gpsi":"msisdn-10557","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "ecgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"eutraCellId":"0000001"}},
                "maxRespTime":20,
                "requestedRangingSlResult":["RANGING"],
                "relatedUes":[{{"applicationlayerId":"ZZZ","relatedUeType":"REFERENCE_UE"}}]}}"#
        );
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });

        answer_capability_request(&mut tap_rx, &supi, true, false).await;
        let (corr, _dl, txn) = next_downlink(&mut tap_rx).await;
        let ul_lpp = build_ecid_lpp(77, 60, 800, txn);
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, &supi, &ul_lpp))
                .await
                .status,
            204
        );

        // SLPP capability transfer (TS 38.355 §5.1).
        let slpp_dl = |dl: &[u8]| {
            let msg = nextgcore_slpp_gen::decode(dl).expect("an SLPP downlink");
            msg.transaction_id.expect("a transactionID").0
        };
        let (corr, dl) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("lmfd sent SLPP RequestCapabilities")
            .expect("captured");
        let tid = slpp_dl(&dl);
        let seq_of = |dl: &[u8]| {
            nextgcore_slpp_gen::decode(dl)
                .unwrap()
                .sequence_number
                .map(|s| s.0)
        };
        let seq = seq_of(&dl);
        assert!(
            seq.is_some(),
            "TS 38.355 §4.3.2: every SLPP message carries one"
        );
        assert_eq!(
            dl,
            crate::slpp::build_request_capabilities(tid, seq).unwrap(),
            "amfd relays lmfd's SLPP RequestCapabilities byte-exact"
        );
        answer_slpp(
            &corr,
            &supi,
            &crate::slpp::golden::NEXTGSIM_UE_PROVIDE_CAPABILITIES,
            tid,
        )
        .await;

        // SLPP location information transfer (TS 38.355 §5.3).
        let (corr, dl) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("lmfd sent SLPP RequestLocationInformation")
            .expect("captured");
        let tid = slpp_dl(&dl);
        let seq2 = seq_of(&dl);
        assert_ne!(seq2, seq, "a distinct sequence number per message");
        assert_eq!(
            dl,
            crate::slpp::build_request_location_information(tid, seq2).unwrap()
        );
        answer_slpp(&corr, &supi, &located_as_me, tid).await;

        let resp = tokio::time::timeout(Duration::from_secs(20), det)
            .await
            .expect("DetermineLocation did not hang")
            .expect("no panic");
        assert_eq!(resp.status, 200);
        let v = body_json(&resp);
        assert!(v["locationEstimate"].is_object(), "the location is kept");
        assert_eq!(v["relatedApplicationlayerId"], "ZZZ");
        let d = v["distanceDirection"]["distance"]
            .as_f64()
            .expect("an SL-RTT distance");
        // The UE's half is the 38.133 bin of a 50 m flight time and the peer's is
        // 326 Tc, so the sum resolves to within one 4 Tc step (0.3 m) of 50 m.
        assert!((d - 50.0).abs() < 0.5, "distance {d}");
        crate::slpp::app_id_bindings().forget(me);

        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// **#2260, fail closed.** When the UDR maps the UE's Application Layer ID
    /// to another GPSI (TS 29.519 §6.2.26), the LMF authorises no ID for the
    /// target. It sends it no SLPP at all and returns the location without a
    /// distance, even with the peer's half held under that ID.
    ///
    /// REVERT-VERIFIED: with the authorisation skipped (the run goes on with no
    /// authorised ID), lmfd sends RequestCapabilities.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_id_the_udr_maps_to_another_gpsi_gets_no_sl_rtt_run_2260() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _slpp = crate::slpp::SLPP_GLOBALS_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000002260".to_string();
        lmf_context_init(1024);
        prime_lmf_self();
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            g.set_cell_coord(
                "pci-77".to_string(),
                crate::positioning::TrpCoord::new(40.1, -74.5, 0.0),
            );
        }
        seed_amf_connected_ue(&supi);
        crate::slpp::sl_rtt_store().note(
            b"ZZZ",
            &[crate::slpp::SlRttHalf {
                peer: b"ue-2260".to_vec(),
                rx_tx_tc: 326.0,
            }],
        );
        let (amf_server, nrf_server, _udr, mut tap_rx) = start_positioning_harness_with_udr(
            supi.clone(),
            Some(serde_json::json!([
                {"rsUeIdMappingInfo": {"appLayerId": "ue-2260", "gpsi": "msisdn-OTHER"}}
            ])),
        )
        .await;
        let body = format!(
            r#"{{"supi":"{supi}","gpsi":"msisdn-12260","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "ecgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"eutraCellId":"0000001"}},
                "maxRespTime":20,
                "requestedRangingSlResult":["RANGING"],
                "relatedUes":[{{"applicationlayerId":"ZZZ","relatedUeType":"REFERENCE_UE"}}]}}"#
        );
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });
        answer_capability_request(&mut tap_rx, &supi, true, false).await;
        let (corr, _dl, txn) = next_downlink(&mut tap_rx).await;
        let ul_lpp = build_ecid_lpp(77, 60, 800, txn);
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, &supi, &ul_lpp))
                .await
                .status,
            204
        );
        let resp = tokio::time::timeout(Duration::from_secs(20), det)
            .await
            .expect("DetermineLocation did not hang")
            .expect("no panic");
        assert_eq!(resp.status, 200);
        let v = body_json(&resp);
        assert!(v["locationEstimate"].is_object(), "the location is kept");
        assert!(v.get("distanceDirection").is_none(), "no distance: {v}");
        assert!(
            tap_rx.try_recv().is_err(),
            "no SLPP was sent to a target with no authorised ID"
        );
        crate::slpp::sl_rtt_store().clear();
        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// **#2260 (R48 on #2265), defence in depth.** An Application Layer ID the
    /// UDR maps to the target's GPSI *and* to another GPSI (a 1:N mapping
    /// written around the UDR's 1:1 check) is authorised for no one: the LMF
    /// sends the target no SLPP and returns no distance.
    ///
    /// REVERT-VERIFIED: with the second read by `app-layer-ids` skipped (every
    /// ID read by GPSI kept), lmfd sends RequestCapabilities.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_id_the_udr_maps_to_two_gpsis_is_no_one_s_2260() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _slpp = crate::slpp::SLPP_GLOBALS_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000022602".to_string();
        lmf_context_init(1024);
        prime_lmf_self();
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            g.set_cell_coord(
                "pci-77".to_string(),
                crate::positioning::TrpCoord::new(40.1, -74.5, 0.0),
            );
        }
        seed_amf_connected_ue(&supi);
        crate::slpp::sl_rtt_store().note(
            b"ZZZ",
            &[crate::slpp::SlRttHalf {
                peer: b"ue-2260".to_vec(),
                rx_tx_tc: 326.0,
            }],
        );
        let (amf_server, nrf_server, _udr, mut tap_rx) = start_positioning_harness_with_udr(
            supi.clone(),
            Some(serde_json::json!([
                {"rsUeIdMappingInfo": {"appLayerId": "ue-2260", "gpsi": "msisdn-12260"}},
                {"rsUeIdMappingInfo": {"appLayerId": "ue-2260", "gpsi": "msisdn-OTHER"}}
            ])),
        )
        .await;
        let body = format!(
            r#"{{"supi":"{supi}","gpsi":"msisdn-12260","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "ecgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"eutraCellId":"0000001"}},
                "maxRespTime":20,
                "requestedRangingSlResult":["RANGING"],
                "relatedUes":[{{"applicationlayerId":"ZZZ","relatedUeType":"REFERENCE_UE"}}]}}"#
        );
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });
        answer_capability_request(&mut tap_rx, &supi, true, false).await;
        let (corr, _dl, txn) = next_downlink(&mut tap_rx).await;
        let ul_lpp = build_ecid_lpp(77, 60, 800, txn);
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, &supi, &ul_lpp))
                .await
                .status,
            204
        );
        let resp = tokio::time::timeout(Duration::from_secs(20), det)
            .await
            .expect("DetermineLocation did not hang")
            .expect("no panic");
        assert_eq!(resp.status, 200);
        let v = body_json(&resp);
        assert!(v["locationEstimate"].is_object(), "the location is kept");
        assert!(v.get("distanceDirection").is_none(), "no distance: {v}");
        assert!(
            tap_rx.try_recv().is_err(),
            "no SLPP was sent to a target with no authorised ID"
        );
        crate::slpp::sl_rtt_store().clear();
        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// The next downlink LPP the harness captured, and its transaction number.
    async fn next_downlink(
        tap_rx: &mut tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    ) -> (String, Vec<u8>, u8) {
        let (corr, dl) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("amfd accepted an N1N2MessageTransfer within budget")
            .expect("harness captured the correlation + downlink LPP");
        let txn = nextgcore_lpp_gen::decode(&dl)
            .expect("DL LPP decodes")
            .transaction_id
            .expect("a transactionID")
            .transaction_number
            .0;
        (corr, dl, txn)
    }

    /// Three TRPs, so the registry does not force E-CID (#906 chain tests).
    fn seed_three_cells() {
        let ctx = lmf_self();
        let g = ctx.read().unwrap();
        for (k, lat) in [("pci-77", 40.1), ("pci-78", 40.11), ("pci-79", 40.12)] {
            g.set_cell_coord(k, crate::positioning::TrpCoord::new(lat, -74.5, 0.0));
        }
    }

    /// A high-accuracy request for an NR UE whose capability is unknown.
    fn high_accuracy_request(supi: &str, max_resp_time: u32) -> SbiRequest {
        let body = format!(
            r#"{{"supi":"{supi}","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "locationQoS":{{"hAccuracy":5}},"maxRespTime":{max_resp_time},
                "ncgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"nrCellId":"000000001"}}}}"#
        );
        SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json")
    }

    /// #906: lmfd asks a UE whose capabilities it does not know for them (LPP
    /// RequestCapabilities through real amfd) BEFORE it asks for a location, and
    /// the answer decides the method. This UE reports NR E-CID only, so a <=10 m
    /// request asks it for NR E-CID; with its capability unknown the same
    /// request asks for NR DL-TDOA.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_capabilities_are_asked_for_and_decide_the_method() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000906".to_string();
        lmf_context_init(1024);
        prime_lmf_self();
        seed_three_cells();
        seed_amf_connected_ue(&supi);
        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        let req = high_accuracy_request(&supi, 10);
        let det = tokio::spawn(async move { handle_determine_location(&req).await });
        answer_capability_request(&mut tap_rx, &supi, false, true).await;
        let (_corr, dl, txn) = next_downlink(&mut tap_rx).await;
        assert_eq!(
            dl,
            codec_glue::build_lpp_request(codec_glue::LppMethod::NrEcid, txn).unwrap(),
            "the UE reported NR E-CID only, so it is not asked for DL-TDOA"
        );
        det.abort();

        // The capabilities are kept: the next request asks for no capabilities,
        // and goes straight to the location request.
        let req = high_accuracy_request(&supi, 10);
        let det = tokio::spawn(async move { handle_determine_location(&req).await });
        let (_corr, dl, txn) = next_downlink(&mut tap_rx).await;
        assert_eq!(
            dl,
            codec_glue::build_lpp_request(codec_glue::LppMethod::NrEcid, txn).unwrap()
        );
        det.abort();
        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// #998: a UE that answers the RequestCapabilities with an LPP Abort is
    /// positioned at once, not after the capability wait, and is backed off.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_an_aborted_capability_request_ends_the_wait() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000998".to_string();
        lmf_context_init(1024);
        prime_lmf_self();
        seed_three_cells();
        seed_amf_connected_ue(&supi);
        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        // 20 s budget: the capability wait would be 2 s.
        let req = high_accuracy_request(&supi, 20);
        let det = tokio::spawn(async move { handle_determine_location(&req).await });
        let (cap_corr, dl, cap_txn) = next_downlink(&mut tap_rx).await;
        assert_eq!(
            dl,
            codec_glue::build_lpp_request_capabilities(cap_txn).unwrap()
        );
        let aborted = std::time::Instant::now();
        assert_eq!(
            notify_n1(&amfd_notify_request(
                &cap_corr,
                &supi,
                &crate::lpp_fixtures::target_abort(cap_txn)
            ))
            .await
            .status,
            204
        );
        let (_corr, dl, txn) = next_downlink(&mut tap_rx).await;
        assert!(
            aborted.elapsed() < Duration::from_millis(1_000),
            "the Abort ended the 2 s wait: {:?}",
            aborted.elapsed()
        );
        assert_eq!(
            dl,
            codec_glue::build_lpp_request(codec_glue::LppMethod::DlTdoa, txn).unwrap()
        );
        det.abort();
        assert!(
            lmf_self()
                .read()
                .unwrap()
                .capability_exchange_begin(&supi, 0)
                .is_none(),
            "backed off"
        );
        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// #906: a UE that does not answer the RequestCapabilities is positioned on
    /// what is known after a bounded wait (a quarter of a 2 s budget), is not
    /// asked again on the next request, and a late ProvideCapabilities is still
    /// recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_unanswered_capability_request_is_not_repeated() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000916".to_string();
        lmf_context_init(1024);
        prime_lmf_self();
        seed_three_cells();
        seed_amf_connected_ue(&supi);
        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        let req = high_accuracy_request(&supi, 2);
        let det = tokio::spawn(async move { handle_determine_location(&req).await });
        let (_cap_corr, dl, cap_txn) = next_downlink(&mut tap_rx).await;
        assert_eq!(
            dl,
            codec_glue::build_lpp_request_capabilities(cap_txn).unwrap()
        );
        // The UE stays silent; the location request follows within the wait.
        let asked = std::time::Instant::now();
        let (corr, dl, txn) = next_downlink(&mut tap_rx).await;
        assert!(asked.elapsed() <= Duration::from_millis(1_500));
        assert_eq!(
            dl,
            codec_glue::build_lpp_request(codec_glue::LppMethod::DlTdoa, txn).unwrap(),
            "with the capability unknown, a <=10 m request asks for DL-TDOA"
        );

        // The late answer, on the capability transaction, arrives under the
        // positioning session's correlation (amfd keeps the latest one per UE).
        let late = crate::lpp_fixtures::ecid_capabilities(cap_txn, false, true);
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, &supi, &late))
                .await
                .status,
            204
        );
        assert_eq!(
            lmf_self().read().unwrap().ue_lpp_capability(&supi),
            crate::codec_glue::UeLppCapability::EcidOnly
        );
        det.abort();

        // Not asked again: the next downlink is the location request, now NR E-CID.
        let req = high_accuracy_request(&supi, 2);
        let det = tokio::spawn(async move { handle_determine_location(&req).await });
        let (_corr, dl, txn) = next_downlink(&mut tap_rx).await;
        assert_eq!(
            dl,
            codec_glue::build_lpp_request(codec_glue::LppMethod::NrEcid, txn).unwrap()
        );
        det.abort();
        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// #715 over both real NFs: a UE on NR access (`ncgi`) is asked for NR E-CID
    /// (`nr-ECID-RequestLocationInformation-r16`), not E-UTRA E-CID. Its NR E-CID
    /// report carries no UE timing quantity, so without the NRPPa leg there is no
    /// E-CID timing term and no fix: 500 POSITIONING_FAILED, never a guess.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_nr_access_asks_for_nr_ecid() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000709".to_string();

        lmf_context_init(1024);
        prime_lmf_self();
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            g.set_cell_coord(
                "pci-77".to_string(),
                crate::positioning::TrpCoord::new(40.1, -74.5, 0.0),
            );
        }
        seed_amf_connected_ue(&supi);
        seed_capabilities_reported(&supi);
        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        let body = format!(
            r#"{{"supi":"{supi}","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "ncgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"nrCellId":"000000001"}}}}"#
        );
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });

        let (corr, dl_lpp) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("amfd accepted the N1N2MessageTransfer within budget")
            .expect("harness captured the correlation + downlink LPP");
        let dl_msg = nextgcore_lpp_gen::decode(&dl_lpp).expect("DL LPP decodes");
        let txn = dl_msg
            .transaction_id
            .as_ref()
            .expect("txn")
            .transaction_number
            .0;
        assert_eq!(
            dl_lpp,
            codec_glue::build_lpp_request(codec_glue::LppMethod::NrEcid, txn).expect("encode"),
            "an NR UE is asked for NR E-CID"
        );

        let ul_lpp = crate::lpp_fixtures::nr_ecid_lpp(77, 80, 60, &[], txn);
        let notify = amfd_notify_request(&corr, &supi, &ul_lpp);
        assert_eq!(notify_n1(&notify).await.status, 204);
        let resp = tokio::time::timeout(Duration::from_secs(10), det)
            .await
            .expect("DetermineLocation did not hang")
            .expect("DetermineLocation task did not panic");
        assert_eq!(resp.status, 500);
        assert_eq!(body_json(&resp)["cause"], "POSITIONING_FAILED");

        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// #715 review MAJOR, end to end through real amfd: with the NRPPa downlink on,
    /// the UE's NR E-CID report arrives BEFORE the gNB's E-CID answer. It used to
    /// end the session with 500 on its own (no timing term). Now the session waits
    /// for the NRPPa leg, and the two give a 200 NR_ECID fix.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_nr_ecid_lpp_before_nrppa_is_a_fix() {
        use crate::nrppa_uplink::test_support::{ecid_initiation_response, nr_cgi, rsrp, ta1};
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000715".to_string();

        lmf_context_init(1024);
        prime_lmf_self();
        nrppa_downlink::set_for_test(true);
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            // The same cell as the UE names it (PCI) and as the gNB does (NR CGI).
            let cell = crate::positioning::TrpCoord::new(40.1, -74.5, 0.0);
            g.set_cell_coord("pci-77".to_string(), cell);
            g.set_cell_coord("02f839-000000001".to_string(), cell);
        }
        seed_amf_connected_ue(&supi);
        seed_capabilities_reported(&supi);
        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        let body = format!(
            r#"{{"supi":"{supi}","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "ncgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"nrCellId":"000000001"}}}}"#
        );
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });

        let (corr, dl_lpp) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("amfd accepted the N1N2MessageTransfer within budget")
            .expect("harness captured the correlation + downlink LPP");
        let txn = nextgcore_lpp_gen::decode(&dl_lpp)
            .expect("DL LPP decodes")
            .transaction_id
            .expect("txn")
            .transaction_number
            .0;

        // 1. The UE's leg first.
        let ul_lpp = crate::lpp_fixtures::nr_ecid_lpp(77, 80, 60, &[], txn);
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, &supi, &ul_lpp))
                .await
                .status,
            204
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !det.is_finished(),
            "the LPP leg alone must not answer the DetermineLocation"
        );

        // 2. The gNB's answer to the on-demand E-CID request.
        let nrppa = ecid_initiation_response(
            0,
            1,
            5,
            nr_cgi([0x02, 0xf8, 0x39], 1),
            [0x00, 0x00, 0x01],
            Some(vec![rsrp(&[60]), ta1(100)]),
        );
        let json = format!(
            "{{\"n2NotifySubscriptionId\":\"sub-715\",\
             \"n2InfoContainer\":{{\"n2InformationClass\":\"NRPPa\",\
             \"nrppaInfo\":{{\"nrppaPdu\":{{\"ngapIeType\":\"NRPPA_PDU\",\
             \"ngapData\":{{\"contentId\":\"nrppa\"}}}}}}}},\
             \"lcsCorrelationId\":\"{corr}\"}}"
        );
        let mut n2 = SbiRequest::post("/nlmf-loc/v1/notify/n2");
        n2.http.set_content(json);
        n2.http
            .add_part(nextgcore_sbi::message::SbiPart::with_content(
                "nrppa",
                "application/vnd.3gpp.ngap",
                bytes::Bytes::from(nrppa),
            ));
        assert_eq!(notify_n2(&n2).await.status, 204);

        let resp = tokio::time::timeout(Duration::from_secs(10), det)
            .await
            .expect("DetermineLocation did not hang")
            .expect("DetermineLocation task did not panic");
        nrppa_downlink::set_for_test(false);
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        let out = body_json(&resp);
        assert_eq!(out["positioningDataList"][0]["method"], "NR_ECID", "{out}");

        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// #911, end to end through real amfd: with the NRPPa downlink on, a <=10 m
    /// request makes lmfd learn the TRPs' PRS configuration (TRP Information
    /// Exchange, non-UE NRPPa through amfd), and the UE's first downlink LPP is
    /// the ProvideAssistanceData, before the RequestLocationInformation (TS
    /// 38.305 §8.10.3.2 step 7 before step 8). The serving gNB does not answer
    /// Positioning Information, so the method falls back to DL-TDOA, and the UE's
    /// DL-TDOA report on the DL-PRS IDs of the assistance data gives a 200 fix.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_sends_dl_prs_assistance_before_the_request() {
        use crate::nrppa_positioning::test_support as gnb;
        use nextgcore_lpp_gen::generated as lpp;
        use nextgcore_nrppa_gen::generated as nrppa;
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000911".to_string();
        lmf_context_init(1024);
        prime_lmf_self();
        nrppa_downlink::set_for_test(true);
        let node = crate::site_config::NgRanNode {
            mcc: "001".into(),
            mnc: "01".into(),
            gnb_id: 0x911,
            bit_length: 22,
        };
        let origin = crate::positioning::TrpCoord::new(40.1, -74.5, 0.0);
        let at = move |e: f64, n: f64| {
            crate::positioning::enu_to_geodetic(
                crate::positioning::EnuPoint { e, n, u: 0.0 },
                origin,
            )
        };
        // (TRP id, PCI, east, north); the UE at (300, 450) m. PCI 77 twice.
        let trps = [
            (1u16, 77u16, 0.0, 0.0),
            (2, 78, 1000.0, 0.0),
            (3, 79, 0.0, 1000.0),
            (4, 77, 1000.0, 1000.0),
        ];
        let ue = (300.0, 450.0);
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            g.set_ng_ran_nodes(vec![node.clone()]);
            // Three configured reference points, so a multilateration is selected.
            for (k, e, n) in [
                ("pci-78", 1000.0, 0.0),
                ("pci-79", 0.0, 1000.0),
                ("pci-80", 9.0, 9.0),
            ] {
                g.set_cell_coord(k, at(e, n));
            }
        }
        seed_amf_connected_ue(&supi);
        // #906: capabilities known (nothing in them), so no Capability Transfer.
        seed_capabilities_reported(&supi);
        let _ = amf_self().read().unwrap().non_ue_nrppa_drain();
        // The NG-RAN node: answers TRP Information with PRS configurations.
        let answering = tokio::spawn(async move {
            let scale = f64::from(1u32 << 31);
            for _ in 0..500 {
                for d in amf_self().read().unwrap().non_ue_nrppa_drain() {
                    let Ok(nrppa::NRPPA_PDU::InitiatingMessage(m)) =
                        nextgcore_nrppa_gen::decode(&d.nrppa_pdu)
                    else {
                        continue;
                    };
                    if m.procedure_code.0 != nrppa::ID_T_RP_INFORMATION_EXCHANGE {
                        continue;
                    }
                    use nrppa::TRPInformationTypeResponseItem as I;
                    let items = trps
                        .iter()
                        .map(|(id, pci, e, n)| {
                            let c = at(*e, *n);
                            (
                                *id,
                                vec![
                                    I::PCI_NR(nrppa::TRPInformationTypeResponseItem_pCI_NR(*pci)),
                                    I::PRSConfiguration(crate::dl_prs_assistance::tests::config(
                                        vec![crate::dl_prs_assistance::tests::set(
                                            0,
                                            1,
                                            5,
                                            0,
                                            0,
                                            620_000,
                                            &[(*id, 0)],
                                        )],
                                    )),
                                    gnb::geographical(
                                        (c.lat_deg * scale / 90.0).floor() as i32,
                                        (c.lon_deg * scale / 180.0).floor() as i32,
                                        0,
                                    ),
                                ],
                            )
                        })
                        .collect();
                    let answer =
                        gnb::trp_information_response_items(m.nrppatransaction_id.0, items);
                    lmf_self().read().unwrap().nrppa_deliver(
                        nrppa::ID_T_RP_INFORMATION_EXCHANGE,
                        m.nrppatransaction_id.0,
                        None,
                        &context::NotifyOwner::non_ue(),
                        answer,
                    );
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        let body = format!(
            r#"{{"supi":"{supi}","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "locationQoS":{{"hAccuracy":5}},"maxRespTime":5,
                "ncgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"nrCellId":"000000001"}}}}"#
        );
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });

        async fn next(
            rx: &mut tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
        ) -> (String, Vec<u8>) {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("a downlink LPP within budget")
                .expect("captured")
        }
        // 1. ProvideAssistanceData, DL-TDOA only (the Multi-RTT gNB half failed).
        let (_corr, ad) = next(&mut tap_rx).await;
        let msg = nextgcore_lpp_gen::decode(&ad).expect("decodes");
        let Some(lpp::LPP_MessageBody::C1(lpp::LPP_MessageBody_c1::ProvideAssistanceData(p))) =
            msg.lpp_message_body
        else {
            panic!("the first downlink is a ProvideAssistanceData, got {msg:?}");
        };
        let lpp::ProvideAssistanceDataCriticalExtensions::C1(
            lpp::ProvideAssistanceDataCriticalExtensions_c1::ProvideAssistanceData_r9(ies),
        ) = p.critical_extensions
        else {
            panic!("r9");
        };
        assert!(ies
            .extensions
            .nr_multi_rtt_provide_assistance_data_r16
            .is_none());
        let data = ies
            .extensions
            .nr_dl_tdoa_provide_assistance_data_r16
            .and_then(|d| d.nr_dl_prs_assistance_data_r16)
            .expect("NR-DL-PRS-AssistanceData");
        let per = &data.nr_dl_prs_assistance_data_list_r16.0[0]
            .nr_dl_prs_assistance_data_per_freq_r16
            .0;
        assert_eq!(per.len(), 4, "every TRP, PCI 77 twice");
        let id_of = |trp: u16| lmf_self().read().unwrap().dl_prs_id_of(&node, trp).unwrap();
        let ref_id = data.nr_dl_prs_reference_info_r16.dl_prs_id_r16.0;

        // 2. The RequestLocationInformation for DL-TDOA.
        let (corr, dl) = next(&mut tap_rx).await;
        let txn = nextgcore_lpp_gen::decode(&dl)
            .unwrap()
            .transaction_id
            .unwrap()
            .transaction_number
            .0;
        assert_eq!(
            dl,
            codec_glue::build_lpp_request(codec_glue::LppMethod::DlTdoa, txn).unwrap()
        );

        // 3. The UE measures on the assistance data: RSTDs against the reference.
        let tc_ns = 1e9 / (480_000.0 * 4_096.0);
        let prop = |e: f64, n: f64| {
            (ue.0 - e).hypot(ue.1 - n) / crate::positioning::SPEED_OF_LIGHT_M_S * 1e9
        };
        let reference = trps.iter().find(|t| id_of(t.0) == ref_id).unwrap();
        let neighbours: Vec<(u8, Option<u16>, u32)> = trps
            .iter()
            .filter(|t| t.0 != reference.0)
            .map(|(id, pci, e, n)| {
                let rstd = prop(*e, *n) - prop(reference.2, reference.3);
                (
                    id_of(*id),
                    Some(*pci),
                    ((rstd / tc_ns).floor() + 985_025.0) as u32,
                )
            })
            .collect();
        let ul = crate::lpp_fixtures::dl_tdoa_lpp(ref_id, &neighbours, txn);
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, &supi, &ul))
                .await
                .status,
            204
        );
        let resp = tokio::time::timeout(Duration::from_secs(10), det)
            .await
            .expect("DetermineLocation did not hang")
            .expect("DetermineLocation task did not panic");
        nrppa_downlink::set_for_test(false);
        answering.abort();
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        let out = body_json(&resp);
        assert_eq!(out["positioningDataList"][0]["method"], "DL_TDOA", "{out}");
        let fix = crate::positioning::geodetic_to_enu(
            crate::positioning::TrpCoord::new(
                out["locationEstimate"]["point"]["lat"].as_f64().unwrap(),
                out["locationEstimate"]["point"]["lon"].as_f64().unwrap(),
                0.0,
            ),
            origin,
        );
        let err = (fix.e - ue.0).hypot(fix.n - ue.1);
        assert!(err < 2.0, "the fix is {err:.2} m off, from all four TRPs");
        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// #1013, end to end through real amfd: a UE that reported Multi-RTT and not
    /// DL-TDOA, NRPPa downlink on, and an NG-RAN node that answers TRP Information
    /// with PRS configurations. The serving gNB does not answer Positioning
    /// Information, so the gNB half fails and the session falls back to NR E-CID
    /// (#906). The DL-PRS assistance data is built, but an E-CID session gets none of
    /// it (#911): the only downlink LPP is the E-CID RequestLocationInformation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_ecid_fallback_session_sends_no_dl_prs_assistance_data() {
        use crate::nrppa_positioning::test_support as gnb;
        use nextgcore_nrppa_gen::generated as nrppa;
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000001013".to_string();
        lmf_context_init(1024);
        prime_lmf_self();
        nrppa_downlink::set_for_test(true);
        // Turned off again however the test ends, a failed assertion included, so
        // the flag cannot leak into the next test (#1131 review).
        struct NrppaDownlinkOff;
        impl Drop for NrppaDownlinkOff {
            fn drop(&mut self) {
                nrppa_downlink::set_for_test(false);
            }
        }
        let _downlink_off = NrppaDownlinkOff;
        let node = crate::site_config::NgRanNode {
            mcc: "001".into(),
            mnc: "01".into(),
            gnb_id: 0x1013,
            bit_length: 22,
        };
        let origin = crate::positioning::TrpCoord::new(40.1, -74.5, 0.0);
        let at = move |e: f64, n: f64| {
            crate::positioning::enu_to_geodetic(
                crate::positioning::EnuPoint { e, n, u: 0.0 },
                origin,
            )
        };
        let trps = [
            (1u16, 77u16, 0.0, 0.0),
            (2, 78, 1000.0, 0.0),
            (3, 79, 0.0, 1000.0),
        ];
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            g.set_ng_ran_nodes(vec![node.clone()]);
            for (k, e, n) in [
                ("pci-78", 1000.0, 0.0),
                ("pci-79", 0.0, 1000.0),
                ("pci-80", 9.0, 9.0),
            ] {
                g.set_cell_coord(k, at(e, n));
            }
            // Multi-RTT and not DL-TDOA: without the gNB half, E-CID (#906).
            g.note_ue_capabilities(
                &supi,
                &codec_glue::ReportedCapabilities {
                    class: codec_glue::UeLppCapability::AdvancedMethods,
                    ecid: codec_glue::EcidFlavours::default(),
                    nr: codec_glue::NrMethods {
                        multi_rtt: true,
                        dl_tdoa: false,
                    },
                    transaction: None,
                },
            );
        }
        seed_amf_connected_ue(&supi);
        let _ = amf_self().read().unwrap().non_ue_nrppa_drain();
        // The NG-RAN node answers TRP Information with PRS configurations, and
        // nothing else (Positioning Information goes unanswered).
        let trp_info_answered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let answered = std::sync::Arc::clone(&trp_info_answered);
        let answering = tokio::spawn(async move {
            let scale = f64::from(1u32 << 31);
            for _ in 0..500 {
                for d in amf_self().read().unwrap().non_ue_nrppa_drain() {
                    let Ok(nrppa::NRPPA_PDU::InitiatingMessage(m)) =
                        nextgcore_nrppa_gen::decode(&d.nrppa_pdu)
                    else {
                        continue;
                    };
                    if m.procedure_code.0 != nrppa::ID_T_RP_INFORMATION_EXCHANGE {
                        continue;
                    }
                    use nrppa::TRPInformationTypeResponseItem as I;
                    let items = trps
                        .iter()
                        .map(|(id, pci, e, n)| {
                            let c = at(*e, *n);
                            (
                                *id,
                                vec![
                                    I::PCI_NR(nrppa::TRPInformationTypeResponseItem_pCI_NR(*pci)),
                                    I::PRSConfiguration(crate::dl_prs_assistance::tests::config(
                                        vec![crate::dl_prs_assistance::tests::set(
                                            0,
                                            1,
                                            5,
                                            0,
                                            0,
                                            620_000,
                                            &[(*id, 0)],
                                        )],
                                    )),
                                    gnb::geographical(
                                        (c.lat_deg * scale / 90.0).floor() as i32,
                                        (c.lon_deg * scale / 180.0).floor() as i32,
                                        0,
                                    ),
                                ],
                            )
                        })
                        .collect();
                    let answer =
                        gnb::trp_information_response_items(m.nrppatransaction_id.0, items);
                    lmf_self().read().unwrap().nrppa_deliver(
                        nrppa::ID_T_RP_INFORMATION_EXCHANGE,
                        m.nrppatransaction_id.0,
                        None,
                        &context::NotifyOwner::non_ue(),
                        answer,
                    );
                    answered.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        let body = format!(
            r#"{{"supi":"{supi}","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"],
                "locationQoS":{{"hAccuracy":5}},"maxRespTime":3,
                "ncgi":{{"plmnId":{{"mcc":"001","mnc":"01"}},"nrCellId":"000000001"}}}}"#
        );
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });

        // The first downlink LPP is the E-CID request, not a ProvideAssistanceData.
        let (_corr, dl) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("a downlink LPP within budget")
            .expect("captured");
        assert!(
            trp_info_answered.load(std::sync::atomic::Ordering::SeqCst),
            "the assistance data was built (TRP Information answered), so only the method \
             guard keeps it from the UE"
        );
        let txn = nextgcore_lpp_gen::decode(&dl)
            .expect("decodes")
            .transaction_id
            .expect("a transactionID")
            .transaction_number
            .0;
        assert_eq!(
            dl,
            codec_glue::build_lpp_request(codec_glue::LppMethod::NrEcid, txn).unwrap(),
            "the only downlink is the NR E-CID RequestLocationInformation: {:?}",
            nextgcore_lpp_gen::decode(&dl)
        );

        // Nothing else goes to the UE while the session runs out its budget.
        let _ = tokio::time::timeout(Duration::from_secs(10), det)
            .await
            .expect("DetermineLocation did not hang");
        answering.abort();
        assert!(
            tap_rx.try_recv().is_err(),
            "no further downlink LPP (no ProvideAssistanceData after the request)"
        );
        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// #807, both ends of the non-UE NRPPa leg through real amfd code:
    /// - lmfd's NonUeN2InfoSubscribe for NRPPa is accepted by amfd;
    /// - lmfd's NonUeN2MessageTransfer is queued by amfd for the named gNB with the
    ///   LMF's nfId as Routing ID;
    /// - amfd's NonUeN2InfoNotify for the gNB's answer, which names no session, is
    ///   handed by lmfd's N2 notify route to the exchange waiting on it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_non_ue_nrppa_round_trip_through_real_amfd() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _serial = chain_lock().lock().await;
        lmf_context_init(1024);
        nextgcore_amfd::test_support::init_context();
        let node = crate::site_config::NgRanNode {
            mcc: "001".into(),
            mnc: "01".into(),
            gnb_id: 0x807,
            bit_length: 22,
        };

        // #1518: the subscription's N2 token, held from the moment it is minted.
        let amf_peer = namf_client::DiscoveredAmf {
            host: "127.0.0.1".into(),
            port: 9,
            scheme: "http".into(),
            nf_instance_id: None,
        };
        let (start, _) = lmf_self()
            .read()
            .unwrap()
            .amf_subscription_begin(&amf_peer.non_ue_subscription_key(), &amf_peer, None)
            .expect("no subscription yet");
        let mut sub = namf_client::build_non_ue_nrppa_subscription_request(
            "lmf-807",
            "http://127.0.0.1:7816",
            &start.n2_token,
        );
        // #1865: amfd binds the subscription to a verified LMF; without one the
        // production profile refuses it, so this would depend on a sibling test
        // having selected dev.
        sub.oauth2_subject = Some("lmf-807".into());
        let resp = nextgcore_amfd::namf_request_handler(sub).await;
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);

        let (txn, pdu) = nrppa_downlink::build_trp_information(&[]).unwrap();
        let _ = amf_self().read().unwrap().non_ue_nrppa_drain();
        let resp = nextgcore_amfd::namf_request_handler(
            namf_client::build_non_ue_nrppa_transfer_request(&node, "lmf-807", pdu.clone()),
        )
        .await;
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        let queued = amf_self().read().unwrap().non_ue_nrppa_drain();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].routing_id, b"lmf-807");
        assert_eq!(queued[0].target_gnb_ids, vec![0x807]);
        assert_eq!(queued[0].nrppa_pdu, pdu);

        // The gNB's answer, as amfd notifies it.
        let answer = crate::nrppa_positioning::test_support::trp_information_response(
            txn.0,
            &[(1, 201, 0, 0, 0)],
        );
        let n2_path = namf_client::notify_path(context::NotifyKind::N2, start.n2_token.as_str());
        let notify = nextgcore_amfd::namf_server::build_non_ue_nrppa_info_notify_request(
            &n2_path,
            "nonuen2sub-x",
            Some("lmf-807"),
            Some(&serde_json::json!({"plmnId": {"mcc": "001", "mnc": "01"},
                "gNbId": {"bitLength": 22, "gNBValue": "000807"}})),
            &answer,
        )
        .unwrap();
        let waiter = lmf_self().read().unwrap().nrppa_wait(
            nextgcore_nrppa_gen::generated::ID_T_RP_INFORMATION_EXCHANGE,
            txn.0,
            None,
        );
        assert_eq!(lmf_sbi_request_handler(notify.clone()).await.status, 204);
        let got = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("delivered")
            .expect("not dropped");
        assert_eq!(got, answer);

        // An answer nobody waits for, with no session, is still unknown: 404.
        assert_eq!(lmf_sbi_request_handler(notify).await.status, 404);
    }

    /// #907 review MAJOR: an unsolicited ProvideCapabilities during a session is
    /// recorded and answered 204, and it is not the session's LPP leg: the session
    /// stays pending, and the real report still completes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_capability_report_is_recorded_and_is_not_the_lpp_leg() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _serial = chain_lock().lock().await;
        lmf_context_init(1024);
        let supi = "imsi-001010000000907";
        let (corr, mut rx, request_id) = {
            let g = lmf_self();
            let g = g.read().unwrap();
            g.set_cell_coord("pci-7", crate::positioning::TrpCoord::new(40.0, -74.0, 0.0));
            let req = g
                .measurement_request(
                    0,
                    PositioningMethod::Ecid,
                    None,
                    None,
                    PositioningQos::BestEffort,
                )
                .unwrap();
            let (corr, rx) = g.positioning_session_register(Some(supi.into()), 3, req.request_id);
            (corr, rx, req.request_id)
        };
        let caps = crate::lpp_equivalence_tests::unhex("9203084858");
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, supi, &caps))
                .await
                .status,
            204
        );
        assert!(
            rx.try_recv().is_err(),
            "the capability report did not complete the session"
        );
        assert!(lmf_self()
            .read()
            .unwrap()
            .positioning_session_find(&corr)
            .is_some());
        assert_eq!(
            lmf_self().read().unwrap().ue_lpp_capability(supi),
            crate::codec_glue::UeLppCapability::EcidOnly
        );
        let report = crate::lpp_fixtures::ecid_lpp(7, 60, 500, 3);
        assert_eq!(
            notify_n1(&amfd_notify_request(&corr, supi, &report))
                .await
                .status,
            204
        );
        assert!(matches!(rx.try_recv(), Ok(PositioningOutcome::Fix(_))));
        let _ = request_id;
    }

    /// Negative leg (WS-A §A9 step 3): amfd accepts the transfer but the UE stays
    /// silent within the response-time budget → 504 UNREACHABLE_USER (fail-closed,
    /// never a fabricated fix). `NO_DELAY` gives a zero budget so the timeout is
    /// deterministic (no real sleep). The lmfd→amfd transfer still executes over
    /// the real harness (proving the A2 leg), then fail-closes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_silent_ue_times_out_504() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000702".to_string();

        lmf_context_init(1024);
        prime_lmf_self();
        // #103: seed a reference point. The live procedure refuses with 500 before any
        // peer is contacted when the registry is empty, and `lmf_context_init` now
        // clears it in test builds -- so a test that must reach the AMF has to provision
        // its own scene rather than inherit a sibling's.
        {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard.set_cell_coord(
                "chain-reference-cell",
                crate::positioning::TrpCoord::new(37.5, 126.9, 0.0),
            );
        }
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // Drives REAL amfd peer-call code against a loopback PLAINTEXT stub, i.e.
        // describes a dev-profile deployment (issue #63). Declared, not inherited.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000703".to_string();

        lmf_context_init(1024);
        prime_lmf_self();
        // #103: seed a reference point. The live procedure refuses with 500 before any
        // peer is contacted when the registry is empty, and `lmf_context_init` now
        // clears it in test builds -- so a test that must reach the AMF has to provision
        // its own scene rather than inherit a sibling's.
        {
            let ctx = lmf_self();
            let guard = ctx.read().expect("context");
            guard.set_cell_coord(
                "chain-reference-cell",
                crate::positioning::TrpCoord::new(37.5, 126.9, 0.0),
            );
        }
        seed_amf_connected_ue(&supi);
        seed_capabilities_reported(&supi);
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
            "/nlmf-loc/v1/notify/n1-message-notify/test",
            Some("sub-corrupt"),
            "LPP",
            Some(&corr),
            Some(&supi),
            &corrupt,
        )
        .expect("amfd builds N1MessageNotify");
        // Delivered to a matched session (204), but yields no fix.
        assert_eq!(notify_n1(&notify).await.status, 204);

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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
            "/nlmf-loc/v1/notify/n1-message-notify/test",
            Some("sub-iso"),
            "LPP",
            Some(&corr_a),
            Some(supi_a),
            &ul,
        )
        .expect("amfd builds N1MessageNotify");
        assert_eq!(notify_n1(&notify).await.status, 204);

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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
                    PositioningDlKind::LppToUe { lpp_pdu, .. } => Some(lpp_pdu),
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

    /// WS-H §H4, #1087: a registered CM-IDLE UE is not "not reachable". amfd's real
    /// handler pages it and answers 202 ATTEMPTING_TO_REACH_UE (TS 29.518
    /// §5.2.2.3.1), which lmfd takes as an initiated transfer. It is not a fake 200,
    /// and not the 504 a UE that cannot be paged gets.
    #[tokio::test]
    async fn test_h4_lmfd_transfer_idle_ue_is_paged_202() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000732";
        let ue_id = seed_amf_idle_ue(supi);

        let lpp = codec_glue::build_lpp_ecid_request(42).expect("LPP encode");
        let req = namf_client::build_n1n2_transfer_request(supi, "corr-idle", "lmf-h4", lpp);
        let resp = nextgcore_amfd::handle_n1_n2_message_transfer_request(supi, &req);
        assert_eq!(resp.status, 202);
        assert_eq!(body_json(&resp)["cause"], "ATTEMPTING_TO_REACH_UE");
        let g = amf_self();
        let g = g.read().unwrap();
        assert!(g.paging_remove(ue_id).is_some(), "the UE is paged");
        let _ = g.positioning_dl_drain();
    }

    /// Negative (WS-H §H4): an unknown ueContextId → 404 CONTEXT_NOT_FOUND from
    /// amfd's real handler (the transfer can never land for an absent UE).
    #[tokio::test]
    async fn test_h4_lmfd_transfer_unknown_ue_404() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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

/// #1324: the NFProfile carries its host where its type belongs (TS 29.510
/// §6.1.6.2.2): IPv4 in ipv4Addresses, IPv6 in ipv6Addresses, an FQDN as fqdn, and
/// the service ipEndPoints likewise.
#[cfg(test)]
mod tests_nf_profile_host_kind_1324 {
    use super::*;

    #[test]
    fn the_nf_profile_carries_its_host_by_type() {
        for host in nextgcore_sbi::nf_addressing::SAMPLE_HOSTS {
            let profile =
                build_lmf_nf_profile("id", host, 7777, nextgcore_sbi::types::UriScheme::Http);
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}

/// #1518: the AMF notify callbacks carry a per-subscription token, and only that
/// token admits a notification, and only for that subscription's UE.
#[cfg(test)]
mod callback_tokens_1518 {
    use super::*;
    use crate::context::{NotifyKind, PROCESS_STATE_TEST_LOCK};
    use crate::namf_client::DiscoveredAmf;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::sync::Mutex;

    const FORGED: &str = "0123456789abcdef0123456789abcdef";

    fn amf_at(port: u16) -> DiscoveredAmf {
        DiscoveredAmf {
            host: "127.0.0.1".into(),
            port,
            scheme: "http".into(),
            nf_instance_id: None,
        }
    }

    /// A UE subscription held for `ue` on a (never contacted) AMF, as created.
    fn subscribe(port: u16, ue: &str) -> (String, String) {
        let amf = amf_at(port);
        let key = amf.subscription_key(ue);
        let c = lmf_self();
        let c = c.read().unwrap();
        let (start, _) = c
            .amf_subscription_begin(&key, &amf, Some(ue))
            .expect("not yet held");
        assert!(c.amf_subscription_created(&key, &start, format!("sub-{ue}")));
        (
            start.n1_token.unwrap().as_str().to_string(),
            start.n2_token.as_str().to_string(),
        )
    }

    /// A pending E-CID session for `ue` on LPP transaction `txn`, solvable on pci-42.
    fn session(
        ue: &str,
        txn: u8,
    ) -> (
        String,
        tokio::sync::oneshot::Receiver<crate::context::PositioningOutcome>,
    ) {
        let c = lmf_self();
        let c = c.read().unwrap();
        c.set_cell_coord(
            "pci-42".to_string(),
            crate::positioning::TrpCoord::new(37.5, -122.3, 0.0),
        );
        let req = c
            .measurement_request(
                0,
                PositioningMethod::Ecid,
                None,
                None,
                PositioningQos::BestEffort,
            )
            .expect("measurement request");
        c.positioning_session_register_for(Some(ue.into()), Some(ue.into()), txn, req.request_id)
    }

    /// amfd's N1MessageNotify for `corr` (when given), as amfd builds it, at `path`.
    fn n1(path: &str, corr: Option<&str>, supi: &str, txn: u8) -> SbiRequest {
        nextgcore_amfd::namf_server::build_n1_message_notify_request(
            path,
            Some("sub"),
            "LPP",
            corr,
            Some(supi),
            &crate::lpp_fixtures::ecid_lpp(42, 60, 800, txn),
        )
        .expect("amfd builds N1MessageNotify")
    }

    fn n1_path(token: &str) -> String {
        namf_client::notify_path(NotifyKind::N1, token)
    }

    /// #1518: a notification reaches its handler only on a token one of this LMF's
    /// subscriptions holds for that callback, and acts only on that subscription's
    /// UE. Every refusal is 404 with the session untouched, and the right token then
    /// completes it.
    ///
    /// REVERT-VERIFIED: with `notify_subscriber` returning an owner for any token,
    /// the forged and wrong-callback cases complete the session; with
    /// `NotifyOwner::serves` always true, the other UE's token does (by correlation
    /// and by LPP transaction).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_notification_acts_only_on_its_subscriptions_token_1518() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let (a_ue, b_ue) = ("imsi-001010000015181", "imsi-001010000015182");
        let (a_n1, a_n2) = subscribe(15181, a_ue);
        let (b_n1, _) = subscribe(15182, b_ue);
        let (corr, mut rx) = session(a_ue, 151);

        for (label, req) in [
            ("forged token", n1(&n1_path(FORGED), Some(&corr), a_ue, 151)),
            (
                "the N2 token at N1",
                n1(&n1_path(&a_n2), Some(&corr), a_ue, 151),
            ),
            (
                "the N1 token at N2",
                n1(
                    &namf_client::notify_path(NotifyKind::N2, &a_n1),
                    Some(&corr),
                    a_ue,
                    151,
                ),
            ),
            (
                "the legacy URI",
                n1("/nlmf-loc/v1/notify/n1", Some(&corr), a_ue, 151),
            ),
            (
                "another UE's token",
                n1(&n1_path(&b_n1), Some(&corr), a_ue, 151),
            ),
            (
                "another UE's token, by LPP transaction",
                n1(&n1_path(&b_n1), None, a_ue, 151),
            ),
        ] {
            assert_eq!(lmf_sbi_request_handler(req).await.status, 404, "{label}");
            assert!(
                matches!(
                    rx.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ),
                "{label}: the session must be untouched"
            );
        }
        assert!(lmf_self()
            .read()
            .unwrap()
            .positioning_session_find(&corr)
            .is_some());

        let resp = lmf_sbi_request_handler(n1(&n1_path(&a_n1), Some(&corr), a_ue, 151)).await;
        assert_eq!(resp.status, 204, "{:?}", resp.http.content);
        let outcome = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("completed")
            .expect("sender kept");
        assert!(
            matches!(outcome, crate::context::PositioningOutcome::Fix(_)),
            "{outcome:?}"
        );
    }

    /// #1518: a UE-associated NRPPa report on another UE's N2 subscription, or on
    /// the non-UE one, is 404 and not attached to the session; on its UE's N2
    /// subscription it is.
    ///
    /// REVERT-VERIFIED: with the N2 session lookup not scoped to `owner`, the other
    /// UE's report is attached.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_nrppa_report_counts_only_on_its_ue_s_subscription_1518() {
        use crate::nrppa_uplink::test_support::{ecid_report, nr_cgi, rsrp, ta1};
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let (a_ue, b_ue) = ("imsi-001010000015188", "imsi-001010000015189");
        let (_, a_n2) = subscribe(15188, a_ue);
        let (_, b_n2) = subscribe(15189, b_ue);
        let non_ue = amf_at(15188);
        let (non_ue_start, _) = lmf_self()
            .read()
            .unwrap()
            .amf_subscription_begin(&non_ue.non_ue_subscription_key(), &non_ue, None)
            .unwrap();
        let (corr, mut rx) = session(a_ue, 152);
        // The session waits for the gNB's E-CID report alone, so that report ends it.
        {
            let c = lmf_self();
            let c = c.read().unwrap();
            c.positioning_session_expect_leg(&corr, crate::context::MeasurementLeg::NrppaEcid);
            c.positioning_session_withdraw_leg(&corr, crate::context::MeasurementLeg::Lpp);
        }
        let report = |token: &str| {
            let json = serde_json::json!({
                "n2NotifySubscriptionId": "sub",
                "n2InfoContainer": {"n2InformationClass": "NRPPa", "nrppaInfo": {
                    "nrppaPdu": {"ngapIeType": "NRPPA_PDU", "ngapData": {"contentId": "nrppa"}}}},
                "lcsCorrelationId": corr,
            });
            let pdu = ecid_report(
                1,
                42,
                7,
                nr_cgi([0x02, 0xF8, 0x39], 0x000000001),
                [0x00, 0x12, 0x34],
                Some(vec![ta1(500), rsrp(&[60])]),
            );
            let mut req = SbiRequest::post(namf_client::notify_path(NotifyKind::N2, token))
                .with_body(json.to_string(), "application/json");
            req.http
                .add_part(nextgcore_sbi::message::SbiPart::with_content(
                    "nrppa",
                    "application/vnd.3gpp.ngap",
                    bytes::Bytes::from(pdu),
                ));
            req
        };
        assert_eq!(lmf_sbi_request_handler(report(&b_n2)).await.status, 404);
        assert_eq!(
            lmf_sbi_request_handler(report(non_ue_start.n2_token.as_str()))
                .await
                .status,
            404
        );
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "another subscription's report must not end the session"
        );
        assert_eq!(lmf_sbi_request_handler(report(&a_n2)).await.status, 204);
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("the session ends on its own UE's report")
            .expect("sender kept");
    }

    /// #1518: a ProvideCapabilities on another UE's subscription is not filed
    /// against the UE whose capability exchange it names; on the right one it is.
    ///
    /// REVERT-VERIFIED: with the capability lookups not filtered by `owner`, the
    /// other UE's report is recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_capability_report_counts_only_on_its_ue_s_subscription_1518() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let (a_ue, b_ue) = ("imsi-001010000015183", "imsi-001010000015184");
        let (a_n1, _) = subscribe(15183, a_ue);
        let (b_n1, _) = subscribe(15184, b_ue);
        let (corr, _rx, _) = lmf_self()
            .read()
            .unwrap()
            .capability_exchange_begin(a_ue, 77)
            .expect("exchange starts");
        let caps = crate::lpp_fixtures::ecid_capabilities(77, false, true);
        let body = |path: &str| {
            nextgcore_amfd::namf_server::build_n1_message_notify_request(
                path,
                Some("sub"),
                "LPP",
                Some(&corr),
                None,
                &caps,
            )
            .expect("amfd builds N1MessageNotify")
        };
        assert_eq!(
            lmf_sbi_request_handler(body(&n1_path(&b_n1))).await.status,
            204
        );
        assert!(
            !lmf_self().read().unwrap().ue_capabilities_reported(a_ue),
            "another UE's subscription must not file A's capabilities"
        );
        assert_eq!(
            lmf_sbi_request_handler(body(&n1_path(&a_n1))).await.status,
            204
        );
        assert!(lmf_self().read().unwrap().ue_capabilities_reported(a_ue));
    }

    /// #1518: the composition root exempts exactly the two tokened callbacks,
    /// token-only, and an OAuth2-required listener (empty JWKS) admits a token-less
    /// notification on a held token only: a forged token, the legacy URI and a
    /// service request stay 401.
    ///
    /// REVERT-VERIFIED: with the exemption's check always true, the forged token
    /// and the N2 token at N1 are admitted (404 from the router, not 401).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_oauth2_listener_admits_the_callbacks_only_on_held_tokens_1518() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        let routes: Vec<String> = oauth2_callback_exemptions()
            .iter()
            .map(|e| e.route())
            .collect();
        assert_eq!(
            routes,
            [
                "POST /nlmf-loc/v1/notify/n1-message-notify/{token}",
                "POST /nlmf-loc/v1/notify/n2-info-notify/{token}",
            ]
        );
        let (n1_tok, n2_tok) = subscribe(15185, "imsi-001010000015185");

        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr)
            .with_oauth2_callback_exemptions(oauth2_callback_exemptions());
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(serde_json::json!({"keys": []}));
        let server = SbiServer::on_listener(cfg, listener);
        server.start(lmf_sbi_request_handler).await.expect("start");
        let client = SbiClient::with_host_port("127.0.0.1", addr.port());
        let mut got = Vec::new();
        for path in [
            n1_path(&n1_tok),
            namf_client::notify_path(NotifyKind::N2, &n2_tok),
            n1_path(FORGED),
            n1_path(&n2_tok),
            "/nlmf-loc/v1/notify/n1".to_string(),
            "/nlmf-loc/v1/determine-location".to_string(),
        ] {
            // A body-less POST: the handler answers 400, the gate 401.
            let status = tokio::time::timeout(
                Duration::from_secs(5),
                client.send_request(SbiRequest::post(path.clone())),
            )
            .await
            .expect("bounded")
            .expect("response")
            .status;
            got.push((path, status));
        }
        server.stop().await.ok();
        let statuses: Vec<u16> = got.iter().map(|(_, s)| *s).collect();
        assert_eq!(statuses, [400, 400, 401, 401, 401, 401], "{got:?}");
    }

    /// A stand-in AMF that records each request and answers a subscribe with
    /// `subscribe_status` (201 with a fresh id) and a transfer with
    /// `transfer_status`.
    struct StandInAmf {
        server: SbiServer,
        amf: DiscoveredAmf,
        seen: Arc<Mutex<Vec<(String, String)>>>,
        subscribe_status: Arc<std::sync::atomic::AtomicU16>,
        transfer_status: Arc<std::sync::atomic::AtomicU16>,
        /// #1877: how long a subscribe is held before it is answered (ms).
        subscribe_delay_ms: Arc<std::sync::atomic::AtomicU64>,
    }

    async fn stand_in_amf() -> StandInAmf {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let subscribe_status = Arc::new(std::sync::atomic::AtomicU16::new(201));
        let transfer_status = Arc::new(std::sync::atomic::AtomicU16::new(200));
        let subscribe_delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let (s, sub, tr, delay) = (
            seen.clone(),
            subscribe_status.clone(),
            transfer_status.clone(),
            subscribe_delay_ms.clone(),
        );
        server
            .start(move |req: SbiRequest| {
                let (s, sub, tr, delay) = (s.clone(), sub.clone(), tr.clone(), delay.clone());
                async move {
                    let uri = req.header.uri.clone();
                    let n = {
                        let mut seen = s.lock().unwrap();
                        seen.push((uri.clone(), req.http.content.clone().unwrap_or_default()));
                        seen.len()
                    };
                    if uri.ends_with("/subscriptions") {
                        let held = delay.load(Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(held)).await;
                        let status = sub.load(Ordering::SeqCst);
                        SbiResponse::with_status(status)
                            .with_json_body(&serde_json::json!({
                                "n1n2NotifySubscriptionId": format!("s{n}"),
                                // #1877: and the non-UE NRPPa answer's member.
                                "n2NotifySubscriptionId": format!("s{n}"),
                            }))
                            .unwrap()
                    } else {
                        SbiResponse::with_status(tr.load(Ordering::SeqCst))
                            .with_json_body(
                                &serde_json::json!({"cause": "N1_N2_TRANSFER_INITIATED"}),
                            )
                            .unwrap()
                    }
                }
            })
            .await
            .expect("stand-in AMF starts");
        StandInAmf {
            server,
            amf: amf_at(addr.port()),
            seen,
            subscribe_status,
            transfer_status,
            subscribe_delay_ms,
        }
    }

    impl StandInAmf {
        /// The N1 token of each subscribe this AMF has received, in order.
        fn subscribed_n1_tokens(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(uri, _)| uri.ends_with("/subscriptions"))
                .map(|(_, body)| {
                    let v: serde_json::Value = serde_json::from_str(body).unwrap();
                    let uri = v["n1NotifyCallbackUri"].as_str().unwrap().to_string();
                    uri.rsplit('/').next().unwrap().to_string()
                })
                .collect()
        }
    }

    /// Whether this LMF acts on an N1 notification on `token` (it reaches the
    /// handler, which answers a body-less POST 400) rather than refusing it (404).
    async fn admitted(token: &str) -> bool {
        match lmf_sbi_request_handler(SbiRequest::post(n1_path(token)))
            .await
            .status
        {
            400 => true,
            404 => false,
            other => panic!("unexpected {other}"),
        }
    }

    /// #1877: a DetermineLocation whose consumer went away while the AMF was making
    /// the N1N2 subscription leaves it recorded, its token admitted, not orphaned at
    /// the AMF: the create and its commit run on their own task.
    ///
    /// REVERT-VERIFIED: with the create awaited inline again, this fails: the entry
    /// is abandoned and the AMF's subscription is recorded nowhere.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_subscribe_cancelled_mid_create_is_still_recorded_1877() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        lmf_self()
            .read()
            .unwrap()
            .set_callback_base("http://127.0.0.1:7816");
        let ue = "imsi-001010000018774";
        let amf = stand_in_amf().await;
        amf.subscribe_delay_ms.store(300, Ordering::SeqCst);
        {
            let mut ensure = Box::pin(namf_client::ensure_n1n2_subscription(&amf.amf, ue));
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while amf.subscribed_n1_tokens().is_empty() {
                assert!(tokio::time::Instant::now() < deadline, "never subscribed");
                if tokio::time::timeout(std::time::Duration::from_millis(5), &mut ensure)
                    .await
                    .is_ok()
                {
                    panic!("finished before the AMF answered");
                }
            }
            // Dropped here: the consumer went away.
        }
        let key = amf.amf.subscription_key(ue);
        let recorded = || lmf_self().read().unwrap().amf_subscription_get(&key);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while recorded().is_none() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let id = recorded();
        let token = amf.subscribed_n1_tokens()[0].clone();
        let still_admitted = admitted(&token).await;
        amf.server.stop().await.ok();

        assert_eq!(
            id.as_deref(),
            Some("s1"),
            "the AMF's subscription is recorded"
        );
        assert!(still_admitted, "and its token admitted");
    }

    /// #1877: the same for the non-UE NRPPa subscription (TS 29.518 §5.2.2.4.2):
    /// its create, dropped by a caller that went away, is still recorded.
    ///
    /// REVERT-VERIFIED: with this create awaited inline again, this fails: the entry
    /// is abandoned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_non_ue_subscribe_cancelled_mid_create_is_still_recorded_1877() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        lmf_self()
            .read()
            .unwrap()
            .set_callback_base("http://127.0.0.1:7816");
        let amf = stand_in_amf().await;
        amf.subscribe_delay_ms.store(300, Ordering::SeqCst);
        let subscribed = || {
            amf.seen
                .lock()
                .unwrap()
                .iter()
                .any(|(uri, _)| uri.ends_with("/subscriptions"))
        };
        {
            let mut ensure = Box::pin(namf_client::ensure_non_ue_nrppa_subscription(
                &amf.amf, "lmf-1877",
            ));
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while !subscribed() {
                assert!(tokio::time::Instant::now() < deadline, "never subscribed");
                if tokio::time::timeout(std::time::Duration::from_millis(5), &mut ensure)
                    .await
                    .is_ok()
                {
                    panic!("finished before the AMF answered");
                }
            }
        }
        let key = amf.amf.non_ue_subscription_key();
        let recorded = || lmf_self().read().unwrap().amf_subscription_get(&key);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while recorded().is_none() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let id = recorded();
        amf.server.stop().await.ok();

        assert_eq!(
            id.as_deref(),
            Some("s1"),
            "the AMF's subscription is recorded"
        );
    }

    /// #1518, restarts of both peers. The subscription is made once and reused;
    /// after the AMF loses it (it answers a transfer 404) the LMF forgets it and the
    /// next request subscribes again with a new token, the old one now refused;
    /// after the LMF restarts, its old token is refused and it subscribes again; a
    /// subscribe the AMF refuses leaves no token admitted.
    ///
    /// REVERT-VERIFIED: without the 404 forget, the lost subscription's token is
    /// still admitted; with `fini` not clearing the store, the pre-restart token is;
    /// with a refused create not forgotten, its token is; without one create per
    /// key, the second call subscribes again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn both_peers_restarting_leave_only_live_tokens_admitted_1518() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        lmf_context_init(1024);
        lmf_self()
            .read()
            .unwrap()
            .set_callback_base("http://127.0.0.1:7816");
        let ue = "imsi-001010000015186";
        let amf = stand_in_amf().await;

        namf_client::ensure_n1n2_subscription(&amf.amf, ue).await;
        namf_client::ensure_n1n2_subscription(&amf.amf, ue).await;
        let tokens = amf.subscribed_n1_tokens();
        assert_eq!(tokens.len(), 1, "made once, then reused");
        assert!(admitted(&tokens[0]).await);

        // The AMF restarted: it no longer knows the UE.
        amf.transfer_status.store(404, Ordering::SeqCst);
        let outcome = namf_client::send_n1n2_transfer(&amf.amf, ue, "c", "lmf", vec![0x90]).await;
        assert!(matches!(outcome, namf_client::TransferOutcome::Failed(_)));
        assert!(!admitted(&tokens[0]).await, "the lost subscription's token");
        namf_client::ensure_n1n2_subscription(&amf.amf, ue).await;
        let tokens = amf.subscribed_n1_tokens();
        assert_eq!(tokens.len(), 2, "subscribed again");
        assert_ne!(tokens[0], tokens[1]);
        assert!(admitted(&tokens[1]).await);

        // The LMF restarts: nothing it held survives.
        lmf_context_final();
        lmf_context_init(1024);
        lmf_self()
            .read()
            .unwrap()
            .set_callback_base("http://127.0.0.1:7816");
        assert!(!admitted(&tokens[1]).await, "the pre-restart token");
        namf_client::ensure_n1n2_subscription(&amf.amf, ue).await;
        let tokens = amf.subscribed_n1_tokens();
        assert_eq!(tokens.len(), 3);
        assert!(admitted(&tokens[2]).await);

        // A subscribe the AMF refuses is forgotten, its token with it.
        let other = "imsi-001010000015187";
        amf.subscribe_status.store(500, Ordering::SeqCst);
        namf_client::ensure_n1n2_subscription(&amf.amf, other).await;
        let tokens = amf.subscribed_n1_tokens();
        assert_eq!(tokens.len(), 4);
        assert!(!admitted(&tokens[3]).await, "a refused create's token");
        assert!(lmf_self()
            .read()
            .unwrap()
            .amf_subscription_get(&amf.amf.subscription_key(other))
            .is_none());
        amf.server.stop().await.ok();
    }

    /// #1518 (R8 M2): a subscribe whose caller is cancelled mid-create (its
    /// DetermineLocation consumer disconnected) does not hold its in-flight entry
    /// for ever. #1877: the create now finishes on its own task, so against an AMF
    /// that never answers the entry is abandoned when the create's own bounded
    /// request gives up (not at the cancel), and then the key can be subscribed
    /// again. Both the UE and the non-UE paths.
    ///
    /// REVERT-VERIFIED: with `InFlightCreate`'s drop not abandoning, the key stays
    /// in flight after the create gives up and a fresh start is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_subscribe_leaves_nothing_in_flight_1518() {
        // #1884: the subscribe goes to a loopback plaintext AMF, i.e. a dev
        // deployment. Without the override it relied on a sibling having set it.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // Plaintext loopback AMF: under the default production profile the
        // client fails at once for want of TLS material and the task finishes
        // before it can be cancelled, so this test passed only after a sibling
        // had set `dev` (found running it alone under #1865).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        lmf_context_init(1024);
        lmf_self()
            .read()
            .unwrap()
            .set_callback_base("http://127.0.0.1:7816");

        // An AMF that accepts the connection and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let amf = amf_at(port);
        let ue = "imsi-001010000015188";

        // By key: other modules' tests share the store without this lock.
        let held = |key: &str| lmf_self().read().unwrap().amf_subscription_holds(key);
        // The create's own bound (client connect 2 s + request 3 s), with margin.
        let gave_up = |key: String| async move {
            for _ in 0..80 {
                if !lmf_self().read().unwrap().amf_subscription_holds(&key) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        let in_flight = |key: String| async move {
            for _ in 0..100 {
                if lmf_self().read().unwrap().amf_subscription_holds(&key) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("{key} never went in flight");
        };

        let ue_amf = amf.clone();
        let task = tokio::spawn(async move {
            namf_client::ensure_n1n2_subscription(&ue_amf, ue).await;
        });
        in_flight(amf.subscription_key(ue)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        gave_up(amf.subscription_key(ue)).await;
        assert!(
            !held(&amf.subscription_key(ue)),
            "abandoned once the create gives up"
        );
        assert!(
            lmf_self()
                .read()
                .unwrap()
                .amf_subscription_begin(&amf.subscription_key(ue), &amf, Some(ue))
                .is_some(),
            "the UE can be subscribed again"
        );
        lmf_self()
            .read()
            .unwrap()
            .amf_subscription_forget(&amf.subscription_key(ue));

        let non_ue_amf = amf.clone();
        let task = tokio::spawn(async move {
            namf_client::ensure_non_ue_nrppa_subscription(&non_ue_amf, "lmf-1518").await;
        });
        in_flight(amf.non_ue_subscription_key()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        gave_up(amf.non_ue_subscription_key()).await;
        assert!(
            !held(&amf.non_ue_subscription_key()),
            "abandoned once the create gives up"
        );

        hold.abort();
        lmf_context_final();
    }
}

/// #1665: the outbound OAuth2 client follows the SBI security profile.
#[cfg(test)]
mod outbound_oauth2_1665_tests {
    use nextgcore_sbi::security::SbiProfile;
    use nextgcore_sbi::types::NfType;

    const NRF: &str = "http://127.0.0.10:7777";

    /// Under the `production` profile this LMF installs its token client with
    /// the `sbi.oauth2.require` knob off, so its service requests to the AMF, AUSF,
    /// SMF and UDM (which require a bearer under that profile, #63) carry one
    /// (TS 33.501 §13.4.1.1.2). Before #1665 it installed it only under the knob.
    #[test]
    fn the_production_profile_installs_the_outbound_oauth2_client_without_the_knob() {
        let oauth2 = super::outbound_oauth2_client(SbiProfile::Production, false, Some(NRF))
            .expect("production profile, knob off: the outbound OAuth2 client is installed");
        assert_eq!(oauth2.self_consumer().nf_type, NfType::Lmf);
        assert_eq!(oauth2.nrf_uri(), NRF);
        assert!(
            super::outbound_oauth2_client(SbiProfile::Dev, true, Some(NRF)).is_some(),
            "dev profile, knob on: the client is installed"
        );
        assert!(
            super::outbound_oauth2_client(SbiProfile::Dev, false, Some(NRF)).is_none(),
            "dev profile, knob off: no client, the token-free path is unchanged"
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
            let profile = build_lmf_nf_profile("lmf-1791", "10.0.0.1", 7777, cfg.scheme);
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
    /// production half serves cleartext and the helper fails naming LMF.
    #[test]
    fn the_listener_follows_the_sbi_profile_1795() {
        nextgcore_sbi::test_support::assert_listener_follows_sbi_profile(
            nextgcore_sbi::types::NfType::Lmf,
            super::sbi_listener_config,
        );
    }
}
