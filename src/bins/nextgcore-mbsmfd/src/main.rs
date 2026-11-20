//! NextGCore MB-SMF (Multicast/Broadcast Session Management Function)
//!
//! The MB-SMF is a 5G core network function responsible for (TS 23.247):
//! - MBS session management (create, update, release)
//! - Multicast transport resource management via N4mb PFCP
//! - MBS QoS flow management
//! - TMGI-based session identification and group membership tracking
//! - Interaction with SMF for unicast-to-multicast switching

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::constants::content_type::APPLICATION_NGAP;
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiPart, SbiRequest, SbiResponse};
use nextgcore_sbi::owner_binding;
use nextgcore_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
mod lane; // #1854: one ContextCreate/ContextDelete at a time per (AMF, TMGI)
mod n2_mbs_transfer; // #417: the N2 MBS SM transfers, on the generated NGAP codec
mod n4mb;
mod namf_client;
mod reconcile; // #1817: ContextDeletes that outlived their retry budget
mod subscription;
mod types;

// G1-3: strict-peer round-trip integration test (conformant AMF-side client
// harness vs the live mbsmfd ContextUpdate handler). In-crate because mbsmfd
// is bin-only; request construction stays independent of `crate::types`.
#[cfg(test)]
mod strict_peer_test;

pub use context::*;

/// NextGCore MB-SMF - Multicast/Broadcast Session Management Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-mbsmfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Multicast/Broadcast Session Management Function (TS 23.247)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/mbsmf.yaml")]
    config: String,

    /// Log file path
    #[arg(short = 'l', long)]
    log_file: Option<String>,

    /// Log level (trace, debug, info, warn, error). Without it, the config
    /// file's `logger.level`, else `info`; `RUST_LOG` overrides (#691).
    #[arg(short = 'e', long)]
    log_level: Option<String>,

    /// Disable color output
    #[arg(short = 'm', long)]
    no_color: bool,

    /// SBI server address
    /// Without it, `mbsmf.sbi.server[0].address` from the config file, else
    /// 127.0.0.1 (#1308, #1312). The port likewise defaults to the file, else 7812.
    #[arg(long)]
    sbi_addr: Option<String>,

    /// The SBI host advertised in the NRF NFProfile and callback URIs. Without it,
    /// `NEXTGCORE_SBI_ADVERTISE`, else `mbsmf.sbi.server[0].advertise`, else the
    /// bind address; a wildcard is never advertised (#1312).
    #[arg(long)]
    sbi_advertise: Option<String>,

    /// SBI server port
    #[arg(long)]
    sbi_port: Option<u16>,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate file
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key file
    #[arg(long)]
    tls_key: Option<String>,

    /// Maximum MBS sessions
    #[arg(long, default_value = "256")]
    max_sessions: usize,

    /// NRF URI for registration
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,
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
// `mbsmf.sbi.oauth2.require: true` yaml knob. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The installed outbound OAuth2 client, if any (Wave-6 H8 Phase A, #1662).
pub(crate) fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    #[cfg(test)]
    if let Ok(oauth2) = TEST_OAUTH2_CLIENT.try_with(Arc::clone) {
        return Some(oauth2);
    }
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

#[cfg(test)]
tokio::task_local! {
    /// #1662 tests: the OAuth2 client [`oauth2_client`] returns inside
    /// `TEST_OAUTH2_CLIENT.scope(..)`. Task-local, so the other tests in the
    /// process keep the default (none installed).
    pub(crate) static TEST_OAUTH2_CLIENT: Arc<nextgcore_sbi::oauth::OAuth2Client>;
}

/// #1758: spawn `fut` on its own task, so dropping the caller (a consumer request
/// whose client went away) does not drop it. Under test the task-local OAuth2
/// client is carried into the task, as the caller would have seen it.
pub(crate) fn spawn_detached<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
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

/// #1662: `client` with the installed OAuth2 client attached, so a service
/// request to the `target` producer carries an NRF-issued token (TS 33.501
/// §13.4.1.1.2, TS 29.500 §6.7.3). Unchanged when no client is installed.
/// Notifications do not go through this: they carry no token.
pub(crate) fn attach_oauth2(
    client: nextgcore_sbi::client::SbiClient,
    target: nextgcore_sbi::types::NfType,
) -> nextgcore_sbi::client::SbiClient {
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
    }
}

/// #1665: the outbound OAuth2 client this MBSMF installs at startup: under the
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
        nextgcore_sbi::types::NfType::Mbsmf,
    )
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
/// NRF JWKS and requires `aud` to include NfType::Mbsmf; with no NRF URI it
/// fails closed (503). `nrf_uri` empty ⇒ unconfigured ⇒ fail-closed.
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
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Mbsmf);
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

/// #1795: the MB-SMF's SBI listener under the SBI security profile. Under
/// `production`: TLS from `policy`'s certificate paths (whatever `--tls` or the
/// config file said), the client certificate verified against its CA, and an
/// access token required, with MB-SMF as the audience and the NRF's JWKS unless
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
        nextgcore_sbi::types::NfType::Mbsmf,
        nrf_uri,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // #1312: the command line, else `mbsmf.sbi.server[0]` in the config file,
    // else loopback.
    let sbi = nextgcore_core::sockaddr::SbiEndpoint::resolve_from_file(
        args.sbi_addr.as_deref(),
        args.sbi_port,
        args.sbi_advertise.as_deref(),
        &args.config,
        "mbsmf",
        7812,
    )
    .map_err(|e| anyhow::anyhow!("SBI listen address: {e}"))?;
    let (sbi_addr, sbi_port) = (sbi.host.clone(), sbi.port);

    init_logging(&nextgcore_core::log::nf_log_level(
        args.log_level.as_deref(),
        Some(&args.config),
    ));
    // #1004 review: an unset clock makes a wrong PFCP Recovery Time Stamp.
    nextgcore_pfcp::recovery_time::check_local_clock().map_err(|e| anyhow::anyhow!(e))?;
    // #2115: the TMGI PLMN, refused at start-up rather than allocated from.
    check_plmn_env(
        std::env::var("MBSMF_PLMN_MCC").ok().as_deref(),
        std::env::var("MBSMF_PLMN_MNC").ok().as_deref(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore MB-SMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Multicast/Broadcast Session Management Function (3GPP TS 23.247)");

    // Initialize context
    mbsmf_context_init(args.max_sessions);

    let nf_instance_id =
        nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Mbsmf)
            .to_string();

    // Setup shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    // Start SBI server
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
        log::info!("TLS enabled: cert={cert}, key={key}");
    }
    let require_oauth2 = oauth2_required(&args.config);
    // #1665: the outbound token client follows the SBI security profile as well
    // as the knob. The production profile's AMF/AUSF/SMF/UDM demand a token on
    // every service request (TS 33.501 §13.4.1.1.2), whatever this listener asks.
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    warn_ignored_debug_routes(sbi_profile);
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
    // #1796: the AMF's ContextStatusNotify comes back to the advertised address.
    if let Ok(context) = mbsmf_self().read() {
        context.set_amf_notify_base(format!(
            "{}://{}",
            sbi_scheme,
            nextgcore_sbi::uri_encode::uri_authority(
                sbi.advertise.as_deref().unwrap_or("127.0.0.1"),
                sbi_port
            )
        ));
    }

    log::info!("Starting MB-SMF SBI server on {addr}");

    sbi_server
        .start(mbsmf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    let scheme = if args.tls { "HTTPS" } else { "HTTP" };
    log::info!("SBI HTTP/2 {scheme} server listening on {addr}");

    // Register with NRF
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    // #1482: a failed attempt is retried in the background, and the heartbeat
    // starts after the one that succeeds.
    match sbi.registration_host() {
        Ok(host) => {
            let (host, id) = (host.to_string(), nf_instance_id.clone());
            nextgcore_sbi::heartbeat::register_or_retry(
                "MB-SMF",
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
                    // (active MBS sessions, saturated at 100; TS 29.510 §5.2.2.3.2).
                    // Honest session-count proxy — no fabricated CPU numbers.
                    nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                        nf_instance_id,
                        5,
                        || {
                            let load = mbsmf_self().read().map(|c| c.session_count()).unwrap_or(0);
                            load.min(100) as u8
                        },
                    );
                },
            )
            .await;
        }
        Err(e) => log::warn!("NRF registration not attempted (will operate without NRF): {e}"),
    }

    // #1817: retry the ContextDeletes that outlived their retry budget.
    let _reconciler = reconcile::spawn_reconciler();

    // #1817: the Prometheus endpoint (the reconciler's gauge and counter beside the
    // common families), on NEXTGCORE_METRICS_BIND (loopback by default) and
    // MBSMF_METRICS_PORT (9090). Non-fatal, like every NF's.
    let _metrics = nextgcore_metrics::nf::serve_nf_metrics(
        "MB-SMF",
        "MBSMF_METRICS_PORT",
        Arc::new(render_prometheus),
    )
    .await;

    log::info!("NextGCore MB-SMF ready (instance: {nf_instance_id})");

    // Main event loop.
    //
    // #76: also drains the N4mb Session Report queue. The recv loop answers each
    // report on the wire immediately; this applies the consequence (activating a
    // deactivated multicast session on downlink data arrival, TS 23.247 §7.2.5.2)
    // where the session state lives, so the socket loop never takes the context
    // lock. 100ms is the loop's existing tick, and a report already answered is not
    // time-critical to apply.
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        apply_n4mb_reports().await;
    }

    // Graceful shutdown
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
    log::info!("SBI HTTP/2 server stopped");

    mbsmf_context_final();
    log::info!("MB-SMF shutdown complete");

    Ok(())
}

/// MB-SMF SBI request handler
async fn mbsmf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!(
        "MB-SMF SBI: {method} {uri}",
        uri = nextgcore_sbi::log_redact::redact_callback_tokens(uri)
    );

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // MBS Session Management (Nmbsmf_MBSSession)
        ["nmbsmf-mbssession", "v1", "mbs-sessions"] => match method {
            "POST" => handle_mbs_session_create(&request).await,
            "GET" => handle_mbs_session_list().await,
            _ => send_method_not_allowed(method, "mbs-sessions"),
        },
        // ContextUpdate — start/terminate MBS data reception (TS 29.532 §5.3.2.5).
        // [mbsmfd-03] Must precede the `{session_id}` arm (longer path wins).
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "contexts", "update"] => match method {
            "POST" => handle_mbs_session_context_update(&request).await,
            _ => send_method_not_allowed(method, "mbs-sessions/contexts/update"),
        },
        // ContextStatus subscriptions (TS 29.532 §5.3.2.9/10, SMF-facing). [mbsmfd-05]
        // Placed before the 4-segment `{session_id}` wildcard to avoid being shadowed.
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "contexts", "subscriptions"] => match method {
            "POST" => handle_ctx_status_subscribe(&request).await,
            _ => send_method_not_allowed(method, "mbs-sessions/contexts/subscriptions"),
        },
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "contexts", "subscriptions", sub_id] => {
            match method {
                "PATCH" => handle_ctx_status_subscribe_mod(sub_id, &request).await,
                "DELETE" => handle_ctx_status_unsubscribe(sub_id, &request).await,
                _ => send_method_not_allowed(method, "mbs-sessions/contexts/subscriptions/{id}"),
            }
        }
        // Status subscriptions (TS 29.532 §5.3.2.6/7, NEF/MBSF/AF-facing). [mbsmfd-05]
        // Placed before `{session_id}` arm so "subscriptions" isn't swallowed.
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "subscriptions"] => match method {
            "POST" => handle_status_subscribe(&request).await,
            _ => send_method_not_allowed(method, "mbs-sessions/subscriptions"),
        },
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "subscriptions", sub_id] => match method {
            "PATCH" => handle_status_subscribe_mod(sub_id, &request).await,
            "DELETE" => handle_status_unsubscribe(sub_id, &request).await,
            _ => send_method_not_allowed(method, "mbs-sessions/subscriptions/{id}"),
        },
        // Per-session document: GET / PATCH / DELETE. Must come after all
        // literal 4-segment arms above. [mbsmfd-06/08]
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id] => match method {
            "GET" => handle_mbs_session_get(session_id).await,
            "PATCH" => handle_mbs_session_update(session_id, &request).await,
            "DELETE" => handle_mbs_session_release(session_id, &request).await,
            _ => send_method_not_allowed(method, "mbs-sessions/{id}"),
        },
        // #1796: the AMF's Namf_MBSBroadcast ContextStatusNotify to the notifyUri
        // this MB-SMF minted for a ContextCreate.
        ["nmbsmf-mbssession", "v1", "amf-context-status", token] => match method {
            "POST" => handle_amf_context_status_notify(token, &request).await,
            _ => send_method_not_allowed(method, "amf-context-status/{token}"),
        },
        // Nmbsmf_TMGI service (TS 29.532 §5.2, TS29532_Nmbsmf_TMGI.yaml). [mbsmfd-04]
        ["nmbsmf-tmgi", "v1", "tmgi"] => match method {
            "POST" => handle_tmgi_allocate(&request).await,
            "DELETE" => handle_tmgi_deallocate(&request).await,
            _ => send_method_not_allowed(method, "tmgi"),
        },
        // --- Non-spec debug routes (mbsmfd-10): only when MBSMF_DEBUG_ROUTES is
        // set. The N4mb activation that `/activate` used to drive is now folded
        // into the ContextUpdate Start path; group membership is internal
        // MBS-session-context state, not an SBI sub-resource.
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "activate"]
            if debug_routes_enabled() =>
        {
            match method {
                "POST" => handle_mbs_session_activate(session_id, &request).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}/activate"),
            }
        }
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "members"]
            if debug_routes_enabled() =>
        {
            match method {
                "POST" => handle_member_join(session_id, &request).await,
                "GET" => handle_member_list(session_id).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}/members"),
            }
        }
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "members", supi]
            if debug_routes_enabled() =>
        {
            match method {
                "DELETE" => handle_member_leave(session_id, supi, &request).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}/members/{supi}"),
            }
        }
        _ => {
            log::debug!("Unknown path: {path}");
            send_not_found(&format!("Resource not found: {path}"), None)
        }
    }
}

/// Whether the non-spec debug routes (`/activate`, `/members*`) are exposed.
/// Off by default so the SBI surface is exactly the TS 29.532 resource set;
/// enabled by setting `MBSMF_DEBUG_ROUTES` (any non-empty value). [mbsmfd-10]
///
/// #1944 (R32 on #2057): never under the `production` SBI profile. The routes
/// add any SUPI to a session and establish N4mb towards a `upfAddr` the body
/// names, which no TS 29.532 operation lets a consumer do; the variable is
/// ignored there (and [`warn_ignored_debug_routes`] says so at startup).
fn debug_routes_enabled() -> bool {
    debug_routes_allowed(
        std::env::var("MBSMF_DEBUG_ROUTES").ok().as_deref(),
        nextgcore_sbi::security::SbiProfile::resolve(),
    )
}

/// [`debug_routes_enabled`] for a given variable value and SBI profile.
fn debug_routes_allowed(value: Option<&str>, profile: nextgcore_sbi::security::SbiProfile) -> bool {
    value.is_some_and(|v| !v.is_empty()) && !profile.is_production()
}

/// #1944 (R32 on #2057): a WARN at startup when `MBSMF_DEBUG_ROUTES` is set
/// under the production profile, where it is ignored.
fn warn_ignored_debug_routes(profile: nextgcore_sbi::security::SbiProfile) {
    let set = std::env::var("MBSMF_DEBUG_ROUTES").is_ok_and(|v| !v.is_empty());
    if set && profile.is_production() {
        log::warn!(
            "MBSMF_DEBUG_ROUTES is set but ignored: the debug routes (/activate, /members) are \
             never served under the production SBI profile (#1944)"
        );
    }
}

/// Parse session pool ID from string like "mbs-sess-123"
fn parse_session_id(session_id: &str) -> Option<u64> {
    session_id
        .strip_prefix("mbs-sess-")
        .and_then(|s| s.parse::<u64>().ok())
}

/// Build an internal [`context::Tmgi`] from a spec [`types::Tmgi`], or a default
/// `010203` TMGI in PLMN 001/01 when the request carries no TMGI (e.g. a
/// multicast create where the MB-SMF would allocate one).
fn context_tmgi_from(spec: Option<&types::Tmgi>) -> Tmgi {
    match spec {
        Some(t) => Tmgi {
            mbs_service_id: t.service_id_bytes(),
            plmn_id: PlmnId {
                mcc: t.plmn_id.mcc.clone(),
                mnc: t.plmn_id.mnc.clone(),
            },
        },
        None => Tmgi {
            mbs_service_id: [0x01, 0x02, 0x03],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        },
    }
}

/// Render an internal [`context::Tmgi`] as a spec [`types::Tmgi`] for response
/// bodies (6 hex-digit `mbsServiceId`).
fn spec_tmgi_from(tmgi: &Tmgi) -> types::Tmgi {
    types::Tmgi {
        mbs_service_id: hex::encode(tmgi.mbs_service_id),
        plmn_id: types::PlmnId {
            mcc: tmgi.plmn_id.mcc.clone(),
            mnc: tmgi.plmn_id.mnc.clone(),
        },
    }
}

/// Handle MBS Session Create (TS 29.532 §5.3.2.2, CreateReqData/CreateRspData)
async fn handle_mbs_session_create(request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Create");
    // #1863: the session is bound to the consumer's verified identity, refused
    // before anything is read or allocated.
    let owner =
        match nextgcore_sbi::owner_binding::owner_for_new_resource(request, "MBS Session Create") {
            Ok(owner) => owner,
            Err(refused) => return *refused,
        };

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // mbsmfd-06: parse the spec CreateReqData{ mbsSession: ExtMbsSession }.
    let req: types::CreateReqData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(&format!("Invalid CreateReqData: {e}"), Some("INVALID_JSON"))
        }
    };

    // #76: `serviceType` is REQUIRED in TS 29.571's `MbsSession`. It used to be
    // defaulted (`_ => Multicast`), so a request omitting a mandatory IE was
    // accepted and silently became a multicast session — the create then succeeded
    // and the consumer never learned its request was incomplete.
    let session_type = match req.mbs_session.service_type {
        Some(types::MbsServiceType::Broadcast) => MbsSessionType::Broadcast,
        Some(types::MbsServiceType::Multicast) => MbsSessionType::Multicast,
        None => {
            return send_bad_request(
                "mbsSession.serviceType is mandatory (TS 29.571 MbsSession)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let ctx = mbsmf_self();

    // #76: resolve the TMGI. TS 29.571 makes `MbsSession` `anyOf [mbsSessionId,
    // tmgiAllocReq]`, so a create either NAMES its session or ASKS for a TMGI.
    //
    // The no-TMGI path used to return a HARDCODED TMGI (`mbsServiceId
    // [0x01,0x02,0x03]`, PLMN 001/01) from `context_tmgi_from`, so every such create
    // collided with every other one — and `session_add` overwrote `tmgi_hash`
    // silently, orphaning the earlier session. It now allocates from the same
    // `TmgiPool` the Nmbsmf TMGI service uses, so two such creates get two sessions.
    let spec_tmgi = req
        .mbs_session
        .mbs_session_id
        .as_ref()
        .and_then(|id| id.tmgi.as_ref());
    let tmgi = match spec_tmgi {
        Some(t) => {
            let tmgi = context_tmgi_from(Some(t));
            // #1863: a TMGI this MB-SMF allocated to another consumer cannot
            // name this consumer's session.
            let allocation = ctx.read().ok().and_then(|c| c.tmgi_allocation(&tmgi));
            if let Some(allocated_to) = allocation {
                if !may_manage(allocated_to.as_deref(), request) {
                    return tmgi_not_owned("MBS Session Create", &tmgi);
                }
            }
            tmgi
        }
        None => {
            // No TMGI: allocate one. TS 29.571's `MbsSession` is
            // `anyOf [mbsSessionId, tmgiAllocReq]`, and that `anyOf` is deliberately
            // NOT enforced here -- #76's criterion 7 requires a create carrying no
            // TMGI to SUCCEED by allocating from the pool, so refusing an absent
            // `tmgiAllocReq` would contradict it. An absent flag is therefore read as
            // an implicit request, which is the reading that makes both the criterion
            // and the schema's intent satisfiable. Stated rather than silent: a
            // conformance suite exercising the `anyOf` will see it accepted.
            let allocated = ctx.read().ok().and_then(|c| {
                let (tmgis, _expiry) = c.tmgi_allocate_owned(
                    &default_plmn(),
                    1,
                    context::TMGI_DEFAULT_TTL_SECS,
                    owner.as_deref(),
                );
                tmgis.into_iter().next()
            });
            match allocated {
                Some(t) => t,
                None => {
                    return nextgcore_sbi::server::send_error(
                        507,
                        "Insufficient Storage",
                        "No TMGI could be allocated for this MBS session",
                        Some("TMGI_POOL_EXHAUSTED"),
                    )
                }
            }
        }
    };

    let session = match ctx.read() {
        // #1863 (R32 on #1943): the TMGI is claimed for this consumer under the
        // same locks as the add; one allocated to another consumer in the
        // meantime is refused here too.
        Ok(context) => match context.session_add_claiming(tmgi.clone(), session_type, owner, |o| {
            may_manage(o, request)
        }) {
            Ok(session) => session,
            Err(context::TmgiRefusal::NotOwned(t)) => {
                return tmgi_not_owned("MBS Session Create", &t);
            }
        },
        Err(_) => None,
    };

    match session {
        Some(mut session) => {
            let session_id = format!("mbs-sess-{}", session.id);
            log::info!("MBS Session created: {session_id} (type={session_type:?})");

            // #76: remember the SSM the consumer identified this session with, so an
            // SSM-identified ContextUpdate can resolve it. `MbsSessionId` is
            // `anyOf(tmgi, ssm)`, and the SSM form used to be unresolvable at all.
            if let Some(ssm) = req
                .mbs_session
                .mbs_session_id
                .as_ref()
                .and_then(|id| id.ssm.as_ref())
                .or(req.mbs_session.ssm.as_ref())
            {
                session.ssm = Some(ssm.clone());
                if let Ok(context) = ctx.read() {
                    context.session_update(&session);
                }
            }

            // #75: discover the serving AMF and create the MBS context on it
            // (TS 23.247 §7.3.1 step 2). This handler used to terminate at
            // `session_add`, so no AMF interaction happened at all and the N2 MBS
            // SM containers this MB-SMF builds were never carried to the RAN.
            //
            // Deliberately AFTER the local session exists and does NOT fail the
            // create: the MBS session is the MB-SMF's own resource and TS 29.532
            // defines no failure cause for "the AMF leg did not complete". A
            // failure is logged and the RAN simply does not have the session,
            // which the log names rather than hides.
            //
            // #1758: the create and its record run on their own task, so a consumer
            // that disconnects mid-ContextCreate cannot leave an AMF context no
            // release will ever delete; see [`create_amf_mbs_context`].
            // #1796: see [`amf_leg_for`].
            let amf_leg = amf_leg_for(
                session_type,
                req.mbs_session.mbs_service_area.clone(),
                body,
                &session,
            );
            if amf_leg.is_none() && session_type == MbsSessionType::Broadcast {
                log::warn!(
                    "MBS session {session_id}: a broadcast session without an mbsServiceArea \
                     has no NG-RAN to set up; no AMF ContextCreate"
                );
            }
            match amf_leg {
                None => {}
                Some(leg) => match namf_client::discover_amf().await {
                    Some(amf) => match spawn_detached(create_amf_mbs_context(
                        session.id,
                        session.tmgi.clone(),
                        amf.clone(),
                        leg,
                    ))
                    .await
                    .ok()
                    .flatten()
                    {
                        Some(context_ref) => log::info!(
                            "MBS session {session_id}: AMF {}:{} created MBS context {context_ref}",
                            amf.host,
                            amf.port
                        ),
                        None => log::warn!(
                            "MBS session {session_id}: AMF {}:{} did not create an MBS context; \
                             the RAN does not have this session",
                            amf.host,
                            amf.port
                        ),
                    },
                    None => log::warn!(
                        "MBS session {session_id}: no serving AMF discovered (NRF unconfigured, \
                         unreachable, or no AMF advertises namf-mbs-bc); the RAN does not have \
                         this session"
                    ),
                },
            }

            // mbsmfd-06: respond with CreateRspData{ mbsSession }.
            let rsp = types::CreateRspData {
                mbs_session: types::ExtMbsSession {
                    mbs_session_id: Some(types::MbsSessionId {
                        tmgi: Some(spec_tmgi_from(&session.tmgi)),
                        // #76: an SSM-identified create gets its SSM back, so the
                        // consumer can address the session the way it named it.
                        ssm: req
                            .mbs_session
                            .mbs_session_id
                            .as_ref()
                            .and_then(|id| id.ssm.clone()),
                    }),
                    service_type: Some(match session_type {
                        MbsSessionType::Broadcast => types::MbsServiceType::Broadcast,
                        MbsSessionType::Multicast => types::MbsServiceType::Multicast,
                    }),
                    // #76: a structured TS 29.571 `TunnelAddress` ARRAY, not the hex
                    // TEID string this used to emit. `ingressTunAddr` is readOnly and
                    // `minItems: 1`, and it is the one member a consumer needs in
                    // order to send traffic anywhere.
                    ingress_tun_addr: Some(vec![types::TunnelAddress {
                        // The MB-SMF's own transport address and the GTP-U port
                        // (TS 29.281): where the content provider sends ingress
                        // traffic for this session.
                        ipv4_addr: Some(std::net::Ipv4Addr::from(configured_cp_addr()).to_string()),
                        ipv6_addr: None,
                        port_number: 2152,
                    }]),
                    // The write-only members are echoed so a consumer can confirm
                    // what the MB-SMF stored rather than assume it.
                    ssm: req.mbs_session.ssm.clone(),
                    mbs_service_area: req.mbs_session.mbs_service_area.clone(),
                    mbs_serv_info: req.mbs_session.mbs_serv_info.clone(),
                    mbs_security_context: req.mbs_session.mbs_security_context.clone(),
                    contact_pcf_ind: req.mbs_session.contact_pcf_ind,
                    area_session_policy_id: req.mbs_session.area_session_policy_id,
                    activity_status: None,
                    tmgi_alloc_req: None,
                    ingress_tun_addr_req: None,
                },
            };

            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nmbsmf-mbssession/v1/mbs-sessions/{session_id}"),
                )
                .with_json_body(&rsp)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request("Failed to create MBS session", Some("CREATION_FAILED")),
    }
}

/// Handle MBS Session List - now returns real session data
async fn handle_mbs_session_list() -> SbiResponse {
    log::debug!("MBS Session List");

    let ctx = mbsmf_self();
    let sessions: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context
            .all_sessions()
            .iter()
            .map(|s| {
                let has_n4mb = s.n4mb_session.is_some();
                serde_json::json!({
                    "mbsSessionId": format!("mbs-sess-{}", s.id),
                    "mbsSessionType": format!("{:?}", s.session_type).to_uppercase(),
                    "mbsSessionStatus": format!("{:?}", s.state).to_uppercase(),
                    "joinedUeCount": s.joined_ue_count,
                    "gtpTeid": format!("{:#010x}", s.gtp_teid),
                    "n4mbEstablished": has_n4mb,
                })
            })
            .collect()
    } else {
        vec![]
    };

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"mbsSessions": sessions}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle MBS Session Get
async fn handle_mbs_session_get(session_id: &str) -> SbiResponse {
    log::debug!("MBS Session Get: {session_id}");

    let pool_id = parse_session_id(session_id);

    let ctx = mbsmf_self();
    let session = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.session_find_by_id(id)
        } else {
            None
        }
    });

    match session {
        Some(session) => {
            let n4mb_info = session.n4mb_session.as_ref().map(|n| {
                serde_json::json!({
                    "localSeid": n.local_seid,
                    "remoteSeid": n.remote_seid,
                    "upfAddr": n.upf_addr.to_string(),
                    "state": format!("{:?}", n.state),
                    "dlTeid": format!("{:#010x}", n.dl_teid),
                    "gnbEndpoints": n.gnb_teids.len(),
                })
            });

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "mbsSessionType": format!("{:?}", session.session_type).to_uppercase(),
                    "mbsSessionStatus": format!("{:?}", session.state).to_uppercase(),
                    "joinedUeCount": session.joined_ue_count,
                    "gtpTeid": format!("{:#010x}", session.gtp_teid),
                    "n4mbSession": n4mb_info,
                    "groupMembers": session.group_members.len(),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// Handle MBS Session Update (TS 29.532 §5.3.2.3, PATCH with PatchData)
///
/// Parses the spec `PatchData` (RFC 6902 `PatchItem` array) and applies the
/// modifiable attributes. Returns 204 No Content on success, or 200 with
/// `redMbsServArea` when the MBS service area is reduced.
async fn handle_mbs_session_update(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Update: {session_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // mbsmfd-08: parse the spec PatchData (array of PatchItem).
    let patch: types::PatchData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(&format!("Invalid PatchData: {e}"), Some("INVALID_JSON"))
        }
    };

    let pool_id = parse_session_id(session_id);

    let ctx = mbsmf_self();
    let session = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.session_find_by_id(id)
        } else {
            None
        }
    });

    // #1863: only the consumer that created the session, before any change.
    if let Some(refused) = session.as_ref().and_then(|s| {
        nextgcore_sbi::owner_binding::refuse_non_owner(
            s.owner.as_deref(),
            request,
            "MBS Session Update",
        )
    }) {
        return refused;
    }

    match session {
        Some(mut session) => {
            // #76: `activityStatus`, `mbsServInfo` (QoS) and `mbsSecurityContext`
            // used to be silently ignored, so a PATCH activating a session answered
            // 204 and changed nothing. They are collected here and persisted below.
            let mut changes = types::PatchChanges::default();
            let outcome =
                types::apply_patch_data(&patch, &mut session.service_area_tacs, &mut changes);

            // TS 23.247 §7.2.5: `activityStatus` drives whether distribution is
            // active. Applied to the session state so a subsequent GET and the N4mb
            // driver both see it, rather than being acknowledged and dropped.
            if let Some(ref status) = changes.activity_status {
                session.state = match status.as_str() {
                    "ACTIVE" => MbsSessionState::Active,
                    "INACTIVE" => MbsSessionState::Suspended,
                    other => {
                        log::warn!(
                            "MBS session {session_id} PATCH: unrecognised activityStatus \
                             '{other}'; state left unchanged"
                        );
                        session.state
                    }
                };
            }
            // The QoS request: 5QI and maximum bit rate, when the patch names them.
            if let Some(ref info) = changes.mbs_serv_info {
                if let Some(five_qi) = info
                    .pointer("/mbsQoSReq/5qi")
                    .or_else(|| info.get("5qi"))
                    .and_then(serde_json::Value::as_u64)
                {
                    session.fiveqi = five_qi as u8;
                }
                if let Some(mbr) = info
                    .pointer("/mbsQoSReq/mbrDl")
                    .or_else(|| info.get("mbrDl"))
                    .and_then(serde_json::Value::as_u64)
                {
                    session.max_bitrate = mbr;
                }
            }

            if let Ok(context) = ctx.read() {
                context.session_update(&session);
            }

            match outcome {
                // Service area reduced -> 200 + redMbsServArea (TS 29.532 §5.3.2.3).
                types::PatchOutcome::ReducedArea(area) => SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({ "redMbsServArea": area }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200)),
                // Otherwise success is 204 No Content.
                types::PatchOutcome::NoContent => SbiResponse::with_status(204),
            }
        }
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// #1796: what the AMF is given for a newly created session, or `None` when no
/// AMF broadcast MBS context is to be created. Only a BROADCAST session has one
/// (Namf_MBSBroadcast is TS 23.247 §7.3's procedure; a multicast session reaches
/// the RAN through the SMF and Namf_MBSCommunication, §7.2), and only with an MBS
/// service area: without it the AMF has no NG-RAN to set up.
fn amf_leg_for(
    session_type: MbsSessionType,
    mbs_service_area: Option<serde_json::Value>,
    body: &str,
    session: &MbsSession,
) -> Option<namf_client::AmfLeg> {
    match (session_type, mbs_service_area) {
        (MbsSessionType::Broadcast, Some(area)) => Some(namf_client::AmfLeg {
            mbs_service_area: area,
            snssai: requested_snssai(body),
            qfi: session.qfi,
            five_qi: session.fiveqi,
        }),
        _ => None,
    }
}

/// #1796: the S-NSSAI of the MBS session the consumer created
/// (`mbsSession.snssai`, TS 29.571 `MbsSession`), which ContextCreate must carry
/// (TS 29.518 Table 6.5.6.2.2-1). A create that named none gets SST 1 (eMBB,
/// TS 23.501 §5.15.2.2), the standardized slice an MBS session defaults to here.
fn requested_snssai(body: &str) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("mbsSession")?.get("snssai").cloned())
        .filter(|s| {
            s.get("sst")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|v| v <= 255)
        })
        .unwrap_or_else(|| serde_json::json!({ "sst": 1 }))
}

/// #2062: a ContextStatusNotify token minted for a ContextCreate, forgotten when
/// dropped unless [`Self::commit`]ted to the context's record: a create that
/// fails, or is dropped at any await, leaves no Live token behind.
struct MintedNotifyToken(Option<String>);

impl MintedNotifyToken {
    fn new(token: String) -> Self {
        Self(Some(token))
    }

    fn as_str(&self) -> &str {
        self.0.as_deref().unwrap_or_default()
    }

    /// Hand the token to the record that now owns it; nothing is forgotten.
    fn commit(mut self) -> String {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for MintedNotifyToken {
    fn drop(&mut self) {
        if let Some(token) = self.0.take() {
            if let Ok(c) = mbsmf_self().read() {
                c.forget_amf_notify_token(&token);
            }
        }
    }
}

/// #1758: Namf_MBSBroadcast ContextCreate on `amf` for session `session_id`, and
/// its record, so the session's release can delete it. When the session was
/// released while the create was in flight (the release found nothing to delete),
/// the new context is deleted here instead, so the AMF never keeps one this MB-SMF
/// does not record.
///
/// #1796: the request carries a `notifyUri` ending in a token minted here, so the
/// AMF's ContextStatusNotify for this context is admitted; a create that did not
/// produce a context forgets it (#2062: as does one dropped mid-flight).
async fn create_amf_mbs_context(
    session_id: u64,
    tmgi: Tmgi,
    amf: namf_client::DiscoveredAmf,
    leg: namf_client::AmfLeg,
) -> Option<namf_client::MbsContextRef> {
    let (base, token) = {
        let ctx = mbsmf_self();
        let guard = ctx.read().ok()?;
        let Some(base) = guard.amf_notify_base() else {
            log::warn!(
                "MBS session {session_id}: no notifyUri base configured; no AMF ContextCreate"
            );
            return None;
        };
        (base, guard.mint_amf_notify_token(session_id)?)
    };
    // #2062: the token is Live until the create commits it to a record, and the
    // mint cap never reclaims a Live token; so a create dropped mid-flight (its
    // task aborted, the runtime shut down, a caller's timeout) must forget it, or
    // enough of them wedge the cap and every later create is refused.
    let token = MintedNotifyToken::new(token);
    // #1854: the create and its record run in the (AMF, TMGI) lane, so a delete of
    // the context a released session held on the same TMGI is either done before
    // this create (which then gets a fresh context) or sees this record and is
    // dropped. The AMF's ContextCreate is idempotent on the TMGI, so without the
    // lane this create could be handed a context an in-flight delete then removes.
    let lane = lane::enter(&amf.host, amf.port, Some(&tmgi)).await;
    // #2062: a create that fails drops `token`, which forgets it.
    let context_ref = namf_client::context_create(&amf, &tmgi, &leg, &base, token.as_str()).await?;
    let record = AmfMbsContext {
        host: amf.host,
        port: amf.port,
        nf_instance_id: amf.nf_instance_id,
        context_ref: context_ref.clone(),
        // #2062: the record owns the token from here: recorded, the session's
        // release forgets it; not recorded, the delete below does.
        notify_token: token.commit(),
        tmgi: Some(tmgi),
    };
    // #2068: from the 201 on, the AMF holds this context. Until a session's
    // record or a finished release accounts for it, dropping this create parks
    // its ContextDelete for the reconciler, so an abort cannot leave the context
    // at the AMF recorded nowhere.
    let created = CreatedAmfContext::new(record.clone());
    let recorded = mbsmf_self()
        .read()
        .map(|c| c.record_amf_context(session_id, record.clone()))
        .unwrap_or(false);
    drop(lane);
    if recorded {
        created.settle();
        return Some(context_ref);
    }
    log::warn!(
        "MBS session {session_id} was released while its ContextCreate was in flight; \
         deleting the AMF context {context_ref}"
    );
    // #2068: an abort during this delete parks it (the guard); once it returns,
    // the context is deleted, or its retries own it (and then the reconciler).
    release_amf_contexts(vec![record]).await;
    created.settle();
    None
}

/// #2068: an AMF context a ContextCreate was answered with (201), not yet
/// accounted for by a session's record or by a finished release. Dropped
/// unsettled -- the create's task aborted between the 201 and either -- it parks
/// the context's ContextDelete with [`reconcile`], which delivers it (or drops
/// it, if a live session holds the context again by then).
struct CreatedAmfContext(Option<AmfMbsContext>);

impl CreatedAmfContext {
    fn new(context: AmfMbsContext) -> Self {
        Self(Some(context))
    }

    /// A record or a finished release accounts for the context now.
    fn settle(mut self) {
        self.0 = None;
    }
}

impl Drop for CreatedAmfContext {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            log::warn!(
                "MBS: the ContextCreate that made AMF {}:{} MBS context {} was dropped \
                 before the context was recorded or released; parking its ContextDelete",
                c.host,
                c.port,
                c.context_ref
            );
            reconcile::park(vec![c]);
        }
    }
}

/// #1817: what `/metrics` serves: the families every NF shares and the reconciler's.
fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "mbsmf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    reconcile::render(&mut out);
    out
}

/// #1758: the waits before each retry of a failed ContextDelete.
#[cfg(not(test))]
const AMF_RELEASE_RETRY_DELAYS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];
#[cfg(test)]
const AMF_RELEASE_RETRY_DELAYS: [Duration; 5] = [Duration::from_millis(20); 5];

/// #1758: Namf_MBSBroadcast ContextDelete for each of `contexts`. 404 is gone. A
/// failed delete is retried on [`AMF_RELEASE_RETRY_DELAYS`] on a detached task, and
/// (#1817) parked for [`reconcile`] if every retry fails, rather than forgotten. Returns whether all
/// were released on the first attempt.
async fn release_amf_contexts(contexts: Vec<AmfMbsContext>) -> bool {
    let mut failed = Vec::new();
    for c in contexts {
        match delete_in_lane(&c).await {
            None => {}
            Some(
                outcome @ (namf_client::ContextDeleteOutcome::Deleted
                | namf_client::ContextDeleteOutcome::Gone),
            ) => {
                log::info!(
                    "MBS: AMF {}:{} released MBS context {}",
                    c.host,
                    c.port,
                    c.context_ref
                );
                retire_amf_notify_token(&c, outcome);
            }
            Some(namf_client::ContextDeleteOutcome::Failed) => failed.push(c),
        }
    }
    if failed.is_empty() {
        return true;
    }
    release_retries(failed);
    false
}

/// #1854: one ContextDelete of `c` in its (AMF, TMGI) lane: `None`, not sent, when a
/// live session holds the context again (a session reusing the TMGI was handed the
/// same `mbsContextRef`, R24), checked inside the lane so no create for the TMGI
/// can record it between the check and the send.
pub(crate) async fn delete_in_lane(c: &AmfMbsContext) -> Option<namf_client::ContextDeleteOutcome> {
    let _lane = lane::enter(&c.host, c.port, c.tmgi.as_ref()).await;
    if mbsmf_self()
        .read()
        .is_ok_and(|ctx| ctx.amf_context_in_use(c))
    {
        // #1930: its notify tokens went to the session that holds the context now
        // (`record_amf_context`), and go with the context's own release.
        log::info!(
            "MBS: AMF {}:{} MBS context {} is in use again; its ContextDelete is dropped",
            c.host,
            c.port,
            c.context_ref
        );
        return None;
    }
    Some(namf_client::context_delete(c).await)
}

/// The fast retries of [`release_amf_contexts`] (#1758), on a detached task; then
/// (#1817) the reconciler.
///
/// #2075: the contexts not yet delivered are held in an [`UndeliveredDeletes`]
/// for the whole task, the one in flight included, so an abort (between retries
/// or mid-delete) parks them with the reconciler instead of losing them.
pub(crate) fn release_retries(failed: Vec<AmfMbsContext>) -> tokio::task::JoinHandle<()> {
    spawn_detached(async move {
        let mut undelivered = UndeliveredDeletes(failed);
        for delay in AMF_RELEASE_RETRY_DELAYS {
            tokio::time::sleep(delay).await;
            let mut i = 0;
            while let Some(c) = undelivered.0.get(i).cloned() {
                // R24, #1854: in its lane, and not when a session reusing the TMGI
                // got this same context back. #2075: it stays held until the
                // outcome is known.
                match delete_in_lane(&c).await {
                    Some(namf_client::ContextDeleteOutcome::Failed) => i += 1,
                    None => {
                        undelivered.0.remove(i);
                    }
                    Some(outcome) => {
                        undelivered.0.remove(i);
                        retire_amf_notify_token(&c, outcome);
                    }
                }
            }
            if undelivered.0.is_empty() {
                return;
            }
        }
        let failed = std::mem::take(&mut undelivered.0);
        for c in &failed {
            log::error!(
                "MBS: AMF {}:{} MBS context {} could not be released after {} retries; \
                 handing it to the reconciler",
                c.host,
                c.port,
                c.context_ref,
                AMF_RELEASE_RETRY_DELAYS.len()
            );
        }
        // #1817: not dropped. The reconciler keeps retrying until the AMF answers.
        // #1985: its notify tokens are kept: the context still exists at the AMF,
        // and a session that reuses it is notified on them. They go with the
        // context's end: the reconciler's 204 (after the grace) or 404, a
        // `releasedInd`, the reconciler's eviction or expiry, or (#2015) the
        // pending-token bound; never the token cap's reclaim, which takes only
        // contexts the AMF released.
        reconcile::park(failed);
    })
}

/// #2075: the ContextDeletes a [`release_retries`] task has not delivered yet.
/// Dropped non-empty -- the task aborted -- they are parked with [`reconcile`]
/// (which drops any a live session holds again), as the task would have done
/// after its last retry. A delete in flight at the abort may have reached the
/// AMF; the reconciler's resend is then a 404, which ends it.
struct UndeliveredDeletes(Vec<AmfMbsContext>);

impl Drop for UndeliveredDeletes {
    fn drop(&mut self) {
        if self.0.is_empty() {
            return;
        }
        log::warn!(
            "MBS: the ContextDelete retries for {} AMF MBS context(s) were dropped; \
             parking them",
            self.0.len()
        );
        reconcile::park(std::mem::take(&mut self.0));
    }
}

/// #1796 (R29): how long a released AMF context's notify token is still admitted
/// after the AMF's 204. The AMF reports a Release Response Transfer that arrives
/// after its ContextDelete answered, and the NG-RANs it could not reach, until its
/// own release timeout (amfd `RELEASE_RESPONSE_TIMEOUT`, 10 s) -- so this outlasts it.
#[cfg(not(test))]
const AMF_NOTIFY_GRACE: Duration = Duration::from_secs(15);
#[cfg(test)]
const AMF_NOTIFY_GRACE: Duration = Duration::from_millis(200);

/// #1796: retire the notify token of a context the AMF released. On a 204 the
/// AMF may still notify the release's late NG-RAN answers, so the token stays
/// admitted for [`AMF_NOTIFY_GRACE`]; on a 404 the AMF holds nothing and it goes now.
fn retire_amf_notify_token(c: &AmfMbsContext, outcome: namf_client::ContextDeleteOutcome) {
    if outcome != namf_client::ContextDeleteOutcome::Deleted {
        forget_amf_notify_token(c);
        return;
    }
    // #2015: in its grace only, so the token cap may reclaim it.
    if let Ok(ctx) = mbsmf_self().read() {
        ctx.mark_amf_context_released(c);
    }
    let c = c.clone();
    // Detached: the forget must outlive the release that scheduled it.
    drop(spawn_detached(async move {
        tokio::time::sleep(AMF_NOTIFY_GRACE).await;
        forget_amf_notify_token(&c);
    }));
}

/// #1796: the AMF context `c` is released (or given up on): its
/// ContextStatusNotify tokens are no longer admitted (#1930: every token of that
/// context, whichever session's create minted it).
fn forget_amf_notify_token(c: &AmfMbsContext) {
    if let Ok(ctx) = mbsmf_self().read() {
        ctx.forget_amf_context_tokens(c);
    }
}

/// #2015: a delete given up on (evicted at `reconcile::MAX_PENDING` or expired
/// after `reconcile::MAX_AGE`): its context's tokens go, unless a live session
/// re-recorded that context after the delete left the pending set -- the tokens
/// are that session's then.
fn forget_abandoned_amf_notify_token(c: &AmfMbsContext) {
    if let Ok(ctx) = mbsmf_self().read() {
        ctx.forget_unheld_context_tokens(c);
    }
}

/// `POST {AMF_NOTIFY_PREFIX}/{token}` — the AMF's Namf_MBSBroadcast
/// ContextStatusNotify (TS 29.518 §5.6.2.5), #1796. The token must be one this
/// MB-SMF minted for a ContextCreate and has not forgotten (404 otherwise, which
/// the AMF treats as gone). `mbsSessionId` is required. A `releasedInd` means the
/// AMF released the context itself, so its record is dropped and the session's
/// release will not delete it again. Answered 204: these notifications carry no
/// Broadcast Session Transport Request Transfer, the only content that needs a
/// 200 with a response (step 2a).
async fn handle_amf_context_status_notify(token: &str, request: &SbiRequest) -> SbiResponse {
    let ctx = mbsmf_self();
    let Some(session_id) = ctx.read().ok().and_then(|c| c.amf_notify_session(token)) else {
        return send_not_found("No such AMF MBS context notification resource", None);
    };
    let Some(body) = request
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
    else {
        return send_bad_request(
            "ContextStatusNotification is not JSON",
            Some("INVALID_MSG_FORMAT"),
        );
    };
    if body.get("mbsSessionId").is_none() {
        return send_bad_request(
            "ContextStatusNotification.mbsSessionId is mandatory",
            Some("MANDATORY_IE_MISSING"),
        );
    }
    let containers = body
        .get("n2MbsSmInfoList")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    log::info!(
        "MBS session {session_id}: AMF ContextStatusNotify with {containers} N2 container(s), \
         operationStatus {:?}, operationEvents {}",
        body.get("operationStatus")
            .and_then(serde_json::Value::as_str),
        body.get("operationEvents")
            .map_or(0, |e| e.as_array().map_or(0, Vec::len)),
    );
    if body.get("releasedInd").and_then(serde_json::Value::as_bool) == Some(true) {
        let dropped = ctx.read().is_ok_and(|c| c.drop_amf_context_by_token(token));
        log::warn!(
            "MBS session {session_id}: the AMF released its broadcast MBS context \
             (record dropped: {dropped}); the RAN no longer has this session"
        );
    }
    SbiResponse::with_status(204)
}

/// #1796: the AMF sends its ContextStatusNotify to the `notifyUri` this MB-SMF
/// minted, without an access token (as amfd sends every notification), so the
/// OAuth2 gate admits that route only on a token this MB-SMF holds -- the same
/// callback-token scheme as #1518.
fn oauth2_callback_exemptions() -> Vec<nextgcore_sbi::server::OAuth2CallbackExemption> {
    vec![nextgcore_sbi::server::OAuth2CallbackExemption::new(
        "POST",
        format!("{}/{{token}}", namf_client::AMF_NOTIFY_PREFIX),
        |cb| {
            mbsmf_self()
                .read()
                .is_ok_and(|c| c.amf_notify_session(cb.token).is_some())
        },
    )]
}

/// Handle MBS Session Release (TS 23.247 7.2.3)
async fn handle_mbs_session_release(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Release: {session_id}");

    let pool_id = parse_session_id(session_id);

    // #1863: only the consumer that created the session releases it, checked
    // before the N4mb release or anything else; a stale or foreign DELETE used
    // to release another consumer's session and its TMGI binding.
    let ctx = mbsmf_self();
    let found = pool_id.and_then(|id| ctx.read().ok()?.session_find_by_id(id));
    if let Some(refused) = found.as_ref().and_then(|s| {
        nextgcore_sbi::owner_binding::refuse_non_owner(
            s.owner.as_deref(),
            request,
            "MBS Session Release",
        )
    }) {
        return refused;
    }

    // #76: release the N4mb session on the MB-UPF BEFORE dropping local state. The
    // old code called `session_remove` alone, whose log line said "releasing N4mb
    // SEID" while releasing nothing, so every released MBS session leaked a session
    // on the MB-UPF. Awaited, so the local removal below happens after the Session
    // Deletion Response (or after it demonstrably failed).
    if let Some(id) = pool_id {
        release_n4mb_transport(id).await;
    }

    let ctx = mbsmf_self();
    let removed = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.session_remove(id)
        } else {
            None
        }
    });

    // #1758: taken in the same step as the removal (no await between), so a
    // ContextCreate landing after it sees the session gone and deletes its own.
    let amf_contexts = match (&removed, ctx.read()) {
        (Some(session), Ok(context)) => context.take_amf_contexts(session.id),
        _ => Vec::new(),
    };

    match removed {
        Some(session) => {
            log::info!("MBS Session {session_id} released");
            // #1758: release the broadcast MBS contexts this session created on its
            // AMF(s) (TS 23.247 §7.3.2, Namf_MBSBroadcast ContextDelete). On its own
            // task, so a consumer disconnect cannot drop it; a failure is retried.
            if !amf_contexts.is_empty() {
                let _ = spawn_detached(release_amf_contexts(amf_contexts)).await;
            }
            // For Broadcast sessions: emit BROADCAST_DELIVERY_STATUS/TERMINATED to Status subs.
            if matches!(session.session_type, MbsSessionType::Broadcast) {
                emit_status_notify(session_id);
            }
            // Emit SESSION_RELEASE to ContextStatus subs keyed by this session's MbsSessionId.
            let session_key = serde_json::to_value(types::MbsSessionId {
                tmgi: Some(spec_tmgi_from(&session.tmgi)),
                ssm: None,
            })
            .unwrap_or_default();
            emit_ctx_status_notify("SESSION_RELEASE", Some(session_key));
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// Handle MBS Session Activate (debug route) - establish N4mb PFCP with the
/// MB-UPF (TS 23.247 7.3). [mbsmfd-10] The production trigger for this is the
/// ContextUpdate Start path; this debug alias reuses the same establishment
/// drive ([`drive_n4mb_establishment`]).
async fn handle_mbs_session_activate(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Activate (N4mb, debug): {session_id}");

    let pool_id = match parse_session_id(session_id) {
        Some(id) => id,
        None => return send_bad_request("Invalid session ID", Some("INVALID_SESSION_ID")),
    };
    // #1944: only the session's creator, before the N4mb establishment.
    if let Some(refused) = refuse_debug_route_non_owner(pool_id, request, "MBS Session Activate") {
        return refused;
    }

    // Parse UPF address from request body (defaults to the configured MB-UPF).
    let upf_addr: std::net::Ipv4Addr = if let Some(body) = &request.http.content {
        let data: serde_json::Value = match serde_json::from_str(body) {
            Ok(p) => p,
            Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
        };
        data.get("upfAddr")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(configured_mb_upf_ip)
    } else {
        configured_mb_upf_ip()
    };

    let ctx = mbsmf_self();
    let session = if let Ok(context) = ctx.read() {
        context.session_activate_n4mb(pool_id, upf_addr)
    } else {
        None
    };

    match session {
        Some(session) => {
            let Some(n4mb) = session.n4mb_session.as_ref() else {
                log::error!("MBS Session {session_id} has no N4mb session after activation");
                return send_bad_request(
                    "N4mb session not initialized",
                    Some("N4MB_SESSION_MISSING"),
                );
            };
            let local_seid = n4mb.local_seid;
            let dl_teid = n4mb.dl_teid;

            // Drive a real PFCP establishment (assoc-gated, response-processed,
            // T1/N1) through the persistent node. [mbsmfd-02]
            tokio::spawn(drive_n4mb_establishment(pool_id, session.clone()));

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "mbsSessionStatus": "ACTIVE",
                    "n4mbSession": {
                        "localSeid": local_seid,
                        "upfAddr": upf_addr.to_string(),
                        "dlTeid": format!("{dl_teid:#010x}"),
                        "state": "ESTABLISHMENT_PENDING",
                    },
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// Configured MB-UPF PFCP endpoint (env `MB_UPF_ADDR` / `UPF_PFCP_PORT`).
fn configured_mb_upf() -> SocketAddr {
    SocketAddr::from((configured_mb_upf_ip(), configured_upf_pfcp_port()))
}

/// Configured MB-UPF IPv4 address (env `MB_UPF_ADDR`, default 127.0.0.7).
fn configured_mb_upf_ip() -> std::net::Ipv4Addr {
    std::env::var("MB_UPF_ADDR")
        .ok()
        .and_then(|a| a.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 7))
}

/// Configured MB-UPF PFCP port (env `UPF_PFCP_PORT`, default 8805).
fn configured_upf_pfcp_port() -> u16 {
    std::env::var("UPF_PFCP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8805)
}

/// Configured MB-SMF (CP function) N4mb address (env `MBSMF_N4MB_ADDR`,
/// default 127.0.0.1) used as the PFCP Node ID / F-SEID address.
fn configured_cp_addr() -> [u8; 4] {
    std::env::var("MBSMF_N4MB_ADDR")
        .ok()
        .and_then(|a| a.parse::<std::net::Ipv4Addr>().ok())
        .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1))
        .octets()
}

/// #2115: `MBSMF_PLMN_MCC` / `MBSMF_PLMN_MNC`, when set, must be a 3-digit MCC
/// and a 2-3 digit MNC (TS 23.003 §2.2). Checked once at start-up, so
/// [`default_plmn`] never hands out a TMGI in a PLMN like "1".
fn check_plmn_env(mcc: Option<&str>, mnc: Option<&str>) -> Result<(), String> {
    use nextgcore_core::plmn::{check_digits, PlmnPart};
    if let Some(mcc) = mcc {
        check_digits("MBSMF_PLMN_MCC", PlmnPart::Mcc, mcc)?;
    }
    if let Some(mnc) = mnc {
        check_digits("MBSMF_PLMN_MNC", PlmnPart::Mnc, mnc)?;
    }
    Ok(())
}

/// Configured serving PLMN for TMGI allocation (env `MBSMF_PLMN_MCC/MNC`).
fn default_plmn() -> PlmnId {
    PlmnId {
        mcc: std::env::var("MBSMF_PLMN_MCC").unwrap_or_else(|_| "001".to_string()),
        mnc: std::env::var("MBSMF_PLMN_MNC").unwrap_or_else(|_| "01".to_string()),
    }
}

/// Persistent N4mb PFCP node toward the MB-UPF, bound lazily on first use.
/// [mbsmfd-02]
static N4MB_NODE: tokio::sync::OnceCell<Arc<n4mb::N4mbPfcpNode>> =
    tokio::sync::OnceCell::const_new();

/// Get (or lazily bind) the persistent N4mb PFCP node.
async fn n4mb_node() -> Option<Arc<n4mb::N4mbPfcpNode>> {
    N4MB_NODE
        .get_or_try_init(|| async {
            n4mb::N4mbPfcpNode::new(
                "0.0.0.0:0".parse().expect("valid bind addr"),
                configured_mb_upf(),
                configured_cp_addr(),
            )
            .await
        })
        .await
        .map_err(|e| log::warn!("[N4mb] failed to bind PFCP node: {e}"))
        .ok()
        .cloned()
}

/// Drive a real N4mb PFCP establishment for `session` through the persistent
/// node: association-gated, response-processed, with T1/N1 retransmission. On a
/// successful establishment the stored session transitions to `Established`.
/// [mbsmfd-02/03]
async fn drive_n4mb_establishment(pool_id: u64, session: MbsSession) {
    let Some(n4mb) = session.n4mb_session.as_ref() else {
        return;
    };
    let upf_addr = n4mb.upf_addr;
    let params = n4mb::N4mbEstablishParams {
        local_seid: n4mb.local_seid,
        cp_addr: configured_cp_addr(),
        upf_addr: upf_addr.octets(),
        dl_teid: n4mb.dl_teid,
        pdr_id: n4mb.mcast_pdr_id,
        far_id: n4mb.mcast_far_id,
        // OuterHeaderCreation toward the multicast group (mbsmfd-09).
        mcast_transport_addr: n4mb.ll_ssm_dst.unwrap_or(upf_addr).octets(),
        c_teid: n4mb.dl_teid,
    };

    let Some(node) = n4mb_node().await else {
        return;
    };

    match node.establish_session(&params).await {
        Ok(outcome) => {
            let transport = outcome.transport_addr.unwrap_or(upf_addr);
            let dl_teid = outcome.up_dl_teid.unwrap_or(params.dl_teid);
            let ctx = mbsmf_self();
            if let Ok(c) = ctx.read() {
                c.apply_n4mb_response(pool_id, outcome.remote_seid, dl_teid, transport);
            }
            log::info!(
                "[N4mb] session {pool_id} established (remote_seid={})",
                outcome.remote_seid
            );
        }
        Err(e) => log::warn!("[N4mb] session {pool_id} establishment failed: {e}"),
    }
}

/// Apply queued N4mb Session Reports to the session state (#76).
///
/// TS 23.247 §7.2.5.2: downlink data arriving at the MB-UPF **activates** a
/// (de)activated multicast session. The report is answered on the wire by the recv
/// loop (the UP is waiting); this is the consequence, driven where the session state
/// lives so the socket loop never takes the context lock.
///
/// Returns the ids of the sessions whose state actually changed, so a caller — and a
/// test — can tell a reactivation from a report about an already-active session.
async fn apply_n4mb_reports() -> Vec<u64> {
    let Some(node) = n4mb_node().await else {
        return Vec::new();
    };
    let reports = node.take_reports();
    if reports.is_empty() {
        return Vec::new();
    }
    let ctx = mbsmf_self();
    let mut activated = Vec::new();
    for report in reports {
        if !report.downlink_data {
            // A report with no Downlink Data Report is answered and otherwise has no
            // consequence here: usage reporting is not part of this NF's remit, and
            // acting on a report type we do not model would be inventing behaviour.
            log::debug!(
                "[N4mb] Session Report on seid=0x{:016x} carried no Downlink Data Report; \
                 answered, no activation",
                report.seid
            );
            continue;
        }
        let Ok(c) = ctx.read() else { continue };
        // Addressed to our LOCAL seid: the UP answers to the CP F-SEID it was given.
        let Some(session) = c.session_find_by_local_seid(report.seid) else {
            log::warn!(
                "[N4mb] Downlink Data Report on seid=0x{:016x} matches no session; the \
                 MB-UPF may hold a session this MB-SMF has released",
                report.seid
            );
            continue;
        };
        if c.session_activate_on_downlink_data(session.id) {
            log::info!(
                "[N4mb] downlink data reactivated MBS session {} (TS 23.247 §7.2.5.2)",
                session.id
            );
            activated.push(session.id);
        }
    }
    activated
}

/// Release a session's N4mb transport ON THE WIRE, then clear it locally (#76).
///
/// TS 29.244 §7.5.4 / TS 23.247 §7.1.1.4: releasing an MBS session tears down the
/// associated MB-UPF resources, and that requires a PFCP Session Deletion Request.
/// `release_session` existed and had **no callers at all** — `grep` found only its
/// definition — so both the DELETE and the TERMINATE paths mutated local state and
/// left the UPF session behind. Every released MBS session leaked one.
///
/// Order matters and is the criterion: mark `ReleasePending`, send and await the
/// deletion, and only then clear. Clearing first (which
/// `session_context_terminate` used to do) discards the remote SEID the request has
/// to be addressed to, so nothing could be deleted even in principle.
///
/// Returns whether the deletion was **acknowledged**. A timeout or a refusal still
/// clears the local context: the session is going away from this MB-SMF either way,
/// and keeping a context whose UPF counterpart may or may not exist would leave the
/// two sides disagreeing with no path back. The leak is named in the log so it is
/// diagnosable rather than silent.
async fn release_n4mb_transport(session_id: u64) -> bool {
    let ctx = mbsmf_self();
    let remote_seid = match ctx.read() {
        Ok(c) => c.session_mark_release_pending(session_id),
        Err(_) => None,
    };
    let Some(remote_seid) = remote_seid else {
        // No N4mb context, or one whose establishment never completed: there is
        // nothing on the MB-UPF to delete. Clearing is still right.
        let cleared = ctx
            .read()
            .map(|c| c.session_clear_n4mb(session_id))
            .unwrap_or(false);
        if cleared {
            log::debug!(
                "[N4mb] session {session_id} had no UP-allocated SEID; cleared without a \
                 Session Deletion (its establishment never completed)"
            );
        }
        return false;
    };

    let acknowledged = match n4mb_node().await {
        Some(node) => match node.release_session(remote_seid).await {
            Ok(()) => {
                log::info!(
                    "[N4mb] session {session_id} released on the MB-UPF \
                     (remote_seid=0x{remote_seid:016x})"
                );
                true
            }
            Err(e) => {
                log::warn!(
                    "[N4mb] Session Deletion for session {session_id} \
                     (remote_seid=0x{remote_seid:016x}) failed: {e}. The MB-UPF may retain \
                     the session; local state is cleared regardless."
                );
                false
            }
        },
        None => {
            log::warn!(
                "[N4mb] no PFCP node: session {session_id} \
                 (remote_seid=0x{remote_seid:016x}) is released locally only and LEAKS on the \
                 MB-UPF"
            );
            false
        }
    };

    if let Ok(c) = ctx.read() {
        c.session_clear_n4mb(session_id);
    }
    acknowledged
}

/// #2060: a ContextUpdate names its consumer in `nfcInstanceId`; a Start
/// registers it and a Terminate deregisters it (the last one releases the
/// shared N4mb transport, #295). That must be the calling NF itself, or any NF
/// could tear down another SMF's multicast leg. The caller is its verified NF
/// instance ID (`owner_binding::verified_consumer_id`: the client certificate's
/// when direct, with or without NFTypes; the verified token `sub` behind an
/// SCP or SEPP). A mismatch, or conflicting identities, is 403 before anything
/// changes. A caller with no verified identity is refused under the production
/// profile and, as for every `owner_binding` resource, admitted under dev.
/// `Some` is the refusal.
fn refuse_foreign_nfc_instance(
    request: &SbiRequest,
    nfc_instance_id: &str,
    terminate: bool,
) -> Option<SbiResponse> {
    refuse_foreign_nfc_instance_with(
        request,
        nfc_instance_id,
        terminate,
        owner_binding::identity_required(),
    )
}

/// [`refuse_foreign_nfc_instance`] under an explicit profile (#2214): the
/// profile is read once, so the identity rule and the "no identity" decision
/// cannot disagree, and the production refusals are testable without touching
/// the process-wide override.
fn refuse_foreign_nfc_instance_with(
    request: &SbiRequest,
    nfc_instance_id: &str,
    terminate: bool,
    production: bool,
) -> Option<SbiResponse> {
    let operation = if terminate {
        "ContextUpdate Terminate"
    } else {
        "ContextUpdate"
    };
    let forbidden = |detail: String| {
        Some(nextgcore_sbi::server::send_error(
            403,
            "Forbidden",
            &detail,
            None,
        ))
    };
    let caller = match owner_binding::verified_consumer_id_with(request, production) {
        Ok(Some(caller)) => caller,
        Ok(None) if !production => return None,
        Ok(None) => return forbidden(format!("{operation}: the caller proved no NF identity")),
        Err(why) => return forbidden(format!("{operation}: {why}")),
    };
    if owner_binding::same_nf_instance_id(&caller, nfc_instance_id) {
        return None;
    }
    // debug, not warn: a peer can send these at will (#1620 review m7).
    log::debug!(
        "{operation} refused: nfcInstanceId {nfc_instance_id:?} is not the caller ({caller})"
    );
    forbidden(format!(
        "{operation}: nfcInstanceId {nfc_instance_id:?} is not the calling NF"
    ))
}

/// Handle ContextUpdate (TS 29.532 §5.3.2.5) - start/terminate MBS data
/// reception. [mbsmfd-03] On an SMF multicast Start the MB-SMF allocates and
/// returns a `cTeid` + `llSsm` and drives N4mb establishment; on Terminate /
/// leave it releases the N4mb transport; on the AMF path it returns an N2 MBS
/// SM container.
async fn handle_mbs_session_context_update(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let req: types::ContextUpdateReqData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid ContextUpdateReqData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    // #76: resolve the session by TMGI **or by SSM**. `MbsSessionId` is
    // `anyOf(tmgi, ssm)`, and this used to hard-reject anything without a TMGI with
    // `400 MANDATORY_IE_MISSING` — so an SSM-identified multicast session could not
    // be updated at all, by any consumer, ever.
    //
    // An SSM resolves to the session's own TMGI, which every session has (allocated
    // at create when the consumer supplied none). That keeps the whole downstream
    // handler keyed on one identifier instead of carrying two.
    let tmgi = match req.mbs_session_id.tmgi.as_ref() {
        Some(t) => context_tmgi_from(Some(t)),
        None => match req.mbs_session_id.ssm.as_ref() {
            Some(ssm) => {
                match mbsmf_self()
                    .read()
                    .ok()
                    .and_then(|c| c.session_find_by_ssm(ssm))
                {
                    Some(session) => session.tmgi,
                    None => {
                        return send_not_found(
                            "No MBS session matches the supplied mbsSessionId.ssm",
                            Some("CONTEXT_NOT_FOUND"),
                        )
                    }
                }
            }
            None => {
                return send_bad_request(
                    "ContextUpdate requires mbsSessionId.tmgi or mbsSessionId.ssm \
                     (TS 29.571 MbsSessionId anyOf)",
                    Some("MANDATORY_IE_MISSING"),
                )
            }
        },
    };

    let action = req
        .requested_action
        .clone()
        .unwrap_or(types::ContextUpdateAction::Start);
    let is_amf = req.ran_node_id.is_some() || req.n2_mbs_sm_info.is_some();
    let terminate =
        matches!(action, types::ContextUpdateAction::Terminate) || req.leave_ind == Some(true);

    // #2060: the consumer a ContextUpdate joins or terminates is the body's
    // `nfcInstanceId`, so it must be the caller's own; before any change.
    if let Some(refused) = refuse_foreign_nfc_instance(request, &req.nfc_instance_id, terminate) {
        return refused;
    }

    let ctx = mbsmf_self();

    // --- Terminate / leave: deregister this consumer, and release the N4mb
    // multicast transport only when it was the LAST one (#295, TS 23.247
    // §7.2.1.3/§7.2.1.4).
    //
    // A multicast MBS session is a SHARED distribution session established once and
    // reused across joins. This leg used to release the transport for whichever
    // consumer asked first, so one SMF leaving tore it down for every other SMF still
    // receiving — and the remaining consumers' sessions looked fine (state, SBI
    // surface, TMGI all unchanged) and simply stopped receiving, because the MB-UPF
    // session underneath them had been deleted.
    if terminate {
        match ctx
            .read()
            .map(|c| c.session_context_terminate_for(&tmgi, &req.nfc_instance_id))
            .unwrap_or(context::ConsumerTerminate::NotFound)
        {
            context::ConsumerTerminate::NotFound => {
                return send_not_found(
                    "MBS session not found for ContextUpdate",
                    Some("CONTEXT_NOT_FOUND"),
                );
            }
            context::ConsumerTerminate::ConsumerRemains { remaining } => {
                // The never-departing-consumer decision (#295), logged rather than
                // implemented: NOTHING unpins a transport whose remaining consumer
                // never sends a TERMINATE. A TTL would have the MB-SMF tear down a
                // transport that is still carrying data because a consumer was quiet,
                // which is worse than the pin; tying it to NRF liveness needs an
                // NF-status subscription this daemon does not have. So the pin is
                // accepted and made visible, naming who holds it — nothing else in the
                // system can.
                log::warn!(
                    "ContextUpdate Terminate from {} (TMGI {:02x?}): shared transport \
                     stays UP for {} remaining consumer(s) {:?}. Nothing unpins it if \
                     they never terminate (#295).",
                    req.nfc_instance_id,
                    tmgi.mbs_service_id,
                    remaining.len(),
                    remaining
                );
                return SbiResponse::with_status(204);
            }
            context::ConsumerTerminate::LastConsumer => {}
        }
        // #76: `session_context_terminate` now only marks the N4mb context
        // ReleasePending -- it used to zero it, discarding the remote SEID before
        // anything could send a Session Deletion. The wire release happens here and
        // clears the context afterwards.
        if let Some(id) = ctx
            .read()
            .ok()
            .and_then(|c| c.session_find_by_tmgi(&tmgi).map(|s| s.id))
        {
            release_n4mb_transport(id).await;
        }
        log::info!(
            "ContextUpdate Terminate (TMGI {:02x?})",
            tmgi.mbs_service_id
        );
        return SbiResponse::with_status(204);
    }

    // --- AMF path: shared-delivery establishment / release driven by a real
    // N2 MBS SM container (TS 29.532 §5.3.2.5 steps 1/2a/2b, TS 38.413
    // §9.3.5.7-§9.3.5.10). [G1-2]
    if is_amf {
        return handle_context_update_amf(request, &req, &tmgi).await;
    }

    // --- SMF multicast Start: allocate cTeid + llSsm, drive N4mb establishment.
    //
    // #295: register this consumer FIRST, so the transport the establishment below
    // brings up is already accounted for. Registering after would leave a window in
    // which a second consumer's TERMINATE saw an empty set and released a transport
    // this START had just asked for.
    //
    // Only this leg registers. The AMF leg's `nfcInstanceId` is the AMF's, and an AMF
    // relaying N2 for shared delivery is not what pins the MB-UPF session — counting it
    // would let an AMF's silence hold a transport open.
    if ctx
        .read()
        .ok()
        .and_then(|c| c.session_consumer_register(&tmgi, &req.nfc_instance_id))
        .is_none()
        && req.nfc_instance_id.is_empty()
    {
        // Not a rejection: `nfcInstanceId` is required by the schema, so an empty one
        // is a peer sending a member it declares. Such a consumer cannot be counted and
        // therefore cannot pin the transport — which is the pre-#295 behaviour for it.
        log::warn!(
            "ContextUpdate Start (TMGI {:02x?}) carried an empty nfcInstanceId: the \
             consumer cannot be tracked, so the first Terminate releases the shared \
             transport as it did before #295",
            tmgi.mbs_service_id
        );
    }

    let upf_addr = configured_mb_upf_ip();
    let started = ctx
        .read()
        .ok()
        .and_then(|c| c.session_context_start(&tmgi, upf_addr));
    let session = match started {
        Some(s) => s,
        None => {
            return send_not_found(
                "MBS session not found for ContextUpdate",
                Some("CONTEXT_NOT_FOUND"),
            )
        }
    };
    let Some(n4mb) = session.n4mb_session.as_ref() else {
        return send_bad_request("N4mb session not initialized", Some("N4MB_SESSION_MISSING"));
    };
    let c_teid = n4mb.dl_teid;
    let ll_ssm = types::Ssm {
        source_ip_addr: types::IpAddr {
            ipv4_addr: n4mb.ll_ssm_src.map(|a| a.to_string()),
            ipv6_addr: None,
        },
        dest_ip_addr: types::IpAddr {
            ipv4_addr: n4mb.ll_ssm_dst.map(|a| a.to_string()),
            ipv6_addr: None,
        },
    };
    let pool_id = session.id;

    log::info!(
        "ContextUpdate Start (TMGI {:02x?}): cTeid={c_teid:#010x}, llSsm dst={:?}",
        tmgi.mbs_service_id,
        n4mb.ll_ssm_dst
    );

    // Drive the real N4mb establishment in the background. [mbsmfd-02]
    tokio::spawn(drive_n4mb_establishment(pool_id, session.clone()));

    let rsp = types::ContextUpdateRspData {
        ll_ssm: Some(ll_ssm),
        c_teid: Some(c_teid),
        n2_mbs_sm_info: None,
    };
    SbiResponse::with_status(200)
        .with_json_body(&rsp)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ---------------------------------------------------------------------------
// G1-2: ContextUpdate AMF path — real multipart/related N2 container handling
// (TS 29.532 §5.3.2.5, §6.2.6.2.5/6/9, §6.2.6.5.2; TS 38.413 §9.3.5.7-10;
//  TS 23.247 §7.2.1.4/§7.2.2.4)
// ---------------------------------------------------------------------------

/// Content-Id used for the N2 MBS SM container part in ContextUpdate
/// responses (`ContextUpdateRspData.n2MbsSmInfo.ngapData.contentId`).
const N2_RSP_CONTENT_ID: &str = "n2MbsSmInfo";

/// BCD-encode an MCC/MNC digit-string pair into the 3-octet PLMN identity of
/// TS 24.008 §10.5.1.3 (as carried in the NGAP TMGI, TS 38.413 §9.3.1.206):
/// octet1 = MCC2|MCC1, octet2 = MNC3|MCC3 (MNC3=0xF for 2-digit MNC),
/// octet3 = MNC2|MNC1. Non-digit / missing positions encode as 0xF.
fn plmn_bcd(mcc: &str, mnc: &str) -> [u8; 3] {
    fn digit(s: &str, i: usize) -> u8 {
        s.as_bytes()
            .get(i)
            .map(|b| b.wrapping_sub(b'0'))
            .filter(|d| *d <= 9)
            .unwrap_or(0xF)
    }
    let (m1, m2, m3) = (digit(mcc, 0), digit(mcc, 1), digit(mcc, 2));
    let (n1, n2) = (digit(mnc, 0), digit(mnc, 1));
    let n3 = if mnc.len() >= 3 { digit(mnc, 2) } else { 0xF };
    [(m2 << 4) | m1, (n3 << 4) | m3, (n2 << 4) | n1]
}

/// The NGAP-side TMGI (PLMN identity BCD, MBS Service ID) for an internal [`Tmgi`].
fn ngap_session_id_from(tmgi: &Tmgi) -> n2_mbs_transfer::NgapTmgi {
    (
        plmn_bcd(&tmgi.plmn_id.mcc, &tmgi.plmn_id.mnc),
        tmgi.mbs_service_id,
    )
}

/// TMGI-match validation (G1-2 step 3): the TMGI inside the decoded NGAP
/// transfer container must equal `req.mbsSessionId.tmgi`.
fn transfer_tmgi_matches(container: &n2_mbs_transfer::NgapTmgi, tmgi: &Tmgi) -> bool {
    *container == ngap_session_id_from(tmgi)
}

/// Resolve `n2MbsSmInfo.ngapData.contentId` against the inbound multipart
/// parts (`request.http.parts`, populated by the SBI server per TS 29.500
/// §6.1.2.3). Fail-closed: a dangling contentId or a part that is not
/// `application/vnd.3gpp.ngap` is a 400 MANDATORY_IE_INCORRECT — never a
/// silent JSON-only fallback.
fn resolve_n2_part<'a>(
    request: &'a SbiRequest,
    content_id: &str,
) -> Result<&'a SbiPart, Box<SbiResponse>> {
    let part = request
        .http
        .parts
        .iter()
        .find(|p| p.content_id.as_deref() == Some(content_id))
        .ok_or_else(|| {
            Box::new(send_bad_request(
                &format!("n2MbsSmInfo references missing binary part '{content_id}'"),
                Some("MANDATORY_IE_INCORRECT"),
            ))
        })?;
    let ct_ok = part
        .content_type
        .as_deref()
        .and_then(|ct| ct.split(';').next())
        .map(|ct| ct.trim().eq_ignore_ascii_case(APPLICATION_NGAP))
        .unwrap_or(false);
    if !ct_ok {
        return Err(Box::new(send_bad_request(
            &format!("binary part '{content_id}' must be {APPLICATION_NGAP}"),
            Some("MANDATORY_IE_INCORRECT"),
        )));
    }
    Ok(part)
}

/// Build the 200 multipart ContextUpdate response: `ContextUpdateRspData`
/// JSON root referencing an `application/vnd.3gpp.ngap` binary part carrying
/// `ngap_bytes` (the SBI server auto-encodes `multipart/related` when parts
/// are attached).
fn context_update_n2_response(ie_type: types::NgapIeType, ngap_bytes: Vec<u8>) -> SbiResponse {
    let rsp = types::ContextUpdateRspData {
        ll_ssm: None,
        c_teid: None,
        n2_mbs_sm_info: Some(types::N2MbsSmInfo {
            ngap_ie_type: ie_type,
            ngap_data: types::RefToBinaryData {
                content_id: N2_RSP_CONTENT_ID.to_string(),
            },
        }),
    };
    match SbiResponse::with_status(200).with_json_body(&rsp) {
        Ok(r) => r.with_part(SbiPart::with_content(
            N2_RSP_CONTENT_ID,
            APPLICATION_NGAP,
            bytes::Bytes::from(ngap_bytes),
        )),
        Err(e) => {
            log::error!("Failed to serialize ContextUpdateRspData: {e}");
            SbiResponse::with_status(500)
        }
    }
}

/// AMF shared-delivery establishment (TS 23.247 §7.2.1.4, single shared
/// NG-U tunnel per session): drive the session_context_start/N4mb path and
/// answer with an `MBS_DIS_SETUP_RSP` (TS 38.413 §9.3.5.8) built from the
/// session's real N4mb transport (llSsm + cTeid), or an `MBS_DIS_SETUP_FAIL`
/// (§9.3.5.9) with a real Cause when establishment cannot be started.
///
/// #301: registers `ran_node_key` as a holder of the session's shared transport
/// BEFORE the establishment below brings it up, mirroring where #295 registers a
/// consumer. Registering afterwards would leave a window in which a second RAN node's
/// `MBS_DIS_REL_REQ` saw an empty set and released a transport this setup had just
/// asked for.
fn amf_shared_delivery_setup(tmgi: &Tmgi, ran_node_key: Option<&str>) -> SbiResponse {
    let ctx = mbsmf_self();
    match ran_node_key {
        Some(key) => {
            let _ = ctx
                .read()
                .ok()
                .and_then(|c| c.session_ran_node_register(tmgi, key));
        }
        None => log::warn!(
            "ContextUpdate AMF setup (TMGI {:02x?}) carried no usable ranNodeId: this RAN              node cannot be tracked, so the first MBS_DIS_REL_REQ releases the shared              transport as it did before #301",
            tmgi.mbs_service_id
        ),
    }
    let upf_addr = configured_mb_upf_ip();
    let started = ctx
        .read()
        .ok()
        .and_then(|c| c.session_context_start(tmgi, upf_addr));
    let ngap_tmgi = ngap_session_id_from(tmgi);

    let (session, n4mb) = match started
        .as_ref()
        .and_then(|s| s.n4mb_session.as_ref().map(|n| (s, n)))
    {
        Some(pair) => pair,
        None => {
            // N4mb/establishment failure: a real Unsuccessful Transfer with a
            // real Cause instead of the old silent JSON 200. [G1-2 step 5]
            return match n2_mbs_transfer::setup_unsuccessful_transfer(ngap_tmgi) {
                Ok(bytes) => {
                    log::warn!(
                        "ContextUpdate AMF setup failed for TMGI {:02x?}: N4mb start unavailable",
                        tmgi.mbs_service_id
                    );
                    context_update_n2_response(types::NgapIeType::MbsDisSetupFail, bytes)
                }
                Err(e) => {
                    log::error!("Failed to encode MbsDistributionSetupUnsuccessfulTransfer: {e}");
                    SbiResponse::with_status(500)
                }
            };
        }
    };

    // Shared NG-U Multicast TNL Information (TS 38.413 §9.3.2.16) from the
    // session's real N4mb transport: llSsm dst/src + the common GTP TEID.
    let tunnel = n2_mbs_transfer::SharedMulticastTunnel {
        multicast_address: n4mb.ll_ssm_dst.unwrap_or(upf_addr).octets(),
        source_address: n4mb.ll_ssm_src.unwrap_or(upf_addr).octets(),
        teid: n4mb.dl_teid,
    };
    // Single QoS flow derived from the session model (default QFI 1 / 5QI 9
    // when the create carried no mbsServiceInfo) — documented minimal scope.
    match n2_mbs_transfer::setup_response_transfer(
        ngap_tmgi,
        tunnel,
        session.qfi.min(63),
        session.fiveqi,
    ) {
        Ok(bytes) => {
            log::info!(
                "ContextUpdate AMF setup (TMGI {:02x?}): cTeid={:#010x}, llSsm dst={:?}",
                tmgi.mbs_service_id,
                n4mb.dl_teid,
                n4mb.ll_ssm_dst
            );
            // Drive the real N4mb establishment in the background, exactly
            // like the SMF Start path. [mbsmfd-02]
            tokio::spawn(drive_n4mb_establishment(session.id, session.clone()));
            context_update_n2_response(types::NgapIeType::MbsDisSetupRsp, bytes)
        }
        Err(e) => {
            log::error!("Failed to encode MbsDistributionSetupResponseTransfer: {e}");
            SbiResponse::with_status(500)
        }
    }
}

/// ContextUpdate AMF path (TS 29.532 §5.3.2.5): decode the inbound N2 MBS SM
/// container (when present) from the multipart body, drive shared-delivery
/// establishment or release, and answer with a *response-direction* container
/// (`MBS_DIS_SETUP_RSP`/`MBS_DIS_SETUP_FAIL`) or 204 (release, spec 2b).
async fn handle_context_update_amf(
    request: &SbiRequest,
    req: &types::ContextUpdateReqData,
    tmgi: &Tmgi,
) -> SbiResponse {
    let ctx = mbsmf_self();
    let exists = ctx
        .read()
        .map(|c| c.session_find_by_tmgi(tmgi).is_some())
        .unwrap_or(false);
    if !exists {
        return send_not_found(
            "MBS session not found for ContextUpdate",
            Some("CONTEXT_NOT_FOUND"),
        );
    }

    // #301: one canonical key per RAN node, computed once for both legs. `None` means
    // the request carried no `ranNodeId` at all (the schema makes it optional, and the
    // release leg can arrive with only the N2 container), which is the untracked case.
    let ran_node_key = req
        .ran_node_id
        .as_ref()
        .and_then(context::canonical_ran_node_key);

    let Some(n2) = req.n2_mbs_sm_info.as_ref() else {
        // Legacy JSON-only AMF request (ranNodeId only, no inbound container):
        // still a shared-delivery setup — the response now carries a REAL
        // container part (no dangling contentId). [G1-2 step 8]
        return amf_shared_delivery_setup(tmgi, ran_node_key.as_deref());
    };

    let part = match resolve_n2_part(request, &n2.ngap_data.content_id) {
        Ok(p) => p,
        Err(rsp) => return *rsp,
    };

    match n2.ngap_ie_type {
        // Establishment of shared delivery toward the RAN node
        // (TS 23.247 §7.2.1.4): decode the Setup Request Transfer (§9.3.5.7).
        types::NgapIeType::MbsDisSetupReq => {
            let transfer_tmgi = match n2_mbs_transfer::parse_setup_request_tmgi(&part.data) {
                Ok(t) => t,
                Err(e) => {
                    return send_bad_request(
                        &format!("Invalid MBS Distribution Setup Request Transfer: {e}"),
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
            };
            if !transfer_tmgi_matches(&transfer_tmgi, tmgi) {
                return send_bad_request(
                    "TMGI in N2 container does not match mbsSessionId.tmgi",
                    Some("INVALID_MSG_FORMAT"),
                );
            }
            amf_shared_delivery_setup(tmgi, ran_node_key.as_deref())
        }
        // Release of shared delivery toward the RAN node (TS 23.247
        // §7.2.2.4): decode the Release Request Transfer (§9.3.5.10),
        // release the shared transport, 204 (spec 2b: nothing to return).
        types::NgapIeType::MbsDisRelReq => {
            let transfer_tmgi = match n2_mbs_transfer::parse_release_request_tmgi(&part.data) {
                Ok(t) => t,
                Err(e) => {
                    return send_bad_request(
                        &format!("Invalid MBS Distribution Release Request Transfer: {e}"),
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
            };
            if !transfer_tmgi_matches(&transfer_tmgi, tmgi) {
                return send_bad_request(
                    "TMGI in N2 container does not match mbsSessionId.tmgi",
                    Some("INVALID_MSG_FORMAT"),
                );
            }
            // #301: deregister THIS RAN node and release the shared transport only
            // when nothing holds it any more. This arm used to call the unconditional
            // `session_context_terminate`, so one RAN node's release deleted the MB-UPF
            // session for every other RAN node still receiving on it (TS 23.247
            // §7.2.2.4 releases shared delivery toward ONE node).
            let key = ran_node_key.clone().unwrap_or_default();
            match ctx
                .read()
                .map(|c| c.session_ran_node_release(tmgi, &key))
                .unwrap_or(context::ConsumerTerminate::NotFound)
            {
                context::ConsumerTerminate::NotFound => {
                    return send_not_found(
                        "MBS session not found for ContextUpdate",
                        Some("CONTEXT_NOT_FOUND"),
                    );
                }
                context::ConsumerTerminate::ConsumerRemains { remaining } => {
                    // #295's never-departing-holder decision applies unchanged here:
                    // logged rather than timed out, because tearing down a transport
                    // that is still carrying data because a RAN node went quiet is
                    // worse than the pin.
                    log::warn!(
                        "ContextUpdate AMF release from RAN node {} (TMGI {:02x?}): shared                          transport stays UP for {} remaining holder(s) {:?}. Nothing unpins                          it if they never release (#301).",
                        if key.is_empty() { "<untracked>" } else { &key },
                        tmgi.mbs_service_id,
                        remaining.len(),
                        remaining
                    );
                    return SbiResponse::with_status(204);
                }
                context::ConsumerTerminate::LastConsumer => {}
            }
            // #76: same as the SMF terminate leg above -- the wire release, then the
            // local clear.
            if let Some(id) = ctx
                .read()
                .ok()
                .and_then(|c| c.session_find_by_tmgi(tmgi).map(|s| s.id))
            {
                release_n4mb_transport(id).await;
            }
            log::info!(
                "ContextUpdate AMF release (TMGI {:02x?}): last holder gone, shared                  transport released",
                tmgi.mbs_service_id
            );
            SbiResponse::with_status(204)
        }
        // Response-direction IE types are invalid in a request (TS 29.532
        // §5.3.2.5 step 1) — fail-closed.
        types::NgapIeType::MbsDisSetupRsp | types::NgapIeType::MbsDisSetupFail => send_bad_request(
            "response-direction ngapIeType in ContextUpdate request",
            Some("INVALID_MSG_FORMAT"),
        ),
        types::NgapIeType::Unknown => send_bad_request(
            "unknown ngapIeType in ContextUpdate request",
            Some("INVALID_MSG_FORMAT"),
        ),
    }
}

/// Handle TMGI Allocate (TS 29.532 §5.2.2.2, POST /nmbsmf-tmgi/v1/tmgi).
/// [mbsmfd-04] Allocates `tmgiNumber` fresh TMGIs and/or refreshes a supplied
/// `tmgiList`, returning `TmgiAllocated` with one common `expirationTime`.
async fn handle_tmgi_allocate(request: &SbiRequest) -> SbiResponse {
    // #1863: TMGIs are allocated to the consumer's verified identity, refused
    // before anything is read or allocated.
    let owner = match nextgcore_sbi::owner_binding::owner_for_new_resource(request, "TMGI Allocate")
    {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let req: types::TmgiAllocate = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid TmgiAllocate: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let ctx = mbsmf_self();
    let plmn = default_plmn();
    let ttl = TMGI_DEFAULT_TTL_SECS;

    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => return send_bad_request("Context unavailable", None),
    };

    let mut allocated: Vec<Tmgi> = Vec::new();
    let mut expiry = 0u64;

    let fresh_count = req.tmgi_number.filter(|n| *n > 0);
    let refresh: Vec<Tmgi> = req
        .tmgi_list
        .iter()
        .flatten()
        .map(|t| context_tmgi_from(Some(t)))
        .collect();
    if refresh.is_empty() && fresh_count.is_none() {
        return send_bad_request(
            "TmgiAllocate requires tmgiNumber and/or tmgiList",
            Some("MANDATORY_IE_MISSING"),
        );
    }
    // Refresh any supplied TMGIs (TS 29.532 §5.2.2.2). #1863: only TMGIs
    // allocated to this consumer, and checked before anything is allocated, so a
    // refused request changes nothing.
    if !refresh.is_empty() {
        match context.tmgi_refresh(&refresh, ttl, |o| may_manage(o, request)) {
            Ok(e) => expiry = e,
            Err(context::TmgiRefusal::NotOwned(t)) => {
                return tmgi_not_owned("TMGI Allocate (refresh)", &t);
            }
        }
        allocated.extend(refresh);
    }
    // Allocate the requested number of fresh TMGIs.
    if let Some(count) = fresh_count {
        let (fresh, e) = context.tmgi_allocate_owned(&plmn, count, ttl, owner.as_deref());
        expiry = e;
        allocated.extend(fresh);
    }
    drop(context);

    let spec_list: Vec<types::Tmgi> = allocated.iter().map(spec_tmgi_from).collect();
    let rsp = types::TmgiAllocated {
        tmgi_list: spec_list,
        expiration_time: unix_to_rfc3339(expiry),
        nid: None,
    };
    log::info!(
        "TMGI Allocate: {} TMGI(s) (expiry={expiry})",
        allocated.len()
    );
    SbiResponse::with_status(200)
        .with_json_body(&rsp)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// #1863: whether `request` may refresh, deallocate, update or release a
/// resource allocated to `owner` (`nextgcore_sbi::owner_binding`).
fn may_manage(owner: Option<&str>, request: &SbiRequest) -> bool {
    nextgcore_sbi::owner_binding::non_owner_refusal(owner, request).is_none()
}

/// #1863: the 403 for a TMGI that is not allocated to the requester.
fn tmgi_not_owned(operation: &str, tmgi: &Tmgi) -> SbiResponse {
    log::debug!("{operation} refused: TMGI {tmgi:?} is not allocated to the requester");
    nextgcore_sbi::server::send_forbidden(
        &format!("{operation}: a listed TMGI is not allocated to the requester"),
        None,
    )
}

/// Handle TMGI Deallocate (TS 29.532 §5.2.2.3, DELETE /nmbsmf-tmgi/v1/tmgi).
/// [mbsmfd-04] The `tmgi-list` query param names the TMGIs to deallocate.
/// #1863: it is mandatory (TS 29.532 §5.2.2.3: the consumer deallocates the
/// TMGIs it lists); an absent one used to deallocate the WHOLE pool, every
/// consumer's TMGIs, and is now 400 `MANDATORY_QUERY_PARAM_MISSING`. Every listed
/// TMGI still allocated must be the requester's, else 403 and nothing is freed.
///
/// `tmgi-list` is a JSON array in a query parameter, so every conformant sender
/// percent-encodes it (TS 29.500 §5.2.10.2): `[`, `{`, `"` and `:` are all
/// reserved. Feeding `get_param` straight to `serde_json` is therefore only
/// correct because the shared SBI server decodes query values on the way in
/// (#65) — before that it answered 400 to exactly the requests that were
/// spelled correctly. `percent_encoded_tmgi_list_deallocates_and_does_not_400`
/// drives the encoded form over a real connection to keep that true.
async fn handle_tmgi_deallocate(request: &SbiRequest) -> SbiResponse {
    let ctx = mbsmf_self();

    let Some(raw) = request.http.get_param("tmgi-list") else {
        return send_bad_request(
            "TMGI Deallocate requires the tmgi-list query parameter (TS 29.532 §5.2.2.3)",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    };
    let list = match serde_json::from_str::<Vec<types::Tmgi>>(raw) {
        // minItems 1 (TS29532_Nmbsmf_TMGI.yaml).
        Ok(list) if !list.is_empty() => list,
        Ok(_) => {
            return send_bad_request(
                "tmgi-list must name at least one TMGI",
                Some("INVALID_QUERY_PARAM"),
            )
        }
        Err(e) => {
            return send_bad_request(
                &format!("Invalid tmgi-list query parameter: {e}"),
                Some("INVALID_QUERY_PARAM"),
            )
        }
    };
    let ctmgis: Vec<Tmgi> = list.iter().map(|t| context_tmgi_from(Some(t))).collect();
    let freed = match ctx.read() {
        Ok(c) => match c.tmgi_deallocate(&ctmgis, |o| may_manage(o, request)) {
            Ok(n) => n,
            Err(context::TmgiRefusal::NotOwned(t)) => {
                return tmgi_not_owned("TMGI Deallocate", &t);
            }
        },
        Err(_) => 0,
    };

    log::info!("TMGI Deallocate: freed {freed} TMGI(s)");
    SbiResponse::with_status(204)
}

/// #1944: the caller check of the debug routes (`/activate`, `/members*`,
/// [`debug_routes_enabled`]): only the consumer that created the session
/// (`nextgcore_sbi::owner_binding`: its verified NF instance ID, the
/// certificate's when direct, the token `sub` behind an SCP) may activate it
/// or change its members, refused 403 before any change. These routes are
/// not TS 29.532 resources; in the specified flows a UE joins through its
/// serving SMF's ContextUpdate (TS 23.247 §7.2.1.3). `None` for an unknown
/// session: the handler answers that as before.
fn refuse_debug_route_non_owner(
    pool_id: u64,
    request: &SbiRequest,
    operation: &str,
) -> Option<SbiResponse> {
    let session = mbsmf_self().read().ok()?.session_find_by_id(pool_id)?;
    owner_binding::refuse_non_owner(session.owner.as_deref(), request, operation)
}

/// Handle member join (TMGI group membership)
async fn handle_member_join(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Member Join: {session_id}");

    let pool_id = match parse_session_id(session_id) {
        Some(id) => id,
        None => return send_bad_request("Invalid session ID", Some("INVALID_SESSION_ID")),
    };
    if let Some(refused) = refuse_debug_route_non_owner(pool_id, request, "MBS Member Join") {
        return refused;
    }

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let supi = data
        .get("supi")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let ctx = mbsmf_self();
    let joined = if let Ok(context) = ctx.read() {
        context.session_member_join(pool_id, supi)
    } else {
        false
    };

    if joined {
        SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({
                "mbsSessionId": session_id,
                "supi": supi,
                "result": "JOINED",
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(201))
    } else {
        send_bad_request(
            &format!("Failed to join UE {supi} to session {session_id}"),
            Some("JOIN_FAILED"),
        )
    }
}

/// Handle member list
async fn handle_member_list(session_id: &str) -> SbiResponse {
    log::debug!("MBS Member List: {session_id}");

    let pool_id = parse_session_id(session_id);

    let ctx = mbsmf_self();
    let session = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.session_find_by_id(id)
        } else {
            None
        }
    });

    match session {
        Some(session) => {
            let members: Vec<&String> = session.group_members.iter().collect();
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "memberCount": members.len(),
                    "members": members,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// Handle member leave
async fn handle_member_leave(session_id: &str, supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Member Leave: {session_id} / {supi}");

    let pool_id = match parse_session_id(session_id) {
        Some(id) => id,
        None => return send_bad_request("Invalid session ID", Some("INVALID_SESSION_ID")),
    };
    if let Some(refused) = refuse_debug_route_non_owner(pool_id, request, "MBS Member Leave") {
        return refused;
    }

    let ctx = mbsmf_self();
    let left = if let Ok(context) = ctx.read() {
        context.session_member_leave(pool_id, supi)
    } else {
        false
    };

    if left {
        SbiResponse::with_status(204)
    } else {
        send_not_found(
            &format!("UE {supi} not found in session {session_id}"),
            Some("MEMBER_NOT_FOUND"),
        )
    }
}

// ---------------------------------------------------------------------------
// mbsmfd-05: Status / ContextStatus Subscribe / Unsubscribe / Notify handlers
// ---------------------------------------------------------------------------

/// #1865: `404` for an unknown subscription (checked first), `403` for a caller
/// that is not the one that subscribed (TS 33.501 §13.4.1), else `None`.
/// `owner` is the store's lookup: `None` = no such subscription.
fn refuse_sub_non_owner(
    owner: Option<Option<String>>,
    sub_id: &str,
    kind: &str,
    request: &SbiRequest,
    operation: &str,
) -> Option<SbiResponse> {
    let Some(owner) = owner else {
        return Some(send_not_found(
            &format!("{kind} subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ));
    };
    owner_binding::refuse_non_owner(owner.as_deref(), request, operation)
}

/// StatusSubscribe — POST `/mbs-sessions/subscriptions` → 201 + Location
/// (TS 29.532 §5.3.2.6). Body: StatusSubscribeReqData{subscription:MbsSessionSubscription}.
async fn handle_status_subscribe(request: &SbiRequest) -> SbiResponse {
    // #1865: bound to the verified identity of the subscriber, decided before
    // the body is read or anything is stored.
    let owner = match owner_binding::owner_for_new_resource(request, "StatusSubscribe") {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let req: subscription::StatusSubscribeReqData = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid StatusSubscribeReqData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let entry = {
        let sub = &req.subscription;
        if sub.event_list.is_empty() || sub.notify_uri.is_empty() {
            return send_bad_request(
                "subscription requires eventList and notifyUri",
                Some("MANDATORY_IE_MISSING"),
            );
        }
        let document = serde_json::to_value(sub).unwrap_or_default();
        subscription::SubEntry {
            notify_uri: sub.notify_uri.clone(),
            notify_correlation_id: sub.notify_correlation_id.clone(),
            event_types: sub
                .event_list
                .iter()
                .map(|e| e.event_type.clone())
                .collect(),
            mbs_session_id: document.get("mbsSessionId").cloned(),
            document,
            owner,
        }
    };
    let ctx = mbsmf_self();
    let sub_id = match ctx.read().ok().and_then(|c| c.status_sub_add(entry)) {
        Some(id) => id,
        None => return send_bad_request("Failed to create subscription", None),
    };
    log::info!("[sub] Status subscription created: {sub_id}");
    let rsp_body = subscription::StatusSubscribeRspData {
        subscription: req.subscription,
    };
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/{sub_id}"),
        )
        .with_json_body(&rsp_body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// StatusSubscribeMod — PATCH `/mbs-sessions/subscriptions/{id}` → 200
/// (TS 29.532 §5.3.2.6, operationId StatusSubscribeMod).
/// Body: application/json-patch+json (array of PatchItem). Returns modified bare subscription.
async fn handle_status_subscribe_mod(sub_id: &str, request: &SbiRequest) -> SbiResponse {
    // #1865: only the subscriber may modify, checked before the body is read.
    let owner = mbsmf_self()
        .read()
        .ok()
        .and_then(|c| c.status_sub_owner(sub_id));
    if let Some(refused) =
        refuse_sub_non_owner(owner, sub_id, "Status", request, "StatusSubscribeMod")
    {
        return refused;
    }
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let patch: types::PatchData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid PatchData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let ctx = mbsmf_self();
    match ctx
        .read()
        .ok()
        .and_then(|c| c.status_sub_patch(sub_id, &patch))
    {
        Some(doc) => {
            log::debug!("[sub] Status subscription patched: {sub_id}");
            SbiResponse::with_status(200)
                .with_json_body(&doc)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("Status subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// StatusUnsubscribe — DELETE `/mbs-sessions/subscriptions/{id}` → 204
/// (TS 29.532 §5.3.2.7).
async fn handle_status_unsubscribe(sub_id: &str, request: &SbiRequest) -> SbiResponse {
    let ctx = mbsmf_self();
    // #1865: only the subscriber may unsubscribe, checked before the removal.
    let owner = ctx.read().ok().and_then(|c| c.status_sub_owner(sub_id));
    if let Some(refused) =
        refuse_sub_non_owner(owner, sub_id, "Status", request, "StatusUnsubscribe")
    {
        return refused;
    }
    let removed = ctx
        .read()
        .ok()
        .map(|c| c.status_sub_remove(sub_id))
        .unwrap_or(false);
    if removed {
        log::info!("[sub] Status subscription removed: {sub_id}");
        SbiResponse::with_status(204)
    } else {
        send_not_found(
            &format!("Status subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// ContextStatusSubscribe — POST `/mbs-sessions/contexts/subscriptions` → 201
/// (TS 29.532 §5.3.2.9). Body: ContextStatusSubscribeReqData{subscription:ContextStatusSubscription}.
async fn handle_ctx_status_subscribe(request: &SbiRequest) -> SbiResponse {
    // #1865: bound to the verified identity of the subscriber, decided before
    // the body is read or anything is stored.
    let owner = match owner_binding::owner_for_new_resource(request, "ContextStatusSubscribe") {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let req: subscription::ContextStatusSubscribeReqData = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid ContextStatusSubscribeReqData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let entry = {
        let sub = &req.subscription;
        if sub.event_list.is_empty() {
            return send_bad_request(
                "subscription requires eventList",
                Some("MANDATORY_IE_MISSING"),
            );
        }
        let document = serde_json::to_value(sub).unwrap_or_default();
        let session_id_val = serde_json::to_value(&sub.mbs_session_id).unwrap_or_default();
        subscription::SubEntry {
            notify_uri: sub.notify_uri.clone(),
            notify_correlation_id: sub.notify_correlation_id.clone(),
            event_types: sub
                .event_list
                .iter()
                .map(|e| e.event_type.clone())
                .collect(),
            mbs_session_id: Some(session_id_val),
            document,
            owner,
        }
    };
    let ctx = mbsmf_self();
    let sub_id = match ctx.read().ok().and_then(|c| c.ctx_sub_add(entry)) {
        Some(id) => id,
        None => return send_bad_request("Failed to create subscription", None),
    };
    log::info!("[sub] ContextStatus subscription created: {sub_id}");
    let rsp_body = subscription::ContextStatusSubscribeRspData {
        subscription: req.subscription,
    };
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nmbsmf-mbssession/v1/mbs-sessions/contexts/subscriptions/{sub_id}"),
        )
        .with_json_body(&rsp_body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// ContextStatusSubscribeMod — PATCH `/mbs-sessions/contexts/subscriptions/{id}` → 200
/// (TS 29.532 §5.3.2.9, operationId ContextStatusSubscribeMod).
/// Body: application/json-patch+json. Returns modified bare subscription.
async fn handle_ctx_status_subscribe_mod(sub_id: &str, request: &SbiRequest) -> SbiResponse {
    // #1865: only the subscriber may modify, checked before the body is read.
    let owner = mbsmf_self()
        .read()
        .ok()
        .and_then(|c| c.ctx_sub_owner(sub_id));
    if let Some(refused) = refuse_sub_non_owner(
        owner,
        sub_id,
        "ContextStatus",
        request,
        "ContextStatusSubscribeMod",
    ) {
        return refused;
    }
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let patch: types::PatchData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid PatchData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let ctx = mbsmf_self();
    match ctx
        .read()
        .ok()
        .and_then(|c| c.ctx_sub_patch(sub_id, &patch))
    {
        Some(doc) => {
            log::debug!("[sub] ContextStatus subscription patched: {sub_id}");
            SbiResponse::with_status(200)
                .with_json_body(&doc)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("ContextStatus subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// ContextStatusUnsubscribe — DELETE `/mbs-sessions/contexts/subscriptions/{id}` → 204
/// (TS 29.532 §5.3.2.10).
async fn handle_ctx_status_unsubscribe(sub_id: &str, request: &SbiRequest) -> SbiResponse {
    let ctx = mbsmf_self();
    // #1865: only the subscriber may unsubscribe, checked before the removal.
    let owner = ctx.read().ok().and_then(|c| c.ctx_sub_owner(sub_id));
    if let Some(refused) = refuse_sub_non_owner(
        owner,
        sub_id,
        "ContextStatus",
        request,
        "ContextStatusUnsubscribe",
    ) {
        return refused;
    }
    let removed = ctx
        .read()
        .ok()
        .map(|c| c.ctx_sub_remove(sub_id))
        .unwrap_or(false);
    if removed {
        log::info!("[sub] ContextStatus subscription removed: {sub_id}");
        SbiResponse::with_status(204)
    } else {
        send_not_found(
            &format!("ContextStatus subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// Fan out a Status notification for a broadcast session delivery termination.
/// Fires BROADCAST_DELIVERY_STATUS / TERMINATED to all matching Status subscribers.
/// Called only when a Broadcast session is released. [mbsmfd-05]
fn emit_status_notify(session_id: &str) {
    let _ = session_id; // session_id is available for future session-keyed filtering
    let ctx = mbsmf_self();
    let subs = ctx
        .read()
        .ok()
        .map(|c| c.status_subs_matching("BROADCAST_DELIVERY_STATUS", &None))
        .unwrap_or_default();
    let ts = crate::context::unix_to_rfc3339(crate::context::now_unix());
    for sub in subs {
        let body = subscription::StatusNotifyReqData {
            event_list: subscription::MbsSessionEventReportList {
                event_report_list: vec![subscription::MbsSessionEventReport {
                    event_type: "BROADCAST_DELIVERY_STATUS".to_string(),
                    time_stamp: Some(ts.clone()),
                    broadcast_del_status: Some("TERMINATED".to_string()),
                }],
                notify_correlation_id: sub.notify_correlation_id.clone(),
            },
        };
        let uri = sub.notify_uri.clone();
        tokio::spawn(async move {
            subscription::send_notify_post(&uri, &body).await;
        });
    }
}

/// Fan out a ContextStatus notification for `event_type` to all matching
/// ContextStatus subscribers (SMF-facing), filtered by `session_key`. [mbsmfd-05]
fn emit_ctx_status_notify(event_type: &str, session_key: Option<serde_json::Value>) {
    let ctx = mbsmf_self();
    let subs = ctx
        .read()
        .ok()
        .map(|c| c.ctx_subs_matching(event_type, &session_key))
        .unwrap_or_default();
    let ts = crate::context::unix_to_rfc3339(crate::context::now_unix());
    let event_type = event_type.to_string();
    for sub in subs {
        let body = subscription::ContextStatusNotifyReqData {
            report_list: vec![subscription::ContextStatusEventReport {
                event_type: event_type.clone(),
                time_stamp: ts.clone(),
            }],
            notify_correlation_id: sub.notify_correlation_id.clone(),
        };
        let uri = sub.notify_uri.clone();
        tokio::spawn(async move {
            subscription::send_notify_post(&uri, &body).await;
        });
    }
}

/// Every Nmbsmf service this MB-SMF serves: the service type, the API version it
/// is defined at, and the NF types allowed to consume it (TS 29.510 §6.1.6.2.3
/// `NFService.allowedNfTypes`).
///
/// ONE table (#392), consumed by both [`build_mbsmf_nf_instance`] (the typed self
/// instance) and [`build_mbsmf_nf_profile`] (the NFProfile PUT to the NRF). The
/// profile already advertised both services; the self instance carried
/// `nmbsmf-mbssession` alone, so the two disagreed.
const MBSMF_SERVICES: &[(nextgcore_sbi::types::SbiServiceType, &str, &[&str])] = &[
    // TS 29.532 Nmbsmf_MBSSession, consumed by the AMF/SMF/NEF.
    (
        nextgcore_sbi::types::SbiServiceType::NmbsmfMbssession,
        "1.0.0",
        &["AMF", "SMF", "NEF", "SCP"],
    ),
    // TS 29.532 Nmbsmf_TMGI (Allocate/Deallocate). [mbsmfd-04]
    (
        nextgcore_sbi::types::SbiServiceType::NmbsmfTmgi,
        "1.1.0",
        &["AMF", "SMF", "NEF", "SCP"],
    ),
];

/// Build this MB-SMF's typed self NF instance from [`MBSMF_SERVICES`].
fn build_mbsmf_nf_instance(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
) -> nextgcore_sbi::context::NfInstance {
    let mut self_instance = nextgcore_sbi::context::NfInstance::new(
        nf_instance_id,
        nextgcore_sbi::types::NfType::Mbsmf,
    );
    nextgcore_sbi::nf_addressing::set_instance_host(&mut self_instance, sbi_addr);
    self_instance.heartbeat_interval = 10;
    for (service_type, _full_version, _allowed) in MBSMF_SERVICES {
        let mut svc = nextgcore_sbi::context::NfService::new(service_type.to_name(), *service_type);
        svc.port = sbi_port;
        nextgcore_sbi::nf_addressing::set_service_host(&mut svc, sbi_addr);
        self_instance.add_service(svc);
    }
    self_instance
}

/// Build the MB-SMF's NFProfile for NRF registration (TS 29.510 §6.1.6.2.2).
///
/// Split out of [`register_with_nrf`] so the advertised service list is
/// assertable without standing up an NRF. Each service carries its own
/// `ipEndPoints` and `allowedNfTypes`; the NF-level `allowedNfTypes` is the UNION
/// over the services, since a type barred at NF level can never reach any
/// service.
fn build_mbsmf_nf_profile(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    scheme: nextgcore_sbi::types::UriScheme,
) -> serde_json::Value {
    let services: Vec<serde_json::Value> = MBSMF_SERVICES
        .iter()
        .map(|(service_type, full_version, allowed)| {
            let name = service_type.to_name();
            serde_json::json!({
                "serviceInstanceId": format!("{nf_instance_id}-{name}"),
                "serviceName": name,
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": full_version}],
                "scheme": scheme.as_str(),
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
                "allowedNfTypes": allowed,
            })
        })
        .collect();

    let mut nf_allowed: Vec<&str> = Vec::new();
    for (_, _, allowed) in MBSMF_SERVICES {
        for t in *allowed {
            if !nf_allowed.contains(t) {
                nf_allowed.push(t);
            }
        }
    }

    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "MB_SMF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": services,
            "allowedNfTypes": nf_allowed,
            "heartBeatTimer": 10
        }),
        sbi_addr,
    )
}

/// Register MB-SMF with NRF
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

    log::info!("Registering MB-SMF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = build_mbsmf_nf_profile(nf_instance_id, sbi_addr, sbi_port, sbi_scheme);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("MB-SMF registered with NRF successfully (id={nf_instance_id})");
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&nf_profile);

            // From the SAME table the profile came from: it used to be built here
            // with `nmbsmf-mbssession` alone (#392).
            sbi_ctx
                .set_self_instance(build_mbsmf_nf_instance(nf_instance_id, sbi_addr, sbi_port))
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

/// #1863: the verified consumer the crate's tests call the router as.
#[cfg(test)]
pub(crate) const TEST_CONSUMER_1863: &str = "c0c0c0c0-1863-4000-8000-0000000000c0";

/// `request` as [`TEST_CONSUMER_1863`], unless it already names a verified
/// identity, so tests that create and then manage a TMGI or session pass under
/// both SBI profiles (`production` refuses an anonymous create).
#[cfg(test)]
pub(crate) fn as_test_consumer(mut request: SbiRequest) -> SbiRequest {
    if request.peer_cert_nf_instance_id.is_none() && request.oauth2_subject.is_none() {
        request.oauth2_subject = Some(TEST_CONSUMER_1863.to_string());
    }
    request
}

#[cfg(test)]
mod tests {
    /// #1796: only a broadcast session with an MBS service area gets an AMF
    /// ContextCreate, carrying the consumer's S-NSSAI (SST 1 when it named none)
    /// and the session's QoS flow.
    ///
    /// REVERT-VERIFIED: with the session type not checked, the multicast session
    /// gets an AMF leg.
    #[test]
    fn only_a_broadcast_session_with_an_area_gets_an_amf_context_1796() {
        let tmgi = Tmgi::default();
        let session = MbsSession::new(1, tmgi, MbsSessionType::Broadcast);
        let area = serde_json::json!({ "taiList": [ { "plmnId": { "mcc": "001", "mnc": "01" },
                                                       "tac": "000001" } ] });
        let body = r#"{"mbsSession":{"serviceType":"BROADCAST","snssai":{"sst":2,"sd":"0000aa"}}}"#;
        assert!(
            amf_leg_for(
                MbsSessionType::Multicast,
                Some(area.clone()),
                body,
                &session
            )
            .is_none(),
            "a multicast session has no AMF broadcast context"
        );
        assert!(amf_leg_for(MbsSessionType::Broadcast, None, body, &session).is_none());
        let leg = amf_leg_for(
            MbsSessionType::Broadcast,
            Some(area.clone()),
            body,
            &session,
        )
        .expect("a broadcast session with an area");
        assert_eq!(leg.mbs_service_area, area);
        assert_eq!(leg.snssai, serde_json::json!({ "sst": 2, "sd": "0000aa" }));
        assert_eq!((leg.qfi, leg.five_qi), (session.qfi, session.fiveqi));
        let leg = amf_leg_for(MbsSessionType::Broadcast, Some(area), "{}", &session).unwrap();
        assert_eq!(leg.snssai, serde_json::json!({ "sst": 1 }));
    }

    use super::*;

    /// #2115: a malformed `MBSMF_PLMN_MCC` / `_MNC` fails start-up; unset (the
    /// 001/01 default) or well-formed passes.
    ///
    /// REVERT-VERIFIED: with `check_plmn_env` always `Ok`, `expect_err` panics.
    #[test]
    fn a_malformed_plmn_env_fails_start_up_2115() {
        assert_eq!(check_plmn_env(None, None), Ok(()));
        assert_eq!(check_plmn_env(Some("999"), Some("070")), Ok(()));
        let err = check_plmn_env(Some("1"), Some("01")).expect_err("short MCC");
        assert!(
            err.starts_with("MBSMF_PLMN_MCC=\"1\": an MCC is 3 digits"),
            "{err}"
        );
        let err = check_plmn_env(Some("001"), Some("0700")).expect_err("long MNC");
        assert!(
            err.starts_with("MBSMF_PLMN_MNC=\"0700\": an MNC is 2 or 3 digits"),
            "{err}"
        );
    }

    /// #1863: the router as [`TEST_CONSUMER_1863`]. Shadows the glob import; a
    /// test that needs another caller sets its identity, or calls
    /// `super::mbsmf_sbi_request_handler` for an anonymous one.
    async fn mbsmf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
        super::mbsmf_sbi_request_handler(as_test_consumer(as_its_nfc_instance(request))).await
    }

    /// #2060: a ContextUpdate is sent by the NF its `nfcInstanceId` names, so
    /// one with no identity calls as that NF (`as_test_consumer` would make it
    /// TEST_CONSUMER_1863, which the check refuses). A test of another caller
    /// sets its identity itself.
    fn as_its_nfc_instance(mut request: SbiRequest) -> SbiRequest {
        let unidentified =
            request.peer_cert_nf_instance_id.is_none() && request.oauth2_subject.is_none();
        if unidentified && request.header.uri.contains("/contexts/update") {
            let body = request.http.content.clone().unwrap_or_default();
            let marker = "\"nfcInstanceId\":\"";
            if let Some(start) = body.find(marker).map(|i| i + marker.len()) {
                if let Some(len) = body[start..].find('"') {
                    request.oauth2_subject = Some(body[start..start + len].to_string());
                }
            }
        }
        request
    }
    // #417: the Setup Response is read back by the generated codec's strict
    // decode and pinned whole against the hand-derived octets
    // (n2_mbs_transfer/golden.rs), not against the hand-written codec.
    use crate::n2_mbs_transfer::golden;

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-mbsmfd"]);
        assert_eq!(args.sbi_addr, None);
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-mbsmfd"]);
        assert_eq!(args.config, "/etc/nextgcore/mbsmf.yaml");
        assert_eq!(args.log_level, None);
        assert_eq!(args.sbi_port, None);
        assert_eq!(args.max_sessions, 256);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-mbsmfd",
            "--sbi-port",
            "8812",
            "--max-sessions",
            "512",
            "--nrf-uri",
            "http://nrf:7777",
        ]);
        assert_eq!(args.sbi_port, Some(8812));
        assert_eq!(args.max_sessions, 512);
        assert_eq!(args.nrf_uri, "http://nrf:7777");
    }

    #[test]
    fn test_parse_session_id() {
        assert_eq!(parse_session_id("mbs-sess-42"), Some(42));
        assert_eq!(parse_session_id("mbs-sess-0"), Some(0));
        assert_eq!(parse_session_id("invalid"), None);
    }

    /// Locate a byte subsequence (used to assert specific IE windows on the
    /// encoded N4mb establishment packet).
    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    // ---- mbsmfd-01: N4mb PFCP establishment encoded via nextgcore-pfcp ----

    /// Encode an N4mb establishment packet via the shared [`n4mb`] builder.
    fn encode_establishment(
        cp_addr: [u8; 4],
        upf_addr: [u8; 4],
        local_seid: u64,
        dl_teid: u32,
        pdr_id: u16,
        far_id: u32,
    ) -> Vec<u8> {
        let params = n4mb::N4mbEstablishParams {
            local_seid,
            cp_addr,
            upf_addr,
            dl_teid,
            pdr_id,
            far_id,
            mcast_transport_addr: [239, 1, 0, 1],
            c_teid: dl_teid,
        };
        let req = n4mb::build_establishment_request(&params);
        nextgcore_pfcp::message::build_message(
            &nextgcore_pfcp::message::PfcpMessage::SessionEstablishmentRequest(req),
            7,
            Some(0),
        )
        .to_vec()
    }

    /// #392: the registered NFProfile advertises both Nmbsmf services, each at its
    /// own full version, and the typed self instance advertises the SAME surface.
    ///
    /// The profile already carried both; the self instance carried
    /// `nmbsmf-mbssession` alone, so this MB-SMF held two different answers to
    /// "what do I serve".
    #[test]
    fn the_mbsmf_profile_and_self_instance_advertise_one_surface() {
        let profile = build_mbsmf_nf_profile(
            "mbsmf-test-instance",
            "10.45.0.14",
            7811,
            nextgcore_sbi::types::UriScheme::Http,
        );
        let services = profile["nfServices"].as_array().expect("nfServices");
        let names: Vec<&str> = services
            .iter()
            .map(|s| s["serviceName"].as_str().expect("serviceName"))
            .collect();

        assert!(
            names.contains(&"nmbsmf-mbssession"),
            "advertised: {names:?}"
        );
        assert!(names.contains(&"nmbsmf-tmgi"), "advertised: {names:?}");

        // The two full versions differ and both are pinned: TMGI is 1.1.0.
        let tmgi = services
            .iter()
            .find(|s| s["serviceName"] == "nmbsmf-tmgi")
            .expect("nmbsmf-tmgi");
        assert_eq!(tmgi["versions"][0]["apiFullVersion"], "1.1.0");
        let session = services
            .iter()
            .find(|s| s["serviceName"] == "nmbsmf-mbssession")
            .expect("nmbsmf-mbssession");
        assert_eq!(session["versions"][0]["apiFullVersion"], "1.0.0");

        for svc in services {
            let name = svc["serviceName"].as_str().unwrap_or_default();
            let eps = svc["ipEndPoints"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} carries no ipEndPoints"));
            assert_eq!(eps[0]["port"].as_u64(), Some(7811), "{name} port");
            assert!(
                svc["allowedNfTypes"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
                "{name} must state its allowedNfTypes (TS 29.510 §6.1.6.2.3)"
            );
        }

        let instance = build_mbsmf_nf_instance("mbsmf-test-instance", "10.45.0.14", 7811);
        let mut from_instance: Vec<String> =
            instance.services.iter().map(|s| s.name.clone()).collect();
        let mut from_profile: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        from_instance.sort();
        from_profile.sort();
        assert_eq!(
            from_instance, from_profile,
            "the self instance carried nmbsmf-mbssession alone while the profile carried both"
        );
        assert_eq!(from_instance.len(), MBSMF_SERVICES.len());
    }

    #[test]
    fn test_n4mb_establishment_byte_vector() {
        let cp_addr = [127, 0, 0, 1];
        let upf_addr = [10, 0, 0, 7];
        let pkt = encode_establishment(cp_addr, upf_addr, 0x100, 0x0BCA_0001, 1002, 2002);

        // PFCP header: version=1 + S(seid) flag => 0x21, msg type 50.
        assert_eq!(pkt[0], 0x21, "version/SEID flag byte");
        assert_eq!(pkt[1], 50, "Session Establishment Request type");

        // Node ID IE (type 60 = 0x003C), len 5, node-id-type 0 (IPv4) — the
        // mandatory IE the old hand-rolled encoder omitted entirely.
        assert!(
            find_subsequence(&pkt, &[0x00, 0x3C, 0x00, 0x05, 0x00]).is_some(),
            "Node ID IE (type 60, IPv4) present"
        );

        // F-TEID IE (type 21 = 0x0015), len 9, flags octet == 0x01 (V4) — the
        // old encoder wrongly set 0x02 (V6).
        assert!(
            find_subsequence(&pkt, &[0x00, 0x15, 0x00, 0x09, 0x01]).is_some(),
            "F-TEID IE V4 flag octet == 0x01"
        );

        // Apply-Action IE (type 44 = 0x002C), len 2, octet5 == 0x02 (FORW),
        // octet6 == 0x00 — the old encoder put 0x02 in octet6 instead.
        assert!(
            find_subsequence(&pkt, &[0x00, 0x2C, 0x00, 0x02, 0x02, 0x00]).is_some(),
            "Apply-Action FORW in octet 5 == 0x02"
        );
    }

    #[test]
    fn test_n4mb_establishment_roundtrip_decode() {
        use nextgcore_pfcp::message::{parse_message, PfcpMessage};
        use nextgcore_pfcp::types::NodeIdType;

        let cp_addr = [127, 0, 0, 1];
        let upf_addr = [10, 0, 0, 7];
        let local_seid = 0x0000_0000_0000_0100u64;
        let dl_teid = 0x0BCA_0001u32;
        let pdr_id = 1002u16;
        let far_id = 2002u32;

        let pkt = encode_establishment(cp_addr, upf_addr, local_seid, dl_teid, pdr_id, far_id);

        let mut buf = bytes::Bytes::copy_from_slice(&pkt);
        let (header, msg) = parse_message(&mut buf).expect("decode N4mb establishment");
        assert!(header.seid_presence);
        assert_eq!(header.seid, Some(0));

        let req = match msg {
            PfcpMessage::SessionEstablishmentRequest(r) => r,
            other => panic!("expected SessionEstablishmentRequest, got {other:?}"),
        };

        // Node ID round-trips as the CP IPv4 address.
        assert_eq!(req.node_id.node_id_type, NodeIdType::Ipv4);
        assert_eq!(req.node_id.ipv4_addr, Some(cp_addr));

        // CP F-SEID carries the local SEID.
        assert!(req.cp_f_seid.ipv4);
        assert_eq!(req.cp_f_seid.seid, local_seid);

        // PDR/PDI F-TEID round-trips the multicast DL TEID + V4 flag.
        assert_eq!(req.create_pdrs.len(), 1);
        let pdr = &req.create_pdrs[0];
        assert_eq!(pdr.pdr_id, pdr_id);
        assert_eq!(pdr.far_id, Some(far_id));
        let fteid = pdr.pdi.local_f_teid.as_ref().expect("F-TEID present");
        assert!(fteid.ipv4);
        assert!(!fteid.ipv6);
        assert_eq!(fteid.teid, dl_teid);
        assert_eq!(fteid.ipv4_addr, Some(upf_addr));

        // FAR round-trips Apply-Action FORW + Destination=ACCESS for DL
        // multicast distribution toward NG-RAN (mbsmfd-09).
        assert_eq!(req.create_fars.len(), 1);
        let far = &req.create_fars[0];
        assert_eq!(far.far_id, far_id);
        assert!(far.apply_action.forw);
        let fp = far
            .forwarding_parameters
            .as_ref()
            .expect("forwarding parameters present");
        assert_eq!(
            fp.destination_interface,
            nextgcore_pfcp::types::DestinationInterface::Access
        );
    }

    // ---- mbsmfd-07: resolve a created session by its TMGI ----

    #[test]
    fn test_lookup_session_by_tmgi() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        // Create via a spec MbsSessionId carrying a TMGI.
        let spec_id = types::MbsSessionId {
            tmgi: Some(types::Tmgi {
                mbs_service_id: "0a0b0c".to_string(),
                plmn_id: types::PlmnId {
                    mcc: "001".to_string(),
                    mnc: "01".to_string(),
                },
            }),
            ssm: None,
        };
        let ctx_tmgi = context_tmgi_from(spec_id.tmgi.as_ref());
        let created = ctx
            .session_add(ctx_tmgi.clone(), MbsSessionType::Broadcast)
            .unwrap();

        // Resolving the same spec TMGI maps back to the created internal id.
        let resolve_tmgi = context_tmgi_from(spec_id.tmgi.as_ref());
        let found = ctx
            .session_find_by_tmgi(&resolve_tmgi)
            .expect("resolved by TMGI");
        assert_eq!(found.id, created.id);
        assert_eq!(found.tmgi.mbs_service_id, [0x0A, 0x0B, 0x0C]);
    }

    // ---- mbsmfd-03/04/10: SBI router behaviour (against the global context) ----

    /// Seed a session in the *global* context keyed by `tmgi` (in the given
    /// PLMN), returning its `mbsServiceId` hex string.
    fn seed_global_session_plmn(svc_id: [u8; 3], mcc: &str, mnc: &str) -> String {
        mbsmf_context_init(256);
        let tmgi = Tmgi {
            mbs_service_id: svc_id,
            plmn_id: PlmnId {
                mcc: mcc.to_string(),
                mnc: mnc.to_string(),
            },
        };
        let ctx = mbsmf_self();
        let guard = ctx.read().unwrap();
        guard
            .session_add(tmgi, MbsSessionType::Multicast)
            .expect("session added");
        hex::encode(svc_id)
    }

    /// Seed a session in the *global* context keyed by `tmgi` (PLMN 001/01),
    /// returning its `mbsServiceId` hex string for building an `MbsSessionId`.
    fn seed_global_session(svc_id: [u8; 3]) -> String {
        seed_global_session_plmn(svc_id, "001", "01")
    }

    // mbsmfd-03: ContextUpdate SMF Start → 200 with cTeid + llSsm.
    #[tokio::test]
    async fn test_router_context_update_smf_start() {
        let svc = seed_global_session([0xC0, 0x01, 0x01]);
        let body = format!(
            r#"{{"nfcInstanceId":"smf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"requestedAction":"START"}}"#
        );
        let req = SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
            .with_body(body, "application/json");
        let rsp = mbsmf_sbi_request_handler(req).await;
        assert_eq!(rsp.status, 200);
        let body = rsp.http.content.as_deref().unwrap();
        let parsed: types::ContextUpdateRspData = serde_json::from_str(body).unwrap();
        assert!(parsed.c_teid.is_some(), "cTeid allocated");
        let ssm = parsed.ll_ssm.as_ref().expect("llSsm present");
        assert!(ssm.dest_ip_addr.ipv4_addr.is_some(), "llSsm dest allocated");
        // G1-2 regression: the SMF JSON path is unchanged — no N2 container,
        // no multipart parts, and the body is exactly the serde shape of
        // ContextUpdateRspData (no extra fields).
        assert!(parsed.n2_mbs_sm_info.is_none(), "SMF path carries no N2");
        assert!(!body.contains("n2MbsSmInfo"), "no n2MbsSmInfo key emitted");
        assert!(rsp.http.parts.is_empty(), "SMF path stays JSON-only");
        assert_eq!(
            body,
            serde_json::to_string(&parsed).unwrap(),
            "byte-identical to the ContextUpdateRspData serde shape"
        );
    }

    /// An SMF-leg ContextUpdate body for one consumer (#295).
    fn smf_ctx_update_body(svc_hex: &str, nfc: &str, action: &str) -> String {
        format!(
            r#"{{"nfcInstanceId":"{nfc}","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc_hex}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"requestedAction":"{action}"}}"#
        )
    }

    /// The stored session for a service id seeded by `seed_global_session`.
    fn stored_session(svc_id: [u8; 3]) -> MbsSession {
        let tmgi = Tmgi {
            mbs_service_id: svc_id,
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        };
        mbsmf_self()
            .read()
            .unwrap()
            .session_find_by_tmgi(&tmgi)
            .expect("session exists")
    }

    /// **#2214**: the production refusals of the #2060 consumer check, through
    /// `refuse_foreign_nfc_instance_with(.., production = true)` so no test
    /// changes the process-wide profile. Under production, a ContextUpdate is
    /// refused 403 when the caller proves no NF identity (anonymous, or a
    /// certificate without NF types, #2065), and when `nfcInstanceId` is empty:
    /// an empty ID names no NF, so even a verified caller does not match it.
    /// Admitted: a verified caller naming itself. Under dev only the anonymous
    /// caller is admitted; an identified one still has to name itself.
    ///
    /// REVERT-VERIFIED: with the `Ok(None)` arm admitting under production too,
    /// "production: anonymous" fails; with `same_nf_instance_id` treating ""
    /// as anyone's, "production: empty nfcInstanceId" fails.
    #[test]
    fn the_production_consumer_check_refuses_anonymous_and_empty_ids_2214() {
        const SMF: &str = "aaaaaaaa-2214-4000-8000-0000000000a1";
        let anonymous = SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update");
        let mut typeless = anonymous.clone();
        typeless.peer_cert_nf_instance_id = Some(SMF.to_string());
        let mut smf = anonymous.clone();
        smf.peer_cert_nf_instance_id = Some(SMF.to_string());
        smf.peer_cert_nf_types = vec!["SMF".into()];
        let detail = |r: Option<SbiResponse>| -> Option<(u16, String)> {
            r.map(|r| (r.status, r.http.content.unwrap_or_default()))
        };
        for terminate in [false, true] {
            let check = |r: &SbiRequest, nfc: &str, production: bool| {
                detail(super::refuse_foreign_nfc_instance_with(
                    r, nfc, terminate, production,
                ))
            };
            for (what, req, why) in [
                ("anonymous", &anonymous, "proved no NF identity"),
                // #2065: an untyped certificate is no identity under production.
                ("typeless", &typeless, "names no NF type"),
            ] {
                let (status, body) = check(req, SMF, true).expect("refused");
                assert_eq!(status, 403, "production: {what}");
                assert!(body.contains(why), "{what}: {body}");
            }
            let (status, body) = check(&smf, "", true).expect("refused");
            assert_eq!(status, 403, "production: empty nfcInstanceId");
            assert!(body.contains("is not the calling NF"), "{body}");
            assert!(
                check(&anonymous, "", true).is_some(),
                "production: anonymous and empty"
            );
            assert_eq!(
                check(&smf, SMF, true),
                None,
                "production: the SMF naming itself"
            );
            // Dev: the anonymous caller is admitted, an identified one is not
            // excused from naming itself.
            assert_eq!(check(&anonymous, "", false), None, "dev: anonymous");
            assert!(check(&smf, "", false).is_some(), "dev: an SMF naming no NF");
        }
    }

    /// #2060: a ContextUpdate joins or terminates only the caller's own
    /// `nfcInstanceId`. Another SMF naming smf-a is refused 403, and smf-a stays
    /// a consumer, whether it calls directly with an SMF certificate, with a
    /// certificate naming no NF type, or through an SCP with its token; so is a
    /// Start naming smf-a, and a caller whose token and certificate disagree.
    /// smf-a's own Terminate is a 204.
    ///
    /// REVERT-VERIFIED: with `refuse_foreign_nfc_instance` returning `None`,
    /// smf-b's Terminate naming smf-a is 204 and smf-a is gone.
    #[tokio::test]
    async fn a_context_update_names_only_the_calling_nf_2060() {
        const SMF_A: &str = "aaaaaaaa-2060-4000-8000-0000000000a1";
        const SMF_B: &str = "bbbbbbbb-2060-4000-8000-0000000000b2";
        let svc_id = [0xC2, 0x06, 0x60];
        let svc = seed_global_session(svc_id);
        let update = |nfc: &str, action: &str| {
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(smf_ctx_update_body(&svc, nfc, action), "application/json")
        };
        let direct = |mut r: SbiRequest, id: &str, types: &[&str]| {
            r.peer_cert_nf_instance_id = Some(id.to_string());
            r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            r
        };
        let via_scp = |mut r: SbiRequest, sub: &str| {
            r.peer_cert_nf_instance_id = Some("cccccccc-2060-4000-8000-0000000000c3".into());
            r.peer_cert_nf_types = vec!["SCP".into()];
            r.oauth2_subject = Some(sub.to_string());
            r
        };
        let rsp =
            super::mbsmf_sbi_request_handler(direct(update(SMF_A, "START"), SMF_A, &["SMF"])).await;
        assert_eq!(rsp.status, 200, "{:?}", rsp.http.content);
        let consumers = || {
            stored_session(svc_id)
                .consumers
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(consumers(), vec![SMF_A.to_string()]);

        let mut mismatched = direct(update(SMF_A, "TERMINATE"), SMF_B, &["SMF"]);
        mismatched.oauth2_subject = Some(SMF_A.to_string());
        for (req, who) in [
            (
                direct(update(SMF_A, "TERMINATE"), SMF_B, &["SMF"]),
                "smf-b, directly",
            ),
            (
                direct(update(SMF_A, "TERMINATE"), SMF_B, &[]),
                "smf-b, a typeless certificate",
            ),
            (
                via_scp(update(SMF_A, "TERMINATE"), SMF_B),
                "smf-b, through the SCP",
            ),
            (
                direct(update(SMF_A, "START"), SMF_B, &["SMF"]),
                "smf-b's Start naming smf-a",
            ),
            (mismatched, "a token naming smf-a on smf-b's certificate"),
        ] {
            let rsp = super::mbsmf_sbi_request_handler(req).await;
            assert_eq!(rsp.status, 403, "{who}: {:?}", rsp.http.content);
            assert_eq!(consumers(), vec![SMF_A.to_string()], "{who}");
        }
        assert!(
            stored_session(svc_id).n4mb_session.is_some(),
            "the transport is up"
        );
        // smf-a through the SCP, with its own token: its Terminate is served.
        let rsp =
            super::mbsmf_sbi_request_handler(via_scp(update(SMF_A, "TERMINATE"), SMF_A)).await;
        assert_eq!(rsp.status, 204, "{:?}", rsp.http.content);
        assert!(consumers().is_empty());
    }

    /// #295 criteria 1-3: two consumers share one transport, the first TERMINATE
    /// leaves it up, the second releases it, and a repeated TERMINATE cannot release a
    /// transport another consumer still holds.
    ///
    /// `n4mb_session.is_some()` is the assertion that no Session Deletion was sent:
    /// `release_n4mb_transport` is the only path that sends one, and it clears the
    /// context whether or not the MB-UPF answered (which is how the existing AMF-release
    /// test observes a release). So a context that is still present is a release that
    /// did not happen.
    #[tokio::test]
    async fn two_consumers_share_a_transport_and_only_the_last_terminate_releases_it() {
        let svc_id = [0xC2, 0x95, 0x01];
        let svc = seed_global_session(svc_id);

        for nfc in ["smf-a", "smf-b"] {
            let rsp = post_ctx_update(
                SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                    .with_body(smf_ctx_update_body(&svc, nfc, "START"), "application/json"),
            )
            .await;
            assert_eq!(rsp.status, 200, "{nfc}'s START must succeed");
        }
        let session = stored_session(svc_id);
        assert_eq!(
            session.consumers.len(),
            2,
            "both consumers hold the shared transport, got {:?}",
            session.consumers
        );
        assert!(session.n4mb_session.is_some(), "the transport is up");

        // --- first TERMINATE: 204, and the transport stays up ---
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body(&svc, "smf-a", "TERMINATE"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 204, "a consumer's departure is a 204");
        let session = stored_session(svc_id);
        assert!(
            session.n4mb_session.is_some(),
            "the MB-UPF session must survive one consumer leaving: the others are still \
             receiving on it (TS 23.247 §7.2.1.4)"
        );
        assert_eq!(
            session.consumers.iter().cloned().collect::<Vec<_>>(),
            vec!["smf-b".to_string()],
            "only the departing consumer is removed"
        );
        assert_ne!(
            session.state,
            MbsSessionState::Suspended,
            "a session another consumer still receives on is not suspended"
        );

        // --- a REPEATED terminate from the same consumer changes nothing ---
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body(&svc, "smf-a", "TERMINATE"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session(svc_id).n4mb_session.is_some(),
            "a repeated TERMINATE must not double-decrement and release a transport \
             smf-b still holds"
        );

        // --- the LAST consumer's terminate releases it ---
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body(&svc, "smf-b", "TERMINATE"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 204);
        let session = stored_session(svc_id);
        assert!(
            session.n4mb_session.is_none(),
            "the last consumer's departure releases the shared transport"
        );
        assert!(
            session.consumers.is_empty(),
            "and leaves no consumer behind"
        );
    }

    // ================================================================
    // #301: shared delivery is released per RAN NODE, not per session
    // ================================================================

    /// An AMF ContextUpdate body with an explicit `ranNodeId`, so a test can be two
    /// different RAN nodes. `amf_ctx_update_body` hardcodes one gNB.
    fn amf_ctx_update_body_gnb(
        svc_hex: &str,
        mcc: &str,
        mnc: &str,
        ie_type: &str,
        content_id: &str,
        gnb_value: &str,
    ) -> String {
        format!(
            r#"{{"nfcInstanceId":"amf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc_hex}","plmnId":{{"mcc":"{mcc}","mnc":"{mnc}"}}}}}},"ranNodeId":{{"plmnId":{{"mcc":"{mcc}","mnc":"{mnc}"}},"gNbId":{{"bitLength":24,"gNBValue":"{gnb_value}"}}}},"n2MbsSmInfo":{{"ngapIeType":"{ie_type}","ngapData":{{"contentId":"{content_id}"}}}}}}"#
        )
    }

    /// An SMF ContextUpdate body for an explicit PLMN, so the SMF and AMF legs in one
    /// test can address the same session.
    fn smf_ctx_update_body_plmn(
        svc_hex: &str,
        nfc: &str,
        action: &str,
        mcc: &str,
        mnc: &str,
    ) -> String {
        format!(
            r#"{{"nfcInstanceId":"{nfc}","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc_hex}","plmnId":{{"mcc":"{mcc}","mnc":"{mnc}"}}}}}},"requestedAction":"{action}"}}"#
        )
    }

    /// The minimal §9.3.5.7 Setup Request Transfer for a TMGI in PLMN 208/93:
    /// presence/preamble octet, then the PLMN in BCD (02 F8 39) and the service id.
    fn setup_container_208_93(svc_id: [u8; 3]) -> Vec<u8> {
        vec![0x00, 0x02, 0xF8, 0x39, svc_id[0], svc_id[1], svc_id[2]]
    }

    /// The §9.3.5.10 Release Request Transfer for the same TMGI — the setup container
    /// plus the trailing octet the golden constant carries.
    fn rel_container_208_93(svc_id: [u8; 3]) -> Vec<u8> {
        let mut v = setup_container_208_93(svc_id);
        v.push(0x40);
        v
    }

    async fn amf_leg(body: String, container: Vec<u8>) -> SbiResponse {
        post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json")
                .with_part(SbiPart::with_content(
                    "n2SmInfo",
                    APPLICATION_NGAP,
                    bytes::Bytes::from(container),
                )),
        )
        .await
    }

    fn stored_session_plmn(svc_id: [u8; 3], mcc: &str, mnc: &str) -> MbsSession {
        let tmgi = Tmgi {
            mbs_service_id: svc_id,
            plmn_id: PlmnId {
                mcc: mcc.to_string(),
                mnc: mnc.to_string(),
            },
        };
        mbsmf_self()
            .read()
            .unwrap()
            .session_find_by_tmgi(&tmgi)
            .expect("session exists")
    }

    /// #301 criteria 1-3: two RAN nodes receive one TMGI's shared delivery; the first
    /// `MBS_DIS_REL_REQ` answers 204 with the transport UP, a repeated one from the same
    /// node changes nothing, and the second releases it.
    ///
    /// `n4mb_session.is_some()` is the assertion that no Session Deletion was sent, as
    /// in #295's test: `release_n4mb_transport` is the only path that sends one and it
    /// clears the context either way, so a context still present is a release that did
    /// not happen.
    #[tokio::test]
    async fn two_ran_nodes_share_delivery_and_only_the_last_release_tears_it_down() {
        let svc_id = [0xC3, 0x01, 0x01];
        let svc = seed_global_session_plmn(svc_id, "208", "93");

        for gnb in ["000001", "000002"] {
            let rsp = amf_leg(
                amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_SETUP_REQ", "n2SmInfo", gnb),
                setup_container_208_93(svc_id),
            )
            .await;
            assert_eq!(rsp.status, 200, "gNB {gnb}'s shared-delivery setup");
        }
        let session = stored_session_plmn(svc_id, "208", "93");
        assert_eq!(
            session.ran_nodes.len(),
            2,
            "both RAN nodes receive this session's shared delivery, got {:?}",
            session.ran_nodes
        );
        assert!(session.n4mb_session.is_some(), "the transport is up");

        // --- the first RAN node releases: 204, and delivery continues ---
        let rsp = amf_leg(
            amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_REL_REQ", "n2SmInfo", "000001"),
            rel_container_208_93(svc_id),
        )
        .await;
        assert_eq!(
            rsp.status, 204,
            "release → 204 (spec 2b: nothing to return)"
        );
        let session = stored_session_plmn(svc_id, "208", "93");
        assert!(
            session.n4mb_session.is_some(),
            "the MB-UPF session must survive one RAN node's release: the others are still \
             receiving on it (TS 23.247 §7.2.2.4 releases delivery toward ONE node)"
        );
        assert_eq!(
            session.ran_nodes.len(),
            1,
            "only the releasing node is removed, got {:?}",
            session.ran_nodes
        );

        // --- a REPEATED release from the same node changes nothing ---
        let rsp = amf_leg(
            amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_REL_REQ", "n2SmInfo", "000001"),
            rel_container_208_93(svc_id),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session_plmn(svc_id, "208", "93")
                .n4mb_session
                .is_some(),
            "a repeated release must not double-decrement and tear down delivery gNB \
             000002 is still receiving"
        );

        // --- the last RAN node releases it ---
        let rsp = amf_leg(
            amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_REL_REQ", "n2SmInfo", "000002"),
            rel_container_208_93(svc_id),
        )
        .await;
        assert_eq!(rsp.status, 204);
        let session = stored_session_plmn(svc_id, "208", "93");
        assert!(
            session.n4mb_session.is_none(),
            "the last RAN node's release tears the shared transport down"
        );
        assert!(session.ran_nodes.is_empty(), "and leaves no node behind");
    }

    /// #301 criterion 4: a setup from a `ranNodeId` already in the set does not
    /// double-count, so an AMF that re-sends `MBS_DIS_SETUP_REQ` cannot pin the
    /// transport past its own release.
    #[tokio::test]
    async fn a_repeated_setup_from_one_ran_node_does_not_double_count() {
        let svc_id = [0xC3, 0x01, 0x02];
        let svc = seed_global_session_plmn(svc_id, "208", "93");

        for _ in 0..3 {
            let rsp = amf_leg(
                amf_ctx_update_body_gnb(
                    &svc,
                    "208",
                    "93",
                    "MBS_DIS_SETUP_REQ",
                    "n2SmInfo",
                    "000001",
                ),
                setup_container_208_93(svc_id),
            )
            .await;
            assert_eq!(rsp.status, 200);
        }
        assert_eq!(
            stored_session_plmn(svc_id, "208", "93").ran_nodes.len(),
            1,
            "three setups from one RAN node are one RAN node"
        );

        // So one release is therefore the last one.
        let rsp = amf_leg(
            amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_REL_REQ", "n2SmInfo", "000001"),
            rel_container_208_93(svc_id),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session_plmn(svc_id, "208", "93")
                .n4mb_session
                .is_none(),
            "one node, one release, transport gone"
        );
    }

    /// #301 criterion 5: the two sets interact, and EITHER being non-empty keeps the
    /// shared transport up. Guarded in both directions, because the safe reading is a
    /// decision rather than an obvious truth.
    ///
    /// The reason for it: the sets count different things at different layers — SMF
    /// consumers of the MBS session, and RAN nodes receiving the shared NG-U tunnel —
    /// and the ONE MB-UPF session underneath serves both. Releasing it while either
    /// still needs it stops data for that side, which is the defect #295 and #301 each
    /// fix in their own dimension; consulting only one set would leave the other's
    /// version of it open.
    #[tokio::test]
    async fn either_a_consumer_or_a_ran_node_keeps_the_shared_transport_up() {
        // --- direction 1: the RAN node releases while an SMF consumer remains ---
        let svc_id = [0xC3, 0x01, 0x03];
        let svc = seed_global_session_plmn(svc_id, "208", "93");

        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body_plmn(&svc, "smf-a", "START", "208", "93"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 200, "the SMF's START");
        let rsp = amf_leg(
            amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_SETUP_REQ", "n2SmInfo", "000001"),
            setup_container_208_93(svc_id),
        )
        .await;
        assert_eq!(rsp.status, 200, "the RAN node's setup");

        let session = stored_session_plmn(svc_id, "208", "93");
        assert_eq!(session.consumers.len(), 1);
        assert_eq!(session.ran_nodes.len(), 1);

        let rsp = amf_leg(
            amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_REL_REQ", "n2SmInfo", "000001"),
            rel_container_208_93(svc_id),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session_plmn(svc_id, "208", "93")
                .n4mb_session
                .is_some(),
            "the last RAN node leaving must not delete the MB-UPF session an SMF consumer \
             is still using"
        );

        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body_plmn(&svc, "smf-a", "TERMINATE", "208", "93"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session_plmn(svc_id, "208", "93")
                .n4mb_session
                .is_none(),
            "and once neither holds it, it goes"
        );

        // --- direction 2: the SMF consumer terminates while a RAN node remains ---
        let svc_id = [0xC3, 0x01, 0x04];
        let svc = seed_global_session_plmn(svc_id, "208", "93");

        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body_plmn(&svc, "smf-a", "START", "208", "93"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 200);
        let rsp = amf_leg(
            amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_SETUP_REQ", "n2SmInfo", "000001"),
            setup_container_208_93(svc_id),
        )
        .await;
        assert_eq!(rsp.status, 200);

        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body_plmn(&svc, "smf-a", "TERMINATE", "208", "93"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session_plmn(svc_id, "208", "93")
                .n4mb_session
                .is_some(),
            "the last SMF consumer leaving must not stop delivery a RAN node is still \
             receiving: #295's set alone would have released here"
        );

        let rsp = amf_leg(
            amf_ctx_update_body_gnb(&svc, "208", "93", "MBS_DIS_REL_REQ", "n2SmInfo", "000001"),
            rel_container_208_93(svc_id),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session_plmn(svc_id, "208", "93")
                .n4mb_session
                .is_none(),
            "and the RAN node's release is then the last holder's"
        );
    }

    /// An AMF release carrying no usable `ranNodeId` releases on the first request, as
    /// it did before #301 — the same "cannot be tracked, so behave as before" rule #295
    /// states for an empty `nfcInstanceId`, and stated here rather than left to be
    /// discovered.
    #[tokio::test]
    async fn an_untracked_ran_node_releases_on_the_first_request() {
        let svc_id = [0xC3, 0x01, 0x05];
        let svc = seed_global_session_plmn(svc_id, "208", "93");

        // Setup with no ranNodeId at all: only the N2 container identifies the leg.
        let no_ran_node = format!(
            r#"{{"nfcInstanceId":"amf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"208","mnc":"93"}}}}}},"n2MbsSmInfo":{{"ngapIeType":"MBS_DIS_SETUP_REQ","ngapData":{{"contentId":"n2SmInfo"}}}}}}"#
        );
        let rsp = amf_leg(no_ran_node, setup_container_208_93(svc_id)).await;
        assert_eq!(rsp.status, 200);
        let session = stored_session_plmn(svc_id, "208", "93");
        assert!(
            session.ran_nodes.is_empty(),
            "an untracked RAN node is not in the set: keying it on nothing would make \
             every such node the SAME holder"
        );
        assert!(session.n4mb_session.is_some());

        let rel_no_ran_node = format!(
            r#"{{"nfcInstanceId":"amf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"208","mnc":"93"}}}}}},"n2MbsSmInfo":{{"ngapIeType":"MBS_DIS_REL_REQ","ngapData":{{"contentId":"n2SmInfo"}}}}}}"#
        );
        let rsp = amf_leg(rel_no_ran_node, rel_container_208_93(svc_id)).await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session_plmn(svc_id, "208", "93")
                .n4mb_session
                .is_none(),
            "with nothing tracked there is nothing to keep it up, which is the pre-#301 \
             behaviour"
        );
    }

    /// #295 criterion 4: a START from a consumer already in the set does not
    /// double-count, so a consumer that restarts and re-STARTs cannot pin the transport
    /// past its own departure.
    ///
    /// Also the empty-`nfcInstanceId` fallback: such a consumer cannot be tracked, so
    /// the first TERMINATE releases the transport exactly as it did before #295 —
    /// stated here rather than left to be discovered.
    #[tokio::test]
    async fn a_repeated_start_from_one_consumer_does_not_double_count() {
        let svc_id = [0xC2, 0x95, 0x02];
        let svc = seed_global_session(svc_id);

        for _ in 0..3 {
            let rsp = post_ctx_update(
                SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                    smf_ctx_update_body(&svc, "smf-a", "START"),
                    "application/json",
                ),
            )
            .await;
            assert_eq!(rsp.status, 200);
        }
        assert_eq!(
            stored_session(svc_id).consumers.len(),
            1,
            "three STARTs from one consumer are one consumer"
        );

        // One TERMINATE from it is therefore the last one.
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body(&svc, "smf-a", "TERMINATE"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session(svc_id).n4mb_session.is_none(),
            "a consumer that STARTed three times still holds the transport once"
        );

        // ---- an untrackable consumer keeps the pre-#295 behaviour ----
        //
        // #2157: dev only. An empty nfcInstanceId names no NF, so no verified
        // caller can match it and production refuses it 403 (#2060,
        // `refuse_foreign_nfc_instance`); only a dev deployment's anonymous
        // caller reaches this fallback. Declared here: this half used to pass
        // only after a sibling had set the override, and failed 403 alone.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let anon_id = [0xC2, 0x95, 0x03];
        let anon = seed_global_session(anon_id);
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(smf_ctx_update_body(&anon, "", "START"), "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 200, "an empty nfcInstanceId is not a rejection");
        assert!(
            stored_session(anon_id).consumers.is_empty(),
            "an empty nfcInstanceId names no consumer and must not be stored as one"
        );
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                smf_ctx_update_body(&anon, "", "TERMINATE"),
                "application/json",
            ),
        )
        .await;
        assert_eq!(rsp.status, 204);
        assert!(
            stored_session(anon_id).n4mb_session.is_none(),
            "with no trackable consumer the first TERMINATE releases, as before #295"
        );
    }

    // mbsmfd-03: ContextUpdate Terminate → 204; unknown session → 404.
    #[tokio::test]
    async fn test_router_context_update_terminate_and_unknown() {
        let svc = seed_global_session([0xC0, 0x02, 0x02]);
        // First Start so there is an N4mb context to release.
        let start = format!(
            r#"{{"nfcInstanceId":"smf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"requestedAction":"START"}}"#
        );
        let _ = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(start, "application/json"),
        )
        .await;

        let term = format!(
            r#"{{"nfcInstanceId":"smf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"requestedAction":"TERMINATE"}}"#
        );
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(term, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 204, "Terminate releases → 204");

        // An unknown TMGI is 404.
        let unknown = r#"{"nfcInstanceId":"smf-x","mbsSessionId":{"tmgi":{"mbsServiceId":"eeeeee","plmnId":{"mcc":"001","mnc":"01"}}},"requestedAction":"START"}"#;
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(unknown, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 404);
    }

    // ---- G1-2: ContextUpdate AMF path — real multipart N2 containers ----

    /// The G1-1 golden `MBS-DistributionSetupRequestTransfer` APER vector
    /// (TS 38.413 §9.3.5.7), hand-derived independently in
    /// `libs/nextgcore-ngap/src/mbs_transfer.rs` (GOLDEN_SETUP_REQ):
    /// TMGI = PLMN 208/93 (BCD `02 F8 39`) + service id `00 00 01`,
    /// areaSessionId=1, sharedNGU-UnicastTNLInformation = GTP tunnel
    /// 10.1.2.3 / TEID 0x00003039, no iE-Extensions.
    const GOLDEN_MBS_SETUP_REQ: [u8; 20] = [
        0x60, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0xF0, 0x0A, 0x01, 0x02,
        0x03, 0x00, 0x00, 0x30, 0x39,
    ];

    /// Hand-derived `MBS-DistributionReleaseRequestTransfer` (§9.3.5.10) for
    /// TMGI 208/93 / `C1 02 02`, cause = nas:normal-release(0). Same
    /// derivation as the G1-1 GOLDEN_REL_REQ vector — every field is
    /// byte-aligned, so only the TMGI octets differ:
    ///   byte0 = ext(0) area(0) tnl(0) iE-Ext(0) | MBS-SessionID
    ///           preamble 000 | TMGI align pad 0            = 0x00
    ///   bytes1-6 = TMGI 02 F8 39 C1 02 02
    ///   byte7 = Cause CHOICE nas (idx 2 of 6, 3 bits) 010 |
    ///           ENUM ext 0 | normal-release 00 | pad 00    = 0x40
    const GOLDEN_MBS_REL_REQ: [u8; 8] = [0x00, 0x02, 0xF8, 0x39, 0xC1, 0x02, 0x02, 0x40];

    /// Build an AMF ContextUpdate JSON body carrying an `n2MbsSmInfo`
    /// (field names typed from TS29532_Nmbsmf_MBSSession.yaml).
    fn amf_ctx_update_body(
        svc_hex: &str,
        mcc: &str,
        mnc: &str,
        ie_type: &str,
        content_id: &str,
    ) -> String {
        format!(
            r#"{{"nfcInstanceId":"amf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc_hex}","plmnId":{{"mcc":"{mcc}","mnc":"{mnc}"}}}}}},"ranNodeId":{{"gNbId":{{"bitLength":24,"gNBValue":"000001"}}}},"n2MbsSmInfo":{{"ngapIeType":"{ie_type}","ngapData":{{"contentId":"{content_id}"}}}}}}"#
        )
    }

    /// POST a ContextUpdate request through the real router.
    async fn post_ctx_update(req: SbiRequest) -> SbiResponse {
        mbsmf_sbi_request_handler(req).await
    }

    /// Contract check vs TS29532_Nmbsmf_MBSSession.yaml:236-283: every
    /// `RefToBinaryData.contentId` in the response JSON must resolve to a
    /// body part with Content-Id equal to it and Content-Type
    /// `application/vnd.3gpp.ngap`. A JSON-only body whose `n2MbsSmInfo`
    /// references a missing part (the old stub shape) is schema-invalid.
    fn check_ctx_update_rsp_contract(
        json: &str,
        parts: &[nextgcore_sbi::message::SbiPart],
    ) -> Result<(), String> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
        let mut stack = vec![&value];
        while let Some(v) = stack.pop() {
            match v {
                serde_json::Value::Object(map) => {
                    if let Some(cid) = map.get("contentId").and_then(|c| c.as_str()) {
                        let part = parts
                            .iter()
                            .find(|p| p.content_id.as_deref() == Some(cid))
                            .ok_or_else(|| format!("dangling contentId '{cid}': no body part"))?;
                        let ct = part.content_type.as_deref().unwrap_or("");
                        if !ct.eq_ignore_ascii_case(APPLICATION_NGAP) {
                            return Err(format!(
                                "part '{cid}' Content-Type '{ct}' != {APPLICATION_NGAP}"
                            ));
                        }
                    }
                    stack.extend(map.values());
                }
                serde_json::Value::Array(arr) => stack.extend(arr.iter()),
                _ => {}
            }
        }
        Ok(())
    }

    // G1-2 (legacy shape): a JSON-only AMF request (ranNodeId only, no
    // n2MbsSmInfo) now returns a REAL response-direction container part —
    // ngapIeType MBS_DIS_SETUP_RSP with no dangling contentId.
    #[tokio::test]
    async fn test_router_context_update_amf_n2() {
        let svc = seed_global_session([0xC0, 0x03, 0x03]);
        let body = format!(
            r#"{{"nfcInstanceId":"amf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"ranNodeId":{{"gNbId":{{"bitLength":24,"gNBValue":"000001"}}}}}}"#
        );
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 200);
        let parsed: types::ContextUpdateRspData =
            serde_json::from_str(rsp.http.content.as_deref().unwrap()).unwrap();
        let n2 = parsed.n2_mbs_sm_info.expect("N2 container produced");
        assert_eq!(
            n2.ngap_ie_type,
            types::NgapIeType::MbsDisSetupRsp,
            "response direction is MBS_DIS_SETUP_RSP (never *_REQ)"
        );
        // The referenced part is really attached (multipart/related is
        // auto-encoded by the SBI server when parts are present).
        check_ctx_update_rsp_contract(rsp.http.content.as_deref().unwrap(), &rsp.http.parts)
            .expect("contract: contentId resolves to an application/vnd.3gpp.ngap part");
        // The part decodes as a Setup Response Transfer (§9.3.5.8).
        let part = &rsp.http.parts[0];
        golden::decode_setup_response(&part.data)
            .expect("part decodes as MBS Distribution Setup Response Transfer");
    }

    // G1-2 round-trip: inbound multipart MBS_DIS_SETUP_REQ (G1-1 golden
    // bytes) → 200 multipart whose part decodes as MBS_DIS_SETUP_RSP with
    // the session's real N4mb transport, equal to the SMF-path cTeid.
    #[tokio::test]
    async fn test_router_context_update_amf_multipart_setup_roundtrip() {
        // Session TMGI must equal the golden container's TMGI:
        // PLMN 208/93, service id 000001.
        let svc = seed_global_session_plmn([0x00, 0x00, 0x01], "208", "93");
        let body = amf_ctx_update_body(&svc, "208", "93", "MBS_DIS_SETUP_REQ", "n2SmInfo");
        let req = SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
            .with_body(body, "application/json")
            .with_part(SbiPart::with_content(
                "n2SmInfo",
                APPLICATION_NGAP,
                bytes::Bytes::copy_from_slice(&GOLDEN_MBS_SETUP_REQ),
            ));
        let rsp = post_ctx_update(req).await;
        assert_eq!(rsp.status, 200);

        // JSON root: ngapIeType is the response direction, contentId resolves.
        let json = rsp.http.content.as_deref().unwrap();
        let parsed: types::ContextUpdateRspData = serde_json::from_str(json).unwrap();
        let n2 = parsed.n2_mbs_sm_info.expect("n2MbsSmInfo present");
        assert_eq!(n2.ngap_ie_type, types::NgapIeType::MbsDisSetupRsp);
        assert_eq!(n2.ngap_data.content_id, "n2MbsSmInfo");
        check_ctx_update_rsp_contract(json, &rsp.http.parts).expect("contract");

        // Binary part: decodes as §9.3.5.8 with the session's real N4mb TNL.
        let part = rsp
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n2MbsSmInfo"))
            .expect("response part n2MbsSmInfo");
        let decoded =
            golden::decode_setup_response(&part.data).expect("decodes as Setup Response Transfer");
        assert_eq!(decoded.tmgi, ([0x02, 0xF8, 0x39], [0x00, 0x00, 0x01]));
        assert!(decoded.activated);
        let tnl = decoded.tunnel.expect("shared NG-U multicast TNL present");

        // The decoded TNL matches the stored session's N4mb transport.
        let ctx = mbsmf_self();
        let tmgi = Tmgi {
            mbs_service_id: [0x00, 0x00, 0x01],
            plmn_id: PlmnId {
                mcc: "208".to_string(),
                mnc: "93".to_string(),
            },
        };
        let session = ctx
            .read()
            .unwrap()
            .session_find_by_tmgi(&tmgi)
            .expect("session");
        let n4mb = session.n4mb_session.as_ref().expect("n4mb allocated");
        assert_eq!(tnl.teid, n4mb.dl_teid);
        assert_eq!(tnl.multicast_address, n4mb.ll_ssm_dst.unwrap().octets());
        assert_eq!(tnl.source_address, n4mb.ll_ssm_src.unwrap().octets());
        // One QoS flow derived from the session model (QFI 1 / 5QI 9 default).
        assert_eq!(decoded.qfis, vec![session.qfi]);
        // The whole part is the hand-derived §9.3.5.8 octets for these values.
        assert_eq!(
            part.data[..],
            golden::setup_response_octets(decoded.tmgi, tnl, session.qfi, session.fiveqi)[..]
        );

        // Acceptance cross-check: the SMF Start path of the SAME session
        // reports the same cTeid in JSON as the decoded NGAP TNL TEID.
        let smf_body = format!(
            r#"{{"nfcInstanceId":"smf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"208","mnc":"93"}}}}}},"requestedAction":"START"}}"#
        );
        let smf_rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(smf_body, "application/json"),
        )
        .await;
        assert_eq!(smf_rsp.status, 200);
        let smf_parsed: types::ContextUpdateRspData =
            serde_json::from_str(smf_rsp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            smf_parsed.c_teid.expect("cTeid"),
            tnl.teid,
            "SMF-path JSON cTeid == decoded NGAP SharedNguMulticastTnl gtp_teid"
        );
    }

    // G1-2 fail-closed: a dangling contentId (no matching body part) → 400,
    // never a silent JSON-only 200.
    #[tokio::test]
    async fn test_router_context_update_amf_dangling_content_id_400() {
        let svc = seed_global_session([0xC1, 0x04, 0x04]);
        let body = amf_ctx_update_body(&svc, "001", "01", "MBS_DIS_SETUP_REQ", "missingPart");
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 400, "dangling contentId is fail-closed");
        assert!(rsp
            .http
            .content
            .as_deref()
            .unwrap_or("")
            .contains("MANDATORY_IE_INCORRECT"));
    }

    // G1-2 fail-closed: unknown ngapIeType (yaml anyOf open string) → 400.
    #[tokio::test]
    async fn test_router_context_update_amf_unknown_ie_type_400() {
        let svc = seed_global_session([0xC1, 0x05, 0x05]);
        let body = amf_ctx_update_body(&svc, "001", "01", "FUTURE_IE_TYPE", "n2SmInfo");
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json")
                .with_part(SbiPart::with_content(
                    "n2SmInfo",
                    APPLICATION_NGAP,
                    bytes::Bytes::copy_from_slice(&GOLDEN_MBS_SETUP_REQ),
                )),
        )
        .await;
        assert_eq!(rsp.status, 400, "unknown ngapIeType is fail-closed");
    }

    // G1-2 fail-closed: a response-direction ngapIeType in a request → 400
    // (TS 29.532 §5.3.2.5 step 1 only allows SETUP_REQ / REL_REQ inbound).
    #[tokio::test]
    async fn test_router_context_update_amf_response_direction_ie_type_400() {
        let svc = seed_global_session([0xC1, 0x06, 0x06]);
        let body = amf_ctx_update_body(&svc, "001", "01", "MBS_DIS_SETUP_RSP", "n2SmInfo");
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json")
                .with_part(SbiPart::with_content(
                    "n2SmInfo",
                    APPLICATION_NGAP,
                    bytes::Bytes::copy_from_slice(&GOLDEN_MBS_SETUP_REQ),
                )),
        )
        .await;
        assert_eq!(rsp.status, 400, "SETUP_RSP in a request is fail-closed");
    }

    // G1-2 fail-closed: the referenced part must be application/vnd.3gpp.ngap.
    #[tokio::test]
    async fn test_router_context_update_amf_wrong_part_content_type_400() {
        let svc = seed_global_session([0xC1, 0x07, 0x07]);
        let body = amf_ctx_update_body(&svc, "001", "01", "MBS_DIS_SETUP_REQ", "n2SmInfo");
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json")
                .with_part(SbiPart::with_content(
                    "n2SmInfo",
                    "application/json",
                    bytes::Bytes::copy_from_slice(&GOLDEN_MBS_SETUP_REQ),
                )),
        )
        .await;
        assert_eq!(rsp.status, 400, "non-NGAP part content-type is fail-closed");
    }

    // G1-2 fail-closed: TMGI inside the NGAP container must match
    // req.mbsSessionId.tmgi (golden bytes carry 208/93/000001; the JSON and
    // session use 001/01/C10303).
    #[tokio::test]
    async fn test_router_context_update_amf_tmgi_mismatch_400() {
        let svc = seed_global_session([0xC1, 0x03, 0x03]);
        let body = amf_ctx_update_body(&svc, "001", "01", "MBS_DIS_SETUP_REQ", "n2SmInfo");
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json")
                .with_part(SbiPart::with_content(
                    "n2SmInfo",
                    APPLICATION_NGAP,
                    bytes::Bytes::copy_from_slice(&GOLDEN_MBS_SETUP_REQ),
                )),
        )
        .await;
        assert_eq!(rsp.status, 400, "container/JSON TMGI mismatch is 400");
    }

    // G1-2 fail-closed: corrupt NGAP bytes → 400 with ProblemDetails
    // (assert NOT 200 — real decoding, not pass-through).
    #[tokio::test]
    async fn test_router_context_update_amf_corrupt_ngap_400() {
        let svc = seed_global_session([0xC1, 0x08, 0x08]);
        let body = amf_ctx_update_body(&svc, "001", "01", "MBS_DIS_SETUP_REQ", "n2SmInfo");
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json")
                .with_part(SbiPart::with_content(
                    "n2SmInfo",
                    APPLICATION_NGAP,
                    bytes::Bytes::from_static(&[0xFF, 0xFF, 0xFF]),
                )),
        )
        .await;
        assert_ne!(rsp.status, 200, "corrupt NGAP bytes must not yield 200");
        assert_eq!(rsp.status, 400);
        assert!(rsp
            .http
            .content
            .as_deref()
            .unwrap_or("")
            .contains("INVALID_MSG_FORMAT"));
    }

    // G1-2 release leg: MBS_DIS_REL_REQ golden bytes → 204 (spec 2b) and the
    // shared transport is released.
    #[tokio::test]
    async fn test_router_context_update_amf_release_golden_204() {
        let svc = seed_global_session_plmn([0xC1, 0x02, 0x02], "208", "93");
        // Establish first (AMF setup path) so there is a transport to release.
        let setup = amf_ctx_update_body(&svc, "208", "93", "MBS_DIS_SETUP_REQ", "n2SmInfo");
        // Minimal §9.3.5.7 container for this TMGI (no optionals):
        // byte0 = presence 0000 | preamble 000 | pad 0 = 0x00, then TMGI.
        let setup_bytes = [0x00, 0x02, 0xF8, 0x39, 0xC1, 0x02, 0x02];
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(setup, "application/json")
                .with_part(SbiPart::with_content(
                    "n2SmInfo",
                    APPLICATION_NGAP,
                    bytes::Bytes::copy_from_slice(&setup_bytes),
                )),
        )
        .await;
        assert_eq!(rsp.status, 200, "setup leg established");

        // Release with the hand-derived §9.3.5.10 container.
        let rel = amf_ctx_update_body(&svc, "208", "93", "MBS_DIS_REL_REQ", "n2SmInfo");
        let rsp = post_ctx_update(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(rel, "application/json")
                .with_part(SbiPart::with_content(
                    "n2SmInfo",
                    APPLICATION_NGAP,
                    bytes::Bytes::copy_from_slice(&GOLDEN_MBS_REL_REQ),
                )),
        )
        .await;
        assert_eq!(rsp.status, 204, "release → 204 (nothing to return)");

        // The stored session's shared transport is gone.
        let ctx = mbsmf_self();
        let tmgi = Tmgi {
            mbs_service_id: [0xC1, 0x02, 0x02],
            plmn_id: PlmnId {
                mcc: "208".to_string(),
                mnc: "93".to_string(),
            },
        };
        let session = ctx
            .read()
            .unwrap()
            .session_find_by_tmgi(&tmgi)
            .expect("session still exists");
        assert!(
            session.n4mb_session.is_none(),
            "shared transport released by MBS_DIS_REL_REQ"
        );
    }

    // G1-2 contract: the OLD stub-style response body (JSON referencing
    // contentId 'n2MbsSmInfo' with NO body part, request-direction ie type)
    // FAILS the yaml contract check; the new response construction passes.
    #[test]
    fn test_context_update_rsp_contract_rejects_old_stub_shape() {
        // Old stub shape (pre-G1-2): dangling RefToBinaryData.
        let old_stub = r#"{"n2MbsSmInfo":{"ngapIeType":"MBS_DIS_SETUP_REQ","ngapData":{"contentId":"n2MbsSmInfo"}}}"#;
        let err = check_ctx_update_rsp_contract(old_stub, &[]).unwrap_err();
        assert!(err.contains("dangling contentId"), "got: {err}");

        // New shape: real part attached via context_update_n2_response.
        let rsp = context_update_n2_response(
            types::NgapIeType::MbsDisSetupRsp,
            GOLDEN_MBS_SETUP_REQ.to_vec(),
        );
        assert_eq!(rsp.status, 200);
        check_ctx_update_rsp_contract(rsp.http.content.as_deref().unwrap(), &rsp.http.parts)
            .expect("new response construction satisfies the yaml contract");
        // Serialized field names match TS29532_Nmbsmf_MBSSession.yaml.
        let json = rsp.http.content.as_deref().unwrap();
        assert!(json.contains("\"ngapIeType\":\"MBS_DIS_SETUP_RSP\""));
        assert!(json.contains("\"ngapData\":{\"contentId\":\"n2MbsSmInfo\"}"));
        let part = &rsp.http.parts[0];
        assert_eq!(part.content_id.as_deref(), Some("n2MbsSmInfo"));
        assert_eq!(part.content_type.as_deref(), Some(APPLICATION_NGAP));
    }

    // G1-2: PLMN BCD encoding per TS 24.008 §10.5.1.3 (2- and 3-digit MNC).
    #[test]
    fn test_plmn_bcd_encoding() {
        assert_eq!(plmn_bcd("208", "93"), [0x02, 0xF8, 0x39]);
        assert_eq!(plmn_bcd("001", "01"), [0x00, 0xF1, 0x10]);
        assert_eq!(plmn_bcd("310", "410"), [0x13, 0x00, 0x14]);
    }

    // mbsmfd-04: TMGI Allocate → 200 + TmgiAllocated; Deallocate → 204.
    #[tokio::test]
    async fn test_router_tmgi_allocate_deallocate() {
        mbsmf_context_init(256);
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-tmgi/v1/tmgi")
                .with_body(r#"{"tmgiNumber":3}"#, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 200);
        let alloc: types::TmgiAllocated =
            serde_json::from_str(rsp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(alloc.tmgi_list.len(), 3);
        assert!(!alloc.expiration_time.is_empty());

        // Deallocate exactly the three we got back → 204.
        let list_json = serde_json::to_string(&alloc.tmgi_list).unwrap();
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::delete("/nmbsmf-tmgi/v1/tmgi").with_param("tmgi-list", list_json),
        )
        .await;
        assert_eq!(rsp.status, 204);
    }

    /// #65 acceptance: a conformant **percent-encoded** `tmgi-list` must be
    /// parsed, not answered 400.
    ///
    /// End to end over a real HTTP/2 connection, because that is the only place
    /// the defect lived. The handler and its `serde_json::from_str` were always
    /// fine, and `test_router_tmgi_allocate_deallocate` above — which calls the
    /// handler directly with an UNencoded param — passes whether or not the
    /// server decodes anything. Here the value goes onto the wire encoded (the
    /// client has encoded query values since #101) and can only arrive parseable
    /// if the server decodes it.
    ///
    /// Asserts 204 AND that the untouched TMGI survived: a deallocate-all
    /// fallback would also answer 204 while silently freeing everything, which is
    /// a worse outcome than the 400 this replaces.
    #[tokio::test]
    async fn percent_encoded_tmgi_list_deallocates_and_does_not_400() {
        mbsmf_context_init(256);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let server = SbiServer::on_listener(
            NextgcoreSbiServerConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], port))),
            port_listener,
        );
        server
            .start(mbsmf_sbi_request_handler)
            .await
            .expect("server start");
        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", port);

        // Allocate two so a targeted deallocate is distinguishable from all.
        let alloc = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.send_request(
                SbiRequest::post("/nmbsmf-tmgi/v1/tmgi")
                    .with_body(r#"{"tmgiNumber":2}"#, "application/json"),
            ),
        )
        .await
        .expect("bounded")
        .expect("allocate");
        assert_eq!(alloc.status, 200);
        let allocated: types::TmgiAllocated =
            serde_json::from_str(alloc.http.content.as_deref().unwrap()).expect("allocated");
        assert_eq!(allocated.tmgi_list.len(), 2);
        let survivor = context_tmgi_from(Some(&allocated.tmgi_list[1]));

        // Name ONLY the first, as a JSON array. `set_param` hands the client raw
        // JSON; what crosses the wire is `tmgi-list=%5B%7B%22mbsServiceId%22...`.
        let raw = serde_json::to_string(&vec![allocated.tmgi_list[0].clone()]).expect("json");
        let mut req = SbiRequest::delete("/nmbsmf-tmgi/v1/tmgi");
        req.http.set_param("tmgi-list", raw);
        let resp =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.send_request(req))
                .await
                .expect("bounded")
                .expect("deallocate");
        assert_eq!(
            resp.status, 204,
            "a percent-encoded tmgi-list must parse; 400 here means the server is \
             not decoding query values (TS 29.500 §5.2.10.2)"
        );

        // Positive assertion: the OTHER TMGI is still held, so the 204 came from
        // the targeted path and not from the deallocate-all fallback.
        assert!(
            mbsmf_self()
                .read()
                .map(|c| c.tmgi_expiry_of(&survivor).is_some())
                .unwrap_or(false),
            "only the named TMGI should have been freed; the untouched one is gone, \
             so the tmgi-list was not honoured"
        );

        server.stop().await.expect("stop");
    }

    // mbsmfd-10: only the spec resource set responds — `/members` is not exposed
    // (404) while `/contexts/update` is a real route (400 on a missing body, not
    // 404), with debug routes disabled.
    #[tokio::test]
    async fn test_router_only_spec_resources() {
        std::env::remove_var("MBSMF_DEBUG_ROUTES");
        mbsmf_context_init(256);

        // Non-spec /members route is absent → 404.
        let rsp = mbsmf_sbi_request_handler(SbiRequest::get(
            "/nmbsmf-mbssession/v1/mbs-sessions/mbs-sess-1/members",
        ))
        .await;
        assert_eq!(rsp.status, 404, "/members is not a spec resource");

        // Spec /contexts/update route exists → 400 (bad/missing body), not 404.
        let rsp = mbsmf_sbi_request_handler(SbiRequest::post(
            "/nmbsmf-mbssession/v1/mbs-sessions/contexts/update",
        ))
        .await;
        assert_eq!(rsp.status, 400, "/contexts/update exists (400, not 404)");
    }

    /// #1944 (R32 on #2057): `MBSMF_DEBUG_ROUTES` turns the debug routes on
    /// under the dev profile only; under production they are never served.
    ///
    /// REVERT-VERIFIED: with the profile not consulted, the production
    /// assertion fails.
    #[test]
    fn debug_routes_are_never_served_under_production_1944() {
        use nextgcore_sbi::security::SbiProfile;
        assert!(debug_routes_allowed(Some("1"), SbiProfile::Dev));
        assert!(!debug_routes_allowed(Some("1"), SbiProfile::Production));
        assert!(!debug_routes_allowed(Some(""), SbiProfile::Dev));
        assert!(!debug_routes_allowed(None, SbiProfile::Dev));
    }

    #[test]
    fn test_debug_routes_disabled_by_default() {
        std::env::remove_var("MBSMF_DEBUG_ROUTES");
        assert!(!debug_routes_enabled());
    }

    // ---- mbsmfd-05: subscription router integration tests ----

    /// #1865: the verified subscriber of the router tests below, so they pass
    /// under both SBI profiles (production refuses an anonymous subscribe).
    const TEST_NF_1865: &str = "aaaaaaaa-1865-4000-8000-0000000000a1";

    fn as_nf(mut r: SbiRequest) -> SbiRequest {
        r.oauth2_subject = Some(TEST_NF_1865.to_string());
        r
    }

    // Subscribe → 201 + Location; unsubscribe → 204; double-delete → 404.
    #[tokio::test]
    async fn test_router_status_subscribe_and_unsubscribe() {
        mbsmf_context_init(256);
        let body = r#"{"subscription":{"eventList":[{"eventType":"BROADCAST_DELIVERY_STATUS"}],"notifyUri":"http://nef:9000/notify"}}"#;
        let rsp = mbsmf_sbi_request_handler(
            as_nf(SbiRequest::post(
                "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions",
            ))
            .with_body(body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 201, "Status subscribe → 201");
        let loc = rsp.http.get_header("location").cloned();
        assert!(loc.is_some(), "Location header present");
        let sub_id = loc.unwrap().rsplit('/').next().unwrap().to_string();

        // Unsubscribe the subscription we just created → 204.
        let del = mbsmf_sbi_request_handler(as_nf(SbiRequest::delete(format!(
            "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/{sub_id}"
        ))))
        .await;
        assert_eq!(del.status, 204, "Status unsubscribe → 204");

        // Second delete → 404 (already removed).
        let del2 = mbsmf_sbi_request_handler(as_nf(SbiRequest::delete(format!(
            "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/{sub_id}"
        ))))
        .await;
        assert_eq!(del2.status, 404, "Second delete → 404");
    }

    // PATCH updates an existing Status subscription; PATCH on unknown ID → 404.
    #[tokio::test]
    async fn test_router_status_subscribe_update() {
        mbsmf_context_init(256);
        let create_body = r#"{"subscription":{"eventList":[{"eventType":"BROADCAST_DELIVERY_STATUS"}],"notifyUri":"http://nef/cb","notifyCorrelationId":"corr-orig"}}"#;
        let rsp = mbsmf_sbi_request_handler(
            as_nf(SbiRequest::post(
                "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions",
            ))
            .with_body(create_body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 201);
        let loc = rsp.http.get_header("location").cloned().unwrap();
        let sub_id = loc.rsplit('/').next().unwrap().to_string();

        // PATCH to replace notifyCorrelationId → 200 with updated doc.
        let patch_body =
            r#"[{"op":"replace","path":"/notifyCorrelationId","value":"corr-updated"}]"#;
        let upd = mbsmf_sbi_request_handler(
            as_nf(SbiRequest::patch(format!(
                "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/{sub_id}"
            )))
            .with_body(patch_body, "application/json-patch+json"),
        )
        .await;
        assert_eq!(upd.status, 200, "PATCH → 200");
        let doc: serde_json::Value =
            serde_json::from_str(upd.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["notifyCorrelationId"], "corr-updated");

        // PATCH on a random unknown ID → 404.
        let miss = mbsmf_sbi_request_handler(
            as_nf(SbiRequest::patch(
                "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/00000000-0000-0000-0000-000000000000",
            ))
            .with_body(patch_body, "application/json-patch+json"),
        )
        .await;
        assert_eq!(miss.status, 404, "PATCH unknown → 404");
    }

    // ContextStatus subscribe → 201 + Location; unsubscribe → 204.
    #[tokio::test]
    async fn test_router_ctx_status_subscribe_and_unsubscribe() {
        mbsmf_context_init(256);
        let body = r#"{"subscription":{"nfcInstanceId":"smf-1","mbsSessionId":{"tmgi":{"mbsServiceId":"010203","plmnId":{"mcc":"001","mnc":"01"}}},"eventList":[{"eventType":"SESSION_RELEASE"}],"notifyUri":"http://smf:8080/ctx-notify"}}"#;
        let rsp = mbsmf_sbi_request_handler(
            as_nf(SbiRequest::post(
                "/nmbsmf-mbssession/v1/mbs-sessions/contexts/subscriptions",
            ))
            .with_body(body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 201, "ContextStatus subscribe → 201");
        let loc = rsp.http.get_header("location").cloned();
        assert!(
            loc.as_deref()
                .unwrap_or("")
                .contains("/contexts/subscriptions/"),
            "Location under /contexts/subscriptions/"
        );
        let sub_id = loc.unwrap().rsplit('/').next().unwrap().to_string();

        let del = mbsmf_sbi_request_handler(as_nf(SbiRequest::delete(format!(
            "/nmbsmf-mbssession/v1/mbs-sessions/contexts/subscriptions/{sub_id}"
        ))))
        .await;
        assert_eq!(del.status, 204, "ContextStatus unsubscribe → 204");
    }

    // Session release with an active Status subscription produces a
    // subscription-store mutation (notify is fire-and-forget; the POST to a
    // loopback notifyUri will fail silently, which is expected in unit tests —
    // we verify the router returns 204 and the subscription count is unchanged
    // because the notify is to a different endpoint than the session).
    // ---- #76: create validation, TMGI allocation, SSM ContextUpdate ---------

    async fn post_create(body: serde_json::Value) -> SbiResponse {
        mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions")
                .with_body(body.to_string(), "application/json"),
        )
        .await
    }

    fn rsp_json(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}"))
            .expect("response body is not JSON")
    }

    /// #76 criterion 6: a missing mandatory `serviceType` is REFUSED, and the create
    /// response carries a structured `ingressTunAddr`.
    ///
    /// `serviceType` used to be defaulted (`_ => Multicast`), so a request omitting a
    /// mandatory IE succeeded and silently became a multicast session.
    /// `ingressTunAddr` used to be `format!("{:#010x}", gtp_teid)` — a hex TEID
    /// string where TS 29.571 declares an ARRAY of `TunnelAddress`, i.e. the one
    /// member a consumer needs in order to send traffic anywhere was unparseable.
    #[tokio::test]
    async fn create_refuses_a_missing_service_type_and_answers_a_structured_ingress_address() {
        mbsmf_context_init(256);

        let resp = post_create(serde_json::json!({ "mbsSession": {} })).await;
        assert_eq!(resp.status, 400, "body: {:?}", resp.http.content);
        assert_eq!(
            rsp_json(&resp)["cause"],
            serde_json::json!("MANDATORY_IE_MISSING")
        );

        let resp = post_create(serde_json::json!({
            "mbsSession": { "serviceType": "MULTICAST" }
        }))
        .await;
        assert_eq!(resp.status, 201);
        let body = rsp_json(&resp);
        let addrs = body["mbsSession"]["ingressTunAddr"]
            .as_array()
            .expect("ingressTunAddr is an ARRAY of TunnelAddress, minItems 1");
        assert_eq!(addrs.len(), 1);
        assert!(
            addrs[0]["ipv4Addr"].as_str().is_some(),
            "TunnelAddress is anyOf[ipv4Addr, ipv6Addr], got {}",
            addrs[0]
        );
        assert!(
            addrs[0]["portNumber"].as_u64().is_some(),
            "portNumber is REQUIRED in TunnelAddress, got {}",
            addrs[0]
        );
        assert!(
            !addrs[0].is_string(),
            "the hex-TEID-string form is what this replaces"
        );
    }

    /// #76 criterion 6, the round-trip half: a full `ExtMbsSession` keeps its
    /// `serviceArea`, `ssm`, QoS and security rather than dropping them.
    #[tokio::test]
    async fn a_full_ext_mbs_session_round_trips_its_write_only_members() {
        mbsmf_context_init(256);

        let resp = post_create(serde_json::json!({
            "mbsSession": {
                "serviceType": "MULTICAST",
                "ssm": { "sourceIpAddr": {"ipv4Addr": "10.1.1.1"},
                         "destIpAddr": {"ipv4Addr": "232.0.0.1"} },
                "mbsServiceArea": { "ncgiList": [{ "plmnId": {"mcc":"001","mnc":"01"},
                                                    "nrCellId": "000000001" }] },
                "mbsServInfo": { "mbsQoSReq": { "5qi": 7 } },
                "mbsSecurityContext": { "keyList": ["k1"] },
                "contactPcfInd": true,
                "areaSessionPolicyId": 42,
            }
        }))
        .await;
        assert_eq!(resp.status, 201, "body: {:?}", resp.http.content);
        let s = &rsp_json(&resp)["mbsSession"];
        assert_eq!(
            s["ssm"]["destIpAddr"]["ipv4Addr"],
            serde_json::json!("232.0.0.1")
        );
        assert!(
            s["mbsServiceArea"]["ncgiList"].is_array(),
            "serviceArea dropped"
        );
        assert_eq!(s["mbsServInfo"]["mbsQoSReq"]["5qi"], serde_json::json!(7));
        assert!(
            s["mbsSecurityContext"]["keyList"].is_array(),
            "security dropped"
        );
        assert_eq!(s["contactPcfInd"], serde_json::json!(true));
        assert_eq!(s["areaSessionPolicyId"], serde_json::json!(42));
    }

    /// #76 criterion 7: two no-TMGI creates yield two DISTINCT sessions.
    ///
    /// `context_tmgi_from` returned a hardcoded TMGI for the no-TMGI path, so every
    /// such create collided — and `session_add` overwrote `tmgi_hash` silently, so
    /// the earlier session stayed in the list reachable by nothing and its MB-UPF
    /// session could never be released.
    #[tokio::test]
    async fn two_no_tmgi_creates_get_two_sessions_from_the_pool() {
        mbsmf_context_init(256);

        let first = post_create(serde_json::json!({
            "mbsSession": { "serviceType": "MULTICAST", "tmgiAllocReq": true }
        }))
        .await;
        let second = post_create(serde_json::json!({
            "mbsSession": { "serviceType": "MULTICAST", "tmgiAllocReq": true }
        }))
        .await;
        assert_eq!(first.status, 201, "body: {:?}", first.http.content);
        assert_eq!(
            second.status, 201,
            "a second no-TMGI create must succeed, got {:?}",
            second.http.content
        );

        let first_tmgi = rsp_json(&first)["mbsSession"]["mbsSessionId"]["tmgi"].clone();
        let second_tmgi = rsp_json(&second)["mbsSession"]["mbsSessionId"]["tmgi"].clone();
        assert_ne!(
            first_tmgi, second_tmgi,
            "each allocated TMGI must be distinct, got {first_tmgi} twice"
        );
        // Both sessions must still be REACHABLE, which is what "the second did not
        // orphan the first" means in practice. Asserted per-session rather than on a
        // global count: the session store is process-global and sibling tests create
        // their own, so an absolute count is a race rather than an assertion.
        for (label, resp) in [("first", &first), ("second", &second)] {
            let path = resp.http.get_header("location").expect("Location").clone();
            let got = mbsmf_sbi_request_handler(SbiRequest::get(path)).await;
            assert!(
                got.status == 200 || got.status == 204,
                "the {label} session must still be retrievable, got {}",
                got.status
            );
        }
    }

    /// #76 criterion 9: a ContextUpdate identified by SSM is ACCEPTED.
    ///
    /// It used to be rejected `400 MANDATORY_IE_MISSING` for having no TMGI, so an
    /// SSM-identified multicast session could not be updated at all — by any
    /// consumer, ever — even though `MbsSessionId` is `anyOf(tmgi, ssm)`.
    #[tokio::test]
    async fn a_context_update_identified_by_ssm_is_accepted() {
        mbsmf_context_init(256);

        let ssm = serde_json::json!({
            "sourceIpAddr": { "ipv4Addr": "10.2.2.2" },
            "destIpAddr": { "ipv4Addr": "232.0.0.9" }
        });
        let created = post_create(serde_json::json!({
            "mbsSession": {
                "serviceType": "MULTICAST",
                "mbsSessionId": { "ssm": ssm },
            }
        }))
        .await;
        assert_eq!(created.status, 201, "body: {:?}", created.http.content);

        let resp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                serde_json::json!({
                    "nfcInstanceId": "smf-ssm",
                    "mbsSessionId": { "ssm": ssm },
                    "requestedAction": "TERMINATE",
                })
                .to_string(),
                "application/json",
            ),
        )
        .await;
        assert_eq!(
            resp.status, 204,
            "an SSM-identified ContextUpdate must be served, got {} {:?}",
            resp.status, resp.http.content
        );

        // An SSM no session carries is a 404 (a real lookup miss), not a 400.
        let resp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                serde_json::json!({
                    "nfcInstanceId": "smf-ssm",
                    "mbsSessionId": { "ssm": {
                        "sourceIpAddr": { "ipv4Addr": "10.9.9.9" },
                        "destIpAddr": { "ipv4Addr": "232.9.9.9" } } },
                    "requestedAction": "TERMINATE",
                })
                .to_string(),
                "application/json",
            ),
        )
        .await;
        assert_eq!(resp.status, 404);

        // Neither identifier is still a 400: the anyOf is unsatisfied.
        let resp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update").with_body(
                serde_json::json!({ "nfcInstanceId": "smf-ssm", "mbsSessionId": {} }).to_string(),
                "application/json",
            ),
        )
        .await;
        assert_eq!(resp.status, 400);
    }

    #[tokio::test]
    async fn test_router_release_fires_notify_path() {
        mbsmf_context_init(256);

        // Create a session.
        let create_body = r#"{"mbsSession":{"serviceType":"MULTICAST"}}"#;
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions")
                .with_body(create_body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 201);
        let loc = rsp.http.get_header("location").cloned().unwrap();
        let session_path = loc.clone();
        let session_id = loc.rsplit('/').next().unwrap().to_string();

        // Subscribe to SESSION_RELEASE on this notifyUri (unreachable in unit
        // tests — the notify POST is spawned async and fails silently).
        let sub_body = format!(
            r#"{{"subscription":{{"eventList":[{{"eventType":"SESSION_RELEASE"}}],"notifyUri":"http://127.0.0.1:1/notify","notifyCorrelationId":"rel-corr-{session_id}"}}}}"#
        );
        let sub_rsp = mbsmf_sbi_request_handler(
            as_nf(SbiRequest::post(
                "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions",
            ))
            .with_body(sub_body, "application/json"),
        )
        .await;
        assert_eq!(sub_rsp.status, 201);

        // Release the session — should return 204 (notify is spawned async).
        let del_rsp = mbsmf_sbi_request_handler(SbiRequest::delete(session_path.clone())).await;
        assert_eq!(del_rsp.status, 204, "Release → 204");
    }

    // Missing body on subscribe → 400; method not allowed on wrong verb → 405.
    #[tokio::test]
    async fn test_router_subscribe_bad_request_and_method() {
        mbsmf_context_init(256);

        // POST with no body → 400.
        let no_body = mbsmf_sbi_request_handler(as_nf(SbiRequest::post(
            "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions",
        )))
        .await;
        assert_eq!(no_body.status, 400);

        // PATCH on subscriptions collection → 405.
        let wrong_verb = mbsmf_sbi_request_handler(SbiRequest::patch(
            "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions",
        ))
        .await;
        assert_eq!(wrong_verb.status, 405);
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `mbsmf_sbi_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=MB_SMF, ES256-signed against the served JWKS) passes through.
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
            "iss": "NRF", "sub": "mbsmf-1", "aud": aud,
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
        super::mbsmf_context_init(256);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Mbsmf);
        let server = SbiServer::on_listener(cfg, port_listener);
        server
            .start(super::mbsmf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("mbsmf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "mbsmf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("mbsmf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "mbsmf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
        assert!(super::oauth2_required(on.to_str().unwrap()));
        let _ = std::fs::remove_file(off);
        let _ = std::fs::remove_file(on);
    }

    #[tokio::test]
    async fn test_oauth2_missing_token_rejected_401() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/nmbsmf-mbssession/v1/mbs-sessions"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_wrong_audience_rejected_403() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "nmbsmf-mbssession");
        let req = SbiRequest::get("/nmbsmf-mbssession/v1/mbs-sessions")
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
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "MB_SMF", "nmbsmf-mbssession");
        let req = SbiRequest::get("/nmbsmf-mbssession/v1/mbs-sessions/does-not-exist")
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
                build_mbsmf_nf_profile("id", host, 7777, nextgcore_sbi::types::UriScheme::Http);
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}

/// #1665: the outbound OAuth2 client follows the SBI security profile.
#[cfg(test)]
mod outbound_oauth2_1665_tests {
    use nextgcore_sbi::security::SbiProfile;
    use nextgcore_sbi::types::NfType;

    const NRF: &str = "http://127.0.0.10:7777";

    /// Under the `production` profile this MBSMF installs its token client with
    /// the `sbi.oauth2.require` knob off, so its service requests to the AMF, AUSF,
    /// SMF and UDM (which require a bearer under that profile, #63) carry one
    /// (TS 33.501 §13.4.1.1.2). Before #1665 it installed it only under the knob.
    #[test]
    fn the_production_profile_installs_the_outbound_oauth2_client_without_the_knob() {
        let oauth2 = super::outbound_oauth2_client(SbiProfile::Production, false, Some(NRF))
            .expect("production profile, knob off: the outbound OAuth2 client is installed");
        assert_eq!(oauth2.self_consumer().nf_type, NfType::Mbsmf);
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
            let profile = build_mbsmf_nf_profile("mbsmf-1791", "10.0.0.1", 7777, cfg.scheme);
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

/// #1863: TMGIs and MBS sessions are managed only by the consumer they were
/// allocated to / created by, Deallocate needs its `tmgi-list`, through the
/// real router.
#[cfg(test)]
mod tmgi_session_owner_tests_1863 {
    use super::*;

    const NEF_A: &str = "aaaaaaaa-1863-4000-8000-0000000000a1";
    const NEF_B: &str = "bbbbbbbb-1863-4000-8000-0000000000b2";

    fn as_nf(mut r: SbiRequest, id: &str) -> SbiRequest {
        r.oauth2_subject = Some(id.to_string());
        r
    }

    async fn allocate(owner: &str, n: u32) -> Vec<types::Tmgi> {
        let rsp = mbsmf_sbi_request_handler(as_nf(
            SbiRequest::post("/nmbsmf-tmgi/v1/tmgi")
                .with_body(format!(r#"{{"tmgiNumber":{n}}}"#), "application/json"),
            owner,
        ))
        .await;
        assert_eq!(rsp.status, 200, "{:?}", rsp.http.content);
        serde_json::from_str::<types::TmgiAllocated>(rsp.http.content.as_deref().unwrap())
            .unwrap()
            .tmgi_list
    }

    fn deallocate(list: &[types::Tmgi]) -> SbiRequest {
        SbiRequest::delete("/nmbsmf-tmgi/v1/tmgi")
            .with_param("tmgi-list", serde_json::to_string(list).unwrap())
    }

    /// REVERT-VERIFIED: with the missing-`tmgi-list` arm restored to
    /// "deallocate all" the bare DELETE answers 204 and empties the pool; with
    /// `may_manage` always true NEF-B's DELETE frees NEF-A's TMGI.
    #[tokio::test]
    async fn tmgi_deallocate_needs_a_list_and_frees_only_the_callers_tmgis_1863() {
        mbsmf_context_init(256);
        let mine = allocate(NEF_A, 2).await;
        let theirs = allocate(NEF_B, 1).await;
        let held = |list: &[types::Tmgi]| {
            list.iter()
                .filter(|t| {
                    mbsmf_self()
                        .read()
                        .unwrap()
                        .tmgi_allocation(&context_tmgi_from(Some(t)))
                        .is_some()
                })
                .count()
        };
        let all: Vec<types::Tmgi> = mine.iter().chain(&theirs).cloned().collect();

        // No tmgi-list: refused, nothing freed (it used to free the whole pool).
        let rsp =
            mbsmf_sbi_request_handler(as_nf(SbiRequest::delete("/nmbsmf-tmgi/v1/tmgi"), NEF_B))
                .await;
        assert_eq!(rsp.status, 400);
        assert!(rsp
            .http
            .content
            .as_deref()
            .unwrap_or("")
            .contains("MANDATORY_QUERY_PARAM_MISSING"));
        assert_eq!(held(&all), 3);

        // NEF-B lists one of NEF-A's TMGIs beside its own: 403, nothing freed.
        let mixed = [theirs[0].clone(), mine[0].clone()];
        let rsp = mbsmf_sbi_request_handler(as_nf(deallocate(&mixed), NEF_B)).await;
        assert_eq!(rsp.status, 403);
        assert_eq!(held(&all), 3);
        // Nor may NEF-B refresh NEF-A's.
        let refresh = SbiRequest::post("/nmbsmf-tmgi/v1/tmgi").with_body(
            serde_json::json!({ "tmgiList": [mine[0].clone()] }).to_string(),
            "application/json",
        );
        let rsp = mbsmf_sbi_request_handler(as_nf(refresh, NEF_B)).await;
        assert_eq!(rsp.status, 403);
        // An anonymous caller frees nothing either.
        let rsp = super::mbsmf_sbi_request_handler(deallocate(&mine)).await;
        assert_eq!(rsp.status, 403);
        assert_eq!(held(&all), 3);

        // Each owner frees its own.
        let rsp = mbsmf_sbi_request_handler(as_nf(deallocate(&mine), NEF_A)).await;
        assert_eq!(rsp.status, 204);
        let rsp = mbsmf_sbi_request_handler(as_nf(deallocate(&theirs), NEF_B)).await;
        assert_eq!(rsp.status, 204);
        assert_eq!(held(&all), 0);
    }

    /// REVERT-VERIFIED: with the Release check removed NEF-B's stale DELETE
    /// releases NEF-A's session (404 for NEF-A afterwards); with the Update
    /// check removed NEF-B's PATCH answers 204; with the TMGI check at create
    /// removed NEF-B creates a session on NEF-A's TMGI.
    #[tokio::test]
    async fn an_mbs_session_is_updated_and_released_by_its_creator_only_1863() {
        mbsmf_context_init(256);
        let tmgi = allocate(NEF_A, 1).await.remove(0);
        let create = |who: &str| {
            as_nf(
                SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions").with_body(
                    serde_json::json!({"mbsSession": {
                        "mbsSessionId": {"tmgi": tmgi.clone()},
                        "serviceType": "BROADCAST",
                    }})
                    .to_string(),
                    "application/json",
                ),
                who,
            )
        };
        // NEF-B cannot open a session on NEF-A's TMGI.
        assert_eq!(mbsmf_sbi_request_handler(create(NEF_B)).await.status, 403);
        let rsp = mbsmf_sbi_request_handler(create(NEF_A)).await;
        assert_eq!(rsp.status, 201, "{:?}", rsp.http.content);
        let location = rsp.http.get_header("location").cloned().unwrap();
        let id = location.rsplit('/').next().unwrap().to_string();
        assert!(id.starts_with("mbs-sess-") && id != "mbs-sess-1", "{id}");
        let uri = format!("/nmbsmf-mbssession/v1/mbs-sessions/{id}");
        let patch = || {
            SbiRequest::patch(uri.clone()).with_body(
                r#"[{"op":"replace","path":"/activityStatus","value":"INACTIVE"}]"#,
                "application/json-patch+json",
            )
        };
        assert_eq!(
            mbsmf_sbi_request_handler(as_nf(patch(), NEF_B))
                .await
                .status,
            403
        );
        assert_eq!(
            mbsmf_sbi_request_handler(as_nf(SbiRequest::delete(uri.clone()), NEF_B))
                .await
                .status,
            403
        );
        assert_eq!(
            super::mbsmf_sbi_request_handler(SbiRequest::delete(uri.clone()))
                .await
                .status,
            403,
            "anonymous"
        );
        let pool_id = parse_session_id(&id).unwrap();
        let session = mbsmf_self().read().unwrap().session_find_by_id(pool_id);
        assert_eq!(
            session.and_then(|s| s.owner).as_deref(),
            Some(NEF_A),
            "still there"
        );
        let rsp = mbsmf_sbi_request_handler(as_nf(SbiRequest::delete(uri.clone()), NEF_A)).await;
        assert_eq!(rsp.status, 204, "{:?}", rsp.http.content);
        assert!(mbsmf_self()
            .read()
            .unwrap()
            .session_find_by_id(pool_id)
            .is_none());
    }

    /// #1944: the debug routes (`/activate`, `/members*`) are the session
    /// creator's only. Another NF and an anonymous caller get 403, and the
    /// membership is unchanged; the creator joins and removes a UE. The
    /// handlers are called directly: the routes need `MBSMF_DEBUG_ROUTES`,
    /// a process-wide variable other tests clear.
    ///
    /// REVERT-VERIFIED: without the check in `handle_member_join`, NEF-B's join
    /// is 201; without it in `handle_member_leave`, NEF-B's leave removes
    /// NEF-A's UE (204); without it in `handle_mbs_session_activate`, NEF-B's
    /// activate is not refused 403.
    #[tokio::test]
    async fn debug_route_members_and_activate_are_the_creators_only_1944() {
        mbsmf_context_init(256);
        let tmgi = allocate(NEF_A, 1).await.remove(0);
        let rsp = mbsmf_sbi_request_handler(as_nf(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions").with_body(
                serde_json::json!({"mbsSession": {
                    "mbsSessionId": {"tmgi": tmgi},
                    "serviceType": "MULTICAST",
                }})
                .to_string(),
                "application/json",
            ),
            NEF_A,
        ))
        .await;
        assert_eq!(rsp.status, 201, "{:?}", rsp.http.content);
        let id = rsp
            .http
            .get_header("location")
            .and_then(|l| l.rsplit('/').next().map(str::to_string))
            .unwrap();
        let pool_id = parse_session_id(&id).unwrap();
        let members = || {
            mbsmf_self()
                .read()
                .unwrap()
                .session_find_by_id(pool_id)
                .map(|s| s.group_members.len())
                .unwrap()
        };
        let join = |who: Option<&str>| {
            let r = SbiRequest::post(format!("/nmbsmf-mbssession/v1/mbs-sessions/{id}/members"))
                .with_body(r#"{"supi":"imsi-001010000019440"}"#, "application/json");
            match who {
                Some(w) => as_nf(r, w),
                None => r,
            }
        };
        let leave = |who: &str| {
            as_nf(
                SbiRequest::delete(format!(
                    "/nmbsmf-mbssession/v1/mbs-sessions/{id}/members/imsi-001010000019440"
                )),
                who,
            )
        };

        assert_eq!(
            handle_member_join(&id, &join(Some(NEF_B))).await.status,
            403
        );
        assert_eq!(
            handle_member_join(&id, &join(None)).await.status,
            403,
            "anonymous"
        );
        assert_eq!(members(), 0);
        assert_eq!(
            handle_member_join(&id, &join(Some(NEF_A))).await.status,
            201
        );
        assert_eq!(members(), 1);
        let rsp = handle_member_leave(&id, "imsi-001010000019440", &leave(NEF_B)).await;
        assert_eq!(rsp.status, 403, "{:?}", rsp.http.content);
        assert_eq!(members(), 1, "NEF-B cannot remove NEF-A's UE");
        let activate = as_nf(
            SbiRequest::post(format!("/nmbsmf-mbssession/v1/mbs-sessions/{id}/activate")),
            NEF_B,
        );
        assert_eq!(
            handle_mbs_session_activate(&id, &activate).await.status,
            403
        );
        let rsp = handle_member_leave(&id, "imsi-001010000019440", &leave(NEF_A)).await;
        assert_eq!(rsp.status, 204, "{:?}", rsp.http.content);
        assert_eq!(members(), 0);
    }
}

/// #1865: a Status or ContextStatus subscription is modified or cancelled only
/// by the consumer that created it (TS 33.501 §13.4.1). Every request goes
/// through `mbsmf_sbi_request_handler`, so the routing that hands the caller to
/// each handler is covered as well as the check.
#[cfg(test)]
mod subscription_owner_tests_1865 {
    use super::*;

    const OWNER: &str = "aaaaaaaa-1865-4000-8000-0000000000b1";
    const OTHER: &str = "bbbbbbbb-1865-4000-8000-0000000000b2";

    fn with_identity(mut r: SbiRequest, cert: Option<&str>, token: Option<&str>) -> SbiRequest {
        r.peer_cert_nf_instance_id = cert.map(str::to_string);
        if cert.is_some() {
            // #2065: typed, as a consumer's certificate is (RFC 9310).
            r.peer_cert_nf_types = vec!["AF".into()];
        }
        r.oauth2_subject = token.map(str::to_string);
        r
    }

    /// The callers that must not manage OWNER's subscription: a foreign
    /// certificate, a foreign token, no identity at all, and OWNER's
    /// certificate with a foreign token.
    fn intruders() -> [(Option<&'static str>, Option<&'static str>); 4] {
        [
            (Some(OTHER), None),
            (None, Some(OTHER)),
            (None, None),
            (Some(OWNER), Some(OTHER)),
        ]
    }

    struct Kind {
        collection: &'static str,
        body: String,
        owner_of: fn(&str) -> Option<Option<String>>,
    }

    fn status_kind(tag: &str) -> Kind {
        Kind {
            collection: "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions",
            body: format!(
                r#"{{"subscription":{{"eventList":[{{"eventType":"BROADCAST_DELIVERY_STATUS"}}],"notifyUri":"http://nef/{tag}","notifyCorrelationId":"orig"}}}}"#
            ),
            owner_of: |id| mbsmf_self().read().unwrap().status_sub_owner(id),
        }
    }

    fn ctx_kind(tag: &str) -> Kind {
        Kind {
            collection: "/nmbsmf-mbssession/v1/mbs-sessions/contexts/subscriptions",
            body: format!(
                r#"{{"subscription":{{"nfcInstanceId":"smf-1","mbsSessionId":{{"tmgi":{{"mbsServiceId":"010203","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"eventList":[{{"eventType":"SESSION_RELEASE"}}],"notifyUri":"http://smf/{tag}","notifyCorrelationId":"orig"}}}}"#
            ),
            owner_of: |id| mbsmf_self().read().unwrap().ctx_sub_owner(id),
        }
    }

    async fn create(kind: &Kind, cert: Option<&str>, token: Option<&str>) -> SbiResponse {
        mbsmf_sbi_request_handler(with_identity(
            SbiRequest::post(kind.collection).with_body(&kind.body, "application/json"),
            cert,
            token,
        ))
        .await
    }

    fn patch(kind: &Kind, id: &str, value: &str) -> SbiRequest {
        SbiRequest::patch(format!("{}/{id}", kind.collection)).with_body(
            format!(r#"[{{"op":"replace","path":"/notifyCorrelationId","value":"{value}"}}]"#),
            "application/json-patch+json",
        )
    }

    /// REVERT-VERIFIED: with the owner dropped at create (`owner: None` in the
    /// SubEntry) the bound-owner assertion fails; with `refuse_sub_non_owner`
    /// short-circuited to the 404 arm only, every intruder PATCH and DELETE
    /// gets 200/204 and the 403 assertions fail; with the PATCH check removed
    /// alone, or the DELETE check removed alone, the matching assertion fails.
    async fn only_the_subscriber_manages(kind: Kind) {
        mbsmf_context_init(256);
        let rsp = create(&kind, Some(OWNER), None).await;
        assert_eq!(rsp.status, 201, "{:?}", rsp.http.content);
        let loc = rsp.http.get_header("location").cloned().unwrap();
        let id = loc.rsplit('/').next().unwrap().to_string();
        assert_eq!((kind.owner_of)(&id), Some(Some(OWNER.to_string())));

        for (cert, token) in intruders() {
            let r = mbsmf_sbi_request_handler(with_identity(
                patch(&kind, &id, "hijacked"),
                cert,
                token,
            ))
            .await;
            assert_eq!(r.status, 403, "PATCH by cert={cert:?} token={token:?}");
            let r = mbsmf_sbi_request_handler(with_identity(
                SbiRequest::delete(format!("{}/{id}", kind.collection)),
                cert,
                token,
            ))
            .await;
            assert_eq!(r.status, 403, "DELETE by cert={cert:?} token={token:?}");
            assert!((kind.owner_of)(&id).is_some(), "still stored");
        }

        // The owner, by token this time: the refused PATCHes changed nothing.
        let r =
            mbsmf_sbi_request_handler(with_identity(patch(&kind, &id, "owner"), None, Some(OWNER)))
                .await;
        assert_eq!(r.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["notifyCorrelationId"], "owner");
        let r = mbsmf_sbi_request_handler(with_identity(
            SbiRequest::delete(format!("{}/{id}", kind.collection)),
            Some(&OWNER.to_uppercase()),
            None,
        ))
        .await;
        assert_eq!(r.status, 204);
        assert_eq!((kind.owner_of)(&id), None);

        // Unknown stays 404, for anyone.
        let r = mbsmf_sbi_request_handler(with_identity(
            SbiRequest::delete(format!("{}/{id}", kind.collection)),
            Some(OTHER),
            None,
        ))
        .await;
        assert_eq!(r.status, 404);
    }

    #[tokio::test]
    async fn only_the_subscriber_manages_a_status_subscription_1865() {
        only_the_subscriber_manages(status_kind("own-status-1865")).await;
    }

    #[tokio::test]
    async fn only_the_subscriber_manages_a_context_status_subscription_1865() {
        only_the_subscriber_manages(ctx_kind("own-ctx-1865")).await;
    }

    /// REVERT-VERIFIED: with the create-side `owner_for_new_resource` replaced
    /// by `Ok(None)`, the mismatched subscribe gets 201 and is stored.
    #[tokio::test]
    async fn a_subscriber_whose_identities_disagree_stores_nothing_1865() {
        mbsmf_context_init(256);
        for (kind, event) in [
            (
                status_kind("mixed-status-1865"),
                "BROADCAST_DELIVERY_STATUS",
            ),
            (ctx_kind("mixed-ctx-1865"), "SESSION_RELEASE"),
        ] {
            let rsp = create(&kind, Some(OWNER), Some(OTHER)).await;
            assert_eq!(rsp.status, 403);
            let c = mbsmf_self();
            let c = c.read().unwrap();
            let stored = c
                .status_subs_matching(event, &None)
                .into_iter()
                .chain(c.ctx_subs_matching(event, &None))
                .any(|e| e.notify_uri.contains("mixed-"));
            assert!(!stored, "nothing stored for a refused subscribe");
        }
    }
}

/// #1795: the listener `main` builds follows the SBI security profile.
#[cfg(test)]
mod sbi_profile_tests_1795 {
    /// REVERT-VERIFIED: with `sbi_listener_config` returning its input, the
    /// production half serves cleartext and the helper fails naming MB-SMF.
    #[test]
    fn the_listener_follows_the_sbi_profile_1795() {
        nextgcore_sbi::test_support::assert_listener_follows_sbi_profile(
            nextgcore_sbi::types::NfType::Mbsmf,
            super::sbi_listener_config,
        );
    }
}
