//! NextGCore DCCF (Data Collection Co-ordination Function)
//!
//! The DCCF is a Rel-17 optional NF defined in 3GPP TS 23.288 §6.7.
//! It acts as a broker between data producers (AMF, SMF, PCF, etc.)
//! and analytics consumers (NWDAF, ADRF).  Core responsibilities:
//!
//! - Ndccf_DataManagement_Subscribe: consumer registers interest in
//!   network data events (UE location, NF load, QoS, etc.)
//! - Ndccf_DataManagement_Notify: forward collected data to consumers
//! - Ndccf_ContextDocument_Create: bind data subscription to analytics
//! - Routing: fan-out collected data to all matching subscribers

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_method_not_allowed, send_not_found, SbiServer, SbiServerConfig};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
mod coordination;
mod data_mgmt;

pub use context::*;

/// NextGCore DCCF - Data Collection Co-ordination Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-dccfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Data Collection Co-ordination Function (TS 23.288 §6.7)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/dccf.yaml")]
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

    /// SBI bind address
    /// Without it, `dccf.sbi.server[0].address` from the config file, else
    /// 127.0.0.1 (#1308, #1312). The port likewise defaults to the file, else 7816.
    #[arg(long)]
    sbi_addr: Option<String>,

    /// The SBI host advertised in the NRF NFProfile and callback URIs. Without it,
    /// `NEXTGCORE_SBI_ADVERTISE`, else `dccf.sbi.server[0].advertise`, else the
    /// bind address; a wildcard is never advertised (#1312).
    #[arg(long)]
    sbi_advertise: Option<String>,

    /// SBI port (TS 29.574 default: 7816)
    #[arg(long)]
    sbi_port: Option<u16>,

    /// Enable TLS for SBI
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// NRF URI for NF registration
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// Maximum concurrent data subscriptions
    #[arg(long, default_value = "4096")]
    max_subscriptions: usize,
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

/// DCCF SBI request handler (called by the SBI server per request).
async fn dccf_request_handler(req: SbiRequest) -> SbiResponse {
    let method = req.header.method.as_str();
    let uri = &req.header.uri;
    let path = uri.split('?').next().unwrap_or(uri);

    log::debug!(
        "DCCF SBI: {method} {}",
        nextgcore_sbi::log_redact::redact_callback_tokens(path)
    );

    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // ----------------------------------------------------------------
        // Health check
        // ----------------------------------------------------------------
        ["healthz"] => SbiResponse::ok().with_body(r#"{"status":"ok"}"#, "application/json"),

        // ----------------------------------------------------------------
        // Ndccf_DataManagement (TS 29.574 §5.2)
        // ----------------------------------------------------------------

        // POST /ndccf-datamanagement/v1/subscriptions
        ["ndccf-datamanagement", "v1", "subscriptions"] => match method {
            "POST" => handle_dm_subscribe(&req).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },

        // GET/PUT/DELETE /ndccf-datamanagement/v1/subscriptions/{subscriptionId}
        ["ndccf-datamanagement", "v1", "subscriptions", sub_id] => match method {
            "GET" => match dccf_context_get_subscription(sub_id) {
                // #112: echo the stored resource, not a bespoke
                // `{"subscriptionId":..,"status":"ACTIVE"}` body that no schema
                // defines and that a consumer cannot deserialise.
                Some(stored) => SbiResponse::ok()
                    .with_json_body(&stored.resource)
                    .unwrap_or_else(|_| SbiResponse::ok()),
                None => send_not_found("subscription not found", None),
            },
            // #112: `UpdateNWDAFDataSubscription` was absent and PUT answered 405.
            "PUT" => handle_dm_update(sub_id, &req).await,
            "DELETE" => handle_dm_unsubscribe(sub_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // POST /ndccf-datamanagement/v1/notify/dccf-data-notify/{token} — inbound
        // data from a producer, on the token of the producer subscription it is for
        // (#1518). The token-less `/notify` of before is gone: producer
        // subscriptions are held in memory only, so none made before a restart is
        // honoured anyway.
        ["ndccf-datamanagement", "v1", "notify", PRODUCER_NOTIFY_SEGMENT, token] => match method {
            "POST" => handle_dm_notify(token, &req).await,
            _ => send_method_not_allowed(method, "notify"),
        },

        // ----------------------------------------------------------------
        // Ndccf_ContextDocument (TS 29.574 §5.3)
        // ----------------------------------------------------------------

        // POST /ndccf-contextdocument/v1/contexts
        ["ndccf-contextdocument", "v1", "contexts"] => match method {
            "POST" => {
                let ctx_id = uuid::Uuid::new_v4().to_string();
                log::info!("[DCCF] ContextDocument context created ctx_id={ctx_id}");
                dccf_context_add_analytics_context(ctx_id.clone());
                let body = format!(r#"{{"contextId":"{ctx_id}"}}"#);
                SbiResponse::created().with_body(body, "application/json")
            }
            _ => send_method_not_allowed(method, "contexts"),
        },

        // GET/DELETE /ndccf-contextdocument/v1/contexts/{contextId}
        ["ndccf-contextdocument", "v1", "contexts", ctx_id] => match method {
            "GET" => {
                if dccf_context_has_analytics_context(ctx_id) {
                    let body = format!(r#"{{"contextId":"{ctx_id}"}}"#);
                    SbiResponse::ok().with_body(body, "application/json")
                } else {
                    send_not_found("context not found", None)
                }
            }
            "DELETE" => {
                dccf_context_remove_analytics_context(ctx_id);
                SbiResponse::no_content()
            }
            _ => send_method_not_allowed(method, "contexts/{id}"),
        },

        // ----------------------------------------------------------------
        // Fallthrough
        // ----------------------------------------------------------------
        _ => send_not_found("resource not found", None),
    }
}

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// enabled per-NF via `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` (overlay-friendly) or the
// `dccf.sbi.oauth2.require: true` yaml knob. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The installed outbound OAuth2 client, if any (Wave-6 H8 Phase A, #1663).
pub(crate) fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    #[cfg(test)]
    if let Ok(oauth2) = TEST_OAUTH2_CLIENT.try_with(Arc::clone) {
        return Some(oauth2);
    }
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

#[cfg(test)]
tokio::task_local! {
    /// #1663 tests: the OAuth2 client [`oauth2_client`] returns inside
    /// `TEST_OAUTH2_CLIENT.scope(..)`. Task-local, so the other tests in the
    /// process keep the default (none installed).
    pub(crate) static TEST_OAUTH2_CLIENT: Arc<nextgcore_sbi::oauth::OAuth2Client>;
}

/// #1755: spawn `fut` on its own task, so dropping the caller (a consumer request
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

/// #1663: `client` with the installed OAuth2 client attached, so a service
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

/// #1665: the outbound OAuth2 client this DCCF installs at startup: under the
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
        nextgcore_sbi::types::NfType::Dccf,
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
/// NRF JWKS and requires `aud` to include NfType::Dccf; with no NRF URI it
/// fails closed (503). `nrf_uri` empty ⇒ unconfigured ⇒ fail-closed.
fn apply_oauth2_enforcement(mut cfg: SbiServerConfig, nrf_uri: &str) -> SbiServerConfig {
    cfg.require_oauth2 = true;
    let uri = (!nrf_uri.is_empty()).then_some(nrf_uri);
    cfg.oauth2_jwks_uri = uri.map(|u| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(u)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Dccf);
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // #1312: the command line, else `dccf.sbi.server[0]` in the config file,
    // else loopback.
    let sbi = nextgcore_core::sockaddr::SbiEndpoint::resolve_from_file(
        args.sbi_addr.as_deref(),
        args.sbi_port,
        args.sbi_advertise.as_deref(),
        &args.config,
        "dccf",
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

    log::info!("NextGCore DCCF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Data Collection Co-ordination Function (3GPP TS 23.288 §6.7)");

    dccf_context_init(args.max_subscriptions);

    let nf_instance_id =
        nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Dccf)
            .to_string();

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let bind_addr: SocketAddr = nextgcore_core::sockaddr::parse_listen_addr(&sbi_addr, sbi_port)
        .context("Invalid SBI bind address")?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    nextgcore_core::sockaddr::warn_if_loopback_listener("SBI", &bind_addr, "--sbi-addr");
    log::info!("DCCF SBI listening on {bind_addr}");

    let mut sbi_config = SbiServerConfig::new(bind_addr)
        .with_oauth2_callback_exemptions(oauth2_callback_exemptions());
    if args.tls {
        if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
            sbi_config = sbi_config.with_tls(key, cert);
        }
    }
    let require_oauth2 = oauth2_required(&args.config);
    // #1665: the outbound token client follows the SBI security profile as well
    // as the knob. The production profile's AMF/AUSF/SMF/UDM demand a token on
    // every service request (TS 33.501 §13.4.1.1.2), whatever this listener asks.
    let _ = OAUTH2_CLIENT.set(outbound_oauth2_client(
        nextgcore_sbi::security::SbiProfile::resolve(),
        require_oauth2,
        Some(&args.nrf_uri),
    ));
    // #1667: the same client gives this NF's own NRF calls their access token.
    nextgcore_sbi::nrf_tls::set_nrf_oauth2_client(OAUTH2_CLIENT.get().cloned().flatten());
    if require_oauth2 {
        sbi_config = apply_oauth2_enforcement(sbi_config, &args.nrf_uri);
    }

    let sbi_server = SbiServer::new(sbi_config);
    sbi_server
        .start(dccf_request_handler)
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
                "DCCF",
                Default::default(),
                move || {
                    let (host, id) = (host.clone(), id.clone());
                    async move {
                        register_with_nrf(&host, sbi_port, &id)
                            .await
                            .map(|()| Some(id))
                    }
                },
                |nf_instance_id| {
                    // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
                    // (active data-collection subscriptions, saturated at 100;
                    // TS 29.510 §5.2.2.3.2). Honest subscription-count proxy — no
                    // fabricated CPU numbers.
                    nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                        nf_instance_id,
                        5,
                        || dccf_context_subscription_count().min(100) as u8,
                    );
                },
            )
            .await;
        }
        Err(e) => log::warn!("NRF registration not attempted (will operate without NRF): {e}"),
    }

    log::info!("NextGCore DCCF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("DCCF shutting down");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes away, so
    // the NRF stops handing this profile to consumers instead of waiting out its
    // supervision timer. Stopping the server first would open the bad window:
    // not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;

    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;

    dccf_context_final();
    log::info!("DCCF shutdown complete");
    Ok(())
}

/// Every Ndccf service this DCCF serves, with the NF types allowed to consume it
/// (TS 29.510 §6.1.6.2.3 `NFService.allowedNfTypes`).
///
/// ONE table, consumed by both [`build_dccf_nf_instance`] (the typed self
/// instance) and [`build_dccf_nf_profile`] (the NFProfile PUT to the NRF), so the
/// two cannot drift (#392).
const DCCF_SERVICES: &[(nextgcore_sbi::types::SbiServiceType, &[&str])] = &[
    // TS 29.574 Ndccf_DataManagement (TS 23.288 §8.2).
    (
        nextgcore_sbi::types::SbiServiceType::NdccfDatamanagement,
        &["NWDAF", "AMF", "SMF", "PCF", "NEF", "SCP"],
    ),
    // TS 29.574 Ndccf_ContextManagement (TS 23.288 §8.3), served at
    // `/ndccf-contextdocument/v1/contexts`. #392: routed with a real context
    // store but absent from the registered profile, and the NRF filters
    // discovery on `nfServices[].serviceName`, so no consumer could find it.
    (
        nextgcore_sbi::types::SbiServiceType::NdccfContextdocument,
        &["NWDAF", "SCP"],
    ),
];

/// Build this DCCF's typed self NF instance from [`DCCF_SERVICES`].
fn build_dccf_nf_instance(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
) -> nextgcore_sbi::context::NfInstance {
    let mut self_instance =
        nextgcore_sbi::context::NfInstance::new(nf_instance_id, nextgcore_sbi::types::NfType::Dccf);
    nextgcore_sbi::nf_addressing::set_instance_host(&mut self_instance, sbi_addr);
    self_instance.heartbeat_interval = 10;
    for (service_type, _allowed) in DCCF_SERVICES {
        let mut svc = nextgcore_sbi::context::NfService::new(service_type.to_name(), *service_type);
        svc.port = sbi_port;
        nextgcore_sbi::nf_addressing::set_service_host(&mut svc, sbi_addr);
        self_instance.add_service(svc);
    }
    self_instance
}

/// Build the DCCF's NFProfile for NRF registration (TS 29.510 §6.1.6.2.2).
///
/// Split out of [`register_with_nrf`] so a test can assert the advertised service
/// list without standing up an NRF. Each service carries its own `ipEndPoints`
/// and `allowedNfTypes`; the NF-level `allowedNfTypes` is the UNION over the
/// services, since a type barred at NF level can never reach any service.
fn build_dccf_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    let services: Vec<serde_json::Value> = DCCF_SERVICES
        .iter()
        .map(|(service_type, allowed)| {
            let name = service_type.to_name();
            serde_json::json!({
                "serviceInstanceId": format!("{nf_instance_id}-{name}"),
                "serviceName": name,
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
                "allowedNfTypes": allowed,
            })
        })
        .collect();

    let mut nf_allowed: Vec<&str> = Vec::new();
    for (_, allowed) in DCCF_SERVICES {
        for t in *allowed {
            if !nf_allowed.contains(t) {
                nf_allowed.push(t);
            }
        }
    }

    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "DCCF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": services,
            "allowedNfTypes": nf_allowed,
            "heartBeatTimer": 10
        }),
        sbi_addr,
    )
}

/// Register DCCF with NRF
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

    log::info!("Registering DCCF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = build_dccf_nf_profile(nf_instance_id, sbi_addr, sbi_port);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("DCCF registered with NRF successfully (id={nf_instance_id})");
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&nf_profile);

            // From the SAME table the profile came from: it used to be built here
            // with `ndccf-datamanagement` alone (#392).
            sbi_ctx
                .set_self_instance(build_dccf_nf_instance(nf_instance_id, sbi_addr, sbi_port))
                .await;

            Ok(())
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

// ---------------------------------------------------------------------------
// #112: Ndccf_DataManagement handlers (TS 29.574, schema-mirrored from
// TS29520_Nnwdaf_DataManagement.yaml)
// ---------------------------------------------------------------------------

/// Resource collection path for data-management subscriptions; the `Location`
/// header of a created subscription is built from it.
const DM_SUBSCRIPTIONS_PATH: &str = "/ndccf-datamanagement/v1/subscriptions";

/// A `400` with a conformant `application/problem+json` body (TS 29.500 §5.2.7).
///
/// The old subscribe path parsed the body with `unwrap_or_default()`, so a
/// missing or unparseable body still answered `201` for a subscription that could
/// never work.
fn bad_request(detail: &str, cause: &str) -> SbiResponse {
    nextgcore_sbi::server::send_bad_request(detail, Some(cause))
}

/// Parse and validate a subscribe/update body.
///
/// The error is boxed: `SbiResponse` is ~300 bytes, and a `Result` whose `Err`
/// dwarfs its `Ok` makes every caller pay for the failure path
/// (`clippy::result_large_err`). Same shape as eesd's `parse_json_body`.
#[allow(clippy::result_large_err)]
fn parse_subsc(req: &SbiRequest) -> Result<data_mgmt::DataManagementSubsc, Box<SbiResponse>> {
    let Some(body) = req.http.content.as_deref().filter(|b| !b.trim().is_empty()) else {
        return Err(Box::new(bad_request(
            "A request body is required (NnwdafDataManagementSubsc)",
            "MANDATORY_IE_MISSING",
        )));
    };
    let sub: data_mgmt::DataManagementSubsc = serde_json::from_str(body).map_err(|e| {
        Box::new(bad_request(
            &format!("Unparseable NnwdafDataManagementSubsc: {e}"),
            "INVALID_MSG_FORMAT",
        ))
    })?;
    sub.validate()
        .map_err(|e| Box::new(bad_request(e.detail(), "MANDATORY_IE_MISSING")))?;
    Ok(sub)
}

/// `POST /ndccf-datamanagement/v1/subscriptions` — subscribe (#112).
///
/// Four defects fixed here at once: the callback is read from `notificURI`
/// (not the bespoke `notifyUri`), the body is validated with a `400` +
/// ProblemDetails instead of `unwrap_or_default()`, the `201` carries the
/// mandatory `Location` header and echoes the resource, and the subscription's
/// scope is recorded so the fan-out can be keyed on it.
async fn handle_dm_subscribe(req: &SbiRequest) -> SbiResponse {
    let sub = match parse_subsc(req) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let sub_id = uuid::Uuid::new_v4().to_string();
    let scope = data_mgmt::SubscriptionScope::from_subsc(&sub);
    log::info!(
        "[DCCF] DataManagement subscribe sub_id={sub_id} notifCorrId={} notificURI={} events={:?}",
        sub.notif_corr_id,
        nextgcore_sbi::log_redact::redact_last_segment(&sub.notific_uri),
        scope.events
    );

    let stored = dccf_context_store_subscription(context::DccfSubscription {
        id: sub_id.clone(),
        notify_uri: sub.notific_uri.clone(),
        notif_corr_id: sub.notif_corr_id.clone(),
        scope: scope.clone(),
        resource: sub.clone(),
    });
    if !stored {
        return nextgcore_sbi::server::send_error(
            507,
            "Insufficient Storage",
            "Subscription capacity exhausted",
            Some("INSUFFICIENT_RESOURCES"),
        );
    }

    // TS 23.288 §5A.2: collect once, share to many. Off by default; see
    // `coordination.rs` for why this is a runtime switch and not a cargo feature.
    // A coordination failure does not fail the consumer's subscription: the
    // consumer's contract is with the DCCF, and refusing it would make an
    // unreachable producer look like a malformed request.
    let outcome = coordination::ensure_producer_subscription(&sub_id, &scope, &sub).await;
    log::debug!("[DCCF] coordination for {sub_id}: {outcome:?}");

    SbiResponse::created()
        .with_header("Location", format!("{DM_SUBSCRIPTIONS_PATH}/{sub_id}"))
        .with_json_body(&sub)
        .unwrap_or_else(|_| SbiResponse::created())
}

/// `PUT /ndccf-datamanagement/v1/subscriptions/{subscriptionId}` —
/// `UpdateNWDAFDataSubscription` (#112). Previously answered `405`.
///
/// A full replace, which is what PUT means: the new body is validated exactly as
/// on create, and the recorded scope is recomputed so a changed `anaSub` changes
/// what the consumer receives. `404` when the resource does not exist — PUT here
/// updates an existing subscription and does not create one at a
/// consumer-chosen id.
async fn handle_dm_update(sub_id: &str, req: &SbiRequest) -> SbiResponse {
    if !dccf_context_has_subscription(sub_id) {
        return send_not_found("subscription not found", None);
    }
    let sub = match parse_subsc(req) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = data_mgmt::SubscriptionScope::from_subsc(&sub);
    log::info!(
        "[DCCF] DataManagement update sub_id={sub_id} events={:?}",
        scope.events
    );
    dccf_context_store_subscription(context::DccfSubscription {
        id: sub_id.to_string(),
        notify_uri: sub.notific_uri.clone(),
        notif_corr_id: sub.notif_corr_id.clone(),
        scope,
        resource: sub.clone(),
    });
    SbiResponse::ok()
        .with_json_body(&sub)
        .unwrap_or_else(|_| SbiResponse::ok())
}

/// `DELETE /ndccf-datamanagement/v1/subscriptions/{subscriptionId}` (#112).
///
/// Releases this consumer's claim on its producer subscription, and deletes that
/// producer subscription when it was the last consumer — refcounted, so one
/// consumer unsubscribing cannot cut off another's data.
async fn handle_dm_unsubscribe(sub_id: &str) -> SbiResponse {
    if !remove_consumer_subscription(sub_id).await {
        return send_not_found("subscription not found", None);
    }
    log::info!("[DCCF] DataManagement subscription deleted sub_id={sub_id}");
    SbiResponse::no_content()
}

/// Remove a consumer subscription and release its producer claim, deleting the
/// producer subscription at the producer when it was the last consumer. `false`
/// when there was no such subscription.
async fn remove_consumer_subscription(sub_id: &str) -> bool {
    if !dccf_context_remove_subscription(sub_id) {
        return false;
    }
    if let Some(orphaned) = dccf_context_release_producer_sub(sub_id) {
        // One still being created is deleted when its create completes.
        if let Some(uri) = orphaned.resource_uri.as_deref() {
            coordination::delete_producer_subscription(uri).await;
        }
    }
    true
}

/// The producer notify callback, admitted without an OAuth2 bearer when the
/// listener requires one (#1518): a notification carries no access token (TS
/// 33.501 §13.4.1, TS 29.500 §6.10.7 NOTE). It needs the producer subscription's
/// token AND a verified mutual-TLS peer that is the producer NF instance the
/// subscription was created on: producer event-exposure subscriptions can be read
/// back by other consumers of the producer (the #1522 rule). Without a verified
/// certificate the route stays on the bearer.
fn oauth2_callback_exemptions() -> Vec<nextgcore_sbi::server::OAuth2CallbackExemption> {
    vec![
        nextgcore_sbi::server::OAuth2CallbackExemption::for_verified_peer(
            "POST",
            format!("/ndccf-datamanagement/v1/notify/{PRODUCER_NOTIFY_SEGMENT}/{{token}}"),
            |cb, peer| async move {
                dccf_context_producer_for_token(&cb.token)
                    .is_some_and(|producer| same_nf_instance(&producer, &peer.nf_instance_id))
            },
        ),
    ]
}

/// Whether two NF instance ids name the same instance: UUIDs compare
/// case-insensitively, with or without the `urn:uuid:` prefix a certificate's URI
/// SAN carries.
fn same_nf_instance(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        let s = s.trim();
        s.strip_prefix("urn:uuid:")
            .unwrap_or(s)
            .to_ascii_lowercase()
    };
    !a.trim().is_empty() && norm(a) == norm(b)
}

/// The segment before the token in a producer `notificationURI` (#1518).
const PRODUCER_NOTIFY_SEGMENT: &str = "dccf-data-notify";

/// `POST /ndccf-datamanagement/v1/notify/dccf-data-notify/{token}` — inbound
/// producer data (#112).
///
/// #1518: acted on only for the producer subscription holding `token`, whatever
/// admitted the request, and fanned out only to that subscription's consumers.
/// Any other token is 404, and nothing is sent.
///
/// Two defects fixed: the fan-out is keyed on `(events, target)` instead of
/// going to every subscriber with a callback URI, and each consumer receives a
/// conformant `NnwdafDataManagementNotif` echoing **its own** `notifCorrId`
/// instead of a bespoke `{"data": "<stringified body>"}` envelope.
///
/// Because each consumer's body differs (its own correlation id), the
/// notification is built per target rather than once and broadcast.
async fn handle_dm_notify(token: &str, req: &SbiRequest) -> SbiResponse {
    if dccf_context_producer_for_token(token).is_none() {
        return send_not_found(
            "no producer subscription holds this callback",
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    }
    let raw = req.http.content.as_deref().unwrap_or("{}");
    let body: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return bad_request(
                &format!("Unparseable producer notification: {e}"),
                "INVALID_MSG_FORMAT",
            )
        }
    };
    let notif_scope = data_mgmt::SubscriptionScope::from_notification(&body);
    log::debug!(
        "[DCCF] notify received: events={:?} target={:?} len={}",
        notif_scope.events,
        notif_scope.target,
        raw.len()
    );

    let Some(targets) = dccf_context_fanout_for_token(token, &notif_scope) else {
        return send_not_found(
            "no producer subscription holds this callback",
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    };
    let timestamp = rfc3339_now();
    for (sub_id, notify_uri, notif_corr_id) in targets {
        let Some((host, port)) = parse_host_port(&notify_uri) else {
            log::warn!(
                "[DCCF] subscriber {sub_id} has unparseable notificURI: {notify_uri}",
                notify_uri = nextgcore_sbi::log_redact::redact_last_segment(&notify_uri)
            );
            continue;
        };
        let path = notify_uri
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let path_owned = path
            .find('/')
            .map(|i| path[i..].to_string())
            .unwrap_or_else(|| "/".to_string());
        let notif = data_mgmt::DataManagementNotif::with_data(
            notif_corr_id,
            timestamp.clone(),
            body.clone(),
        );
        let client = SbiClient::for_peer(&host, port);
        tokio::spawn(async move {
            match client.post_json(&path_owned, &notif).await {
                // The consumer no longer has the subscription (TS 29.500 §6.2.3: a
                // 404 to a notification should end it, SUBSCRIPTION_NOT_FOUND, and
                // may for any other 404), so neither does this DCCF.
                Ok(resp) if resp.status == 404 => {
                    log::info!("[DCCF] consumer of {sub_id} answered 404; subscription removed");
                    remove_consumer_subscription(&sub_id).await;
                }
                Ok(resp) => {
                    log::debug!("[DCCF] fanout POST {sub_id} -> status={}", resp.status)
                }
                Err(e) => log::warn!("[DCCF] fanout POST {sub_id} failed: {e}"),
            }
        });
    }
    SbiResponse::no_content()
}

/// Current time as an RFC 3339 UTC timestamp, for `notifTimestamp`.
///
/// Delegates to the shared SBI formatter rather than hand-rolling one: the
/// per-daemon copies of this were consolidated for a reason (a copy that
/// formats a pre-epoch instant wrongly, or omits the `Z`, produces a `DateTime`
/// a conformant consumer rejects).
fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    nextgcore_sbi::datetime::epoch_to_rfc3339_signed(secs)
}

/// Parse host and port from a URI string
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
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `dccf_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=DCCF, ES256-signed against the served JWKS) passes through.
    use super::dccf_request_handler;
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
            "iss": "NRF", "sub": "dccf-1", "aud": aud,
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
        super::dccf_context_init(256);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Dccf);
        let server = SbiServer::on_listener(cfg, port_listener);
        server
            .start(dccf_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("dccf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "dccf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("dccf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "dccf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
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
            client.get("/ndccf-datamanagement/v1/subscriptions"),
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
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "ndccf-datamanagement");
        let req = SbiRequest::get("/ndccf-datamanagement/v1/subscriptions")
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
        let token = build_es256_token(&sk, "nrf-es256", "DCCF", "ndccf-datamanagement");
        let req = SbiRequest::get("/ndccf-datamanagement/v1/subscriptions/does-not-exist")
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

// ---------------------------------------------------------------------------
// #112: Ndccf_DataManagement conformance and coordination
// ---------------------------------------------------------------------------
#[cfg(test)]
mod data_management_tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    /// Serialises these tests: they share the process-global DCCF context (its
    /// subscription map and producer-subscription registry) and the coordination
    /// switch.
    ///
    /// The CRATE-WIDE lock from `context`, not a private one: `context::tests`
    /// mutates the same singleton, and `clear_subscriptions` below would otherwise
    /// wipe a subscription a `context::tests` case was mid-way through asserting
    /// on.
    use context::GLOBAL_TEST_LOCK as TEST_GUARD;

    fn init() {
        dccf_context_init(256);
    }

    /// Remove every subscription, so a test's assertions are about its own
    /// subscriptions and not whatever a sibling left behind. The context is
    /// process-global, and `GLOBAL` locks serialise but do not isolate.
    ///
    /// Releases each consumer's producer-subscription claim as well, as
    /// `handle_dm_unsubscribe` does: removing only the consumer record left the
    /// producer subscription behind, so whichever test took the lock next
    /// inherited it (`coordination_off_creates_no_producer_subscription` failed
    /// with a count of 1 when it ran after the coordination test). No remote
    /// DELETE is sent, since the loopback producer is already stopped by then.
    fn clear_subscriptions() {
        for id in context::dccf_context_subscription_ids() {
            dccf_context_remove_subscription(&id);
            dccf_context_release_producer_sub(&id);
        }
    }

    fn subscribe_body(corr: &str, uri: &str, event: &str) -> String {
        serde_json::json!({
            "notifCorrId": corr,
            "notificURI": uri,
            "anaSub": {"eventSubscriptions": [{"event": event}]}
        })
        .to_string()
    }

    /// The sub id in a 201's `Location`.
    fn created_id(resp: &SbiResponse) -> String {
        resp.http
            .get_header("location")
            .expect("Location")
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    }

    /// Hold a producer subscription on `producer` for consumer `sub_id`'s scope,
    /// as coordination does before its create (#1518), and return its token.
    fn claim_producer_token(sub_id: &str, producer: &str) -> String {
        let scope = dccf_context_get_subscription(sub_id).expect("stored").scope;
        match context::dccf_context_claim_producer_sub(sub_id, &scope, Some(producer)) {
            context::ProducerClaim::NeedsCreate { notify_token, .. } => {
                notify_token.as_str().to_string()
            }
            other => panic!("expected a fresh claim, got {other:?}"),
        }
    }

    /// The producer notify path for `token` (#1518).
    fn notify_path(token: &str) -> String {
        format!("{}/{token}", coordination::PRODUCER_NOTIFY_PREFIX)
    }

    fn post(path: &str, body: &str) -> SbiResponse {
        let req = SbiRequest::post(path).with_body(body.to_string(), "application/json");
        futures_lite_block_on(dccf_request_handler(req))
    }

    /// Minimal block_on: this crate has tokio but these handler calls need no
    /// reactor beyond what the runtime provides.
    fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fut)
    }

    /// A loopback consumer that records the notification bodies it receives.
    async fn spawn_consumer() -> (SbiServer, u16, Arc<StdMutex<Vec<serde_json::Value>>>) {
        let seen: Arc<StdMutex<Vec<serde_json::Value>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = seen.clone();
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let server = SbiServer::on_listener(
            SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
            port_listener,
        );
        server
            .start(move |req: SbiRequest| {
                let sink = sink.clone();
                async move {
                    if let Some(body) = req.http.content.as_deref() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                            sink.lock().unwrap_or_else(|e| e.into_inner()).push(v);
                        }
                    }
                    SbiResponse::no_content()
                }
            })
            .await
            .expect("consumer server start");
        (server, port, seen)
    }

    /// #392: the registered NFProfile advertises `ndccf-contextdocument` as well
    /// as `ndccf-datamanagement`.
    ///
    /// Positive on both names. `ndccf-contextdocument` (TS 29.574 §5.3 /
    /// TS 23.288 §8.3 Ndccf_ContextManagement) is routed against a real context
    /// store, but was absent from the registered profile — and the NRF filters
    /// discovery strictly on `nfServices[].serviceName`, so an NWDAF registering
    /// an analytics context could not find this DCCF by service name.
    #[test]
    fn the_dccf_profile_advertises_both_routed_ndccf_services() {
        let profile = build_dccf_nf_profile("dccf-test-instance", "10.45.0.12", 7813);
        let names: Vec<&str> = profile["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .map(|s| s["serviceName"].as_str().expect("serviceName"))
            .collect();

        assert!(
            names.contains(&"ndccf-datamanagement"),
            "advertised: {names:?}"
        );
        assert!(
            names.contains(&"ndccf-contextdocument"),
            "the DCCF routes /ndccf-contextdocument/v1/contexts but does not advertise the \
             service, so the NRF drops this DCCF from a SearchResult filtered on it. \
             Advertised: {names:?}"
        );

        for svc in profile["nfServices"].as_array().expect("nfServices") {
            let name = svc["serviceName"].as_str().unwrap_or_default();
            let eps = svc["ipEndPoints"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} carries no ipEndPoints"));
            assert_eq!(eps[0]["port"].as_u64(), Some(7813), "{name} port");
            assert!(
                svc["allowedNfTypes"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
                "{name} must state its allowedNfTypes (TS 29.510 §6.1.6.2.3)"
            );
        }
    }

    /// #392: the typed self instance and the registered profile advertise the SAME
    /// surface, because both render `DCCF_SERVICES`.
    #[test]
    fn the_dccf_self_instance_matches_the_registered_profile() {
        let instance = build_dccf_nf_instance("dccf-test-instance", "10.45.0.12", 7813);
        let profile = build_dccf_nf_profile("dccf-test-instance", "10.45.0.12", 7813);

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

        assert_eq!(from_instance, from_profile);
        assert_eq!(from_instance.len(), DCCF_SERVICES.len());
    }

    /// #112 acceptance: a subscription supplying `notificURI` receives its
    /// notifications.
    ///
    /// The anchor defect: the handler read `notifyUri`, so a conformant
    /// consumer's URI was never stored, the empty-URI filter dropped it from
    /// every fan-out, and it was never notified — with no error surface at all.
    /// End to end over a real connection, because that is the only place the
    /// whole chain (parse → store → key → deliver) is exercised.
    #[test]
    fn a_conformant_subscription_receives_its_notifications() {
        // #1666: the notification client follows the SBI profile, and this
        // drives it at a loopback plaintext peer, i.e. a dev deployment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        futures_lite_block_on(async {
            let (consumer, port, seen) = spawn_consumer().await;

            let resp = dccf_request_handler(
                SbiRequest::post("/ndccf-datamanagement/v1/subscriptions").with_body(
                    subscribe_body("corr-A", &format!("http://127.0.0.1:{port}/cb"), "NF_LOAD"),
                    "application/json",
                ),
            )
            .await;
            assert_eq!(resp.status, 201);
            let token = claim_producer_token(&created_id(&resp), "amf-1");

            // A producer notification for the subscribed event, on its
            // subscription's token (#1518).
            let resp = dccf_request_handler(
                SbiRequest::post(notify_path(&token)).with_body(
                    serde_json::json!({
                        "subscriptionId": "prod-1",
                        "eventNotifications": [{"event": "NF_LOAD"}]
                    })
                    .to_string(),
                    "application/json",
                ),
            )
            .await;
            assert_eq!(resp.status, 204);

            // The fan-out POSTs are spawned, so wait for delivery.
            for _ in 0..50 {
                if !seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let delivered = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
            assert_eq!(
                delivered.len(),
                1,
                "the conformant consumer must be notified exactly once, got {delivered:?}"
            );

            // #112 acceptance: the body is an NnwdafDataManagementNotif echoing
            // this consumer's notifCorrId, not a bespoke {"data": "..."} envelope.
            let notif: data_mgmt::DataManagementNotif =
                serde_json::from_value(delivered[0].clone()).expect("parses as the spec type");
            assert_eq!(notif.notif_corr_id, "corr-A", "the subscription's own id");
            assert!(!notif.notif_timestamp.is_empty());
            assert!(notif.data_notification.is_some());
            assert!(
                delivered[0].get("data").is_none(),
                "the old bespoke envelope must be gone: {:?}",
                delivered[0]
            );

            consumer.stop().await.expect("stop");
        });
        clear_subscriptions();
    }

    /// #112 acceptance: fan-out is keyed on the event — a notification for event
    /// A reaches only the consumer subscribed to A.
    ///
    /// The old fan-out returned every subscriber with a callback URI, so any
    /// consumer received every other consumer's collected data.
    #[test]
    fn fanout_is_keyed_on_the_subscribed_event() {
        // #1666: the notification client follows the SBI profile, and this
        // drives it at a loopback plaintext peer, i.e. a dev deployment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        futures_lite_block_on(async {
            let (consumer_a, port_a, seen_a) = spawn_consumer().await;
            let (consumer_b, port_b, seen_b) = spawn_consumer().await;

            let mut tokens = Vec::new();
            for (corr, port, event) in [
                ("corr-A", port_a, "NF_LOAD"),
                ("corr-B", port_b, "UE_MOBILITY"),
            ] {
                let resp = dccf_request_handler(
                    SbiRequest::post("/ndccf-datamanagement/v1/subscriptions").with_body(
                        subscribe_body(corr, &format!("http://127.0.0.1:{port}/cb"), event),
                        "application/json",
                    ),
                )
                .await;
                assert_eq!(resp.status, 201);
                tokens.push(claim_producer_token(&created_id(&resp), "amf-1"));
            }

            // A notification for NF_LOAD only, on A's producer subscription.
            dccf_request_handler(SbiRequest::post(notify_path(&tokens[0])).with_body(
                serde_json::json!({"eventNotifications": [{"event": "NF_LOAD"}]}).to_string(),
                "application/json",
            ))
            .await;

            for _ in 0..50 {
                if !seen_a.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // Give B a fair chance to be (wrongly) notified before asserting it
            // was not: an absence assertion checked too early passes for the
            // wrong reason.
            tokio::time::sleep(Duration::from_millis(150)).await;

            assert_eq!(
                seen_a.lock().unwrap_or_else(|e| e.into_inner()).len(),
                1,
                "consumer A subscribed to NF_LOAD and must receive it"
            );
            assert!(
                seen_b.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "consumer B subscribed to UE_MOBILITY and must NOT receive NF_LOAD data"
            );

            consumer_a.stop().await.expect("stop");
            consumer_b.stop().await.expect("stop");
        });
        clear_subscriptions();
    }

    /// #112 acceptance: every `required` / `oneOf` violation is a `400` with
    /// `application/problem+json`. A missing or unparseable body used to answer
    /// `201`.
    #[test]
    fn invalid_subscribe_bodies_are_rejected_with_problem_details() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        let cases: &[(&str, &str)] = &[
            ("", "no body at all"),
            ("not json", "unparseable"),
            (r#"{}"#, "no members"),
            (
                r#"{"notificURI":"http://c/cb","anaSub":{}}"#,
                "missing notifCorrId",
            ),
            (r#"{"notifCorrId":"c","anaSub":{}}"#, "missing notificURI"),
            (
                r#"{"notifCorrId":"c","notifyUri":"http://c/cb","anaSub":{}}"#,
                "the OLD bespoke key does not satisfy notificURI",
            ),
            (
                r#"{"notifCorrId":"c","notificURI":"http://c/cb"}"#,
                "neither anaSub nor dataSub",
            ),
            (
                r#"{"notifCorrId":"c","notificURI":"http://c/cb","anaSub":{},"dataSub":{}}"#,
                "both anaSub and dataSub (oneOf)",
            ),
        ];
        for (body, why) in cases {
            let resp = post("/ndccf-datamanagement/v1/subscriptions", body);
            assert_eq!(resp.status, 400, "must be 400 for: {why}");
            assert_eq!(
                resp.http.get_header("content-type").map(String::as_str),
                Some("application/problem+json"),
                "a 400 must carry ProblemDetails for: {why}"
            );
            let problem: nextgcore_sbi::message::ProblemDetails =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}"))
                    .expect("parses as ProblemDetails");
            assert_eq!(problem.status, Some(400));
        }
        clear_subscriptions();
    }

    /// #112 acceptance: the `201` carries the mandatory `Location` header and a
    /// body that round-trips as the spec resource; `GET` returns the same
    /// resource rather than a bespoke status object.
    #[test]
    fn create_returns_location_and_the_spec_resource() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        let resp = post(
            "/ndccf-datamanagement/v1/subscriptions",
            &subscribe_body("corr-1", "http://consumer/cb", "NF_LOAD"),
        );
        assert_eq!(resp.status, 201);
        let location = resp
            .http
            .get_header("location")
            .cloned()
            .expect("Location is required: true in the yaml");
        assert!(
            location.starts_with(DM_SUBSCRIPTIONS_PATH),
            "Location must point at the individual resource, got {location}"
        );
        let sub_id = location.rsplit('/').next().unwrap().to_string();
        assert!(!sub_id.is_empty());

        let created: data_mgmt::DataManagementSubsc =
            serde_json::from_str(resp.http.content.as_deref().unwrap())
                .expect("the 201 body round-trips as NnwdafDataManagementSubsc");
        assert_eq!(created.notif_corr_id, "corr-1");
        assert_eq!(created.notific_uri, "http://consumer/cb");

        // GET returns the resource, not {"subscriptionId":..,"status":"ACTIVE"}.
        let req = SbiRequest::get(format!("{DM_SUBSCRIPTIONS_PATH}/{sub_id}"));
        let resp = futures_lite_block_on(dccf_request_handler(req));
        assert_eq!(resp.status, 200);
        let fetched: data_mgmt::DataManagementSubsc =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).expect("spec resource");
        assert_eq!(fetched, created);
        clear_subscriptions();
    }

    /// #112 acceptance: `PUT` updates the subscription (no longer `405`), and the
    /// change is observable on a later `GET` **and** in what the consumer
    /// receives — the scope must be recomputed, not just the stored body.
    #[test]
    fn put_updates_the_subscription_and_its_scope() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        let resp = post(
            "/ndccf-datamanagement/v1/subscriptions",
            &subscribe_body("corr-1", "http://consumer/cb", "NF_LOAD"),
        );
        let sub_id = resp
            .http
            .get_header("location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        let put = SbiRequest::put(format!("{DM_SUBSCRIPTIONS_PATH}/{sub_id}")).with_body(
            subscribe_body("corr-2", "http://consumer/other", "UE_MOBILITY"),
            "application/json",
        );
        let resp = futures_lite_block_on(dccf_request_handler(put));
        assert_ne!(resp.status, 405, "PUT must be implemented");
        assert_eq!(resp.status, 200);

        // Observable on GET.
        let resp = futures_lite_block_on(dccf_request_handler(SbiRequest::get(format!(
            "{DM_SUBSCRIPTIONS_PATH}/{sub_id}"
        ))));
        let fetched: data_mgmt::DataManagementSubsc =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(fetched.notif_corr_id, "corr-2");
        assert_eq!(fetched.notific_uri, "http://consumer/other");

        // ...and the SCOPE moved with it: the subscription now matches
        // UE_MOBILITY and no longer matches NF_LOAD. Storing the new body while
        // leaving the old scope in place would pass the GET assertion above.
        let stored = dccf_context_get_subscription(&sub_id).expect("stored");
        assert!(stored.scope.events.contains("UE_MOBILITY"));
        assert!(
            !stored.scope.events.contains("NF_LOAD"),
            "the old event must not linger in the recomputed scope"
        );
        assert_eq!(stored.notif_corr_id, "corr-2");

        // PUT on an unknown id is 404, not a create at a consumer-chosen id.
        let put = SbiRequest::put(format!("{DM_SUBSCRIPTIONS_PATH}/no-such-id")).with_body(
            subscribe_body("c", "http://c/cb", "NF_LOAD"),
            "application/json",
        );
        assert_eq!(futures_lite_block_on(dccf_request_handler(put)).status, 404);
        clear_subscriptions();
    }

    /// #112 acceptance (coordination): two consumers asking for the same
    /// `(events, target)` share ONE producer subscription.
    ///
    /// Runs against a loopback NRF (serving `GET
    /// /nnrf-nfm/v1/nf-instances/{id}`) and a loopback producer (counting
    /// `POST /namf-evts/v1/subscriptions`), so the discovery and the producer
    /// signalling are real HTTP, not a stubbed seam.
    #[test]
    fn overlapping_consumers_share_one_producer_subscription() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        // A plaintext NRF: the dev profile, or #1617's NRF client dials https.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        init();
        clear_subscriptions();

        futures_lite_block_on(async {
            // Producer: counts the subscriptions created on it.
            let created = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = created.clone();
            let bodies: Arc<StdMutex<Vec<serde_json::Value>>> = Arc::default();
            let seen_bodies = bodies.clone();
            let (producer_listener, producer_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let producer_port = producer_addr.port();
            let producer = SbiServer::on_listener(
                SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], producer_port))),
                producer_listener,
            );
            producer
                .start(move |req: SbiRequest| {
                    let counter = counter.clone();
                    let seen_bodies = seen_bodies.clone();
                    async move {
                        if req.header.method == "POST" {
                            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            if let Some(b) = req
                                .http
                                .content
                                .as_deref()
                                .and_then(|c| serde_json::from_str(c).ok())
                            {
                                seen_bodies
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .push(b);
                            }
                            return SbiResponse::created()
                                .with_header("Location", "http://producer/sub/1");
                        }
                        SbiResponse::no_content()
                    }
                })
                .await
                .expect("producer start");

            // NRF: answers the NF profile retrieval with an event-exposure service
            // pointing at the producer above.
            let (nrf_listener, nrf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let nrf_port = nrf_addr.port();
            let nrf = SbiServer::on_listener(
                SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], nrf_port))),
                nrf_listener,
            );
            nrf.start(move |_req: SbiRequest| async move {
                SbiResponse::ok()
                    .with_json_body(&serde_json::json!({
                        "nfInstanceId": "amf-1",
                        "nfType": "AMF",
                        "nfStatus": "REGISTERED",
                        "nfServices": [{
                            "serviceInstanceId": "amf-evts-1",
                            "serviceName": "namf-evts",
                            "scheme": "http",
                            "ipEndPoints": [
                                {"ipv4Address": "127.0.0.1", "port": producer_port}
                            ]
                        }]
                    }))
                    .unwrap_or_else(|_| SbiResponse::ok())
            })
            .await
            .expect("nrf start");

            coordination::set_coordination_for_test(Some(coordination::CoordinationConfig {
                nrf_uri: format!("http://127.0.0.1:{nrf_port}"),
                own_api_root: "http://dccf".to_string(),
            }));

            // Two consumers, same event and same target NF.
            let body = |corr: &str| {
                serde_json::json!({
                    "notifCorrId": corr,
                    "notificURI": "http://consumer/cb",
                    "targetNfId": "amf-1",
                    "anaSub": {"eventSubscriptions": [{"event": "UE_MOBILITY"}]}
                })
                .to_string()
            };
            for corr in ["corr-1", "corr-2"] {
                let resp = dccf_request_handler(
                    SbiRequest::post("/ndccf-datamanagement/v1/subscriptions")
                        .with_body(body(corr), "application/json"),
                )
                .await;
                assert_eq!(resp.status, 201);
            }

            assert_eq!(
                created.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the second consumer must REUSE the producer subscription, not create a second"
            );
            assert_eq!(
                dccf_context_producer_sub_count(),
                1,
                "one producer subscription for the shared scope"
            );

            // #1518: the producer is handed a notificationURI carrying that
            // subscription's token, which names the producer it was created on.
            let uri = bodies.lock().unwrap_or_else(|e| e.into_inner())[0]["notificationURI"]
                .as_str()
                .expect("notificationURI")
                .to_string();
            let token = uri
                .strip_prefix(&format!(
                    "http://dccf{}/",
                    coordination::PRODUCER_NOTIFY_PREFIX
                ))
                .unwrap_or_else(|| panic!("tokened notificationURI, got {uri}"));
            assert!(token.len() >= 32 && !token.contains('/'), "{uri}");
            assert_eq!(
                context::dccf_context_producer_for_token(token).as_deref(),
                Some("amf-1")
            );
            assert!(
                !nextgcore_sbi::log_redact::redact_callback_tokens(&uri).contains(token),
                "the token must never reach a log"
            );

            coordination::set_coordination_for_test(None);
            producer.stop().await.expect("stop");
            nrf.stop().await.expect("stop");
        });
        clear_subscriptions();
        assert_eq!(
            dccf_context_producer_sub_count(),
            0,
            "clearing must release the producer subscription too, or the next \
             test inherits it"
        );
    }

    /// #112: with coordination OFF (the default) no producer signalling happens
    /// at all — the guard on the default posture. Same request as the test above.
    #[test]
    fn coordination_off_creates_no_producer_subscription() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        coordination::set_coordination_for_test(None);

        let body = serde_json::json!({
            "notifCorrId": "corr-1",
            "notificURI": "http://consumer/cb",
            "targetNfId": "amf-1",
            "anaSub": {"eventSubscriptions": [{"event": "UE_MOBILITY"}]}
        })
        .to_string();
        let resp = post("/ndccf-datamanagement/v1/subscriptions", &body);
        assert_eq!(resp.status, 201, "the consumer subscription still succeeds");
        assert_eq!(
            dccf_context_producer_sub_count(),
            0,
            "coordination is off by default: no producer is dialled"
        );
        clear_subscriptions();
    }

    /// Wait for a spawned fan-out to land, then give stragglers a fair chance so
    /// an absence assertion is not checked too early.
    async fn settle(seen: &StdMutex<Vec<serde_json::Value>>, want: usize) {
        for _ in 0..50 {
            if seen.lock().unwrap_or_else(|e| e.into_inner()).len() >= want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    /// #1518: producer data is acted on only on the token of a producer
    /// subscription this DCCF holds. Any other token, and the token-less
    /// `/notify` of earlier builds, is 404 and nothing is fanned out.
    ///
    /// REVERT-VERIFIED: with any non-empty token taken as held (the lookups in
    /// `context` no longer comparing it), this test and the other #1518 fan-out
    /// and exemption tests fail.
    #[test]
    fn producer_data_is_acted_on_only_on_a_held_token_1518() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        futures_lite_block_on(async {
            let (consumer, port, seen) = spawn_consumer().await;
            let resp = dccf_request_handler(
                SbiRequest::post("/ndccf-datamanagement/v1/subscriptions").with_body(
                    subscribe_body("corr-A", &format!("http://127.0.0.1:{port}/cb"), "NF_LOAD"),
                    "application/json",
                ),
            )
            .await;
            assert_eq!(resp.status, 201);
            let token = claim_producer_token(&created_id(&resp), "amf-1");
            let notif =
                serde_json::json!({"eventNotifications": [{"event": "NF_LOAD"}]}).to_string();
            let send = |path: String| {
                dccf_request_handler(
                    SbiRequest::post(path).with_body(notif.clone(), "application/json"),
                )
            };

            assert_eq!(
                send(notify_path("0123456789abcdef0123456789abcdef"))
                    .await
                    .status,
                404,
                "a token no producer subscription holds"
            );
            // #1755: with SUBSCRIPTION_NOT_FOUND (TS 29.500 Table 5.2.7.2-1), so the
            // producer terminates the subscription rather than retrying.
            let refused = send(notify_path("0123456789abcdef0123456789abcdef")).await;
            assert!(
                refused
                    .http
                    .content
                    .as_deref()
                    .is_some_and(|b| b.contains("\"SUBSCRIPTION_NOT_FOUND\"")),
                "the 404 names SUBSCRIPTION_NOT_FOUND: {:?}",
                refused.http.content
            );
            assert_eq!(
                send("/ndccf-datamanagement/v1/notify".to_string())
                    .await
                    .status,
                404,
                "the token-less route is gone"
            );
            settle(&seen, 1).await;
            assert!(
                seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "nothing may be fanned out on a refused notification"
            );

            assert_eq!(send(notify_path(&token)).await.status, 204);
            settle(&seen, 1).await;
            assert_eq!(seen.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);

            // Once its last consumer leaves, the token is no longer held.
            let id = context::dccf_context_subscription_ids()[0].clone();
            assert!(remove_consumer_subscription(&id).await);
            assert_eq!(send(notify_path(&token)).await.status, 404);

            consumer.stop().await.expect("stop");
        });
        clear_subscriptions();
    }

    /// #1518: a notification on one producer subscription's token reaches only
    /// that subscription's consumers, even when another consumer's scope matches
    /// it too. Before, every consumer whose scope matched was sent it.
    #[test]
    fn a_token_fans_out_only_to_its_own_consumers_1518() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        futures_lite_block_on(async {
            let (consumer_a, port_a, seen_a) = spawn_consumer().await;
            let (consumer_b, port_b, seen_b) = spawn_consumer().await;
            let mut tokens = Vec::new();
            for (corr, port, event) in [
                ("corr-A", port_a, "NF_LOAD"),
                ("corr-B", port_b, "UE_MOBILITY"),
            ] {
                let resp = post_async(&subscribe_body(
                    corr,
                    &format!("http://127.0.0.1:{port}/cb"),
                    event,
                ))
                .await;
                tokens.push(claim_producer_token(&created_id(&resp), "amf-1"));
            }

            // Both events, so B's scope matches as well as A's.
            let resp = dccf_request_handler(
                SbiRequest::post(notify_path(&tokens[0])).with_body(
                    serde_json::json!({"eventNotifications": [
                        {"event": "NF_LOAD"}, {"event": "UE_MOBILITY"}
                    ]})
                    .to_string(),
                    "application/json",
                ),
            )
            .await;
            assert_eq!(resp.status, 204);
            settle(&seen_a, 1).await;
            assert_eq!(seen_a.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);
            assert!(
                seen_b.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "B's data comes on B's producer subscription, not A's"
            );

            consumer_a.stop().await.expect("stop");
            consumer_b.stop().await.expect("stop");
        });
        clear_subscriptions();
    }

    async fn post_async(body: &str) -> SbiResponse {
        let resp = dccf_request_handler(
            SbiRequest::post("/ndccf-datamanagement/v1/subscriptions")
                .with_body(body.to_string(), "application/json"),
        )
        .await;
        assert_eq!(resp.status, 201);
        resp
    }

    /// #1518: on an OAuth2-required listener the producer notify route is admitted
    /// without a bearer only on a held token AND a verified certificate of the
    /// producer NF instance that subscription was created on. Producer
    /// subscriptions can be read back by the producer's other consumers, so the
    /// token alone is not enough.
    ///
    /// REVERT-VERIFIED: with the exemption admitting on a held token whatever the
    /// certificate names, the other instance's certificate is admitted.
    #[test]
    fn the_notify_route_admits_only_the_subscriptions_producer_1518() {
        use nextgcore_sbi::callback_auth::VerifiedPeer;
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        let producer = "4e3c1518-0000-4000-8000-0000000000dc";
        let resp = post(
            "/ndccf-datamanagement/v1/subscriptions",
            &subscribe_body("corr-1", "http://consumer/cb", "NF_LOAD"),
        );
        let token = claim_producer_token(&created_id(&resp), producer);
        let exemptions = oauth2_callback_exemptions();
        let admits = |path: String, id: Option<&str>| {
            let peer = id.map(|id| VerifiedPeer {
                nf_instance_id: id.to_string(),
                nf_types: vec!["AMF".to_string()],
            });
            futures_lite_block_on(nextgcore_sbi::callback_auth::admits_without_bearer_from(
                &exemptions,
                "POST",
                &path,
                peer.as_ref(),
            ))
        };

        assert!(admits(notify_path(&token), Some(producer)));
        assert!(
            admits(
                notify_path(&token),
                Some("urn:uuid:4E3C1518-0000-4000-8000-0000000000DC")
            ),
            "the certificate's urn:uuid: form, in any case"
        );
        assert!(!admits(
            notify_path(&token),
            Some("4e3c1518-0000-4000-8000-0000000000ee")
        ));
        assert!(!admits(notify_path(&token), Some("")));
        assert!(!admits(notify_path(&token), None), "no certificate");
        assert!(!admits(
            notify_path("0123456789abcdef0123456789abcdef"),
            Some(producer)
        ));
        assert!(!admits(
            "/ndccf-datamanagement/v1/notify".to_string(),
            Some(producer)
        ));

        // Real HTTP: an OAuth2-required listener with an empty JWKS and the
        // exemption. Plaintext carries no certificate, so the held token is 401 as
        // well as the forged one, the token-less route and a service request.
        let got = tokio::runtime::Builder::new_multi_thread()
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
                server.start(dccf_request_handler).await.expect("start");
                let client = SbiClient::with_host_port("127.0.0.1", addr.port());
                let mut got = Vec::new();
                for path in [
                    notify_path(&token),
                    notify_path("0123456789abcdef0123456789abcdef"),
                    "/ndccf-datamanagement/v1/notify".to_string(),
                    "/ndccf-datamanagement/v1/subscriptions".to_string(),
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
                got
            });
        for (path, status) in got {
            assert_eq!(status, 401, "{path}");
        }
        clear_subscriptions();
    }

    /// A fresh claim for consumer `sub_id`'s scope on `producer`: its token and seq.
    fn claim(sub_id: &str, producer: &str) -> (String, u64) {
        let scope = dccf_context_get_subscription(sub_id).expect("stored").scope;
        match context::dccf_context_claim_producer_sub(sub_id, &scope, Some(producer)) {
            context::ProducerClaim::NeedsCreate {
                notify_token,
                claim_seq,
            } => (notify_token.as_str().to_string(), claim_seq),
            other => panic!("expected a fresh claim, got {other:?}"),
        }
    }

    /// A consumer subscription to NF_LOAD with no producer signalling: its id and
    /// scope.
    fn consumer() -> (String, data_mgmt::SubscriptionScope) {
        let resp = post(
            "/ndccf-datamanagement/v1/subscriptions",
            &subscribe_body("corr-1", "http://consumer/cb", "NF_LOAD"),
        );
        let id = created_id(&resp);
        let scope = dccf_context_get_subscription(&id).unwrap().scope;
        (id, scope)
    }

    /// #1518: a producer subscription is held from the claim, so its token is
    /// admitted before the 201 arrives; a concurrent claim reuses it; a failed
    /// create forgets it and its token; a create that lands after every consumer
    /// left is not recorded (the caller deletes it).
    #[test]
    fn an_in_flight_producer_subscription_is_held_and_released_1518() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        let (id, scope) = consumer();
        let (token, seq) = claim(&id, "amf-1");
        assert_eq!(
            context::dccf_context_producer_for_token(&token).as_deref(),
            Some("amf-1"),
            "in flight, already held"
        );
        assert!(matches!(
            context::dccf_context_claim_producer_sub("other", &scope, Some("amf-1")),
            context::ProducerClaim::Reused { .. }
        ));
        assert!(matches!(
            context::dccf_context_claim_producer_sub(
                "x",
                &data_mgmt::SubscriptionScope::default(),
                None
            ),
            context::ProducerClaim::NoProducer
        ));

        // A failed create forgets it, and names who relied on it.
        let mut left = context::dccf_context_abandon_producer_sub(&scope, seq);
        left.sort();
        let mut want = vec![id.clone(), "other".to_string()];
        want.sort();
        assert_eq!(left, want);
        assert!(context::dccf_context_producer_for_token(&token).is_none());

        // Every consumer leaves while the create is in flight.
        let (token, seq) = claim(&id, "amf-1");
        let orphaned = dccf_context_release_producer_sub(&id).expect("last consumer");
        assert!(
            orphaned.resource_uri.is_none(),
            "deleted when its create lands"
        );
        assert!(!context::dccf_context_record_producer_sub(
            &scope,
            seq,
            "http://producer/sub/1".to_string()
        ));
        assert!(context::dccf_context_producer_for_token(&token).is_none());
        clear_subscriptions();
    }

    /// #1747 review (R7 probe): an old claim's late abandon does not remove a newer
    /// claim of the same scope.
    ///
    /// REVERT-VERIFIED: with abandon keyed on the scope alone, B's claim is removed.
    #[test]
    fn r7_stale_abandon_hits_newer_claim() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        let (id, scope) = consumer();
        let (_, a) = claim(&id, "amf-1");
        dccf_context_release_producer_sub(&id).expect("A released");
        let (token_b, b) = claim(&id, "amf-1");
        assert_ne!(a, b);
        assert!(context::dccf_context_abandon_producer_sub(&scope, a).is_empty());
        assert!(
            context::dccf_context_producer_for_token(&token_b).is_some(),
            "B's in-flight claim stays"
        );
        assert!(context::dccf_context_record_producer_sub(
            &scope,
            b,
            "http://producer/sub/b".to_string()
        ));
        clear_subscriptions();
    }

    /// #1747 review (R7 probe): an old claim's late 201 does not bind to a newer
    /// claim of the same scope; it is refused, so its creator deletes it.
    ///
    /// REVERT-VERIFIED: with record keyed on the scope alone, X's 201 is recorded on
    /// Y's entry.
    #[test]
    fn r7_stale_record_binds_newer_claim() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        let (id, scope) = consumer();
        let (_, x) = claim(&id, "amf-1");
        dccf_context_release_producer_sub(&id).expect("X released");
        let (_, y) = claim(&id, "amf-1");
        assert!(!context::dccf_context_record_producer_sub(
            &scope,
            x,
            "http://producer/sub/x".to_string()
        ));
        let held = dccf_context_release_producer_sub(&id).expect("Y held");
        assert_eq!(held.claim_seq, y);
        assert!(held.resource_uri.is_none(), "X's resource is not Y's");
        clear_subscriptions();
    }

    /// A loopback server answering with `handler`, recording each request's method
    /// and path.
    async fn stub<F, Fut>(handler: F) -> (SbiServer, u16, Arc<StdMutex<Vec<(String, String)>>>)
    where
        F: Fn(SbiRequest) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = SbiResponse> + Send + 'static,
    {
        let seen: Arc<StdMutex<Vec<(String, String)>>> = Arc::default();
        let sink = seen.clone();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = addr.port();
        let server = SbiServer::on_listener(
            SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
            listener,
        );
        server
            .start(move |req: SbiRequest| {
                let (sink, handler) = (sink.clone(), handler.clone());
                async move {
                    sink.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((req.header.method.clone(), req.header.uri.clone()));
                    handler(req).await
                }
            })
            .await
            .expect("stub start");
        (server, port, seen)
    }

    /// An NRF answering every NF profile retrieval with an event-exposure service
    /// on `producer_port`.
    async fn nrf_for(producer_port: u16) -> (SbiServer, u16) {
        let (nrf, port, _) = stub(move |_req| async move {
            SbiResponse::ok()
                .with_json_body(&serde_json::json!({
                    "nfInstanceId": "amf-1",
                    "nfType": "AMF",
                    "nfStatus": "REGISTERED",
                    "nfServices": [{
                        "serviceInstanceId": "amf-evts-1",
                        "serviceName": "namf-evts",
                        "scheme": "http",
                        "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                    }]
                }))
                .unwrap_or_else(|_| SbiResponse::ok())
        })
        .await;
        (nrf, port)
    }

    fn coordinate_via(nrf_port: u16) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        coordination::set_coordination_for_test(Some(coordination::CoordinationConfig {
            nrf_uri: format!("http://127.0.0.1:{nrf_port}"),
            own_api_root: "http://dccf".to_string(),
        }));
    }

    /// A consumer subscription naming producer amf-1, so coordination claims.
    fn targeted_body(corr: &str) -> String {
        serde_json::json!({
            "notifCorrId": corr,
            "notificURI": "http://consumer/cb",
            "targetNfId": "amf-1",
            "anaSub": {"eventSubscriptions": [{"event": "UE_MOBILITY"}]}
        })
        .to_string()
    }

    fn targeted_scope() -> data_mgmt::SubscriptionScope {
        let sub: data_mgmt::DataManagementSubsc =
            serde_json::from_str(&targeted_body("c")).expect("body");
        data_mgmt::SubscriptionScope::from_subsc(&sub)
    }

    /// #1747 review (R7 probe, MAJOR): a consumer subscribe cancelled while its
    /// producer create is in flight (its client went away) abandons the claim, so
    /// the next consumer of the scope creates a producer subscription instead of
    /// reusing one that is never made.
    ///
    /// REVERT-VERIFIED: with `InFlightClaim`'s drop not abandoning, the next claim is
    /// `Reused` onto the wedged entry. Since #1755 the claim outlives the cancelled
    /// request (its create runs on its own task) and is abandoned when that fails.
    #[test]
    fn r7_cancelled_create_wedges_scope() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        futures_lite_block_on(async {
            // An NRF that accepts the connection and never answers.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let nrf_port = listener.local_addr().unwrap().port();
            let hold = tokio::spawn(async move {
                let mut held = Vec::new();
                while let Ok((sock, _)) = listener.accept().await {
                    held.push(sock);
                }
            });
            coordinate_via(nrf_port);
            let task = tokio::spawn(dccf_request_handler(
                SbiRequest::post("/ndccf-datamanagement/v1/subscriptions")
                    .with_body(targeted_body("corr-1"), "application/json"),
            ));
            let scope = targeted_scope();
            for _ in 0..100 {
                if context::dccf_context_holds_producer_sub(&scope) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                context::dccf_context_holds_producer_sub(&scope),
                "in flight"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            // #1755: the create is owned by its own task, so cancelling the consumer's
            // request leaves it in flight rather than abandoning it under a producer
            // that may already have accepted it.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                context::dccf_context_holds_producer_sub(&scope),
                "still in flight on its own task after the consumer's request is cancelled"
            );
            // The NRF drops its connections: discovery fails, and the task abandons.
            hold.abort();
            for _ in 0..300 {
                if !context::dccf_context_holds_producer_sub(&scope) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                !context::dccf_context_holds_producer_sub(&scope),
                "abandoned when the create fails"
            );
            assert!(matches!(
                context::dccf_context_claim_producer_sub("next", &scope, Some("amf-1")),
                context::ProducerClaim::NeedsCreate { .. }
            ));
            dccf_context_release_producer_sub("next");
            coordination::set_coordination_for_test(None);
        });
        clear_subscriptions();
    }

    /// #1755: a producer that holds a create's 201 until `release`, signalling
    /// `arrived` when the POST lands. DELETEs are answered 204. Every request is
    /// recorded.
    async fn holding_producer() -> (
        SbiServer,
        u16,
        Arc<StdMutex<Vec<(String, String)>>>,
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
    ) {
        let arrived = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let location: Arc<StdMutex<String>> = Arc::default();
        let (a, r, loc) = (arrived.clone(), release.clone(), location.clone());
        let (producer, port, seen) = stub(move |req: SbiRequest| {
            let (a, r, loc) = (a.clone(), r.clone(), loc.clone());
            async move {
                if req.header.method == "POST" {
                    a.notify_one();
                    r.notified().await;
                    let l = loc.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    return SbiResponse::created().with_header("Location", l);
                }
                SbiResponse::no_content()
            }
        })
        .await;
        *location.lock().unwrap_or_else(|e| e.into_inner()) =
            format!("http://127.0.0.1:{port}/namf-evts/v1/subscriptions/held");
        (producer, port, seen, arrived, release)
    }

    /// Start a targeted consumer subscribe and cancel it once the producer holds its
    /// create: the consumer's client went away mid-POST. Returns the consumer's id.
    async fn subscribe_then_cancel_mid_post(arrived: &tokio::sync::Notify) -> String {
        let task = tokio::spawn(dccf_request_handler(
            SbiRequest::post("/ndccf-datamanagement/v1/subscriptions")
                .with_body(targeted_body("corr-1755"), "application/json"),
        ));
        tokio::time::timeout(Duration::from_secs(5), arrived.notified())
            .await
            .expect("the producer receives the create");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        context::dccf_context_subscription_ids()[0].clone()
    }

    /// #1755 (failure-path check 3): a consumer subscribe cancelled while the
    /// producer holds its 201 still records the producer subscription, so the
    /// consumer's later unsubscribe deletes it at the producer.
    ///
    /// REVERT-VERIFIED: with the create awaited inline again, the claim is abandoned
    /// on cancel, nothing is recorded and the unsubscribe sends no DELETE.
    #[test]
    fn a_subscribe_cancelled_mid_post_still_records_the_producer_subscription_1755() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        futures_lite_block_on(async {
            let (producer, producer_port, seen, arrived, release) = holding_producer().await;
            let (nrf, nrf_port) = nrf_for(producer_port).await;
            coordinate_via(nrf_port);
            let scope = targeted_scope();
            let id = subscribe_then_cancel_mid_post(&arrived).await;

            release.notify_one();
            let mut recorded = None;
            for _ in 0..300 {
                recorded = context::dccf_context_producer_resource(&scope);
                if recorded.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                recorded.as_deref(),
                Some(
                    format!("http://127.0.0.1:{producer_port}/namf-evts/v1/subscriptions/held")
                        .as_str()
                ),
                "the producer's late 201 is recorded against the claim"
            );

            assert!(remove_consumer_subscription(&id).await);
            let mut deleted = false;
            for _ in 0..300 {
                deleted = seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|(m, p)| m == "DELETE" && p.ends_with("/subscriptions/held"));
                if deleted {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                deleted,
                "the unsubscribe deletes it: {:?}",
                seen.lock().unwrap()
            );
            coordination::set_coordination_for_test(None);
            producer.stop().await.ok();
            nrf.stop().await.ok();
        });
        clear_subscriptions();
    }

    /// #1755: a subscribe cancelled mid-POST whose consumer then unsubscribes while
    /// the producer still holds the 201: the late 201 is deleted at the producer.
    ///
    /// REVERT-VERIFIED: with the create awaited inline again, the 201 is never read
    /// and the producer sees no DELETE.
    #[test]
    fn a_subscribe_cancelled_mid_post_then_unsubscribed_deletes_the_late_201_1755() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        futures_lite_block_on(async {
            let (producer, producer_port, seen, arrived, release) = holding_producer().await;
            let (nrf, nrf_port) = nrf_for(producer_port).await;
            coordinate_via(nrf_port);
            let scope = targeted_scope();
            let id = subscribe_then_cancel_mid_post(&arrived).await;
            assert!(remove_consumer_subscription(&id).await);

            release.notify_one();
            let mut deleted = false;
            for _ in 0..300 {
                deleted = seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|(m, p)| m == "DELETE" && p.ends_with("/subscriptions/held"));
                if deleted {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                deleted,
                "the late 201 is deleted: {:?}",
                seen.lock().unwrap()
            );
            assert!(!context::dccf_context_holds_producer_sub(&scope));
            coordination::set_coordination_for_test(None);
            producer.stop().await.ok();
            nrf.stop().await.ok();
        });
        clear_subscriptions();
    }

    /// #1747 review MINOR: coordination abandons its claim on every failed path:
    /// discovery fails, the producer advertises no event exposure, and the producer
    /// refuses the create.
    ///
    /// REVERT-VERIFIED: with the guard never abandoning, the claim survives each.
    #[test]
    fn a_failed_create_is_abandoned_on_every_path_1747() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        futures_lite_block_on(async {
            let scope = targeted_scope();
            let (refusing, refusing_port, refused) = stub(|_req| async move {
                nextgcore_sbi::server::send_error(500, "Internal", "no", None)
            })
            .await;
            let (nrf_ok, nrf_ok_port) = nrf_for(refusing_port).await;
            let (nrf_404, nrf_404_port, _) =
                stub(|_req| async move { send_not_found("no such NF", None) }).await;
            let (nrf_bare, nrf_bare_port, _) = stub(|_req| async move {
                SbiResponse::ok()
                    .with_json_body(&serde_json::json!({
                        "nfInstanceId": "amf-1", "nfType": "AMF",
                        "nfServices": [{"serviceName": "namf-comm"}]
                    }))
                    .unwrap_or_else(|_| SbiResponse::ok())
            })
            .await;
            for (nrf_port, why) in [
                (nrf_404_port, "discovery fails"),
                (nrf_bare_port, "no event-exposure service"),
                (nrf_ok_port, "the producer refuses"),
            ] {
                coordinate_via(nrf_port);
                let resp = dccf_request_handler(
                    SbiRequest::post("/ndccf-datamanagement/v1/subscriptions")
                        .with_body(targeted_body("corr-1"), "application/json"),
                )
                .await;
                assert_eq!(resp.status, 201, "{why}: the consumer still subscribes");
                assert!(
                    !context::dccf_context_holds_producer_sub(&scope),
                    "{why}: the claim is abandoned"
                );
            }
            assert!(
                refused
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|(m, _)| m == "POST"),
                "the producer was asked"
            );
            coordination::set_coordination_for_test(None);
            for s in [refusing, nrf_ok, nrf_404, nrf_bare] {
                s.stop().await.ok();
            }
        });
        clear_subscriptions();
    }

    /// #1747 review MINOR: a producer create that lands after every consumer of its
    /// claim left is deleted at the producer, not recorded.
    ///
    /// REVERT-VERIFIED: without the delete when record answers `false`, the
    /// producer sees no DELETE.
    #[test]
    fn a_create_landing_after_its_consumers_left_is_deleted_1747() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        futures_lite_block_on(async {
            let location: Arc<StdMutex<String>> = Arc::default();
            let loc = location.clone();
            let (producer, producer_port, seen) = stub(move |req: SbiRequest| {
                let loc = loc.clone();
                async move {
                    if req.header.method == "POST" {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        let l = loc.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        return SbiResponse::created().with_header("Location", l);
                    }
                    SbiResponse::no_content()
                }
            })
            .await;
            *location.lock().unwrap() =
                format!("http://127.0.0.1:{producer_port}/namf-evts/v1/subscriptions/late");
            let (nrf, nrf_port) = nrf_for(producer_port).await;
            coordinate_via(nrf_port);
            let scope = targeted_scope();
            let task = tokio::spawn(dccf_request_handler(
                SbiRequest::post("/ndccf-datamanagement/v1/subscriptions")
                    .with_body(targeted_body("corr-1"), "application/json"),
            ));
            for _ in 0..100 {
                if context::dccf_context_holds_producer_sub(&scope) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // The consumer unsubscribes while the create is in flight.
            let id = context::dccf_context_subscription_ids()[0].clone();
            assert!(remove_consumer_subscription(&id).await);
            assert_eq!(task.await.expect("joined").status, 201);
            let mut deleted = false;
            for _ in 0..100 {
                deleted = seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|(m, p)| m == "DELETE" && p.ends_with("/subscriptions/late"));
                if deleted {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                deleted,
                "the orphaned create is deleted: {:?}",
                seen.lock().unwrap()
            );
            assert!(!context::dccf_context_holds_producer_sub(&scope));
            coordination::set_coordination_for_test(None);
            producer.stop().await.ok();
            nrf.stop().await.ok();
        });
        clear_subscriptions();
    }

    /// #1747 review MINOR: a consumer that answers a fan-out with 404 no longer has
    /// the subscription (TS 29.500 §6.2.3), so the DCCF removes it.
    ///
    /// REVERT-VERIFIED: without the 404 removal, the subscription stays.
    #[test]
    fn a_consumer_answering_404_loses_its_subscription_1747() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        futures_lite_block_on(async {
            let (gone, port, seen) =
                stub(|_req| async move { send_not_found("no such subscription", None) }).await;
            let resp = dccf_request_handler(
                SbiRequest::post("/ndccf-datamanagement/v1/subscriptions").with_body(
                    subscribe_body("corr-A", &format!("http://127.0.0.1:{port}/cb"), "NF_LOAD"),
                    "application/json",
                ),
            )
            .await;
            let id = created_id(&resp);
            let token = claim_producer_token(&id, "amf-1");
            let resp = dccf_request_handler(SbiRequest::post(notify_path(&token)).with_body(
                serde_json::json!({"eventNotifications": [{"event": "NF_LOAD"}]}).to_string(),
                "application/json",
            ))
            .await;
            assert_eq!(resp.status, 204);
            for _ in 0..100 {
                if dccf_context_get_subscription(&id).is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(!seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            assert!(
                dccf_context_get_subscription(&id).is_none(),
                "removed on the consumer's 404"
            );
            assert!(
                context::dccf_context_producer_for_token(&token).is_none(),
                "and its producer claim released"
            );
            gone.stop().await.ok();
        });
        clear_subscriptions();
    }
}

#[cfg(test)]
mod default_bind_tests {
    use super::Args;
    use clap::Parser;

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-dccfd"]);
        assert_eq!(args.sbi_addr, None);
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
            let profile = build_dccf_nf_profile("id", host, 7777);
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

    /// Under the `production` profile this DCCF installs its token client with
    /// the `sbi.oauth2.require` knob off, so its service requests to the AMF, AUSF,
    /// SMF and UDM (which require a bearer under that profile, #63) carry one
    /// (TS 33.501 §13.4.1.1.2). Before #1665 it installed it only under the knob.
    #[test]
    fn the_production_profile_installs_the_outbound_oauth2_client_without_the_knob() {
        let oauth2 = super::outbound_oauth2_client(SbiProfile::Production, false, Some(NRF))
            .expect("production profile, knob off: the outbound OAuth2 client is installed");
        assert_eq!(oauth2.self_consumer().nf_type, NfType::Dccf);
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
