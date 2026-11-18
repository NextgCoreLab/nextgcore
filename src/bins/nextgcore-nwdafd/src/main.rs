//! NextGCore NWDAF (Network Data Analytics Function)
//!
//! The NWDAF is a Rel-16/17/18/20 network function responsible for (TS 23.288):
//! - Collecting and analyzing network data from various NFs
//! - Providing analytics to consumers (AMF, SMF, PCF, etc.)
//! - ML model training and inference for predictive analytics
//! - Supporting various analytics types (NF load, UE mobility, QoS, etc.)

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::context::{global_context, SbiContext};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_method_not_allowed, send_not_found, SbiServer, SbiServerConfig as NextgcoreSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "amf-mobility")]
pub mod amf_mobility; // nextgsim#466: UE_MOBILITY from AMF LOCATION_REPORT events
pub mod analytics;
mod context;
pub mod federation;
pub mod ml_service;
pub mod notification_dispatcher;
pub mod nrf_collector;
pub mod onnx_export; // issue #109: export the active model as an ONNX artefact
                     // The reader is no longer gated at the module level: #109 serves an ONNX model
                     // built by `onnx_export`, and the reader is how we prove those bytes round-trip
                     // and reproduce our own prediction. Reading *operator-supplied* files stays the
                     // opt-in part — the `onnx:<path>` arm of `ml_service::load_model` is still behind
                     // the `onnx-model` feature.
pub mod model_store; // nextgsim#468: versioned, content-addressed model artefacts
pub mod onnx_model; // issue #26: zero-dep ONNX LinearRegressor subset backend

/// nextgsim#468: Nnwdaf_MLModelMonitor (demo d441e-model-retrain).
#[cfg(feature = "demo-d441e-model-retrain")]
pub mod model_monitor;
/// nextgsim#468: the MTLF's retrain and the seeded series (demo d441e-model-retrain).
#[cfg(feature = "demo-d441e-model-retrain")]
pub mod model_refit;
/// nextgsim#468: the AnLF model client (demo d441e-model-retrain).
#[cfg(feature = "demo-d441e-model-retrain")]
pub mod model_retrain;
/// nextgsim#465: USER_DATA_CONGESTION from RAN cell reports.
#[cfg(feature = "demo-d441a-congestion-loop")]
pub mod ran_congestion;
pub mod role; // nextgsim#468: nwdaf.role (mtlf | anlf | both)
mod sbi_handler;

pub use context::*;
pub use sbi_handler::*;

/// NextGCore NWDAF - Network Data Analytics Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nwdafd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Data Analytics Function (TS 23.288)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nwdaf.yaml")]
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
    /// Without it, `nwdaf.sbi.server[0].address` from the config file, else
    /// 127.0.0.1 (#1308, #1312). The port likewise defaults to the file, else 7815.
    #[arg(long)]
    sbi_addr: Option<String>,

    /// The SBI host advertised in the NRF NFProfile and callback URIs. Without it,
    /// `NEXTGCORE_SBI_ADVERTISE`, else `nwdaf.sbi.server[0].advertise`, else the
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

    /// Maximum analytics subscriptions
    #[arg(long, default_value = "1024")]
    max_subscriptions: usize,

    /// JSON snapshot file for analytics and ML-provision subscriptions plus
    /// THRESHOLD edge state (issue #66/#192).
    ///
    /// Falls back to `NEXTGCORE_NWDAF_STATE_FILE`; an empty value is treated as
    /// unset. With neither set the NWDAF is memory-only, which is the shipped
    /// default and byte-identical to previous behaviour. An unreadable snapshot,
    /// or one written by a newer build, FAILS STARTUP rather than coming up empty
    /// and overwriting it.
    #[arg(long)]
    state_file: Option<String>,

    /// NRF URI for registration
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// NF instance ID
    #[arg(long)]
    nf_instance_id: Option<String>,
}

/// Resolve the durable-state path from the flag and the environment variable
/// (issue #66/#192).
///
/// The precedence the other NFs use, and the one the configuration docs state:
/// **the flag wins over the variable, and an empty or whitespace-only value is
/// treated as unset rather than as a path.** That last part matters in container
/// deployments, where an unset variable routinely arrives as `""` — taking it
/// literally would try to snapshot to a file with no name and log a write error
/// on every mutation.
///
/// Split out of `main` so the precedence is testable without a process
/// environment.
fn resolve_state_file(flag: Option<String>, env: Option<String>) -> Option<String> {
    flag.or(env)
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
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
// `nwdaf.sbi.oauth2.require: true` yaml knob. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled (Wave-6 H8
/// Phase A). Outbound SBI clients attach a token via `client.with_oauth2`.
#[allow(dead_code)]
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// #1665: the outbound OAuth2 client this NWDAF installs at startup: under the
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
        nextgcore_sbi::types::NfType::Nwdaf,
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

/// The Nnwdaf callback routes admitted without an OAuth2 bearer when the listener
/// requires one (#1421): a notification carries no access token (TS 33.501
/// §13.4.1, TS 29.500 §6.10.7 NOTE), and each of these is authenticated by the
/// unguessable token this NWDAF minted into the callback URI instead. The server
/// admits one only when the same check its route applies finds the token held
/// now; any other request still needs a bearer. Feature-gated routes are listed
/// only in the builds that serve them.
fn oauth2_callback_exemptions() -> Vec<nextgcore_sbi::server::OAuth2CallbackExemption> {
    oauth2_callback_exemptions_from(CallbackSources::PROCESS)
}

/// Where the D441E callback checks find the state that holds their tokens: the
/// process-wide monitor and AnLF in production, test instances in a test (a
/// process-wide one cannot be installed in a test binary without leaking into
/// every other test).
#[derive(Clone, Copy)]
struct CallbackSources {
    #[cfg(feature = "demo-d441e-model-retrain")]
    monitor: fn() -> Option<&'static model_monitor::Monitor>,
    #[cfg(feature = "demo-d441e-model-retrain")]
    anlf: fn() -> Option<&'static model_retrain::Anlf>,
}

impl CallbackSources {
    const PROCESS: Self = Self {
        #[cfg(feature = "demo-d441e-model-retrain")]
        monitor: model_monitor::monitor,
        #[cfg(feature = "demo-d441e-model-retrain")]
        anlf: model_retrain::anlf,
    };
}

#[cfg_attr(not(feature = "demo-d441e-model-retrain"), allow(unused_variables))]
fn oauth2_callback_exemptions_from(
    sources: CallbackSources,
) -> Vec<nextgcore_sbi::server::OAuth2CallbackExemption> {
    use nextgcore_sbi::server::OAuth2CallbackExemption;
    let route = |segment: &str| format!("/nnwdaf-callback/v1/{segment}/{{token}}");
    #[allow(unused_mut)]
    let mut list = vec![OAuth2CallbackExemption::new(
        "POST",
        route(nrf_collector::CALLBACK_SEGMENT),
        |cb| nrf_collector::holds_callback_token(cb.token),
    )];
    #[cfg(feature = "amf-mobility")]
    list.push(OAuth2CallbackExemption::new(
        "POST",
        route(amf_mobility::CALLBACK_SEGMENT),
        |cb| amf_mobility::holds_callback_token(cb.token),
    ));
    #[cfg(feature = "demo-d441a-congestion-loop")]
    list.push(OAuth2CallbackExemption::new(
        "POST",
        route(ran_congestion::CALLBACK_SEGMENT),
        |cb| ran_congestion::holds_callback_token(cb.token),
    ));
    #[cfg(feature = "demo-d441e-model-retrain")]
    {
        let monitor = sources.monitor;
        list.push(OAuth2CallbackExemption::new(
            "POST",
            route(model_monitor::CALLBACK_SEGMENT),
            move |cb| model_monitor::holds_callback_token(monitor(), cb.token),
        ));
        let anlf = sources.anlf;
        list.push(OAuth2CallbackExemption::new(
            "POST",
            route(model_retrain::CALLBACK_SEGMENT),
            move |cb| model_retrain::holds_callback_token(anlf(), cb.token),
        ));
    }
    list
}

/// The NWDAF SBI server for `cfg`, with [`oauth2_callback_exemptions`]
/// registered (#1421). `main` builds its server here, so a test can see what
/// it registers.
fn sbi_server(cfg: NextgcoreSbiServerConfig) -> SbiServer {
    SbiServer::new(cfg.with_oauth2_callback_exemptions(oauth2_callback_exemptions()))
}

/// Apply OAuth2 producer enforcement to `cfg` (Wave-6 H8). The outbound client
/// is installed apart from it, by [`outbound_oauth2_client`] (#1665). The server verifies incoming Bearer tokens against the
/// NRF JWKS and requires `aud` to include NfType::Nwdaf; with no NRF URI it
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
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Nwdaf);
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // #1312: the command line, else `nwdaf.sbi.server[0]` in the config file,
    // else loopback.
    let sbi = nextgcore_core::sockaddr::SbiEndpoint::resolve_from_file(
        args.sbi_addr.as_deref(),
        args.sbi_port,
        args.sbi_advertise.as_deref(),
        &args.config,
        "nwdaf",
        7815,
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

    log::info!("NextGCore NWDAF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Network Data Analytics Function (3GPP TS 23.288)");

    // nextgsim#458: the demo: block. Checked against the demos this build was
    // compiled with, so an unknown key or mode, or a demo whose cargo feature is
    // not built, fails start-up. With no demo active nothing below changes.
    let config_root = config_root(&args.config).map_err(|e| anyhow::anyhow!("{e}"))?;
    nextgcore_demo::init_from_root(&config_root, &demo_registry())
        .map_err(|e| anyhow::anyhow!("{e} ({e:?})"))?;
    // nextgsim#466: decided once, before the NRF registration below, so the
    // profile advertises UE_MOBILITY exactly when it is served.
    #[cfg(feature = "amf-mobility")]
    let amf_mobility_plan = {
        let knob =
            amf_mobility::knob_from_root(&config_root).map_err(|e| anyhow::anyhow!("{e}"))?;
        let plan = amf_mobility::resolve(nextgcore_demo::active_mode(amf_mobility::DEMO_KEY), knob);
        amf_mobility::install(plan);
        plan
    };
    // nextgsim#465: the ingest route and USER_DATA_CONGESTION, decided once here,
    // before the NRF registration, like UE_MOBILITY above.
    #[cfg(feature = "demo-d441a-congestion-loop")]
    ran_congestion::install(
        nextgcore_demo::active_mode(ran_congestion::DEMO_KEY),
        &args.nrf_uri,
    );
    // nextgsim#468: which logical functions this NWDAF contains. An unknown
    // role fails start-up. Decided before the NRF registration, which
    // advertises nnwdaf-mlmodelprovision only for an MTLF.
    let nwdaf_role = role::from_root(&config_root).map_err(|e| anyhow::anyhow!("{e}"))?;
    role::install(nwdaf_role);
    log::info!("NWDAF role: {}", nwdaf_role.as_str());
    #[cfg(feature = "demo-d441e-model-retrain")]
    let model_retrain_plan = {
        let plan = model_retrain::resolve(
            nextgcore_demo::active_mode(model_retrain::DEMO_KEY),
            nwdaf_role,
            &config_root,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        model_retrain::announce(&plan);
        plan
    };
    // nextgsim#468 PR 4: the seeded series both NWDAFs judge and retrain on,
    // while the demo is on. A malformed `nwdaf.retrain_series` fails start-up.
    #[cfg(feature = "demo-d441e-model-retrain")]
    let retrain_series = match &model_retrain_plan {
        model_retrain::Plan::Off => None,
        _ => model_refit::series_config_from_root(&config_root)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    };

    // Issue #187: the flag seeds the shared resolver (so it still wins) and the
    // fallback resolves there rather than minting an id no operator can pin.
    if let Some(id) = args.nf_instance_id.as_deref() {
        nextgcore_sbi::nf_instance_id::seed(id);
    }
    let nf_instance_id =
        nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Nwdaf)
            .to_string();

    nwdaf_context_init(nf_instance_id.clone(), args.max_subscriptions);
    // #1428: bound the per-SUPI UE mobility history (least recently reported
    // evicted). A malformed value fails start-up.
    #[cfg(feature = "amf-mobility")]
    {
        let max_ues =
            amf_mobility::max_ues_from_root(&config_root).map_err(|e| anyhow::anyhow!("{e}"))?;
        let ctx = nwdaf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        guard.lock_engine().set_max_tracked_ues(max_ues);
        if amf_mobility_plan.serves() {
            log::info!(
                "ue-mobility: history bounded at {max_ues} UEs (nwdaf.amf_mobility.max_ues)"
            );
        }
    }

    // Issue #1412: who the NRF lets discover this NWDAF and get a token for it.
    // A malformed configured list fails startup rather than registering one.
    let allowed_nf_types =
        allowed_nf_types_from_config(&args.config).map_err(|e| anyhow::anyhow!("{e}"))?;
    log::info!("NFProfile allowedNfTypes: {allowed_nf_types:?}");

    // Issue #66/#192: restore durable state AFTER the context knows its capacity
    // cap and BEFORE the SBI server can accept a subscription, so a restored
    // record is never shadowed by a fresh one. Precedence matches the other NFs:
    // the flag wins over the env var, and an empty value is treated as unset
    // rather than as a path.
    let state_file = resolve_state_file(
        args.state_file.clone(),
        std::env::var("NEXTGCORE_NWDAF_STATE_FILE").ok(),
    );
    if let Some(path) = state_file {
        let ctx = nwdaf_self();
        let mut guard = ctx
            .write()
            .map_err(|_| anyhow::anyhow!("NWDAF context lock poisoned"))?;
        // Fail STARTUP on a snapshot that cannot be read or is from a newer
        // build. Coming up empty would answer "no such subscription" for
        // subscriptions that exist and silently stop analytics for them, and the
        // store would then refuse every later write to protect the file -- so the
        // NF would be running in a state that is neither durable nor honest.
        let restored = guard.set_state_file(std::path::PathBuf::from(&path))?;
        log::info!("NWDAF durable state: {path} ({restored} record(s) restored)");
    } else {
        log::info!(
            "NWDAF durable state disabled (no --state-file / NEXTGCORE_NWDAF_STATE_FILE): \
             analytics and ML-provision subscriptions are memory-only and lost on restart"
        );
    }

    // Issue #109: the model URL notified to MLModelProvision consumers has to
    // resolve back to this NF, so record our own SBI base. Uses the advertised
    // address rather than the bind address: `0.0.0.0` is what we listen on, not
    // somewhere a consumer can fetch from. nextgsim#466's eventNotifyUri uses it too.
    let sbi_base = {
        let scheme = if args.tls { "https" } else { "http" };
        let host = match sbi.advertise.as_deref() {
            Some(host) => host,
            None => {
                log::warn!(
                    "SBI bound to {sbi_addr}: the ML model URL will advertise 127.0.0.1; set \
                     --sbi-advertise or NEXTGCORE_SBI_ADVERTISE to a reachable address for \
                     consumers to download models (issue #109, #1312)"
                );
                "127.0.0.1"
            }
        };
        let base = format!(
            "{scheme}://{}",
            nextgcore_sbi::uri_encode::uri_authority(host, sbi_port)
        );
        let ctx = nwdaf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        guard.set_sbi_base_uri(&base);
        log::info!("SBI base URI for model provisioning: {base}");
        base
    };
    #[cfg(not(any(feature = "amf-mobility", feature = "demo-d441e-model-retrain")))]
    let _ = &sbi_base;
    // nextgsim#468: Nnwdaf_MLModelMonitor, while the demo is on: an MTLF takes
    // registrations and subscribes at AnLFs; an AnLF serves the subscriptions
    // and reports accuracy. Installed before the NRF registration, which
    // advertises the service.
    #[cfg(feature = "demo-d441e-model-retrain")]
    match &model_retrain_plan {
        model_retrain::Plan::Off => {}
        model_retrain::Plan::On { mode, role } => {
            let m = model_monitor::install(
                model_monitor::Monitor::new(mode, *role, &sbi_base, &nf_instance_id, &args.nrf_uri)
                    .with_series(retrain_series.map(|_| model_refit::SERIES_NF_INSTANCE)),
            );
            // Audit idle registrations and expire stale ones (#1473 review).
            if role.serves_mtlf() {
                model_monitor::spawn_upkeep(m, nwdaf_self());
            }
        }
        model_retrain::Plan::Client { mode, .. } => {
            let m = model_monitor::install(
                model_monitor::Monitor::new(
                    mode,
                    role::Role::Anlf,
                    &sbi_base,
                    &nf_instance_id,
                    &args.nrf_uri,
                )
                .with_series(retrain_series.map(|_| model_refit::SERIES_NF_INSTANCE)),
            );
            model_monitor::spawn_reporter(m);
        }
    }
    #[cfg(feature = "demo-d441e-model-retrain")]
    if let Some(cfg) = retrain_series {
        model_refit::announce(&cfg);
        model_refit::spawn_series(cfg, nwdaf_self());
    }

    // Issue #26: optional prediction-model selection. Default (env unset) is
    // the OLS baseline — behavior-identical to the pre-#26 inline math.
    if let Ok(model_id) = std::env::var("NWDAF_PREDICTION_MODEL") {
        match ml_service::load_model(&model_id) {
            Ok(model) => {
                let ctx = nwdaf_self();
                let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
                guard.lock_engine().set_predictor(model);
                log::info!("NF_LOAD prediction model set to {model_id}");
            }
            Err(e) => {
                log::warn!("NWDAF_PREDICTION_MODEL={model_id} ignored ({e}); keeping ols-linear");
            }
        }
    }

    // nextgsim#468: publish the boot model (v1) now the predictor is chosen, and
    // record ML-provision subscriptions restored from an older build's snapshot
    // as holding it, so an upgrade does not re-notify every consumer.
    {
        let ctx = nwdaf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        let adopted = guard.adopt_legacy_ml_prov_deliveries();
        if adopted > 0 {
            log::info!("MLModelProvision: {adopted} restored subscription(s) adopted as holding the active model");
        }
        if guard.current_model_version().is_none() {
            log::info!("MLModelProvision: the active prediction model has no exportable form; no model is provisioned");
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = nextgcore_core::sockaddr::parse_listen_addr(&sbi_addr, sbi_port)
        .context("Invalid SBI address")?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    nextgcore_core::sockaddr::warn_if_loopback_listener("SBI", &addr, "--sbi-addr");

    let mut sbi_server_config = NextgcoreSbiServerConfig::new(addr);
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
    let _ = OAUTH2_CLIENT.set(outbound_oauth2_client(
        nextgcore_sbi::security::SbiProfile::resolve(),
        require_oauth2,
        Some(&args.nrf_uri),
    ));
    // #1667: the same client gives this NF's own NRF calls their access token.
    nextgcore_sbi::nrf_tls::set_nrf_oauth2_client(OAUTH2_CLIENT.get().cloned().flatten());
    if require_oauth2 {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config, &args.nrf_uri);
    }
    // #1421: the callbacks this NWDAF subscribed for are admitted on their own
    // token when the listener requires OAuth2 (a notification carries no bearer).
    let sbi_server = sbi_server(sbi_server_config);

    log::info!("Starting NWDAF SBI server on {addr}");
    sbi_server
        .start(nwdaf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF. main() is the composition root: acquire the shared SBI
    // context once here and inject it downstream, instead of each function
    // reaching for the global_context() singleton.
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    // #1482: a failed attempt is retried in the background, and the heartbeat
    // starts after the one that succeeds.
    match sbi.registration_host() {
        Ok(host) => {
            let (host, id, allowed) = (
                host.to_string(),
                nf_instance_id.clone(),
                allowed_nf_types.clone(),
            );
            nextgcore_sbi::heartbeat::register_or_retry(
                "NWDAF",
                Default::default(),
                move || {
                    let (ctx, host, id, allowed) =
                        (sbi_ctx.clone(), host.clone(), id.clone(), allowed.clone());
                    async move {
                        register_with_nrf(ctx, &host, sbi_port, &id, &allowed)
                            .await
                            .map(|()| Some(id))
                    }
                },
                |nf_instance_id| {
                    // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
                    // (active analytics subscriptions, saturated at 100;
                    // TS 29.510 §5.2.2.3.2). Honest subscription-count proxy — no
                    // fabricated CPU numbers.
                    nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                        nf_instance_id,
                        5,
                        || {
                            let load = nwdaf_self()
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

    // G2-1: arm the NRF NF_LOAD collector and attempt the initial
    // NFStatusSubscribe (TS 29.510 §5.2.2.5). Non-fatal on every failure —
    // the dispatcher tick retries/renews; analytics degrade to no-data.
    {
        let ctx = nwdaf_self();
        if let Ok(guard) = ctx.read() {
            guard.set_nrf_collector_config(NrfCollectorConfig {
                nrf_uri: args.nrf_uri.clone(),
                // #1421: the tokenised callback, so an OAuth2-required
                // listener can admit the NRF's bearer-less notification.
                callback_uri: format!(
                    "http://{}{}",
                    nextgcore_sbi::uri_encode::uri_authority(
                        sbi.advertise.as_deref().unwrap_or("127.0.0.1"),
                        sbi_port
                    ),
                    nrf_collector::callback_path()
                ),
            });
        }
        nrf_collector::subscribe_nf_status(&ctx).await;
    }

    // nextgsim#466: Namf_EventExposure_Subscribe (LOCATION_REPORT, any UE) to an
    // AMF discovered at the NRF, retried in the background until it is accepted;
    // and this NWDAF's /metrics. Mode `baseline` and the default plan do neither
    // subscription nor serving; a default build has neither.
    #[cfg(feature = "demo-d441a-congestion-loop")]
    ran_congestion::set_amf_sub_context(ran_congestion::AmfSubContext {
        nrf_uri: args.nrf_uri.clone(),
        sbi_base: sbi_base.clone(),
        nf_id: nf_instance_id.clone(),
    });
    #[cfg(feature = "amf-mobility")]
    {
        if amf_mobility_plan.serves() {
            amf_mobility::spawn_subscriber(
                args.nrf_uri.clone(),
                sbi_base.clone(),
                nf_instance_id.clone(),
            );
        }
    }
    // nextgsim#468: the AnLF subscribes to an MTLF for its model, retried in the
    // background, when the demo is on and this NWDAF's role is `anlf`.
    #[cfg(feature = "demo-d441e-model-retrain")]
    if let model_retrain::Plan::Client { config, .. } = &model_retrain_plan {
        model_retrain::spawn_client(
            config.clone(),
            args.nrf_uri.clone(),
            sbi_base.clone(),
            nf_instance_id.clone(),
        );
    }
    // This NWDAF's /metrics, in a build with a demo that exports any.
    #[cfg(any(feature = "amf-mobility", feature = "demo-d441e-model-retrain"))]
    let _metrics = nextgcore_metrics::nf::serve_nf_metrics(
        "NWDAF",
        "NWDAF_METRICS_PORT",
        Arc::new(render_prometheus),
    )
    .await;

    // Spawn the notification dispatcher background task (T5.3).
    // It wakes every DEFAULT_DISPATCH_INTERVAL_SECS (30 s), computes analytics,
    // and POSTs Nnwdaf_EventsSubscription_Notify to all due subscribers.
    // The interval is intentionally short so subscriptions with the default
    // repetition_period_secs=60 receive their first notification quickly.
    let dispatch_interval = std::env::var("NWDAF_DISPATCH_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(notification_dispatcher::DEFAULT_DISPATCH_INTERVAL_SECS);
    notification_dispatcher::spawn_dispatcher(nwdaf_self(), dispatch_interval);
    log::info!(
        "Notification dispatcher spawned (interval={}s)",
        dispatch_interval
    );

    log::info!("NextGCore NWDAF ready (instance: {nf_instance_id})");

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

    nwdaf_context_final();
    log::info!("NWDAF shutdown complete");

    Ok(())
}

/// NWDAF SBI request handler
async fn nwdaf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    // #1421: callback paths carry a token; the log shows it redacted (#940).
    log::debug!(
        "NWDAF SBI: {method} {}",
        nextgcore_sbi::log_redact::redact_callback_tokens(uri)
    );

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // Nnwdaf_AnalyticsInfo service — TS 29.520 §4.3.2.2.2 mandates HTTP GET
        // with an `event-id` query parameter (no request body).
        ["nnwdaf-analyticsinfo", "v1", "analytics"] => match method {
            "GET" => handle_analytics_info_query(&request).await,
            _ => send_method_not_allowed(method, "analytics"),
        },

        // Nnwdaf_AnalyticsInfo_ContextTransfer (`GetNwdafContext`, TS 29.520
        // §4.3.2.3, TS29520_Nnwdaf_AnalyticsInfo.yaml:118). Issue #171: this
        // operation was unrouted, so an advertised part of the API 404'd.
        ["nnwdaf-analyticsinfo", "v1", "context"] => match method {
            "GET" => handle_nwdaf_context_query(&request).await,
            _ => send_method_not_allowed(method, "context"),
        },

        // Nnwdaf_EventsSubscription service
        ["nnwdaf-eventssubscription", "v1", "subscriptions"] => match method {
            "POST" => handle_subscription_create(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["nnwdaf-eventssubscription", "v1", "subscriptions", subscription_id] => match method {
            "GET" => handle_subscription_get(subscription_id).await,
            "PUT" => handle_subscription_update(subscription_id, &request).await,
            "DELETE" => handle_subscription_delete(subscription_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // nextgsim#468: an AnLF-only NWDAF (`nwdaf.role: anlf`) contains no
        // MTLF, so it serves no part of Nnwdaf_MLModelProvision.
        ["nnwdaf-mlmodelprovision", ..] if !role::current().serves_mtlf() => {
            send_not_found("this NWDAF contains no MTLF (nwdaf.role: anlf)", None)
        }

        // Nnwdaf_MLModelProvision model artefact (issue #109). The Subscribe/
        // Notify half notifies an `mLFileAddr.mLModelUrl`; this is the route it
        // resolves to. nextgsim#468: the last segment is the model version's
        // sha256 (or `{sha256}.manifest.json`), so each URL serves one fixed
        // artefact; the #109 `{subscriptionId}` form serves the active one.
        ["nnwdaf-mlmodelprovision", "v1", "models", event, artefact] => match method {
            "GET" => handle_ml_model_download(event, artefact).await,
            _ => send_method_not_allowed(method, "models/{event}/{artefact}"),
        },

        // Nnwdaf_MLModelProvision service — TS 29.520 is a Subscribe/Notify
        // resource on /subscriptions.
        ["nnwdaf-mlmodelprovision", "v1", "subscriptions"] => match method {
            "POST" => handle_ml_prov_subscription_create(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["nnwdaf-mlmodelprovision", "v1", "subscriptions", subscription_id] => match method {
            "PUT" => handle_ml_prov_subscription_update(subscription_id, &request).await,
            "DELETE" => handle_ml_prov_subscription_delete(subscription_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // #1421: the same callback on the tokenised nfStatusNotificationUri this
        // NWDAF now subscribes with; a token it did not hand out is 404.
        ["nnwdaf-callback", "v1", segment, token]
            if *segment == nrf_collector::CALLBACK_SEGMENT =>
        {
            match method {
                "POST" if nrf_collector::holds_callback_token(token) => {
                    nrf_collector::handle_nf_status_notify(&request).await
                }
                "POST" => send_not_found("no such NF status subscription callback", None),
                _ => send_method_not_allowed(method, "nf-status-notify/{token}"),
            }
        }

        // G2-1: Nnrf_NFManagement NFStatusNotify callback (TS 29.510
        // §5.2.2.6) — the NRF POSTs NotificationData here; NFProfile.load
        // becomes the NF_LOAD analytics data. The token-less URI subscriptions
        // made before #1421 named; bearer-protected on an OAuth2 listener.
        ["nnwdaf-nfstatus-notify", "v1", "notify"] => match method {
            "POST" => nrf_collector::handle_nf_status_notify(&request).await,
            _ => send_method_not_allowed(method, "notify"),
        },

        // nextgsim#466: Namf_EventExposure Notify from the AMF this NWDAF
        // subscribed to, on the eventNotifyUri it gave (`amf_mobility`).
        #[cfg(feature = "amf-mobility")]
        ["nnwdaf-callback", "v1", segment, token] if *segment == amf_mobility::CALLBACK_SEGMENT => {
            match method {
                "POST" => amf_mobility::handle_location_notify(&nwdaf_self(), token, &request),
                _ => send_method_not_allowed(method, "amf-location-notify/{token}"),
            }
        }

        // nextgsim#465 (non-normative): RAN cell reports from the gNB, standing in
        // for OAM PM (TS 23.288 §6.2.3). The route checks its own OAuth2 token.
        #[cfg(feature = "demo-d441a-congestion-loop")]
        ["nnwdaf-randata", "v1", "cell-reports"] => match method {
            "POST" => ran_congestion::handle_cell_report(&request).await,
            _ => send_method_not_allowed(method, "cell-reports"),
        },
        // nextgsim#465: the AMF's UES_IN_AREA_REPORT notify, on the
        // eventNotifyUri this NWDAF gave it (token-authenticated like #466's).
        #[cfg(feature = "demo-d441a-congestion-loop")]
        ["nnwdaf-callback", "v1", segment, token]
            if *segment == ran_congestion::CALLBACK_SEGMENT =>
        {
            match method {
                "POST" => ran_congestion::handle_ues_in_area_notify(
                    ran_congestion::store(),
                    token,
                    &request,
                ),
                _ => send_method_not_allowed(method, "amf-ues-in-area-notify/{token}"),
            }
        }

        // nextgsim#468: Nnwdaf_MLModelMonitor (registrations at an MTLF,
        // subscriptions at an AnLF). 404 with the demo off.
        #[cfg(feature = "demo-d441e-model-retrain")]
        ["nnwdaf-mlmodelmonitor", "v1", rest @ ..] => model_monitor::route(
            model_monitor::monitor(),
            &nwdaf_self(),
            method,
            rest,
            &request,
        ),
        // nextgsim#468: an AnLF's Nnwdaf_MLModelMonitor_Notify, on the
        // notificationUri this MTLF gave it (`model_monitor`).
        #[cfg(feature = "demo-d441e-model-retrain")]
        ["nnwdaf-callback", "v1", segment, token]
            if *segment == model_monitor::CALLBACK_SEGMENT =>
        {
            match method {
                "POST" => model_monitor::handle_notify(model_monitor::monitor(), token, &request),
                _ => send_method_not_allowed(method, "mlmodel-monitor-notify/{token}"),
            }
        }

        // nextgsim#468: Nnwdaf_MLModelProvision_Notify from the MTLF this AnLF
        // subscribed to, on the notifUri it gave (`model_retrain`).
        #[cfg(feature = "demo-d441e-model-retrain")]
        ["nnwdaf-callback", "v1", segment, token]
            if *segment == model_retrain::CALLBACK_SEGMENT =>
        {
            match method {
                "POST" => model_retrain::handle_model_notify(
                    model_retrain::anlf(),
                    nwdaf_self(),
                    token,
                    &request,
                ),
                _ => send_method_not_allowed(method, "mtlf-model-notify/{token}"),
            }
        }

        // Issue #16 (non-normative 6G ISAC, no frozen Stage-3): sensing-result
        // collection endpoint, feature-gated and off by default.
        #[cfg(feature = "sensing")]
        ["nnwdaf-sensingdata", "v1", "results"] => match method {
            "POST" => handle_sensing_result_post(&request).await,
            _ => send_method_not_allowed(method, "results"),
        },

        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// Build the TS 29.510 `NFProfile` this NWDAF registers at the NRF.
///
/// G2-3 (supported-events honesty): the profile advertises the analytics
/// events this NWDAF actually supports via `nwdafInfo.eventIds`
/// (TS 29.510 `NwdafInfo`, TS29510_Nnrf_NFManagement.yaml `NwdafInfo.eventIds`
/// → TS 29.520 `EventId`), derived from the single source of truth
/// [`SUPPORTED_EVENTS`] so consumers discover only analytics with a live
/// collector. Additive JSON: the NRF ignores unknown NFProfile members, so
/// registration behavior is otherwise unchanged.
///
/// The same honesty rule now applies to `nnwdaf-mlmodelprovision` (issue #109):
/// it is advertised only when this NWDAF's active predictor has an exportable
/// form, so a consumer that discovers the MTLF role can actually download a
/// model. Advertising it unconditionally is what made it a facade — the notified
/// URL 404'd.
///
/// Issue #175: `NwdafInfo` has TWO event members with DIFFERENT enumerations —
/// `eventIds` typed `EventId` (24 values, the Nnwdaf_AnalyticsInfo spelling) and
/// `nwdafEvents` typed `NwdafEvent` (25, the Nnwdaf_EventsSubscription spelling).
/// Both are advertised from the same [`SUPPORTED_EVENTS`], each in its own
/// spelling, so a consumer discovering us for either API sees tokens that API
/// actually defines. Previously `eventIds` carried `NwdafEvent` spellings, which
/// is only invisible because NF_LOAD is spelled the same in both; a
/// SLICE_LOAD_LEVEL or PFD_DETERMINATION collector would have advertised a token
/// no `EventId` consumer could match. `eventIds` is omitted entirely rather than
/// emitted empty if no supported event has an `EventId` value (it has
/// `minItems: 1`).
fn build_nf_profile(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    allowed_nf_types: &[String],
) -> serde_json::Value {
    // nextgsim#468: an AnLF-only NWDAF contains no MTLF. The role is decided
    // first, so an AnLF is not told its model has no exportable form (#1493).
    let ml_provision = MlProvision::decide(role::current().serves_mtlf(), || {
        nwdaf_self()
            .read()
            .map(|ctx| ctx.can_provision_model())
            .unwrap_or(false)
    });
    build_nf_profile_for(
        nf_instance_id,
        sbi_addr,
        sbi_port,
        allowed_nf_types,
        ml_provision,
    )
}

/// [`build_nf_profile`] for a given [`MlProvision`] outcome, so each outcome is
/// testable without mutating the process-wide role or predictor.
fn build_nf_profile_for(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    allowed_nf_types: &[String],
    ml_provision: MlProvision,
) -> serde_json::Value {
    #[allow(unused_mut)]
    let mut nwdaf_info = nwdaf_info(SUPPORTED_EVENTS);
    // nextgsim#466: UE_MOBILITY is advertised for Nnwdaf_AnalyticsInfo
    // (`eventIds`, the EventId spelling) only while it is served; not in
    // `nwdafEvents`, because the EventsSubscription surface does not serve it.
    #[cfg(feature = "amf-mobility")]
    if AnalyticsId::UeMobility.is_served_by_analytics_info() {
        advertise_analytics_info_event(&mut nwdaf_info, AnalyticsId::UeMobility);
    }
    // nextgsim#465: USER_DATA_CONGESTION likewise, only while served, and only in
    // `eventIds` (the EventsSubscription surface does not serve it).
    #[cfg(feature = "demo-d441a-congestion-loop")]
    if AnalyticsId::UserDataCongestion.is_served_by_analytics_info() {
        advertise_analytics_info_event(&mut nwdaf_info, AnalyticsId::UserDataCongestion);
    }

    // #1570: an MTLF that offers Nnwdaf_MLModelProvision states which
    // Analytics IDs it provisions a model for.
    if let (Some(list), Some(info)) = (ml_analytics_list(ml_provision), nwdaf_info.as_object_mut())
    {
        info.insert("mlAnalyticsList".to_string(), list);
    }
    #[allow(unused_mut)]
    let mut services = nwdaf_services(nf_instance_id, sbi_addr, sbi_port, ml_provision);
    // nextgsim#468: Nnwdaf_MLModelMonitor, only while the demo is on.
    #[cfg(feature = "demo-d441e-model-retrain")]
    if model_monitor::monitor().is_some() {
        services.push(model_monitor::nf_service(
            nf_instance_id,
            sbi_addr,
            sbi_port,
        ));
    }
    // nextgsim#465: the ingest service, so the NRF can grant its token.
    #[cfg(feature = "demo-d441a-congestion-loop")]
    if ran_congestion::serving() {
        services.push(ran_congestion::nf_service(
            nf_instance_id,
            sbi_addr,
            sbi_port,
        ));
    }

    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "NWDAF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": services,
            "nwdafInfo": nwdaf_info,
            "allowedNfTypes": allowed_nf_types,
            "heartBeatTimer": 10
        }),
        sbi_addr,
    )
}

/// The NF service consumers of Nnwdaf_AnalyticsInfo, TS 29.520 §4.3.1.3.2
/// (`29520-k00.txt:4708-4995`): PCF, NSSF, AMF, SMF, NEF, AF, LMF, OAM, NWDAF,
/// DCCF, ADRF, UDM, NRF and SCP, in the clause's order. OAM is left out because
/// it is not a TS 29.510 `NFType` (TS29510_Nnrf_NFManagement.yaml), so no NF
/// profile, token request or discovery query can name it. Set as that service's
/// `NFService.allowedNfTypes` (#1415).
const ANALYTICSINFO_ALLOWED_NF_TYPES: &[&str] = &[
    "PCF", "NSSF", "AMF", "SMF", "NEF", "AF", "LMF", "NWDAF", "DCCF", "ADRF", "UDM", "NRF", "SCP",
];

/// The NF service consumers of Nnwdaf_EventsSubscription, TS 29.520 §4.2.1.3.2
/// (`29520-k00.txt:2501-2820`): the AnalyticsInfo consumers plus the CEF
/// (l.2771) and the UPF (l.2816), in the clause's order, OAM again left out.
/// Set as that service's `NFService.allowedNfTypes` (#1415).
const EVENTSSUBSCRIPTION_ALLOWED_NF_TYPES: &[&str] = &[
    "PCF", "NSSF", "AMF", "SMF", "NEF", "AF", "CEF", "LMF", "NWDAF", "DCCF", "ADRF", "UDM", "NRF",
    "SCP", "UPF",
];

/// The default NF-level `allowedNfTypes` (issue #1412, #1415): the union of the
/// per-service lists ([`EVENTSSUBSCRIPTION_ALLOWED_NF_TYPES`] is a superset of
/// the other two). nrfd authorizes a service only when the profile AND the
/// service allow the consumer, so the NF level must admit every service's
/// consumers, and each service narrows it to its own clause.
///
/// The pre-#1412 list, AMF, SMF, PCF, NEF and SCP, made the NRF hide this NWDAF
/// from, and refuse an `nnwdaf-*` token to, every other consumer the clauses
/// name: a trusted AF (TS 23.288 §6.1), an NSSF, an LMF or a UDM got
/// `nfInstances: []` and `unauthorized_client`.
const SPEC_ALLOWED_NF_TYPES: &[&str] = EVENTSSUBSCRIPTION_ALLOWED_NF_TYPES;

/// The NF service consumers of Nnwdaf_MLModelProvision, TS 29.520 §4.5.1.3.2:
/// the NWDAF (containing an AnLF or MTLF) and the LMF. Set as that service's
/// `NFService.allowedNfTypes`, which nrfd checks together with the NF-level list.
const MLMODELPROVISION_ALLOWED_NF_TYPES: &[&str] = &["NWDAF", "LMF"];

/// [`SPEC_ALLOWED_NF_TYPES`] as owned strings.
fn spec_allowed_nf_types() -> Vec<String> {
    SPEC_ALLOWED_NF_TYPES
        .iter()
        .map(|t| t.to_string())
        .collect()
}

/// The NF-level `allowedNfTypes` this NWDAF registers with (issue #1412):
/// `nwdaf.sbi.nrf_profile.allowed_nf_types` in the config file, the same knob
/// udmd has (#85), else [`SPEC_ALLOWED_NF_TYPES`].
///
/// A missing file, section or key means the default, as for the other file
/// knobs here; a file that exists but cannot be read or parsed fails. A PRESENT key must be a non-empty list of `NFType` tokens
/// (uppercase letters, digits and `_`, as TS 29.510 spells them); anything else
/// fails startup. This is access control, so a typo must not silently bar a
/// consumer, and an empty list must not silently mean "everyone": TS 29.510
/// reads an absent `allowedNfTypes` as no restriction, which is not what an
/// operator writing `[]` meant either way. Duplicates are dropped, order kept.
fn allowed_nf_types_from_config(config_path: &str) -> Result<Vec<String>, String> {
    let default = spec_allowed_nf_types;
    let content = match std::fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(default()),
        Err(e) => return Err(format!("cannot read {config_path}: {e}")),
    };
    let value = serde_yaml::from_str::<serde_yaml::Value>(&content)
        .map_err(|e| format!("{config_path} is not valid YAML: {e}"))?;
    let Some(list) = value
        .get("nwdaf")
        .and_then(|n| n.get("sbi"))
        .and_then(|s| s.get("nrf_profile"))
        .and_then(|p| p.get("allowed_nf_types"))
    else {
        return Ok(default());
    };
    let key = "nwdaf.sbi.nrf_profile.allowed_nf_types";
    let items = list
        .as_sequence()
        .ok_or_else(|| format!("{key} must be a list of NF types, got {list:?}"))?;
    if items.is_empty() {
        return Err(format!(
            "{key} is empty; list the NF types allowed to consume this NWDAF, or omit the key \
             for the TS 29.520 default {SPEC_ALLOWED_NF_TYPES:?}"
        ));
    }
    let mut types: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let t = item
            .as_str()
            .filter(|t| {
                !t.is_empty()
                    && t.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            })
            .ok_or_else(|| {
                format!("{key}: {item:?} is not a TS 29.510 NFType (e.g. \"AF\", \"5G_EIR\")")
            })?;
        if !types.iter().any(|seen| seen == t) {
            types.push(t.to_string());
        }
    }
    Ok(types)
}

/// Build TS 29.510 `NwdafInfo` for a set of supported analytics (issue #175).
///
/// `NwdafInfo` has two event members typed as two DIFFERENT TS 29.520
/// enumerations, so each is emitted in its own spelling:
///
/// - `eventIds` → `EventId` (24 values, the Nnwdaf_AnalyticsInfo spelling). An
///   event with no `EventId` value is skipped, because a consumer discovering us
///   for that API could not name it anyway.
/// - `nwdafEvents` → `NwdafEvent` (25 values, the Nnwdaf_EventsSubscription
///   spelling). Covers every supported event, which is how one with no `EventId`
///   value is still advertised.
///
/// Both have `minItems: 1`, so an empty member is omitted rather than emitted.
///
/// Taken as a parameter rather than read from [`SUPPORTED_EVENTS`] so the
/// spelling logic is testable with events whose two spellings actually differ —
/// same reason `nwdaf_services` takes `can_provision`. With `SUPPORTED_EVENTS`
/// hardcoded, a test could only ever see NF_LOAD, which is spelled identically in
/// both enumerations and therefore proves nothing about the divergence.
fn nwdaf_info(events: &[AnalyticsId]) -> serde_json::Value {
    let event_ids: Vec<&'static str> = events.iter().filter_map(|e| e.as_event_id()).collect();
    let nwdaf_events: Vec<&'static str> = events.iter().map(|e| e.as_str()).collect();

    let mut info = serde_json::Map::new();
    if !event_ids.is_empty() {
        info.insert("eventIds".to_string(), serde_json::json!(event_ids));
    }
    if !nwdaf_events.is_empty() {
        info.insert("nwdafEvents".to_string(), serde_json::json!(nwdaf_events));
    }
    serde_json::Value::Object(info)
}

/// TS 29.510 `NwdafInfo.mlAnalyticsList` (Table 6.1.6.2.45-1, "ML Analytics
/// Filter information supported by Network Data Analytics Services, e.g. the
/// Nnwdaf_MLModelProvision service"), for an NWDAF whose MTLF offers that
/// service (#1570), else `None`.
///
/// One `MlAnalyticsInfo` (Table 6.1.6.2.84-1) whose `mlAnalyticsIds` are
/// [`ml_service::PROVISIONED_ML_EVENTS`], the same list that filters a
/// subscription's events (#1452), so the profile cannot claim an event a
/// Subscribe would answer UNAVAILABLE_ML_MODEL. No `snssaiList` or
/// `trackingAreaList`: this NWDAF is configured with no S-NSSAI or TAI scope,
/// and their absence means "any". No `mlModelInterInfo`: no FL
/// interoperability is offered.
fn ml_analytics_list(ml_provision: MlProvision) -> Option<serde_json::Value> {
    if ml_provision != MlProvision::Offered {
        return None;
    }
    let ids: Vec<&'static str> = ml_service::PROVISIONED_ML_EVENTS
        .iter()
        .map(|e| e.as_str())
        .collect();
    if ids.is_empty() {
        return None;
    }
    Some(serde_json::json!([{ "mlAnalyticsIds": ids }]))
}

/// Add `event` to `nwdafInfo.eventIds` (nextgsim#466).
#[cfg(feature = "amf-mobility")]
fn advertise_analytics_info_event(info: &mut serde_json::Value, event: AnalyticsId) {
    let Some(token) = event.as_event_id() else {
        return;
    };
    let ids = info
        .as_object_mut()
        .map(|o| o.entry("eventIds").or_insert_with(|| serde_json::json!([])));
    if let Some(serde_json::Value::Array(ids)) = ids {
        if !ids.iter().any(|v| v == token) {
            ids.push(serde_json::json!(token));
        }
    }
}

/// The YAML root of the config file, for the `demo:` block (nextgsim#458) and
/// the `amf-mobility` knob. A missing file is an empty root, as for the other
/// file knobs here; one that cannot be read or parsed fails start-up.
fn config_root(config_path: &str) -> Result<serde_yaml::Value, String> {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yaml::from_str(&content)
            .map_err(|e| format!("{config_path} is not valid YAML: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_yaml::Value::Null),
        Err(e) => Err(format!("cannot read {config_path}: {e}")),
    }
}

/// The demos this build can run: `d441c-amf-mobility` under the `amf-mobility`
/// feature, none otherwise.
fn demo_registry() -> nextgcore_demo::DemoRegistry {
    #[allow(unused_mut)]
    let mut specs: Vec<nextgcore_demo::DemoSpec> = Vec::new();
    #[cfg(feature = "amf-mobility")]
    specs.push(amf_mobility::DEMO_SPEC);
    #[cfg(feature = "demo-d441a-congestion-loop")]
    specs.push(ran_congestion::DEMO_SPEC);
    #[cfg(feature = "demo-d441e-model-retrain")]
    specs.push(model_retrain::DEMO_SPEC);
    nextgcore_demo::DemoRegistry::new(&specs)
}

/// The `/metrics` body of a build with a demo: the families every NF shares
/// (including `nextg_demo_enabled` while a demo is active) and the modules' own.
#[cfg(any(feature = "amf-mobility", feature = "demo-d441e-model-retrain"))]
fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "nwdaf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    #[cfg(feature = "amf-mobility")]
    amf_mobility::render_metrics(&mut out);
    #[cfg(feature = "demo-d441e-model-retrain")]
    model_retrain::render_metrics(&mut out);
    #[cfg(feature = "demo-d441e-model-retrain")]
    model_monitor::render_metrics(&mut out);
    #[cfg(feature = "demo-d441a-congestion-loop")]
    ran_congestion::render_metrics(&mut out);
    out
}

/// Whether this NWDAF offers `nnwdaf-mlmodelprovision`, and if not, why.
///
/// TS 29.520 §4.5.1.2 (`29520-k00.txt:6722-6724`): the service "is part of the
/// Nnwdaf service-based interface exhibited by the [NWDAF] containing Model
/// Training Logical Function (MTLF)". So an AnLF-only role never offers it, which
/// is configuration, not a fault. An MTLF whose active predictor cannot be
/// exported (issue #109) could serve no model artefact, which is a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MlProvision {
    /// An MTLF with an exportable predictor: the service is advertised.
    Offered,
    /// The role contains no MTLF (`nwdaf.role: anlf`, nextgsim#468).
    NoMtlf,
    /// An MTLF whose active predictor has no exportable form (issue #109).
    NotExportable,
}

impl MlProvision {
    /// The role decides first: `exportable` is not consulted for an AnLF.
    fn decide(serves_mtlf: bool, exportable: impl FnOnce() -> bool) -> Self {
        if !serves_mtlf {
            Self::NoMtlf
        } else if exportable() {
            Self::Offered
        } else {
            Self::NotExportable
        }
    }

    /// The log line for a withheld service, with its level: info for a role
    /// without an MTLF, warn for an MTLF that cannot export its model (#1493).
    fn withheld_log(self) -> Option<(log::Level, &'static str)> {
        match self {
            Self::Offered => None,
            Self::NoMtlf => Some((
                log::Level::Info,
                "role anlf: this NWDAF contains no MTLF, so nnwdaf-mlmodelprovision is not \
                 offered (TS 29.520 §4.5.1.2)",
            )),
            Self::NotExportable => Some((
                log::Level::Warn,
                "not advertising nnwdaf-mlmodelprovision: the active prediction model has no \
                 exportable form, so no model artefact could be served (issue #109)",
            )),
        }
    }
}

/// The `nfServices[]` this NWDAF advertises.
///
/// `ml_provision` gates `nnwdaf-mlmodelprovision` (issue #109, #1493): the MTLF
/// role is only claimed by an MTLF whose active predictor can actually be
/// exported. Taken as a parameter rather than read from the global context so
/// every branch is testable without mutating process-wide state — swapping the
/// global predictor in a test raced the artefact-download test in the same
/// binary.
fn nwdaf_services(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    ml_provision: MlProvision,
) -> Vec<serde_json::Value> {
    let mut services = vec![
        serde_json::json!({
            "serviceInstanceId": format!("{}-nnwdaf-eventssubscription", nf_instance_id),
            "serviceName": "nnwdaf-eventssubscription",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
            // TS 29.520 §4.2.1.3.2 (#1415): the CEF and the UPF too.
            "allowedNfTypes": EVENTSSUBSCRIPTION_ALLOWED_NF_TYPES
        }),
        serde_json::json!({
            "serviceInstanceId": format!("{}-nnwdaf-analyticsinfo", nf_instance_id),
            "serviceName": "nnwdaf-analyticsinfo",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
            // TS 29.520 §4.3.1.3.2 (#1415): the NF-level union is wider.
            "allowedNfTypes": ANALYTICSINFO_ALLOWED_NF_TYPES
        }),
    ];
    if ml_provision == MlProvision::Offered {
        services.push(serde_json::json!({
            "serviceInstanceId": format!("{}-nnwdaf-mlmodelprovision", nf_instance_id),
            "serviceName": "nnwdaf-mlmodelprovision",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
            // TS 29.520 §4.5.1.3.2: only the NWDAF and the LMF consume this
            // service. The NF-level list (#1412) is wider, and nrfd ANDs the two
            // levels, so without this every AnalyticsInfo consumer could get it.
            "allowedNfTypes": MLMODELPROVISION_ALLOWED_NF_TYPES,
            // TS 29.510 NFService.supportedFeatures; nextgsim#468: feature 4,
            // ModelProvisionExt (TS 29.520 Table 5.4.8-1).
            "supportedFeatures": ml_service::MLMODELPROVISION_SUPPORTED_FEATURES
        }));
    } else if let Some((level, line)) = ml_provision.withheld_log() {
        log::log!(level, "{line}");
    }
    services
}

/// Register NWDAF with NRF
async fn register_with_nrf(
    sbi_ctx: Arc<SbiContext>,
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
    allowed_nf_types: &[String],
) -> Result<(), String> {
    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(());
        }
    };

    log::info!("Registering NWDAF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = build_nf_profile(nf_instance_id, sbi_addr, sbi_port, allowed_nf_types);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("NWDAF registered with NRF successfully (id={nf_instance_id})");
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&nf_profile);

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Nwdaf,
            );
            nextgcore_sbi::nf_addressing::set_instance_host(&mut self_instance, sbi_addr);
            let mut svc = nextgcore_sbi::context::NfService::new(
                "nnwdaf-eventssubscription",
                nextgcore_sbi::types::SbiServiceType::NnwdafEventssubscription,
            );
            svc.port = sbi_port;
            nextgcore_sbi::nf_addressing::set_service_host(&mut svc, sbi_addr);
            self_instance.add_service(svc);
            let mut svc2 = nextgcore_sbi::context::NfService::new(
                "nnwdaf-analyticsinfo",
                nextgcore_sbi::types::SbiServiceType::NnwdafAnalyticsinfo,
            );
            svc2.port = sbi_port;
            nextgcore_sbi::nf_addressing::set_service_host(&mut svc2, sbi_addr);
            self_instance.add_service(svc2);
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

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-nwdafd"]);
        assert_eq!(args.sbi_addr, None);
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-nwdafd"]);
        assert_eq!(args.config, "/etc/nextgcore/nwdaf.yaml");
        assert_eq!(args.sbi_port, None);
        assert_eq!(args.max_subscriptions, 1024);
        assert_eq!(
            args.state_file, None,
            "memory-only is the shipped default (issue #66/#192)"
        );
    }

    /// The documented `--state-file` precedence (issue #66/#192): the flag wins,
    /// and an empty value is unset rather than a path.
    #[test]
    fn state_file_precedence_is_flag_then_env_and_empty_means_unset() {
        let s = |v: &str| Some(v.to_string());

        assert_eq!(resolve_state_file(None, None), None, "neither set");
        assert_eq!(resolve_state_file(s("/f.json"), None), s("/f.json"));
        assert_eq!(resolve_state_file(None, s("/e.json")), s("/e.json"));
        assert_eq!(
            resolve_state_file(s("/f.json"), s("/e.json")),
            s("/f.json"),
            "the flag wins over the environment variable"
        );

        // An unset variable routinely arrives as "" in container deployments;
        // taking it literally would snapshot to a nameless file and log a write
        // error on every mutation.
        assert_eq!(resolve_state_file(None, s("")), None);
        assert_eq!(resolve_state_file(None, s("   ")), None);
        assert_eq!(resolve_state_file(s(""), None), None);
        assert_eq!(
            resolve_state_file(s(""), s("/e.json")),
            None,
            "an explicitly empty flag still wins -- it is an explicit opt-out, \
             not a fallthrough to the environment"
        );
        assert_eq!(
            resolve_state_file(s(" /f.json "), None),
            s("/f.json"),
            "surrounding whitespace is trimmed"
        );
    }

    // --- SbiContext dependency-injection pilot (DANGER-ZONES #1) ---

    #[tokio::test]
    async fn test_register_with_nrf_uses_injected_context() {
        // The injected context carries no NRF URI, so registration is skipped
        // and returns Ok without any network access. This proves
        // register_with_nrf reads the *injected* context rather than the
        // global_context() singleton (which a parallel test might have set).
        let ctx = SbiContext::new_isolated();
        let result = register_with_nrf(
            ctx,
            "127.0.0.1",
            7815,
            "nwdaf-test",
            &spec_allowed_nf_types(),
        )
        .await;
        assert!(
            result.is_ok(),
            "no NRF URI on the injected context should skip registration: {result:?}"
        );
    }

    // --- G2-3: NF profile advertises supported events (contract test) ---

    /// G2-3 honesty contract: the registered NFProfile advertises the supported
    /// analytics, and — issue #175 — it does so in BOTH of `NwdafInfo`'s event
    /// members, each in the enumeration that member is typed as:
    /// `eventIds` → `EventId`, `nwdafEvents` → `NwdafEvent`
    /// (`TS29510_Nnrf_NFManagement.yaml` `NwdafInfo`). Advertising `NwdafEvent`
    /// spellings under `eventIds` is only invisible while every supported event
    /// happens to be spelled the same in both enums.
    #[test]
    fn test_honesty_profile_advertises_supported_event_ids() {
        let profile = build_nf_profile(
            "nwdaf-contract-test",
            "127.0.0.1",
            7815,
            &spec_allowed_nf_types(),
        );

        let member = |name: &str| -> Vec<String> {
            profile
                .get("nwdafInfo")
                .and_then(|i| i.get(name))
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("NFProfile must carry nwdafInfo.{name}"))
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| panic!("{name} entries are strings"))
                        .to_string()
                })
                .collect()
        };

        // eventIds is the EventId spelling, in SUPPORTED_EVENTS order, skipping
        // any event EventId does not define.
        let event_ids = member("eventIds");
        assert!(
            !event_ids.is_empty(),
            "nwdafInfo.eventIds has minItems 1 in the yaml"
        );
        let expected_ids: Vec<&str> = SUPPORTED_EVENTS
            .iter()
            .filter_map(|e| e.as_event_id())
            .collect();
        assert_eq!(event_ids, expected_ids);
        for t in &event_ids {
            assert!(
                AnalyticsId::from_event_id(t).is_some(),
                "advertised eventId {t} must be a TS 29.520 EventId value"
            );
        }

        // nwdafEvents is the NwdafEvent spelling, covering every supported event.
        let nwdaf_events = member("nwdafEvents");
        let expected_events: Vec<&str> = SUPPORTED_EVENTS.iter().map(|e| e.as_str()).collect();
        assert_eq!(nwdaf_events, expected_events);
        for t in &nwdaf_events {
            assert!(
                AnalyticsId::from_str(t).is_some(),
                "advertised nwdafEvent {t} must be a TS 29.520 NwdafEvent value"
            );
        }
        assert_eq!(
            nwdaf_events.len(),
            SUPPORTED_EVENTS.len(),
            "nwdafEvents must cover every supported event, even those EventId omits"
        );

        // Initially exactly NF_LOAD (the only live collector, G2-1), which is
        // spelled identically in both enumerations.
        assert_eq!(event_ids, vec!["NF_LOAD"]);
        assert_eq!(nwdaf_events, vec!["NF_LOAD"]);
    }

    /// **The load-bearing half of the #175 profile fix.** The test above can only
    /// ever see NF_LOAD, which is spelled the same in both enumerations, so it
    /// cannot tell `eventIds` built from `EventId` spellings apart from one built
    /// from `NwdafEvent` spellings. This drives the pure builder with events whose
    /// spellings DO differ.
    #[test]
    fn test_nwdaf_info_emits_each_member_in_its_own_enumeration() {
        let info = nwdaf_info(&[
            AnalyticsId::NfLoad,
            AnalyticsId::SliceLoadLevel,
            AnalyticsId::PfdDetermination,
        ]);

        // eventIds is EventId: SLICE_LOAD_LEVEL becomes LOAD_LEVEL_INFORMATION,
        // and PFD_DETERMINATION is dropped because EventId has no value for it.
        assert_eq!(
            info["eventIds"],
            serde_json::json!(["NF_LOAD", "LOAD_LEVEL_INFORMATION"]),
            "eventIds must carry EventId spellings only"
        );

        // nwdafEvents is NwdafEvent: all three, in their own spelling. This is
        // how an event with no EventId value is still advertised at all.
        assert_eq!(
            info["nwdafEvents"],
            serde_json::json!(["NF_LOAD", "SLICE_LOAD_LEVEL", "PFD_DETERMINATION"]),
            "nwdafEvents must carry NwdafEvent spellings for every supported event"
        );

        // An event with no EventId value at all → eventIds omitted, not empty
        // (minItems 1), while nwdafEvents still advertises it.
        let only_pfd = nwdaf_info(&[AnalyticsId::PfdDetermination]);
        assert!(
            only_pfd.get("eventIds").is_none(),
            "an empty eventIds would violate minItems 1: {only_pfd}"
        );
        assert_eq!(
            only_pfd["nwdafEvents"],
            serde_json::json!(["PFD_DETERMINATION"])
        );

        // No supported events at all → both omitted.
        assert_eq!(nwdaf_info(&[]), serde_json::json!({}));
    }

    // --- nwafd-02: Nnwdaf_AnalyticsInfo is GET-only at the routing layer ---

    #[tokio::test]
    async fn test_routing_analytics_post_is_405() {
        // TS 29.520 §4.3.2.2.2: Nnwdaf_AnalyticsInfo is HTTP GET. A POST to the
        // analytics resource must be rejected with 405 Method Not Allowed.
        let req = SbiRequest::post("/nnwdaf-analyticsinfo/v1/analytics");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 405, "POST /analytics must be 405");
    }

    #[tokio::test]
    async fn test_routing_analytics_get_is_routed() {
        // A GET with a valid event-id reaches the handler. G2-1: the handler
        // computes from ingested NRF data only, so seed the global engine with
        // a sample for a test-unique instance and filter the query to it —
        // proving the route reaches the real handler AND real data flows back.
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        {
            let ctx = nwdaf_self();
            let guard = ctx.read().unwrap();
            guard
                .lock_engine()
                .ingest_nf_load(crate::analytics::NfLoadSample::now(
                    "AMF",
                    "amf-route-test",
                    0.5,
                    0.0,
                    0,
                ));
        }
        let req = SbiRequest::get(
            "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter=%7B%22nfInstanceIds%22%3A%5B%22amf-route-test%22%5D%7D",
        );
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(
            resp.status, 200,
            "GET /analytics?event-id=NF_LOAD with data must be 200"
        );
    }

    /// Issue #171 acceptance: `GET /nnwdaf-analyticsinfo/v1/context`
    /// (`GetNwdafContext`) is routed through the REAL router and no longer 404s.
    /// A GET with no `context-ids` reaches the handler and is answered 400 by it —
    /// which is only distinguishable from the old unrouted 404 because the route
    /// exists. Non-GET is 405, not 404, for the same reason.
    #[tokio::test]
    async fn test_routing_nwdaf_context_is_routed() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        let resp = nwdaf_sbi_request_handler(SbiRequest::get(
            "/nnwdaf-analyticsinfo/v1/context?context-ids=%7B%22contextIds%22%3A%5B%7B%22subscriptionId%22%3A%22nope%22%2C%22nfAnaCtxts%22%3A%5B%22NF_LOAD%22%5D%7D%5D%7D",
        ))
        .await;
        assert_eq!(
            resp.status, 204,
            "GET /context with an unknown subscription must be 204 (204 proves it is routed; \
             404 was the unrouted defect)"
        );

        let resp =
            nwdaf_sbi_request_handler(SbiRequest::get("/nnwdaf-analyticsinfo/v1/context")).await;
        assert_eq!(
            resp.status, 400,
            "GET /context without the mandatory context-ids must be 400, not 404"
        );

        let resp =
            nwdaf_sbi_request_handler(SbiRequest::post("/nnwdaf-analyticsinfo/v1/context")).await;
        assert_eq!(resp.status, 405, "POST /context must be 405, not 404");
    }

    /// G2-3 honesty (acceptance check 1, curl-style through the REAL router):
    /// GET ?event-id=UE_MOBILITY returns 204 with an empty body — a 200 here
    /// is the empty-200 dishonesty this item removes. The engine is seeded
    /// with NF_LOAD data first so the 204 provably comes from the
    /// supported-events gate, not from a globally-empty engine.
    #[tokio::test]
    async fn test_honesty_routing_unsupported_event_get_204() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        {
            let ctx = nwdaf_self();
            let guard = ctx.read().unwrap();
            guard
                .lock_engine()
                .ingest_nf_load(crate::analytics::NfLoadSample::now(
                    "AMF",
                    "amf-honesty-route",
                    0.5,
                    0.0,
                    0,
                ));
        }
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(
            resp.status, 204,
            "GET ?event-id=UE_MOBILITY must be 204 No Content (a 200 fails CI)"
        );
        assert!(
            resp.http.content.as_deref().is_none_or(str::is_empty),
            "the 204 must carry an empty body"
        );
    }

    // --- G2-1: NFStatusNotify callback route ---

    #[tokio::test]
    async fn test_routing_nfstatus_notify_post_routed() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-nfstatus-notify/v1/notify")
            .with_json_body(&serde_json::json!({
                "event": "NF_REGISTERED",
                "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/amf-route-notify",
                "nfProfile": {
                    "nfInstanceId": "amf-route-notify",
                    "nfType": "AMF",
                    "nfStatus": "REGISTERED",
                    "load": 10
                }
            }))
            .expect("valid JSON body");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 204, "NFStatusNotify must route and return 204");
    }

    #[tokio::test]
    async fn test_routing_nfstatus_notify_get_is_405() {
        let req = SbiRequest::get("/nnwdaf-nfstatus-notify/v1/notify");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 405, "GET on the notify callback must be 405");
    }

    // --- nwafd-05 / issue #109: Nnwdaf_MLModelProvision is Subscribe/Notify on
    //     /subscriptions, plus a model-artefact route the notified
    //     mLFileAddr.mLModelUrl resolves to ---

    #[tokio::test]
    async fn test_routing_mlmodelprovision_bespoke_registry_still_gone() {
        // The old bespoke /models *registry* resource stays gone: the artefact
        // route added by #109 is a GET on /models/{event}/{subscriptionId}, not
        // a POST-able collection.
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-mlmodelprovision/v1/models");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 404, "the /models registry must stay removed");
    }

    /// **The #109 acceptance test.** A GET on the notified `mLModelUrl` must
    /// return 200 with a non-empty artefact — and not merely a well-formed one:
    /// the bytes must parse back to a model that predicts what this NWDAF
    /// predicts. Before #109 the URL was fabricated and this route 404'd.
    #[tokio::test]
    async fn test_ml_model_url_serves_a_real_downloadable_artefact() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        // Exactly the path a notification advertises (nextgsim#468: the
        // version's sha256 address).
        let model = nwdaf_self()
            .read()
            .unwrap()
            .current_model_version()
            .expect("the default predictor is provisioned");
        let url = model.url("http://x", AnalyticsId::NfLoad);
        let path = url.strip_prefix("http://x").expect("built from the base");
        let resp = nwdaf_sbi_request_handler(SbiRequest::get(path)).await;

        assert_eq!(resp.status, 200, "the advertised model URL must be live");
        assert_eq!(
            resp.http.get_header("Content-Type").map(String::as_str),
            Some(onnx_export::ONNX_CONTENT_TYPE)
        );
        let bytes = resp
            .http
            .binary_content
            .as_ref()
            .expect("the artefact is served as bytes, not JSON");
        assert!(!bytes.is_empty(), "a non-empty model-file body");

        // The load-bearing assertion: this really is the NWDAF's model.
        let parsed = onnx_model::OnnxLinearRegressor::from_bytes(bytes, "onnx:served")
            .expect("the served bytes are a valid ONNX LinearRegressor");
        let series = [0.2, 0.35, 0.4, 0.55, 0.6];
        let (expected, _) =
            ml_service::InferenceModel::predict_series(&ml_service::OlsLinearModel, &series)
                .expect("baseline predicts");
        let (actual, _) = ml_service::InferenceModel::predict_series(&parsed, &series)
            .expect("served model predicts");
        assert!(
            (expected - actual).abs() < 1e-6,
            "the downloaded model must reproduce the NWDAF's own prediction \
             (expected {expected}, got {actual})"
        );
    }

    /// nextgsim#468: the served bytes ARE the notified version (sha256), its
    /// manifest is served beside it, the #109 URL an older build notified still
    /// resolves, and anything else is a 404 rather than some model.
    #[tokio::test]
    async fn test_ml_model_routes_serve_the_addressed_version() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let model = nwdaf_self()
            .read()
            .unwrap()
            .current_model_version()
            .expect("provisioned");
        let get =
            |path: String| async move { nwdaf_sbi_request_handler(SbiRequest::get(&path)).await };
        let base = "/nnwdaf-mlmodelprovision/v1/models";

        let resp = get(format!("{base}/NF_LOAD/{}", model.sha256)).await;
        assert_eq!(resp.status, 200);
        let bytes = resp.http.binary_content.as_ref().expect("bytes");
        assert_eq!(model_store::sha256_hex(bytes), model.sha256);

        let resp = get(format!("{base}/NF_LOAD/{}.manifest.json", model.sha256)).await;
        assert_eq!(resp.status, 200);
        let manifest: serde_json::Value = resp.json_body().expect("manifest JSON");
        assert_eq!(manifest["sha256"], model.sha256);
        assert_eq!(manifest["id"], model_store::MODEL_ID);

        let resp = get(format!("{base}/NF_LOAD/mlsub-legacy")).await;
        assert_eq!(
            resp.status, 200,
            "the #109 URL form serves the active model"
        );
        assert_eq!(
            model_store::sha256_hex(resp.http.binary_content.as_ref().unwrap()),
            model.sha256
        );

        let unknown = model_store::sha256_hex(b"never provisioned");
        assert_eq!(get(format!("{base}/NF_LOAD/{unknown}")).await.status, 404);
        assert_eq!(
            get(format!("{base}/NF_LOAD/{unknown}.manifest.json"))
                .await
                .status,
            404
        );
        assert_eq!(
            get(format!("{base}/NOT_AN_EVENT/{}", model.sha256))
                .await
                .status,
            404
        );
    }

    #[tokio::test]
    async fn test_ml_model_route_rejects_non_get() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-mlmodelprovision/v1/models/NF_LOAD/mlsub-1");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 405);
    }

    /// The profile advertises the MTLF service only when a model can actually be
    /// served (issue #109). Both branches are asserted on the pure service
    /// builder: an earlier version swapped the process-global predictor, which
    /// raced `test_ml_model_url_serves_a_real_downloadable_artefact` in this same
    /// binary — the two tests share `nwdaf_self()`.
    #[test]
    fn test_profile_advertises_mlmodelprovision_only_when_exportable() {
        let names = |can_provision: bool| -> Vec<String> {
            let ml = if can_provision {
                MlProvision::Offered
            } else {
                MlProvision::NotExportable
            };
            nwdaf_services("nwdaf-test", "10.0.0.5", 7777, ml)
                .iter()
                .filter_map(|s| s["serviceName"].as_str().map(String::from))
                .collect()
        };

        let with = names(true);
        assert!(
            with.iter().any(|n| n == "nnwdaf-mlmodelprovision"),
            "an exportable predictor means the MTLF role is real: {with:?}"
        );

        let without = names(false);
        assert!(
            !without.iter().any(|n| n == "nnwdaf-mlmodelprovision"),
            "a NWDAF that cannot serve a model must not claim the MTLF role: {without:?}"
        );
        // Only that one service is gated; the rest are unconditional.
        assert_eq!(without.len() + 1, with.len());
        assert!(without.iter().any(|n| n == "nnwdaf-eventssubscription"));
        assert!(without.iter().any(|n| n == "nnwdaf-analyticsinfo"));
    }

    /// #1493: an AnLF-only role withholds nnwdaf-mlmodelprovision because it
    /// contains no MTLF, and says so at info, without consulting the model. Only
    /// an MTLF whose model cannot be exported is warned about.
    #[test]
    fn an_anlf_withholds_mlmodelprovision_for_its_role_not_its_model() {
        let anlf = MlProvision::decide(false, || panic!("an AnLF's model is not consulted"));
        assert_eq!(anlf, MlProvision::NoMtlf);
        let (level, line) = anlf.withheld_log().expect("withheld");
        assert_eq!(level, log::Level::Info);
        assert!(line.starts_with("role anlf: "), "{line}");
        assert!(!line.contains("exportable"), "{line}");

        let broken = MlProvision::decide(true, || false);
        assert_eq!(broken, MlProvision::NotExportable);
        let (level, line) = broken.withheld_log().expect("withheld");
        assert_eq!(level, log::Level::Warn);
        assert!(line.contains("no exportable form"), "{line}");

        assert_eq!(MlProvision::decide(true, || true), MlProvision::Offered);
        assert_eq!(MlProvision::Offered.withheld_log(), None);

        // Both withheld reasons advertise the same services: only the log differs.
        let names = |ml| -> Vec<String> {
            nwdaf_services("nwdaf-test", "10.0.0.5", 7777, ml)
                .iter()
                .filter_map(|s| s["serviceName"].as_str().map(String::from))
                .collect()
        };
        assert_eq!(
            names(MlProvision::NoMtlf),
            names(MlProvision::NotExportable)
        );
        assert!(!names(MlProvision::NoMtlf)
            .iter()
            .any(|n| n == "nnwdaf-mlmodelprovision"));
    }

    /// The default build's predictor IS exportable, so a freshly initialised
    /// NWDAF advertises the service — the integration half of the above.
    #[tokio::test]
    async fn test_default_build_advertises_mlmodelprovision() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let profile = build_nf_profile("nwdaf-test", "10.0.0.5", 7777, &spec_allowed_nf_types());
        let names: Vec<&str> = profile["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .filter_map(|s| s["serviceName"].as_str())
            .collect();
        assert!(names.contains(&"nnwdaf-mlmodelprovision"), "{names:?}");
        // nextgsim#468: it declares ModelProvisionExt (TS 29.520 Table 5.4.8-1).
        let ml = profile["nfServices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["serviceName"] == "nnwdaf-mlmodelprovision")
            .unwrap();
        assert_eq!(ml["supportedFeatures"], "8");
    }

    #[tokio::test]
    async fn test_routing_mlmodelprovision_subscriptions_post_routed() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-mlmodelprovision/v1/subscriptions")
            .with_json_body(&serde_json::json!({
                "notifUri": "http://anlf.local/cb",
                "mLEventSubscs": [ { "mLEvent": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(
            resp.status, 201,
            "POST /nnwdaf-mlmodelprovision/v1/subscriptions must reach the create handler"
        );
    }

    #[tokio::test]
    async fn test_routing_subscription_put_routed() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::put("/nnwdaf-eventssubscription/v1/subscriptions/unknown-id")
            .with_json_body(&serde_json::json!({
                "notificationURI": "http://amf.local/cb",
                "eventSubscriptions": [ { "event": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(
            resp.status, 404,
            "PUT must route to the update handler (404, not 405)"
        );
    }

    #[tokio::test]
    async fn test_injected_contexts_are_isolated() {
        // Two injected contexts must not share state — the whole point of DI.
        let a = SbiContext::new_isolated();
        let b = SbiContext::new_isolated();

        a.set_nrf_uri("http://nrf-a:7777").await;

        assert_eq!(a.get_nrf_uri().await.as_deref(), Some("http://nrf-a:7777"));
        assert_eq!(
            b.get_nrf_uri().await,
            None,
            "context b must not observe context a's NRF URI"
        );
    }
}

/// G2-1 STRICT-PEER test (the pcfd lesson: no lenient mocks).
///
/// The conformant peer is our REAL nrfd: its NF-instance registry
/// (`nf_manager`), its real `apply_json_patch`, its real
/// `NotificationData`/`profileChanges` serializer and its real HTTP notify
/// sender (`nrf_nnrf_nfm_send_*_notify_all_async`) deliver TS 29.510
/// NFStatusNotify bodies over a real socket to nwdafd's REAL SBI server and
/// router. Analytics are then queried back over the wire via
/// Nnwdaf_AnalyticsInfo.
#[cfg(test)]
mod g21_strict_peer_tests {
    use super::*;
    use nextgcore_nrfd::{
        apply_json_patch, nf_manager, nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async,
        nrf_nnrf_nfm_send_nf_status_notify_all_async, ChangeItem, NfProfile, NotificationEventType,
        SubscriptionData,
    };
    use nextgcore_sbi::client::SbiClient;
    use serde_json::{json, Value};

    const INSTANCE: &str = "g21-strict-amf";
    /// Percent-encoded `{"nfInstanceIds":["g21-strict-amf"]}`.
    const FILTER_QS: &str = "%7B%22nfInstanceIds%22%3A%5B%22g21-strict-amf%22%5D%7D";
    const NRF_SELF_URI: &str = "http://nrf.test:7777";

    async fn get_nf_load(client: &SbiClient) -> (u16, Option<Value>) {
        let uri =
            format!("/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter={FILTER_QS}");
        let resp = client
            .send_request(SbiRequest::get(&uri))
            .await
            .expect("GET analytics over the wire");
        let body = resp
            .http
            .content
            .as_deref()
            .and_then(|b| serde_json::from_str::<Value>(b).ok());
        (resp.status, body)
    }

    fn avg_of(body: &Option<Value>) -> u64 {
        body.as_ref()
            .and_then(|b| b.get("nfLoadLevelInfos"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|i| i.get("nfLoadLevelAverage"))
            .and_then(|v| v.as_u64())
            .expect("nfLoadLevelAverage present")
    }

    /// Full chain: NRF NF_REGISTERED → PATCH /load (two different values) →
    /// NF_DEREGISTERED, all delivered by nrfd's real notify pipeline, with the
    /// reported nfLoadLevelAverage tracking every PATCHed value and analytics
    /// going dark (204) after deregistration.
    #[tokio::test]
    async fn test_g21_strict_peer_nrf_load_ingestion() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        // Real nwdafd SBI server on a free localhost port.
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let server = SbiServer::on_listener(
            NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
            port_listener,
        );
        server
            .start(nwdaf_sbi_request_handler)
            .await
            .expect("nwdafd server starts");

        // Conformant peer state: our real nrfd registry with a fake AMF whose
        // profile carries load=40, plus a subscription pointing at nwdafd's
        // real NFStatusNotify callback.
        let profile = NfProfile::from_json(&json!({
            "nfInstanceId": INSTANCE,
            "nfType": "AMF",
            "nfStatus": "REGISTERED",
            "load": 40,
        }))
        .expect("valid NFProfile");
        nf_manager()
            .register(profile.clone())
            .expect("register at nrfd");
        nf_manager().add_subscription(SubscriptionData {
            id: "g21-strict-sub".to_string(),
            req_nf_type: Some("NWDAF".to_string()),
            req_nf_instance_id: None,
            notification_uri: format!("http://127.0.0.1:{port}/nnwdaf-nfstatus-notify/v1/notify"),
            subscr_cond: None, // all NFs
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
        });

        let client = SbiClient::with_host_port("127.0.0.1", port);

        // ── Leg A: NF_REGISTERED (full profile, load 40) ────────────────────
        let sent = nrf_nnrf_nfm_send_nf_status_notify_all_async(
            NotificationEventType::NfRegistered,
            &profile,
            NRF_SELF_URI,
        )
        .await
        .expect("nrfd delivers NF_REGISTERED");
        assert_eq!(sent, 1, "exactly our subscription must be notified");

        let (status, body) = get_nf_load(&client).await;
        assert_eq!(status, 200, "data exists after NF_REGISTERED");
        assert_eq!(avg_of(&body), 40, "average must equal the registered load");
        let info = body.as_ref().expect("body")["nfLoadLevelInfos"][0].clone();
        assert_eq!(info["nfInstanceId"].as_str(), Some(INSTANCE));
        assert_eq!(
            info["nfStatus"]["statusRegistered"].as_u64(),
            Some(100),
            "nfStatus must come from the NRF profile, in the TS 29.520 object form"
        );
        assert!(info["confidence"].is_u64(), "confidence is a Uinteger");
        assert!(
            info.get("predictedLoad").is_none(),
            "non-spec predictedLoad must not appear on the wire"
        );

        // ── Leg B: PATCH /load → 80, via nrfd's real patch + notify path ────
        let pre = profile.to_json();
        let patch = json!([{"op": "replace", "path": "/load", "value": 80}]);
        let mut post = pre.clone();
        apply_json_patch(&mut post, &patch).expect("nrfd applies the PATCH");
        let updated80 = NfProfile::from_json(&post).expect("patched profile");
        let sent = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
            &updated80,
            NRF_SELF_URI,
            vec![ChangeItem {
                op: "replace".to_string(),
                path: "/load".to_string(),
                value: Some(json!(80)),
                orig_value: Some(json!(40)),
            }],
        )
        .await
        .expect("nrfd delivers NF_PROFILE_CHANGED");
        assert_eq!(sent, 1);

        let (status, body) = get_nf_load(&client).await;
        assert_eq!(status, 200);
        // Samples [40, 80] → average 60.
        assert_eq!(
            avg_of(&body),
            60,
            "the reported average must move with the PATCHed load (40→80)"
        );

        // ── Leg B': a DIFFERENT PATCH value moves the average differently ───
        let patch = json!([{"op": "replace", "path": "/load", "value": 90}]);
        let mut post90 = post.clone();
        apply_json_patch(&mut post90, &patch).expect("nrfd applies the PATCH");
        let updated90 = NfProfile::from_json(&post90).expect("patched profile");
        let sent = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
            &updated90,
            NRF_SELF_URI,
            vec![ChangeItem {
                op: "replace".to_string(),
                path: "/load".to_string(),
                value: Some(json!(90)),
                orig_value: Some(json!(80)),
            }],
        )
        .await
        .expect("nrfd delivers NF_PROFILE_CHANGED");
        assert_eq!(sent, 1);

        let (status, body) = get_nf_load(&client).await;
        assert_eq!(status, 200);
        // Samples [40, 80, 90] → average 70 — a constant/fabricated value
        // could not produce 40 → 60 → 70 tracking the PATCH sequence.
        assert_eq!(
            avg_of(&body),
            70,
            "a second, different PATCH value must move the average again"
        );

        // ── Fail-closed over the wire: mandatory-IE violation → 400 ─────────
        let bad = client
            .post_json(
                "/nnwdaf-nfstatus-notify/v1/notify",
                &json!({ "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x" }),
            )
            .await
            .expect("POST over the wire");
        assert_eq!(bad.status, 400, "missing event must fail closed with 400");

        // ── Leg C: NF_DEREGISTERED → analytics go dark (204, no fabrication) ─
        let sent = nrf_nnrf_nfm_send_nf_status_notify_all_async(
            NotificationEventType::NfDeregistered,
            &updated90,
            NRF_SELF_URI,
        )
        .await
        .expect("nrfd delivers NF_DEREGISTERED");
        assert_eq!(sent, 1);

        let (status, body) = get_nf_load(&client).await;
        assert_eq!(
            status, 204,
            "after the data source is gone, NF_LOAD must be 204 — numbers here would mean fabricated analytics"
        );
        assert!(body.is_none(), "204 carries no body");

        server.stop().await.expect("server stops");
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `nwdaf_sbi_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=NWDAF, ES256-signed against the served JWKS) passes through.
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
            "iss": "NRF", "sub": "nwdaf-1", "aud": aud,
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
        super::nwdaf_context_init("nwdaf-h8-test".to_string(), 256);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Nwdaf);
        let server = SbiServer::on_listener(cfg, port_listener);
        server
            .start(super::nwdaf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("nwdaf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "nwdaf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("nwdaf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "nwdaf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
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
            client.get("/nnwdaf-analyticsinfo/v1/analytics"),
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
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "nnwdaf-analyticsinfo");
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics")
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
        let token = build_es256_token(&sk, "nrf-es256", "NWDAF", "nnwdaf-analyticsinfo");
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics/does-not-exist")
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
            let profile = build_nf_profile("id", host, 7777, &spec_allowed_nf_types());
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}

/// Issue #1412: the NF-level `allowedNfTypes` is TS 29.520 §4.3.1.3.2's consumer
/// list by default, configurable, and is what the real nrfd's discovery filter
/// and access-token decision act on.
#[cfg(test)]
mod allowed_nf_types_1412_tests {
    use super::*;
    use nextgcore_nrfd::{discover_profiles, nf_manager, DiscoveryQuery, NfProfile};

    /// The consumers the issue found barred, and the ones that already worked.
    const NEWLY_ALLOWED: &[&str] = &["AF", "NSSF", "LMF", "UDM", "NWDAF", "DCCF", "ADRF", "NRF"];
    const ALREADY_ALLOWED: &[&str] = &["AMF", "SMF", "PCF", "NEF", "SCP"];

    fn profile_json(id: &str, allowed: &[String]) -> serde_json::Value {
        build_nf_profile(id, "127.0.0.1", 7815, allowed)
    }

    fn write_config(tag: &str, body: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("nwdaf-1412-{tag}-{}.yaml", std::process::id()));
        std::fs::write(&path, body).expect("write config");
        path
    }

    fn from_config(tag: &str, body: &str) -> Result<Vec<String>, String> {
        let path = write_config(tag, body);
        let out = allowed_nf_types_from_config(path.to_str().expect("utf-8 path"));
        let _ = std::fs::remove_file(&path);
        out
    }

    /// #1415: the NF-level default is the union of the services' consumer
    /// lists, §4.2.1.3.2 being the widest (§4.3.1.3.2 plus CEF and UPF).
    #[test]
    fn the_default_profile_lists_the_union_of_the_service_consumers() {
        let profile = profile_json("nwdaf-1412-default", &spec_allowed_nf_types());
        let listed: Vec<&str> = profile["allowedNfTypes"]
            .as_array()
            .expect("allowedNfTypes array")
            .iter()
            .map(|v| v.as_str().expect("string"))
            .collect();
        assert_eq!(
            listed,
            [
                "PCF", "NSSF", "AMF", "SMF", "NEF", "AF", "CEF", "LMF", "NWDAF", "DCCF", "ADRF",
                "UDM", "NRF", "SCP", "UPF"
            ],
            "TS 29.520 §4.2.1.3.2, in the clause's order, without OAM (not an NFType)"
        );
        assert!(!listed.contains(&"OAM"));
        let mut union: Vec<&str> = ANALYTICSINFO_ALLOWED_NF_TYPES
            .iter()
            .chain(EVENTSSUBSCRIPTION_ALLOWED_NF_TYPES)
            .chain(MLMODELPROVISION_ALLOWED_NF_TYPES)
            .copied()
            .collect();
        union.sort_unstable();
        union.dedup();
        let mut sorted = listed.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, union, "the NF level is exactly the services' union");
    }

    /// #1415: each service registers its own clause's list, and the real
    /// nrfd's `authorizes_service` (profile AND service) grants the CEF and the
    /// UPF EventsSubscription but not AnalyticsInfo.
    #[test]
    fn nrfd_authorizes_eventssubscription_for_cef_and_upf_only_there() {
        let mut doc = profile_json("nwdaf-1415", &spec_allowed_nf_types());
        doc["nfServices"] = serde_json::Value::Array(nwdaf_services(
            "nwdaf-1415",
            "127.0.0.1",
            7815,
            MlProvision::Offered,
        ));
        let service_list = |name: &str| -> Vec<String> {
            doc["nfServices"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["serviceName"] == name)
                .and_then(|s| s["allowedNfTypes"].as_array())
                .unwrap_or_else(|| panic!("{name} carries allowedNfTypes"))
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            service_list("nnwdaf-eventssubscription"),
            EVENTSSUBSCRIPTION_ALLOWED_NF_TYPES
        );
        assert_eq!(
            service_list("nnwdaf-analyticsinfo"),
            ANALYTICSINFO_ALLOWED_NF_TYPES
        );

        let producer = NfProfile::from_json(&doc).expect("nrfd accepts the profile");
        for consumer in ["CEF", "UPF"] {
            assert_eq!(
                producer.authorizes_service(consumer, "nnwdaf-eventssubscription"),
                (true, true),
                "{consumer} is a §4.2.1.3.2 consumer"
            );
            assert_eq!(
                producer.authorizes_service(consumer, "nnwdaf-analyticsinfo"),
                (true, false),
                "{consumer} is not a §4.3.1.3.2 consumer"
            );
            assert_eq!(
                producer.authorizes_service(consumer, "nnwdaf-mlmodelprovision"),
                (true, false),
                "{consumer} is not a §4.5.1.3.2 consumer"
            );
        }
        for consumer in ANALYTICSINFO_ALLOWED_NF_TYPES {
            for service in ["nnwdaf-eventssubscription", "nnwdaf-analyticsinfo"] {
                assert_eq!(
                    producer.authorizes_service(consumer, service),
                    (true, true),
                    "{consumer} keeps {service}"
                );
            }
        }
        assert_eq!(
            producer.authorizes_service("CHF", "nnwdaf-eventssubscription"),
            (true, false),
            "a type no clause lists stays barred"
        );
    }

    #[test]
    fn the_shipped_compose_config_registers_the_spec_default() {
        let shipped = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../docker/rust/configs/5gc/nwdaf.yaml"
        );
        assert!(std::path::Path::new(shipped).exists(), "{shipped}");
        assert_eq!(
            allowed_nf_types_from_config(shipped),
            Ok(spec_allowed_nf_types())
        );
    }

    #[test]
    fn absent_file_section_or_key_means_the_spec_default() {
        assert_eq!(
            allowed_nf_types_from_config("/nonexistent/nwdaf-1412.yaml"),
            Ok(spec_allowed_nf_types())
        );
        assert_eq!(
            from_config("nosection", "logger:\n  level: info\n"),
            Ok(spec_allowed_nf_types())
        );
        assert_eq!(
            from_config(
                "nokey",
                "nwdaf:\n  sbi:\n    nrf_profile:\n      heartbeat_timer: 10\n"
            ),
            Ok(spec_allowed_nf_types())
        );
    }

    #[test]
    fn a_configured_list_replaces_the_default_deduplicated_in_order() {
        let body =
            "nwdaf:\n  sbi:\n    nrf_profile:\n      allowed_nf_types: [NEF, AF, NEF, 5G_EIR]\n";
        assert_eq!(
            from_config("custom", body),
            Ok(vec![
                "NEF".to_string(),
                "AF".to_string(),
                "5G_EIR".to_string()
            ])
        );
    }

    #[test]
    fn a_malformed_configured_list_fails_instead_of_registering() {
        for (tag, value) in [
            ("empty", "[]"),
            ("scalar", "AF"),
            ("lower", "[af]"),
            ("blank", "[\"\"]"),
            ("spaced", "[\"AF \"]"),
            ("number", "[42]"),
        ] {
            let body =
                format!("nwdaf:\n  sbi:\n    nrf_profile:\n      allowed_nf_types: {value}\n");
            let err = from_config(tag, &body).expect_err(tag);
            assert!(
                err.contains("nwdaf.sbi.nrf_profile.allowed_nf_types"),
                "{tag}: {err}"
            );
        }
    }

    /// The token path: nrfd's `authorize_access_token` grants a scope when a
    /// producer profile's `authorizes_service` permits the consumer type
    /// (TS 33.501 §13.4.1.1.2 step 2). Run on the profile nwdafd registers.
    #[test]
    fn nrfd_authorizes_an_analyticsinfo_token_for_every_listed_consumer() {
        let doc = profile_json("nwdaf-1412-token", &spec_allowed_nf_types());
        let producer = NfProfile::from_json(&doc).expect("nrfd accepts the profile");
        for consumer in NEWLY_ALLOWED.iter().chain(ALREADY_ALLOWED) {
            assert_eq!(
                producer.authorizes_service(consumer, "nnwdaf-analyticsinfo"),
                (true, true),
                "{consumer} must get an nnwdaf-analyticsinfo token"
            );
        }
        assert_eq!(
            producer.authorizes_service("CHF", "nnwdaf-analyticsinfo"),
            (true, false),
            "a type TS 29.520 §4.3.1.3.2 does not list stays barred (unauthorized_client)"
        );
    }

    /// MLModelProvision keeps its own, narrower consumer list (§4.5.1.3.2): the
    /// wider NF-level list must not open it to the AnalyticsInfo consumers.
    #[test]
    fn nrfd_authorizes_mlmodelprovision_only_for_nwdaf_and_lmf() {
        let mut doc = profile_json("nwdaf-1412-mlmp", &spec_allowed_nf_types());
        doc["nfServices"] = serde_json::Value::Array(nwdaf_services(
            "nwdaf-1412-mlmp",
            "127.0.0.1",
            7815,
            MlProvision::Offered,
        ));
        let producer = NfProfile::from_json(&doc).expect("nrfd accepts the profile");
        for consumer in ["NWDAF", "LMF"] {
            assert_eq!(
                producer.authorizes_service(consumer, "nnwdaf-mlmodelprovision"),
                (true, true),
                "{consumer} is a §4.5.1.3.2 consumer"
            );
        }
        for consumer in [
            "AF", "NSSF", "UDM", "NRF", "DCCF", "ADRF", "AMF", "SMF", "PCF", "NEF", "SCP",
        ] {
            assert_eq!(
                producer.authorizes_service(consumer, "nnwdaf-mlmodelprovision"),
                (true, false),
                "{consumer} is not a §4.5.1.3.2 consumer"
            );
            assert_eq!(
                producer.authorizes_service(consumer, "nnwdaf-analyticsinfo"),
                (true, true),
                "{consumer} still gets AnalyticsInfo"
            );
        }
    }

    #[test]
    fn an_unparseable_config_fails_instead_of_defaulting() {
        let err = from_config("badyaml", "nwdaf: [unclosed\n").expect_err("invalid YAML");
        assert!(err.contains("not valid YAML"), "{err}");
    }

    /// #1570: only an MTLF offering Nnwdaf_MLModelProvision advertises
    /// `nwdafInfo.mlAnalyticsList`, built from the events it provisions, and
    /// nrfd's `ml-analytics-info-list` discovery returns it for NF_LOAD and for
    /// nothing else; an AnLF or a non-exportable MTLF is never returned.
    #[test]
    fn nrfd_ml_analytics_discovery_finds_only_the_offering_mtlf() {
        let pid = std::process::id();
        let cases = [
            (
                MlProvision::Offered,
                format!("6b1d7e3c-1570-4100-8000-{pid:012x}"),
            ),
            (
                MlProvision::NoMtlf,
                format!("6b1d7e3c-1570-4100-8001-{pid:012x}"),
            ),
            (
                MlProvision::NotExportable,
                format!("6b1d7e3c-1570-4100-8002-{pid:012x}"),
            ),
        ];
        for (ml, id) in &cases {
            let doc = build_nf_profile_for(id, "127.0.0.1", 7815, &spec_allowed_nf_types(), *ml);
            let list = doc["nwdafInfo"].get("mlAnalyticsList");
            if *ml == MlProvision::Offered {
                let want: Vec<&str> = ml_service::PROVISIONED_ML_EVENTS
                    .iter()
                    .map(|e| e.as_str())
                    .collect();
                assert_eq!(list, Some(&serde_json::json!([{ "mlAnalyticsIds": want }])));
                assert_eq!(want, ["NF_LOAD"]);
            } else {
                assert_eq!(list, None, "{ml:?} claims no ML analytics");
            }
            nf_manager()
                .register(NfProfile::from_json(&doc).expect("nrfd accepts the profile"))
                .expect("register at nrfd");
        }
        let found = |event: &str| -> Vec<String> {
            discover_profiles(&DiscoveryQuery {
                target_nf_type: "NWDAF".to_string(),
                requester_nf_type: "NWDAF".to_string(),
                service_names: vec!["nnwdaf-mlmodelprovision".to_string()],
                ml_analytics_info_list: vec![serde_json::json!({ "mlAnalyticsIds": [event] })],
                ..Default::default()
            })
            .iter()
            .filter_map(|p| p["nfInstanceId"].as_str().map(String::from))
            .collect()
        };
        let nf_load = found("NF_LOAD");
        let ue_mobility = found("UE_MOBILITY");
        for (_, id) in &cases {
            let _ = nf_manager().deregister(id);
        }
        assert!(nf_load.contains(&cases[0].1), "{nf_load:?}");
        assert!(!nf_load.contains(&cases[1].1) && !nf_load.contains(&cases[2].1));
        assert!(!ue_mobility.contains(&cases[0].1), "{ue_mobility:?}");
    }

    /// The discovery path: nrfd's SearchNFInstances filter (TS 29.510 §6.2)
    /// returns the NWDAF to a requester type its profile allows, and only then.
    #[test]
    fn nrfd_discovery_returns_this_nwdaf_to_every_listed_consumer() {
        let id = format!("6b1d7e3c-1412-4000-8000-{:012x}", std::process::id());
        let doc = profile_json(&id, &spec_allowed_nf_types());
        nf_manager()
            .register(NfProfile::from_json(&doc).expect("valid profile"))
            .expect("register at nrfd");
        let found = |requester: &str| {
            discover_profiles(&DiscoveryQuery {
                target_nf_type: "NWDAF".to_string(),
                requester_nf_type: requester.to_string(),
                target_nf_instance_id: Some(id.clone()),
                ..Default::default()
            })
            .len()
        };
        let results: Vec<(&str, usize)> = NEWLY_ALLOWED
            .iter()
            .chain(ALREADY_ALLOWED)
            .chain(&["CHF"])
            .map(|t| (*t, found(t)))
            .collect();
        let _ = nf_manager().deregister(&id);
        for (requester, n) in results {
            let want = usize::from(requester != "CHF");
            assert_eq!(
                n, want,
                "discovery of NWDAF by requester-nf-type={requester}"
            );
        }
    }
}

#[cfg(test)]
mod callback_oauth2_1421_tests {
    //! #1421: the real router behind an OAuth2-required listener that registers
    //! [`super::oauth2_callback_exemptions`] the way `main` does. A notification
    //! carries no bearer (TS 33.501 §13.4.1); each callback this NWDAF subscribed
    //! for is admitted on its own token, and nothing else is.
    use super::*;
    use nextgcore_nrfd::sbi_path::{nrf_nnrf_nfm_send_nf_status_notify_async, NotifySendResult};
    use nextgcore_nrfd::{NfProfile, NotificationEventType, SubscriptionData};
    use nextgcore_sbi::client::SbiClient;
    use serde_json::json;

    async fn oauth2_listener() -> (SbiServer, u16) {
        oauth2_listener_with(oauth2_callback_exemptions(), nwdaf_sbi_request_handler).await
    }

    async fn oauth2_listener_with<H: nextgcore_sbi::server::SbiRequestHandler>(
        exemptions: Vec<nextgcore_sbi::server::OAuth2CallbackExemption>,
        handler: H,
    ) -> (SbiServer, u16) {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = NextgcoreSbiServerConfig::new(addr)
            .with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Nwdaf)
            .with_oauth2_callback_exemptions(exemptions);
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(json!({"keys": []}));
        let server = SbiServer::on_listener(cfg, listener);
        server.start(handler).await.expect("server start");
        (server, addr.port())
    }

    /// The server `main` builds registers every callback this build serves.
    #[test]
    fn the_nwdaf_server_registers_its_callback_exemptions() {
        let server = sbi_server(NextgcoreSbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))));
        let routes: Vec<String> = server
            .config()
            .oauth2_callback_exemptions
            .iter()
            .map(|e| e.route())
            .collect();
        #[allow(unused_mut)]
        let mut want = vec!["POST /nnwdaf-callback/v1/nf-status-notify/{token}"];
        #[cfg(feature = "amf-mobility")]
        want.push("POST /nnwdaf-callback/v1/amf-location-notify/{token}");
        #[cfg(feature = "demo-d441a-congestion-loop")]
        want.push("POST /nnwdaf-callback/v1/amf-ues-in-area-notify/{token}");
        #[cfg(feature = "demo-d441e-model-retrain")]
        {
            want.push("POST /nnwdaf-callback/v1/mlmodel-monitor-notify/{token}");
            want.push("POST /nnwdaf-callback/v1/mtlf-model-notify/{token}");
        }
        assert_eq!(routes, want);
    }

    #[cfg(feature = "demo-d441e-model-retrain")]
    static TEST_MONITOR: std::sync::OnceLock<model_monitor::Monitor> = std::sync::OnceLock::new();
    #[cfg(feature = "demo-d441e-model-retrain")]
    static TEST_ANLF: std::sync::OnceLock<model_retrain::Anlf> = std::sync::OnceLock::new();

    /// nextgsim#468 (the case #1421's comment reproduced): an AnLF's
    /// MLModelProvision notify and an MTLF's MLModelMonitor notify, token-less,
    /// reach the real handlers on the held notifUri / notificationUri token over
    /// an OAuth2-required listener, and a forged token is 401. The exemptions'
    /// state is injected (`CallbackSources`), the same instances the handlers get.
    #[cfg(feature = "demo-d441e-model-retrain")]
    #[tokio::test]
    async fn the_d441e_notifies_are_admitted_on_their_tokens_only() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        fn monitor() -> Option<&'static model_monitor::Monitor> {
            Some(TEST_MONITOR.get_or_init(|| {
                model_monitor::Monitor::new(
                    "retrain",
                    role::Role::Mtlf,
                    "http://m",
                    "m",
                    "http://n",
                )
            }))
        }
        fn anlf() -> Option<&'static model_retrain::Anlf> {
            Some(TEST_ANLF.get_or_init(model_retrain::Anlf::new))
        }
        let sources = CallbackSources { monitor, anlf };
        let (server, port) = oauth2_listener_with(
            oauth2_callback_exemptions_from(sources),
            move |req: SbiRequest| async move {
                let parts: Vec<String> = req.header.uri.split('/').map(str::to_owned).collect();
                let (segment, token) = (parts[3].as_str(), parts[4].as_str());
                if segment == model_retrain::CALLBACK_SEGMENT {
                    model_retrain::handle_model_notify(anlf(), nwdaf_self(), token, &req)
                } else {
                    model_monitor::handle_notify(monitor(), token, &req)
                }
            },
        )
        .await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let post = |segment: &str, token: &str, body: serde_json::Value| {
            SbiRequest::post(format!("/nnwdaf-callback/v1/{segment}/{token}"))
                .with_body(body.to_string(), "application/json")
        };
        let forged = uuid::Uuid::new_v4().simple().to_string();
        let prov = json!([{ "subscriptionId": "s-1421", "eventNotifs": [] }]);
        let accu = json!({ "notifCorrId": "corr-1421", "modelAccuInfos": [] });

        let (seg_p, tok_p) = (
            model_retrain::CALLBACK_SEGMENT,
            model_retrain::test_token(anlf()),
        );
        let (seg_m, tok_m) = (
            model_monitor::CALLBACK_SEGMENT,
            model_monitor::test_token(monitor()),
        );
        assert_eq!(
            status(&client, post(seg_p, &forged, prov.clone())).await,
            401
        );
        assert_eq!(
            status(&client, post(seg_m, &forged, accu.clone())).await,
            401
        );

        // MLModelProvision notify with no model to fetch: 204 from the handler.
        assert_eq!(status(&client, post(seg_p, &tok_p, prov)).await, 204);
        // MLModelMonitor notify: past the token check, the handler looks the
        // registration up (none here), so its own 404 answers, not the gate.
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.send_request(post(seg_m, &tok_m, accu)),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 404);
        assert!(
            resp.http
                .content
                .as_deref()
                .is_some_and(|b| b.contains("no MLModelMonitor registration corr-1421")),
            "{:?}",
            resp.http.content
        );
        server.stop().await.expect("stop");
    }

    async fn status(client: &SbiClient, req: SbiRequest) -> u16 {
        tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response")
            .status
    }

    fn subscription(uri: String) -> SubscriptionData {
        SubscriptionData {
            id: "nwdaf-1421-sub".to_string(),
            req_nf_type: Some("NWDAF".to_string()),
            req_nf_instance_id: None,
            notification_uri: uri,
            subscr_cond: None,
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
        }
    }

    fn last_load(id: &str) -> Option<u8> {
        let ctx = nwdaf_self();
        let guard = ctx.read().expect("ctx");
        let engine = guard.lock_engine();
        engine.nf_meta(id).and_then(|m| m.last_load)
    }

    /// The NRF's NFStatusNotify, sent by nrfd's real notify pipeline (no bearer),
    /// is admitted on the tokenised callback URI this NWDAF subscribes with and
    /// ingested. On a forged token, or on the token-less URI, it is refused 401
    /// and ingests nothing; so is a service request without a bearer.
    #[tokio::test]
    async fn the_nrf_status_notify_is_admitted_on_its_token_only() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let (server, port) = oauth2_listener().await;
        let base = format!("http://127.0.0.1:{port}");
        let id = "nwdaf-1421-amf";
        let profile = NfProfile::from_json(&json!({
            "nfInstanceId": id, "nfType": "AMF", "nfStatus": "REGISTERED", "load": 55,
        }))
        .expect("profile");
        let notify = |uri: String| {
            let profile = profile.clone();
            async move {
                nrf_nnrf_nfm_send_nf_status_notify_async(
                    &subscription(uri),
                    NotificationEventType::NfRegistered,
                    &profile,
                    "http://nrf.test:7777",
                )
                .await
            }
        };
        let token = nrf_collector::callback_token();
        assert!(nrf_collector::callback_path().ends_with(&format!("/nf-status-notify/{token}")));

        let forged = uuid::Uuid::new_v4().simple().to_string();
        for uri in [
            format!("{base}/nnwdaf-callback/v1/nf-status-notify/{forged}"),
            format!("{base}/nnwdaf-nfstatus-notify/v1/notify"),
            format!("{base}/nnwdaf-callback/v1/nf-status-notify/{token}/"),
        ] {
            match notify(uri.clone()).await {
                NotifySendResult::Failed(why) => assert_eq!(why, "HTTP 401", "{uri}"),
                other => panic!("{uri}: {other:?}"),
            }
        }
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let analytics = "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD";
        assert_eq!(status(&client, SbiRequest::get(analytics)).await, 401);
        assert_eq!(last_load(id), None, "a refused notification was ingested");

        let ok = notify(format!("{base}{}", nrf_collector::callback_path())).await;
        assert!(matches!(ok, NotifySendResult::Success), "{ok:?}");
        assert_eq!(
            last_load(id),
            Some(55),
            "the admitted notification is ingested"
        );
        server.stop().await.expect("stop");
    }

    /// The tokenised NFStatusNotify route checks its token itself too, so a
    /// forged one is 404 even where no listener enforces OAuth2.
    #[tokio::test]
    async fn the_tokenised_route_refuses_a_forged_token_itself() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let body =
            json!({ "event": "NF_DEREGISTERED", "nfInstanceUri": "http://nrf/x/nwdaf-1421-r" });
        let req = |token: &str| {
            SbiRequest::post(format!("/nnwdaf-callback/v1/nf-status-notify/{token}"))
                .with_body(body.to_string(), "application/json")
        };
        let forged = uuid::Uuid::new_v4().simple().to_string();
        assert_eq!(nwdaf_sbi_request_handler(req(&forged)).await.status, 404);
        let held = nrf_collector::callback_token();
        assert_eq!(nwdaf_sbi_request_handler(req(held)).await.status, 204);
    }

    /// Every registered exemption refuses a token this NWDAF does not hold, so a
    /// forged notification on any callback route is 401 before the router.
    #[tokio::test]
    async fn every_callback_route_refuses_a_forged_token() {
        let exemptions = oauth2_callback_exemptions();
        assert!(!exemptions.is_empty());
        let (server, port) = oauth2_listener().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let forged = uuid::Uuid::new_v4().simple().to_string();
        for e in &exemptions {
            let path = e
                .route()
                .trim_start_matches("POST ")
                .replace("{token}", &forged);
            assert!(e.match_path("POST", &path).is_some(), "{path}");
            let req = SbiRequest::post(&path).with_body("{}".to_string(), "application/json");
            assert_eq!(status(&client, req).await, 401, "{path}");
        }
        server.stop().await.expect("stop");
    }

    /// nextgsim#466: the AMF's token-less LOCATION_REPORT notify reaches the
    /// handler on this NWDAF's callback token, and is refused 401 on any other.
    #[cfg(feature = "amf-mobility")]
    #[tokio::test]
    async fn the_amf_location_notify_is_admitted_on_its_token_only() {
        let _serving = amf_mobility::ServingOnThisThread::new();
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let (server, port) = oauth2_listener().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let body =
            json!({ "notifyCorrelationId": amf_mobility::NOTIFY_CORRELATION_ID, "reportList": [] });
        let post = |token: &str| {
            SbiRequest::post(format!(
                "/nnwdaf-callback/v1/{}/{token}",
                amf_mobility::CALLBACK_SEGMENT
            ))
            .with_body(body.to_string(), "application/json")
        };
        let token = amf_mobility::callback_token();
        assert_eq!(status(&client, post(&"0".repeat(32))).await, 401);
        assert_eq!(status(&client, post(token)).await, 204);
        server.stop().await.expect("stop");
    }

    /// nextgsim#465: the AMF's token-less UES_IN_AREA_REPORT notify, likewise.
    #[cfg(feature = "demo-d441a-congestion-loop")]
    #[tokio::test]
    async fn the_amf_ues_in_area_notify_is_admitted_on_its_token_only() {
        let _serving = ran_congestion::ServingOnThisThread::new();
        let (server, port) = oauth2_listener().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let body = json!({ "notifyCorrelationId": "nwdaf-udc-x", "reportList": [] });
        let post = |token: &str| {
            SbiRequest::post(format!(
                "/nnwdaf-callback/v1/{}/{token}",
                ran_congestion::CALLBACK_SEGMENT
            ))
            .with_body(body.to_string(), "application/json")
        };
        let token = ran_congestion::callback_token();
        assert_eq!(status(&client, post(&"0".repeat(32))).await, 401);
        assert_eq!(status(&client, post(token)).await, 204);
        server.stop().await.expect("stop");
    }
}

/// #1665: the outbound OAuth2 client follows the SBI security profile.
#[cfg(test)]
mod outbound_oauth2_1665_tests {
    use nextgcore_sbi::security::SbiProfile;
    use nextgcore_sbi::types::NfType;

    const NRF: &str = "http://127.0.0.10:7777";

    /// Under the `production` profile this NWDAF installs its token client with
    /// the `sbi.oauth2.require` knob off, so its service requests to the AMF, AUSF,
    /// SMF and UDM (which require a bearer under that profile, #63) carry one
    /// (TS 33.501 §13.4.1.1.2). Before #1665 it installed it only under the knob.
    #[test]
    fn the_production_profile_installs_the_outbound_oauth2_client_without_the_knob() {
        let oauth2 = super::outbound_oauth2_client(SbiProfile::Production, false, Some(NRF))
            .expect("production profile, knob off: the outbound OAuth2 client is installed");
        assert_eq!(oauth2.self_consumer().nf_type, NfType::Nwdaf);
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
