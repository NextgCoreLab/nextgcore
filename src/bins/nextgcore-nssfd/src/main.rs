//! NextGCore NSSF (Network Slice Selection Function)
//!
//! The NSSF is a 5G core network function responsible for:
//! - Selecting the Network Slice instances to serve the UE
//! - Determining the allowed NSSAI and mapping to subscribed S-NSSAIs
//! - Determining the AMF Set to be used to serve the UE
//!
//! External API per 3GPP TS 29.531:
//! - Nnssf_NSSelection v2: GET /nnssf-nsselection/v2/network-slice-information
//! - Nnssf_NSSAIAvailability v1: /nnssf-nssaiavailability/v1/nssai-availability/...

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::{JwksCache, OAuth2Client};
use nextgcore_sbi::server::{
    send_method_not_allowed, SbiServer, SbiServerConfig as NextgcoreSbiServerConfig,
};
use nextgcore_sbi::types::NfType;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

mod context;
mod event;
mod nnrf_handler;
mod nnssf_build;
mod nnssf_handler;
mod nsacf;
mod nssf_sm;
mod sbi_path;
mod sbi_response;
mod timer;

pub use context::*;
pub use event::{
    EventSbiRequest, EventSbiResponse, NssfEvent, NssfEventId, NssfTimerId, SbiEventData,
    SbiMessage,
};
pub use nnrf_handler::*;
pub use nnssf_build::*;
pub use nnssf_handler::*;
pub use nssf_sm::{NssfSmContext, NssfState};
pub use sbi_path::*;
pub use timer::{timer_manager, NssfTimerManager};

/// NextGCore NSSF - Network Slice Selection Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nssfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Slice Selection Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nssf.yaml")]
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

    /// Kill a running instance (NOT SUPPORTED: exits with an error;
    /// stop the NF through its supervisor)
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

    /// Maximum number of NF instances
    #[arg(long, default_value = "512")]
    max_nf: usize,

    /// Target AMF Set ID for AMF re-selection
    /// (format <MCC>-<MNC>-<RegionId>-<SetId>, TS 29.531 targetAmfSet)
    #[arg(long)]
    target_amf_set: Option<String>,

    /// Path to the JSON snapshot file for NSSAI-availability subscriptions and
    /// availability data. When unset (the default) these are purely in-memory
    /// and lost on restart. Also settable via NEXTGCORE_NSSF_STATE_FILE.
    #[arg(long)]
    state_file: Option<String>,
}

// ---------------------------------------------------------------------------
// Typed YAML configuration structs for NRF URI seeding
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct NrfClientYaml {
    uri: String,
}

/// One Network Slice Instance entry: `nssf.sbi.client.nsi[]`.
///
/// **This block already exists in every shipped `nssf.yaml`** — it was simply
/// never deserialised, because `SbiClientYaml` declared only `nrf`. So the NSI
/// table had no production writer and `nsi_find_by_s_nssai` missed on every
/// request, which is the `403` #93 reports. The fix is to READ the configuration
/// the deployments already carry rather than to invent a second, top-level `nsi`
/// schema: a new key would have left the shipped one inert while looking fixed,
/// which is the same divergent-configuration trap as two NF-profile builders.
#[derive(Debug, Default, Deserialize)]
struct NsiClientYaml {
    /// NRF serving this slice instance (TS 29.531 `NsiInformation.nrfId`).
    uri: String,
    /// The S-NSSAI this slice instance serves.
    s_nssai: Option<SnssaiYaml>,
    /// Optional operator-assigned `nsiId`. Absent => a UUID is minted, which is
    /// what `NssfNsi::new` already does.
    nsi_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiClientYaml {
    nrf: Option<Vec<NrfClientYaml>>,
    nsi: Option<Vec<NsiClientYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiServerYaml {
    address: Option<String>,
    port: Option<u16>,
}

/// SBI OAuth2 enforcement knob (`nssf.sbi.oauth2.require`).
///
/// **Defaults to ENABLED** (#94). It used to default to disabled, which meant
/// the shipped default posture both accepted token-less requests AND — because
/// availability authorization had no attestable identity to bind to — let any
/// reachable NF overwrite any AMF's slice-availability document. An absent knob
/// now means "authenticate", and a deployment that cannot yet issue tokens says
/// so explicitly with `require: false`; every dev artefact was given that
/// explicit opt-out in the same commit as this flip, since flipping first would
/// break them and look like a code bug.
///
/// This knob also governs whether availability writes must be bound to an
/// attested caller — see `strict_availability_authz`.
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

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (set only when `nssf.sbi.oauth2.require` is true).
static OAUTH2_CLIENT: OnceLock<Option<Arc<OAuth2Client>>> = OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled. Outbound
/// SBI clients attach tokens via [`attach_oauth2`].
fn oauth2_client() -> Option<Arc<OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Attach the process-wide OAuth2 client (when enforcement is on) so the
/// outbound request carries an NRF-issued Bearer token scoped to `target`.
/// A no-op (returns the client unchanged) when enforcement is off.
fn attach_oauth2(client: SbiClient, target: NfType) -> SbiClient {
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
    }
}

/// A single configured S-NSSAI (`{ sst: <u8>, sd: "<6 hex>" }`), used by the
/// optional PLMN-supported-S-NSSAI restriction (nssfd-01).
#[derive(Debug, Default, Deserialize)]
struct SnssaiYaml {
    sst: u8,
    sd: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NssfSection {
    sbi: Option<SbiYaml>,
    /// Target AMF Set ID used for AMF re-selection in registration scenarios
    amf_set_id: Option<String>,
    /// Optional explicit set of S-NSSAIs supported in this PLMN
    /// (TS 29.531 §6.2.3.2.3.1). ABSENT (the default) => NO restriction =>
    /// allow-all (matched-sim back-compat). When present, an NSSAIAvailability
    /// PUT/PATCH reporting an S-NSSAI outside this set is rejected with 403
    /// SNSSAI_NOT_SUPPORTED.
    supported_snssai_list: Option<Vec<SnssaiYaml>>,
    /// VPLMN-to-HPLMN S-NSSAI mapping served on the `pdn-connection` scenario
    /// (TS 29.531 §5.2.2.2.5, `mappingOfNssai`, feature RSIPCE).
    ///
    /// Operator-provisioned because nothing in this core derives it: the
    /// registration path only echoes a mapping the CONSUMER supplied, and the
    /// home store is keyed by (home PLMN, home S-NSSAI) rather than holding a
    /// serving-to-home pair. With no entries the scenario answers the spec's own
    /// 403 SNSSAI_NOT_SUPPORTED rather than a fabricated mapping.
    nssai_mapping: Option<Vec<NssaiMappingYaml>>,
    /// Per-home-PLMN S-NSSAI restrictions emitted as `restrictedSnssaiList`
    /// (TS 29.531 §6.2.6.2.5). Absent => no restrictions (default-allow).
    snssai_restrictions: Option<Vec<SnssaiRestrictionYaml>>,
}

/// Per-home-PLMN S-NSSAI restriction: `nssf.snssai_restrictions[]`
/// (TS 29.531 §6.2.6.2.5 `RestrictedSnssai`).
///
/// #94: `set_plmn_snssai_restrictions` previously had **no production caller** —
/// its only call site was inside `#[cfg(test)]` — so an operator had no way to
/// configure a restriction at all, and the `restrictedSnssaiList` serialization
/// bug was latent because nothing could ever emit the field.
#[derive(Debug, Default, Deserialize)]
struct SnssaiRestrictionYaml {
    /// Home PLMN the restriction applies to.
    home_plmn: PlmnYaml,
    /// S-NSSAIs a UE from that home PLMN may NOT use here.
    restricted: Vec<SnssaiYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct PlmnYaml {
    mcc: String,
    mnc: String,
}

/// One VPLMN-to-HPLMN S-NSSAI mapping: `nssf.nssai_mapping[]`.
#[derive(Debug, Default, Deserialize)]
struct NssaiMappingYaml {
    serving: SnssaiYaml,
    home: SnssaiYaml,
}

#[derive(Debug, Default, Deserialize)]
struct NssfYaml {
    nssf: Option<NssfSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Notification client timeouts (bounded; callbacks must not hang the NSSF)
const NOTIFY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const NOTIFY_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::main]
async fn main() -> Result<()> {
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

    log::info!("NextGCore NSSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialise the NSSF context, optionally restoring persisted
    // NSSAI-availability subscriptions and availability data. Path precedence:
    // --state-file, then NEXTGCORE_NSSF_STATE_FILE. With neither set the
    // context stays purely in-memory (previous behaviour). This must run before
    // nssf_context_init() so the persisting context backs the singleton.
    let nssf_state_file = args
        .state_file
        .clone()
        .or_else(|| std::env::var("NEXTGCORE_NSSF_STATE_FILE").ok())
        .filter(|s| !s.is_empty());
    match &nssf_state_file {
        Some(path) => {
            nssf_context_init_with_state(Some(std::path::PathBuf::from(path)));
            log::info!("NSSF availability persistence enabled: {path}");
        }
        None => {
            nssf_context_init_with_state(None);
            log::info!("NSSF availability persistence disabled (in-memory only)");
        }
    }

    // Initialize NSSF context
    nssf_context_init(args.max_nf);
    log::info!("NSSF context initialized (max_nf={})", args.max_nf);

    // Initialize NSSF state machine
    let mut nssf_sm = NssfSmContext::new();
    nssf_sm.init();
    log::info!("NSSF state machine initialized");

    // Parse configuration (if file exists) and seed NRF URI
    let mut nrf_uri_cfg: Option<String> = None;
    // #94: default ON. An ABSENT nssf.sbi.oauth2 section now means "enforce",
    // so a config that never mentions OAuth2 gets the secure posture rather than
    // the permissive one.
    let mut require_oauth2 = true;
    // How many NSIs the configuration installed. Checked after the config block
    // so the always-403 condition cannot ship silently (#93).
    let mut configured_nsi_count = 0usize;
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<NssfYaml>(&content) {
                    if let Some(nssf) = yaml.nssf {
                        if let Some(set_id) = nssf.amf_set_id {
                            log::info!("Target AMF Set configured: {set_id}");
                            if let Ok(ctx) = nssf_self().read() {
                                ctx.set_target_amf_set(&set_id);
                            }
                        }
                        // nssfd-01: optional PLMN-supported S-NSSAI restriction.
                        // When ABSENT (the default) the NSSF imposes no
                        // restriction (allow-all, matched-sim back-compat); when
                        // present, an availability update reporting an S-NSSAI
                        // outside this set is rejected with 403
                        // SNSSAI_NOT_SUPPORTED (TS 29.531 §6.2.3.2.3.1).
                        if let Some(list) = nssf.supported_snssai_list {
                            let snssais: Vec<context::SNssai> = list
                                .iter()
                                .map(|s| {
                                    let sd = s
                                        .sd
                                        .as_deref()
                                        .and_then(|h| u32::from_str_radix(h, 16).ok())
                                        .and_then(|v| if v == 0xFF_FFFF { None } else { Some(v) });
                                    context::SNssai::new(s.sst, sd)
                                })
                                .collect();
                            log::info!(
                                "PLMN-supported S-NSSAI restriction configured: {} entries",
                                snssais.len()
                            );
                            if let Ok(ctx) = nssf_self().read() {
                                ctx.set_plmn_supported_snssais(Some(snssais));
                            }
                        }
                        // #94: per-home-PLMN S-NSSAI restrictions. This is the
                        // production caller set_plmn_snssai_restrictions never had.
                        if let Some(list) = nssf.snssai_restrictions {
                            let mut installed = 0usize;
                            if let Ok(ctx) = nssf_self().read() {
                                for r in &list {
                                    if r.home_plmn.mcc.is_empty() || r.home_plmn.mnc.is_empty() {
                                        log::warn!(
                                            "nssf.snssai_restrictions entry has an incomplete \
                                             home_plmn; skipped (a restriction must name the \
                                             PLMN it applies to)"
                                        );
                                        continue;
                                    }
                                    let plmn =
                                        context::PlmnId::new(&r.home_plmn.mcc, &r.home_plmn.mnc);
                                    let snssais: Vec<context::SNssai> =
                                        r.restricted.iter().map(snssai_from_yaml).collect();
                                    ctx.set_plmn_snssai_restrictions(&plmn, snssais);
                                    installed += 1;
                                }
                            }
                            log::info!(
                                "per-home-PLMN S-NSSAI restrictions configured: {installed} PLMN(s)"
                            );
                        }
                        // #93: VPLMN->HPLMN S-NSSAI mapping for the
                        // pdn-connection scenario (TS 29.531 §5.2.2.2.5).
                        if let Some(list) = nssf.nssai_mapping {
                            let pairs: Vec<(context::SNssai, context::SNssai)> = list
                                .iter()
                                .map(|m| (snssai_from_yaml(&m.serving), snssai_from_yaml(&m.home)))
                                .collect();
                            log::info!(
                                "VPLMN->HPLMN S-NSSAI mapping configured: {} entries",
                                pairs.len()
                            );
                            set_nssai_mapping(pairs);
                        }
                        if let Some(sbi) = nssf.sbi {
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
                                // #93: populate the NSI table from configuration.
                                // Until now `nsi_add` had NO production caller, so
                                // every PDU-session selection missed and answered
                                // 403 (TS 29.531 §5.2.2.2.3 requires nsiInformation
                                // for the requested S-NSSAI).
                                if let Some(nsi_list) = client.nsi {
                                    configured_nsi_count = load_configured_nsis(&nsi_list);
                                }
                            }
                            // SBI OAuth2 enforcement knob (nssf.sbi.oauth2.require).
                            // An absent `oauth2` section, and an absent
                            // `require` inside one, both mean ENFORCE (#94).
                            require_oauth2 = sbi.oauth2.and_then(|o| o.require).unwrap_or(true);
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

    // #93: an NSSF with an empty NSI table answers 403 to EVERY PDU-session
    // selection (TS 29.531 §5.2.2.2.3), so it cannot do the job it was deployed
    // for. That must not be discoverable only by a consumer getting a 403.
    //
    // An ERROR log naming the consequence rather than a non-zero exit: startup
    // failure is the right answer for a malformed config, but an ABSENT optional
    // section is not malformed, and refusing to boot would break every existing
    // deployment and the E2E on upgrade — for a daemon that is still perfectly
    // able to serve the registration and NSSAI-availability scenarios, which do
    // not consult the NSI table. The shipped configs all carry an `nsi` block, so
    // this fires only for a deployment that removed it.
    if configured_nsi_count == 0 {
        let existing = nssf_self()
            .read()
            .map(|c| c.nsi_get_all().len())
            .unwrap_or(0);
        if existing == 0 {
            log::error!(
                "No Network Slice Instances configured: every \
                 Nnssf_NSSelection slice-info-request-for-pdu-session will be answered \
                 403 (TS 29.531 §5.2.2.2.3 requires nsiInformation for the requested \
                 S-NSSAI). Populate nssf.sbi.client.nsi[] in {} with one entry per \
                 served S-NSSAI: '- uri: <nrf-uri>' plus 's_nssai: {{ sst: <n>, sd: <hex> }}'.",
                args.config
            );
        }
    } else {
        log::info!("{configured_nsi_count} Network Slice Instance(s) configured");
    }

    // CLI flag overrides the YAML target AMF set
    if let Some(ref set_id) = args.target_amf_set {
        if let Ok(ctx) = nssf_self().read() {
            ctx.set_target_amf_set(set_id);
        }
    }

    // Build SBI server configuration (legacy, for context)
    let sbi_config = SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open legacy SBI server (for context initialization)
    nssf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);
    // #94: one knob governs both authentication and the caller-to-resource
    // binding, because binding is only meaningful against an authenticated
    // identity. Recorded before the `if` so the log below reports the posture
    // actually installed.
    set_strict_availability_authz(require_oauth2);
    if !require_oauth2 {
        log::warn!(
            "SBI OAuth2 enforcement is DISABLED by configuration: incoming requests are not \
             authenticated, and NSSAI-availability writes therefore cannot be bound to the \
             AMF that owns the document — any reachable NF can overwrite any AMF's slice \
             picture (TS 33.501 §13.4.1). This is a documented escape hatch, not a default."
        );
    }
    if require_oauth2 {
        // Server side (TS 33.501 §13.4.1): verify incoming Bearer tokens
        // against the NRF's published JWKS and require the token's `aud` to
        // include this NF's own type ("NSSF"). With no NRF URI configured the
        // server fails closed (503).
        sbi_server_config.require_oauth2 = true;
        sbi_server_config.oauth2_jwks_uri = nrf_uri_cfg
            .as_deref()
            .map(|uri| JwksCache::for_nrf(uri).jwks_uri().to_string());
        sbi_server_config = sbi_server_config.with_expected_audience_nf_type(NfType::Nssf);

        // Client side (T1.1): install the process-wide OAuth2 client so
        // outbound SBI calls acquire and attach an NRF-issued Bearer token.
        if let Some(nrf_uri) = nrf_uri_cfg.as_deref() {
            let nf_instance_id = format!("nssf-{}", uuid::Uuid::new_v4());
            let oauth2 = Arc::new(OAuth2Client::new(nrf_uri, nf_instance_id, NfType::Nssf));
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
        .start(nssf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF (B24.3)
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
            // (NSI count vs configured capacity; TS 29.510 §5.2.2.3.2).
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(nf_instance_id, 5, || {
                let ctx = crate::context::nssf_self();
                let load = ctx.read().map(|c| c.get_nsi_load()).unwrap_or(0);
                load.clamp(0, 100) as u8
            });
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    // Discover H-NSSF instances from NRF
    if let Err(e) = discover_nf_from_nrf("NSSF", "nnssf-nsselection").await {
        log::warn!("H-NSSF discovery failed (will retry on demand): {e}");
    }

    log::info!("NextGCore NSSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut nssf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes
    // away, so the NRF stops handing this profile to consumers instead of
    // waiting out its supervision timer. Stopping the server first would
    // open the bad window: not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    nssf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    nssf_sm.fini();
    log::info!("NSSF state machine finalized");

    // Cleanup context
    nssf_context_final();
    log::info!("NSSF context finalized");

    log::info!("NextGCore NSSF stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// Run a closure against the global NSSF context read guard, returning None
/// if the lock is poisoned. Keeps guard lifetimes contained (no guard ever
/// crosses an `.await` or another lock acquisition).
fn with_nssf_context<T>(f: impl FnOnce(&NssfContext) -> T) -> Option<T> {
    let ctx = nssf_self();
    let result = ctx.read().ok().map(|guard| f(&guard));
    result
}

/// Build a TS 29.500 ProblemDetails error response
/// (`application/problem+json`, RFC 7807).
fn problem_details(status: u16, title: &str, detail: &str, cause: Option<&str>) -> SbiResponse {
    let mut body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
    });
    if let Some(c) = cause {
        body["cause"] = serde_json::json!(c);
    }
    SbiResponse::with_status(status).with_body(body.to_string(), "application/problem+json")
}

/// Parse the query string of a request URI into percent-decoded key/values.
///
/// #65: the local `percent_decode` copy this used is gone; decoding now happens
/// once, in the shared SBI server, and this function exists only for a caller
/// that still holds a whole URI with its query attached (a handler invoked
/// directly, without going through the server glue). It delegates to
/// [`nextgcore_sbi::uri_encode::decode_query_value`] so there is one decoder in
/// the tree rather than three that disagree.
fn parse_query_params(uri: &str) -> HashMap<String, String> {
    let query = match uri.split_once('?') {
        Some((_, q)) => q,
        None => return HashMap::new(),
    };
    query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (
                nextgcore_sbi::uri_encode::decode_query_value(k),
                nextgcore_sbi::uri_encode::decode_query_value(v),
            )
        })
        .collect()
}

/// Split an absolute URI into (host, port, path-with-query)
fn split_uri(uri: &str) -> Option<(String, u16, String)> {
    let (scheme_default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (80u16, r)
    } else {
        (80u16, uri)
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        Some((host.to_string(), port_str.parse().ok()?, path))
    } else {
        Some((host_port.to_string(), scheme_default_port, path))
    }
}

// ---------------------------------------------------------------------------
// SBI routing
// ---------------------------------------------------------------------------

/// SBI request handler for NSSF
async fn nssf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.clone();
    let method = method.as_str();
    let uri = request.header.uri.clone();

    log::debug!("NSSF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(&uri);
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() < 2 {
        return problem_details(404, "Not Found", "Invalid resource path", None);
    }

    let service = parts[0];
    let version = parts[1];

    match service {
        // NS Selection Service (TS 29.531 §6.1: API version is v2)
        "nnssf-nsselection" => {
            if version != "v2" {
                return problem_details(
                    404,
                    "Not Found",
                    &format!("Unsupported API version '{version}' (nnssf-nsselection uses v2)"),
                    None,
                );
            }
            match (parts.get(2).copied(), method) {
                (Some("network-slice-information"), "GET") if parts.len() == 3 => {
                    handle_ns_selection(&request).await
                }
                (Some("network-slice-information"), _) => {
                    send_method_not_allowed(method, "network-slice-information")
                }
                _ => problem_details(404, "Not Found", "Unknown nnssf-nsselection resource", None),
            }
        }

        // NSSAI Availability Service (TS 29.531 §6.2: API version is v1)
        "nnssf-nssaiavailability" => {
            if version != "v1" {
                return problem_details(
                    404,
                    "Not Found",
                    &format!(
                        "Unsupported API version '{version}' (nnssf-nssaiavailability uses v1)"
                    ),
                    None,
                );
            }
            if parts.get(2).copied() != Some("nssai-availability") {
                return problem_details(
                    404,
                    "Not Found",
                    "Unknown nnssf-nssaiavailability resource",
                    None,
                );
            }
            match (parts.len(), parts.get(3).copied(), method) {
                // OPTIONS /nssai-availability (store-level discovery)
                (3, None, "OPTIONS") => handle_nssai_availability_options().await,
                // Subscriptions collection
                (4, Some("subscriptions"), "POST") => handle_subscription_create(&request).await,
                (4, Some("subscriptions"), m) => send_method_not_allowed(m, "subscriptions"),
                (5, Some("subscriptions"), "DELETE") => handle_subscription_delete(parts[4]).await,
                (5, Some("subscriptions"), "PATCH") => {
                    handle_subscription_patch(parts[4], &request).await
                }
                (5, Some("subscriptions"), m) => {
                    send_method_not_allowed(m, "subscriptions/{subscriptionId}")
                }
                // Per-NF availability document
                (4, Some(nf_id), "PUT") => handle_nssai_availability_update(nf_id, &request).await,
                (4, Some(nf_id), "PATCH") => handle_nssai_availability_patch(nf_id, &request).await,
                (4, Some(nf_id), "DELETE") => handle_nssai_availability_delete(nf_id).await,
                (4, Some(_), m) => send_method_not_allowed(m, "nssai-availability/{nfId}"),
                _ => problem_details(
                    404,
                    "Not Found",
                    "Unknown nssai-availability resource",
                    None,
                ),
            }
        }

        _ => {
            log::warn!("Unknown NSSF request: {method} {uri}");
            problem_details(
                404,
                "Not Found",
                &format!("Unknown service: {service}"),
                None,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// NS Selection (TS 29.531 §5.2: Nnssf_NSSelection v2)
// ---------------------------------------------------------------------------

async fn handle_ns_selection(request: &SbiRequest) -> SbiResponse {
    // #65: `http.params` now arrives ALREADY percent-decoded from the shared SBI
    // server, so this no longer decodes on access. It must not: decoding again
    // would corrupt any value whose plaintext legitimately contains a `%`
    // escape (`%2520` -> `%20` -> a space that was never sent).
    //
    // parse_query_params still covers a caller that kept the full URI with its
    // query attached (a handler invoked directly rather than through the server
    // glue, which is how several tests below drive this).
    let query = parse_query_params(&request.header.uri);
    let get_param = |k: &str| -> Option<String> {
        query
            .get(k)
            .cloned()
            .or_else(|| request.http.params.get(k).cloned())
    };

    // nf-type and nf-id are mandatory query parameters (TS 29.531 §6.1.3.2.3.1)
    let nf_type = get_param("nf-type");
    let nf_id = get_param("nf-id");
    let mut missing: Vec<&str> = Vec::new();
    if nf_type.is_none() {
        missing.push("nf-type");
    }
    if nf_id.is_none() {
        missing.push("nf-id");
    }
    if !missing.is_empty() {
        return problem_details(
            400,
            "Bad Request",
            &format!(
                "Missing mandatory query parameter(s): {}",
                missing.join(", ")
            ),
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    }
    let nf_id = nf_id.expect("checked above");
    let nf_type = nf_type.expect("checked above");

    let tai = get_param("tai")
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| context::tai_from_json(&v));

    // Exactly one slice-info-request-for-* parameter drives the scenario
    let sir = get_param("slice-info-request-for-registration");
    let sip = get_param("slice-info-request-for-pdu-session");
    let sicu = get_param("slice-info-request-for-ue-cu");

    if let Some(raw) = sir {
        let info_json: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                return problem_details(
                    400,
                    "Bad Request",
                    &format!("Invalid slice-info-request-for-registration JSON: {e}"),
                    Some("INVALID_QUERY_PARAM"),
                )
            }
        };
        return handle_ns_selection_registration(&nf_id, &info_json, tai.as_ref());
    }

    // nssfd-06: UE-Configuration-Update uses a dedicated handler
    // (TS 29.531 §5.2.2.2.4). When requestedNssai is absent the response
    // MUST NOT include allowedNssaiList — a distinct handler enforces this.
    if let Some(raw) = sicu {
        let info_json: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                return problem_details(
                    400,
                    "Bad Request",
                    &format!("Invalid slice-info-request-for-ue-cu JSON: {e}"),
                    Some("INVALID_QUERY_PARAM"),
                )
            }
        };
        return handle_ns_selection_ue_cu(&nf_id, &info_json, tai.as_ref());
    }

    if let Some(raw) = sip {
        let info_json: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                return problem_details(
                    400,
                    "Bad Request",
                    &format!("Invalid slice-info-request-for-pdu-session JSON: {e}"),
                    Some("INVALID_QUERY_PARAM"),
                )
            }
        };
        let supi = get_param("supi");
        return handle_ns_selection_pdu_session(
            &nf_id,
            &nf_type,
            &info_json,
            tai.as_ref(),
            supi,
            get_param("home-plmn-id"),
        )
        .await;
    }

    // #93: the two remaining documented scenarios (TS 29.531 §5.2.2.2.5 and
    // §5.2.2.2.6). Before this they fell through to the 400 below, which told a
    // conformant consumer it had omitted a mandatory query parameter it had in
    // fact supplied.
    if let Some(raw) = get_param("slice-info-request-for-pdn-connection") {
        return handle_ns_selection_pdn_connection(&nf_id, &raw);
    }
    if let Some(raw) = get_param("slice-info-request-for-other-purpose") {
        return handle_ns_selection_other_purpose(&nf_id, &raw);
    }

    problem_details(
        400,
        "Bad Request",
        "One of slice-info-request-for-registration, slice-info-request-for-pdu-session, \
         slice-info-request-for-ue-cu, slice-info-request-for-pdn-connection or \
         slice-info-request-for-other-purpose is required",
        Some("MANDATORY_QUERY_PARAM_MISSING"),
    )
}

/// Parse a SliceInfoForRegistration / SliceInfoForUEConfigurationUpdate document
fn parse_registration_slice_info(v: &serde_json::Value) -> nnssf_handler::RegistrationSliceInfo {
    let mut info = nnssf_handler::RegistrationSliceInfo::default();

    if let Some(subs) = v.get("subscribedNssai").and_then(|x| x.as_array()) {
        for s in subs {
            if let Some(snssai) = s
                .get("subscribedSnssai")
                .and_then(context::snssai_from_json)
            {
                let default_ind = s
                    .get("defaultIndication")
                    .and_then(|d| d.as_bool())
                    .unwrap_or(false);
                info.subscribed.push((snssai, default_ind));
            }
        }
    }
    if let Some(req) = v.get("requestedNssai").and_then(|x| x.as_array()) {
        info.requested = req.iter().filter_map(context::snssai_from_json).collect();
    }
    info.default_configured_ind = v
        .get("defaultConfiguredSnssaiInd")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    if let Some(maps) = v.get("mappingOfNssai").and_then(|x| x.as_array()) {
        for m in maps {
            if let (Some(serving), Some(home)) = (
                m.get("servingSnssai").and_then(context::snssai_from_json),
                m.get("homeSnssai").and_then(context::snssai_from_json),
            ) {
                info.mapping_of_nssai.push((serving, home));
            }
        }
    }
    // #93: the access the consumer is asking about. TS 29.531 puts it on
    // `allowedNssaiCurrentAccess` (an `AllowedNssai`, whose `accessType` is a
    // required member); `allowedNssaiOtherAccess` describes the OTHER access and
    // must not be read as the current one.
    info.current_access_type = v
        .pointer("/allowedNssaiCurrentAccess/accessType")
        .and_then(|a| a.as_str())
        .map(str::to_string);
    info
}

/// Registration-scenario NS selection (TS 29.531 §5.2.3.2.3)
fn handle_ns_selection_registration(
    nf_id: &str,
    info_json: &serde_json::Value,
    tai: Option<&context::Tai>,
) -> SbiResponse {
    let info = parse_registration_slice_info(info_json);

    if info.subscribed.is_empty() && info.requested.is_empty() {
        return problem_details(
            400,
            "Bad Request",
            "sliceInfoRequestForRegistration must contain subscribedNssai and/or requestedNssai",
            Some("MANDATORY_IE_MISSING"),
        );
    }

    // Snapshot everything we need from the context, then drop the guard
    // BEFORE doing any further work (lock-order rule: never hold a context
    // guard while taking other locks or awaiting).
    let snapshot = {
        let ctx = nssf_self();
        let context = match ctx.read() {
            Ok(c) => c,
            Err(_) => {
                return problem_details(500, "Internal Server Error", "context lock poisoned", None)
            }
        };
        let supported_for_tai = match tai {
            Some(t) if context.has_availability_data() => {
                Some(context.get_supported_snssai_for_tai(t))
            }
            _ => None,
        };
        // #93: `targetAmfSet` comes ONLY from configuration.
        //
        // This used to synthesise `<mcc>-<mnc>-01-001` from the UE's TAI when
        // unconfigured. That value is syntactically valid and semantically a
        // fabrication: region 01 / set 001 is an AMF set nobody deployed, so the
        // AMF was told to re-select against a set that does not exist — and
        // because it is well-formed, the failure surfaces as a re-selection that
        // finds nothing rather than as a bad response. Absent is checkable by the
        // consumer; a plausible wrong value is acted on with full confidence.
        let target_amf_set = context.get_target_amf_set();
        nnssf_handler::RegistrationContextSnapshot {
            supported_for_tai,
            per_nf_support: context.per_nf_supported_snssais(),
            nsi_info: context
                .nsi_get_all()
                .iter()
                .map(|n| (n.s_nssai.clone(), n.nrf_id.clone(), n.nsi_id.clone()))
                .collect(),
            target_amf_set,
        }
    };

    let sel = nnssf_handler::nssf_nsselection_handle_registration(nf_id, &info, &snapshot);

    // Assemble AuthorizedNetworkSliceInfo
    let mut response = serde_json::json!({ "supportedFeatures": "1" });

    if !sel.allowed.is_empty() {
        let allowed_list: Vec<serde_json::Value> = sel
            .allowed
            .iter()
            .map(|(snssai, nsi, mapped)| {
                let mut item = serde_json::json!({
                    "allowedSnssai": context::snssai_to_json(snssai)
                });
                if let Some((nrf_id, nsi_id)) = nsi {
                    item["nsiInformationList"] =
                        serde_json::json!([{ "nrfId": nrf_id, "nsiId": nsi_id }]);
                }
                if let Some(home) = mapped {
                    item["mappedHomeSnssai"] = context::snssai_to_json(home);
                }
                item
            })
            .collect();
        response["allowedNssaiList"] = serde_json::json!([{
            "allowedSnssaiList": allowed_list,
            // #93: the access the consumer asked about, not a hardcoded
            // 3GPP_ACCESS. A non-3GPP registration was previously answered as
            // 3GPP, which mis-attributes the access on a response IE the AMF
            // routes on.
            "accessType": info
                .current_access_type
                .as_deref()
                .unwrap_or(DEFAULT_ACCESS_TYPE)
        }]);
    }

    if !sel.configured.is_empty() {
        let configured: Vec<serde_json::Value> = sel
            .configured
            .iter()
            .map(|(snssai, mapped)| {
                let mut item = serde_json::json!({
                    "configuredSnssai": context::snssai_to_json(snssai)
                });
                if let Some(home) = mapped {
                    item["mappedHomeSnssai"] = context::snssai_to_json(home);
                }
                item
            })
            .collect();
        response["configuredNssai"] = serde_json::json!(configured);
    }

    if !sel.rejected_in_plmn.is_empty() {
        response["rejectedNssaiInPlmn"] = serde_json::json!(sel
            .rejected_in_plmn
            .iter()
            .map(context::snssai_to_json)
            .collect::<Vec<_>>());
    }
    if !sel.rejected_in_ta.is_empty() {
        response["rejectedNssaiInTa"] = serde_json::json!(sel
            .rejected_in_ta
            .iter()
            .map(context::snssai_to_json)
            .collect::<Vec<_>>());
    }

    if !sel.candidate_amf_list.is_empty() {
        response["candidateAmfList"] = serde_json::json!(sel.candidate_amf_list);
    }
    // nssfd-07: populate targetAmfSet whenever one is configured
    // (TS 29.531 §5.2.2.2.2 step 2a). sel.target_amf_set is populated
    // by the selection algorithm only when a candidate AMF list is found;
    // fall back to the context-configured / TAI-derived value so the field
    // is also emitted on plain-success responses (no candidateAmfList).
    //
    // REROUTE non-support: the NSSF does NOT advertise the "REROUTE"
    // capability in supportedFeatures (TS 29.531 §6.1.6.3). targetAmfSet
    // is emitted for AMF-set selection only; REROUTE initiation (which
    // requires explicit feature negotiation) is out of scope.
    //
    // #93: suppressed when a candidateAmfList is present. TS 29.531 §6.1.6.2.2
    // makes the two alternative ways to steer re-selection -- a SET to pick from,
    // or an explicit CANDIDATE LIST -- and sending both leaves the AMF to guess
    // which governs. The candidate list is the more specific answer, so it wins
    // when the selection algorithm produced one.
    let effective_amf_set = sel
        .target_amf_set
        .or_else(|| snapshot.target_amf_set.clone());
    if let Some(set) = effective_amf_set {
        if sel.candidate_amf_list.is_empty() {
            response["targetAmfSet"] = serde_json::json!(set);
        } else {
            log::debug!(
                "targetAmfSet {set} suppressed: a candidateAmfList of {} entry/entries is \
                 the more specific re-selection answer (TS 29.531 §6.1.6.2.2)",
                sel.candidate_amf_list.len()
            );
        }
    }

    SbiResponse::with_status(200)
        .with_json_body(&response)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// UE-Configuration-Update (UE-CU) scenario NS selection
/// (TS 29.531 §5.2.2.2.4 / §5.2.3.2 SliceInfoForUEConfigurationUpdate).
///
/// When `requestedNssai` is absent: return `configuredNssai` /
/// `rejectedNssai*` only — do NOT synthesize `allowedNssaiList`
/// ("provide Configured/Rejected NSSAI without synthesizing an Allowed
/// NSSAI", TS 29.531 §5.2.2.2.4).
///
/// When `requestedNssai` is present: full response identical to
/// the registration scenario.
fn handle_ns_selection_ue_cu(
    nf_id: &str,
    info_json: &serde_json::Value,
    tai: Option<&context::Tai>,
) -> SbiResponse {
    let has_requested_nssai = info_json
        .get("requestedNssai")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    // Reuse the registration algorithm; strip allowedNssaiList when
    // requestedNssai was absent (UE-CU-specific rule per §5.2.2.2.4).
    let reg_resp = handle_ns_selection_registration(nf_id, info_json, tai);

    if has_requested_nssai {
        // requestedNssai present → full response (same as registration).
        return reg_resp;
    }

    if reg_resp.status != 200 {
        return reg_resp;
    }

    // Strip allowedNssaiList from the registration response body.
    let body: serde_json::Value = reg_resp
        .http
        .content
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::json!({}));

    let mut ue_cu_body = serde_json::json!({ "supportedFeatures": "1" });
    for field in [
        "configuredNssai",
        "rejectedNssaiInPlmn",
        "rejectedNssaiInTa",
        "targetAmfSet",
        "candidateAmfList",
    ] {
        if let Some(v) = body.get(field) {
            ue_cu_body[field] = v.clone();
        }
    }
    // allowedNssaiList intentionally omitted per TS 29.531 §5.2.2.2.4.
    SbiResponse::with_status(200)
        .with_json_body(&ue_cu_body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Map TS 29.531 RoamingIndication enum string
/// The normative TS 29.531 §6.1.6.3.3 spelling of the home-routed roaming
/// indication (`TS29531_Nnssf_NSSelection.yaml:485-492`).
///
/// pcfd/nssfd previously used `HOME_ROUTED`, which appears nowhere in the spec:
/// a conformant consumer sending `HOME_ROUTED_ROAMING` had its value parsed to
/// `None` and silently dropped, and the outbound H-NSSF query advertised the
/// non-normative spelling to the home network.
pub const ROAMING_HOME_ROUTED: &str = "HOME_ROUTED_ROAMING";

/// Parse a `RoamingIndication` (TS 29.531 §6.1.6.3.3).
///
/// Returns `Err(())` for a value outside the enumeration so the caller can
/// answer 400 rather than treating "not understood" as "not sent" — the two are
/// different facts and only one of them is the consumer's fault.
///
/// `HOME_ROUTED` is still ACCEPTED as an inbound back-compat shim, because this
/// NSSF emitted it on its own H-NSSF queries until this change, so a peer NSSF
/// deployed against an older build may echo it back. It is never emitted.
fn roaming_indication_parse(s: &str) -> Result<context::RoamingIndication, ()> {
    match s {
        "NON_ROAMING" => Ok(context::RoamingIndication::NonRoaming),
        "LOCAL_BREAKOUT" => Ok(context::RoamingIndication::LocalBreakout),
        ROAMING_HOME_ROUTED => Ok(context::RoamingIndication::HomeRouted),
        // Documented non-normative shim; see above.
        "HOME_ROUTED" => {
            log::debug!(
                "accepting non-normative roamingIndication HOME_ROUTED as \
                 {ROAMING_HOME_ROUTED} (TS 29.531 §6.1.6.3.3)"
            );
            Ok(context::RoamingIndication::HomeRouted)
        }
        _ => Err(()),
    }
}

/// Parse a `SnssaiYaml` into an `SNssai`, treating the wildcard `FFFFFF` as
/// "no SD" exactly as the supported-S-NSSAI loader does.
fn snssai_from_yaml(y: &SnssaiYaml) -> context::SNssai {
    let sd =
        y.sd.as_deref()
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .and_then(|v| if v == 0xFF_FFFF { None } else { Some(v) });
    context::SNssai::new(y.sst, sd)
}

/// Configured VPLMN-to-HPLMN S-NSSAI mapping (TS 29.531 §5.2.2.2.5).
///
/// Process-global and written once at startup, before the SBI server accepts a
/// request, mirroring how `set_plmn_supported_snssais` is handled. A `Mutex`
/// rather than `OnceLock` so tests can install a mapping.
static NSSAI_MAPPING: std::sync::Mutex<Vec<(context::SNssai, context::SNssai)>> =
    std::sync::Mutex::new(Vec::new());

fn set_nssai_mapping(pairs: Vec<(context::SNssai, context::SNssai)>) {
    if let Ok(mut m) = NSSAI_MAPPING.lock() {
        *m = pairs;
    }
}

/// The home S-NSSAI configured for `serving`, if any.
fn nssai_mapping_home_for(serving: &context::SNssai) -> Option<context::SNssai> {
    NSSAI_MAPPING
        .lock()
        .ok()?
        .iter()
        .find(|(s, _)| s == serving)
        .map(|(_, h)| h.clone())
}

/// Parse an `array(Snssai)` query parameter (the shape both the
/// `pdn-connection` and `other-purpose` scenarios use).
fn parse_snssai_array(raw: &str) -> Result<Vec<context::SNssai>, String> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let Some(arr) = v.as_array() else {
        return Err("expected a JSON array of Snssai".to_string());
    };
    // Schema: minItems 1.
    if arr.is_empty() {
        return Err("array must contain at least one Snssai (minItems: 1)".to_string());
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(sst) = item.get("sst").and_then(|s| s.as_u64()) else {
            return Err("each Snssai requires sst".to_string());
        };
        let sd = item
            .get("sd")
            .and_then(|s| s.as_str())
            .and_then(|h| u32::from_str_radix(h, 16).ok());
        out.push(context::SNssai::new(sst as u8, sd));
    }
    Ok(out)
}

/// `slice-info-request-for-pdn-connection` (TS 29.531 §5.2.2.2.5, feature
/// RSIPCE): return the VPLMN-to-HPLMN `mappingOfNssai` for the requested
/// subscribed S-NSSAI(s).
///
/// Per §5.2.2.2.5 step 2b, when no mapping can be found the answer is **403
/// SNSSAI_NOT_SUPPORTED** — not the 400 MANDATORY_QUERY_PARAM_MISSING this
/// scenario used to fall through to, which told the consumer it had omitted a
/// query parameter it had in fact sent.
fn handle_ns_selection_pdn_connection(nf_id: &str, raw: &str) -> SbiResponse {
    let requested = match parse_snssai_array(raw) {
        Ok(v) => v,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid slice-info-request-for-pdn-connection: {e}"),
                Some("INVALID_QUERY_PARAM"),
            )
        }
    };

    let mapping: Vec<serde_json::Value> = requested
        .iter()
        .filter_map(|serving| {
            nssai_mapping_home_for(serving).map(|home| {
                serde_json::json!({
                    "servingSnssai": context::snssai_to_json(serving),
                    "homeSnssai": context::snssai_to_json(&home),
                })
            })
        })
        .collect();

    if mapping.is_empty() {
        log::warn!(
            "[{nf_id}] pdn-connection: no VPLMN->HPLMN mapping configured for any of the \
             {} requested S-NSSAI(s); answering 403 SNSSAI_NOT_SUPPORTED \
             (TS 29.531 §5.2.2.2.5 step 2b). Configure nssf.nssai_mapping[] to serve this.",
            requested.len()
        );
        return problem_details(
            403,
            "Forbidden",
            "No S-NSSAI mapping available for the requested subscribed S-NSSAI(s)",
            Some("SNSSAI_NOT_SUPPORTED"),
        );
    }

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "supportedFeatures": NSSF_SUPPORTED_FEATURES,
            "mappingOfNssai": mapping,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// `slice-info-request-for-other-purpose` (TS 29.531 §5.2.2.2.6, feature SIOP):
/// return the NSI ID(s) for the requested S-NSSAI(s) in `snssaiInfoRspData`.
///
/// Served from the configured NSI table — the same table the PDU-session
/// scenario consults — so this scenario became answerable only once #93's NSI
/// population landed. Per §5.2.2.2.6 step 2b, no resolvable S-NSSAI is 403
/// SNSSAI_NOT_SUPPORTED.
fn handle_ns_selection_other_purpose(nf_id: &str, raw: &str) -> SbiResponse {
    let requested = match parse_snssai_array(raw) {
        Ok(v) => v,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid slice-info-request-for-other-purpose: {e}"),
                Some("INVALID_QUERY_PARAM"),
            )
        }
    };

    let mut rsp = serde_json::Map::new();
    if let Ok(context) = nssf_self().read() {
        for snssai in &requested {
            if let Some(nsi) = context.nsi_find_by_s_nssai(snssai) {
                // The map key is the S-NSSAI; serialised canonically so a
                // consumer can correlate it with what it asked for.
                let key = match snssai.sd {
                    Some(sd) => format!("{}-{:06x}", snssai.sst, sd),
                    None => format!("{}", snssai.sst),
                };
                rsp.insert(key, serde_json::json!({ "nsiIds": [nsi.nsi_id] }));
            }
        }
    }

    if rsp.is_empty() {
        log::warn!(
            "[{nf_id}] other-purpose: none of the {} requested S-NSSAI(s) has a configured \
             NSI; answering 403 SNSSAI_NOT_SUPPORTED (TS 29.531 §5.2.2.2.6 step 2b)",
            requested.len()
        );
        return problem_details(
            403,
            "Forbidden",
            "No slice information available for the requested S-NSSAI(s)",
            Some("SNSSAI_NOT_SUPPORTED"),
        );
    }

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "supportedFeatures": NSSF_SUPPORTED_FEATURES,
            "snssaiInfoRspData": rsp,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Feature bits this NSSF advertises on the two scenarios #93 added.
///
/// Bit 1 (the pre-existing `"1"`) plus RSIPCE (bit 3, TS 29.531 Table 6.1.8-1
/// entry 3) and SIOP (bit 4, entry 4), which are the features that gate
/// `mappingOfNssai` and `snssaiInfoRspData` respectively: 0b1101 = 0xd.
///
/// Emitted only on the two new handlers. The registration / PDU-session / UE-CU
/// responses keep their existing `"1"` — widening what they advertise would be
/// an unrequested change to already-negotiated behaviour on paths #93 does not
/// touch.
const NSSF_SUPPORTED_FEATURES: &str = "d";

/// `AllowedNssai.accessType` when the request does not state one.
///
/// The member is REQUIRED by TS 29.531, so it cannot be omitted the way an
/// optional unheld member would be. `3GPP_ACCESS` is the documented default for
/// a consumer that did not say, not a claim about the UE: where the request DOES
/// carry an access type (registration's `allowedNssaiCurrentAccess`), that value
/// is used instead.
///
/// Note `SliceInfoForPDUSession` has NO `accessType` member at all — only
/// `sNssai`, `homeSnssai` and `roamingIndication` — so on the PDU-session path
/// there is nothing to derive it from and this default is the only answer
/// available. Deriving one would mean inventing it.
const DEFAULT_ACCESS_TYPE: &str = "3GPP_ACCESS";

/// Install the configured NSIs into the context, returning how many landed.
///
/// Reads `nssf.sbi.client.nsi[]`, the block every shipped `nssf.yaml` already
/// carries. An entry with no `s_nssai` is skipped with a warning rather than
/// defaulted to SST 0: guessing a slice identity would install a slice instance
/// that answers for a slice nobody configured.
fn load_configured_nsis(entries: &[NsiClientYaml]) -> usize {
    let ctx = context::nssf_self();
    let Ok(context) = ctx.read() else {
        log::error!("NSSF context unavailable; cannot install configured NSIs");
        return 0;
    };
    let mut installed = 0usize;
    for entry in entries {
        let Some(ref snssai) = entry.s_nssai else {
            log::warn!(
                "nssf.sbi.client.nsi entry for {} has no s_nssai; skipped (an NSI \
                 must name the slice it serves)",
                entry.uri
            );
            continue;
        };
        // `sd` is 3 octets of hex in the YAML, matching supported_snssai_list.
        let sd = snssai
            .sd
            .as_deref()
            .and_then(|h| u32::from_str_radix(h, 16).ok());
        match context.nsi_add(&entry.uri, snssai.sst, sd) {
            Some(mut nsi) => {
                // Honour an operator-assigned nsiId; otherwise keep the UUID
                // NssfNsi::new minted.
                if let Some(ref id) = entry.nsi_id {
                    nsi.nsi_id = id.clone();
                    context.nsi_update(&nsi);
                }
                installed += 1;
                log::info!(
                    "NSI configured: sst={} sd={:?} nsiId={} nrf={}",
                    snssai.sst,
                    sd,
                    nsi.nsi_id,
                    entry.uri
                );
            }
            None => log::error!(
                "failed to install NSI for sst={} sd={:?} (capacity reached?)",
                snssai.sst,
                sd
            ),
        }
    }
    installed
}

/// PDU-session-scenario NS selection (TS 29.531 §5.2.3.2.4)
async fn handle_ns_selection_pdu_session(
    nf_id: &str,
    nf_type: &str,
    si_json: &serde_json::Value,
    tai: Option<&context::Tai>,
    supi: Option<String>,
    home_plmn_id: Option<String>,
) -> SbiResponse {
    // sNssai and roamingIndication are mandatory in SliceInfoForPDUSession
    let snssai = match si_json.get("sNssai").and_then(context::snssai_from_json) {
        Some(s) => s,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "sliceInfoRequestForPduSession.sNssai is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let roaming = match si_json.get("roamingIndication") {
        Some(serde_json::Value::String(s)) => match roaming_indication_parse(s) {
            Ok(r) => r,
            Err(()) => {
                return problem_details(
                    400,
                    "Bad Request",
                    &format!(
                        "Invalid roamingIndication '{s}'; expected one of NON_ROAMING, \
                         LOCAL_BREAKOUT, {ROAMING_HOME_ROUTED} (TS 29.531 §6.1.6.3.3)"
                    ),
                    Some("INVALID_IE_VALUE"),
                )
            }
        },
        _ => {
            return problem_details(
                400,
                "Bad Request",
                "sliceInfoRequestForPduSession.roamingIndication is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let mut param = nnssf_handler::NsSelectionParam {
        nf_id: Some(nf_id.to_string()),
        nf_type: Some(nf_type.to_string()),
        slice_info_for_pdu_session: nnssf_handler::SliceInfoForPduSession {
            presence: true,
            snssai: Some(snssai.clone()),
            roaming_indication: roaming,
        },
        tai: tai.cloned(),
        ..Default::default()
    };

    if let Some(hp) = home_plmn_id
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .or_else(|| si_json.get("homePlmnId").cloned())
    {
        if let (Some(mcc), Some(mnc)) = (
            hp.get("mcc").and_then(|v| v.as_str()),
            hp.get("mnc").and_then(|v| v.as_str()),
        ) {
            param.home_plmn_id = Some(context::PlmnId::new(mcc, mnc));
        }
    }
    if let Some(hs) = si_json
        .get("homeSnssai")
        .and_then(context::snssai_from_json)
    {
        param.home_snssai = Some(hs);
    }

    // Call the real NS selection handler
    let result = nnssf_handler::nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(0, &param);

    match result {
        nnssf_handler::NsSelectionResult::Success(info) => {
            // Snapshot everything we need from the NSSF context into OWNED data
            // and drop the read-lock BEFORE the async DB call below (DANGER-ZONES B1).
            let ctx = nssf_self();
            let (mut allowed_snssai_list, supported_for_tai): (
                Vec<serde_json::Value>,
                Vec<(u8, Option<u32>)>,
            ) = {
                let context = match ctx.read() {
                    Ok(c) => c,
                    Err(_) => {
                        return problem_details(
                            500,
                            "Internal Server Error",
                            "context lock poisoned",
                            None,
                        )
                    }
                };

                // nssfd-04: seed allowedNssaiList from the validated requested
                // S-NSSAI only (TS 29.531 §5.2.2.2.3 step 2a: "the allowed
                // NSSAI corresponds to the requested S-NSSAI, not the full
                // catalogue"). For home-routed roaming include the mapped home
                // S-NSSAI when present. The subscription + availability retain
                // filters below apply as defence-in-depth narrowing.
                let mut allowed_item = serde_json::json!({
                    "allowedSnssai": context::snssai_to_json(&snssai)
                });
                if let Some(ref hs) = param.home_snssai {
                    allowed_item["mappedHomeSnssai"] = context::snssai_to_json(hs);
                }
                let list = vec![allowed_item];

                // Snapshot TAI-supported S-NSSAIs as owned (sst, sd) tuples
                // (TS 29.531 6.1.3.2.3.2) so we can filter after dropping the lock.
                let supported = if let Some(t) = tai {
                    context
                        .get_supported_snssai_for_tai(t)
                        .iter()
                        .map(|s| (s.sst, s.sd))
                        .collect()
                } else {
                    Vec::new()
                };

                (list, supported)
            }; // <- context read-lock released here, before any await

            // Subscription-based filtering: if SUPI provided, query UDR for
            // subscribed NSSAIs and filter (TS 29.531 6.1.3.2.3.1).
            if let Some(ref supi_val) = supi {
                match nextgcore_dbi::nextgcore_dbi_subscription_data_async(supi_val.to_string())
                    .await
                {
                    Ok(sub_data) => {
                        let subscribed: Vec<(u8, Option<u32>)> = sub_data
                            .slice
                            .iter()
                            .map(|s| {
                                (
                                    s.s_nssai.sst,
                                    if s.s_nssai.sd.v == 0xFFFFFF {
                                        None
                                    } else {
                                        Some(s.s_nssai.sd.v)
                                    },
                                )
                            })
                            .collect();

                        if !subscribed.is_empty() {
                            allowed_snssai_list.retain(|item| {
                                let sst = item
                                    .get("allowedSnssai")
                                    .and_then(|s| s.get("sst"))
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0) as u8;
                                let sd = item
                                    .get("allowedSnssai")
                                    .and_then(|s| s.get("sd"))
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| u32::from_str_radix(s, 16).ok());
                                subscribed
                                    .iter()
                                    .any(|(sub_sst, sub_sd)| *sub_sst == sst && *sub_sd == sd)
                            });
                        }
                    }
                    Err(e) => {
                        log::debug!(
                            "UDR subscription query unavailable for SUPI ({e}), allowing all NSSAIs"
                        );
                    }
                }
            }

            // Also filter against the NSSAI-availability snapshot taken above
            if !supported_for_tai.is_empty() {
                allowed_snssai_list.retain(|item| {
                    let sst = item
                        .get("allowedSnssai")
                        .and_then(|s| s.get("sst"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u8;
                    let sd = item
                        .get("allowedSnssai")
                        .and_then(|s| s.get("sd"))
                        .and_then(|v| v.as_str())
                        .and_then(|s| u32::from_str_radix(s, 16).ok());
                    supported_for_tai
                        .iter()
                        .any(|(s_sst, s_sd)| *s_sst == sst && *s_sd == sd)
                });
            }

            let mut response = serde_json::json!({
                "allowedNssaiList": [{
                    "allowedSnssaiList": allowed_snssai_list,
                    // SliceInfoForPDUSession carries no accessType, so this is
                    // the documented default rather than a derived value; see
                    // DEFAULT_ACCESS_TYPE.
                    "accessType": DEFAULT_ACCESS_TYPE
                }],
                "supportedFeatures": "1"
            });

            // nsiInformation is the spec response attribute for the PDU
            // session scenario; nsiInformationList is kept for back-compat.
            if let Some(nsi_info) = info.nsi_information {
                response["nsiInformation"] = serde_json::json!({
                    "nrfId": nsi_info.nrf_id,
                    "nsiId": nsi_info.nsi_id
                });
                response["nsiInformationList"] = serde_json::json!([{
                    "nrfId": nsi_info.nrf_id,
                    "nsiId": nsi_info.nsi_id
                }]);
            }

            SbiResponse::with_status(200)
                .with_json_body(&response)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        nnssf_handler::NsSelectionResult::NeedHnssf(home_id) => {
            // Query H-NSSF via SBI client
            log::info!("NS Selection requires H-NSSF query (home_id={home_id})");

            match send_hnssf_query(home_id, &param).await {
                Ok(nsi_info) => SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "nsiInformation": {
                            "nrfId": nsi_info.nrf_id,
                            "nsiId": nsi_info.nsi_id
                        },
                        "nsiInformationList": [{
                            "nrfId": nsi_info.nrf_id,
                            "nsiId": nsi_info.nsi_id
                        }],
                        "supportedFeatures": "1"
                    }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200)),
                Err(e) => {
                    log::warn!("H-NSSF query failed: {e}");
                    problem_details(
                        500,
                        "Internal Server Error",
                        &format!("H-NSSF query failed: {e}"),
                        Some("H_NSSF_UNAVAILABLE"),
                    )
                }
            }
        }
        nnssf_handler::NsSelectionResult::Error(status, msg) => {
            log::warn!("NS Selection error: {status} - {msg}");
            let title = match status {
                400 => "Bad Request",
                403 => "Forbidden",
                404 => "Not Found",
                _ => "Error",
            };
            let cause = match status {
                403 => Some("SNSSAI_NOT_SUPPORTED"),
                _ => None,
            };
            problem_details(status, title, &msg, cause)
        }
    }
}

// ---------------------------------------------------------------------------
// NSSAI Availability (TS 29.531 §5.3: Nnssf_NSSAIAvailability v1)
// ---------------------------------------------------------------------------

/// Validate a NssaiAvailabilityInfo doc; returns affected TAIs on success.
fn validate_availability_doc(doc: &serde_json::Value) -> Result<Vec<context::Tai>, String> {
    let entries = doc
        .get("supportedNssaiAvailabilityData")
        .and_then(|v| v.as_array())
        .ok_or("Missing mandatory attribute supportedNssaiAvailabilityData")?;
    if entries.is_empty() {
        return Err("supportedNssaiAvailabilityData must contain at least one entry".to_string());
    }
    let mut tais = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let tai = entry
            .get("tai")
            .and_then(context::tai_from_json)
            .ok_or_else(|| {
                format!("supportedNssaiAvailabilityData[{i}]: missing/invalid mandatory tai")
            })?;
        let snssai_list = entry
            .get("supportedSnssaiList")
            .and_then(|v| v.as_array())
            .filter(|a| !a.is_empty())
            .ok_or_else(|| {
                format!(
                    "supportedNssaiAvailabilityData[{i}]: missing mandatory supportedSnssaiList"
                )
            })?;
        for (j, s) in snssai_list.iter().enumerate() {
            context::snssai_from_json(s).ok_or_else(|| {
                format!(
                    "supportedNssaiAvailabilityData[{i}].supportedSnssaiList[{j}]: invalid S-NSSAI"
                )
            })?;
        }
        tais.push(tai);
        if let Some(extra) = entry.get("taiList").and_then(|v| v.as_array()) {
            tais.extend(extra.iter().filter_map(context::tai_from_json));
        }
    }
    Ok(tais)
}

/// Outcome of the NSSAIAvailability authorization / PLMN-support cross-check
/// (TS 29.531 §6.2.3.2.3.1, TS 33.521). Both variants map to 403 Forbidden;
/// only the ProblemDetails `cause` differs.
enum AvailabilityAuthError {
    /// NF service consumer (identified by NF Id) is not authorized to update
    /// the NSSAI availability information -> cause `NOT_AUTHORIZED`.
    Unauthorized(String),
    /// A reported S-NSSAI is not supported in the PLMN -> `SNSSAI_NOT_SUPPORTED`.
    UnsupportedSnssai(String),
}

impl AvailabilityAuthError {
    /// Render the 403 ProblemDetails (TS 29.531 §6.2.3.2.3.1 Table
    /// 6.2.3.2.3.1-2) carrying the appropriate `cause`.
    fn into_problem(self) -> SbiResponse {
        match self {
            AvailabilityAuthError::Unauthorized(detail) => {
                problem_details(403, "Forbidden", &detail, Some("NOT_AUTHORIZED"))
            }
            AvailabilityAuthError::UnsupportedSnssai(detail) => {
                problem_details(403, "Forbidden", &detail, Some("SNSSAI_NOT_SUPPORTED"))
            }
        }
    }
}

/// Cross-check an NssaiAvailabilityInfo document against the consumer's
/// authorization and the PLMN-supported S-NSSAI set (TS 29.531 §6.2.3.2.3.1,
/// TS 33.521). Pure (no global state) so it is unit-testable in isolation.
///
/// Default-allow stance (matched-sim back-compat, TS 29.531 §6.2.3.2.3.1):
///   * `authorized == true` is the default for any non-empty NF Id; only a
///     missing/empty NF Id yields `NOT_AUTHORIZED`. We deliberately do NOT
///     require an NRF lookup here, which would otherwise reject the matched
///     simulator's AMF.
///   * `restriction == None` means NO PLMN restriction is configured, so EVERY
///     reported S-NSSAI is accepted (the matched-sim registers default slices,
///     e.g. sst=1, and must not be newly rejected). `SNSSAI_NOT_SUPPORTED` is
///     returned ONLY when a restriction is explicitly configured AND a reported
///     S-NSSAI falls outside it.
///
/// Authorization is checked before PLMN support so a forbidden consumer is
/// rejected regardless of slice contents.
fn authorize_availability_doc(
    nf_id: &str,
    doc: &serde_json::Value,
    authorized: bool,
    restriction: Option<&[context::SNssai]>,
) -> Result<(), AvailabilityAuthError> {
    if !authorized {
        return Err(AvailabilityAuthError::Unauthorized(format!(
            "NF Id '{nf_id}' is not authorized to update NSSAI availability information"
        )));
    }
    let Some(allowed) = restriction else {
        // No restriction configured -> allow all (default-allow, see above).
        return Ok(());
    };
    for (_tais, snssais) in context::availability_entries(doc) {
        for s in &snssais {
            if !allowed.contains(s) {
                let sd =
                    s.sd.map(|v| format!("{v:06x}"))
                        .unwrap_or_else(|| "none".to_string());
                return Err(AvailabilityAuthError::UnsupportedSnssai(format!(
                    "S-NSSAI (sst={}, sd={sd}) is not supported in the PLMN",
                    s.sst
                )));
            }
        }
    }
    Ok(())
}

/// Snapshot the NSSF's availability-authorization config from the global
/// context and run [`authorize_availability_doc`]. Returns the 403
/// ProblemDetails response on failure, `None` when the update is permitted.
fn check_availability_authorization(
    nf_id: &str,
    doc: &serde_json::Value,
    affected_tais: &[context::Tai],
    request: &SbiRequest,
) -> Option<SbiResponse> {
    let tai = affected_tais.first().cloned().unwrap_or_default();

    // The identity THIS PROCESS attested, in preference order. The verified
    // client certificate outranks the token because it is bound to the
    // connection rather than bearer-presentable; both are verified locally, and
    // neither is read from the request path or body.
    let caller = request
        .peer_cert_nf_instance_id
        .as_deref()
        .or(request.oauth2_subject.as_deref());

    let result = with_nssf_context(|context| {
        let restriction = if context.has_plmn_snssai_restriction() {
            Some(context.plmn_supported_snssais())
        } else {
            None
        };
        (
            context.nf_authorized_for_availability(nf_id, caller, &tai),
            restriction,
        )
    });

    let (authorized, restriction) = match result {
        Some(v) => v,
        // #94: a poisoned context lock now FAILS CLOSED. It used to fall back to
        // the default-allow policy, so poisoning the lock — which any panicking
        // sibling request can do — turned the authorization check off entirely.
        // An availability write is a write to another NF's slice picture; not
        // being able to evaluate the policy is not a reason to permit it.
        None => {
            log::error!(
                "NSSF context lock poisoned; DENYING availability write for {nf_id} \
                 (fail-closed, issue #94)"
            );
            return Some(policy_unevaluable_response());
        }
    };

    // The documented escape hatch: a deployment that has explicitly turned SBI
    // OAuth2 enforcement off has no attestable identity to bind to, so requiring
    // one would make availability writes impossible rather than safe. Permitted,
    // and WARNED about at every write so the posture is visible in the log rather
    // than only in the config (the #64 pattern).
    // The hatch covers a MISSING CALLER IDENTITY, never a missing resource owner:
    // an empty `{nfId}` names no document, so there is nothing it could be
    // authorized to write whatever the posture. Without this guard the hatch
    // permitted an empty nfId, which the whole-workspace run caught.
    if !authorized && caller.is_none() && !nf_id.trim().is_empty() && !strict_availability_authz() {
        log::warn!(
            "availability write for {nf_id} accepted WITHOUT an attested caller identity: \
             SBI OAuth2 enforcement is disabled, so any reachable NF can write any AMF's \
             slice-availability document. Set nssf.sbi.oauth2.require = true to bind the \
             caller to the resource (TS 33.501 §13.4.1)."
        );
        return authorize_availability_doc(nf_id, doc, true, restriction.as_deref())
            .err()
            .map(AvailabilityAuthError::into_problem);
    }

    if !authorized {
        log::warn!(
            "availability write for {nf_id} REJECTED: attested caller {:?} is not the owner \
             of that document (TS 29.531 Table 6.2.3.2.3.1-2)",
            caller
        );
    }

    authorize_availability_doc(nf_id, doc, authorized, restriction.as_deref())
        .err()
        .map(AvailabilityAuthError::into_problem)
}

/// The response when the availability-authorization policy cannot be EVALUATED
/// (e.g. a poisoned context lock).
///
/// A denial. Before #94 this path fell back to the default-allow policy, so any
/// panicking sibling request — which is all it takes to poison a `std` lock —
/// turned the authorization check off for every subsequent availability write.
/// Not being able to evaluate a policy is not a reason to permit the write.
///
/// Extracted so the outcome is assertable: poisoning the PROCESS-GLOBAL context
/// lock inside a test would break every parallel test in the binary, which is the
/// avalanche the recorded poisoned-mutex lesson describes. The call site is pinned
/// by a source guard instead.
fn policy_unevaluable_response() -> SbiResponse {
    problem_details(
        403,
        "Forbidden",
        "NSSF cannot evaluate availability authorization at this time",
        Some("NOT_AUTHORIZED"),
    )
}

/// Whether availability writes must be bound to an attested caller identity.
///
/// Tied to `nssf.sbi.oauth2.require`, which is the operator's existing statement
/// about whether this NSSF authenticates its consumers at all: binding a caller
/// to a resource is only meaningful when a caller identity is authenticated, so
/// one knob governs both rather than two that can disagree.
static STRICT_AVAILABILITY_AUTHZ: AtomicBool = AtomicBool::new(true);

fn strict_availability_authz() -> bool {
    STRICT_AVAILABILITY_AUTHZ.load(Ordering::SeqCst)
}

fn set_strict_availability_authz(strict: bool) {
    STRICT_AVAILABILITY_AUTHZ.store(strict, Ordering::SeqCst);
}

/// Build the AuthorizedNssaiAvailabilityInfo response for a stored doc
/// (TS 29.531 §5.3.2.2 / §6.2.6.2.4).
///
/// nssfd-02: For each TA entry, include `restrictedSnssaiList` when the
/// NSSF configuration restricts S-NSSAIs per home PLMN (§6.2.6.2.4
/// RestrictedSnssai). Default empty map → field absent (matched-sim
/// back-compat: the matched-sim AMF does not expect this field).
///
/// nssfd-03: Return `204 No Content` when no S-NSSAIs remain
/// authorized/supported across all TAs ("No supported slices after
/// Successful update", TS 29.531 §6.2.3.2.3.1 Table 6.2.3.2.3.1-2).
/// Notifications are NOT affected (storage is already committed by callers
/// before this function is invoked).
fn authorized_availability_response(doc: &serde_json::Value) -> SbiResponse {
    let entries = doc
        .get("supportedNssaiAvailabilityData")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut authorized_entries: Vec<serde_json::Value> = Vec::new();
    for entry in &entries {
        let tai = entry.get("tai").and_then(context::tai_from_json);

        // nssfd-02: lookup per-home-PLMN restrictions from NSSF config for
        // this TAI (TS 29.531 §6.2.6.2.4 RestrictedSnssai per home PLMN).
        let restrictions: Vec<(context::PlmnId, Vec<context::SNssai>)> = tai
            .as_ref()
            .and_then(|t| with_nssf_context(|c| c.restricted_snssais_for_tai(t)))
            .unwrap_or_default();

        let mut out = serde_json::json!({});
        if let Some(tai_val) = entry.get("tai") {
            out["tai"] = tai_val.clone();
        }
        if let Some(snssai_list) = entry.get("supportedSnssaiList") {
            out["supportedSnssaiList"] = snssai_list.clone();
        }
        // #94 criterion 7: carry the locality/scoping members through. These were
        // dropped, so an availability entry scoped by a TAI RANGE (or carrying NSAG
        // information) came back scoped by nothing — the consumer could not tell
        // which TAIs the authorization actually covered.
        for member in ["taiList", "taiRangeList", "nsagInfos"] {
            if let Some(v) = entry.get(member) {
                out[member] = v.clone();
            }
        }
        if !restrictions.is_empty() {
            out["restrictedSnssaiList"] = serde_json::json!(restrictions
                .iter()
                .map(|(plmn, snssais)| {
                    serde_json::json!({
                        "homePlmnId": { "mcc": plmn.mcc, "mnc": plmn.mnc },
                        // #94: `sNssaiList`, not `sNssais`. TS 29.531
                        // RestrictedSnssai has `required: [homePlmnId, sNssaiList]`,
                        // so the old key made the object fail schema validation at
                        // any strict consumer -- latent only because nothing could
                        // configure a restriction in production until now.
                        "sNssaiList": snssais.iter().map(context::snssai_to_json).collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>());
        }
        authorized_entries.push(out);
    }

    // nssfd-03: 204 No Content when no S-NSSAIs remain authorized/supported
    // across all TAs (TS 29.531 §6.2.3.2.3.1 Table 6.2.3.2.3.1-2 "No
    // supported slices after Successful update").
    let any_supported = authorized_entries.iter().any(|e| {
        e.get("supportedSnssaiList")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    });
    if !any_supported {
        return SbiResponse::with_status(204);
    }

    let response = serde_json::json!({
        "authorizedNssaiAvailabilityData": authorized_entries,
        "supportedFeatures": "1"
    });
    SbiResponse::with_status(200)
        .with_json_body(&response)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_nssai_availability_update(nf_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Update: nf_id={nf_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body (NssaiAvailabilityInfo)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let doc: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let affected_tais = match validate_availability_doc(&doc) {
        Ok(t) => t,
        Err(e) => return problem_details(400, "Bad Request", &e, Some("MANDATORY_IE_MISSING")),
    };

    // nssfd-01: authorize the consumer + cross-check every reported S-NSSAI
    // against the PLMN-supported set BEFORE storing or notifying (TS 29.531
    // §6.2.3.2.3.1, TS 33.521). On failure the 403 returns here, so nothing is
    // stored and no notification is spawned.
    if let Some(resp) = check_availability_authorization(nf_id, &doc, &affected_tais, request) {
        return resp;
    }

    let info = context::availability_info_from_doc(nf_id, doc.clone());
    with_nssf_context(|context| context.set_nssai_availability(nf_id, info));

    log::info!(
        "Stored NSSAI availability for NF {nf_id} ({} TA entries)",
        affected_tais.len()
    );

    spawn_availability_notifications(affected_tais, Some(nf_id.to_string()));

    authorized_availability_response(&doc)
}

async fn handle_nssai_availability_patch(nf_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Patch: nf_id={nf_id}");

    // nssfd-05: RFC 6902 / TS 29.531 §6.2 PatchDocument mandate
    // Content-Type: application/json-patch+json. Reject any other media type
    // (or missing Content-Type) with 415 Unsupported Media Type before
    // attempting to parse or apply the patch.
    let ct = request
        .http
        .get_header("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    let ct_base = ct.split(';').next().unwrap_or("").trim();
    if !ct_base.eq_ignore_ascii_case("application/json-patch+json") {
        return problem_details(
            415,
            "Unsupported Media Type",
            "PATCH requires Content-Type: application/json-patch+json (RFC 6902, TS 29.531 §6.2)",
            None,
        );
    }

    let existing = with_nssf_context(|context| context.get_nssai_availability(nf_id)).flatten();
    let existing = match existing {
        Some(e) => e,
        None => {
            return problem_details(
                404,
                "Not Found",
                &format!("No NSSAI availability stored for NF {nf_id}"),
                Some("RESOURCE_NOT_FOUND"),
            )
        }
    };

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body (PatchDocument)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    // RFC 6902 JSON Patch (TS 29.531 PatchDocument) applied to a clone;
    // only commit on success.
    let mut patched = existing.doc.clone();
    if let Err(e) = nextgcore_sbi::json_patch::apply_patch(&mut patched, &patch) {
        return problem_details(
            400,
            "Bad Request",
            &format!("JSON Patch failed: {e}"),
            Some("INVALID_MSG_FORMAT"),
        );
    }

    let affected_tais = match validate_availability_doc(&patched) {
        Ok(t) => t,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Patched document is not a valid NssaiAvailabilityInfo: {e}"),
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    // nssfd-01: apply the identical authorization + PLMN-support cross-check to
    // the POST-PATCH document before committing (TS 29.531 §6.2.3.2.3.1). A
    // patch that introduces an S-NSSAI unsupported in the PLMN is rejected with
    // 403 and the previously stored document is left unchanged.
    if let Some(resp) = check_availability_authorization(nf_id, &patched, &affected_tais, request) {
        return resp;
    }

    let info = context::availability_info_from_doc(nf_id, patched.clone());
    with_nssf_context(|context| context.set_nssai_availability(nf_id, info));

    log::info!("Patched NSSAI availability for NF {nf_id}");

    spawn_availability_notifications(affected_tais, Some(nf_id.to_string()));

    authorized_availability_response(&patched)
}

async fn handle_nssai_availability_delete(nf_id: &str) -> SbiResponse {
    log::info!("NSSAI Availability Delete: nf_id={nf_id}");

    let (removed, affected_tais) = with_nssf_context(|context| {
        let old = context.get_nssai_availability(nf_id);
        let removed = context.remove_nssai_availability(nf_id);
        (removed, old.map(|o| o.tai_list).unwrap_or_default())
    })
    .unwrap_or((false, Vec::new()));

    if !removed {
        return problem_details(
            404,
            "Not Found",
            &format!("No NSSAI availability stored for NF {nf_id}"),
            Some("RESOURCE_NOT_FOUND"),
        );
    }

    spawn_availability_notifications(affected_tais, Some(nf_id.to_string()));

    SbiResponse::with_status(204)
}

async fn handle_nssai_availability_options() -> SbiResponse {
    log::debug!("NSSAI Availability Options");
    SbiResponse::with_status(200).with_header("Allow", "PUT, PATCH, DELETE, POST, OPTIONS")
}

// ---------------------------------------------------------------------------
// Availability-change subscriptions + notifications
// ---------------------------------------------------------------------------

/// The only `NssfEventType` this NSSF has a producer for.
///
/// `spawn_availability_notifications` fires on an availability change and
/// nothing else; `SNSSAI_REPLACEMENT_REPORT`, `NSI_UNAVAILABILITY_REPORT` and
/// `SNSSAI_VALIDITY_TIME_REPORT` have no code path that could emit them. That is
/// what `acceptedEvents` exists to tell the consumer, so it is reported honestly
/// rather than echoing back everything requested.
const REPORTABLE_EVENTS: &[&str] = &["SNSSAI_STATUS_CHANGE_REPORT"];

/// Parse and validate `NssfEventSubscriptionCreateData`.
///
/// Mandatory per TS 29.531 Table 6.2.6.2.8-1 and the OpenAPI
/// (`required: [nfNssaiAvailabilityUri, event]`): **those two only**.
///
/// `taiList` is OPTIONAL and was previously rejected as missing, so a conformant
/// consumer subscribing to all TAIs got a 400. An absent or empty list means "all
/// TAIs", which is already exactly how `subscriptions_matching` treats an empty
/// list — the semantics existed, only the validation disagreed.
///
/// Deviation from the issue's suggested approach, stated deliberately: #94
/// proposes requiring `taiList` for the status-change event specifically. The
/// spec imposes no such conditional, so adding one would 400 a legal request; the
/// schema is followed instead and the "all TAIs" reading is documented here.
/// (The issue also names the event `SNSSAI_STATUS_CHANGE`; the enum token is
/// `SNSSAI_STATUS_CHANGE_REPORT`, and the OpenAPI spelling is what is used.)
fn subscription_from_json(
    subscription_id: &str,
    v: &serde_json::Value,
) -> Result<context::NssfSubscription, String> {
    let mut missing = Vec::new();
    let uri = v.get("nfNssaiAvailabilityUri").and_then(|x| x.as_str());
    if uri.is_none() {
        missing.push("nfNssaiAvailabilityUri");
    }
    let event = v.get("event").and_then(|x| x.as_str());
    if event.is_none() {
        missing.push("event");
    }
    if !missing.is_empty() {
        return Err(format!(
            "Missing mandatory attribute(s): {}",
            missing.join(", ")
        ));
    }

    // Optional; absent => no TAI scoping => all TAIs.
    let mut tai_list = Vec::new();
    if let Some(arr) = v.get("taiList").and_then(|x| x.as_array()) {
        for (i, t) in arr.iter().enumerate() {
            tai_list.push(
                context::tai_from_json(t)
                    .ok_or_else(|| format!("taiList[{i}] is not a valid Tai"))?,
            );
        }
    }

    // `additionalEvents` alongside `event` (Table 6.2.6.2.8-1). `NssfEventType`
    // is an anyOf over the enum plus a free-form string, so an unrecognised token
    // is forward-compatibility and must NOT be rejected — it simply does not
    // appear in `acceptedEvents`.
    let event = event.expect("checked above").to_string();
    let mut requested = vec![event.clone()];
    if let Some(arr) = v.get("additionalEvents").and_then(|x| x.as_array()) {
        for e in arr {
            match e.as_str() {
                Some(s) if !s.is_empty() => {
                    if !requested.contains(&s.to_string()) {
                        requested.push(s.to_string());
                    }
                }
                _ => return Err("additionalEvents members must be non-empty strings".to_string()),
            }
        }
    }
    let accepted_events: Vec<String> = requested
        .iter()
        .filter(|e| REPORTABLE_EVENTS.contains(&e.as_str()))
        .cloned()
        .collect();
    if accepted_events.is_empty() {
        // Nothing requested can ever fire, so the subscription would leave the
        // consumer waiting forever. Unlike the Npcf_EventExposure case, TS 29.531
        // DOES give a conformant way to report partial acceptance
        // (`acceptedEvents`), which is why only the empty intersection is refused.
        return Err(format!(
            "none of the requested event(s) {requested:?} can be reported by this NSSF; \
             reportable events are {REPORTABLE_EVENTS:?}"
        ));
    }

    // TS 29.531 Table 6.2.6.2.9-1: the NSSF assigns the expiry. A
    // consumer-requested value is honoured only when EARLIER than the NSSF's own
    // bound, so a consumer cannot extend its subscription past what the producer
    // is willing to keep. Previously the consumer's value was echoed verbatim and
    // none was assigned when it was absent, so subscriptions were unbounded.
    let now = nextgcore_sbi::datetime::now_epoch_secs();
    let nssf_deadline = now + timer::defaults::SUBSCRIPTION_VALIDITY.as_secs();
    let deadline = v
        .get("expiry")
        .and_then(|x| x.as_str())
        .and_then(nextgcore_sbi::datetime::rfc3339_to_epoch)
        .filter(|requested| *requested > now)
        .map(|requested| requested.min(nssf_deadline))
        .unwrap_or(nssf_deadline);

    Ok(context::NssfSubscription {
        subscription_id: subscription_id.to_string(),
        nf_nssai_availability_uri: uri.expect("checked above").to_string(),
        tai_list,
        event,
        expiry: Some(nextgcore_sbi::datetime::epoch_to_rfc3339(deadline)),
        accepted_events,
        amf_id: v.get("amfId").and_then(|x| x.as_str()).map(String::from),
        amf_set_id: v.get("amfSetId").and_then(|x| x.as_str()).map(String::from),
    })
}

/// Collect AuthorizedNssaiAvailabilityData entries matching a subscription's
/// TAI list (empty list = all entries) from all stored availability docs.
fn collect_authorized_data_for(sub_tais: &[context::Tai]) -> Vec<serde_json::Value> {
    let infos = with_nssf_context(|context| context.all_nssai_availability()).unwrap_or_default();
    let mut result = Vec::new();
    for info in infos {
        let Some(entries) = info
            .doc
            .get("supportedNssaiAvailabilityData")
            .and_then(|v| v.as_array())
        else {
            continue;
        };
        for entry in entries {
            let entry_tais: Vec<context::Tai> = {
                let mut t = Vec::new();
                if let Some(tai) = entry.get("tai").and_then(context::tai_from_json) {
                    t.push(tai);
                }
                if let Some(extra) = entry.get("taiList").and_then(|v| v.as_array()) {
                    t.extend(extra.iter().filter_map(context::tai_from_json));
                }
                t
            };
            let matches = sub_tais.is_empty()
                || entry_tais.iter().any(|et| {
                    sub_tais.iter().any(|st| {
                        st.plmn_id.mcc == et.plmn_id.mcc
                            && st.plmn_id.mnc == et.plmn_id.mnc
                            && st.tac == et.tac
                    })
                });
            if matches {
                result.push(entry.clone());
            }
        }
    }
    result
}

/// Fire NssfEventNotification POSTs to all subscriptions matching the
/// affected TAIs. Runs each delivery on its own task with bounded timeouts.
fn spawn_availability_notifications(affected_tais: Vec<context::Tai>, changed_by: Option<String>) {
    let subs = with_nssf_context(|context| context.subscriptions_matching(&affected_tais))
        .unwrap_or_default();

    for sub in subs {
        // Don't notify the AMF whose own update caused the change; it gets
        // the AuthorizedNssaiAvailabilityInfo in the direct response.
        if let (Some(ref changed), Some(ref amf_id)) = (&changed_by, &sub.amf_id) {
            if *changed == *amf_id {
                continue;
            }
        }

        let data = collect_authorized_data_for(&sub.tai_list);
        tokio::spawn(async move {
            send_availability_notification(sub, data).await;
        });
    }
}

/// Deliver one NssfEventNotification as a real HTTP POST (bounded timeouts)
async fn send_availability_notification(
    sub: context::NssfSubscription,
    data: Vec<serde_json::Value>,
) {
    let Some((host, port, path)) = split_uri(&sub.nf_nssai_availability_uri) else {
        log::warn!(
            "Subscription {}: invalid nfNssaiAvailabilityUri '{}'",
            sub.subscription_id,
            sub.nf_nssai_availability_uri
        );
        return;
    };

    let body = serde_json::json!({
        "subscriptionId": sub.subscription_id,
        "authorizedNssaiAvailabilityData": data,
    });

    let client = SbiClient::new(
        SbiClientConfig::new(host, port)
            .with_connect_timeout(NOTIFY_CONNECT_TIMEOUT)
            .with_request_timeout(NOTIFY_REQUEST_TIMEOUT),
    );
    // NSSAI-availability notifications are consumed by AMFs; attach an
    // NRF-issued token when OAuth2 enforcement is on (no-op otherwise).
    let client = attach_oauth2(client, NfType::Amf);

    match client.post_json(&path, &body).await {
        Ok(resp) if resp.status == 204 || resp.is_success() => {
            log::debug!(
                "Availability notification delivered to {} (sub {})",
                sub.nf_nssai_availability_uri,
                sub.subscription_id
            );
        }
        Ok(resp) => {
            log::warn!(
                "Availability notification to {} returned {}",
                sub.nf_nssai_availability_uri,
                resp.status
            );
        }
        Err(e) => {
            log::warn!(
                "Availability notification to {} failed: {e}",
                sub.nf_nssai_availability_uri
            );
        }
    }
    client.close().await;
}

async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body (NssfEventSubscriptionCreateData)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let subscription_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let subscription_id = uuid::Uuid::new_v4().to_string();
    let sub = match subscription_from_json(&subscription_id, &subscription_data) {
        Ok(s) => s,
        Err(e) => return problem_details(400, "Bad Request", &e, Some("MANDATORY_IE_MISSING")),
    };

    let mut created = sub.to_created_json();
    let authorized = collect_authorized_data_for(&sub.tai_list);
    if !authorized.is_empty() {
        created["authorizedNssaiAvailabilityData"] = serde_json::json!(authorized);
    }

    with_nssf_context(|context| context.subscription_add(sub));

    log::info!("Created NSSAI availability subscription: {subscription_id}");

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/{subscription_id}"
            ),
        )
        .with_json_body(&created)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Delete: {subscription_id}");

    let removed =
        with_nssf_context(|context| context.subscription_remove(subscription_id)).unwrap_or(false);

    if removed {
        SbiResponse::with_status(204)
    } else {
        problem_details(
            404,
            "Not Found",
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

async fn handle_subscription_patch(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Patch: {subscription_id}");

    let existing = with_nssf_context(|context| context.subscription_get(subscription_id)).flatten();
    let existing = match existing {
        Some(s) => s,
        None => {
            return problem_details(
                404,
                "Not Found",
                &format!("Subscription {subscription_id} not found"),
                Some("SUBSCRIPTION_NOT_FOUND"),
            )
        }
    };

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body (PatchDocument)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    // Render the subscription as its CreateData document, patch it, and
    // re-validate the mandatory attributes.
    let mut doc = serde_json::json!({
        "nfNssaiAvailabilityUri": existing.nf_nssai_availability_uri,
        "taiList": existing.tai_list.iter().map(context::tai_to_json).collect::<Vec<_>>(),
        "event": existing.event,
    });
    if let Some(ref e) = existing.expiry {
        doc["expiry"] = serde_json::json!(e);
    }
    if let Some(ref a) = existing.amf_id {
        doc["amfId"] = serde_json::json!(a);
    }
    if let Some(ref a) = existing.amf_set_id {
        doc["amfSetId"] = serde_json::json!(a);
    }

    if let Err(e) = nextgcore_sbi::json_patch::apply_patch(&mut doc, &patch) {
        return problem_details(
            400,
            "Bad Request",
            &format!("JSON Patch failed: {e}"),
            Some("INVALID_MSG_FORMAT"),
        );
    }

    let updated = match subscription_from_json(subscription_id, &doc) {
        Ok(s) => s,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Patched subscription is invalid: {e}"),
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let mut created = updated.to_created_json();
    let authorized = collect_authorized_data_for(&updated.tai_list);
    if !authorized.is_empty() {
        created["authorizedNssaiAvailabilityData"] = serde_json::json!(authorized);
    }

    with_nssf_context(|context| context.subscription_update(updated));

    SbiResponse::with_status(200)
        .with_json_body(&created)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ---------------------------------------------------------------------------
// H-NSSF / NRF interaction
// ---------------------------------------------------------------------------

/// Build the H-NSSF `Nnssf_NSSelection` GET path for a home-routed query.
///
/// Extracted from [`send_hnssf_query`] so the emitted `roamingIndication` is
/// assertable without a network: the value on the wire is what TS 29.531
/// §6.1.6.3.3 constrains, and it was previously the non-normative `HOME_ROUTED`
/// with no test able to see it (#93).
fn build_hnssf_query_path(param: &nnssf_handler::NsSelectionParam) -> String {
    let mut query_parts = vec![format!(
        "nf-type={}",
        param.nf_type.as_deref().unwrap_or("AMF")
    )];
    if let Some(ref nf_id) = param.nf_id {
        query_parts.push(format!("nf-id={nf_id}"));
    }
    if let Some(ref snssai) = param.slice_info_for_pdu_session.snssai {
        // TS 29.531 §6.1.6.3.3: the normative token. This emitted the
        // non-normative `HOME_ROUTED`, which a strict H-NSSF would reject as
        // outside the RoamingIndication enumeration (#93).
        let mut si = serde_json::json!({
            "sNssai": {"sst": snssai.sst},
            "roamingIndication": ROAMING_HOME_ROUTED
        });
        if let Some(sd) = snssai.sd {
            si["sNssai"]["sd"] = serde_json::json!(format!("{:06x}", sd));
        }
        query_parts.push(format!("slice-info-request-for-pdu-session={si}"));
    }
    format!(
        "/nnssf-nsselection/v2/network-slice-information?{}",
        query_parts.join("&")
    )
}

/// Query H-NSSF for home network slice info (B24.2)
async fn send_hnssf_query(
    home_id: u64,
    param: &nnssf_handler::NsSelectionParam,
) -> Result<nnssf_handler::NsiInformation, String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    // Find NSSF instances for H-NSSF query
    let nssf_instances = sbi_ctx
        .find_nf_instances_by_service(nextgcore_sbi::types::SbiServiceType::NnssfNsselection)
        .await;

    let nssf_instance = nssf_instances
        .first()
        .ok_or_else(|| "No H-NSSF instance available for nnssf-nsselection service".to_string())?;

    let nssf_service = nssf_instance
        .find_service(nextgcore_sbi::types::SbiServiceType::NnssfNsselection)
        .ok_or("H-NSSF instance has no nnssf-nsselection service")?;

    let host = nssf_service
        .fqdn
        .as_deref()
        .or(nssf_instance.fqdn.as_deref())
        .or(nssf_service.ip_addresses.first().map(|s| s.as_str()))
        .or(nssf_instance.ipv4_addresses.first().map(|s| s.as_str()))
        .ok_or("No H-NSSF endpoint address available")?;
    let port = nssf_service.port;

    let client = sbi_ctx.get_client(host, port).await;

    let path = build_hnssf_query_path(param);

    log::debug!("Sending H-NSSF query: GET {path}");

    let response = client
        .get(&path)
        .await
        .map_err(|e| format!("H-NSSF request failed: {e}"))?;

    if response.status != 200 {
        return Err(format!("H-NSSF returned status {}", response.status));
    }

    let body = response.http.content.ok_or("Empty H-NSSF response body")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Invalid H-NSSF response JSON: {e}"))?;

    // Extract NSI information from response (spec attribute first, then the
    // legacy list form)
    let nsi_info = json
        .get("nsiInformation")
        .or_else(|| {
            json.get("nsiInformationList")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
        })
        .ok_or("No nsiInformation in H-NSSF response")?;

    let nrf_id = nsi_info
        .get("nrfId")
        .and_then(|v| v.as_str())
        .ok_or("No nrfId in H-NSSF response")?;
    let nsi_id = nsi_info
        .get("nsiId")
        .and_then(|v| v.as_str())
        .ok_or("No nsiId in H-NSSF response")?;

    // Store in home context
    let ctx = nssf_self();
    if let Ok(context) = ctx.read() {
        if let Some(mut home) = context.home_find_by_id(home_id) {
            home.set_nrf_info(nrf_id, nsi_id);
            context.home_update(&home);
        }
    }

    Ok(nnssf_handler::NsiInformation {
        nrf_id: nrf_id.to_string(),
        nsi_id: nsi_id.to_string(),
    })
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

/// Register NSSF with NRF (B24.3)
///
/// Returns the NF instance ID so callers can start a heartbeat worker.
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

    log::info!("Registering NSSF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;

    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "NSSF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{}-nnssf-nsselection", nf_instance_id),
            "serviceName": "nnssf-nsselection",
            "versions": [{"apiVersionInUri": "v2", "apiFullVersion": "2.2.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }, {
            "serviceInstanceId": format!("{}-nnssf-nssaiavailability", nf_instance_id),
            "serviceName": "nnssf-nssaiavailability",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.2.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }],
        "allowedNfTypes": ["AMF", "SCP", "NSSF"],
        "heartBeatTimer": 10
    });

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("NSSF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                &nf_instance_id,
                nextgcore_sbi::types::NfType::Nssf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];

            let mut svc = nextgcore_sbi::context::NfService::new(
                "nnssf-nsselection",
                nextgcore_sbi::types::SbiServiceType::NnssfNsselection,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);

            let mut svc2 = nextgcore_sbi::context::NfService::new(
                "nnssf-nssaiavailability",
                nextgcore_sbi::types::SbiServiceType::NnssfNssaiavailability,
            );
            svc2.port = sbi_port;
            svc2.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc2);

            sbi_ctx.set_self_instance(self_instance).await;

            Ok(nf_instance_id)
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

/// Discover NF services from NRF (B24.3)
async fn discover_nf_from_nrf(target_nf_type: &str, service_name: &str) -> Result<(), String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => return Ok(()),
    };

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;

    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let path = format!(
        "/nnrf-disc/v1/nf-instances?target-nf-type={target_nf_type}&requester-nf-type=NSSF&service-names={service_name}"
    );

    let response = client
        .get(&path)
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?;

    if response.status != 200 {
        return Err(format!("NRF discovery returned status {}", response.status));
    }

    let body = response
        .http
        .content
        .ok_or("Empty NRF discovery response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Invalid NRF discovery response: {e}"))?;

    // #235: the SearchResult's validityPeriod bounds how long these profiles may
    // be selected; without it a cached peer was chosen for the process lifetime.
    let validity = nextgcore_sbi::context::search_result_validity(&json);

    if let Some(nf_instances) = json.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let nf_id = nf_json
                .get("nfInstanceId")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let nf_type_str = nf_json.get("nfType").and_then(|v| v.as_str()).unwrap_or("");

            let nf_type = match nf_type_str {
                "NSSF" => nextgcore_sbi::types::NfType::Nssf,
                "NRF" => nextgcore_sbi::types::NfType::Nrf,
                "AMF" => nextgcore_sbi::types::NfType::Amf,
                _ => continue,
            };

            let mut instance = nextgcore_sbi::context::NfInstance::new(nf_id, nf_type);

            if let Some(fqdn) = nf_json.get("fqdn").and_then(|v| v.as_str()) {
                instance.fqdn = Some(fqdn.to_string());
            }
            if let Some(addrs) = nf_json.get("ipv4Addresses").and_then(|v| v.as_array()) {
                instance.ipv4_addresses = addrs
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }

            if let Some(services) = nf_json.get("nfServices").and_then(|v| v.as_array()) {
                for svc_json in services {
                    let svc_name = svc_json
                        .get("serviceName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if let Some(svc_type) =
                        nextgcore_sbi::types::SbiServiceType::from_name(svc_name)
                    {
                        let mut svc = nextgcore_sbi::context::NfService::new(svc_name, svc_type);
                        if let Some(endpoints) =
                            svc_json.get("ipEndPoints").and_then(|v| v.as_array())
                        {
                            if let Some(ep) = endpoints.first() {
                                if let Some(addr) = ep.get("ipv4Address").and_then(|v| v.as_str()) {
                                    svc.ip_addresses.push(addr.to_string());
                                }
                                if let Some(port) = ep.get("port").and_then(|v| v.as_u64()) {
                                    svc.port = port as u16;
                                }
                            }
                        }
                        instance.add_service(svc);
                    }
                }
            }

            sbi_ctx
                .add_nf_instance_with_validity(instance, validity)
                .await;
            log::info!(
                "Discovered {nf_type_str} instance: {nf_id} (valid for {}s)",
                validity.as_secs()
            );
        }
    }

    Ok(())
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
async fn run_event_loop_async(
    nssf_sm: &mut NssfSmContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();

    // #94: sweep expired NSSAI-availability subscriptions on the EXISTING run-loop
    // tick rather than arming one timer per subscription. The loop already exists,
    // a per-subscription timer would need its own cancellation story on
    // delete/patch, and a sweep is correct after a restart (where no timer
    // survived) whereas re-arming from the restored records would have to be
    // reconstructed. `subscriptions_matching` filters on expiry independently, so
    // an expired subscription stops being SERVED at once and this only bounds how
    // long it stays STORED.
    let mut last_sweep = tokio::time::Instant::now();
    const SUBSCRIPTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Compute optimal sleep duration based on pending timers
        let poll_interval = nextgcore_core::async_timer::compute_poll_interval(
            timer_mgr.inner(),
            Duration::from_millis(100),
        );
        tokio::time::sleep(poll_interval).await;

        if last_sweep.elapsed() >= SUBSCRIPTION_SWEEP_INTERVAL {
            last_sweep = tokio::time::Instant::now();
            let now = nextgcore_sbi::datetime::now_epoch_secs();
            let removed =
                with_nssf_context(|c| c.sweep_expired_subscriptions(now)).unwrap_or_default();
            if !removed.is_empty() {
                log::info!("expired subscription sweep removed {}", removed.len());
            }
        }

        // Process timer expirations and dispatch to state machine
        let expired = timer_mgr.process_expired();
        for entry in &expired {
            log::debug!(
                "NSSF timer expired: id={} type={:?} data={:?}",
                entry.id,
                entry.timer_type,
                entry.data
            );

            // Create timer event and dispatch to state machine
            let mut event = NssfEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            nssf_sm.dispatch(&mut event);
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

#[cfg(test)]
mod tests {
    /// Process-wide lock for tests that re-initialise the process-global NSSF
    /// context.
    ///
    /// `nssf_context_init` WIPES that context, and 27 tests in this file call it.
    /// Cargo runs them concurrently in one process, so one test's init landed
    /// between another's init and its assertion — the second then computed its
    /// answer from an empty context. That is how CI saw
    /// `test_nsselection_ue_cu_no_requested_nssai_no_allowed_list` fail with
    /// "must include configuredNssai derived from subscribedNssai" while the same
    /// run's retry failed two DIFFERENT tests instead: different symptoms, one
    /// cause. Before this, nssfd had no test guard of any kind.
    ///
    /// Poison-tolerant, so one failing test does not turn its siblings into
    /// misleading second failures.
    static NSSF_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    use super::*;
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use serde_json::json;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-nssfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nssf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_nf, 512);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-nssfd",
            "-c",
            "/custom/nssf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-nf",
            "1024",
        ]);
        assert_eq!(args.config, "/custom/nssf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_nf, 1024);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-nssfd",
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
    fn test_percent_decode_and_query_parse() {
        // #65: the decoder itself is now nextgcore_sbi::uri_encode, tested there.
        // What is still nssfd's own behaviour is this URI-with-query parse.
        let params = parse_query_params("/x/y?nf-type=AMF&nf-id=abc&j=%7B%22sst%22%3A1%7D&empty");
        assert_eq!(params.get("nf-type").map(String::as_str), Some("AMF"));
        assert_eq!(params.get("j").map(String::as_str), Some(r#"{"sst":1}"#));
        assert_eq!(params.get("empty").map(String::as_str), Some(""));
    }

    #[test]
    fn test_split_uri() {
        assert_eq!(
            split_uri("http://10.0.0.1:8080/notify/cb"),
            Some(("10.0.0.1".to_string(), 8080, "/notify/cb".to_string()))
        );
        assert_eq!(
            split_uri("https://amf.example/cb"),
            Some(("amf.example".to_string(), 443, "/cb".to_string()))
        );
    }

    // -----------------------------------------------------------------
    // HTTP-level tests (ephemeral ports, bounded timeouts)
    // -----------------------------------------------------------------

    /// Percent-encode a URI query component (everything but unreserved chars)
    fn enc(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 3);
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    /// Reserve a loopback port for a test server.
    ///
    /// Delegates to the shared helper: 21 crates each had a private
    /// probe-and-drop copy of this, which is TOCTOU and flaked under parallel
    /// `cargo test`. One implementation means one place to harden.
    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

    /// Serializes tests that mutate the *global* NSSF availability/restriction
    /// state (the context is a process-wide singleton). Without this, the
    /// PLMN-supported restriction one test installs could leak into another
    /// running concurrently and flip an expected 200 into a 403 (or vice
    /// versa). An async-aware `tokio::sync::Mutex` is used so the guard may be
    /// held across the handler `.await` points (clippy `await_holding_lock`),
    /// and it does not poison on a failing test.
    async fn availability_state_guard() -> tokio::sync::MutexGuard<'static, ()> {
        static GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        GUARD.lock().await
    }

    async fn start_nssf_server() -> (SbiServer, u16) {
        nssf_context_init(512);
        let port = free_port();
        let server = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        server
            .start(nssf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
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
            "iss": "NRF", "sub": "amf-1", "aud": aud,
            "scope": "nnssf-nsselection", "exp": exp, "iat": 0
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

    /// Start an NSSF SBI server with OAuth2 enforcement keyed to a static JWKS
    /// and the NSSF audience.
    async fn start_nssf_server_oauth2(jwks: serde_json::Value) -> (SbiServer, u16) {
        nssf_context_init(512);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Nssf);
        let server = SbiServer::new(cfg);
        server
            .start(nssf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_yaml_oauth2_require_parses() {
        let yaml = "nssf:\n  sbi:\n    oauth2:\n      require: true\n";
        let parsed: NssfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nssf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(require, "oauth2.require should parse to true");
    }

    #[test]
    fn test_yaml_oauth2_absent_defaults_off() {
        // Default config (no oauth2 block) leaves enforcement off, preserving
        // the dev/E2E path.
        let yaml = "nssf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: 7777\n";
        let parsed: NssfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nssf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(!require, "absent oauth2 block must default to off");
    }

    #[tokio::test]
    async fn test_oauth2_missing_token_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nssf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // No Authorization header -> 401 (missing Bearer token).
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=x"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_valid_token_accepted() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nssf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Valid token whose aud includes "NSSF" passes enforcement; the
        // request reaches the handler (400 for the missing mandatory params,
        // NOT 401/403 — i.e. authorization succeeded).
        let token = build_es256_token(&sk, "nrf-es256", "NSSF");
        let req = SbiRequest::get("/nnssf-nsselection/v2/network-slice-information?nf-type=AMF")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_ne!(resp.status, 401, "valid token must not be 401");
        assert_ne!(resp.status, 403, "valid token must not be 403");
        assert_eq!(resp.status, 400, "request reached handler (missing nf-id)");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_wrong_audience_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nssf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Token addressed to a different NF (aud="UDM") is rejected (401).
        let token = build_es256_token(&sk, "nrf-es256", "UDM");
        let req =
            SbiRequest::get("/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=x")
                .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_nsselection_registration_scenario() {
        // Serialise against the tests that set the process-global
        // PLMN-supported-S-NSSAI restriction: with a sibling's `[sst 1]`
        // restriction installed concurrently, this registration filters every
        // requested slice out and the response carries no body, which surfaces as
        // an unwrap panic here rather than as anything pointing at the sibling.
        // Taking the guard those tests ALREADY take is the fix; a private lock
        // would not order them.
        let _state_guard = availability_state_guard().await;
        with_nssf_context(|c| c.set_plmn_supported_snssais(None));
        let (server, port) = start_nssf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Subscribed: sst 41 (default) + sst 42; requested: sst 41 + sst 47
        // (unsubscribed). Expect allowed=[41], rejectedInPlmn=[47],
        // configured=[41,42].
        let sir = json!({
            "subscribedNssai": [
                {"subscribedSnssai": {"sst": 41}, "defaultIndication": true},
                {"subscribedSnssai": {"sst": 42}}
            ],
            "requestedNssai": [{"sst": 41}, {"sst": 47}]
        })
        .to_string();
        let path = format!(
            "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=amf-reg-1&slice-info-request-for-registration={}",
            enc(&sir)
        );
        let resp = tokio::time::timeout(Duration::from_secs(5), client.get(&path))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let allowed = &body["allowedNssaiList"][0]["allowedSnssaiList"];
        assert_eq!(allowed.as_array().unwrap().len(), 1);
        assert_eq!(allowed[0]["allowedSnssai"]["sst"], 41);
        assert_eq!(body["allowedNssaiList"][0]["accessType"], "3GPP_ACCESS");
        let rejected = body["rejectedNssaiInPlmn"].as_array().unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["sst"], 47);
        let configured = body["configuredNssai"].as_array().unwrap();
        assert_eq!(configured.len(), 2);

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_nsselection_missing_mandatory_params() {
        let (server, port) = start_nssf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Missing nf-id -> 400 ProblemDetails
        let resp = client
            .get("/nnssf-nsselection/v2/network-slice-information?nf-type=AMF")
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        let body = resp.http.content.as_deref().unwrap();
        assert!(body.contains("nf-id"));
        assert!(body.contains("MANDATORY_QUERY_PARAM_MISSING"));

        // No slice-info-request-* at all -> 400
        let resp = client
            .get("/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=x")
            .await
            .expect("response");
        assert_eq!(resp.status, 400);

        // PDU-session info without mandatory roamingIndication -> 400 (no panic)
        let sip = enc(&json!({"sNssai": {"sst": 1}}).to_string());
        let resp = client
            .get(&format!(
                "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=x&slice-info-request-for-pdu-session={sip}"
            ))
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("roamingIndication"));

        // Wrong API version -> 404
        let resp = client
            .get("/nnssf-nsselection/v1/network-slice-information?nf-type=AMF&nf-id=x")
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_availability_lifecycle_with_notifications() {
        // Serialize against the nssfd-01 restriction tests and clear any
        // restriction so this lifecycle PUT/PATCH path sees the default
        // allow-all (matched-sim back-compat).
        let _state_guard = availability_state_guard().await;
        // #94: this drives a REAL HTTP client against a real SbiServer with no
        // OAuth2 configured, so there is no attested caller identity for the
        // server to bind to — which is precisely the deployment the documented
        // escape hatch describes. Declared explicitly rather than left implicit,
        // so the test states which posture it is asserting.
        let _posture = with_authz_posture(false);
        let (server, port) = start_nssf_server().await;
        with_nssf_context(|c| c.set_plmn_supported_snssais(None));
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Notification receiver on its own ephemeral port
        let recv_port = free_port();
        let receiver = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            recv_port,
        ))));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        receiver
            .start(move |req: SbiRequest| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(req.http.content.unwrap_or_default());
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("receiver start");

        let tai = json!({"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "0000c8"});

        // 1. Subscription create: missing mandatory `event` -> 400
        let resp = client
            .post_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions",
                &json!({
                    "nfNssaiAvailabilityUri": format!("http://127.0.0.1:{recv_port}/cb"),
                    "taiList": [tai]
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp.http.content.as_deref().unwrap().contains("event"));

        // 2. Valid subscription create -> 201 + Location + subscriptionId
        let resp = client
            .post_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions",
                &json!({
                    "nfNssaiAvailabilityUri": format!("http://127.0.0.1:{recv_port}/cb"),
                    "taiList": [tai],
                    "event": "SNSSAI_STATUS_CHANGE_REPORT"
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 201);
        let location = resp
            .http
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert!(!location.is_empty(), "Location header missing");
        assert!(location.contains("/nssai-availability/subscriptions/"));
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let sub_id = created["subscriptionId"].as_str().unwrap().to_string();

        // 3. PUT availability missing mandatory supportedNssaiAvailabilityData -> 400
        let resp = client
            .put_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1",
                &json!({"supportedFeatures": "1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("supportedNssaiAvailabilityData"));

        // 4. Valid PUT -> 200 AuthorizedNssaiAvailabilityInfo + notification
        let resp = client
            .put_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1",
                &json!({
                    "supportedNssaiAvailabilityData": [{
                        "tai": tai,
                        "supportedSnssaiList": [{"sst": 51}, {"sst": 52, "sd": "0a0b0c"}]
                    }]
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(body["authorizedNssaiAvailabilityData"].is_array());

        let notif = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("notification within timeout")
            .expect("channel open");
        let notif: serde_json::Value = serde_json::from_str(&notif).unwrap();
        assert_eq!(notif["subscriptionId"], sub_id.as_str());
        assert!(!notif["authorizedNssaiAvailabilityData"]
            .as_array()
            .unwrap()
            .is_empty());

        // 5. PATCH with RFC 6902 document -> 200 + second notification
        // (nssfd-05: must use application/json-patch+json content type)
        let patch_body = json!([{
            "op": "add",
            "path": "/supportedNssaiAvailabilityData/0/supportedSnssaiList/-",
            "value": {"sst": 53}
        }])
        .to_string();
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.send_request(
                SbiRequest::patch("/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1")
                    .with_body(patch_body, "application/json-patch+json"),
            ),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let snssais = body["authorizedNssaiAvailabilityData"][0]["supportedSnssaiList"]
            .as_array()
            .unwrap();
        assert_eq!(snssais.len(), 3);

        let notif2 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("second notification within timeout")
            .expect("channel open");
        assert!(notif2.contains(&sub_id));

        // 6. Bad PATCH (replace of non-existent member) -> 400
        // (nssfd-05: use application/json-patch+json to reach the 400 path)
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.send_request(
                SbiRequest::patch("/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1")
                    .with_body(
                        json!([{"op": "replace", "path": "/nonexistent", "value": 1}]).to_string(),
                        "application/json-patch+json",
                    ),
            ),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 400);

        // 7. PATCH on unknown nfId -> 404
        // (nssfd-05: use application/json-patch+json to reach the 404 path)
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.send_request(
                SbiRequest::patch("/nnssf-nssaiavailability/v1/nssai-availability/amf-unknown")
                    .with_body(
                        json!([{"op": "remove", "path": "/supportedNssaiAvailabilityData/0"}])
                            .to_string(),
                        "application/json-patch+json",
                    ),
            ),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 404);

        // 8. Subscription PATCH (replace expiry) -> 200
        let resp = client
            .patch_json(
                &format!("/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/{sub_id}"),
                &json!([{"op": "add", "path": "/expiry", "value": "2030-01-01T00:00:00Z"}]),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        // #94: the NSSF now OWNS the expiry (TS 29.531 Table 6.2.6.2.9-1). This
        // assertion used to be `== "2030-01-01T00:00:00Z"`, i.e. it pinned the
        // echo-the-consumer behaviour that made subscriptions unbounded. A
        // consumer-requested instant beyond the NSSF's own validity bound must NOT
        // win, so the returned expiry is the NSSF's, not the requested 2030.
        let expiry = body["expiry"].as_str().expect("an expiry must be assigned");
        assert_ne!(
            expiry, "2030-01-01T00:00:00Z",
            "a consumer must not be able to extend its subscription past the NSSF bound"
        );
        let deadline = nextgcore_sbi::datetime::rfc3339_to_epoch(expiry)
            .expect("the NSSF-assigned expiry must be parseable RFC 3339 UTC");
        let now = nextgcore_sbi::datetime::now_epoch_secs();
        assert!(deadline > now, "the assigned expiry must be in the future");
        assert!(
            deadline <= now + timer::defaults::SUBSCRIPTION_VALIDITY.as_secs() + 5,
            "the assigned expiry must be bounded by SUBSCRIPTION_VALIDITY"
        );

        // 9. DELETE availability -> 204, second DELETE -> 404
        let resp = client
            .delete("/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1")
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        // Deletion also notifies subscribers (remaining data for the TA)
        let _ = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("delete notification within timeout");
        let resp = client
            .delete("/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1")
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        // 10. DELETE subscription -> 204, second DELETE -> 404
        let resp = client
            .delete(&format!(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/{sub_id}"
            ))
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let resp = client
            .delete(&format!(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/{sub_id}"
            ))
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        server.stop().await.expect("stop");
        receiver.stop().await.expect("stop receiver");
    }

    // -----------------------------------------------------------------
    // nssfd-01: NSSAIAvailability PUT/PATCH PLMN-support + authorization
    // (TS 29.531 §6.2.3.2.3.1, TS 33.521). Handlers are driven directly so
    // the 403-before-store/notify ordering is observable.
    // -----------------------------------------------------------------

    /// (a) With a configured restricted set, PUT an S-NSSAI outside it ->
    /// 403 SNSSAI_NOT_SUPPORTED; nothing stored, no notification spawned.
    #[tokio::test]
    async fn test_availability_put_unsupported_snssai_403() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        // Restrict the PLMN to sst=1 only; the PUT reports sst=2 (outside it).
        with_nssf_context(|c| {
            c.set_plmn_supported_snssais(Some(vec![context::SNssai::new(1, None)]))
        });

        let nf_id = "amf-nssfd01-unsupported";
        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));

        let body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 2, "sd": "0a0b0c"}]
            }]
        });
        let req = authenticated_availability_request("PUT", nf_id, Some(&body));
        let resp = handle_nssai_availability_update(nf_id, &req).await;

        assert_eq!(resp.status, 403);
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["status"], 403);
        assert_eq!(pd["cause"], "SNSSAI_NOT_SUPPORTED");
        // Nothing stored. The 403 returns before set_nssai_availability + the
        // spawn_availability_notifications call, so no notification is spawned.
        assert!(with_nssf_context(|c| c.get_nssai_availability(nf_id))
            .flatten()
            .is_none());

        with_nssf_context(|c| c.set_plmn_supported_snssais(None));
    }

    /// (b) PUT with an empty NF Id -> 403 NOT_AUTHORIZED.
    #[tokio::test]
    async fn test_availability_put_empty_nf_id_403_not_authorized() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.set_plmn_supported_snssais(None)); // no restriction

        let body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let req = SbiRequest::put("/nnssf-nssaiavailability/v1/nssai-availability/")
            .with_json_body(&body)
            .unwrap();
        // Empty NF Id is unauthorized regardless of slice contents.
        let resp = handle_nssai_availability_update("", &req).await;

        assert_eq!(resp.status, 403);
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["status"], 403);
        assert_eq!(pd["cause"], "NOT_AUTHORIZED");
        assert!(with_nssf_context(|c| c.get_nssai_availability(""))
            .flatten()
            .is_none());
    }

    /// (c) PUT with all-supported S-NSSAIs (here: no restriction configured)
    /// -> 200 and stored.
    #[tokio::test]
    async fn test_availability_put_all_supported_200_stored() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.set_plmn_supported_snssais(None)); // default allow-all

        let nf_id = "amf-nssfd01-ok";
        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));

        let body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let req = authenticated_availability_request("PUT", nf_id, Some(&body));
        let resp = handle_nssai_availability_update(nf_id, &req).await;

        assert_eq!(resp.status, 200);
        let stored = with_nssf_context(|c| c.get_nssai_availability(nf_id)).flatten();
        assert!(stored.is_some(), "supported PUT must be stored");
        assert_eq!(
            stored.unwrap().supported_snssai_list,
            vec![context::SNssai::new(1, None)]
        );

        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));
    }

    /// (d) PATCH producing an unsupported S-NSSAI -> 403; original doc
    /// unchanged.
    #[tokio::test]
    async fn test_availability_patch_unsupported_snssai_403_original_unchanged() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        // Restrict to sst=1: the initial PUT (sst=1) is accepted; the PATCH
        // that appends sst=2 must be rejected and leave the stored doc intact.
        with_nssf_context(|c| {
            c.set_plmn_supported_snssais(Some(vec![context::SNssai::new(1, None)]))
        });

        let nf_id = "amf-nssfd01-patch";
        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));

        let put_body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let put_req = authenticated_availability_request("PUT", nf_id, Some(&put_body));
        assert_eq!(
            handle_nssai_availability_update(nf_id, &put_req)
                .await
                .status,
            200
        );

        // PATCH appends an unsupported S-NSSAI (sst=2) -> 403, doc unchanged.
        let patch = json!([{
            "op": "add",
            "path": "/supportedNssaiAvailabilityData/0/supportedSnssaiList/-",
            "value": {"sst": 2}
        }]);
        let mut patch_req = SbiRequest::patch(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{nf_id}"
        ))
        .with_body(patch.to_string(), "application/json-patch+json");
        // #94: the attested caller must own the document it patches.
        patch_req.oauth2_subject = Some(nf_id.to_string());
        let resp = handle_nssai_availability_patch(nf_id, &patch_req).await;

        assert_eq!(resp.status, 403);
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["status"], 403);
        assert_eq!(pd["cause"], "SNSSAI_NOT_SUPPORTED");

        // Original document unchanged: still exactly [sst=1].
        let stored = with_nssf_context(|c| c.get_nssai_availability(nf_id))
            .flatten()
            .expect("original doc must remain stored after a rejected PATCH");
        assert_eq!(
            stored.supported_snssai_list,
            vec![context::SNssai::new(1, None)]
        );
        let arr = stored.doc["supportedNssaiAvailabilityData"][0]["supportedSnssaiList"]
            .as_array()
            .unwrap();
        assert_eq!(
            arr.len(),
            1,
            "rejected PATCH must not mutate the stored doc"
        );

        with_nssf_context(|c| c.set_plmn_supported_snssais(None));
        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));
    }

    // -----------------------------------------------------------------
    // nssfd-02: AuthorizedNssaiAvailabilityData restrictedSnssaiList
    // (TS 29.531 §5.3.2.2 / §6.2.6.2.4)
    // -----------------------------------------------------------------

    /// With a configured per-PLMN restriction, authorized_availability_response
    /// includes restrictedSnssaiList containing the expected RestrictedSnssai.
    #[tokio::test]
    async fn test_availability_authorized_response_restricted_snssai_list() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| {
            c.set_plmn_snssai_restrictions(
                &context::PlmnId::new("001", "01"),
                vec![context::SNssai::new(99, None)],
            )
        });

        let doc = serde_json::json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let resp = authorized_availability_response(&doc);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();

        let entries = body["authorizedNssaiAvailabilityData"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        // restrictedSnssaiList must be present with homePlmnId 001/01 + sst=99.
        let restricted = entries[0]["restrictedSnssaiList"].as_array().unwrap();
        assert_eq!(
            restricted.len(),
            1,
            "one home-PLMN restriction entry expected"
        );
        assert_eq!(restricted[0]["homePlmnId"]["mcc"], "001");
        assert_eq!(restricted[0]["homePlmnId"]["mnc"], "01");
        // #94: `sNssaiList` is the key TS 29.531 RestrictedSnssai requires. This
        // assertion used to read `sNssais`, i.e. it pinned the wire-conformance
        // bug as the requirement; inverted rather than deleted so review can see
        // the flip.
        assert_eq!(restricted[0]["sNssaiList"][0]["sst"], 99);
        assert!(
            restricted[0].get("sNssais").is_none(),
            "the non-conformant `sNssais` key must be gone entirely"
        );
        // supportedSnssaiList must still equal the input.
        assert_eq!(entries[0]["supportedSnssaiList"][0]["sst"], 1);

        with_nssf_context(|c| c.clear_plmn_snssai_restrictions());
    }

    /// Without restriction config, restrictedSnssaiList is absent and
    /// supportedSnssaiList equals the input (back-compat).
    #[tokio::test]
    async fn test_availability_authorized_response_no_restriction_no_restricted_list() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.clear_plmn_snssai_restrictions());

        let doc = serde_json::json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}, {"sst": 2}]
            }]
        });
        let resp = authorized_availability_response(&doc);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let entries = body["authorizedNssaiAvailabilityData"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].get("restrictedSnssaiList").is_none(),
            "restrictedSnssaiList must be absent when no restriction configured"
        );
        assert_eq!(
            entries[0]["supportedSnssaiList"].as_array().unwrap().len(),
            2
        );
    }

    // -----------------------------------------------------------------
    // nssfd-03: 204 No Content when authorized availability is empty
    // (TS 29.531 §6.2.3.2.3.1 Table 6.2.3.2.3.1-2)
    // -----------------------------------------------------------------

    /// authorized_availability_response returns 204 when no entries remain.
    #[test]
    fn test_availability_authorized_response_empty_entries_is_204() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        nssf_context_init(512);
        let doc = serde_json::json!({"supportedNssaiAvailabilityData": []});
        let resp = authorized_availability_response(&doc);
        assert_eq!(
            resp.status, 204,
            "empty authorized data must yield 204 No Content"
        );
        let body = resp.http.content.as_deref().unwrap_or("");
        assert!(body.is_empty(), "204 must carry no body");
    }

    /// authorized_availability_response returns 200 when entries are present.
    #[tokio::test]
    async fn test_availability_authorized_response_nonempty_is_200() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.clear_plmn_snssai_restrictions());
        let doc = serde_json::json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let resp = authorized_availability_response(&doc);
        assert_eq!(resp.status, 200);
        assert!(resp.http.content.is_some(), "200 must carry a body");
    }

    // -----------------------------------------------------------------
    // nssfd-04: PDU-session NSSelection narrows allowedNssaiList to the
    // requested S-NSSAI (TS 29.531 §5.2.2.2.3 step 2a)
    // -----------------------------------------------------------------

    /// PDU-session request for sNssai A while NSIs {A, B, C} are configured
    /// → response allowedSnssaiList contains only A.
    #[tokio::test]
    async fn test_pdu_nsselection_allowed_narrowed_to_requested_snssai() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        // Configure three NSIs so the old all-NSIs path would have returned 3.
        with_nssf_context(|c| {
            c.nsi_add("http://nrf.example.com", 1, None);
            c.nsi_add("http://nrf.example.com", 2, None);
            c.nsi_add("http://nrf.example.com", 3, None);
        });

        // Request sst=1 → only sst=1 in allowedSnssaiList.
        let si = serde_json::json!({"sNssai": {"sst": 1}, "roamingIndication": "NON_ROAMING"});
        let resp = handle_ns_selection_pdu_session("amf-1", "AMF", &si, None, None, None).await;
        assert_eq!(resp.status, 200, "PDU session selection must succeed");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let allowed = body["allowedNssaiList"][0]["allowedSnssaiList"]
            .as_array()
            .unwrap();
        assert_eq!(
            allowed.len(),
            1,
            "allowedSnssaiList must be narrowed to the requested sNssai, not all NSIs"
        );
        assert_eq!(allowed[0]["allowedSnssai"]["sst"], 1);

        // Request sst=2 → only sst=2 returned (not sst=1 or sst=3).
        let si2 = serde_json::json!({"sNssai": {"sst": 2}, "roamingIndication": "NON_ROAMING"});
        let resp2 = handle_ns_selection_pdu_session("amf-2", "AMF", &si2, None, None, None).await;
        assert_eq!(resp2.status, 200);
        let body2: serde_json::Value =
            serde_json::from_str(resp2.http.content.as_deref().unwrap()).unwrap();
        let allowed2 = body2["allowedNssaiList"][0]["allowedSnssaiList"]
            .as_array()
            .unwrap();
        assert_eq!(
            allowed2.len(),
            1,
            "allowedSnssaiList must be narrowed to sst=2"
        );
        assert_eq!(allowed2[0]["allowedSnssai"]["sst"], 2);

        // Requesting an S-NSSAI with no NSI → existing 403 SNSSAI_NOT_SUPPORTED.
        let si3 = serde_json::json!({"sNssai": {"sst": 99}, "roamingIndication": "NON_ROAMING"});
        let resp3 = handle_ns_selection_pdu_session("amf-3", "AMF", &si3, None, None, None).await;
        assert_eq!(resp3.status, 403, "unsupported sNssai must yield 403");

        with_nssf_context(|c| c.nsi_remove_all());
    }

    // -----------------------------------------------------------------
    // nssfd-05: PATCH Content-Type enforcement (415 Unsupported Media Type)
    // (TS 29.531 §6.2 / RFC 6902)
    // -----------------------------------------------------------------

    /// PATCH with wrong Content-Type → 415; with correct Content-Type the
    /// request proceeds past the media-type check (404 here because no doc
    /// is stored for the test nfId).
    #[tokio::test]
    async fn test_availability_patch_wrong_content_type_415() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        nssf_context_init(512);

        let wrong_ct_req =
            SbiRequest::patch("/nnssf-nssaiavailability/v1/nssai-availability/amf-ct-test")
                .with_body(
                    serde_json::json!([{"op": "add", "path": "/x", "value": 1}]).to_string(),
                    "application/json",
                );
        let resp = handle_nssai_availability_patch("amf-ct-test", &wrong_ct_req).await;
        assert_eq!(resp.status, 415, "wrong Content-Type must yield 415");
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["status"], 415);

        // Correct content type → proceeds past 415 check; 404 (no stored doc).
        let correct_ct_req =
            SbiRequest::patch("/nnssf-nssaiavailability/v1/nssai-availability/amf-ct-test")
                .with_body(
                    serde_json::json!([{"op": "add", "path": "/x", "value": 1}]).to_string(),
                    "application/json-patch+json",
                );
        let resp = handle_nssai_availability_patch("amf-ct-test", &correct_ct_req).await;
        assert_ne!(resp.status, 415, "correct Content-Type must not return 415");
        assert_eq!(resp.status, 404, "no stored doc → 404");

        // Missing Content-Type → also 415.
        let no_ct_req =
            SbiRequest::patch("/nnssf-nssaiavailability/v1/nssai-availability/amf-ct-test");
        let resp = handle_nssai_availability_patch("amf-ct-test", &no_ct_req).await;
        assert_eq!(resp.status, 415, "missing Content-Type must yield 415");
    }

    // -----------------------------------------------------------------
    // nssfd-06: UE-Configuration-Update scenario branch
    // (TS 29.531 §5.2.2.2.4)
    // -----------------------------------------------------------------

    /// UE-CU without requestedNssai → configuredNssai present, no
    /// allowedNssaiList (TS 29.531 §5.2.2.2.4).
    #[test]
    fn test_nsselection_ue_cu_no_requested_nssai_no_allowed_list() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        nssf_context_init(512);
        let info_json = serde_json::json!({
            "subscribedNssai": [
                {"subscribedSnssai": {"sst": 1}, "defaultIndication": true}
            ]
            // requestedNssai deliberately absent
        });
        let resp = handle_ns_selection_ue_cu("nf-ue-cu-1", &info_json, None);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            body.get("allowedNssaiList").is_none(),
            "UE-CU without requestedNssai must NOT include allowedNssaiList"
        );
        assert!(
            body.get("configuredNssai").is_some(),
            "UE-CU must include configuredNssai derived from subscribedNssai"
        );
    }

    /// UE-CU with requestedNssai → full response including allowedNssaiList
    /// (same as registration scenario).
    #[test]
    fn test_nsselection_ue_cu_with_requested_nssai_includes_allowed_list() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        nssf_context_init(512);
        let info_json = serde_json::json!({
            "subscribedNssai": [
                {"subscribedSnssai": {"sst": 1}, "defaultIndication": true}
            ],
            "requestedNssai": [{"sst": 1}]
        });
        let resp = handle_ns_selection_ue_cu("nf-ue-cu-2", &info_json, None);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            body.get("allowedNssaiList").is_some(),
            "UE-CU with requestedNssai must include allowedNssaiList"
        );
    }

    // -----------------------------------------------------------------
    // nssfd-07: Registration success populates targetAmfSet when configured
    // (TS 29.531 §5.2.2.2.2 step 2a)
    // -----------------------------------------------------------------

    /// With a configured target AMF set, a successful registration response
    /// includes targetAmfSet even when no candidateAmfList is produced.
    #[tokio::test]
    async fn test_registration_success_includes_target_amf_set_when_configured() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.set_target_amf_set("001-01-01-001"));

        let info_json = serde_json::json!({
            "subscribedNssai": [
                {"subscribedSnssai": {"sst": 1}, "defaultIndication": true}
            ],
            "requestedNssai": [{"sst": 1}]
        });
        let resp = handle_ns_selection_registration("nf-reg-7a", &info_json, None);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            body.get("targetAmfSet").is_some(),
            "targetAmfSet must be present when configured (TS 29.531 §5.2.2.2.2)"
        );
        assert_eq!(
            body["targetAmfSet"], "001-01-01-001",
            "targetAmfSet must match the configured value"
        );

        with_nssf_context(|c| c.clear_target_amf_set());
    }

    /// Without configured target AMF set and no TAI (no fallback), targetAmfSet
    /// is absent from the registration response.
    #[tokio::test]
    async fn test_registration_success_no_target_amf_set_when_not_configured() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.clear_target_amf_set());

        let info_json = serde_json::json!({
            "subscribedNssai": [
                {"subscribedSnssai": {"sst": 1}, "defaultIndication": true}
            ],
            "requestedNssai": [{"sst": 1}]
        });
        // No TAI → no TAI-derived fallback; no config → no targetAmfSet.
        let resp = handle_ns_selection_registration("nf-reg-7b", &info_json, None);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            body.get("targetAmfSet").is_none(),
            "targetAmfSet must be absent when not configured and no TAI provided"
        );
    }

    // ── #93: NSI population, roaming enum, unrouted scenarios, response IEs ──

    /// The `nsi` block the shipped `nssf.yaml` already carries deserialises and
    /// installs NSIs through the PRODUCTION loader.
    ///
    /// Before #93 `SbiClientYaml` declared only `nrf`, so this block was parsed
    /// into nothing: `nsi_add` had no production caller at all and the NSI table
    /// was populated only from `#[cfg(test)]` code. Asserted against the real
    /// YAML shape rather than a hand-built struct, so a schema drift breaks it.
    #[test]
    fn shipped_nsi_config_block_is_deserialised_and_installed() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The global NSSF context defaults to max_num_of_nf = 0, so `nsi_add`
        // refuses EVERY insert until `init` runs. Without this the assertions
        // below pass for the wrong reason -- the revert-verify pass caught
        // exactly that: a deliberately-broken loader still "installed 0".
        // Idempotent, so it is safe under the shared process-global context.
        context::nssf_context_init(64);

        // Exactly the shape docker/rust/configs/5gc/nssf.yaml ships.
        let yaml = r#"
nssf:
  sbi:
    client:
      nrf:
        - uri: http://172.23.0.10:7777
      nsi:
        - uri: http://172.23.0.10:7777
          s_nssai:
            sst: 1
        - uri: http://172.23.0.11:7777
          s_nssai:
            sst: 2
            sd: "010203"
          nsi_id: operator-assigned-nsi-2
"#;
        let doc: NssfYaml = serde_yaml::from_str(yaml).expect("shipped nssf.yaml shape parses");
        let nsis = doc
            .nssf
            .and_then(|n| n.sbi)
            .and_then(|s| s.client)
            .and_then(|c| c.nsi)
            .expect("the nsi block must deserialise (it was silently dropped before #93)");
        assert_eq!(nsis.len(), 2);

        let installed = load_configured_nsis(&nsis);
        assert_eq!(installed, 2, "both configured NSIs must be installed");

        // Discoverable by the SAME lookup the PDU-session handler uses.
        let one = with_nssf_context(|c| c.nsi_find_by_s_nssai(&context::SNssai::new(1, None)))
            .flatten()
            .expect("sst=1 NSI must be findable");
        assert_eq!(one.nrf_id, "http://172.23.0.10:7777");
        let two =
            with_nssf_context(|c| c.nsi_find_by_s_nssai(&context::SNssai::new(2, Some(0x010203))))
                .flatten()
                .expect("sst=2/sd=010203 NSI must be findable");
        assert_eq!(two.nrf_id, "http://172.23.0.11:7777");
        // An operator-assigned nsiId is honoured rather than replaced by a UUID.
        assert_eq!(two.nsi_id, "operator-assigned-nsi-2");
        // ...and one without an nsi_id still gets a non-empty opaque identifier.
        assert!(!one.nsi_id.is_empty());
    }

    /// An `nsi` entry with no `s_nssai` is skipped, not defaulted to SST 0.
    #[test]
    fn nsi_entry_without_snssai_is_skipped_rather_than_defaulted() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The global NSSF context defaults to max_num_of_nf = 0, so `nsi_add`
        // refuses EVERY insert until `init` runs. Without this the assertions
        // below pass for the wrong reason -- the revert-verify pass caught
        // exactly that: a deliberately-broken loader still "installed 0".
        // Idempotent, so it is safe under the shared process-global context.
        context::nssf_context_init(64);

        let yaml = r#"
nssf:
  sbi:
    client:
      nsi:
        - uri: http://nrf-no-slice:7777
"#;
        let doc: NssfYaml = serde_yaml::from_str(yaml).expect("parses");
        let nsis = doc
            .nssf
            .and_then(|n| n.sbi)
            .and_then(|s| s.client)
            .and_then(|c| c.nsi)
            .expect("nsi block");
        assert_eq!(
            load_configured_nsis(&nsis),
            0,
            "an NSI with no slice is not installed"
        );
        // Critically: it did NOT land under SST 0, which is what defaulting would do.
        assert!(
            with_nssf_context(|c| c.nsi_find_by_s_nssai(&context::SNssai::new(0, None)))
                .flatten()
                .is_none(),
            "a slice-less NSI must not be installed under a guessed SST"
        );
    }

    /// A PDU-session request for a CONFIGURED S-NSSAI returns 200 with
    /// nsiInformation, not the 403 #93 reports.
    ///
    /// The NSI is installed through `load_configured_nsis` — the production
    /// config path — rather than through `nsi_add` directly, which is what makes
    /// this test evidence about the shipped daemon rather than about the store.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pdu_session_selection_succeeds_for_a_configured_nsi() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The global NSSF context defaults to max_num_of_nf = 0, so `nsi_add`
        // refuses EVERY insert until `init` runs. Without this the assertions
        // below pass for the wrong reason -- the revert-verify pass caught
        // exactly that: a deliberately-broken loader still "installed 0".
        // Idempotent, so it is safe under the shared process-global context.
        context::nssf_context_init(64);

        let yaml = r#"
nssf:
  sbi:
    client:
      nsi:
        - uri: http://nrf-slice-7:7777
          s_nssai:
            sst: 7
"#;
        let doc: NssfYaml = serde_yaml::from_str(yaml).expect("parses");
        let nsis = doc
            .nssf
            .and_then(|n| n.sbi)
            .and_then(|s| s.client)
            .and_then(|c| c.nsi)
            .expect("nsi block");
        assert_eq!(load_configured_nsis(&nsis), 1);

        let si = json!({
            "sNssai": {"sst": 7},
            "roamingIndication": "NON_ROAMING"
        });
        let resp = handle_ns_selection_pdu_session("smf-93", "SMF", &si, None, None, None).await;
        assert_eq!(
            resp.status, 200,
            "a configured S-NSSAI must not be answered 403 (TS 29.531 §5.2.2.2.3)"
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let nrf = body
            .pointer("/nsiInformation/nrfId")
            .and_then(|v| v.as_str())
            .expect("nsiInformation.nrfId must be present for the requested S-NSSAI");
        assert_eq!(nrf, "http://nrf-slice-7:7777");
    }

    /// All three normative `RoamingIndication` values parse, the non-normative
    /// shim is still accepted inbound, and anything else is refused.
    #[test]
    fn roaming_indication_accepts_the_normative_enumeration() {
        assert_eq!(
            roaming_indication_parse("NON_ROAMING"),
            Ok(context::RoamingIndication::NonRoaming)
        );
        assert_eq!(
            roaming_indication_parse("LOCAL_BREAKOUT"),
            Ok(context::RoamingIndication::LocalBreakout)
        );
        // The value a conformant consumer sends. Before #93 this parsed to None
        // and the request was refused 400 INVALID_IE_VALUE.
        assert_eq!(
            roaming_indication_parse("HOME_ROUTED_ROAMING"),
            Ok(context::RoamingIndication::HomeRouted)
        );
        // Documented inbound back-compat shim.
        assert_eq!(
            roaming_indication_parse("HOME_ROUTED"),
            Ok(context::RoamingIndication::HomeRouted)
        );
        assert!(roaming_indication_parse("SOMETHING_ELSE").is_err());
        assert!(roaming_indication_parse("").is_err());
        // The constant used on the wire is the normative spelling.
        assert_eq!(ROAMING_HOME_ROUTED, "HOME_ROUTED_ROAMING");
    }

    /// A conformant `HOME_ROUTED_ROAMING` request is no longer refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn home_routed_roaming_request_is_accepted() {
        let si = json!({
            "sNssai": {"sst": 1},
            "roamingIndication": "HOME_ROUTED_ROAMING"
        });
        let resp = handle_ns_selection_pdu_session("smf-93b", "SMF", &si, None, None, None).await;
        assert_ne!(
            resp.status, 400,
            "the normative HOME_ROUTED_ROAMING token must not be a bad request"
        );
    }

    /// `slice-info-request-for-pdn-connection` returns the configured
    /// VPLMN->HPLMN mapping, and 403 SNSSAI_NOT_SUPPORTED when none is
    /// configured — never the 400 it used to fall through to.
    #[test]
    fn pdn_connection_scenario_is_routed_and_maps_configured_snssais() {
        // No mapping configured: the spec's own answer is 403, per §5.2.2.2.5
        // step 2b. The old behaviour was 400 MANDATORY_QUERY_PARAM_MISSING, which
        // accused the consumer of omitting a parameter it had just supplied.
        set_nssai_mapping(Vec::new());
        let resp = handle_ns_selection_pdn_connection("smf-pgw-1", r#"[{"sst":1}]"#);
        assert_eq!(resp.status, 403);
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["cause"], "SNSSAI_NOT_SUPPORTED");

        // With a mapping configured, the scenario is served.
        set_nssai_mapping(vec![(
            context::SNssai::new(1, Some(0x0000AB)),
            context::SNssai::new(3, Some(0x00FF01)),
        )]);
        let resp = handle_ns_selection_pdn_connection("smf-pgw-1", r#"[{"sst":1,"sd":"0000ab"}]"#);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let m = body["mappingOfNssai"]
            .as_array()
            .expect("mappingOfNssai is the RSIPCE response IE (TS 29.531 §5.2.2.2.5)");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["servingSnssai"]["sst"], 1);
        assert_eq!(m[0]["homeSnssai"]["sst"], 3);
        // The feature bit that gates mappingOfNssai must be advertised.
        assert_eq!(body["supportedFeatures"], NSSF_SUPPORTED_FEATURES);

        // A malformed array is a 400 on its own merits, not a 403.
        assert_eq!(
            handle_ns_selection_pdn_connection("smf-pgw-1", "[]").status,
            400,
            "minItems: 1 must be enforced"
        );
        assert_eq!(
            handle_ns_selection_pdn_connection("smf-pgw-1", "not json").status,
            400
        );
        set_nssai_mapping(Vec::new());
    }

    /// `slice-info-request-for-other-purpose` returns NSI IDs for the requested
    /// S-NSSAIs from the configured NSI table, and 403 when none resolves.
    #[test]
    fn other_purpose_scenario_is_routed_and_returns_nsi_ids() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The global NSSF context defaults to max_num_of_nf = 0, so `nsi_add`
        // refuses EVERY insert until `init` runs. Without this the assertions
        // below pass for the wrong reason -- the revert-verify pass caught
        // exactly that: a deliberately-broken loader still "installed 0".
        // Idempotent, so it is safe under the shared process-global context.
        context::nssf_context_init(64);

        let yaml = r#"
nssf:
  sbi:
    client:
      nsi:
        - uri: http://nrf-slice-9:7777
          s_nssai:
            sst: 9
"#;
        let doc: NssfYaml = serde_yaml::from_str(yaml).expect("parses");
        let nsis = doc
            .nssf
            .and_then(|n| n.sbi)
            .and_then(|s| s.client)
            .and_then(|c| c.nsi)
            .expect("nsi block");
        load_configured_nsis(&nsis);

        let resp = handle_ns_selection_other_purpose("nwdaf-1", r#"[{"sst":9}]"#);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let rsp = body["snssaiInfoRspData"]
            .as_object()
            .expect("snssaiInfoRspData is the SIOP response IE (TS 29.531 §5.2.2.2.6)");
        let entry = rsp.get("9").expect("keyed by the requested S-NSSAI");
        let ids = entry["nsiIds"].as_array().expect("nsiIds");
        assert_eq!(ids.len(), 1);
        assert!(!ids[0].as_str().unwrap_or("").is_empty());
        assert_eq!(body["supportedFeatures"], NSSF_SUPPORTED_FEATURES);

        // An S-NSSAI with no configured NSI: 403, per §5.2.2.2.6 step 2b.
        let resp = handle_ns_selection_other_purpose("nwdaf-1", r#"[{"sst":200}]"#);
        assert_eq!(resp.status, 403);
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["cause"], "SNSSAI_NOT_SUPPORTED");
    }

    /// Both new scenarios reach the SBI router, not just the handler.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn both_new_scenarios_are_reachable_through_the_router() {
        for param in [
            "slice-info-request-for-pdn-connection",
            "slice-info-request-for-other-purpose",
        ] {
            let uri = format!(
                "/nnssf-nsselection/v2/network-slice-information?nf-type=SMF&nf-id=smf-1&\
                 {param}={}",
                urlencoding_encode(r#"[{"sst":1}]"#)
            );
            let resp = nssf_sbi_request_handler(SbiRequest::get(&uri)).await;
            assert_ne!(
                resp.status, 400,
                "{param} must be routed, not answered MANDATORY_QUERY_PARAM_MISSING"
            );
        }
    }

    /// A percent-encoder for the JSON-valued query parameters above.
    ///
    /// Written out rather than sent raw: a JSON-shaped query value containing
    /// `{` or `"` is refused by the URI layer before the request is ever sent,
    /// which reads exactly like a routing failure.
    /// Serialises tests that depend on the process-global availability-authz
    /// posture (`STRICT_AVAILABILITY_AUTHZ`).
    ///
    /// The flag is process-wide, so a test that flips it races every parallel
    /// test that reads it. Taken through a recovering lock so one panicking test
    /// cannot poison the rest into `PoisonError` instead of running.
    static AUTHZ_POSTURE_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Hold the posture at `strict` for the duration of the returned guard.
    fn with_authz_posture(strict: bool) -> std::sync::MutexGuard<'static, ()> {
        let g = AUTHZ_POSTURE_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_strict_availability_authz(strict);
        g
    }

    /// Build an availability write request whose ATTESTED caller identity is
    /// `nf_id` — i.e. what a real AMF writing its own document looks like.
    ///
    /// #94 made availability writes require the caller to be the owner of the
    /// document, so a request with no attested identity is now (correctly) 403.
    /// These tests are about storage and restriction semantics, not about
    /// authorization, so they present the identity a conformant consumer would
    /// rather than turning the check off.
    fn authenticated_availability_request(
        method: &str,
        nf_id: &str,
        body: Option<&serde_json::Value>,
    ) -> SbiRequest {
        let uri = format!("/nnssf-nssaiavailability/v1/nssai-availability/{nf_id}");
        let mut req = match method {
            "PUT" => SbiRequest::put(&uri),
            "PATCH" => SbiRequest::patch(&uri),
            "DELETE" => SbiRequest::delete(&uri),
            other => panic!("authenticated_availability_request: unsupported method {other}"),
        };
        if let Some(b) = body {
            req = req.with_json_body(b).expect("encode test body");
        }
        // The verified OAuth2 token subject: an identity the server attested.
        req.oauth2_subject = Some(nf_id.to_string());
        req
    }

    fn urlencoding_encode(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    /// `targetAmfSet` is emitted only from configuration, never synthesised from
    /// the UE's TAI.
    ///
    /// The old fallback produced `<mcc>-<mnc>-01-001`: syntactically valid, and
    /// an AMF set nobody deployed, so the AMF re-selected against a set that does
    /// not exist.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn target_amf_set_is_never_synthesised_from_the_tai() {
        with_nssf_context(|c| c.clear_target_amf_set());
        let info = json!({
            "subscribedNssai": [{"subscribedSnssai": {"sst": 1}}],
            "requestedNssai": [{"sst": 1}]
        });
        // A TAI IS supplied: the old code would have derived 999-70-01-001 here.
        let tai = context::Tai {
            plmn_id: context::PlmnId {
                mcc: "999".to_string(),
                mnc: "70".to_string(),
            },
            tac: 1,
        };
        let resp = handle_ns_selection_registration("amf-93", &info, Some(&tai));
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            body.get("targetAmfSet").is_none(),
            "targetAmfSet must be absent when unconfigured, even with a TAI: got {:?}",
            body.get("targetAmfSet")
        );
    }

    /// The registration response's `accessType` reflects the access the consumer
    /// asked about rather than a hardcoded `3GPP_ACCESS`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn access_type_reflects_the_requested_access() {
        with_nssf_context(|c| c.clear_target_amf_set());

        // Non-3GPP: previously reported back as 3GPP_ACCESS.
        let info = json!({
            "subscribedNssai": [{"subscribedSnssai": {"sst": 1}}],
            "requestedNssai": [{"sst": 1}],
            "allowedNssaiCurrentAccess": {
                "allowedSnssaiList": [{"allowedSnssai": {"sst": 1}}],
                "accessType": "NON_3GPP_ACCESS"
            }
        });
        let resp = handle_ns_selection_registration("amf-93b", &info, None);
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["allowedNssaiList"][0]["accessType"], "NON_3GPP_ACCESS",
            "a NON_3GPP_ACCESS request must not be reported as 3GPP_ACCESS"
        );

        // An `allowedNssaiOtherAccess` must NOT be read as the current access.
        let info = json!({
            "subscribedNssai": [{"subscribedSnssai": {"sst": 1}}],
            "requestedNssai": [{"sst": 1}],
            "allowedNssaiOtherAccess": {
                "allowedSnssaiList": [{"allowedSnssai": {"sst": 1}}],
                "accessType": "NON_3GPP_ACCESS"
            }
        });
        let resp = handle_ns_selection_registration("amf-93c", &info, None);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["allowedNssaiList"][0]["accessType"], DEFAULT_ACCESS_TYPE,
            "allowedNssaiOtherAccess describes the OTHER access and must not set the current one"
        );

        // No access stated at all: the documented default.
        let info = json!({
            "subscribedNssai": [{"subscribedSnssai": {"sst": 1}}],
            "requestedNssai": [{"sst": 1}]
        });
        let resp = handle_ns_selection_registration("amf-93d", &info, None);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["allowedNssaiList"][0]["accessType"],
            DEFAULT_ACCESS_TYPE
        );
    }

    /// The outbound H-NSSF query carries the NORMATIVE roaming token.
    ///
    /// Pins the value on the wire, which is what TS 29.531 §6.1.6.3.3
    /// constrains. Before #93 this emitted `HOME_ROUTED`, and no test could see
    /// it because the string was built inline inside the async send path — the
    /// reason `build_hnssf_query_path` was extracted.
    #[test]
    fn outbound_hnssf_query_emits_the_normative_roaming_token() {
        let mut param = nnssf_handler::NsSelectionParam {
            nf_id: Some("amf-hr-1".to_string()),
            nf_type: Some("AMF".to_string()),
            ..Default::default()
        };
        param.slice_info_for_pdu_session.presence = true;
        param.slice_info_for_pdu_session.snssai = Some(context::SNssai::new(1, Some(0x0000AB)));

        let path = build_hnssf_query_path(&param);
        assert!(
            path.contains("\"roamingIndication\":\"HOME_ROUTED_ROAMING\""),
            "the H-NSSF query must carry the normative token, got: {path}"
        );
        // And must NOT carry the old non-normative spelling as a bare value.
        assert!(
            !path.contains("\"roamingIndication\":\"HOME_ROUTED\""),
            "the non-normative HOME_ROUTED must not reach the wire: {path}"
        );
        // Sanity: the rest of the query is still assembled.
        assert!(path.contains("nf-type=AMF") && path.contains("nf-id=amf-hr-1"));
        assert!(
            path.contains("\"sd\":\"0000ab\""),
            "sd must be 6 hex digits: {path}"
        );
    }

    // ── #94: authz binding, expiry lifecycle, create validation, wire shape ──

    /// #94 criterion 1: an availability write whose ATTESTED identity is not the
    /// `{nfId}` that owns the document is refused; a matching one succeeds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn availability_write_requires_the_caller_to_own_the_document() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = availability_state_guard().await;
        let _posture = with_authz_posture(true);
        nssf_context_init(512);

        let owner = "amf-owner-94";
        let intruder = "amf-intruder-94";
        let _ = with_nssf_context(|c| c.remove_nssai_availability(owner));

        let body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });

        // A DIFFERENT NF presenting its own attested identity may not write the
        // owner's document. Before #94 this succeeded: the check was only that the
        // path segment was non-empty.
        let mut req = SbiRequest::put(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{owner}"
        ))
        .with_json_body(&body)
        .unwrap();
        req.oauth2_subject = Some(intruder.to_string());
        let resp = handle_nssai_availability_update(owner, &req).await;
        assert_eq!(
            resp.status, 403,
            "a non-owner must not be able to write another AMF's slice picture"
        );
        assert!(
            with_nssf_context(|c| c.get_nssai_availability(owner))
                .flatten()
                .is_none(),
            "the refused write must not have been stored"
        );

        // The owner itself succeeds.
        let ok = authenticated_availability_request("PUT", owner, Some(&body));
        let resp = handle_nssai_availability_update(owner, &ok).await;
        assert_eq!(resp.status, 200, "the owning AMF must be able to write");
        assert!(with_nssf_context(|c| c.get_nssai_availability(owner))
            .flatten()
            .is_some());

        // A verified client CERTIFICATE identity works the same way, and is
        // preferred over the token: both are attested by this process.
        let mut cert_req = SbiRequest::put(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{owner}"
        ))
        .with_json_body(&body)
        .unwrap();
        cert_req.peer_cert_nf_instance_id = Some(owner.to_string());
        assert_eq!(
            handle_nssai_availability_update(owner, &cert_req)
                .await
                .status,
            200
        );

        // A token-less write is refused under the strict posture: there is no
        // identity to bind to, and "cannot tell who you are" is not permission.
        let anon = SbiRequest::put(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{owner}"
        ))
        .with_json_body(&body)
        .unwrap();
        assert_eq!(
            handle_nssai_availability_update(owner, &anon).await.status,
            403,
            "an unattested write must be refused under the strict posture"
        );

        let _ = with_nssf_context(|c| c.remove_nssai_availability(owner));
    }

    /// PATCH and DELETE are bound to the owner too, not just PUT.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn availability_patch_and_delete_are_bound_to_the_owner() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = availability_state_guard().await;
        let _posture = with_authz_posture(true);
        nssf_context_init(512);

        let owner = "amf-owner-94b";
        let body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let put = authenticated_availability_request("PUT", owner, Some(&body));
        assert_eq!(
            handle_nssai_availability_update(owner, &put).await.status,
            200
        );

        // PATCH from a non-owner.
        let patch = json!([{
            "op": "add",
            "path": "/supportedNssaiAvailabilityData/0/supportedSnssaiList/-",
            "value": {"sst": 2}
        }]);
        let mut bad = SbiRequest::patch(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{owner}"
        ))
        .with_body(patch.to_string(), "application/json-patch+json");
        bad.oauth2_subject = Some("amf-intruder-94b".to_string());
        assert_eq!(
            handle_nssai_availability_patch(owner, &bad).await.status,
            403,
            "a non-owner must not be able to PATCH another AMF's document"
        );

        // The owner's PATCH works.
        let mut good = SbiRequest::patch(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{owner}"
        ))
        .with_body(patch.to_string(), "application/json-patch+json");
        good.oauth2_subject = Some(owner.to_string());
        assert_eq!(
            handle_nssai_availability_patch(owner, &good).await.status,
            200
        );

        let _ = with_nssf_context(|c| c.remove_nssai_availability(owner));
    }

    /// #94 criterion 2: the authorization decision fails CLOSED.
    ///
    /// Asserted at the policy function rather than by poisoning the real context
    /// lock — poisoning a process-global lock would break every parallel test,
    /// which is the avalanche the recorded poisoned-mutex lesson describes. What
    /// matters is the property: no attested caller means no authorization.
    #[test]
    fn availability_authorization_denies_when_it_cannot_identify_the_caller() {
        let ctx = context::NssfContext::new();
        let tai = context::Tai::default();
        // No caller at all -- the shape a poisoned lock or a token-less request
        // presents. Before #94 the poisoned-lock path fell back to "allow any
        // non-empty nfId".
        assert!(
            !ctx.nf_authorized_for_availability("amf-1", None, &tai),
            "no attested identity must not authorize a write"
        );
        // A mismatched caller.
        assert!(!ctx.nf_authorized_for_availability("amf-1", Some("amf-2"), &tai));
        // The owner.
        assert!(ctx.nf_authorized_for_availability("amf-1", Some("amf-1"), &tai));
        // Case-insensitive, because a UUID may be presented in either case.
        assert!(ctx.nf_authorized_for_availability("AMF-ABC", Some("amf-abc"), &tai));
        // An empty path segment is never authorized, whoever asks.
        assert!(!ctx.nf_authorized_for_availability("", Some(""), &tai));
        assert!(!ctx.nf_authorized_for_availability("  ", Some("  "), &tai));
    }

    /// #94 criterion 4: the NSSF assigns an expiry, an expired subscription stops
    /// matching, and the sweep removes it.
    #[test]
    fn subscription_expiry_is_assigned_enforced_and_swept() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        nssf_context_init(512);
        let created = subscription_from_json(
            "sub-94-expiry",
            &json!({
                "nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb",
                "event": "SNSSAI_STATUS_CHANGE_REPORT"
            }),
        )
        .expect("a create with only the two mandatory members must be accepted");

        // An expiry is ASSIGNED even though the consumer requested none.
        let expiry = created
            .expiry
            .as_deref()
            .expect("the NSSF must assign an expiry (TS 29.531 Table 6.2.6.2.9-1)");
        let deadline = nextgcore_sbi::datetime::rfc3339_to_epoch(expiry).expect("parseable");
        let now = nextgcore_sbi::datetime::now_epoch_secs();
        assert!(deadline > now);
        assert!(deadline <= now + timer::defaults::SUBSCRIPTION_VALIDITY.as_secs() + 5);

        // A consumer cannot extend past the NSSF bound...
        let far = subscription_from_json(
            "sub-94-far",
            &json!({
                "nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb",
                "event": "SNSSAI_STATUS_CHANGE_REPORT",
                "expiry": "2099-01-01T00:00:00Z"
            }),
        )
        .expect("accepted");
        let far_deadline =
            nextgcore_sbi::datetime::rfc3339_to_epoch(far.expiry.as_deref().unwrap()).unwrap();
        assert!(
            far_deadline <= now + timer::defaults::SUBSCRIPTION_VALIDITY.as_secs() + 5,
            "a far-future request must be clamped to the NSSF's own bound"
        );
        // ...but a SHORTER consumer-requested expiry is honoured.
        let soon_epoch = now + 30;
        let soon_text = nextgcore_sbi::datetime::epoch_to_rfc3339(soon_epoch);
        let soon = subscription_from_json(
            "sub-94-soon",
            &json!({
                "nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb",
                "event": "SNSSAI_STATUS_CHANGE_REPORT",
                "expiry": soon_text
            }),
        )
        .expect("accepted");
        assert_eq!(soon.expiry.as_deref(), Some(soon_text.as_str()));

        // Expiry enforcement: is_expired_at is the predicate both the matching
        // filter and the sweep use.
        assert!(!soon.is_expired_at(soon_epoch - 1));
        assert!(soon.is_expired_at(soon_epoch));
        assert!(soon.is_expired_at(soon_epoch + 1));

        // An already-expired subscription never MATCHES...
        let mut expired = created.clone();
        expired.subscription_id = "sub-94-dead".to_string();
        expired.expiry = Some(nextgcore_sbi::datetime::epoch_to_rfc3339(now - 10));
        with_nssf_context(|c| c.subscription_add(expired.clone()));
        let matching = with_nssf_context(|c| c.subscriptions_matching(&[])).unwrap_or_default();
        assert!(
            !matching.iter().any(|s| s.subscription_id == "sub-94-dead"),
            "an expired subscription must not be notified"
        );

        // ...and the sweep REMOVES it, while a live one survives.
        with_nssf_context(|c| c.subscription_add(created.clone()));
        let removed = with_nssf_context(|c| c.sweep_expired_subscriptions(now)).unwrap_or_default();
        assert!(removed.contains(&"sub-94-dead".to_string()));
        assert!(
            with_nssf_context(|c| c.subscription_get("sub-94-dead"))
                .flatten()
                .is_none(),
            "the sweep must remove the expired record, not just hide it"
        );
        assert!(
            with_nssf_context(|c| c.subscription_get("sub-94-expiry"))
                .flatten()
                .is_some(),
            "a live subscription must survive the sweep"
        );

        for id in ["sub-94-expiry", "sub-94-dead"] {
            let _ = with_nssf_context(|c| c.subscription_remove(id));
        }
    }

    /// #94 criterion 5: `taiList` is optional, and `acceptedEvents` is returned.
    #[test]
    fn subscription_create_treats_tai_list_as_optional_and_returns_accepted_events() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        nssf_context_init(512);

        // Only the two members the schema marks required.
        let sub = subscription_from_json(
            "sub-94-notai",
            &json!({
                "nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb",
                "event": "SNSSAI_STATUS_CHANGE_REPORT"
            }),
        )
        .expect("taiList is OPTIONAL per TS 29.531 Table 6.2.6.2.8-1");
        assert!(sub.tai_list.is_empty(), "absent taiList means all TAIs");
        assert_eq!(sub.accepted_events, vec!["SNSSAI_STATUS_CHANGE_REPORT"]);

        // acceptedEvents reaches the wire.
        let created = sub.to_created_json();
        let accepted = created["acceptedEvents"]
            .as_array()
            .expect("acceptedEvents must be returned (Table 6.2.6.2.9-1)");
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0], "SNSSAI_STATUS_CHANGE_REPORT");
        assert!(created["expiry"].is_string());

        // An empty taiList is also fine, and still means all TAIs.
        let sub = subscription_from_json(
            "sub-94-emptytai",
            &json!({
                "nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb",
                "event": "SNSSAI_STATUS_CHANGE_REPORT",
                "taiList": []
            }),
        )
        .expect("an empty taiList is legal");
        assert!(sub.tai_list.is_empty());

        // additionalEvents: reportable ones are accepted, unreportable ones are
        // simply absent from acceptedEvents rather than rejected.
        let sub = subscription_from_json(
            "sub-94-addl",
            &json!({
                "nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb",
                "event": "SNSSAI_STATUS_CHANGE_REPORT",
                "additionalEvents": ["NSI_UNAVAILABILITY_REPORT", "A_FUTURE_EVENT"]
            }),
        )
        .expect("an unreportable additional event must not fail the create");
        assert_eq!(
            sub.accepted_events,
            vec!["SNSSAI_STATUS_CHANGE_REPORT"],
            "only events with a real producer may be reported as accepted"
        );

        // A subscription that could NEVER fire is refused rather than silently kept.
        let err = subscription_from_json(
            "sub-94-none",
            &json!({
                "nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb",
                "event": "NSI_UNAVAILABILITY_REPORT"
            }),
        )
        .expect_err("a subscription with no reportable event must be refused");
        assert!(err.contains("can be reported"), "got: {err}");

        // The two genuinely-mandatory members are still enforced.
        for body in [
            json!({ "event": "SNSSAI_STATUS_CHANGE_REPORT" }),
            json!({ "nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb" }),
        ] {
            assert!(subscription_from_json("sub-94-bad", &body).is_err());
        }
    }

    /// #94 criterion 6: restrictions come from CONFIG, and serialize under
    /// `sNssaiList`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn configured_restrictions_round_trip_under_the_conformant_key() {
        let _guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.clear_plmn_snssai_restrictions());

        // Loaded from YAML through the production config path -- before #94
        // set_plmn_snssai_restrictions had no caller outside cfg(test), so an
        // operator could not configure a restriction at all.
        let yaml = r#"
nssf:
  snssai_restrictions:
    - home_plmn:
        mcc: "001"
        mnc: "01"
      restricted:
        - sst: 99
"#;
        let doc: NssfYaml = serde_yaml::from_str(yaml).expect("config shape parses");
        let list = doc
            .nssf
            .and_then(|n| n.snssai_restrictions)
            .expect("the snssai_restrictions block must deserialise");
        assert_eq!(list.len(), 1);
        with_nssf_context(|c| {
            for r in &list {
                let plmn = context::PlmnId::new(&r.home_plmn.mcc, &r.home_plmn.mnc);
                c.set_plmn_snssai_restrictions(
                    &plmn,
                    r.restricted.iter().map(snssai_from_yaml).collect(),
                );
            }
        });

        let doc = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}],
                "taiList": [{"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "000002"}],
                "nsagInfos": [{"nsagId": 7}]
            }]
        });
        let resp = authorized_availability_response(&doc);
        assert_eq!(resp.status, 200);
        let raw = resp.http.content.as_deref().unwrap().to_string();
        let body: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let entry = &body["authorizedNssaiAvailabilityData"][0];

        let restricted = entry["restrictedSnssaiList"]
            .as_array()
            .expect("a configured restriction must be emitted");
        assert_eq!(restricted[0]["sNssaiList"][0]["sst"], 99);
        // The non-conformant key must not appear ANYWHERE in the document.
        assert!(
            !raw.contains("sNssais\""),
            "the non-conformant `sNssais` key must not reach the wire: {raw}"
        );

        // #94 criterion 7: the locality/scoping members survive into the entry.
        assert_eq!(
            entry["taiList"][0]["tac"], "000002",
            "taiList must be carried through, not dropped"
        );
        assert_eq!(entry["nsagInfos"][0]["nsagId"], 7);

        with_nssf_context(|c| c.clear_plmn_snssai_restrictions());
    }

    /// The unevaluable-policy response is a 403 denial with a cause the consumer
    /// can act on.
    #[test]
    fn unevaluable_policy_response_is_a_403_denial() {
        let resp = policy_unevaluable_response();
        assert_eq!(resp.status, 403, "an unevaluable policy must DENY");
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["cause"], "NOT_AUTHORIZED");
        assert_eq!(pd["status"], 403);
    }
}
