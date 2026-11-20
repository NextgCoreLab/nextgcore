//! NextGCore UDR (Unified Data Repository)
//!
//! The UDR is a 5G core network function responsible for:
//! - Storing and providing subscriber data to UDM
//! - Storing and providing policy data to PCF
//! - Storing and providing application data
//!
//! UDR is a stateless data repository that queries the database directly.

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::JwksCache;
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use nextgcore_udrd::data_store::{
    self, merge_patch, notify_application_data_change, notify_exposure_data_change,
    notify_influence_data_change, notify_subscription_data_change, SubKind,
};
use nextgcore_udrd::{
    udr_context_final, udr_context_init, udr_sbi_close, udr_sbi_open, SbiServerConfig, UdrSmContext,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// NextGCore UDR - Unified Data Repository
#[derive(Parser, Debug)]
#[command(name = "nextgcore-udrd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Unified Data Repository", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/udr.yaml")]
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

    /// Kill a running instance (NOT SUPPORTED: exits with an error;
    /// stop the NF through its supervisor)
    #[arg(short = 'k', long)]
    kill: bool,

    /// SBI bind address. Without it, `udr.sbi.server[0].address`, else
    /// 127.0.0.1 (#1308, #1312): the command line overrides the config file.
    #[arg(long)]
    sbi_addr: Option<String>,

    /// The SBI host advertised in the NRF NFProfile and callback URIs. Without it,
    /// `NEXTGCORE_SBI_ADVERTISE`, else `udr.sbi.server[0].advertise`, else the
    /// bind address; a wildcard is never advertised (#1312).
    #[arg(long)]
    sbi_advertise: Option<String>,

    /// SBI server port. Without it, `udr.sbi.server[0].port`, else 7777.
    #[arg(long)]
    sbi_port: Option<u16>,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// Path to the JSON snapshot file for non-subscriber resource trees
    /// (exposure-data, application-data, smf-registrations, subs-to-notify).
    /// When unset (the default), these trees are kept purely in-memory and are
    /// lost on restart. Also settable via NEXTGCORE_UDR_STATE_FILE.
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

#[derive(Debug, Default, Deserialize)]
struct SbiClientYaml {
    nrf: Option<Vec<NrfClientYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiOauth2Yaml {
    /// Require a valid OAuth2 bearer token on every incoming SBI request.
    /// Verification keys are fetched from the configured NRF's JWKS endpoint.
    require: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiServerYaml {
    address: Option<String>,
    port: Option<u16>,
    /// The host advertised to the NRF and in callback URIs (#1312).
    advertise: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
    oauth2: Option<SbiOauth2Yaml>,
}

/// One `udr.group_id_map` entry: the NF-group ids assigned to the subscribers
/// whose SUPI starts with `supi_prefix` (#87, TS 29.504 §6.2).
///
/// Group assignment is an operator decision made by SUPI range — there is no
/// Nudr verb that provisions it, and deriving a group id from the SUPI would
/// invent a topology this core does not have.
#[derive(Debug, Default, Deserialize, Clone)]
struct GroupIdMapYaml {
    /// SUPI prefix this entry covers, e.g. `imsi-00101`. An empty prefix matches
    /// every subscriber (single-group deployment).
    #[serde(default)]
    supi_prefix: String,
    /// NF type (`UDM`, `AUSF`, ...) -> NF-group id.
    nf_group_ids: std::collections::HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct UdrSection {
    sbi: Option<SbiYaml>,
    /// #87: `udr.group_id_map` — the Nudr_GroupIDmap assignments.
    group_id_map: Option<Vec<GroupIdMapYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct UdrYaml {
    udr: Option<UdrSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// #87: the configured Nudr_GroupIDmap assignments, longest-prefix first.
static GROUP_ID_MAP: std::sync::RwLock<Vec<GroupIdMapYaml>> = std::sync::RwLock::new(Vec::new());

/// Install the group-id-map configuration (longest prefix wins, so a specific
/// range overrides a catch-all rather than depending on file order).
fn set_group_id_map(mut entries: Vec<GroupIdMapYaml>) {
    entries.sort_by_key(|e| std::cmp::Reverse(e.supi_prefix.len()));
    if let Ok(mut guard) = GROUP_ID_MAP.write() {
        *guard = entries;
    }
}

/// The NF-group ids assigned to `subscriber_id`, or `None` when no entry covers
/// it. Filtered to `nf_types` when non-empty.
fn group_ids_for(subscriber_id: &str, nf_types: &[String]) -> Option<serde_json::Value> {
    let guard = GROUP_ID_MAP.read().ok()?;
    let entry = guard
        .iter()
        .find(|e| subscriber_id.starts_with(&e.supi_prefix))?;
    let mut out = serde_json::Map::new();
    for (nf_type, group_id) in &entry.nf_group_ids {
        if !nf_types.is_empty() && !nf_types.iter().any(|t| t.eq_ignore_ascii_case(nf_type)) {
            continue;
        }
        out.insert(nf_type.to_ascii_uppercase(), serde_json::json!(group_id));
    }
    // minProperties: 1 — a map with nothing in it answers nothing.
    if out.is_empty() {
        return None;
    }
    Some(serde_json::Value::Object(out))
}

/// `Nudr_GroupIDmap` (TS 29.504 §6.2), served at
/// `/nudr-group-id-map/v1/...`. The service was unrouted, so the router's
/// unknown-service 404 was the only answer a consumer ever got.
fn handle_group_id_map(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = data_store::store();
    match (parts.get(2).copied().unwrap_or(""), parts.get(3).copied()) {
        // GET /nf-group-ids?nf-type=UDM,AUSF&subscriberId=imsi-...
        ("nf-group-ids", None) => {
            if method != "GET" {
                return send_method_not_allowed(method, "nf-group-ids");
            }
            let Some(subscriber_id) = request.http.params.get("subscriberId") else {
                return missing_mandatory("subscriberId");
            };
            let subscriber_id = pct_decode(subscriber_id);
            let nf_types: Vec<String> = request
                .http
                .params
                .get("nf-type")
                .map(|raw| {
                    pct_decode(raw)
                        .split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if nf_types.is_empty() {
                return missing_mandatory("nf-type");
            }
            match group_ids_for(&subscriber_id, &nf_types) {
                Some(map) => {
                    SbiResponse::with_status(200).with_body(map.to_string(), "application/json")
                }
                None => send_not_found(
                    "No NF group ids assigned for this subscriber",
                    Some("DATA_NOT_FOUND"),
                ),
            }
        }
        ("nf-group-ids", Some("subscriptions")) => {
            let subs_id = parts.get(4).copied().unwrap_or("");
            match (subs_id.is_empty(), method) {
                (true, "POST") => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let Some(uri) = body
                        .get("callbackReference")
                        .or_else(|| body.get("notificationUri"))
                        .and_then(|v| v.as_str())
                    else {
                        return missing_mandatory("callbackReference");
                    };
                    let owner = match owner_for_new_subscription(request, "Subscribe") {
                        Ok(owner) => owner,
                        Err(refused) => return *refused,
                    };
                    let sub = ds.sub_create_owned(SubKind::GroupIdMap, uri, body.clone(), owner);
                    SbiResponse::with_status(201)
                        .with_header(
                            "Location",
                            format!(
                                "/nudr-group-id-map/v1/nf-group-ids/subscriptions/{}",
                                sub.id
                            ),
                        )
                        .with_body(body.to_string(), "application/json")
                }
                (false, "GET") => {
                    match sub_for_caller(subs_id, SubKind::GroupIdMap, request, "Get") {
                        Ok(sub) => SbiResponse::with_status(200)
                            .with_body(sub.body.to_string(), "application/json"),
                        Err(refused) => *refused,
                    }
                }
                (false, "PUT") => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let Some(uri) = body
                        .get("callbackReference")
                        .or_else(|| body.get("notificationUri"))
                        .and_then(|v| v.as_str())
                    else {
                        return missing_mandatory("callbackReference");
                    };
                    if let Err(refused) =
                        sub_for_caller(subs_id, SubKind::GroupIdMap, request, "Modify")
                    {
                        return *refused;
                    }
                    if ds.sub_replace(subs_id, SubKind::GroupIdMap, uri, body.clone()) {
                        SbiResponse::with_status(200)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                    }
                }
                (false, "DELETE") => {
                    if let Err(refused) =
                        sub_for_caller(subs_id, SubKind::GroupIdMap, request, "Unsubscribe")
                    {
                        return *refused;
                    }
                    ds.sub_remove(subs_id);
                    SbiResponse::with_status(204)
                }
                _ => send_method_not_allowed(method, "nf-group-ids/subscriptions"),
            }
        }
        // GET /routing-ids: routing-id assignment is a separate data model this
        // core does not hold, so it is recognised and refused rather than
        // answered with a fabricated mapping.
        ("routing-ids", None) => {
            if method != "GET" {
                return send_method_not_allowed(method, "routing-ids");
            }
            send_error(
                501,
                "Not Implemented",
                "routing-ids assignment is not provisioned in this UDR",
                Some("NOT_IMPLEMENTED"),
            )
        }
        _ => send_not_found("Unknown nudr-group-id-map resource", None),
    }
}

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (Wave-6 H8 Phase A). Installed only when the existing
/// `udr.sbi.oauth2.require` producer knob is enabled; attaching a Bearer to a
/// non-verifying producer is a no-op, so this is matched-sim-E2E safe.
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled.
#[allow(dead_code)]
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// #1665: the outbound OAuth2 client this UDR installs at startup: under the
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
        nextgcore_sbi::types::NfType::Udr,
    )
}

/// #1795: the UDR's SBI listener under the SBI security profile. Under
/// `production`: TLS from `policy`'s certificate paths (whatever `--tls` or the
/// config file said), the client certificate verified against its CA, and an
/// access token required, with UDR as the audience and the NRF's JWKS unless
/// the NF configured its own (TS 33.501 §13.1.0, §13.3, §13.4.1). A missing
/// certificate fails startup, naming it, rather than serving cleartext. Under
/// `dev` the config is left as the NF's own settings made it.
fn sbi_listener_config(
    config: NextgcoreSbiServerConfig,
    profile: nextgcore_sbi::security::SbiProfile,
    policy: &nextgcore_sbi::security::SbiSecurityPolicy,
    nrf_uri: &str,
) -> nextgcore_sbi::SbiResult<NextgcoreSbiServerConfig> {
    let config = nextgcore_sbi::security::apply_sbi_security_policy(
        config,
        profile,
        policy,
        nextgcore_sbi::types::NfType::Udr,
        nrf_uri,
    )?;
    // #1811: whenever the listener requires a token, whether the knob or the
    // production profile asked for it, the AuthenticationSubscription resource
    // (K, OPc, SQN) needs its TS 29.505 resource scope too.
    Ok(if config.require_oauth2 {
        config.with_oauth2_resource_scopes(nextgcore_sbi::resource_scope::required_resource_scope)
    } else {
        config
    })
}

/// The OAuth2 posture of the UDR's listener when `require_oauth2` is on: every
/// request needs a valid NRF-issued bearer whose `aud` names the UDR and whose
/// scope covers what it invokes. The verification keys are the caller's to set.
fn udr_oauth2_listener(config: NextgcoreSbiServerConfig) -> NextgcoreSbiServerConfig {
    let mut config = config;
    config.require_oauth2 = true;
    // Issue #64 gap 3: assert the token's `aud` names the UDR.
    //
    // Without this `oauth2_expected_audience` stays None, the server calls
    // `authorize_bearer_aud(.., None)` and the audience check is SKIPPED -- so a
    // token the NRF minted for any other producer was accepted here, on the NF
    // that holds subscriber data. TS 33.501 13.4.1.2 requires the producer to
    // verify it is the intended audience. Every other OAuth2-enforcing NF
    // already did this; the UDR was the one that did not.
    //
    // #1811: and the AuthenticationSubscription resource (K, OPc, SQN) needs its
    // TS 29.505 resource scope as well as `nudr-dr`, which the NRF grants only to
    // a UDM (UDR_RESOURCE_SCOPES). The server refuses a token without it, 403
    // insufficient_scope, before the router runs, so a refused request reads
    // nothing.
    //
    // #1964: nrfd pins a resource-scoped token's `aud` to the UDR instances it
    // evaluated the scope over, so this UDR accepts its own instance ID too.
    config
        .with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Udr)
        .with_expected_audience_instance(
            nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Udr)
                .to_string(),
        )
        .with_oauth2_resource_scopes(nextgcore_sbi::resource_scope::required_resource_scope)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // #1313 review: the config is read and parsed first, so a file that does not
    // parse fails startup at once (not after the MongoDB connect), rather than
    // falling back to the defaults, the SBI bind among them. No file is no config.
    let config_yaml: Option<UdrYaml> = match std::fs::read_to_string(&args.config) {
        Ok(content) => Some(serde_yaml::from_str(&content).map_err(|e| {
            anyhow::anyhow!("configuration file {} does not parse: {e}", args.config)
        })?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => anyhow::bail!("cannot read the configuration file {}: {e}", args.config),
    };

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

    log::info!("NextGCore UDR v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize UDR context
    udr_context_init();
    log::info!("UDR context initialized");

    // Initialise the persistent data store for non-subscriber resource trees.
    // Path precedence: --state-file flag, then NEXTGCORE_UDR_STATE_FILE env.
    // With neither set the store stays purely in-memory (previous behaviour).
    let state_file = args
        .state_file
        .clone()
        .or_else(|| std::env::var("NEXTGCORE_UDR_STATE_FILE").ok())
        .filter(|s| !s.is_empty());
    match &state_file {
        Some(path) => {
            nextgcore_udrd::data_store::init_store(Some(std::path::PathBuf::from(path)));
            log::info!("UDR resource-tree persistence enabled: {path}");
        }
        None => {
            nextgcore_udrd::data_store::init_store(None);
            log::info!("UDR resource-tree persistence disabled (in-memory only)");
        }
    }

    // Initialize UDR state machine
    let mut udr_sm = UdrSmContext::new();
    udr_sm.init();
    log::info!("UDR state machine initialized");

    // Parse configuration to get db_uri and seed NRF URI
    let db_uri = parse_db_uri(&args.config);
    if !db_uri.is_empty() {
        match nextgcore_dbi::nextgcore_dbi_init_async(db_uri.clone()).await {
            Ok(()) => log::info!("MongoDB connected: {}", mask_uri(&db_uri)),
            Err(e) => log::warn!("MongoDB init failed (will use defaults): {e:?}"),
        }
    } else {
        log::warn!("No db_uri configured, UDR will return hardcoded test data");
    }

    // Seed NRF URI into SBI context for NF registration, and pick up the
    // OAuth2 enforcement knob (udr.sbi.oauth2.require).
    let mut nrf_uri_cfg: Option<String> = None;
    let mut require_oauth2 = false;
    // #1312: the YAML `server[0]`, used once the command line has had its say.
    let mut yaml_sbi = nextgcore_core::sockaddr::YamlServer::default();
    if let Some(yaml) = config_yaml {
        {
            let udr_section = yaml.udr;
            // #87: Nudr_GroupIDmap assignments. Absent config leaves the map
            // empty, so `GET /nf-group-ids` answers 404 DATA_NOT_FOUND rather
            // than inventing a group id.
            if let Some(entries) = udr_section.as_ref().and_then(|u| u.group_id_map.clone()) {
                log::info!("Nudr_GroupIDmap: {} assignment range(s)", entries.len());
                set_group_id_map(entries);
            }
            if let Some(sbi) = udr_section.and_then(|udr| udr.sbi) {
                // Override the advertised/bind SBI address with the routable
                // address from config so the NRF NFProfile advertises a
                // reachable endpoint (not 0.0.0.0).
                if let Some(server) = sbi.server.as_ref().and_then(|s| s.first()) {
                    yaml_sbi = nextgcore_core::sockaddr::YamlServer {
                        address: server.address.clone(),
                        port: server.port,
                        advertise: server.advertise.clone(),
                    };
                }
                nrf_uri_cfg = sbi
                    .client
                    .and_then(|client| client.nrf)
                    .and_then(|nrf_list| nrf_list.into_iter().next())
                    .map(|nrf| nrf.uri);
                require_oauth2 = sbi
                    .oauth2
                    .and_then(|oauth2| oauth2.require)
                    .unwrap_or(false);
            }
        }
    }
    if let Some(uri) = &nrf_uri_cfg {
        log::info!("NRF URI configured: {uri}");
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(uri)
            .await;
    }
    // #2123 (R41 M1): the self instance, as the other NFs register it, so the
    // shared verified-NF-type lookup names this UDR as its requester
    // (`requester-nf-type`, mandatory in TS 29.510: nrfd answers 400 without it).
    register_self_instance().await;

    // Build SBI server configuration (legacy, for context)
    // #1312: bind CLI, then YAML, then loopback; advertise --sbi-advertise, then
    // NEXTGCORE_SBI_ADVERTISE, then the YAML advertise, then the bind (never a wildcard).
    let sbi = nextgcore_core::sockaddr::SbiEndpoint::resolve(
        args.sbi_addr.as_deref(),
        args.sbi_port,
        args.sbi_advertise.as_deref(),
        yaml_sbi.address.as_deref(),
        yaml_sbi.port,
        yaml_sbi.advertise.as_deref(),
        7777,
    );
    let sbi_config = SbiServerConfig {
        addr: sbi.host.clone(),
        port: sbi.port,
        // #1795: the listener below serves TLS under `--tls` or the production
        // profile, so what this NF publishes says so too.
        tls_enabled: args.tls || nextgcore_sbi::security::SbiProfile::resolve().is_production(),
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open legacy SBI context (for context initialization)
    udr_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr = nextgcore_core::sockaddr::parse_listen_addr(&sbi.host, sbi.port)
        .context("Invalid SBI address")?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    nextgcore_core::sockaddr::warn_if_loopback_listener(
        "SBI",
        &sbi_addr,
        "--sbi-addr (or udr.sbi.server[0].address in the config file)",
    );
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);
    // #1795: `--tls` reaches the listener it advertises (under `dev`; the
    // profile's certificate wins under `production`).
    if args.tls {
        sbi_server_config = sbi_server_config.with_tls(
            args.tls_key
                .as_deref()
                .unwrap_or("/etc/nextgcore/tls/server.key"),
            args.tls_cert
                .as_deref()
                .unwrap_or("/etc/nextgcore/tls/server.crt"),
        );
    }
    // #1665: the outbound token client follows the SBI security profile as well
    // as the knob. The production profile's AMF/AUSF/SMF/UDM demand a token on
    // every service request (TS 33.501 §13.4.1.1.2), whatever this listener asks.
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    let _ = OAUTH2_CLIENT.set(outbound_oauth2_client(
        sbi_profile,
        require_oauth2,
        nrf_uri_cfg.as_deref(),
    ));
    // #1667: the same client gives this NF's own NRF calls their access token.
    nextgcore_sbi::nrf_tls::set_nrf_oauth2_client(OAUTH2_CLIENT.get().cloned().flatten());
    if require_oauth2 {
        // Verify bearer tokens against the NRF's published keys (auth stage
        // 4b). With no NRF URI configured the server fails closed.
        sbi_server_config = udr_oauth2_listener(sbi_server_config);
        sbi_server_config.oauth2_jwks_uri = nrf_uri_cfg
            .as_deref()
            .map(|uri| JwksCache::for_nrf(uri).jwks_uri().to_string());
        log::info!(
            "OAuth2 enforcement enabled (JWKS: {})",
            sbi_server_config
                .oauth2_jwks_uri
                .as_deref()
                .unwrap_or("UNCONFIGURED")
        );
    }
    // #1795: the listener follows the SBI security profile.
    let sbi_server_config = sbi_listener_config(
        sbi_server_config,
        sbi_profile,
        &nextgcore_sbi::security::SbiSecurityPolicy::for_profile(sbi_profile),
        nrf_uri_cfg.as_deref().unwrap_or_default(),
    )
    .map_err(|e| anyhow::anyhow!("SBI security profile: {e}"))?;
    // #1791: the NFProfile advertises the scheme this listener serves.
    let sbi_scheme = sbi_server_config.scheme;
    let sbi_server = SbiServer::new(sbi_server_config);

    sbi_server
        .start(udr_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // #1775: report provisioning changes of a watched UE's am-data.
    spawn_am_data_watch();

    // #1334: the Prometheus endpoint, on NEXTGCORE_METRICS_BIND (loopback by default,
    // #837) and UDR_METRICS_PORT (9090). Non-fatal, like smfd's.
    let _metrics = nextgcore_metrics::nf::serve_nf_metrics(
        "UDR",
        "UDR_METRICS_PORT",
        Arc::new(nextgcore_udrd::metrics::render_prometheus),
    )
    .await;

    // Register with NRF and start heartbeat worker. #1482: a failed attempt is
    // retried in the background, and the heartbeat starts after the one that
    // succeeds.
    match sbi.registration_host() {
        Ok(host) => {
            let (host, port) = (host.to_string(), sbi.port);
            nextgcore_sbi::heartbeat::register_or_retry(
                "UDR",
                Default::default(),
                move || {
                    let host = host.clone();
                    async move {
                        register_with_nrf(&host, port, sbi_scheme)
                            .await
                            .map(nextgcore_sbi::heartbeat::registered_id)
                    }
                },
                |nf_instance_id| {
                    // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
                    // (tracked subscribers, saturated at 100; TS 29.510 §5.2.2.3.2).
                    nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                        nf_instance_id,
                        5,
                        || {
                            let ctx = nextgcore_udrd::context::udr_self();
                            let load = ctx.read().map(|c| c.get_load()).unwrap_or(0);
                            load.clamp(0, 100) as u8
                        },
                    );
                },
            )
            .await;
        }
        Err(e) => log::warn!("NRF registration not attempted (will operate without NRF): {e}"),
    }

    log::info!("NextGCore UDR ready");

    // Main event loop (async)
    run_event_loop_async(shutdown).await?;

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
    udr_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    udr_sm.fini();
    log::info!("UDR state machine finalized");

    // Cleanup context
    udr_context_final();
    log::info!("UDR context finalized");

    // Cleanup database
    nextgcore_dbi::nextgcore_dbi_final();

    log::info!("NextGCore UDR stopped");
    Ok(())
}

/// #2123 (R41 M1): record this UDR as the global context's self NF instance
/// (its NF Instance ID, type UDR). The shared NRF lookup of a caller's type
/// (`owner_binding::verified_nf_type`) sends it as `requester-nf-type`.
async fn register_self_instance() {
    let id = nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Udr);
    nextgcore_sbi::context::global_context()
        .set_self_instance(nextgcore_sbi::context::NfInstance::new(
            id,
            nextgcore_sbi::types::NfType::Udr,
        ))
        .await;
}

/// #2079: the NF types that write the UDM's context data in the UDR: the
/// NF-registration documents (TS 29.505 §5.2.6.1 "AMF registrations to be
/// stored in the UDR by the UDM", §5.2.7-§5.2.12), the authentication status
/// (§5.2.24, §5.2.24A, the AuthEvent of Nudm_UEAU ConfirmAuth) and the UDM's own
/// SDM / EE subscriptions (§5.2.16-§5.2.19). TS 23.501 §6.2.11: the UDR stores
/// and retrieves "subscription data by the UDM".
const UDM_CONTEXT_WRITER_NF_TYPES: &[&str] = &["UDM"];

/// #2079: why `request`, a write of the UDM's context data, may not be applied,
/// or `None` if it may (or is not such a write). TS 29.504 §5.2.1.2: the UDR
/// authorizes per data set and answers an illegal data access with an explicit
/// cause.
///
/// Which writes: those [`nextgcore_sbi::resource_scope::required_resource_scope`]
/// puts under `nudr-dr:subscription-data` or `...:registrations:write`, the
/// same table the SBI server's scope gate and every consumer's token request
/// read. GETs are not touched.
///
/// The caller is read only from what this process verified, in this order:
/// 1. a certificate and token naming different NF instances
///    (`owner_binding::verified_consumer_id`): refused;
/// 2. a verified access token's scope must carry the resource scope
///    (`token_grants`), which the NRF grants to the UDM alone
///    (`UDR_RESOURCE_SCOPES`, TS 29.510 NOTE 11): else 403 `insufficient_scope`;
/// 3. under the `dev` SBI profile (plaintext, nothing to verify) a caller with
///    no token and no certificate typing it is admitted;
/// 4. otherwise the shared rule `owner_binding::verified_nf_type(.., Udm)`
///    (#2099, #2113) decides: the consumer's own certificate naming NF types
///    must name UDM -- a certificate naming a relay type plus another type,
///    `[SCP, PCF]`, is that consumer's and not a relay's -- else the NRF must
///    list the verified token subject (direct, or relayed by an SCP or SEPP,
///    TS 33.501 §13.3) as a UDM, and a typeless certificate with no token, an
///    anonymous caller or a failed lookup is refused.
///
/// A direct typed certificate is decided without an `.await` that yields, so
/// such a refusal completes on its first poll.
async fn udm_context_write_refusal(request: &SbiRequest, production: bool) -> Option<SbiResponse> {
    use nextgcore_sbi::owner_binding;
    use nextgcore_sbi::resource_scope::{
        required_resource_scope, token_grants, NUDR_DR_REGISTRATIONS_WRITE,
        NUDR_DR_SUBSCRIPTION_DATA,
    };
    let scope = match required_resource_scope(&request.header.method, &request.header.uri) {
        Some(s) if s == NUDR_DR_SUBSCRIPTION_DATA || s == NUDR_DR_REGISTRATIONS_WRITE => s,
        _ => return None,
    };
    let refuse = |detail: String| {
        // debug, not warn: a peer can send these at will (#1620 review m7).
        log::debug!("UDM context write refused: {detail}");
        Some(nextgcore_sbi::server::send_forbidden(&detail, None))
    };
    if let Err(why) = owner_binding::verified_consumer_id(request) {
        return refuse(why);
    }
    if let Some(granted) = request.oauth2_scope.as_deref() {
        if !token_grants(granted, scope) {
            // The scope is a constant, but it is derived from the request URI, which
            // the #1018 log lint treats as a callback URI: the 403 body names it.
            log::debug!("UDM context write refused: the token lacks the resource scope");
            return Some(
                nextgcore_sbi::server::BearerRefusal::InsufficientScope {
                    scope: scope.to_string(),
                    detail: format!(
                        "the access token's scope does not include {scope}, which this \
                         resource requires in addition to the service scope"
                    ),
                }
                .into_response(),
            );
        }
    }
    let types = &request.peer_cert_nf_types;
    let typed_certificate = !types.is_empty() && !owner_binding::is_relay_certificate(types);
    let token = request
        .oauth2_subject
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    if !production && !token && !typed_certificate {
        return None;
    }
    match owner_binding::verified_nf_type(request, nextgcore_sbi::types::NfType::Udm).await {
        Ok(()) => None,
        Err(why) => refuse(format!(
            "only the UDM writes this subscription-data context resource (TS 29.505): {why}"
        )),
    }
}

/// SBI request handler for UDR
async fn udr_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    // #2079: a write of the UDM's context data from any other NF is refused
    // before anything is routed, counted, stored or notified.
    if let Some(refused) = udm_context_write_refusal(&request, production_profile()).await {
        return refused;
    }
    // #1334: Nudr operations, counted by outcome.
    let operation = nextgcore_udrd::metrics::classify(&request.header.method, &request.header.uri);
    let response = udr_sbi_route(request).await;
    if let Some(op) = operation {
        nextgcore_udrd::metrics::observe(op, response.status);
    }
    response
}

async fn udr_sbi_route(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!(
        "UDR SBI request: {method} {uri}",
        uri = nextgcore_sbi::log_redact::redact_callback_tokens(uri)
    );

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Expected paths:
    // /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription
    // /nudr-dr/v2/subscription-data/{supi}/provisioned-data/{dataset}
    // /nudr-dr/v2/subscription-data/{supi}/{plmn}/provisioned-data/{dataset}
    // /nudr-dr/v2/policy-data/ues/{supi}/{resource}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];

    // #87: Nudr_GroupIDmap is a distinct service, not a nudr-dr resource.
    if service == "nudr-group-id-map" {
        return handle_group_id_map(&parts, method, &request);
    }

    if service != "nudr-dr" {
        log::warn!("Unknown service: {service}");
        return send_not_found(&format!("Unknown service: {service}"), None);
    }

    // Route based on resource type
    let resource_type = parts.get(2).copied().unwrap_or("");

    match resource_type {
        "subscription-data" if parts.get(3).copied() == Some("subs-to-notify") => {
            handle_subscription_data_subs(&parts, method, &request).await
        }
        "subscription-data" => handle_subscription_data(&parts, method, &request).await,
        "policy-data" => handle_policy_data(&parts, method, &request).await,
        "exposure-data" => handle_exposure_data(&parts, method, &request).await,
        "application-data" => handle_application_data(&parts, method, &request).await,
        _ => {
            log::warn!(
                "Unknown UDR resource: {method} {uri}",
                uri = nextgcore_sbi::log_redact::redact_callback_tokens(uri)
            );
            send_not_found(&format!("Unknown resource: {resource_type}"), None)
        }
    }
}

/// #1903 review M1 / M2 (DECISIONS 2026-11-18): the subscription owner
/// binding, hardened for the production SBI profile, where udrd's listener does
/// not itself demand a token (`udr.sbi.oauth2.require` defaults off).
///
/// Under production a Subscribe with no verified identity is refused `403`
/// before anything is stored, so every new subscription has an owner; and an
/// ownerless subscription (restored from a state file written before #1861) is
/// frozen: nobody may read, modify or delete it, and it ends on its expiry or
/// on a callback 404. A UDR subscription may come from any of several NF types,
/// so the first verified caller is NOT adopted: with the sequential IDs those
/// records carry, adoption would hand them to whoever guessed first. Under
/// `dev` both behave as before.
fn production_profile() -> bool {
    nextgcore_sbi::security::SbiProfile::resolve().is_production()
}

/// [`nextgcore_udrd::owner_binding::owner_for_new_resource`], refusing an
/// anonymous Subscribe under production (#1903 review M1).
fn owner_for_new_subscription(
    request: &SbiRequest,
    operation: &str,
) -> Result<Option<String>, Box<SbiResponse>> {
    owner_for_new_subscription_in(request, operation, production_profile())
}

fn owner_for_new_subscription_in(
    request: &SbiRequest,
    operation: &str,
    production: bool,
) -> Result<Option<String>, Box<SbiResponse>> {
    // #1865: the shared helper with this function's explicit policy, so the
    // `_in` tests do not depend on the process-wide profile.
    match nextgcore_udrd::owner_binding::owner_for_new_resource_with(request, operation, false)? {
        None if production => {
            let why = "the requester has no verified identity (no access token subject and no \
                       client certificate NF Instance ID); under the production SBI profile \
                       every subscription is bound to its creator (TS 33.501 §13.4.1)";
            log::debug!("{operation} refused: {why}");
            Err(Box::new(nextgcore_sbi::server::send_forbidden(
                &format!("{operation}: {why}"),
                None,
            )))
        }
        owner => Ok(owner),
    }
}

/// [`nextgcore_udrd::owner_binding::non_owner_refusal`], with an ownerless
/// subscription frozen under production (#1903 review M2).
fn subscription_caller_refusal(owner: Option<&str>, request: &SbiRequest) -> Option<String> {
    subscription_caller_refusal_in(owner, request, production_profile())
}

fn subscription_caller_refusal_in(
    owner: Option<&str>,
    request: &SbiRequest,
    production: bool,
) -> Option<String> {
    if owner.is_none() && production {
        return Some(
            "the subscription predates its owner binding and is frozen under the production \
             SBI profile; it ends on its expiry"
                .to_string(),
        );
    }
    nextgcore_udrd::owner_binding::non_owner_refusal_with(owner, request, production)
}

/// [`subscription_caller_refusal`] as the `403` to send.
fn refuse_subscription_caller(
    owner: Option<&str>,
    request: &SbiRequest,
    operation: &str,
) -> Option<SbiResponse> {
    let why = subscription_caller_refusal(owner, request)?;
    log::debug!("{operation} refused: {why}");
    Some(nextgcore_sbi::server::send_forbidden(
        &format!("{operation}: {why}"),
        None,
    ))
}

/// 400 ProblemDetails for a missing mandatory attribute.
/// #1861 (TS 29.504 §5.2, TS 29.519 §5.2, TS 33.501 §13.4.1): the
/// subscription `id` of `kind`, if the caller may act on it. `404` when there is
/// none of that kind (a PolicyData id is not reachable through the exposure-data
/// path), `403` when it belongs to another NF. Checked before the body is used,
/// so a refusal changes nothing.
fn sub_for_caller(
    id: &str,
    kind: SubKind,
    request: &SbiRequest,
    operation: &str,
) -> Result<data_store::StoredSub, Box<SbiResponse>> {
    let sub = data_store::store()
        .sub_get(id)
        .filter(|s| s.kind == kind)
        .ok_or_else(|| {
            Box::new(send_not_found(
                "Subscription not found",
                Some("DATA_NOT_FOUND"),
            ))
        })?;
    match refuse_subscription_caller(sub.owner.as_deref(), request, operation) {
        Some(refused) => Err(Box::new(refused)),
        None => Ok(sub),
    }
}

fn missing_mandatory(attr: &str) -> SbiResponse {
    send_error(
        400,
        "Bad Request",
        &format!("Missing mandatory attribute: {attr}"),
        Some("MANDATORY_IE_MISSING"),
    )
}

/// Parse a JSON request body, or produce a 400 ProblemDetails.
fn parse_json_body(request: &SbiRequest) -> Result<serde_json::Value, Box<SbiResponse>> {
    let content = request.http.content.as_deref().ok_or_else(|| {
        Box::new(send_bad_request(
            "Missing request body",
            Some("MANDATORY_IE_MISSING"),
        ))
    })?;
    serde_json::from_str(content).map_err(|e| {
        Box::new(send_bad_request(
            &format!("Invalid JSON: {e}"),
            Some("INVALID_MSG_FORMAT"),
        ))
    })
}

/// Minimal percent-decoding for query parameter values.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // Octet-wise: slicing `&s[i + 1..i + 3]` panicked when the cut landed
        // inside a multi-byte character, and from_str_radix took `%+1` as
        // 0x01 (#765).
        if bytes[i] == b'%' {
            let digit = |j: usize| bytes.get(j).and_then(|b| (*b as char).to_digit(16));
            if let (Some(h), Some(l)) = (digit(i + 1), digit(i + 2)) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Handle subscription-data requests
/// Path: /nudr-dr/v2/subscription-data/{supi}/...
async fn handle_subscription_data(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    // parts[3] = {supi} or {suci}
    let supi_or_suci = match parts.get(3) {
        Some(s) => *s,
        None => return send_bad_request("Missing SUPI", Some("MISSING_SUPI")),
    };

    // identity-data is defined for ANY VarUeId, SUPI or GPSI (TS 29.505
    // §5.2.19 "Retrieve identity data by SUPI or GPSI") -- resolving a GPSI is
    // the whole point of the resource -- so it is dispatched before the
    // SUPI-shaped validation below, which would reject `msisdn-`/`extid-`.
    if parts.get(4).copied() == Some("identity-data") {
        return handle_identity_data(supi_or_suci, method, request).await;
    }

    // Convert SUCI to IMSI if needed
    // SUCI format: suci-{type}-{mcc}-{mnc}-{routing}-{scheme}-{msin}
    // For null scheme (0), IMSI = MCC + MNC + MSIN
    let supi = if supi_or_suci.starts_with("suci-") {
        let suci_parts: Vec<&str> = supi_or_suci.split('-').collect();
        if suci_parts.len() >= 7 && suci_parts[1] == "0" {
            let mcc = suci_parts[2];
            let mnc = suci_parts[3];
            let msin = suci_parts[6..].join("");
            let imsi = format!("imsi-{mcc}{mnc}{msin}");
            log::info!("Converted SUCI {supi_or_suci} -> SUPI {imsi}");
            imsi
        } else {
            log::warn!("Unsupported SUCI format: {supi_or_suci}");
            return send_bad_request(
                &format!("Unsupported SUCI: {supi_or_suci}"),
                Some("INVALID_SUCI"),
            );
        }
    } else if supi_or_suci.starts_with("imsi-") {
        supi_or_suci.to_string()
    } else if supi_or_suci.starts_with("nai-")
        || supi_or_suci.starts_with("gci-")
        || supi_or_suci.starts_with("gli-")
    {
        // TS 29.571 VarUeId forms: NAI / GCI / GLI are spec-valid identifiers
        // but are not backed by the subscriber DB in this UDR instance.
        // Return 404 NOT_FOUND (not 400) so the caller knows the form is
        // syntactically valid but not provisioned (udrd-06).
        log::info!("VarUeId form not in subscriber DB, returning 404: {supi_or_suci}");
        return send_not_found(
            &format!("VarUeId form not in subscriber DB: {supi_or_suci}"),
            Some("NOT_FOUND"),
        );
    } else if supi_or_suci.starts_with("extgroupid-") {
        // TS 29.571 external group identifiers target group subscriptions;
        // not supported in this Nudr_DataRepository instance (udrd-06).
        return send_error(
            501,
            "Not Implemented",
            "External group identifiers (extgroupid-) are not supported",
            Some("NOT_SUPPORTED"),
        );
    } else {
        log::warn!("Invalid SUPI type: {supi_or_suci}");
        return send_bad_request(
            &format!("Invalid SUPI type: {supi_or_suci}"),
            Some("INVALID_SUPI"),
        );
    };
    let supi = supi.as_str();

    // Determine sub-resource: parts[4] could be "authentication-data" or "provisioned-data"
    // or a PLMN ID (then parts[5] = "provisioned-data")
    let sub_resource = parts.get(4).copied().unwrap_or("");

    match sub_resource {
        "authentication-data" => handle_auth_data(supi, parts, method, request).await,
        "provisioned-data" => handle_provisioned_data(supi, parts, 5, method, request).await,
        "context-data" => handle_context_data(supi, parts, method, request).await,
        // #87: the Parameter Provision documents the UDM's Nudm_PP producer
        // reads and writes (TS 29.505 §5.2.13).
        "pp-data" => handle_pp_data(supi, method, request),
        "pp-data-store" => {
            let af_instance_id = parts.get(5).copied().unwrap_or("");
            handle_pp_data_store(supi, af_instance_id, method, request)
        }
        _ => {
            // Check if parts[4] is a PLMN ID and parts[5] = "provisioned-data"
            // (PLMN-scoped layout per TS 29.504:
            //  /subscription-data/{ueId}/{servingPlmnId}/provisioned-data/...)
            if parts.get(5).copied() == Some("provisioned-data") {
                if !is_valid_plmn_id(sub_resource) {
                    return send_error(
                        400,
                        "Bad Request",
                        &format!("Invalid servingPlmnId: {sub_resource}"),
                        Some("MANDATORY_IE_INCORRECT"),
                    );
                }
                handle_provisioned_data(supi, parts, 6, method, request).await
            } else if parts.get(5).copied() == Some("context-data") {
                handle_context_data(supi, parts, method, request).await
            } else {
                log::warn!("Unknown subscription-data sub-resource: {sub_resource}");
                send_not_found("Unknown sub-resource", None)
            }
        }
    }
}

/// `GET /subscription-data/{ueId}/identity-data` — TS 29.505 §5.2.19.
///
/// Answers in BOTH directions from the one subscriber record, because that is
/// what the resource is for: `{ueId}` may be a SUPI or a GPSI, and the response
/// carries `supiList` and `gpsiList` regardless. The subscriber DB query is
/// `{<idType>: <idValue>}` over a single document, so an `msisdn-` identifier
/// resolves the same subscriber as its `imsi-` — which is what lets a NEF
/// translate a GPSI it was given by an AF into the SUPI every other 5GC
/// interface needs.
async fn handle_identity_data(ue_id: &str, method: &str, request: &SbiRequest) -> SbiResponse {
    if method != "GET" {
        return send_method_not_allowed(method, "identity-data");
    }
    let _ = request;
    log::info!("[{ue_id}] GET identity-data");
    // GCI/GLI are valid VarUeId forms the subscriber DB does not hold: 404, as on
    // the other subscription-data resources (udrd-06).
    if ue_id.starts_with("gci-") || ue_id.starts_with("gli-") {
        return send_not_found(
            &format!("VarUeId form not in subscriber DB: {ue_id}"),
            Some("NOT_FOUND"),
        );
    }
    match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(ue_id.to_string())
        .await
    {
        Ok(data) => {
            let doc = build_identity_data(&data);
            // supiList is what a consumer translating a GPSI needs; a record
            // with no SUPI cannot answer the question that was asked.
            if doc
                .get("supiList")
                .and_then(|v| v.as_array())
                .is_none_or(|a| a.is_empty())
            {
                return send_not_found(
                    "No SUPI stored for this identifier",
                    Some("DATA_NOT_FOUND"),
                );
            }
            SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
        }
        Err(e) => store_read_failure(ue_id, "identity-data", &e),
    }
}

/// #1534: whether a subscriber-store error is the store failing (unreachable,
/// never opened, a driver or decode error) rather than an answer about the
/// subscriber or the request.
fn store_error_is_outage(e: &nextgcore_dbi::DbiError) -> bool {
    use nextgcore_dbi::DbiError;
    !matches!(
        e,
        DbiError::SubscriberNotFound(_)
            | DbiError::FieldNotFound(_)
            | DbiError::SessionNotFound
            | DbiError::InvalidSupi(_)
            | DbiError::UnsupportedUeIdType(_)
    )
}

/// #1534: `500 SYSTEM_FAILURE` (TS 29.500 Table 5.2.7.2-1) for a store outage. A
/// 404 would tell the consumer the user does not exist (TS 29.504 Table
/// 6.1.7.3-1 `USER_NOT_FOUND`), and a UDM / AUSF would reject the UE rather than
/// retry.
fn store_outage(ue_id: &str, what: &str, e: &nextgcore_dbi::DbiError) -> SbiResponse {
    log::error!("[{ue_id}] {what}: the subscriber store failed: {e}");
    send_error(
        500,
        "Internal Server Error",
        "Subscriber store unavailable",
        Some("SYSTEM_FAILURE"),
    )
}

/// #1534: the answer for a failed subscriber-store read: the 400 of
/// [`ue_id_rejection`], `500 SYSTEM_FAILURE` for an outage ([`store_outage`]),
/// `404 USER_NOT_FOUND` for an unknown subscriber (TS 29.504 Table 6.1.7.3-1),
/// and `404 DATA_NOT_FOUND` for data the subscriber's record lacks.
fn store_read_failure(ue_id: &str, what: &str, e: &nextgcore_dbi::DbiError) -> SbiResponse {
    if let Some(resp) = ue_id_rejection(e) {
        return resp;
    }
    if store_error_is_outage(e) {
        return store_outage(ue_id, what, e);
    }
    log::debug!("[{ue_id}] {what}: {e}");
    match e {
        nextgcore_dbi::DbiError::SubscriberNotFound(_) => {
            send_not_found("Subscriber not found", Some("USER_NOT_FOUND"))
        }
        _ => send_not_found("Subscriber data not found", Some("DATA_NOT_FOUND")),
    }
}

/// The 400 for a `{ueId}` the subscriber store cannot be queried by, `None` for
/// any other lookup failure.
///
/// The type prefix is checked once, in `nextgcore_dbi::nextgcore_ue_id_key`; this
/// only maps that request error to the consumer's fault rather than a 404 or 5xx.
fn ue_id_rejection(e: &nextgcore_dbi::DbiError) -> Option<SbiResponse> {
    match e {
        nextgcore_dbi::DbiError::UnsupportedUeIdType(_)
        | nextgcore_dbi::DbiError::InvalidSupi(_) => Some(send_bad_request(
            "Unsupported ueId type",
            Some("MANDATORY_IE_INCORRECT"),
        )),
        _ => None,
    }
}

/// Build a TS 29.505 `IdentityData` from a subscriber record.
///
/// `supiList` carries the record's IMSI in `imsi-` form and `gpsiList` its GPSIs
/// ([`subscriber_gpsis`]) — the same GPSI spelling `am-data` uses, so a consumer
/// sees one identity vocabulary across both resources. Both members have
/// `minItems: 1`, so an empty list is omitted rather than emitted empty.
fn build_identity_data(
    data: &nextgcore_dbi::types::NextgcoreSubscriptionData,
) -> serde_json::Value {
    let mut doc = serde_json::Map::new();
    if let Some(imsi) = data.imsi.as_deref() {
        doc.insert(
            "supiList".to_string(),
            serde_json::json!([format!("imsi-{imsi}")]),
        );
    }
    let gpsis = subscriber_gpsis(data);
    if !gpsis.is_empty() {
        doc.insert("gpsiList".to_string(), serde_json::Value::Array(gpsis));
    }
    serde_json::Value::Object(doc)
}

/// A subscriber's GPSIs in TS 29.571 `Gpsi` form: each MSISDN as `msisdn-<digits>`,
/// then each External Identifier as `extid-<username@realm>` (nextgsim#480).
///
/// One list for `identity-data`'s `gpsiList` and `am-data`'s `gpsis`, so the two
/// resources cannot disagree about who the subscriber is. The External
/// Identifiers are what a NEF hands an AF (TS 23.502 §4.15.10 steps 9-10, via the
/// UDM's `requested-gpsi-type=EXT_ID`), and the AF names the UE by them in a T8
/// request, which the UDM then resolves back through `identity-data` keyed by
/// that `extid-` GPSI.
fn subscriber_gpsis(
    data: &nextgcore_dbi::types::NextgcoreSubscriptionData,
) -> Vec<serde_json::Value> {
    // `num_of_msisdn` gates the MSISDNs, as it always has here.
    let msisdns = if data.num_of_msisdn > 0 {
        data.msisdn.as_slice()
    } else {
        &[]
    };
    msisdns
        .iter()
        .map(|m| format!("msisdn-{}", m.bcd))
        .chain(data.external_ids.iter().map(|e| format!("extid-{e}")))
        .map(serde_json::Value::String)
        .collect()
}

/// `GET`/`PATCH /subscription-data/{ueId}/pp-data` — TS 29.505 §5.2.13.
///
/// The UE-level Parameter Provision document. A `PUT` is accepted as well as
/// PATCH so an operator (or the webui) can provision the document in one step;
/// TS 29.505 defines GET and PATCH, and PATCH on an absent document would
/// otherwise have no way to ever start.
fn handle_pp_data(supi: &str, method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = data_store::store();
    let path = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data");
    match method {
        "GET" => match ds.doc_get("pp-data", supi) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No pp-data provisioned", Some("DATA_NOT_FOUND")),
        },
        "PUT" => {
            let doc = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put("pp-data", supi, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            // An absent document starts empty rather than 404ing: PATCH is the
            // provisioning verb TS 29.503 §5.6.2.2 gives an AF, and refusing the
            // first provision would leave it with no way to create one.
            let mut doc = ds
                .doc_get("pp-data", supi)
                .unwrap_or_else(|| serde_json::json!({}));
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put("pp-data", supi, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            if ds.doc_remove("pp-data", supi).is_some() {
                notify_subscription_data_change(supi, &path, None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "pp-data"),
    }
}

/// `PUT`/`GET`/`DELETE /subscription-data/{ueId}/pp-data-store/{afInstanceId}` —
/// TS 29.505 §5.2.13, the per-AF Parameter Provision entry. The collection GET
/// returns every AF's entry for the UE.
fn handle_pp_data_store(
    supi: &str,
    af_instance_id: &str,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    let prefix = format!("{supi}\u{1f}");
    let key = format!("{prefix}{af_instance_id}");
    let path = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data-store/{af_instance_id}");
    match (af_instance_id.is_empty(), method) {
        (true, "GET") => {
            let list: Vec<serde_json::Value> = ds
                .doc_list("pp-data-store")
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v)
                .collect();
            SbiResponse::with_status(200).with_body(
                serde_json::Value::Array(list).to_string(),
                "application/json",
            )
        }
        (false, "GET") => match ds.doc_get("pp-data-store", &key) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No pp-data entry for this AF", Some("DATA_NOT_FOUND")),
        },
        (false, "PUT") => {
            let doc = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put("pp-data-store", &key, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        (false, "DELETE") => {
            if ds.doc_remove("pp-data-store", &key).is_some() {
                notify_subscription_data_change(supi, &path, None);
                SbiResponse::with_status(204)
            } else {
                send_not_found("No pp-data entry for this AF", Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, "pp-data-store"),
    }
}

/// VarPlmnId per TS 29.505: 5 or 6 digits (MCC+MNC).
fn is_valid_plmn_id(s: &str) -> bool {
    (s.len() == 5 || s.len() == 6) && s.bytes().all(|b| b.is_ascii_digit())
}

/// Handle authentication-data requests
/// Path: /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription
async fn handle_auth_data(
    supi: &str,
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let resource = parts.get(5).copied().unwrap_or("");

    match (resource, method) {
        ("authentication-subscription", "GET") => {
            log::info!("[{supi}] GET authentication-subscription");

            match nextgcore_dbi::subscription::nextgcore_dbi_auth_info_async(supi.to_string()).await
            {
                Ok(auth_info) => {
                    let response_json = build_auth_subscription_json(supi, &auth_info);
                    log::info!("[{supi}] Returning auth subscription data");
                    SbiResponse::with_status(200)
                        .with_body(response_json.to_string(), "application/json")
                }
                Err(e) => store_read_failure(supi, "authentication-subscription", &e),
            }
        }
        ("authentication-subscription", "PUT") => {
            // Provisioning path: create/replace the stored
            // AuthenticationSubscription credentials.
            log::info!("[{supi}] PUT authentication-subscription");
            let body = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            let auth_method = match body.get("authenticationMethod").and_then(|v| v.as_str()) {
                Some(m) => m.to_string(),
                None => return missing_mandatory("authenticationMethod"),
            };
            let k_hex = match body.get("encPermanentKey").and_then(|v| v.as_str()) {
                Some(k) if k.len() == 32 && k.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    k.to_string()
                }
                Some(_) => {
                    return send_error(
                        400,
                        "Bad Request",
                        "encPermanentKey must be 32 hex characters",
                        Some("MANDATORY_IE_INCORRECT"),
                    )
                }
                None => return missing_mandatory("encPermanentKey"),
            };
            let provision = nextgcore_dbi::subscription::NextgcoreDbiAuthProvision {
                k_hex,
                opc_hex: body
                    .get("encOpcKey")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                op_hex: None,
                amf_hex: body
                    .get("authenticationManagementField")
                    .and_then(|v| v.as_str())
                    .unwrap_or("8000")
                    .to_string(),
                sqn: body
                    .get("sequenceNumber")
                    .and_then(|v| v.get("sqn"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .unwrap_or(0),
                auth_method,
                // #115: TS 29.505 `algorithmId` and `encTopcKey`. Both optional, both
                // stored verbatim — `algorithmId` because the spec makes its values
                // HPLMN-operator specific and the UDR is not the component that
                // interprets them, `encTopcKey` because it is opaque key material.
                //
                // Validated for LENGTH and hex-ness though, like `encPermanentKey`
                // above: a TOPc that is not 32 bytes cannot be used by TUAK at all, and
                // discovering that at authentication time turns a provisioning mistake
                // into an outage. `top` is accepted under the same rule so an operator
                // can provision TOP and let the UDR derive TOPc (TS 35.231 §7.1).
                algorithm_id: body
                    .get("algorithmId")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
                topc_hex: match validate_optional_key_256(&body, "encTopcKey") {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                },
                top_hex: match validate_optional_key_256(&body, "top") {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                },
            };
            match nextgcore_dbi::subscription::nextgcore_dbi_provision_auth_info_async(
                supi.to_string(),
                provision,
            )
            .await
            {
                Ok(created) => {
                    let path = format!(
                        "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
                    );
                    notify_subscription_data_change(supi, &path, Some(&body));
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(204)
                    }
                }
                Err(nextgcore_dbi::DbiError::NotInitialized) => send_error(
                    503,
                    "Service Unavailable",
                    "Subscriber database unavailable",
                    Some("SYSTEM_FAILURE"),
                ),
                Err(e) => {
                    if let Some(resp) = ue_id_rejection(&e) {
                        return resp;
                    }
                    log::error!("[{supi}] DB provision failed: {e:?}");
                    send_error(
                        500,
                        "Internal Server Error",
                        "Failed to provision authentication subscription",
                        Some("SYSTEM_FAILURE"),
                    )
                }
            }
        }
        ("authentication-subscription", "PATCH") => {
            log::info!("[{supi}] PATCH authentication-subscription");

            // TS 29.505 (Nudr subscription-data): PATCH applies the
            // PatchItemList and nothing else — the UDR must store exactly
            // what is written.  SQN generation/advancement is the
            // authentication-centre (UDM/ARPF) function per TS 33.102
            // Annex C.3; udmd already advances the SQN itself before
            // PATCHing the new value (advance_sqn_ind).  The previous
            // unconditional SQN-increment side effect here corrupted every
            // stored SQN by an extra +32 SEQ step (WSB-6).
            // Failures are REPORTED, not swallowed. Previously every path here
            // fell through to 204, so a consumer could not tell an applied
            // patch from a malformed body, an unsupported path, or a database
            // error -- and a non-hex SQN silently became 0 via
            // unwrap_or(0), corrupting the stored value rather than rejecting
            // it. TS 29.505 §5.2.2.x reports failed modifications via
            // PatchResult {report: [ReportItem{path, reason}]} (TS 29.571),
            // and errors carry ProblemDetails (TS 29.500 §5.2.7).
            let Some(content) = &request.http.content else {
                return send_bad_request(
                    "PATCH requires a PatchItem array body",
                    Some("INVALID_MSG_FORMAT"),
                );
            };
            let Ok(patches) = serde_json::from_str::<serde_json::Value>(content) else {
                return send_bad_request("Body is not valid JSON", Some("INVALID_MSG_FORMAT"));
            };
            let Some(arr) = patches.as_array() else {
                return send_bad_request(
                    "Body must be a JSON array of PatchItem",
                    Some("INVALID_MSG_FORMAT"),
                );
            };
            if arr.is_empty() {
                // PatchResult.report is minItems: 1, so an empty patch list can
                // be reported neither as success nor as a failure item.
                return send_bad_request(
                    "PatchItem array must not be empty",
                    Some("INVALID_MSG_FORMAT"),
                );
            }

            // ReportItem.reason should identify the failing operation by its
            // array index (TS 29.571 ReportItem).
            let mut report: Vec<serde_json::Value> = Vec::new();
            let mut applied = 0usize;
            for (idx, patch) in arr.iter().enumerate() {
                let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path != "/sequenceNumber/sqn" {
                    report.push(serde_json::json!({
                        "path": path,
                        "reason": format!(
                            "unsupported path; this UDR applies only \
                             /sequenceNumber/sqn (failed operation index= {idx})"
                        ),
                    }));
                    continue;
                }
                let Some(sqn_hex) = patch.get("value").and_then(|v| v.as_str()) else {
                    report.push(serde_json::json!({
                        "path": path,
                        "reason": format!(
                            "value is absent or not a string \
                             (failed operation index= {idx})"
                        ),
                    }));
                    continue;
                };
                // Reject rather than coerce: the SQN is 48 bits (TS 33.102), so
                // a non-hex or oversized value is a client error, not a 0.
                let sqn = match u64::from_str_radix(sqn_hex, 16) {
                    Ok(v) if v <= 0xFFFF_FFFF_FFFF => v,
                    Ok(_) => {
                        report.push(serde_json::json!({
                            "path": path,
                            "reason": format!(
                                "value exceeds the 48-bit SQN range \
                                 (failed operation index= {idx})"
                            ),
                        }));
                        continue;
                    }
                    Err(_) => {
                        report.push(serde_json::json!({
                            "path": path,
                            "reason": format!(
                                "value is not hexadecimal \
                                 (failed operation index= {idx})"
                            ),
                        }));
                        continue;
                    }
                };
                match nextgcore_dbi::subscription::nextgcore_dbi_update_sqn_async(
                    supi.to_string(),
                    sqn,
                )
                .await
                {
                    Ok(()) => applied += 1,
                    // A storage failure is ours, not the consumer's: surface it
                    // as 5xx immediately rather than as a PatchResult item.
                    Err(nextgcore_dbi::DbiError::NotInitialized) => {
                        return send_error(
                            503,
                            "Service Unavailable",
                            "Subscriber database unavailable",
                            Some("SYSTEM_FAILURE"),
                        );
                    }
                    Err(e) => {
                        if let Some(resp) = ue_id_rejection(&e) {
                            return resp;
                        }
                        log::error!("[{supi}] DB update_sqn failed: {e:?}");
                        return send_error(
                            500,
                            "Internal Server Error",
                            "Failed to store the patched sequence number",
                            Some("SYSTEM_FAILURE"),
                        );
                    }
                }
            }

            if !report.is_empty() {
                log::warn!(
                    "[{supi}] PATCH authentication-subscription: {} of {} items failed",
                    report.len(),
                    arr.len()
                );
                return SbiResponse::with_status(400).with_body(
                    serde_json::json!({ "report": report }).to_string(),
                    "application/json",
                );
            }

            log::info!("[{supi}] PATCH applied {applied} item(s)");
            SbiResponse::with_status(204)
        }
        ("authentication-status", "PUT" | "GET" | "DELETE") => {
            // TS 29.505 §6.3.3 / TS 29.503 §5.4.2: the authentication-status
            // resource carries the AuthEvent the UDM writes on authentication
            // confirmation (TS 33.501 §6.1.4 result storage). It has NO SQN
            // semantics -- an earlier unconditional SQN increment here advanced
            // the stored SQN by an extra +32 SEQ step on every confirmation
            // (WSB-6).
            //
            // The AuthEvent used to be acknowledged with a bare 204 and then
            // DISCARDED, and GET fell through to the catch-all 405 even though
            // TS 29.505 defines PUT/GET/DELETE on both the collection form and
            // the individual .../{servingNetworkName} form. It is now stored.
            //
            // parts[6], when present, is {servingNetworkName}.
            let path_snn = parts.get(6).copied().filter(|s| !s.is_empty());
            handle_auth_status(supi, path_snn, method, request)
        }
        _ => {
            log::warn!("[{supi}] Unknown auth resource: {method} {resource}");
            send_method_not_allowed(
                method,
                &format!("/nudr-dr/v2/subscription-data/{supi}/authentication-data/{resource}"),
            )
        }
    }
}

/// Handle context-data requests
/// Path: /nudr-dr/v2/subscription-data/{supi}/context-data/{resource}
///
/// Implements (TS 29.505 §5.2.4):
/// - GET/PUT/PATCH/DELETE amf-3gpp-access, amf-non-3gpp-access
/// - GET/PUT/PATCH/DELETE smsf-3gpp-access, smsf-non-3gpp-access, ip-sm-gw
/// - GET/PUT/PATCH/DELETE smf-registrations/{pdu-session-id} + collection
/// - CRUD on sdm-subscriptions/{subsId} and ee-subscriptions/{subsId}
async fn handle_context_data(
    supi: &str,
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let resource_idx = if parts.get(4).copied() == Some("context-data") {
        5
    } else {
        6
    };
    let resource = parts.get(resource_idx).copied().unwrap_or("");
    let tail = parts.get(resource_idx + 1).copied().unwrap_or("");

    log::info!("[{supi}] {method} context-data/{resource}");

    match resource {
        "amf-3gpp-access" => {
            handle_amf_access(supi, AmfAccessSlot::ThreeGpp, method, request).await
        }
        // #87 gap 1: this resource returned 404, so non-3GPP AMF registration
        // state could not be stored or read at all -- the store the udmd
        // producer added in #84 writes to.
        "amf-non-3gpp-access" => {
            handle_amf_access(supi, AmfAccessSlot::Non3Gpp, method, request).await
        }
        "smf-registrations" => handle_smf_registrations(supi, method, request, tail),
        // Simple per-UE context documents: one store slot each, same CRUD.
        "smsf-3gpp-access" | "smsf-non-3gpp-access" | "ip-sm-gw" => {
            handle_ue_context_document(supi, resource, method, request)
        }
        // Per-UE subscription collections (TS 29.505 §5.2.4): the UDM's own
        // SDM / EE subscriptions, stored so they survive a UDM restart.
        "sdm-subscriptions" | "ee-subscriptions" => {
            handle_ue_context_collection(supi, resource, tail, method, request)
        }
        _ => {
            log::warn!("[{supi}] Unknown context-data resource: {resource}");
            send_not_found(&format!("Unknown context resource: {resource}"), None)
        }
    }
}

/// Which AMF access-registration document a context-data request addresses.
///
/// The 3GPP slot keeps its dedicated store map (and therefore its snapshot key)
/// while the non-3GPP one lives in the generic document store — the two accesses
/// are distinct resources (TS 29.505 §5.2.4) and a write to one must be
/// invisible to a read of the other, which is exactly the defect #84 fixed on
/// the UDM side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AmfAccessSlot {
    ThreeGpp,
    Non3Gpp,
}

impl AmfAccessSlot {
    fn resource(self) -> &'static str {
        match self {
            Self::ThreeGpp => "amf-3gpp-access",
            Self::Non3Gpp => "amf-non-3gpp-access",
        }
    }

    fn get(self, supi: &str) -> Option<serde_json::Value> {
        let ds = data_store::store();
        match self {
            Self::ThreeGpp => ds.amf_3gpp_get(supi),
            Self::Non3Gpp => ds.doc_get(self.resource(), supi),
        }
    }

    /// Store the document; returns true when newly created.
    fn put(self, supi: &str, doc: serde_json::Value) -> bool {
        let ds = data_store::store();
        match self {
            Self::ThreeGpp => ds.amf_3gpp_put(supi, doc),
            Self::Non3Gpp => ds.doc_put(self.resource(), supi, doc),
        }
    }

    fn remove(self, supi: &str) -> Option<serde_json::Value> {
        let ds = data_store::store();
        match self {
            Self::ThreeGpp => ds.amf_3gpp_remove(supi),
            Self::Non3Gpp => ds.doc_remove(self.resource(), supi),
        }
    }

    fn path(self, supi: &str) -> String {
        context_data_path(supi, self.resource())
    }
}

/// The resource URI of a per-UE context-data document (notification resourceId).
fn context_data_path(supi: &str, resource: &str) -> String {
    format!("/nudr-dr/v2/subscription-data/{supi}/context-data/{resource}")
}

/// CRUD for a single-document per-UE context resource (`smsf-*`, `ip-sm-gw`).
///
/// PATCH is a merge onto the stored document and 404s when there is nothing to
/// patch: applying a patch to an absent resource would invent a registration
/// from a partial update.
fn handle_ue_context_document(
    supi: &str,
    resource: &str,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    let path = context_data_path(supi, resource);
    match method {
        "GET" => match ds.doc_get(resource, supi) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found(
                &format!("{resource} context not found"),
                Some("CONTEXT_NOT_FOUND"),
            ),
        },
        "PUT" => {
            let doc = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put(resource, supi, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            let Some(mut doc) = ds.doc_get(resource, supi) else {
                return send_not_found(
                    &format!("{resource} context not found"),
                    Some("CONTEXT_NOT_FOUND"),
                );
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put(resource, supi, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            if ds.doc_remove(resource, supi).is_some() {
                notify_subscription_data_change(supi, &path, None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, &format!("context-data/{resource}")),
    }
}

/// CRUD for a per-UE context-data COLLECTION (`sdm-subscriptions`,
/// `ee-subscriptions`), whose members are addressed by a subscription id.
///
/// Documents are keyed `{supi}\u{1f}{subsId}` inside the collection so one UE's
/// members list without scanning another's.
fn handle_ue_context_collection(
    supi: &str,
    resource: &str,
    subs_id: &str,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    let prefix = format!("{supi}\u{1f}");
    let key = format!("{prefix}{subs_id}");
    match (subs_id.is_empty(), method) {
        // Collection GET: this UE's members, ordered by id.
        (true, "GET") => {
            let list: Vec<serde_json::Value> = ds
                .doc_list(resource)
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v)
                .collect();
            SbiResponse::with_status(200).with_body(
                serde_json::Value::Array(list).to_string(),
                "application/json",
            )
        }
        // Collection DELETE removes every member for this UE (UE purge).
        (true, "DELETE") => {
            ds.doc_remove_prefix(resource, &prefix);
            SbiResponse::with_status(204)
        }
        (false, "GET") => match ds.doc_get(resource, &key) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("Subscription not found", Some("DATA_NOT_FOUND")),
        },
        (false, "PUT") => {
            let doc = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let path =
                format!("/nudr-dr/v2/subscription-data/{supi}/context-data/{resource}/{subs_id}");
            let created = ds.doc_put(resource, &key, doc.clone());
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        (false, "PATCH") => {
            let Some(mut doc) = ds.doc_get(resource, &key) else {
                return send_not_found("Subscription not found", Some("DATA_NOT_FOUND"));
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put(resource, &key, doc.clone());
            SbiResponse::with_status(204)
        }
        (false, "DELETE") => {
            if ds.doc_remove(resource, &key).is_some() {
                SbiResponse::with_status(204)
            } else {
                send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, &format!("context-data/{resource}")),
    }
}

/// Apply a TS 29.571 patch document to `doc` in place, returning `Some(response)`
/// when the patch itself is malformed.
///
/// Accepts both forms the Nudr resources define: a `PatchItem[]`
/// (`application/json-patch+json`) and a merge-patch object. `remove`/`replace`
/// on an absent member is an error rather than a silent no-op — a consumer
/// patching a path that is not there has a wrong idea of the stored document,
/// and a 204 would confirm it.
fn apply_patch_document(
    doc: &mut serde_json::Value,
    patch: &serde_json::Value,
) -> Option<SbiResponse> {
    if let Some(items) = patch.as_array() {
        for item in items {
            let op = item.get("op").and_then(|v| v.as_str()).unwrap_or("");
            let path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let key = path.trim_start_matches('/');
            if key.is_empty() || key.contains('/') {
                return Some(send_bad_request(
                    &format!("Only top-level attributes are patchable: {path}"),
                    Some("INVALID_MSG_FORMAT"),
                ));
            }
            let Some(obj) = doc.as_object_mut() else {
                return Some(send_bad_request(
                    "Stored document is not an object",
                    Some("INVALID_MSG_FORMAT"),
                ));
            };
            match op {
                "add" => {
                    let Some(value) = item.get("value") else {
                        return Some(missing_mandatory("value"));
                    };
                    obj.insert(key.to_string(), value.clone());
                }
                "replace" => {
                    let Some(value) = item.get("value") else {
                        return Some(missing_mandatory("value"));
                    };
                    if !obj.contains_key(key) {
                        return Some(send_bad_request(
                            &format!("Cannot replace absent attribute: {key}"),
                            Some("INVALID_MSG_FORMAT"),
                        ));
                    }
                    obj.insert(key.to_string(), value.clone());
                }
                "remove" => {
                    if obj.remove(key).is_none() {
                        return Some(send_bad_request(
                            &format!("Cannot remove absent attribute: {key}"),
                            Some("INVALID_MSG_FORMAT"),
                        ));
                    }
                }
                other => {
                    return Some(send_bad_request(
                        &format!("Unsupported patch op: {other}"),
                        Some("INVALID_MSG_FORMAT"),
                    ))
                }
            }
        }
        None
    } else if patch.is_object() {
        merge_patch(doc, patch);
        None
    } else {
        Some(send_bad_request(
            "Invalid patch document",
            Some("INVALID_MSG_FORMAT"),
        ))
    }
}

/// Path of the amf-3gpp-access resource for a SUPI (notification resourceId).
fn amf_3gpp_access_path(supi: &str) -> String {
    context_data_path(supi, "amf-3gpp-access")
}

/// Handle an AMF access registration context for `slot` (TS 29.505 §5.2.4).
///
/// Stores and returns the full `Amf3GppAccessRegistration` /
/// `AmfNon3GppAccessRegistration` document: the shape PUT here by udmd
/// (forwarding the amfd Nudm registration) is preserved verbatim and echoed on
/// GET. The two accesses are separate documents, so a non-3GPP registration
/// cannot be read back as, or overwrite, the 3GPP one.
async fn handle_amf_access(
    supi: &str,
    slot: AmfAccessSlot,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let udr_ctx = nextgcore_udrd::context::udr_self();
    let resource = slot.resource();
    match method {
        "GET" => match slot.get(supi) {
            Some(doc) => {
                log::debug!("[{supi}] GET {resource} - registration found");
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found(
                "AMF registration context not found",
                Some("CONTEXT_NOT_FOUND"),
            ),
        },
        "PUT" => {
            let reg_data = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            // Mandatory attributes per TS 29.503 Amf3GppAccessRegistration.
            // The non-3GPP schema additionally requires imsVoPs.
            for attr in ["amfInstanceId", "deregCallbackUri", "guami", "ratType"] {
                if reg_data.get(attr).is_none() {
                    return missing_mandatory(attr);
                }
            }
            if slot == AmfAccessSlot::Non3Gpp && reg_data.get("imsVoPs").is_none() {
                return missing_mandatory("imsVoPs");
            }
            // Persist the PEI (IMEISV) claim off-thread (last live
            // blocking Mongo call moved to the spawn_blocking wrapper).
            if let Some(pei) = reg_data.get("pei").and_then(|v| v.as_str()) {
                let imeisv = data_store::imeisv_from_pei(pei).to_string();
                if let Err(e) = nextgcore_dbi::subscription::nextgcore_dbi_update_imeisv_async(
                    supi.to_string(),
                    imeisv,
                )
                .await
                {
                    log::debug!("[{supi}] DB update_imeisv unavailable: {e:?}");
                }
            }
            if let Ok(mut ctx) = udr_ctx.write() {
                ctx.ue_find_or_add(supi);
            }
            let created = slot.put(supi, reg_data.clone());
            let path = slot.path(supi);
            notify_subscription_data_change(supi, &path, Some(&reg_data));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(reg_data.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            let Some(mut doc) = slot.get(supi) else {
                return send_not_found(
                    "AMF registration context not found",
                    Some("CONTEXT_NOT_FOUND"),
                );
            };
            let patch_body = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(items) = patch_body.as_array() {
                // PatchItemList (application/json-patch+json)
                for patch in items {
                    let op = patch.get("op").and_then(|v| v.as_str()).unwrap_or("");
                    let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let key = path.trim_start_matches('/');
                    if key.is_empty() || key.contains('/') {
                        continue; // only top-level attributes are patchable here
                    }
                    match op {
                        "replace" | "add" => {
                            if let (Some(obj), Some(value)) =
                                (doc.as_object_mut(), patch.get("value"))
                            {
                                obj.insert(key.to_string(), value.clone());
                            }
                        }
                        "remove" => {
                            if let Some(obj) = doc.as_object_mut() {
                                obj.remove(key);
                            }
                        }
                        _ => {
                            return send_bad_request(
                                &format!("Unsupported patch op: {op}"),
                                Some("INVALID_MSG_FORMAT"),
                            )
                        }
                    }
                }
            } else if patch_body.is_object() {
                // Amf3GppAccessRegistrationModification-style merge
                merge_patch(&mut doc, &patch_body);
            } else {
                return send_bad_request("Invalid patch document", Some("INVALID_MSG_FORMAT"));
            }
            slot.put(supi, doc.clone());
            notify_subscription_data_change(supi, &slot.path(supi), Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            let existed = slot.remove(supi).is_some();
            // The UE tracking entry is shared by both accesses, so it is only
            // dropped once NEITHER access holds a registration -- removing it on
            // a single-access deregistration would forget a UE that is still
            // registered over the other access.
            if AmfAccessSlot::ThreeGpp.get(supi).is_none()
                && AmfAccessSlot::Non3Gpp.get(supi).is_none()
            {
                if let Ok(mut ctx) = udr_ctx.write() {
                    ctx.ue_remove(supi);
                }
            }
            if existed {
                notify_subscription_data_change(supi, &slot.path(supi), None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, &format!("context-data/{resource}")),
    }
}

/// TS 29.505 SmfRegistration mandatory IEs (Table 6.1.6.2.3-1: smfInstanceId,
/// pduSessionId, singleNssai, dnn, plmnId).
const SMF_REGISTRATION_MANDATORY_IES: [&str; 5] = [
    "smfInstanceId",
    "pduSessionId",
    "singleNssai",
    "dnn",
    "plmnId",
];

/// Handle SMF registration context.
///
/// Stores and returns the ACTUAL registered SmfRegistration document (the full
/// PUT body: smfInstanceId, singleNssai, dnn, pduSessionId, plmnId, ...), not a
/// hardcoded summary. Backed by the persistent [`data_store`] so registrations
/// survive a UDR restart.
fn handle_smf_registrations(
    supi: &str,
    method: &str,
    request: &SbiRequest,
    pdu_session_id: &str,
) -> SbiResponse {
    let udr_ctx = nextgcore_udrd::context::udr_self();
    let ds = nextgcore_udrd::data_store::store();
    match method {
        "GET" => {
            if pdu_session_id.is_empty() {
                // Collection GET: every stored registration for the SUPI.
                // Unknown UE -> empty array (TS 29.505), never a panic.
                let registrations = ds.smf_registrations_for_supi(supi);
                SbiResponse::with_status(200).with_body(
                    serde_json::Value::Array(registrations).to_string(),
                    "application/json",
                )
            } else {
                match ds.smf_registration_get(supi, pdu_session_id) {
                    Some(json) => SbiResponse::with_status(200)
                        .with_body(json.to_string(), "application/json"),
                    None => send_not_found("SMF registration not found", Some("CONTEXT_NOT_FOUND")),
                }
            }
        }
        "PUT" => {
            if pdu_session_id.is_empty() {
                return send_bad_request("Missing pduSessionId", Some("MANDATORY_IE_MISSING"));
            }
            // Parse the SmfRegistration document from the request body.
            let Some(content) = request.http.content.as_ref() else {
                return send_bad_request(
                    "Missing SmfRegistration body",
                    Some("MANDATORY_IE_MISSING"),
                );
            };
            let mut doc: serde_json::Value = match serde_json::from_str(content) {
                Ok(v @ serde_json::Value::Object(_)) => v,
                _ => {
                    return send_bad_request(
                        "Invalid SmfRegistration document",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
            };
            // Validate mandatory IEs (TS 29.505 SmfRegistration).
            let missing: Vec<&str> = SMF_REGISTRATION_MANDATORY_IES
                .iter()
                .filter(|ie| match doc.get(**ie) {
                    None | Some(serde_json::Value::Null) => true,
                    Some(serde_json::Value::String(s)) => s.is_empty(),
                    Some(_) => false,
                })
                .copied()
                .collect();
            if !missing.is_empty() {
                return send_bad_request(
                    &format!("Missing mandatory IE(s): {}", missing.join(", ")),
                    Some("MANDATORY_IE_MISSING"),
                );
            }
            // The pduSessionId in the body must match the URI path segment
            // (TS 29.505 §6.1.3.1.3.1) so the stored key is consistent.
            let body_psi = doc.get("pduSessionId").and_then(|v| v.as_u64());
            if let Some(bp) = body_psi {
                if bp.to_string() != pdu_session_id {
                    return send_bad_request(
                        "pduSessionId in body does not match URI",
                        Some("INVALID_MSG_FORMAT"),
                    );
                }
            }
            // Normalise pduSessionId to the URI value as a numeric IE.
            if let Ok(num) = pdu_session_id.parse::<u64>() {
                if let Some(obj) = doc.as_object_mut() {
                    obj.insert("pduSessionId".to_string(), serde_json::json!(num));
                }
            }
            // Keep the context UE/session tracking in sync (for
            // subscription-data change notifications and request correlation).
            let psi: u8 = pdu_session_id.parse().unwrap_or(0);
            let dnn = doc
                .get("dnn")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string());
            if let Ok(mut ctx) = udr_ctx.write() {
                ctx.sess_find_or_add(supi, psi, dnn.as_deref());
            }
            // Store the actual registered document (created vs. replaced).
            let created = ds.smf_registration_put(supi, pdu_session_id, doc.clone());
            let path = format!(
                "/nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/{pdu_session_id}"
            );
            notify_subscription_data_change(supi, &path, Some(&doc));
            // TS 29.505 §5.2.4: 201 Created carries the created SmfRegistration
            // representation AND a required Location header (#87) -- a bare 201
            // leaves the consumer without the URI of the resource it just made,
            // and without confirmation of what was stored.
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            if pdu_session_id.is_empty() {
                return send_bad_request("Missing pduSessionId", Some("MANDATORY_IE_MISSING"));
            }
            // TS 29.505 §5.2.4 defines PATCH on the individual registration;
            // it answered 405 before #87.
            let Some(mut doc) = ds.smf_registration_get(supi, pdu_session_id) else {
                return send_not_found("SMF registration not found", Some("CONTEXT_NOT_FOUND"));
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            // The pduSessionId identifies the resource, so a patch must not be
            // able to move the document to another key.
            if doc
                .get("pduSessionId")
                .and_then(|v| v.as_u64())
                .map(|p| p.to_string())
                != Some(pdu_session_id.to_string())
            {
                return send_bad_request(
                    "pduSessionId is not patchable",
                    Some("INVALID_MSG_FORMAT"),
                );
            }
            ds.smf_registration_put(supi, pdu_session_id, doc.clone());
            let path = format!(
                "/nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/{pdu_session_id}"
            );
            notify_subscription_data_change(supi, &path, Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            if !pdu_session_id.is_empty() {
                let psi: u8 = pdu_session_id.parse().unwrap_or(0);
                if let Ok(mut ctx) = udr_ctx.write() {
                    ctx.sess_remove(supi, psi);
                }
                ds.smf_registration_remove(supi, pdu_session_id);
            } else {
                // Collection DELETE removes all registrations for the SUPI.
                ds.smf_registrations_remove_by_supi(supi);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "context-data/smf-registrations"),
    }
}

/// TS 29.503 `AuthEvent` required attributes (nfInstanceId, success, timeStamp,
/// authType, servingNetworkName).
const AUTH_EVENT_REQUIRED_IES: [&str; 5] = [
    "nfInstanceId",
    "success",
    "timeStamp",
    "authType",
    "servingNetworkName",
];

/// `authentication-data/authentication-status` (TS 29.505), both the collection
/// form and the individual `.../{servingNetworkName}` form. Stores the UDM's
/// `AuthEvent` on authentication confirmation (TS 33.501 §6.1.4).
///
/// `path_snn` is the `{servingNetworkName}` path segment when the individual
/// form was addressed, else `None`.
fn handle_auth_status(
    supi: &str,
    path_snn: Option<&str>,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = nextgcore_udrd::data_store::store();
    log::info!(
        "[{supi}] {method} authentication-status{}",
        path_snn.map(|s| format!("/{s}")).unwrap_or_default()
    );

    match method {
        "PUT" => {
            let Some(content) = request.http.content.as_ref() else {
                return send_bad_request("Missing AuthEvent body", Some("MANDATORY_IE_MISSING"));
            };
            let doc: serde_json::Value = match serde_json::from_str(content) {
                Ok(v @ serde_json::Value::Object(_)) => v,
                _ => {
                    return send_bad_request(
                        "Invalid AuthEvent document",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
            };
            let missing: Vec<&str> = AUTH_EVENT_REQUIRED_IES
                .iter()
                .filter(|ie| match doc.get(**ie) {
                    None | Some(serde_json::Value::Null) => true,
                    Some(serde_json::Value::String(s)) => s.is_empty(),
                    Some(_) => false,
                })
                .copied()
                .collect();
            if !missing.is_empty() {
                return send_bad_request(
                    &format!("Missing mandatory IE(s): {}", missing.join(", ")),
                    Some("MANDATORY_IE_MISSING"),
                );
            }

            // Owned: `doc` is moved into the store below, so the key cannot
            // borrow from it.
            let body_snn = doc
                .get("servingNetworkName")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            // On the individual form the path segment is authoritative and the
            // body must agree, so the stored key cannot disagree with the URI
            // the consumer will GET back.
            if let Some(p) = path_snn {
                if p != body_snn {
                    return send_bad_request(
                        "servingNetworkName in body does not match URI",
                        Some("INVALID_MSG_FORMAT"),
                    );
                }
            }
            // The collection form has no path segment, so the required body
            // field supplies the key.
            let key = path_snn.unwrap_or(&body_snn).to_string();

            // 204 on create AND on replace. TS 29.505 defines ONLY 204 for
            // success on both authentication-status forms -- unlike
            // smf-registrations, which does define 201 Created. Returning 201
            // here would be a fabricated status code the consumer's OpenAPI
            // validator can reject.
            ds.auth_status_put(supi, &key, doc);
            SbiResponse::with_status(204)
        }
        "GET" => {
            // Individual form: that serving network's event. Collection form:
            // the most recent one, since neither a path segment nor a body
            // identifies a specific network there.
            let found = match path_snn {
                Some(snn) => ds.auth_status_get(supi, snn),
                None => ds.auth_status_latest_for_supi(supi),
            };
            match found {
                Some(doc) => {
                    SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                }
                None => send_not_found(
                    "No authentication status stored for this UE",
                    Some("DATA_NOT_FOUND"),
                ),
            }
        }
        "DELETE" => {
            let removed = match path_snn {
                Some(snn) => ds.auth_status_remove(supi, snn).is_some(),
                None => ds.auth_status_remove_all_for_supi(supi) > 0,
            };
            if removed {
                SbiResponse::with_status(204)
            } else {
                send_not_found(
                    "No authentication status stored for this UE",
                    Some("DATA_NOT_FOUND"),
                )
            }
        }
        // PATCH is not defined on either form by TS 29.505.
        _ => send_method_not_allowed(method, "authentication-data/authentication-status"),
    }
}

/// Parse a `dataset-names` query parameter value into a set of requested
/// dataset names.  Handles both comma-separated (`AM,SM`) and percent-encoded
/// forms.  Returns `None` when the parameter is absent (→ return all datasets).
///
/// TS 29.504 §6.1 / TS 29.505 §5.4.2.8 `ProvisionedDataSetName` enum.
fn parse_dataset_names(raw: &str) -> Option<std::collections::HashSet<String>> {
    let decoded = pct_decode(raw);
    let names: std::collections::HashSet<String> = decoded
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// TS 29.504 §6.1.4.2 partial retrieval: project a JSON object value down to
/// the requested attribute paths (JSON Pointer syntax, e.g. `/a/b`).
///
/// Non-object top-level values (e.g. arrays) are returned unchanged.
/// A segment of `/` alone means the whole document — also returned unchanged.
/// Unknown paths are silently omitted from the result.
fn project_fields(value: &serde_json::Value, paths: &[String]) -> serde_json::Value {
    if paths.is_empty() {
        return value.clone();
    }
    if !value.is_object() {
        return value.clone(); // arrays / scalars cannot be path-projected
    }
    let mut out = serde_json::Map::new();
    for path in paths {
        let stripped = path.strip_prefix('/').unwrap_or(path.as_str());
        if stripped.is_empty() {
            // "/" or "" refers to the whole document
            return value.clone();
        }
        let segments: Vec<&str> = stripped.split('/').collect();
        if let Some(extracted) = project_extract(value, &segments) {
            project_insert(&mut out, &segments, extracted);
        }
    }
    serde_json::Value::Object(out)
}

fn project_extract(value: &serde_json::Value, segments: &[&str]) -> Option<serde_json::Value> {
    if segments.is_empty() {
        return Some(value.clone());
    }
    project_extract(value.as_object()?.get(segments[0])?, &segments[1..])
}

fn project_insert(
    out: &mut serde_json::Map<String, serde_json::Value>,
    segments: &[&str],
    value: serde_json::Value,
) {
    if segments.is_empty() {
        return;
    }
    if segments.len() == 1 {
        out.insert(segments[0].to_string(), value);
        return;
    }
    let entry = out
        .entry(segments[0].to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let Some(obj) = entry.as_object_mut() {
        project_insert(obj, &segments[1..], value);
    }
}

/// Apply the `fields` query parameter (TS 29.504 §6.1.4.2 partial retrieval)
/// when present.  Returns `value` unchanged when `fields` is absent.
fn apply_fields_param(value: serde_json::Value, request: &SbiRequest) -> serde_json::Value {
    let Some(raw) = request.http.params.get("fields") else {
        return value;
    };
    let paths: Vec<String> = pct_decode(raw)
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if paths.is_empty() {
        return value;
    }
    project_fields(&value, &paths)
}

/// Handle provisioned-data requests
/// Path: /nudr-dr/v2/subscription-data/{supi}/provisioned-data/{dataset}
async fn handle_provisioned_data(
    supi: &str,
    parts: &[&str],
    dataset_idx: usize,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    if method != "GET" {
        return send_method_not_allowed(method, "provisioned-data");
    }

    let dataset = parts.get(dataset_idx).copied().unwrap_or("");

    log::info!("[{supi}] GET provisioned-data/{dataset}");

    let subscription_data =
        match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(supi.to_string())
            .await
        {
            Ok(data) => data,
            Err(e) => return store_read_failure(supi, "provisioned-data", &e),
        };

    let response = match dataset {
        "am-data" => build_am_data(&subscription_data),
        "smf-selection-subscription-data" => build_smf_selection_data(&subscription_data),
        "sm-data" => build_sm_data(&subscription_data),
        "" => {
            // Combined provisioned-data GET (TS 29.504 §6.1 / TS 29.505 §5.4.2.8).
            // When `dataset-names` is present, return only the requested members;
            // absent param returns the full default set (udrd-03).
            let requested = request
                .http
                .params
                .get("dataset-names")
                .and_then(|raw| parse_dataset_names(raw));

            let include =
                |name: &str| -> bool { requested.as_ref().is_none_or(|set| set.contains(name)) };

            let mut combined = serde_json::Map::new();
            if include("AM") {
                combined.insert("amData".to_string(), build_am_data(&subscription_data));
            }
            if include("SMF_SEL") {
                combined.insert(
                    "smfSelData".to_string(),
                    build_smf_selection_data(&subscription_data),
                );
            }
            if include("SM") {
                combined.insert("smData".to_string(), build_sm_data(&subscription_data));
            }
            serde_json::Value::Object(combined)
        }
        _ => {
            log::warn!("[{supi}] Unknown dataset: {dataset}");
            return send_not_found(&format!("Unknown dataset: {dataset}"), None);
        }
    };

    // TS 29.504 §6.1.4.2 partial retrieval via `fields` param (udrd-07).
    let response = apply_fields_param(response, request);

    SbiResponse::with_status(200).with_body(response.to_string(), "application/json")
}

/// Handle policy-data requests
/// Implements:
/// - GET policy-data/ues/{supi}/am-data: AM policy data
/// - GET/PUT policy-data/ues/{supi}/sm-data: SM policy data
/// - GET policy-data/ues/{supi}/ue-policy-set: UE policy set
async fn handle_policy_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    // TS 29.519 §5.2 resource tree:
    //   /policy-data/ues/{ueId}/{am-data,sm-data[/{usageMonId}],ue-policy-set}
    //   /policy-data/subs-to-notify[/{subsId}]
    //   /policy-data/plmns/{plmnId}/ue-policy-set
    //   /policy-data/sponsor-connectivity-data/{sponsorId}
    //   /policy-data/bdt-data[/{bdtReferenceId}]
    match parts.get(3).copied().unwrap_or("") {
        "ues" => handle_policy_ue_data(parts, method, request).await,
        "subs-to-notify" => handle_policy_subs_to_notify(parts, method, request),
        "plmns" => handle_policy_plmn_data(parts, method, request),
        "sponsor-connectivity-data" => handle_policy_sponsor_data(parts, method, request),
        "bdt-data" => handle_policy_bdt_data(parts, method, request),
        other => send_not_found(&format!("Unknown policy sub-resource: {other}"), None),
    }
}

/// The resource URI of a per-UE policy document (notification resourceId).
fn policy_ue_path(supi: &str, resource: &str) -> String {
    format!("/nudr-dr/v2/policy-data/ues/{supi}/{resource}")
}

/// Store a provisioned policy document and emit both change notifications.
///
/// Both, because the two subscription trees have different audiences: a
/// `/subscription-data/subs-to-notify` subscriber (typically the UDM) gets the
/// `DataChangeNotify`, a `/policy-data/subs-to-notify` subscriber (the PCF) gets
/// the `PolicyDataChangeNotification`. Emitting only the first is why a PCF
/// could subscribe and never hear anything.
fn notify_policy_change(supi: &str, path: &str, doc: Option<&serde_json::Value>) {
    notify_subscription_data_change(supi, path, doc);
    nextgcore_udrd::data_store::notify_policy_data_change(supi, path, doc);
}

/// Read a provisioned policy document by resource name.
fn policy_doc_get(supi: &str, resource: &str) -> Option<serde_json::Value> {
    let ds = nextgcore_udrd::data_store::store();
    match resource {
        "am-data" => ds.policy_am_get(supi),
        "sm-data" => ds.policy_sm_get(supi),
        "ue-policy-set" => ds.policy_ue_get(supi),
        _ => None,
    }
}

/// Write a provisioned policy document by resource name; true when created.
fn policy_doc_put(supi: &str, resource: &str, doc: serde_json::Value) -> bool {
    let ds = nextgcore_udrd::data_store::store();
    match resource {
        "am-data" => ds.policy_am_put(supi, doc),
        "sm-data" => ds.policy_sm_put(supi, doc),
        "ue-policy-set" => ds.policy_ue_put(supi, doc),
        _ => false,
    }
}

/// PUT a provisioned per-UE policy document (`am-data`, `sm-data`,
/// `ue-policy-set`).
fn policy_put(supi: &str, resource: &str, request: &SbiRequest) -> SbiResponse {
    let body = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if !body.is_object() {
        return send_bad_request("Body must be a JSON object", Some("INVALID_MSG_FORMAT"));
    }
    let created = policy_doc_put(supi, resource, body.clone());
    let path = policy_ue_path(supi, resource);
    notify_policy_change(supi, &path, Some(&body));
    if created {
        SbiResponse::with_status(201)
            .with_header("Location", path)
            .with_body(body.to_string(), "application/json")
    } else {
        SbiResponse::with_status(204)
    }
}

/// PATCH a provisioned per-UE policy document (TS 29.519 §5.2: `am-data` :143,
/// `sm-data` :333, `ue-policy-set` :484 — all `405` before #87).
///
/// An absent document starts empty rather than 404ing: PATCH is how a PCF
/// provisions a delta, and refusing the first one would mean a document could
/// only ever be created by a full PUT the consumer may not have.
fn policy_patch(supi: &str, resource: &str, request: &SbiRequest) -> SbiResponse {
    let patch = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut doc = policy_doc_get(supi, resource).unwrap_or_else(|| serde_json::json!({}));
    if let Some(resp) = apply_patch_document(&mut doc, &patch) {
        return resp;
    }
    policy_doc_put(supi, resource, doc.clone());
    let path = policy_ue_path(supi, resource);
    notify_policy_change(supi, &path, Some(&doc));
    SbiResponse::with_status(204)
}

/// Does `entry`'s `snssai` object match the requested one?
///
/// Compared field-wise on `sst`/`sd` rather than by map key, because the key
/// spelling is a UDR-side convention (`"01-000001"`) while the consumer sends a
/// JSON `Snssai` — matching on the key would make the filter depend on how this
/// UDR happens to format it.
fn snssai_entry_matches(entry: &serde_json::Value, want: &serde_json::Value) -> bool {
    let have = entry.get("snssai").unwrap_or(entry);
    let sst_eq =
        have.get("sst").and_then(|v| v.as_u64()) == want.get("sst").and_then(|v| v.as_u64());
    let norm_sd = |v: Option<&serde_json::Value>| {
        v.and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches('0').to_ascii_lowercase())
    };
    sst_eq && norm_sd(have.get("sd")) == norm_sd(want.get("sd"))
}

/// Narrow an `SmPolicyData` to the requested `snssai` / `dnn` (TS 29.519 §5.2).
///
/// Returns `None` when the filter selects nothing — the subscriber has no policy
/// for that slice or DNN, which is a `404` rather than an empty document a PCF
/// would install as "no policy applies".
fn filter_sm_policy_data(
    doc: &serde_json::Value,
    snssai: Option<&serde_json::Value>,
    dnn: Option<&str>,
) -> Option<serde_json::Value> {
    let Some(want) = snssai else {
        // No filter: the whole document, as before #87.
        return Some(doc.clone());
    };
    let entries = doc.get("smPolicySnssaiData").and_then(|v| v.as_object())?;
    let mut kept = serde_json::Map::new();
    for (key, entry) in entries {
        if !snssai_entry_matches(entry, want) {
            continue;
        }
        let mut entry = entry.clone();
        if let Some(dnn) = dnn {
            let dnn_entries = entry
                .get("smPolicyDnnData")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            let Some(hit) = dnn_entries.get(dnn) else {
                // The slice matches but the DNN does not: selecting nothing.
                continue;
            };
            let mut only = serde_json::Map::new();
            only.insert(dnn.to_string(), hit.clone());
            if let Some(obj) = entry.as_object_mut() {
                obj.insert(
                    "smPolicyDnnData".to_string(),
                    serde_json::Value::Object(only),
                );
            }
        }
        kept.insert(key.clone(), entry);
    }
    if kept.is_empty() {
        return None;
    }
    let mut out = doc.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "smPolicySnssaiData".to_string(),
            serde_json::Value::Object(kept),
        );
    }
    Some(out)
}

/// `/policy-data/ues/{ueId}/...` (TS 29.519 §5.2).
async fn handle_policy_ue_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let supi = match parts.get(4) {
        Some(s) => *s,
        None => return send_bad_request("Missing SUPI", Some("MISSING_SUPI")),
    };

    let resource = parts.get(5).copied().unwrap_or("");
    let tail = parts.get(6).copied().unwrap_or("");

    match resource {
        "am-data" => match method {
            "GET" => {
                log::debug!("[{supi}] GET policy am-data");
                // udrd-05: return stored AmPolicyData when provisioned (udrd-04);
                // fall back to `{}` per TS 29.519 (no default AM policy data).
                let body = policy_doc_get(supi, "am-data").unwrap_or_else(|| serde_json::json!({}));
                let body = apply_fields_param(body, request);
                SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
            }
            "PUT" => policy_put(supi, "am-data", request),
            "PATCH" => policy_patch(supi, "am-data", request),
            _ => send_method_not_allowed(method, "policy-data/ues/am-data"),
        },
        "sm-data" if !tail.is_empty() => {
            // /sm-data/{usageMonId} — the UsageMonData document (TS 29.519 :550).
            handle_policy_usage_mon(supi, tail, method, request)
        }
        "sm-data" => match method {
            "GET" => {
                log::debug!("[{supi}] GET policy sm-data");
                // TS 29.519 §5.2: `snssai` (a JSON Snssai) and `dnn` narrow the
                // document. Both are optional in the in-tree OpenAPI, so an
                // absent filter still returns everything; a filter that selects
                // nothing is a 404, not an empty SmPolicyData (#87).
                let snssai = request
                    .http
                    .params
                    .get("snssai")
                    .map(|raw| pct_decode(raw))
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
                let dnn = request.http.params.get("dnn").map(|d| pct_decode(d));
                let stored = match policy_doc_get(supi, "sm-data") {
                    Some(stored) => Some(stored),
                    None => {
                        // Fall back to the default derived from subscription data.
                        match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(
                            supi.to_string(),
                        )
                        .await
                        {
                            Ok(data) => Some(serde_json::json!({
                                "smPolicySnssaiData": build_sm_policy_data(&data)
                            })),
                            Err(e) => return store_read_failure(supi, "sm-data", &e),
                        }
                    }
                };
                let Some(stored) = stored else {
                    return send_not_found("Subscriber not found", None);
                };
                match filter_sm_policy_data(&stored, snssai.as_ref(), dnn.as_deref()) {
                    Some(doc) => {
                        let doc = apply_fields_param(doc, request);
                        SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                    }
                    None => send_not_found(
                        "No SM policy data for the requested S-NSSAI/DNN",
                        Some("DATA_NOT_FOUND"),
                    ),
                }
            }
            "PUT" => policy_put(supi, "sm-data", request),
            "PATCH" => policy_patch(supi, "sm-data", request),
            _ => send_method_not_allowed(method, "policy-data/ues/sm-data"),
        },
        "ue-policy-set" => match method {
            "GET" => {
                log::debug!("[{supi}] GET ue-policy-set");
                // udrd-05: prefer stored UePolicySet when provisioned (udrd-04);
                // fall back to a minimal derived default built from subscription slices.
                if let Some(stored) = policy_doc_get(supi, "ue-policy-set") {
                    let stored = apply_fields_param(stored, request);
                    return SbiResponse::with_status(200)
                        .with_body(stored.to_string(), "application/json");
                }
                match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(
                    supi.to_string(),
                )
                .await
                {
                    Ok(data) => {
                        // Build a minimal UePolicySet with subscribed S-NSSAIs
                        let mut subscribed_ue_pol_sections = serde_json::Map::new();
                        for slice in &data.slice {
                            let snssai_key = if slice.s_nssai.has_sd() {
                                format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
                            } else {
                                format!("{:02x}", slice.s_nssai.sst)
                            };
                            subscribed_ue_pol_sections.insert(
                                snssai_key,
                                serde_json::json!({
                                    "upsi": [],
                                    "allowedRouteSelDescs": {}
                                }),
                            );
                        }
                        let response = serde_json::json!({
                            "subscPolicySections": subscribed_ue_pol_sections
                        });
                        let response = apply_fields_param(response, request);
                        SbiResponse::with_status(200)
                            .with_body(response.to_string(), "application/json")
                    }
                    Err(e) => {
                        if let Some(resp) = ue_id_rejection(&e) {
                            return resp;
                        }
                        if store_error_is_outage(&e) {
                            return store_outage(supi, "ue-policy-set", &e);
                        }
                        // Return empty UePolicySet as default (TS 29.519)
                        SbiResponse::with_status(200)
                            .with_body("{}".to_string(), "application/json")
                    }
                }
            }
            "PUT" => policy_put(supi, "ue-policy-set", request),
            "PATCH" => policy_patch(supi, "ue-policy-set", request),
            _ => send_method_not_allowed(method, "policy-data/ues/ue-policy-set"),
        },
        _ => send_not_found(&format!("Unknown policy resource: {resource}"), None),
    }
}

/// `/policy-data/ues/{ueId}/sm-data/{usageMonId}` — the UsageMonData document
/// (TS 29.519 §5.2). Keyed `{supi}\u{1f}{usageMonId}` so one UE's monitoring
/// documents are independent of another's.
fn handle_policy_usage_mon(
    supi: &str,
    usage_mon_id: &str,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = nextgcore_udrd::data_store::store();
    let key = format!("{supi}\u{1f}{usage_mon_id}");
    let path = format!("/nudr-dr/v2/policy-data/ues/{supi}/sm-data/{usage_mon_id}");
    match method {
        "GET" => match ds.doc_get("policy-usage-mon", &key) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No usage monitoring data", Some("DATA_NOT_FOUND")),
        },
        "PUT" => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put("policy-usage-mon", &key, body.clone());
            notify_policy_change(supi, &path, Some(&body));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "DELETE" => {
            if ds.doc_remove("policy-usage-mon", &key).is_some() {
                notify_policy_change(supi, &path, None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "policy-data/ues/sm-data/{usageMonId}"),
    }
}

/// `/policy-data/subs-to-notify[/{subsId}]` — TS 29.519 §5.2 (:1077, :1250).
///
/// The subscription tree a PCF uses to hear about policy-data changes. It was
/// entirely absent, so a conformant PCF's subscribe attempt 404'd.
fn handle_policy_subs_to_notify(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = nextgcore_udrd::data_store::store();
    let subs_id = parts.get(4).copied().unwrap_or("");
    match (subs_id.is_empty(), method) {
        (true, "POST") => {
            let body = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            // PolicyDataSubscription: notificationUri + monitoredResourceUris.
            let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                return missing_mandatory("notificationUri");
            };
            if body
                .get("monitoredResourceUris")
                .and_then(|v| v.as_array())
                .is_none_or(|a| a.is_empty())
            {
                return missing_mandatory("monitoredResourceUris");
            }
            let owner = match owner_for_new_subscription(request, "Subscribe") {
                Ok(owner) => owner,
                Err(refused) => return *refused,
            };
            let sub = ds.sub_create_owned(SubKind::PolicyData, uri, body.clone(), owner);
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nudr-dr/v2/policy-data/subs-to-notify/{}", sub.id),
                )
                .with_body(body.to_string(), "application/json")
        }
        (false, "GET") => match sub_for_caller(subs_id, SubKind::PolicyData, request, "Get") {
            Ok(sub) => {
                SbiResponse::with_status(200).with_body(sub.body.to_string(), "application/json")
            }
            Err(refused) => *refused,
        },
        (false, "PUT") => {
            let body = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                return missing_mandatory("notificationUri");
            };
            if let Err(refused) = sub_for_caller(subs_id, SubKind::PolicyData, request, "Modify") {
                return *refused;
            }
            if ds.sub_replace(subs_id, SubKind::PolicyData, uri, body.clone()) {
                SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
            } else {
                send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
            }
        }
        (false, "DELETE") => {
            if let Err(refused) =
                sub_for_caller(subs_id, SubKind::PolicyData, request, "Unsubscribe")
            {
                return *refused;
            }
            ds.sub_remove(subs_id);
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "policy-data/subs-to-notify"),
    }
}

/// `/policy-data/plmns/{plmnId}/ue-policy-set` — TS 29.519 §5.2 (:1651): the
/// PLMN-wide UE policy set, as opposed to a per-UE one.
fn handle_policy_plmn_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let plmn_id = parts.get(4).copied().unwrap_or("");
    if parts.get(5).copied() != Some("ue-policy-set") {
        return send_not_found("Unknown policy plmns resource", None);
    }
    if !is_valid_plmn_id(plmn_id) {
        return send_error(
            400,
            "Bad Request",
            &format!("Invalid plmnId: {plmn_id}"),
            Some("MANDATORY_IE_INCORRECT"),
        );
    }
    let ds = nextgcore_udrd::data_store::store();
    let path = format!("/nudr-dr/v2/policy-data/plmns/{plmn_id}/ue-policy-set");
    match method {
        "GET" => match ds.doc_get("policy-plmn-ue-policy-set", plmn_id) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No PLMN UE policy set", Some("DATA_NOT_FOUND")),
        },
        "PUT" => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put("policy-plmn-ue-policy-set", plmn_id, body.clone());
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            let mut doc = ds
                .doc_get("policy-plmn-ue-policy-set", plmn_id)
                .unwrap_or_else(|| serde_json::json!({}));
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put("policy-plmn-ue-policy-set", plmn_id, doc);
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "policy-data/plmns/ue-policy-set"),
    }
}

/// `/policy-data/sponsor-connectivity-data/{sponsorId}` — TS 29.519 §5.2 (:738).
fn handle_policy_sponsor_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let sponsor_id = parts.get(4).copied().unwrap_or("");
    if sponsor_id.is_empty() {
        return send_not_found("Missing sponsorId", None);
    }
    let ds = nextgcore_udrd::data_store::store();
    let path = format!("/nudr-dr/v2/policy-data/sponsor-connectivity-data/{sponsor_id}");
    match method {
        "GET" => match ds.doc_get("policy-sponsor-data", sponsor_id) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No sponsor connectivity data", Some("DATA_NOT_FOUND")),
        },
        "PUT" => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            // SponsorConnectivityData requires aspIds (TS 29.519 §5.6.2.x).
            if body
                .get("aspIds")
                .and_then(|v| v.as_array())
                .is_none_or(|a| a.is_empty())
            {
                return missing_mandatory("aspIds");
            }
            let created = ds.doc_put("policy-sponsor-data", sponsor_id, body.clone());
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        _ => send_method_not_allowed(method, "policy-data/sponsor-connectivity-data"),
    }
}

/// `/policy-data/bdt-data[/{bdtReferenceId}]` — TS 29.519 §5.2 (:799, :864).
fn handle_policy_bdt_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = nextgcore_udrd::data_store::store();
    let bdt_ref = parts.get(4).copied().unwrap_or("");
    match (bdt_ref.is_empty(), method) {
        (true, "GET") => {
            let list: Vec<serde_json::Value> = ds
                .doc_list("policy-bdt-data")
                .into_iter()
                .map(|(_, v)| v)
                .collect();
            SbiResponse::with_status(200).with_body(
                serde_json::Value::Array(list).to_string(),
                "application/json",
            )
        }
        (false, "GET") => match ds.doc_get("policy-bdt-data", bdt_ref) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No BDT data", Some("DATA_NOT_FOUND")),
        },
        (false, "PUT") => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            // BdtData requires aspId, transPolicy and bdtRefId; the path segment
            // is authoritative for the last, so a body that disagrees is refused
            // rather than silently stored under the URI's id.
            for attr in ["aspId", "transPolicy"] {
                if body.get(attr).is_none() {
                    return missing_mandatory(attr);
                }
            }
            if let Some(body_ref) = body.get("bdtRefId").and_then(|v| v.as_str()) {
                if body_ref != bdt_ref {
                    return send_bad_request(
                        "bdtRefId in body does not match URI",
                        Some("INVALID_MSG_FORMAT"),
                    );
                }
            }
            let path = format!("/nudr-dr/v2/policy-data/bdt-data/{bdt_ref}");
            let created = ds.doc_put("policy-bdt-data", bdt_ref, body.clone());
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        (false, "PATCH") => {
            let Some(mut doc) = ds.doc_get("policy-bdt-data", bdt_ref) else {
                return send_not_found("No BDT data", Some("DATA_NOT_FOUND"));
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put("policy-bdt-data", bdt_ref, doc.clone());
            SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
        }
        (false, "DELETE") => {
            if ds.doc_remove("policy-bdt-data", bdt_ref).is_some() {
                SbiResponse::with_status(204)
            } else {
                send_not_found("No BDT data", Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, "policy-data/bdt-data"),
    }
}

/// Build SM policy data from subscription data
fn build_sm_policy_data(
    data: &nextgcore_dbi::types::NextgcoreSubscriptionData,
) -> serde_json::Map<String, serde_json::Value> {
    let mut sm_policy_snssai_data = serde_json::Map::new();
    for slice in &data.slice {
        let snssai_key = if slice.s_nssai.has_sd() {
            format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
        } else {
            format!("{:02x}", slice.s_nssai.sst)
        };
        let mut snssai_json = serde_json::Map::new();
        snssai_json.insert(
            "sst".to_string(),
            serde_json::Value::Number(slice.s_nssai.sst.into()),
        );
        if slice.s_nssai.has_sd() {
            snssai_json.insert(
                "sd".to_string(),
                serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)),
            );
        }
        let mut sm_policy_dnn_data = serde_json::Map::new();
        for sess in &slice.session {
            if let Some(dnn) = &sess.name {
                sm_policy_dnn_data.insert(dnn.clone(), serde_json::json!({"dnn": dnn}));
            }
        }
        let mut snssai_data = serde_json::Map::new();
        snssai_data.insert("snssai".to_string(), serde_json::Value::Object(snssai_json));
        if !sm_policy_dnn_data.is_empty() {
            snssai_data.insert(
                "smPolicyDnnData".to_string(),
                serde_json::Value::Object(sm_policy_dnn_data),
            );
        }
        sm_policy_snssai_data.insert(snssai_key, serde_json::Value::Object(snssai_data));
    }
    sm_policy_snssai_data
}

// ============================================================================
// subscription-data/subs-to-notify (TS 29.505)
// ============================================================================

/// Handle /nudr-dr/v2/subscription-data/subs-to-notify[/{subsId}]
async fn handle_subscription_data_subs(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    match parts.get(4).copied() {
        // Collection: /subscription-data/subs-to-notify
        None => match method {
            "POST" => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(cb) = body.get("callbackReference").and_then(|v| v.as_str()) else {
                    return missing_mandatory("callbackReference");
                };
                if body
                    .get("monitoredResourceUris")
                    .and_then(|v| v.as_array())
                    .is_none()
                {
                    return missing_mandatory("monitoredResourceUris");
                }
                // #1775 review, TS 29.504 §5.2.2.6.2: a suggested `expiry` is
                // confirmed as it is (no later than suggested), and the subscription
                // is removed once it passes. One that cannot be read, or has passed
                // already, is refused rather than silently made unlimited.
                if let Some(expiry) = body.get("expiry") {
                    let at = expiry
                        .as_str()
                        .and_then(nextgcore_sbi::datetime::rfc3339_to_epoch_signed);
                    match at {
                        None => {
                            return send_bad_request(
                                "expiry is not a DateTime (RFC 3339)",
                                Some("INVALID_MSG_FORMAT"),
                            )
                        }
                        Some(at) if at <= nextgcore_sbi::datetime::now_epoch_secs() as i64 => {
                            return send_bad_request(
                                "expiry has passed already",
                                Some("MANDATORY_IE_INCORRECT"),
                            )
                        }
                        Some(_) => {}
                    }
                }
                let cb = cb.to_string();
                let mut stored_body = body;
                let owner = match owner_for_new_subscription(request, "Subscribe") {
                    Ok(owner) => owner,
                    Err(refused) => return *refused,
                };
                let sub = ds.sub_create_owned(
                    SubKind::SubscriptionData,
                    &cb,
                    serde_json::Value::Null,
                    owner,
                );
                if let Some(obj) = stored_body.as_object_mut() {
                    obj.insert(
                        "subscriptionId".to_string(),
                        serde_json::Value::String(sub.id.clone()),
                    );
                }
                ds.sub_set_body(&sub.id, stored_body.clone(), None);
                // #1775: what a subscriber to am-data is told of is measured from
                // the am-data as it is now, not from the first watch pass.
                am_data_watch_baseline(&sub.id).await;
                SbiResponse::with_status(201)
                    .with_header(
                        "Location",
                        format!("/nudr-dr/v2/subscription-data/subs-to-notify/{}", sub.id),
                    )
                    .with_body(stored_body.to_string(), "application/json")
            }
            "GET" => {
                let Some(ue_id) = request.http.params.get("ue-id").cloned() else {
                    return send_bad_request(
                        "Missing mandatory query parameter: ue-id",
                        Some("MANDATORY_QUERY_PARAM_MISSING"),
                    );
                };
                // #1861: the caller's own subscriptions only; another NF's
                // callbackReference is not this caller's to read.
                let subs = ds.subs_matching(SubKind::SubscriptionData, |s| {
                    s.body.get("ueId").and_then(|v| v.as_str()) == Some(ue_id.as_str())
                        && subscription_caller_refusal(s.owner.as_deref(), request).is_none()
                });
                let list: Vec<serde_json::Value> = subs.into_iter().map(|s| s.body).collect();
                SbiResponse::with_status(200).with_body(
                    serde_json::Value::Array(list).to_string(),
                    "application/json",
                )
            }
            "DELETE" => {
                let Some(ue_id) = request.http.params.get("ue-id").cloned() else {
                    return send_bad_request(
                        "Missing mandatory query parameter: ue-id",
                        Some("MANDATORY_QUERY_PARAM_MISSING"),
                    );
                };
                // #1861: removes the caller's own subscriptions for the UE, not
                // every NF's.
                for sub in ds.subs_matching(SubKind::SubscriptionData, |s| {
                    s.body.get("ueId").and_then(|v| v.as_str()) == Some(ue_id.as_str())
                        && subscription_caller_refusal(s.owner.as_deref(), request).is_none()
                }) {
                    ds.sub_remove(&sub.id);
                }
                SbiResponse::with_status(204)
            }
            _ => send_method_not_allowed(method, "subscription-data/subs-to-notify"),
        },
        // Document: /subscription-data/subs-to-notify/{subsId}
        Some(subs_id) => match method {
            "GET" => match live_sub_for_caller(subs_id, request, "Get") {
                Ok(sub) => SbiResponse::with_status(200)
                    .with_body(sub.body.to_string(), "application/json"),
                Err(refused) => *refused,
            },
            "PATCH" => {
                // #1836: an expired subscription is gone (TS 29.504 §5.2.2.6.2:
                // "after which the subscription becomes invalid"), so the UDM's
                // refresh learns it must subscribe again. #1861: and only its
                // creator modifies it.
                let sub = match live_sub_for_caller(subs_id, request, "Modify") {
                    Ok(sub) => sub,
                    Err(refused) => return *refused,
                };
                let patch_body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(items) = patch_body.as_array() else {
                    return send_bad_request(
                        "PATCH body must be a PatchItem array",
                        Some("INVALID_MSG_FORMAT"),
                    );
                };
                // Every item is checked before any is applied (#1836).
                let mut body = sub.body;
                for patch in items {
                    let op = patch.get("op").and_then(|v| v.as_str()).unwrap_or("");
                    let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let key = path.trim_start_matches('/');
                    if !matches!(op, "replace" | "add") || key.is_empty() || key.contains('/') {
                        return send_bad_request(
                            &format!("Unsupported patch: {op} {path}"),
                            Some("INVALID_MSG_FORMAT"),
                        );
                    }
                    let Some(value) = patch.get("value") else {
                        return send_bad_request(
                            &format!("{op} {path} without a value"),
                            Some("INVALID_MSG_FORMAT"),
                        );
                    };
                    if let Err(resp) = check_subscription_data_member(key, value) {
                        return *resp;
                    }
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert(key.to_string(), value.clone());
                    }
                }
                let notify_uri = body
                    .get("callbackReference")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ds.sub_set_body(subs_id, body, notify_uri);
                SbiResponse::with_status(204)
            }
            "DELETE" => {
                if let Err(refused) =
                    sub_for_caller(subs_id, SubKind::SubscriptionData, request, "Unsubscribe")
                {
                    return *refused;
                }
                ds.sub_remove(subs_id);
                SbiResponse::with_status(204)
            }
            _ => send_method_not_allowed(method, "subscription-data/subs-to-notify/{subsId}"),
        },
    }
}

/// Subscription-data subscription `id`, unless it is not one or has expired
/// (TS 29.504 §5.2.2.6.2). An expired one is removed on the way (#1836).
fn live_subscription_data_sub(id: &str) -> Option<data_store::StoredSub> {
    let ds = data_store::store();
    let sub = ds
        .sub_get(id)
        .filter(|s| s.kind == SubKind::SubscriptionData)?;
    if data_store::sub_expired(&sub, nextgcore_sbi::datetime::now_epoch_secs() as i64) {
        log::info!("subscription-data subscription {id} expired: removed");
        ds.sub_remove(id);
        return None;
    }
    Some(sub)
}

/// [`live_subscription_data_sub`] for its creator only (#1861): `404` when it is
/// gone or expired, the owner check's `403` for anyone else.
fn live_sub_for_caller(
    id: &str,
    request: &SbiRequest,
    operation: &str,
) -> Result<data_store::StoredSub, Box<SbiResponse>> {
    let sub = live_subscription_data_sub(id).ok_or_else(|| {
        Box::new(send_not_found(
            "Subscription not found",
            Some("DATA_NOT_FOUND"),
        ))
    })?;
    match refuse_subscription_caller(sub.owner.as_deref(), request, operation) {
        Some(refused) => Err(Box::new(refused)),
        None => Ok(sub),
    }
}

/// Whether a PATCH may set member `key` of a `SubscriptionDataSubscriptions`
/// (TS 29.505) to `value` (#1836): an `expiry` must be a future DateTime, as at the
/// subscribe; `callbackReference` a string; `monitoredResourceUris` a non-empty
/// array of strings (mandatory members, so not unset by a PATCH either).
fn check_subscription_data_member(
    key: &str,
    value: &serde_json::Value,
) -> Result<(), Box<SbiResponse>> {
    let bad = |what: &str, cause: &str| Err(Box::new(send_bad_request(what, Some(cause))));
    match key {
        "expiry" => match value
            .as_str()
            .and_then(nextgcore_sbi::datetime::rfc3339_to_epoch_signed)
        {
            None => bad("expiry is not a DateTime (RFC 3339)", "INVALID_MSG_FORMAT"),
            Some(at) if at <= nextgcore_sbi::datetime::now_epoch_secs() as i64 => {
                bad("expiry has passed already", "MANDATORY_IE_INCORRECT")
            }
            Some(_) => Ok(()),
        },
        "callbackReference" if !value.is_string() => {
            bad("callbackReference is not a URI", "MANDATORY_IE_INCORRECT")
        }
        "monitoredResourceUris"
            if !value
                .as_array()
                .is_some_and(|a| !a.is_empty() && a.iter().all(serde_json::Value::is_string)) =>
        {
            bad(
                "monitoredResourceUris is not a non-empty array of URIs",
                "MANDATORY_IE_INCORRECT",
            )
        }
        "subscriptionId" => bad("subscriptionId is not modifiable", "MANDATORY_IE_INCORRECT"),
        _ => Ok(()),
    }
}

// ============================================================================
// am-data provisioning watch (#1775)
// ============================================================================
//
// TS 23.502 §4.5.1 / §4.5.2: when a subscriber's profile changes in the UDR, the
// UDR notifies the UDM (Nudr_DM_Notify, TS 29.505 §5.4.2.6) and the UDM notifies
// the AMF (Nudm_SDM_Notification). The am-data this UDR serves is built from the
// subscriber database, which an operator provisions directly (the WebUI writes
// MongoDB, not this UDR), so no UDR write path sees the change. The watcher reads
// the am-data of each UE a subscription-data subscription watches, every
// `UDR_AM_DATA_WATCH_MS`, and tells each subscription what changed since the
// am-data it was last told of.
//
// Per-subscription state (`AM_DATA_NOTIFIED_COLLECTION`): the am-data the
// subscription was last told of, persisted with the store. It advances when the
// subscriber answers 2xx, or a 4xx other than 404 (a refusal: the same change is
// not resent, so a subscriber answering 400 is not sent it in a loop). A 404 means
// the subscription is gone at the subscriber, and it is removed here. No answer, or
// a 5xx, leaves the state, so the change is resent once a backoff has passed; a
// subscriber failing for an hour is removed. Each subscription gets at most one
// notification per pass, and passes run one after another, so a later change
// cannot overtake an earlier one. Bounds, concurrency, expiry and the once-per-pass
// persist: see `am_data_watch_pass_with` (#1775 review).

/// The watch period env var, in milliseconds; `0` turns the watch off.
const AM_DATA_WATCH_ENV: &str = "UDR_AM_DATA_WATCH_MS";
/// The default watch period: the longest a provisioning change waits to be told.
const DEFAULT_AM_DATA_WATCH_MS: u64 = 5_000;

fn am_data_watch_period() -> Option<std::time::Duration> {
    let ms = std::env::var(AM_DATA_WATCH_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_AM_DATA_WATCH_MS);
    (ms > 0).then(|| std::time::Duration::from_millis(ms))
}

/// Start the am-data watch, unless `UDR_AM_DATA_WATCH_MS` is 0.
fn spawn_am_data_watch() {
    let Some(period) = am_data_watch_period() else {
        log::info!("{AM_DATA_WATCH_ENV}=0: am-data provisioning changes are not reported");
        return;
    };
    log::info!("am-data provisioning watch every {} ms", period.as_millis());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            am_data_watch_pass().await;
        }
    });
}

/// `supi`'s am-data as this UDR serves it, or `None` when it cannot be read now.
async fn read_am_data(supi: &str) -> Option<serde_json::Value> {
    match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(supi.to_string()).await
    {
        Ok(data) => Some(build_am_data(&data)),
        Err(e) => {
            log::debug!("[{supi}] am-data watch: subscriber data not read: {e:?}");
            None
        }
    }
}

/// Record the am-data subscription `sub_id` starts from, if it watches am-data.
async fn am_data_watch_baseline(sub_id: &str) {
    let Some((supi, _)) = data_store::am_data_watchers()
        .into_iter()
        .find(|(_, s)| s.id == sub_id)
    else {
        return;
    };
    if let Some(now) = read_am_data(&supi).await {
        data_store::store().doc_put(data_store::AM_DATA_NOTIFIED_COLLECTION, sub_id, now);
    }
}

/// The most am-data subscriptions one watch pass serves, env var and default
/// (#1775 review MAJOR-2). A pass takes them round-robin from where the previous
/// one stopped, so every subscription is still served, and one pass costs at most
/// this many MongoDB reads and notifications however many subscriptions there are.
const AM_DATA_WATCH_MAX_ENV: &str = "UDR_AM_DATA_WATCH_MAX_PER_PASS";
const DEFAULT_AM_DATA_WATCH_MAX: usize = 512;
/// The most MongoDB reads, and separately the most notifications, in flight at
/// once in a pass.
const AM_DATA_WATCH_CONCURRENCY: usize = 32;
/// The longest wait before a subscriber that did not answer, or answered 5xx, is
/// tried again: the wait doubles from the watch period up to this.
const AM_DATA_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(300);
/// A subscriber that has not answered, or answered only 5xx, for this long (and at
/// least [`AM_DATA_DEAD_MIN_FAILURES`] times) is gone: its subscription is removed,
/// as on a 404. A UDM that restarted answers 404 on its old tokens; this covers the
/// one that is gone with its address (a replaced pod).
const AM_DATA_DEAD_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);
const AM_DATA_DEAD_MIN_FAILURES: u32 = 5;

fn am_data_watch_max() -> usize {
    std::env::var(AM_DATA_WATCH_MAX_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_AM_DATA_WATCH_MAX)
}

/// The failures in a row of one subscription's notifications.
#[derive(Debug, Clone, Copy)]
struct WatchFailures {
    count: u32,
    first: std::time::Instant,
    next_try: std::time::Instant,
}

/// Subscription id -> its failures in a row, while it has some. Held in memory: a
/// UDR restart tries every subscriber again at once.
static AM_DATA_FAILURES: std::sync::Mutex<
    Option<std::collections::HashMap<String, WatchFailures>>,
> = std::sync::Mutex::new(None);

/// The id of the last subscription the previous pass served (round-robin cursor).
static AM_DATA_CURSOR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn am_data_failures(
) -> std::sync::MutexGuard<'static, Option<std::collections::HashMap<String, WatchFailures>>> {
    AM_DATA_FAILURES.lock().unwrap_or_else(|e| e.into_inner())
}

/// The wait after failure `count` (1-based): the watch period doubling, at most
/// [`AM_DATA_BACKOFF_MAX`].
fn am_data_backoff(count: u32) -> std::time::Duration {
    let base = am_data_watch_period()
        .unwrap_or(std::time::Duration::from_millis(DEFAULT_AM_DATA_WATCH_MS));
    base.saturating_mul(1u32 << count.saturating_sub(1).min(16))
        .min(AM_DATA_BACKOFF_MAX)
}

/// What one subscription's notification came to.
enum WatchOutcome {
    /// 2xx, or a refusal (4xx other than 404): the state advances to the am-data.
    Advance(serde_json::Value, bool),
    /// 404: the subscription is gone at the subscriber.
    Gone,
    /// No answer, or 5xx: resent once its backoff has passed.
    Failed,
}

/// One watch pass at monotonic time `now` and wall-clock `now_epoch` (seconds):
/// tell each am-data subscription due now of a change since what it was last told.
/// Returns how many notifications were answered 2xx.
///
/// #1775 review MAJOR-2:
/// - expired subscriptions (TS 29.504 `expiry`) are removed first, and not told;
/// - at most [`am_data_watch_max`] subscriptions are served, round-robin;
/// - a subscriber that failed is skipped until its backoff has passed, and removed
///   once it has failed for [`AM_DATA_DEAD_AFTER`];
/// - the am-data reads, and then the notifications, run concurrently (at most
///   [`AM_DATA_WATCH_CONCURRENCY`] at once). Each subscription gets at most one
///   notification per pass, and the passes run one after another, so its changes
///   still arrive in order;
/// - the state is written to the store without a snapshot each, and persisted once
///   at the end of the pass, on a blocking thread.
async fn am_data_watch_pass_at(now: std::time::Instant, now_epoch: i64) -> usize {
    am_data_watch_pass_with(now, now_epoch, am_data_watch_max()).await
}

/// [`am_data_watch_pass_at`] serving at most `max` subscriptions.
async fn am_data_watch_pass_with(now: std::time::Instant, now_epoch: i64, max: usize) -> usize {
    use data_store::AM_DATA_NOTIFIED_COLLECTION as NOTIFIED;
    let ds = data_store::store();
    let mut dirty = false;

    // Expired subscription-data subscriptions go, for every notifier.
    for sub in ds.subs_matching(SubKind::SubscriptionData, |s| {
        data_store::sub_expired(s, now_epoch)
    }) {
        log::info!("subscription-data subscription {} expired: removed", sub.id);
        ds.sub_remove(&sub.id);
    }

    let watchers = data_store::am_data_watchers();
    // State of a subscription that is gone, or no longer watches am-data, goes.
    let live: std::collections::HashSet<String> =
        watchers.iter().map(|(_, s)| s.id.clone()).collect();
    for (id, _) in ds.doc_list(NOTIFIED) {
        if !live.contains(&id) {
            dirty |= ds.doc_remove_deferred(NOTIFIED, &id);
        }
    }
    if let Some(f) = am_data_failures().as_mut() {
        f.retain(|id, _| live.contains(id));
    }

    // Round-robin from after the previous pass's last one; skip the backed-off.
    let due: Vec<(String, data_store::StoredSub)> = {
        let failures = am_data_failures();
        let mut cursor = AM_DATA_CURSOR.lock().unwrap_or_else(|e| e.into_inner());
        let (due, next) = am_data_due(&watchers, cursor.as_deref(), max, |id| {
            failures
                .as_ref()
                .and_then(|f| f.get(id))
                .is_some_and(|f| f.next_try > now)
        });
        *cursor = next;
        due
    };

    // One MongoDB read per SUPI, concurrently.
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(AM_DATA_WATCH_CONCURRENCY));
    let mut supis: Vec<String> = due.iter().map(|(supi, _)| supi.clone()).collect();
    supis.sort();
    supis.dedup();
    let mut reads = tokio::task::JoinSet::new();
    for supi in supis {
        let limit = limit.clone();
        reads.spawn(async move {
            let _permit = limit.acquire_owned().await.ok();
            let now = read_am_data(&supi).await;
            (supi, now)
        });
    }
    let mut read: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    while let Some(done) = reads.join_next().await {
        if let Ok((supi, Some(now))) = done {
            read.insert(supi, now);
        }
    }

    // One notification per changed subscription, concurrently.
    let mut sends = tokio::task::JoinSet::new();
    for (supi, sub) in due {
        let Some(now_data) = read.get(&supi).cloned() else {
            continue;
        };
        let Some(told) = ds.doc_get(NOTIFIED, &sub.id) else {
            ds.doc_put_deferred(NOTIFIED, &sub.id, now_data);
            dirty = true;
            continue;
        };
        if told == now_data {
            continue;
        }
        let limit = limit.clone();
        sends.spawn(async move {
            let _permit = limit.acquire_owned().await.ok();
            let changes = data_store::am_data_changes(&told, &now_data);
            let payload = data_store::data_change_notify(
                &sub,
                &supi,
                &data_store::am_data_path(&supi),
                changes,
            );
            let target = nextgcore_sbi::log_redact::redact_last_segment(&sub.notify_uri);
            let outcome = match data_store::deliver_notification(&sub.notify_uri, &payload).await {
                Ok(status) if (200..300).contains(&status) => {
                    log::info!("[{supi}] am-data change notified to {target}: {status}");
                    WatchOutcome::Advance(now_data, true)
                }
                Ok(404) => {
                    log::info!(
                        "[{supi}] {target} answered 404: subscription {} is gone, removed",
                        sub.id
                    );
                    WatchOutcome::Gone
                }
                Ok(status) if (400..500).contains(&status) => {
                    log::warn!(
                        "[{supi}] {target} refused the am-data change ({status}); not resent"
                    );
                    WatchOutcome::Advance(now_data, false)
                }
                Ok(status) => {
                    log::warn!("[{supi}] {target} answered {status}; resent after a backoff");
                    WatchOutcome::Failed
                }
                Err(e) => {
                    log::warn!("[{supi}] {e}; resent after a backoff");
                    WatchOutcome::Failed
                }
            };
            (sub.id, outcome)
        });
    }
    let mut delivered = 0;
    while let Some(done) = sends.join_next().await {
        let Ok((id, outcome)) = done else {
            continue;
        };
        match outcome {
            WatchOutcome::Advance(now_data, ok) => {
                ds.doc_put_deferred(NOTIFIED, &id, now_data);
                dirty = true;
                delivered += usize::from(ok);
                if let Some(f) = am_data_failures().as_mut() {
                    f.remove(&id);
                }
            }
            WatchOutcome::Gone => {
                ds.sub_remove(&id);
                dirty |= ds.doc_remove_deferred(NOTIFIED, &id);
                if let Some(f) = am_data_failures().as_mut() {
                    f.remove(&id);
                }
            }
            WatchOutcome::Failed => {
                let mut failures = am_data_failures();
                let f = failures
                    .get_or_insert_with(std::collections::HashMap::new)
                    .entry(id.clone())
                    .or_insert(WatchFailures {
                        count: 0,
                        first: now,
                        next_try: now,
                    });
                f.count += 1;
                f.next_try = now + am_data_backoff(f.count);
                let dead = f.count >= AM_DATA_DEAD_MIN_FAILURES
                    && now.saturating_duration_since(f.first) >= AM_DATA_DEAD_AFTER;
                if dead {
                    let count = f.count;
                    failures.as_mut().map(|m| m.remove(&id));
                    drop(failures);
                    log::warn!(
                        "am-data subscription {id}: no answer for {} s ({count} tries): the \
                         subscriber is gone, removed",
                        AM_DATA_DEAD_AFTER.as_secs()
                    );
                    ds.sub_remove(&id);
                    dirty |= ds.doc_remove_deferred(NOTIFIED, &id);
                }
            }
        }
    }
    if dirty {
        let _ = tokio::task::spawn_blocking(|| data_store::store().persist_now()).await;
    }
    delivered
}

/// The subscriptions a pass serves, out of `watchers` (sorted by id): at most `max`,
/// starting after `cursor` (the id the previous pass stopped at) and wrapping round,
/// skipping those `backed_off`. With the cursor the next pass starts from: the last
/// one served when some were left out, `None` when every one was served.
fn am_data_due(
    watchers: &[(String, data_store::StoredSub)],
    cursor: Option<&str>,
    max: usize,
    backed_off: impl Fn(&str) -> bool,
) -> (Vec<(String, data_store::StoredSub)>, Option<String>) {
    let start = cursor.map_or(0, |c| watchers.partition_point(|(_, s)| s.id.as_str() <= c));
    let due: Vec<(String, data_store::StoredSub)> = watchers[start..]
        .iter()
        .chain(watchers[..start].iter())
        .filter(|(_, s)| !backed_off(&s.id))
        .take(max)
        .cloned()
        .collect();
    let next = if due.len() < watchers.len() {
        due.last().map(|(_, s)| s.id.clone())
    } else {
        None
    };
    (due, next)
}

/// One watch pass now ([`am_data_watch_pass_at`]).
async fn am_data_watch_pass() -> usize {
    am_data_watch_pass_at(
        std::time::Instant::now(),
        nextgcore_sbi::datetime::now_epoch_secs() as i64,
    )
    .await
}

// ============================================================================
// exposure-data (TS 29.519 shapes via TS 29.504 paths)
// ============================================================================

/// Handle /nudr-dr/v2/exposure-data/...
async fn handle_exposure_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = data_store::store();

    // /exposure-data/subs-to-notify[/{subId}]
    if parts.get(3).copied() == Some("subs-to-notify") {
        return match (parts.get(4).copied(), method) {
            (None, "POST") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                    return missing_mandatory("notificationUri");
                };
                if body
                    .get("monitoredResourceUris")
                    .and_then(|v| v.as_array())
                    .is_none_or(|a| a.is_empty())
                {
                    return missing_mandatory("monitoredResourceUris");
                }
                let owner = match owner_for_new_subscription(request, "Subscribe") {
                    Ok(owner) => owner,
                    Err(refused) => return *refused,
                };
                let sub = ds.sub_create_owned(SubKind::ExposureData, uri, body.clone(), owner);
                SbiResponse::with_status(201)
                    .with_header(
                        "Location",
                        format!("/nudr-dr/v2/exposure-data/subs-to-notify/{}", sub.id),
                    )
                    .with_body(body.to_string(), "application/json")
            }
            (Some(sub_id), "PUT") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                    return missing_mandatory("notificationUri");
                };
                if let Err(refused) =
                    sub_for_caller(sub_id, SubKind::ExposureData, request, "Modify")
                {
                    return *refused;
                }
                if ds.sub_replace(sub_id, SubKind::ExposureData, uri, body.clone()) {
                    SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
                } else {
                    send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                }
            }
            (Some(sub_id), "DELETE") => {
                if let Err(refused) =
                    sub_for_caller(sub_id, SubKind::ExposureData, request, "Unsubscribe")
                {
                    return *refused;
                }
                ds.sub_remove(sub_id);
                SbiResponse::with_status(204)
            }
            _ => send_method_not_allowed(method, "exposure-data/subs-to-notify"),
        };
    }

    // /exposure-data/{ueId}/...
    let Some(ue_id) = parts.get(3).copied() else {
        return send_bad_request("Missing ueId", Some("MANDATORY_IE_MISSING"));
    };
    match parts.get(4).copied() {
        Some("access-and-mobility-data") => {
            let path = format!("/nudr-dr/v2/exposure-data/{ue_id}/access-and-mobility-data");
            match method {
                "PUT" => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let created = ds.exposure_am_put(ue_id, body.clone());
                    notify_exposure_data_change(
                        ue_id,
                        &path,
                        serde_json::json!({"accessAndMobilityData": body}),
                    );
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(200)
                            .with_body(body.to_string(), "application/json")
                    }
                }
                "GET" => match ds.exposure_am_get(ue_id) {
                    Some(doc) => {
                        SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                    }
                    None => {
                        send_not_found("Access and mobility data not found", Some("DATA_NOT_FOUND"))
                    }
                },
                "PATCH" => {
                    let Some(mut doc) = ds.exposure_am_get(ue_id) else {
                        return send_not_found(
                            "Access and mobility data not found",
                            Some("DATA_NOT_FOUND"),
                        );
                    };
                    let patch = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    merge_patch(&mut doc, &patch);
                    ds.exposure_am_put(ue_id, doc.clone());
                    notify_exposure_data_change(
                        ue_id,
                        &path,
                        serde_json::json!({"accessAndMobilityData": doc}),
                    );
                    SbiResponse::with_status(204)
                }
                "DELETE" => {
                    if ds.exposure_am_remove(ue_id).is_some() {
                        notify_exposure_data_change(
                            ue_id,
                            &path,
                            serde_json::json!({"delResources": [path]}),
                        );
                        SbiResponse::with_status(204)
                    } else {
                        send_not_found("Access and mobility data not found", Some("DATA_NOT_FOUND"))
                    }
                }
                _ => send_method_not_allowed(method, "exposure-data/access-and-mobility-data"),
            }
        }
        Some("session-management-data") => {
            let Some(psi) = parts.get(5).copied() else {
                return send_bad_request("Missing pduSessionId", Some("MANDATORY_IE_MISSING"));
            };
            let path = format!("/nudr-dr/v2/exposure-data/{ue_id}/session-management-data/{psi}");
            match method {
                "PUT" => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let created = ds.exposure_sm_put(ue_id, psi, body.clone());
                    notify_exposure_data_change(
                        ue_id,
                        &path,
                        serde_json::json!({"pduSessionManagementData": [body]}),
                    );
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(200)
                            .with_body(body.to_string(), "application/json")
                    }
                }
                "GET" => match ds.exposure_sm_get(ue_id, psi) {
                    Some(doc) => {
                        SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                    }
                    None => {
                        send_not_found("Session management data not found", Some("DATA_NOT_FOUND"))
                    }
                },
                "DELETE" => {
                    if ds.exposure_sm_remove(ue_id, psi).is_some() {
                        notify_exposure_data_change(
                            ue_id,
                            &path,
                            serde_json::json!({"delResources": [path]}),
                        );
                        SbiResponse::with_status(204)
                    } else {
                        send_not_found("Session management data not found", Some("DATA_NOT_FOUND"))
                    }
                }
                _ => send_method_not_allowed(method, "exposure-data/session-management-data"),
            }
        }
        _ => send_not_found("Unknown exposure-data resource", None),
    }
}

// ============================================================================
// application-data (TS 29.519 shapes via TS 29.504 paths)
// ============================================================================

/// Split a comma-separated query parameter into owned strings.
fn csv_param(request: &SbiRequest, name: &str) -> Option<Vec<String>> {
    request.http.params.get(name).map(|v| {
        pct_decode(v)
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// Handle /nudr-dr/v2/application-data/...
async fn handle_application_data(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    match parts.get(3).copied() {
        // --- /application-data/pfds[/{appId}] -----------------------------
        Some("pfds") => match (parts.get(4).copied(), method) {
            (None, "GET") => {
                let app_ids =
                    csv_param(request, "appId").or_else(|| csv_param(request, "application-ids"));
                let list = ds.pfd_list(app_ids.as_deref());
                SbiResponse::with_status(200).with_body(
                    serde_json::Value::Array(list).to_string(),
                    "application/json",
                )
            }
            (Some(app_id), "GET") => match ds.pfd_get(app_id) {
                Some(doc) => {
                    SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                }
                None => send_not_found("PFD data not found", Some("DATA_NOT_FOUND")),
            },
            (Some(app_id), "PUT") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                // PfdDataForApp mandatory attributes (TS 29.551)
                if body.get("applicationId").and_then(|v| v.as_str()).is_none() {
                    return missing_mandatory("applicationId");
                }
                if body
                    .get("pfds")
                    .and_then(|v| v.as_array())
                    .is_none_or(|a| a.is_empty())
                {
                    return missing_mandatory("pfds");
                }
                let path = format!("/nudr-dr/v2/application-data/pfds/{app_id}");
                let created = ds.pfd_put(app_id, body.clone());
                notify_application_data_change(&path, app_id, false);
                if created {
                    SbiResponse::with_status(201)
                        .with_header("Location", path)
                        .with_body(body.to_string(), "application/json")
                } else {
                    SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
                }
            }
            (Some(app_id), "DELETE") => {
                if ds.pfd_remove(app_id).is_some() {
                    let path = format!("/nudr-dr/v2/application-data/pfds/{app_id}");
                    notify_application_data_change(&path, app_id, true);
                    SbiResponse::with_status(204)
                } else {
                    send_not_found("PFD data not found", Some("DATA_NOT_FOUND"))
                }
            }
            _ => send_method_not_allowed(method, "application-data/pfds"),
        },
        // --- /application-data/influenceData... ---------------------------
        Some("influenceData") => match parts.get(4).copied() {
            // Collection read with TS 29.519 query filters
            None => match method {
                "GET" => {
                    let influence_ids = csv_param(request, "influence-Ids");
                    let dnns = csv_param(request, "dnns");
                    let supis = csv_param(request, "supis");
                    let list = ds.influence_list(
                        influence_ids.as_deref(),
                        dnns.as_deref(),
                        supis.as_deref(),
                    );
                    SbiResponse::with_status(200).with_body(
                        serde_json::Value::Array(list).to_string(),
                        "application/json",
                    )
                }
                _ => send_method_not_allowed(method, "application-data/influenceData"),
            },
            // /influenceData/subs-to-notify[/{subscriptionId}]
            Some("subs-to-notify") => match (parts.get(5).copied(), method) {
                (None, "POST") => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                        return missing_mandatory("notificationUri");
                    };
                    // oneOf: dnns / snssais / internalGroupIds / supis
                    if !["dnns", "snssais", "internalGroupIds", "supis"]
                        .iter()
                        .any(|k| body.get(*k).and_then(|v| v.as_array()).is_some())
                    {
                        return missing_mandatory("dnns|snssais|internalGroupIds|supis");
                    }
                    let owner = match owner_for_new_subscription(request, "Subscribe") {
                        Ok(owner) => owner,
                        Err(refused) => return *refused,
                    };
                    let sub = ds.sub_create_owned(SubKind::AppInfluence, uri, body.clone(), owner);
                    SbiResponse::with_status(201)
                        .with_header(
                            "Location",
                            format!(
                                "/nudr-dr/v2/application-data/influenceData/subs-to-notify/{}",
                                sub.id
                            ),
                        )
                        .with_body(body.to_string(), "application/json")
                }
                (None, "GET") => {
                    // #1861: the caller's own subscriptions only.
                    let subs = ds.subs_matching(SubKind::AppInfluence, |s| {
                        subscription_caller_refusal(s.owner.as_deref(), request).is_none()
                    });
                    let list: Vec<serde_json::Value> = subs.into_iter().map(|s| s.body).collect();
                    SbiResponse::with_status(200).with_body(
                        serde_json::Value::Array(list).to_string(),
                        "application/json",
                    )
                }
                (Some(sub_id), "GET") => {
                    match sub_for_caller(sub_id, SubKind::AppInfluence, request, "Get") {
                        Ok(sub) => SbiResponse::with_status(200)
                            .with_body(sub.body.to_string(), "application/json"),
                        Err(refused) => *refused,
                    }
                }
                (Some(sub_id), "PUT") => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                        return missing_mandatory("notificationUri");
                    };
                    if let Err(refused) =
                        sub_for_caller(sub_id, SubKind::AppInfluence, request, "Modify")
                    {
                        return *refused;
                    }
                    if ds.sub_replace(sub_id, SubKind::AppInfluence, uri, body.clone()) {
                        SbiResponse::with_status(200)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                    }
                }
                (Some(sub_id), "DELETE") => {
                    if let Err(refused) =
                        sub_for_caller(sub_id, SubKind::AppInfluence, request, "Unsubscribe")
                    {
                        return *refused;
                    }
                    ds.sub_remove(sub_id);
                    SbiResponse::with_status(204)
                }
                _ => send_method_not_allowed(method, "influenceData/subs-to-notify"),
            },
            // /influenceData/{influenceId}
            Some(influence_id) => {
                let path = format!("/nudr-dr/v2/application-data/influenceData/{influence_id}");
                match method {
                    "PUT" => {
                        let body = match parse_json_body(request) {
                            Ok(v) => v,
                            Err(resp) => return *resp,
                        };
                        if body.get("afAppId").and_then(|v| v.as_str()).is_none() {
                            return missing_mandatory("afAppId");
                        }
                        let created = ds.influence_put(influence_id, body.clone());
                        notify_influence_data_change(&path, Some(&body));
                        if created {
                            SbiResponse::with_status(201)
                                .with_header("Location", path)
                                .with_body(body.to_string(), "application/json")
                        } else {
                            SbiResponse::with_status(200)
                                .with_body(body.to_string(), "application/json")
                        }
                    }
                    "PATCH" => {
                        let Some(mut doc) = ds.influence_get(influence_id) else {
                            return send_not_found(
                                "Traffic influence data not found",
                                Some("DATA_NOT_FOUND"),
                            );
                        };
                        let patch = match parse_json_body(request) {
                            Ok(v) => v,
                            Err(resp) => return *resp,
                        };
                        merge_patch(&mut doc, &patch);
                        ds.influence_put(influence_id, doc.clone());
                        notify_influence_data_change(&path, Some(&doc));
                        SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                    }
                    "DELETE" => {
                        if ds.influence_remove(influence_id).is_some() {
                            notify_influence_data_change(&path, None);
                            SbiResponse::with_status(204)
                        } else {
                            send_not_found(
                                "Traffic influence data not found",
                                Some("DATA_NOT_FOUND"),
                            )
                        }
                    }
                    "GET" => match ds.influence_get(influence_id) {
                        Some(doc) => SbiResponse::with_status(200)
                            .with_body(doc.to_string(), "application/json"),
                        None => send_not_found(
                            "Traffic influence data not found",
                            Some("DATA_NOT_FOUND"),
                        ),
                    },
                    _ => send_method_not_allowed(method, "application-data/influenceData"),
                }
            }
        },
        // --- /application-data/subs-to-notify[/{subsId}] -------------------
        Some("subs-to-notify") => match (parts.get(4).copied(), method) {
            (None, "POST") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                    return missing_mandatory("notificationUri");
                };
                let owner = match owner_for_new_subscription(request, "Subscribe") {
                    Ok(owner) => owner,
                    Err(refused) => return *refused,
                };
                let sub = ds.sub_create_owned(SubKind::AppData, uri, body.clone(), owner);
                SbiResponse::with_status(201)
                    .with_header(
                        "Location",
                        format!("/nudr-dr/v2/application-data/subs-to-notify/{}", sub.id),
                    )
                    .with_body(body.to_string(), "application/json")
            }
            (Some(sub_id), "PUT") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                    return missing_mandatory("notificationUri");
                };
                if let Err(refused) = sub_for_caller(sub_id, SubKind::AppData, request, "Modify") {
                    return *refused;
                }
                if ds.sub_replace(sub_id, SubKind::AppData, uri, body.clone()) {
                    SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
                } else {
                    send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                }
            }
            (Some(sub_id), "DELETE") => {
                if let Err(refused) =
                    sub_for_caller(sub_id, SubKind::AppData, request, "Unsubscribe")
                {
                    return *refused;
                }
                ds.sub_remove(sub_id);
                SbiResponse::with_status(204)
            }
            _ => send_method_not_allowed(method, "application-data/subs-to-notify"),
        },
        // --- the datasets that fell through to 404 before #87 --------------
        // TS 29.519 §5.6 names them exactly as spelled here; the issue's
        // informal "af-qos-data" / "eas-deployment-data" do not appear in the
        // OpenAPI, and routing an invented path would advertise a surface no
        // conformant consumer asks for.
        Some(
            collection @ ("bdtPolicyData" | "iptvConfigData" | "serviceParamData"
            | "am-influence-data" | "af-qos-data-sets" | "eas-deploy-data"),
        ) => handle_application_dataset(collection, parts.get(4).copied(), method, request),
        _ => send_not_found("Unknown application-data resource", None),
    }
}

/// Mandatory members of an application-data document, by dataset
/// (TS 29.519 §5.6.2). Datasets whose schema marks nothing required return an
/// empty slice rather than a made-up requirement.
fn application_dataset_required(collection: &str) -> &'static [&'static str] {
    match collection {
        // BdtPolicyData
        "bdtPolicyData" => &["bdtRefId"],
        // IptvConfigData
        "iptvConfigData" => &["afAppId", "multiAccCtrls"],
        _ => &[],
    }
}

/// CRUD for one application-data dataset (TS 29.519 §5.6).
///
/// All six share the same document shape — a collection of AF-provisioned
/// documents addressed by an id — so they share one handler; only the mandatory
/// members differ, and those come from [`application_dataset_required`]. The
/// collection GET returns every document, which is what an NEF or PCF reading
/// the dataset expects.
fn handle_application_dataset(
    collection: &str,
    doc_id: Option<&str>,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    let store_key = format!("app-{collection}");
    match (doc_id, method) {
        (None, "GET") => {
            let list: Vec<serde_json::Value> = ds
                .doc_list(&store_key)
                .into_iter()
                .map(|(_, v)| v)
                .collect();
            SbiResponse::with_status(200).with_body(
                serde_json::Value::Array(list).to_string(),
                "application/json",
            )
        }
        (Some(id), "GET") => match ds.doc_get(&store_key, id) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found(&format!("{collection} not found"), Some("DATA_NOT_FOUND")),
        },
        (Some(id), "PUT") => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            for attr in application_dataset_required(collection) {
                if body.get(*attr).is_none() {
                    return missing_mandatory(attr);
                }
            }
            let path = format!("/nudr-dr/v2/application-data/{collection}/{id}");
            let created = ds.doc_put(&store_key, id, body.clone());
            notify_application_data_change(&path, id, false);
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
            }
        }
        (Some(id), "PATCH") => {
            let Some(mut doc) = ds.doc_get(&store_key, id) else {
                return send_not_found(&format!("{collection} not found"), Some("DATA_NOT_FOUND"));
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            let path = format!("/nudr-dr/v2/application-data/{collection}/{id}");
            ds.doc_put(&store_key, id, doc.clone());
            notify_application_data_change(&path, id, false);
            SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
        }
        (Some(id), "DELETE") => {
            if ds.doc_remove(&store_key, id).is_some() {
                let path = format!("/nudr-dr/v2/application-data/{collection}/{id}");
                notify_application_data_change(&path, id, true);
                SbiResponse::with_status(204)
            } else {
                send_not_found(&format!("{collection} not found"), Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, &format!("application-data/{collection}")),
    }
}

// ============================================================================
// Data builders (from nudr_handler.rs, adapted for direct SBI response)
// ============================================================================

fn build_am_data(data: &nextgcore_dbi::types::NextgcoreSubscriptionData) -> serde_json::Value {
    let mut am = serde_json::Map::new();
    let gpsis = subscriber_gpsis(data);
    if !gpsis.is_empty() {
        am.insert("gpsis".to_string(), serde_json::Value::Array(gpsis));
    }
    if data.ambr.uplink > 0 || data.ambr.downlink > 0 {
        am.insert(
            "subscribedUeAmbr".to_string(),
            serde_json::json!({
                "uplink": format_ambr(data.ambr.uplink),
                "downlink": format_ambr(data.ambr.downlink)
            }),
        );
    }
    if data.num_of_slice > 0 {
        let mut default_nssais = Vec::new();
        let mut single_nssais = Vec::new();
        for slice in &data.slice {
            let mut nssai_json = serde_json::Map::new();
            nssai_json.insert(
                "sst".to_string(),
                serde_json::Value::Number(slice.s_nssai.sst.into()),
            );
            if slice.s_nssai.has_sd() {
                nssai_json.insert(
                    "sd".to_string(),
                    serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)),
                );
            }
            let val = serde_json::Value::Object(nssai_json);
            if slice.default_indicator {
                default_nssais.push(val);
            } else {
                single_nssais.push(val);
            }
        }
        let mut nssai = serde_json::Map::new();
        if !default_nssais.is_empty() {
            nssai.insert(
                "defaultSingleNssais".to_string(),
                serde_json::Value::Array(default_nssais),
            );
        }
        if !single_nssais.is_empty() {
            nssai.insert(
                "singleNssais".to_string(),
                serde_json::Value::Array(single_nssais),
            );
        }
        am.insert("nssai".to_string(), serde_json::Value::Object(nssai));
    }
    serde_json::Value::Object(am)
}

fn build_smf_selection_data(
    data: &nextgcore_dbi::types::NextgcoreSubscriptionData,
) -> serde_json::Value {
    let mut smf_sel = serde_json::Map::new();
    let mut snssai_infos = serde_json::Map::new();
    for slice in &data.slice {
        let snssai_key = if slice.s_nssai.has_sd() {
            format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
        } else {
            format!("{:02x}", slice.s_nssai.sst)
        };
        // `defaultDnnIndicator` is emitted ONLY when provisioned true (#264, TS 29.503
        // `DnnInfo`; TS 23.501 §5.6.1). The member is typed `boolean` with no default and
        // carries one meaning -- "this is the subscribed default" -- so emitting `false` on
        // every other entry would assert that the operator considered each one and rejected
        // it, where omission says the subscription is silent.
        //
        // That distinction is load-bearing for the consumer: `smfd`'s `select_default_dnn`
        // treats a single unflagged DNN as the unambiguous default (rule 2) and refuses a
        // multi-DNN set with none flagged (rule 3), and it can only tell those apart if
        // "not flagged" and "flagged false" look the same on the wire.
        let dnn_infos: Vec<serde_json::Value> = slice
            .session
            .iter()
            .filter_map(|sess| {
                sess.name.as_ref().map(|dnn| {
                    let mut info = serde_json::Map::new();
                    info.insert("dnn".to_string(), serde_json::Value::String(dnn.clone()));
                    if sess.default_dnn_indicator {
                        info.insert(
                            "defaultDnnIndicator".to_string(),
                            serde_json::Value::Bool(true),
                        );
                    }
                    serde_json::Value::Object(info)
                })
            })
            .collect();
        if !dnn_infos.is_empty() {
            snssai_infos.insert(snssai_key, serde_json::json!({"dnnInfos": dnn_infos}));
        }
    }
    if !snssai_infos.is_empty() {
        smf_sel.insert(
            "subscribedSnssaiInfos".to_string(),
            serde_json::Value::Object(snssai_infos),
        );
    }
    serde_json::Value::Object(smf_sel)
}

/// Build the TS 29.571 §5.5.3 `Arp` JSON object.
///
/// All three members (`priorityLevel`, `preemptCap`, `preemptVuln`) are
/// required by the schema; a strict OpenAPI-validating SMF rejects the
/// DnnConfiguration when either pre-emption field is absent.
///
/// Mapping (mirrors the legacy `nudr_handler.rs:636-648`):
/// - `pre_emption_capability == 1`   → `"MAY_PREEMPT"`, else `"NOT_PREEMPT"`
/// - `pre_emption_vulnerability == 1` → `"PREEMPTABLE"`, else `"NOT_PREEMPTABLE"`
fn arp_json(arp: &nextgcore_dbi::types::NextgcoreArp) -> serde_json::Value {
    let preempt_cap = if arp.pre_emption_capability == 1 {
        "MAY_PREEMPT"
    } else {
        "NOT_PREEMPT"
    };
    let preempt_vuln = if arp.pre_emption_vulnerability == 1 {
        "PREEMPTABLE"
    } else {
        "NOT_PREEMPTABLE"
    };
    serde_json::json!({
        "priorityLevel": arp.priority_level,
        "preemptCap": preempt_cap,
        "preemptVuln": preempt_vuln,
    })
}

fn build_sm_data(data: &nextgcore_dbi::types::NextgcoreSubscriptionData) -> serde_json::Value {
    let mut sm_data_list = Vec::new();
    for slice in &data.slice {
        let mut sm_entry = serde_json::Map::new();
        let mut snssai = serde_json::Map::new();
        snssai.insert(
            "sst".to_string(),
            serde_json::Value::Number(slice.s_nssai.sst.into()),
        );
        if slice.s_nssai.has_sd() {
            snssai.insert(
                "sd".to_string(),
                serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)),
            );
        }
        sm_entry.insert("singleNssai".to_string(), serde_json::Value::Object(snssai));
        let mut dnn_configs = serde_json::Map::new();
        for sess in &slice.session {
            if let Some(dnn) = &sess.name {
                let pdu_type = match sess.session_type {
                    1 => "IPV4",
                    2 => "IPV6",
                    3 => "IPV4V6",
                    _ => "IPV4V6",
                };
                // TS 29.505 §5.4.4 sscModes: NextgcoreSession carries no provisioned
                // SSC-mode field in the current DB schema.  The legacy
                // nudr_handler.rs:627 emitted the full set {1,2,3} as the
                // documented default, which is used here. (udrd-12)
                dnn_configs.insert(dnn.clone(), serde_json::json!({
                    "pduSessionTypes": { "defaultSessionType": pdu_type, "allowedSessionTypes": [pdu_type] },
                    "sscModes": {
                        "defaultSscMode": "SSC_MODE_1",
                        "allowedSscModes": ["SSC_MODE_1", "SSC_MODE_2", "SSC_MODE_3"]
                    },
                    "5gQosProfile": { "5qi": sess.qos.index, "arp": arp_json(&sess.qos.arp) },
                    "sessionAmbr": { "uplink": format_ambr(sess.ambr.uplink), "downlink": format_ambr(sess.ambr.downlink) }
                }));
            }
        }
        if !dnn_configs.is_empty() {
            sm_entry.insert(
                "dnnConfigurations".to_string(),
                serde_json::Value::Object(dnn_configs),
            );
        }
        sm_data_list.push(serde_json::Value::Object(sm_entry));
    }
    serde_json::Value::Array(sm_data_list)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a TS 29.505 AuthenticationSubscription document.
///
/// The SequenceNumber object carries `sqnScheme` and `indLength` alongside the
/// 12-hex-digit `sqn` per the TS 29.505 SequenceNumber shape (the UE-side IND
/// is 5 bits per TS 33.102 SQN array management).
/// Validate an optional 256-bit key member provisioned as hex (#115).
///
/// Returns `Ok(None)` when absent — which is the normal case for every non-TUAK
/// subscriber — and a 400 when present but not 64 hex characters. Rejecting at
/// provisioning time rather than at authentication time is the point: TS 35.231's TOP and
/// TOPc are 256-bit, and a short or non-hex value silently becomes a zero-padded key that
/// authenticates against nothing.
fn validate_optional_key_256(
    body: &serde_json::Value,
    member: &str,
) -> Result<Option<String>, Box<SbiResponse>> {
    match body.get(member).and_then(|v| v.as_str()) {
        None => Ok(None),
        Some("") => Ok(None),
        Some(s) if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(Some(s.to_string()))
        }
        Some(_) => Err(Box::new(send_error(
            400,
            "Bad Request",
            &format!("{member} must be 64 hex characters (a 256-bit TUAK operator field)"),
            Some("MANDATORY_IE_INCORRECT"),
        ))),
    }
}

fn build_auth_subscription_json(
    supi: &str,
    auth_info: &nextgcore_dbi::subscription::NextgcoreDbiAuthInfo,
) -> serde_json::Value {
    // TS 29.505 §5.4.2.2: serve the provisioned authenticationMethod (AuthMethod).
    // Legacy subscriber docs lack the field (empty) -> default to "5G_AKA" per
    // TS 33.501 §6.1.2. (udrd-10 / udrd#1)
    let auth_method = if auth_info.authentication_method.is_empty() {
        "5G_AKA"
    } else {
        auth_info.authentication_method.as_str()
    };

    // TS 29.505 §5.4.2.23 / TS 33.102 SQN array management: with indLength=5
    // the low 5 bits of the 48-bit SQN are the IND component and must be
    // zeroed in the stored/served representation. (udrd-08)
    const IND_LENGTH: u64 = 5;
    const SQN_48_MASK: u64 = 0xFFFF_FFFF_FFFF;
    const IND_MASK: u64 = (1u64 << IND_LENGTH) - 1; // 0x1F
    let sqn_zeroed = (auth_info.sqn & SQN_48_MASK) & !IND_MASK;

    let mut out = serde_json::json!({
        "authenticationMethod": auth_method,
        "encPermanentKey": bytes_to_hex(&auth_info.k),
        "encOpcKey": bytes_to_hex(if auth_info.use_opc { &auth_info.opc } else { &auth_info.op }),
        "authenticationManagementField": bytes_to_hex(&auth_info.amf),
        "supi": supi,
        "sequenceNumber": {
            "sqnScheme": "NON_TIME_BASED",
            "sqn": format!("{sqn_zeroed:012x}"),
            "indLength": IND_LENGTH
        }
    });

    // #115: TS 29.505 `algorithmId` and `encTopcKey`, both optional (0..1) and both
    // OMITTED when not provisioned rather than emitted as empty strings — an empty
    // `algorithmId` is not "MILENAGE", it is a value the UDM would have to interpret,
    // and the whole point of the field being absent is that there is nothing to
    // interpret. Every subscriber provisioned before #115 therefore serialises exactly
    // as it did before.
    if let Some(obj) = out.as_object_mut() {
        if !auth_info.algorithm_id.is_empty() {
            obj.insert(
                "algorithmId".to_string(),
                serde_json::json!(auth_info.algorithm_id),
            );
        }
        if auth_info.use_topc {
            obj.insert(
                "encTopcKey".to_string(),
                serde_json::json!(bytes_to_hex(&auth_info.topc)),
            );
        }
    }
    out
}

/// Lossless AMBR formatter (udrd-02).
///
/// Chooses the largest SI unit (`Tbps` → `Gbps` → `Mbps` → `Kbps` → `bps`)
/// that divides `bps` exactly, producing a value that round-trips back to the
/// original bit-rate.  Truncating integer division is intentionally avoided —
/// `1_500_000_000 bps` becomes `"1500 Mbps"`, not `"1 Gbps"`.
///
/// The output always matches the TS 29.571 `BitRate` pattern
/// `^\d+(\.\d+)? (bps|Kbps|Mbps|Gbps|Tbps)$`.
fn format_ambr(bps: u64) -> String {
    if bps == 0 {
        return "0 bps".to_string();
    }
    const TBPS: u64 = 1_000_000_000_000;
    const GBPS: u64 = 1_000_000_000;
    const MBPS: u64 = 1_000_000;
    const KBPS: u64 = 1_000;
    if bps.is_multiple_of(TBPS) {
        format!("{} Tbps", bps / TBPS)
    } else if bps.is_multiple_of(GBPS) {
        format!("{} Gbps", bps / GBPS)
    } else if bps.is_multiple_of(MBPS) {
        format!("{} Mbps", bps / MBPS)
    } else if bps.is_multiple_of(KBPS) {
        format!("{} Kbps", bps / KBPS)
    } else {
        format!("{bps} bps")
    }
}

// ============================================================================
// Config parsing
// ============================================================================

/// Parse db_uri from YAML config file
fn parse_db_uri(config_path: &str) -> String {
    // Try config file first
    if let Ok(content) = std::fs::read_to_string(config_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("db_uri:") {
                let uri = trimmed.trim_start_matches("db_uri:").trim();
                if !uri.is_empty() {
                    log::info!("Found db_uri in config: {}", mask_uri(uri));
                    return uri.to_string();
                }
            }
        }
    }
    // Fall back to env var
    if let Ok(uri) = std::env::var("DB_URI") {
        return uri;
    }
    // Default for Docker deployment
    String::from("mongodb://172.23.0.2/nextgcore")
}

/// Mask MongoDB URI for logging (hide credentials)
fn mask_uri(uri: &str) -> String {
    if let Some(at_pos) = uri.find('@') {
        if let Some(proto_end) = uri.find("://") {
            return format!("{}://***@{}", &uri[..proto_end], &uri[at_pos + 1..]);
        }
    }
    uri.to_string()
}

// ============================================================================
// Infrastructure
// ============================================================================

/// Initialize logging based on command line arguments
fn init_logging(args: &Args) -> Result<()> {
    // RUST_LOG if set, else --log-level: the same for every NF (#691).
    let mut builder = nextgcore_core::log::nf_log_builder(&nextgcore_core::log::nf_log_level(
        args.log_level.as_deref(),
        Some(&args.config),
    ));

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

/// Async main event loop
async fn run_event_loop_async(shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    log::debug!("Exiting main event loop");
    Ok(())
}

/// Every Nudr service this UDR serves: the service name, the API version it is
/// defined at, and the NF types allowed to consume it (TS 29.510 §6.1.6.2.3
/// `NFService.allowedNfTypes`).
///
/// ONE table (#392), so the advertised surface is stated in a single place. The
/// per-service version is normative and differs between the two: TS 29.504
/// §6.1.1 says "The `<apiVersion>` shall be v2" for **Nudr_DataRepository**,
/// while `TS29504_Nudr_GroupIDmap.yaml` fixes Nudr_GroupIDmap at
/// `{apiRoot}/nudr-group-id-map/v1`.
const UDR_SERVICES: &[(&str, &str, &[&str])] = &[
    // TS 29.504 Nudr_DataRepository.
    ("nudr-dr", "v2", &["UDM", "PCF", "AUSF", "NEF", "SCP"]),
    // TS 29.504 Nudr_GroupIDmap, routed by `handle_group_id_map` since #87.
    // #392: it was routed and working but absent from the registered profile, and
    // the NRF filters discovery on `nfServices[].serviceName`, so a UDM or AUSF
    // resolving a subscriber's NF-group could not find this UDR by service name.
    ("nudr-group-id-map", "v1", &["UDM", "AUSF", "NRF", "SCP"]),
];

/// #1811: the resource/operation-level scopes of a UDR service, and the ONE NF
/// type each is registered for in `allowedOperationsPerNfType` (TS 29.510
/// Table 6.1.6.2.3-1 NOTE 11), so the NRF grants it to that type only.
///
/// The AuthenticationSubscription resource holds K, OPc/TOPc and SQN. TS 33.501
/// §6.1.1 keeps the long-term key in the ARPF, which TS 23.501 §6.2.7 co-locates
/// with the UDM: the UDM is its only legitimate reader (Nudm_UEAU) and writer
/// (the SQN PATCH after a resynchronisation, TS 33.102 Annex C.3). Spellings are
/// TS 29.505's (`nextgcore_sbi::resource_scope`).
const UDR_RESOURCE_SCOPES: &[(&str, &str, &str)] = &[
    (
        "nudr-dr",
        nextgcore_sbi::resource_scope::NUDR_DR_AUTH_SUBSCRIPTION_READ,
        "UDM",
    ),
    (
        "nudr-dr",
        nextgcore_sbi::resource_scope::NUDR_DR_AUTH_SUBSCRIPTION_MODIFY,
        "UDM",
    ),
    // #2079: the UDM's context data (NF registrations, authentication status,
    // its SDM / EE subscriptions): TS 29.505 §5.2.6.1 "stored in the UDR by the
    // UDM", TS 23.501 §6.2.11. The SCP relays and is not granted them itself.
    (
        "nudr-dr",
        nextgcore_sbi::resource_scope::NUDR_DR_SUBSCRIPTION_DATA,
        "UDM",
    ),
    (
        "nudr-dr",
        nextgcore_sbi::resource_scope::NUDR_DR_REGISTRATIONS_WRITE,
        "UDM",
    ),
];

/// The `allowedOperationsPerNfType` of UDR service `name`, or `None` when the
/// service has no resource-level scope (#1811).
///
/// NOTE 11: once the map is present it must name EVERY NF type allowed the
/// service, with all its scopes, the service-level one included -- a type left
/// out is barred from the whole service. So each of `allowed` gets the
/// service-level scope, and only the type [`UDR_RESOURCE_SCOPES`] names gets a
/// resource scope.
fn udr_allowed_operations(name: &str, allowed: &[&str]) -> Option<serde_json::Value> {
    if !UDR_RESOURCE_SCOPES.iter().any(|(svc, _, _)| *svc == name) {
        return None;
    }
    let map: serde_json::Map<String, serde_json::Value> = allowed
        .iter()
        .map(|nf_type| {
            let mut scopes = vec![name.to_string()];
            scopes.extend(
                UDR_RESOURCE_SCOPES
                    .iter()
                    .filter(|(svc, _, t)| *svc == name && t == nf_type)
                    .map(|(_, scope, _)| scope.to_string()),
            );
            (nf_type.to_string(), serde_json::json!(scopes))
        })
        .collect();
    Some(serde_json::Value::Object(map))
}

/// Build the UDR's NFProfile for NRF registration (TS 29.510 §6.1.6.2.2).
///
/// Split out of `register_with_nrf` so the advertised service list and API
/// versions can be asserted without standing up an NRF. Each service carries its
/// own `ipEndPoints` (without which a consumer that discovers the service has no
/// port to dial) and `allowedNfTypes`; the NF-level `allowedNfTypes` is the UNION
/// over the services, since a type barred at NF level can never reach any
/// service.
fn build_udr_nf_profile(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    scheme: nextgcore_sbi::types::UriScheme,
) -> serde_json::Value {
    let services: Vec<serde_json::Value> = UDR_SERVICES
        .iter()
        .map(|(name, version, allowed)| {
            let mut service = serde_json::json!({
                "serviceInstanceId": format!("{nf_instance_id}-{name}"),
                "serviceName": name,
                // apiFullVersion must agree with the URI version, not lag it.
                "versions": [{
                    "apiVersionInUri": version,
                    "apiFullVersion": format!("{}.0.0", version.trim_start_matches('v')),
                }],
                "scheme": scheme.as_str(),
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
                "allowedNfTypes": allowed,
            });
            if let Some(ops) = udr_allowed_operations(name, allowed) {
                service["allowedOperationsPerNfType"] = ops;
            }
            service
        })
        .collect();

    let mut nf_allowed: Vec<&str> = Vec::new();
    for (_, _, allowed) in UDR_SERVICES {
        for t in *allowed {
            if !nf_allowed.contains(t) {
                nf_allowed.push(t);
            }
        }
    }

    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "UDR",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": services,
            "allowedNfTypes": nf_allowed,
            "heartBeatTimer": 10
        }),
        sbi_addr,
    )
}

/// Register UDR with NRF.
///
/// Returns the NF instance ID on success so the caller can start a heartbeat
/// worker.
async fn register_with_nrf(
    sbi_addr: &str,
    sbi_port: u16,
    sbi_scheme: nextgcore_sbi::types::UriScheme,
) -> Result<String, String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(String::new());
        }
    };

    log::info!("Registering UDR with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_nrf_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id =
        nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Udr)
            .to_string();

    let nf_profile = build_udr_nf_profile(&nf_instance_id, sbi_addr, sbi_port, sbi_scheme);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("UDR registered with NRF successfully (id={nf_instance_id})");
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&nf_profile);
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

#[cfg(test)]
mod tests {
    use super::*;

    const PCF_A_1861: &str = "aaaaaaaa-1861-4000-8000-00000000000a";
    const PCF_B_1861: &str = "bbbbbbbb-1861-4000-8000-00000000000b";

    fn as_nf_1861(
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
        who: Option<&str>,
    ) -> SbiRequest {
        let mut r = SbiRequest {
            header: nextgcore_sbi::message::SbiHeader::with_method_uri(method, uri),
            ..SbiRequest::default()
        };
        if let Some(b) = body {
            r.http.set_content(b.to_string());
            r.http.set_header("Content-Type", "application/json");
        }
        r.oauth2_subject = who.map(str::to_string);
        r
    }

    /// #1903 review M1 / M2: under the production SBI profile an anonymous
    /// Subscribe is refused before anything is stored, and an ownerless
    /// (pre-#1861) subscription is frozen against every caller, its old creator
    /// included. Under `dev` both are as before. A bound subscription is judged
    /// the same way under both.
    #[test]
    fn production_refuses_anonymous_subscribes_and_freezes_ownerless_ones_1903() {
        let pcf_a = "aaaaaaaa-1903-4000-8000-00000000000a";
        let pcf_b = "bbbbbbbb-1903-4000-8000-00000000000b";
        let caller = |who: Option<&str>| {
            let mut r = SbiRequest::post("/nudr-dr/v2/policy-data/subs-to-notify");
            r.oauth2_subject = who.map(str::to_string);
            r
        };
        let refused = owner_for_new_subscription_in(&caller(None), "Subscribe", true)
            .expect_err("anonymous Subscribe under production");
        assert_eq!(refused.status, 403);
        assert_eq!(
            owner_for_new_subscription_in(&caller(None), "Subscribe", false).ok(),
            Some(None),
            "dev: ownerless as before"
        );
        assert_eq!(
            owner_for_new_subscription_in(&caller(Some(pcf_a)), "Subscribe", true).ok(),
            Some(Some(pcf_a.to_string()))
        );

        for who in [Some(pcf_a), Some(pcf_b), None] {
            let why = subscription_caller_refusal_in(None, &caller(who), true)
                .unwrap_or_else(|| panic!("{who:?} reached a frozen subscription"));
            assert!(why.contains("frozen"), "{why}");
            assert_eq!(
                subscription_caller_refusal_in(None, &caller(who), false),
                None
            );
        }
        for production in [true, false] {
            assert_eq!(
                subscription_caller_refusal_in(Some(pcf_a), &caller(Some(pcf_a)), production),
                None
            );
            assert!(
                subscription_caller_refusal_in(Some(pcf_a), &caller(Some(pcf_b)), production)
                    .is_some()
            );
        }
    }

    /// #1903: every subscription route goes through the hardened wrappers, so the
    /// production rules above cannot be bypassed by a site that calls the shared
    /// helper directly. Each direct call appears once, inside its wrapper.
    #[test]
    fn every_subscription_site_uses_the_production_wrappers_1903() {
        let src = include_str!("main.rs");
        for direct in [
            "nextgcore_udrd::owner_binding::owner_for_new_resource_with(",
            "nextgcore_udrd::owner_binding::non_owner_refusal_with(",
        ] {
            assert_eq!(
                src.matches(direct).count(),
                2,
                "{direct}: the wrapper and this test"
            );
        }
        assert_eq!(
            src.matches("nextgcore_udrd::owner_binding::refuse_non_owner(")
                .count(),
            1,
            "only this test names it"
        );
    }

    /// #1861, TS 29.504 §5.2 / TS 29.519 §5.2 / TS 33.501 §13.4.1: every
    /// subs-to-notify tree binds a subscription to the verified identity that
    /// created it. Another NF, or an anonymous caller, is refused 403 on read,
    /// modify and delete with the subscription unchanged; the owner manages it;
    /// and the id is not the next integer.
    #[tokio::test]
    async fn a_subscription_is_managed_by_its_creator_only_1861() {
        let ue = "imsi-001010000001861";
        let cb = "http://pcf-a.example/cb";
        let evil = "http://evil.example/cb";
        // (collection, create body, PUT/PATCH method, modify body, GET doc served)
        let trees: Vec<(&str, serde_json::Value, &str, serde_json::Value, bool)> = vec![
            (
                "/nudr-dr/v2/policy-data/subs-to-notify",
                json!({"notificationUri": cb, "monitoredResourceUris": ["/x"]}),
                "PUT",
                json!({"notificationUri": evil, "monitoredResourceUris": ["/x"]}),
                true,
            ),
            (
                "/nudr-dr/v2/subscription-data/subs-to-notify",
                json!({"ueId": ue, "callbackReference": cb, "monitoredResourceUris": ["/y"]}),
                "PATCH",
                json!([{"op": "replace", "path": "/callbackReference", "value": evil}]),
                true,
            ),
            (
                "/nudr-dr/v2/exposure-data/subs-to-notify",
                json!({"notificationUri": cb, "monitoredResourceUris": ["/z"]}),
                "PUT",
                json!({"notificationUri": evil, "monitoredResourceUris": ["/z"]}),
                false,
            ),
            (
                "/nudr-dr/v2/application-data/subs-to-notify",
                json!({"notificationUri": cb}),
                "PUT",
                json!({"notificationUri": evil}),
                false,
            ),
            (
                "/nudr-dr/v2/application-data/influenceData/subs-to-notify",
                json!({"notificationUri": cb, "dnns": ["internet"]}),
                "PUT",
                json!({"notificationUri": evil, "dnns": ["internet"]}),
                true,
            ),
            (
                "/nudr-group-id-map/v1/nf-group-ids/subscriptions",
                json!({"callbackReference": cb}),
                "PUT",
                json!({"callbackReference": evil}),
                true,
            ),
        ];
        let ds = data_store::store();
        for (collection, create, modify_method, modify, has_get) in trees {
            let resp = udr_sbi_route(as_nf_1861(
                "POST",
                collection,
                Some(create),
                Some(PCF_A_1861),
            ))
            .await;
            assert_eq!(resp.status, 201, "{collection}: {:?}", resp.http.content);
            let location = resp.http.get_header("Location").expect("Location").clone();
            let id = location.rsplit('/').next().unwrap().to_string();
            assert!(
                id.len() == 32 && id.parse::<u64>().is_err(),
                "{collection}: {id}"
            );
            assert_eq!(
                ds.sub_get(&id).and_then(|s| s.owner).as_deref(),
                Some(PCF_A_1861)
            );
            let doc = format!("{collection}/{id}");

            for who in [Some(PCF_B_1861), None] {
                let mut ops = vec![(modify_method, Some(modify.clone())), ("DELETE", None)];
                if has_get {
                    ops.push(("GET", None));
                }
                for (method, body) in ops {
                    let resp = udr_sbi_route(as_nf_1861(method, &doc, body, who)).await;
                    assert_eq!(resp.status, 403, "{who:?} {method} {doc}");
                    let pd: serde_json::Value =
                        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
                    assert!(
                        pd["detail"]
                            .as_str()
                            .unwrap_or_default()
                            .contains(&format!("belongs to NF instance {PCF_A_1861}")),
                        "{who:?} {method} {doc}: {pd}"
                    );
                }
                let sub = ds.sub_get(&id).expect("a refused request removes nothing");
                assert_eq!(sub.notify_uri, cb, "a refused request redirects nothing");
            }

            // The owner modifies and then removes it.
            let resp = udr_sbi_route(as_nf_1861(
                modify_method,
                &doc,
                Some(modify),
                Some(PCF_A_1861),
            ))
            .await;
            assert!(matches!(resp.status, 200 | 204), "{doc}: {}", resp.status);
            assert_eq!(ds.sub_get(&id).unwrap().notify_uri, evil);
            let resp = udr_sbi_route(as_nf_1861("DELETE", &doc, None, Some(PCF_A_1861))).await;
            assert_eq!(resp.status, 204, "{doc}");
            assert!(ds.sub_get(&id).is_none());
        }
    }

    /// #1861: the ue-id collection operations of subscription-data subs-to-notify
    /// see and remove the caller's own subscriptions only, and an id of another
    /// kind is not reachable through a different tree.
    #[tokio::test]
    async fn collection_operations_and_other_trees_respect_the_owner_1861() {
        let ue = "imsi-001010000011861";
        let coll = "/nudr-dr/v2/subscription-data/subs-to-notify";
        let create = |cb: &str| json!({"ueId": ue, "callbackReference": cb, "monitoredResourceUris": ["/y"]});
        let ds = data_store::store();
        let a = udr_sbi_route(as_nf_1861(
            "POST",
            coll,
            Some(create("http://a/cb")),
            Some(PCF_A_1861),
        ))
        .await;
        assert_eq!(a.status, 201);
        let a_id = a
            .http
            .get_header("Location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        let mut req = as_nf_1861("GET", coll, None, Some(PCF_B_1861));
        req.http.params.insert("ue-id".to_string(), ue.to_string());
        let listed = udr_sbi_route(req).await;
        assert_eq!(listed.status, 200);
        assert_eq!(
            listed.http.content.as_deref(),
            Some("[]"),
            "B sees none of A's"
        );

        let mut req = as_nf_1861("DELETE", coll, None, Some(PCF_B_1861));
        req.http.params.insert("ue-id".to_string(), ue.to_string());
        assert_eq!(udr_sbi_route(req).await.status, 204);
        assert!(
            ds.sub_get(&a_id).is_some(),
            "B's bulk delete left A's subscription"
        );

        let mut req = as_nf_1861("GET", coll, None, Some(PCF_A_1861));
        req.http.params.insert("ue-id".to_string(), ue.to_string());
        let listed = udr_sbi_route(req).await;
        assert!(listed
            .http
            .content
            .as_deref()
            .unwrap_or_default()
            .contains(&a_id));

        // A SubscriptionData id through the exposure-data tree: 404, still there.
        let resp = udr_sbi_route(as_nf_1861(
            "DELETE",
            &format!("/nudr-dr/v2/exposure-data/subs-to-notify/{a_id}"),
            None,
            Some(PCF_A_1861),
        ))
        .await;
        assert_eq!(resp.status, 404);
        assert!(ds.sub_get(&a_id).is_some());

        let mut req = as_nf_1861("DELETE", coll, None, Some(PCF_A_1861));
        req.http.params.insert("ue-id".to_string(), ue.to_string());
        assert_eq!(udr_sbi_route(req).await.status, 204);
        assert!(
            ds.sub_get(&a_id).is_none(),
            "the owner's bulk delete removed it"
        );
    }

    /// #1861: a caller whose token and certificate disagree subscribes nothing.
    #[tokio::test]
    async fn a_subscribe_with_disagreeing_identities_creates_nothing_1861() {
        let cb = "http://disagree-1861.example/cb";
        let mut req = as_nf_1861(
            "POST",
            "/nudr-dr/v2/policy-data/subs-to-notify",
            Some(json!({"notificationUri": cb, "monitoredResourceUris": ["/x"]})),
            Some(PCF_A_1861),
        );
        req.peer_cert_nf_instance_id = Some(PCF_B_1861.to_string());
        let resp = udr_sbi_route(req).await;
        assert_eq!(resp.status, 403);
        assert!(data_store::store()
            .subs_matching(SubKind::PolicyData, |s| s.notify_uri == cb)
            .is_empty());
    }

    #[test]
    fn pct_decode_never_panics_on_a_multi_byte_character() {
        // #765: `&s[i + 1..i + 3]` cut inside the e-acute and panicked.
        assert_eq!(pct_decode("%a\u{e9}"), "%a\u{e9}");
        assert_eq!(pct_decode("%+1"), "%+1");
        assert_eq!(pct_decode("imsi%2D001010000000001"), "imsi-001010000000001");
        assert_eq!(pct_decode("x%41"), "xA");
    }

    /// #1811: the registered nudr-dr service names, in
    /// `allowedOperationsPerNfType`, every NF type `allowedNfTypes` admits with
    /// the service-level scope (TS 29.510 Table 6.1.6.2.3-1 NOTE 11: a type left
    /// out would be barred from the whole service), and grants the
    /// AuthenticationSubscription scopes to the UDM alone.
    #[test]
    fn the_profile_grants_the_auth_subscription_scopes_to_the_udm_only_1811() {
        use nextgcore_sbi::resource_scope::{
            NUDR_DR_AUTH_SUBSCRIPTION_MODIFY as MODIFY, NUDR_DR_AUTH_SUBSCRIPTION_READ as READ,
        };
        let profile = build_udr_nf_profile(
            "udr-1811",
            "10.45.0.11",
            7777,
            nextgcore_sbi::types::UriScheme::Http,
        );
        let service = |name: &str| {
            profile["nfServices"]
                .as_array()
                .expect("nfServices")
                .iter()
                .find(|s| s["serviceName"] == name)
                .cloned()
                .expect("service registered")
        };
        let dr = service("nudr-dr");
        let ops = dr["allowedOperationsPerNfType"]
            .as_object()
            .expect("nudr-dr registers allowedOperationsPerNfType");
        assert_eq!(
            ops["UDM"],
            json!([
                "nudr-dr",
                READ,
                MODIFY,
                nextgcore_sbi::resource_scope::NUDR_DR_SUBSCRIPTION_DATA,
                nextgcore_sbi::resource_scope::NUDR_DR_REGISTRATIONS_WRITE
            ])
        );
        let allowed: Vec<&str> = dr["allowedNfTypes"]
            .as_array()
            .expect("allowedNfTypes")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(ops.len(), allowed.len(), "one entry per allowed NF type");
        for nf_type in allowed.iter().filter(|t| **t != "UDM") {
            assert_eq!(ops[*nf_type], json!(["nudr-dr"]), "{nf_type}");
        }
        assert!(
            service("nudr-group-id-map")
                .get("allowedOperationsPerNfType")
                .is_none(),
            "Nudr_GroupIDmap defines no resource scope (TS 29.504 §6.2.7)"
        );
    }

    /// #1934 review M1, checked on udrd: no spelling of the AuthenticationSubscription
    /// path gets K out of the real OAuth2 listener with a service-scope-only token.
    /// An empty segment (`//` in either place), a trailing `/` and a dot segment are
    /// refused 400 by the SBI server before the scope check and the router, so the
    /// two can never disagree on what the path names. The well-formed path is the
    /// scope check's 403, and the UDM still reads it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_path_spelling_reads_k_without_its_scope_1934() {
        use nextgcore_sbi::resource_scope::{
            NUDR_DR_AUTH_SUBSCRIPTION_MODIFY as MODIFY, NUDR_DR_AUTH_SUBSCRIPTION_READ as READ,
        };
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        let _store = DbiTestStore::enable().await;
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = udr_oauth2_listener(NextgcoreSbiServerConfig::new(udr_addr));
        cfg.oauth2_jwks = Some(stand_in::jwks_for(&sk, stand_in::TEST_NRF_KID));
        let udr = SbiServer::on_listener(cfg, udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let bearer = |scope: &str| {
            format!(
                "Bearer {}",
                stand_in::es256_access_token(&sk, stand_in::TEST_NRF_KID, "UDR", scope)
            )
        };
        let service_only = bearer("nudr-dr");
        let udm = bearer(&format!("nudr-dr {READ} {MODIFY}"));
        let supi = "imsi-001010000019340";
        let tail = "authentication-data/authentication-subscription";
        let path = format!("/nudr-dr/v2/subscription-data/{supi}/{tail}");
        let k = "465b5ce8b199b49faa5f0a2ee238a6bc";
        let send = |req: SbiRequest, auth: &str| {
            let req = req.with_header("authorization", auth.to_string());
            let client = &client;
            async move { client.send_request(req).await.expect("response") }
        };
        let put = SbiRequest::put(&path)
            .with_json_body(&json!({
                "authenticationMethod": "5G_AKA",
                "encPermanentKey": k,
                "encOpcKey": "e8ed289deba952e4283b54e88e6183ca",
                "authenticationManagementField": "8000",
                "sequenceNumber": {"sqnScheme": "NON_TIME_BASED", "sqn": "000000000020"}
            }))
            .expect("json");
        assert_eq!(send(put, &udm).await.status, 201);

        let mut answers = Vec::new();
        for spelling in [
            format!("/nudr-dr/v2//subscription-data/{supi}/{tail}"),
            format!("/nudr-dr/v2/subscription-data//{supi}/{tail}"),
            format!("{path}/"),
            format!("/nudr-dr/v2/subscription-data/{supi}/authentication-data/./authentication-subscription"),
        ] {
            let r = send(SbiRequest::get(&spelling), &service_only).await;
            answers.push((spelling, r));
        }
        let refused = send(SbiRequest::get(&path), &service_only).await;
        let served = send(SbiRequest::get(&path), &udm).await;
        udr.stop().await.expect("stop");

        for (spelling, r) in &answers {
            assert_eq!(r.status, 400, "{spelling}: {:?}", r.http.content);
            assert!(
                !r.http.content.as_deref().unwrap_or("").contains(k),
                "{spelling}"
            );
        }
        assert_eq!(refused.status, 403);
        assert_eq!(served.status, 200, "{:?}", served.http.content);
        assert!(served.http.content.as_deref().unwrap_or("").contains(k));
    }

    /// #1811: the REAL router behind the UDR's OAuth2 listener
    /// (`udr_oauth2_listener`, the one `main` builds). The AuthenticationSubscription
    /// resource holds K and OPc, so a token scoped for `nudr-dr` alone -- all a
    /// PCF or NEF is granted -- is refused 403 `insufficient_scope` naming the
    /// TS 29.505 resource scope, and nothing is read or written; the UDM's token,
    /// carrying the resource scope too, reads the key. Resources outside it still
    /// need only the service scope.
    ///
    /// REVERT-VERIFIED: with `.with_oauth2_resource_scopes(..)` removed from
    /// `udr_oauth2_listener`, the service-scope-only GET answers 200 with the key
    /// and this test fails on its first assertion.
    /// **#1964.** nrfd pins a resource-scoped token's `aud` to the UDR instances
    /// it evaluated the scope over. The real listener accepts a token whose
    /// `aud` is THIS UDR's instance ID, so the UDM's K read keeps working, and
    /// refuses one pinned to another UDR.
    ///
    /// REVERT-VERIFIED: with `.with_expected_audience_instance(..)` removed from
    /// `udr_oauth2_listener`, the own-instance token is refused and the first
    /// assertion fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_pinned_to_this_udr_is_accepted_1964() {
        use nextgcore_sbi::resource_scope::NUDR_DR_AUTH_SUBSCRIPTION_READ as READ;
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        let _store = DbiTestStore::enable().await;
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = udr_oauth2_listener(NextgcoreSbiServerConfig::new(udr_addr));
        cfg.oauth2_jwks = Some(stand_in::jwks_for(&sk, stand_in::TEST_NRF_KID));
        let udr = SbiServer::on_listener(cfg, udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let own = nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Udr);
        let path = "/nudr-dr/v2/subscription-data/imsi-001010000019640/authentication-data/\
                    authentication-subscription";
        let get = |aud: &str| {
            let token = stand_in::es256_access_token(
                &sk,
                stand_in::TEST_NRF_KID,
                aud,
                &format!("nudr-dr {READ}"),
            );
            let req = SbiRequest::get(path).with_header("authorization", format!("Bearer {token}"));
            let client = &client;
            async move { client.send_request(req).await.expect("response").status }
        };
        let mine = get(own).await;
        assert!(
            mine != 401 && mine != 403,
            "a token pinned to this UDR passes the gate (got {mine})"
        );
        let elsewhere = get("19640000-0000-4000-8000-0000000000ff").await;
        assert!(
            elsewhere == 401 || elsewhere == 403,
            "a token pinned to another UDR is refused (got {elsewhere})"
        );
        udr.stop().await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_auth_subscription_is_served_only_with_its_resource_scope_1811() {
        use nextgcore_sbi::resource_scope::{
            NUDR_DR_AUTH_SUBSCRIPTION_MODIFY as MODIFY, NUDR_DR_AUTH_SUBSCRIPTION_READ as READ,
        };
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        let _store = DbiTestStore::enable().await;
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = udr_oauth2_listener(NextgcoreSbiServerConfig::new(udr_addr));
        cfg.oauth2_jwks = Some(stand_in::jwks_for(&sk, stand_in::TEST_NRF_KID));
        let udr = SbiServer::on_listener(cfg, udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let bearer = |scope: &str| {
            format!(
                "Bearer {}",
                stand_in::es256_access_token(&sk, stand_in::TEST_NRF_KID, "UDR", scope)
            )
        };
        let service_only = bearer("nudr-dr");
        let udm = bearer(&format!("nudr-dr {READ} {MODIFY}"));
        let read_only = bearer(&format!("nudr-dr {READ}"));
        let supi = "imsi-001010000018110";
        let path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
        );
        let k = "465b5ce8b199b49faa5f0a2ee238a6bc";
        let send = |req: SbiRequest, auth: &str| {
            let req = req.with_header("authorization", auth.to_string());
            let client = &client;
            async move { client.send_request(req).await.expect("response") }
        };
        let put = |key: &str| {
            SbiRequest::put(&path)
                .with_json_body(&json!({
                    "authenticationMethod": "5G_AKA",
                    "encPermanentKey": key,
                    "encOpcKey": "e8ed289deba952e4283b54e88e6183ca",
                    "authenticationManagementField": "8000",
                    "sequenceNumber": {"sqnScheme": "NON_TIME_BASED", "sqn": "000000000020"}
                }))
                .expect("json")
        };

        let provisioned = send(put(k), &udm).await;
        let refused_get = send(SbiRequest::get(&path), &service_only).await;
        let refused_put = send(put("00000000000000000000000000000000"), &service_only).await;
        let patch = SbiRequest::patch(&path)
            .with_json_body(
                &json!([{"op": "replace", "path": "/sequenceNumber/sqn", "value": "000000000040"}]),
            )
            .expect("json");
        let refused_patch = send(patch, &read_only).await;
        let sqn_after_refusals = nextgcore_dbi::test_store::stored_sqn(supi);
        let served = send(SbiRequest::get(&path), &udm).await;
        let other = send(
            SbiRequest::get(format!(
                "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
            )),
            &service_only,
        )
        .await;
        udr.stop().await.expect("stop");

        let body = |r: &SbiResponse| -> serde_json::Value {
            serde_json::from_str(r.http.content.as_deref().unwrap_or("{}")).unwrap_or_default()
        };
        let challenge = |r: &SbiResponse| {
            r.http
                .get_header("www-authenticate")
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(
            refused_get.status, 403,
            "a service-scope-only token must not read K: {:?}",
            refused_get.http.content
        );
        assert_eq!(
            challenge(&refused_get),
            format!("Bearer realm=\"5gc-sbi\", error=\"insufficient_scope\", scope=\"{READ}\"")
        );
        assert_eq!(
            body(&refused_get)["status"],
            403,
            "TS 29.500 ProblemDetails"
        );
        assert!(
            !refused_get
                .http
                .content
                .as_deref()
                .unwrap_or("")
                .contains(k),
            "a refusal carries no key material"
        );
        assert_eq!(provisioned.status, 201, "{:?}", provisioned.http.content);
        assert_eq!(refused_put.status, 403);
        assert!(challenge(&refused_put).contains(&format!("scope=\"{MODIFY}\"")));
        assert_eq!(refused_patch.status, 403, "a read scope does not modify");
        assert!(challenge(&refused_patch).contains(&format!("scope=\"{MODIFY}\"")));
        assert_eq!(
            sqn_after_refusals,
            Some(0x20),
            "neither refused write reached the store"
        );
        assert_eq!(served.status, 200, "{:?}", served.http.content);
        assert_eq!(
            body(&served)["encPermanentKey"]
                .as_str()
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some(k),
            "the UDM's token reads the key the provisioning PUT stored"
        );
        assert_ne!(
            other.status, 403,
            "authentication-status needs only the service scope: {:?}",
            other.http.content
        );
    }

    #[test]
    fn test_nrf_profile_advertises_nudr_dr_at_v2() {
        // TS 29.504 §6.1.1: "The <apiVersion> shall be v2" for
        // Nudr_DataRepository, and the OpenAPI server URL is
        // `{apiRoot}/nudr-dr/v2`.
        //
        // Regression: this profile advertised v1 while the PCF already called
        // /nudr-dr/v2/policy-data/... The disagreement was invisible because
        // the UDR's live router discards the version segment
        // (`let _version = parts[1]`), so both spellings routed. Against a
        // strict peer, or once the version is ever enforced, one side breaks.
        let profile = build_udr_nf_profile(
            "udr-test-instance",
            "10.45.0.11",
            7777,
            nextgcore_sbi::types::UriScheme::Http,
        );

        let service = profile["nfServices"]
            .as_array()
            .expect("nfServices must be an array")
            .iter()
            .find(|s| s["serviceName"] == "nudr-dr")
            .expect("nudr-dr must be registered");

        assert_eq!(
            service["versions"][0]["apiVersionInUri"], "v2",
            "Nudr_DataRepository must be advertised at v2 per TS 29.504 6.1.1"
        );
        // apiFullVersion must track the URI version rather than lag it.
        assert_eq!(service["versions"][0]["apiFullVersion"], "2.0.0");
    }

    /// #392: the registered NFProfile advertises `nudr-group-id-map` as well as
    /// `nudr-dr`, each at its own normative version.
    ///
    /// Positive on both names. Nudr_GroupIDmap has been routed by
    /// `handle_group_id_map` since #87, but was absent from the registered
    /// profile — and the NRF filters discovery strictly on
    /// `nfServices[].serviceName`, so a UDM or AUSF resolving a subscriber's
    /// NF-group could not find this UDR by service name.
    ///
    /// The versions differ and both are pinned: TS 29.504 §6.1.1 puts
    /// Nudr_DataRepository at v2, while `TS29504_Nudr_GroupIDmap.yaml` fixes
    /// Nudr_GroupIDmap at `{apiRoot}/nudr-group-id-map/v1`. Advertising one
    /// version for both would break whichever side is enforced.
    #[test]
    fn the_udr_profile_advertises_both_routed_nudr_services() {
        let profile = build_udr_nf_profile(
            "udr-test-instance",
            "10.45.0.11",
            7777,
            nextgcore_sbi::types::UriScheme::Http,
        );
        let services = profile["nfServices"].as_array().expect("nfServices");
        let names: Vec<&str> = services
            .iter()
            .map(|s| s["serviceName"].as_str().expect("serviceName"))
            .collect();

        assert!(names.contains(&"nudr-dr"), "advertised: {names:?}");
        assert!(
            names.contains(&"nudr-group-id-map"),
            "the UDR routes /nudr-group-id-map/v1/nf-group-ids but does not advertise the \
             service, so the NRF drops this UDR from a SearchResult filtered on it. \
             Advertised: {names:?}"
        );

        let group_map = services
            .iter()
            .find(|s| s["serviceName"] == "nudr-group-id-map")
            .expect("nudr-group-id-map must be registered");
        assert_eq!(
            group_map["versions"][0]["apiVersionInUri"], "v1",
            "Nudr_GroupIDmap is v1 (TS29504_Nudr_GroupIDmap.yaml server url), unlike nudr-dr"
        );
        assert_eq!(group_map["versions"][0]["apiFullVersion"], "1.0.0");

        for svc in services {
            let name = svc["serviceName"].as_str().unwrap_or_default();
            let eps = svc["ipEndPoints"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} carries no ipEndPoints"));
            assert_eq!(eps[0]["port"].as_u64(), Some(7777), "{name} port");
            assert!(
                svc["allowedNfTypes"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
                "{name} must state its allowedNfTypes (TS 29.510 §6.1.6.2.3)"
            );
        }
    }

    #[test]
    fn test_udr_yaml_oauth2_knob() {
        let yaml = r#"
udr:
  sbi:
    server:
      - address: 127.0.0.1
        port: 7777
    oauth2:
      require: true
    client:
      nrf:
        - uri: http://nrf:7777
"#;
        let parsed: UdrYaml = serde_yaml::from_str(yaml).unwrap();
        let sbi = parsed.udr.unwrap().sbi.unwrap();
        assert_eq!(sbi.oauth2.unwrap().require, Some(true));
        assert_eq!(sbi.client.unwrap().nrf.unwrap()[0].uri, "http://nrf:7777");
    }

    #[test]
    fn test_udr_yaml_oauth2_defaults_off() {
        let yaml = r#"
udr:
  sbi:
    client:
      nrf:
        - uri: http://nrf:7777
"#;
        let parsed: UdrYaml = serde_yaml::from_str(yaml).unwrap();
        let sbi = parsed.udr.unwrap().sbi.unwrap();
        assert!(sbi.oauth2.is_none());
    }

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-udrd"]);
        assert_eq!(args.sbi_addr, None);
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-udrd"]);
        assert_eq!(args.config, "/etc/nextgcore/udr.yaml");
        assert_eq!(args.log_level, None);
        assert_eq!(args.sbi_addr, None);
        assert_eq!(args.sbi_port, None);
        assert!(!args.tls);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-udrd",
            "-c",
            "/custom/udr.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
        ]);
        assert_eq!(args.config, "/custom/udr.yaml");
        assert_eq!(args.log_level.as_deref(), Some("debug"));
        assert_eq!(args.sbi_addr.as_deref(), Some("0.0.0.0"));
        assert_eq!(args.sbi_port, Some(8080));
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-udrd",
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
    fn test_mask_uri() {
        assert_eq!(
            mask_uri("mongodb://user:pass@host/db"),
            "mongodb://***@host/db"
        );
        assert_eq!(mask_uri("mongodb://host/db"), "mongodb://host/db");
    }

    #[test]
    fn test_is_valid_plmn_id() {
        assert!(is_valid_plmn_id("00101"));
        assert!(is_valid_plmn_id("310410"));
        assert!(!is_valid_plmn_id("0010"));
        assert!(!is_valid_plmn_id("0010100"));
        assert!(!is_valid_plmn_id("00a01"));
    }

    #[test]
    fn test_auth_subscription_sequence_number_shape() {
        // TS 29.505 AuthenticationSubscription / SequenceNumber round-trip:
        // sqnScheme + indLength + 12-hex-digit sqn must be present.
        // udrd-08: the low 5 IND bits must be zeroed — 0x1F21 → 0x1F20.
        let mut info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo::default();
        info.sqn = 0x1F21;
        info.use_opc = true;
        let doc = build_auth_subscription_json("imsi-001010000000001", &info);
        assert_eq!(doc["authenticationMethod"], "5G_AKA");
        let seq = &doc["sequenceNumber"];
        assert_eq!(seq["sqnScheme"], "NON_TIME_BASED");
        assert_eq!(seq["indLength"], 5);
        let sqn = seq["sqn"].as_str().unwrap();
        assert_eq!(sqn.len(), 12);
        assert!(sqn.bytes().all(|b| b.is_ascii_hexdigit()));
        // IND bits [4:0] of 0x1F21 = 0x01 → zeroed → 0x1F20
        assert_eq!(sqn, "000000001f20");
        // Confirm low 5 bits are zero
        let sqn_val = u64::from_str_radix(sqn, 16).unwrap();
        assert_eq!(sqn_val & 0x1F, 0, "IND bits must be zeroed");
        assert_eq!(doc["supi"], "imsi-001010000000001");
    }

    #[test]
    fn test_pct_decode() {
        assert_eq!(pct_decode("a%2Cb"), "a,b");
        assert_eq!(pct_decode("plain"), "plain");
        assert_eq!(pct_decode("%5B%7B%22sst%22%3A1%7D%5D"), "[{\"sst\":1}]");
    }

    // ------------------------------------------------------------------
    // HTTP-level tests over a real HTTP/2 SBI server on ephemeral ports.
    // ------------------------------------------------------------------

    use nextgcore_sbi::client::SbiClient;
    use serde_json::json;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// The lock of the global nextgcore-dbi test store, declared beside it
    /// (`nextgcore_dbi::test_store::TEST_STORE_LOCK`, #1686): the WSB-6 tests
    /// enable the store, and `test_http_auth_provisioning_and_plmn_validation`
    /// (the fail-closed no-DB 503) and `test_varueid_routing` (the no-DB 404)
    /// assert it is off, so none may overlap.
    use nextgcore_dbi::test_store::TEST_STORE_LOCK as DBI_BACKEND_LOCK;

    /// RAII guard (WSB-6): holds `DBI_BACKEND_LOCK` with the nextgcore-dbi
    /// in-memory test store enabled, and disables the store again on drop —
    /// including on panic/unwind, so a failing test cannot leak the store
    /// into the fail-closed 503 test.
    struct DbiTestStore {
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }

    impl DbiTestStore {
        async fn enable() -> Self {
            let lock = DBI_BACKEND_LOCK.lock().await;
            nextgcore_dbi::test_store::enable();
            Self { _lock: lock }
        }
    }

    impl Drop for DbiTestStore {
        fn drop(&mut self) {
            nextgcore_dbi::test_store::disable();
        }
    }

    /// Start the UDR SBI server plus a local notification listener that
    /// forwards (path, body) of every received POST into a channel.
    async fn start_udr_and_listener() -> (
        SbiServer,
        SbiClient,
        SbiServer,
        u16,
        mpsc::UnboundedReceiver<(String, String)>,
    ) {
        // #2079: these loopback peers prove no identity, so the UDM-context write
        // gate admits them under `dev` only. Set, never reset (CONVENTIONS).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr_server =
            SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr_server
            .start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");

        let (listener_listener, listener_addr) =
            nextgcore_sbi::test_support::bound_listener().into_parts();
        let (tx, rx) = mpsc::unbounded_channel::<(String, String)>();
        let listener = SbiServer::on_listener(
            NextgcoreSbiServerConfig::new(listener_addr),
            listener_listener,
        );
        listener
            .start(move |req: SbiRequest| {
                let tx = tx.clone();
                async move {
                    let body = req.http.content.clone().unwrap_or_default();
                    let _ = tx.send((req.header.uri.clone(), body));
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("listener starts");

        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        (udr_server, client, listener, listener_addr.port(), rx)
    }

    async fn recv_notification(
        rx: &mut mpsc::UnboundedReceiver<(String, String)>,
    ) -> (String, serde_json::Value) {
        let (path, body) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("notification within 5s")
            .expect("channel open");
        let value: serde_json::Value = serde_json::from_str(&body).expect("notification JSON");
        (path, value)
    }

    /// #1334: the UDR's `/metrics`, scraped over HTTP, follows Nudr traffic over the
    /// real SBI server: a data change subscription created and one rejected, each
    /// counted by data set, operation and result.
    ///
    /// REVERT-VERIFIED: without `nextgcore_udrd::metrics::observe` in
    /// `udr_sbi_request_handler` the counts stay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_scraped_endpoint_follows_nudr_traffic_1334() {
        let (udr, client, listener, cb_port, _rx) = start_udr_and_listener().await;
        let (bound, handle) = nextgcore_metrics::nes_energy::serve_metrics(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(nextgcore_udrd::metrics::render_prometheus),
        )
        .await
        .expect("metrics endpoint");
        let value = |b: &str, s: &str| nextgcore_metrics::nf::sample_value(b, s).unwrap_or(0.0);
        let ok = r#"udr_operations_total{data="data_change_subscription",operation="create",result="success"}"#;
        let failed = r#"udr_operations_total{data="data_change_subscription",operation="create",result="failure"}"#;
        let before = nextgcore_metrics::nf::scrape_for_test(bound).await;
        let (ok0, failed0) = (value(&before, ok), value(&before, failed));

        let supi = "imsi-001019913340002";
        let resp = client
            .post_json(
                "/nudr-dr/v2/subscription-data/subs-to-notify",
                &json!({
                    "ueId": supi,
                    "callbackReference": format!("http://127.0.0.1:{cb_port}/cb/1334"),
                    "monitoredResourceUris": [format!("http://udr/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access")]
                }),
            )
            .await
            .expect("POST");
        assert_eq!(resp.status, 201);
        let resp = client
            .post_json(
                "/nudr-dr/v2/subscription-data/subs-to-notify",
                &json!({"monitoredResourceUris": ["/x"]}),
            )
            .await
            .expect("POST bad");
        assert_eq!(resp.status, 400);

        // #1334 review: an operation label is admitted on a 2xx, so a made-up resource
        // of every service this NF serves must be answered with an error, or a client
        // could mint label values.
        for service in ["nudr-dr", "nudr-group-id-map"] {
            for path in [
                format!("/{service}/v1/madeup-resource-1334"),
                format!("/{service}/v1/imsi-001010000000001/madeup-resource-1334"),
            ] {
                for request in [
                    nextgcore_sbi::message::SbiRequest::get(&path),
                    nextgcore_sbi::message::SbiRequest::post(&path)
                        .with_body("{}", "application/json"),
                ] {
                    let resp = client.send_request(request).await.expect("answered");
                    assert!(resp.status >= 400, "{path} answered {}", resp.status);
                }
            }
        }
        let after = nextgcore_metrics::nf::scrape_for_test(bound).await;
        assert!(
            !after.contains("madeup"),
            "no made-up resource in a label: {after}"
        );
        assert!(value(&after, ok) >= ok0 + 1.0, "{after}");
        assert!(value(&after, failed) >= failed0 + 1.0, "{after}");
        for name in [
            "udr_ue_contexts",
            "nextgcore_sbi_request_total",
            "nextgcore_nrf_registered",
            "nextgcore_uptime_seconds",
            "process_resident_memory_bytes",
        ] {
            assert!(
                nextgcore_metrics::nf::has_series(&after, name),
                "{name}:\n{after}"
            );
        }
        assert!(!after.contains("9913340002"), "no SUPI in the exposition");
        handle.abort();
        client.close().await;
        udr.stop().await.expect("stop");
        listener.stop().await.expect("stop");
    }

    /// amf-3gpp-access: strict-peer rejection, full registration round-trip,
    /// PATCH, DELETE, and DataChangeNotify delivery to a subs-to-notify
    /// subscriber over a real local listener.
    /// #1814: a subscription receives only the UEs its `monitoredResourceUris`
    /// name. UE A's subscription and a ueId-less one monitoring the bare suffix
    /// `/pp-data` are both created, then UE B's pp-data and UE A's pp-data change.
    /// UE A's subscription gets exactly UE A's change, and nothing reaches either
    /// callback for UE B.
    ///
    /// REVERT-VERIFIED: with `uri_covers`'s raw suffix match restored, the
    /// `/pp-data` subscription is notified of UE B's change. That notification
    /// arrives first, at `/cb/suffix`, so the first assertion (`path == "/cb/a"`)
    /// fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_subscription_gets_only_the_ues_it_monitors_1814() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;
        let ue_a = "imsi-001010000018141";
        let ue_b = "imsi-001010000018142";
        let pp = |ue: &str| format!("/nudr-dr/v2/subscription-data/{ue}/pp-data");
        for (cb, monitored) in [("a", pp(ue_a)), ("suffix", "/pp-data".to_string())] {
            let resp = client
                .post_json(
                    "/nudr-dr/v2/subscription-data/subs-to-notify",
                    &json!({
                        "callbackReference": format!("http://127.0.0.1:{cb_port}/cb/{cb}"),
                        "monitoredResourceUris": [monitored]
                    }),
                )
                .await
                .expect("POST sub");
            assert_eq!(resp.status, 201, "{cb}");
        }

        let doc = json!({"communicationCharacteristics": {"ppSubsRegTimer": {"subsRegTimer": 60}}});
        for ue in [ue_b, ue_a] {
            let resp = client.put_json(&pp(ue), &doc).await.expect("PUT pp-data");
            assert!(
                resp.status == 201 || resp.status == 204,
                "{ue}: {}",
                resp.status
            );
        }

        let (path, notify) = recv_notification(&mut rx).await;
        let mut others = Vec::new();
        while let Ok(Some(n)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            others.push(n);
        }
        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");

        assert_eq!(
            path, "/cb/a",
            "UE A's subscription is told of UE A's change"
        );
        assert_eq!(notify["ueId"], ue_a);
        assert_eq!(notify["notifyItems"][0]["resourceId"], pp(ue_a));
        assert!(
            others.is_empty(),
            "no other notification, UE B's change included: {others:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_amf3gpp_lifecycle_and_notify() {
        // #1666: the notification client follows the SBI profile, and this
        // drives it at a loopback plaintext peer, i.e. a dev deployment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900000001";
        let resource = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access");

        // Subscribe to changes for this UE.
        let cb_uri = format!("http://127.0.0.1:{cb_port}/cb/data-change");
        let sub_body = json!({
            "ueId": supi,
            "callbackReference": cb_uri,
            "monitoredResourceUris": [format!("http://udr{resource}")]
        });
        let resp = client
            .post_json("/nudr-dr/v2/subscription-data/subs-to-notify", &sub_body)
            .await
            .expect("POST sub");
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("Location").expect("Location").clone();
        assert!(loc.contains("/subscription-data/subs-to-notify/"));

        // Missing mandatory callbackReference -> 400 ProblemDetails
        let resp = client
            .post_json(
                "/nudr-dr/v2/subscription-data/subs-to-notify",
                &json!({"monitoredResourceUris": ["/x"]}),
            )
            .await
            .expect("POST bad sub");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");

        // Strict-peer: PUT registration missing mandatory guami -> 400
        let resp = client
            .put_json(
                &resource,
                &json!({
                    "amfInstanceId": "9f7d5a3e-0000-4000-8000-000000000001",
                    "deregCallbackUri": "http://amf/dereg",
                    "ratType": "NR"
                }),
            )
            .await
            .expect("PUT invalid");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");
        assert!(problem["detail"].as_str().unwrap().contains("guami"));

        // Full registration -> 201 + Location + lossless echo
        let registration = json!({
            "amfInstanceId": "9f7d5a3e-0000-4000-8000-000000000001",
            "deregCallbackUri": "http://amf.example.com/namf-callback/v1/dereg",
            "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "020040"},
            "ratType": "NR",
            "initialRegistrationInd": true,
            "pei": "imeisv-3512340000000101"
        });
        let resp = client
            .put_json(&resource, &registration)
            .await
            .expect("PUT registration");
        assert_eq!(resp.status, 201);
        assert!(resp
            .http
            .get_header("Location")
            .expect("Location on 201")
            .ends_with("amf-3gpp-access"));

        // Notification for the PUT must be delivered to the listener.
        let (path, notify) = recv_notification(&mut rx).await;
        assert_eq!(path, "/cb/data-change");
        assert_eq!(notify["ueId"], supi);
        assert!(notify["notifyItems"][0]["resourceId"]
            .as_str()
            .unwrap()
            .ends_with("amf-3gpp-access"));
        assert_eq!(
            notify["notifyItems"][0]["changes"][0]["newValue"]["ratType"],
            "NR"
        );

        // GET returns the full stored registration (not a stub).
        let resp = client.get(&resource).await.expect("GET registration");
        assert_eq!(resp.status, 200);
        let stored: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored, registration, "PUT -> GET must be lossless");

        // Replace -> 204, PATCH purgeFlag -> 204 and visible on GET.
        let resp = client
            .put_json(&resource, &registration)
            .await
            .expect("PUT replace");
        assert_eq!(resp.status, 204);
        let _ = recv_notification(&mut rx).await; // replace notification

        let mut req = SbiRequest::patch(&resource);
        req.http.set_content(
            json!([{"op": "replace", "path": "/purgeFlag", "value": true}]).to_string(),
        );
        req.http
            .set_header("Content-Type", "application/json-patch+json");
        let resp = client.send_request(req).await.expect("PATCH");
        assert_eq!(resp.status, 204);
        let _ = recv_notification(&mut rx).await; // patch notification
        let resp = client.get(&resource).await.expect("GET after PATCH");
        let stored: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored["purgeFlag"], true);

        // DELETE -> 204, then GET -> 404 ProblemDetails.
        let resp = client.delete(&resource).await.expect("DELETE");
        assert_eq!(resp.status, 204);
        let (_, notify) = recv_notification(&mut rx).await;
        assert_eq!(notify["notifyItems"][0]["changes"][0]["op"], "REMOVE");
        let resp = client.get(&resource).await.expect("GET after DELETE");
        assert_eq!(resp.status, 404);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["status"], 404);

        // Unsubscribe by ue-id.
        let mut req = SbiRequest::delete("/nudr-dr/v2/subscription-data/subs-to-notify");
        req.http.set_param("ue-id", supi);
        let resp = client.send_request(req).await.expect("DELETE subs");
        assert_eq!(resp.status, 204);

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    /// Regression (C5 / remote DoS): GET smf-registrations for a SUPI that
    /// the UDR has never seen must return 200 with an empty array, NOT panic
    /// (the handler previously `.expect()`-ed on a missing UE, crashing the
    /// NF on a crafted GET). Also covers the per-PDU GET (404) and the PUT ->
    /// GET-list round-trip so the success path stays intact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_smf_registrations_unknown_ue_no_panic() {
        let (udr, client, listener, _cb_port, _rx) = start_udr_and_listener().await;

        // Unknown UE, collection GET -> 200 + empty JSON array (no panic).
        let unknown = "imsi-001019999999999";
        let coll =
            format!("/nudr-dr/v2/subscription-data/{unknown}/context-data/smf-registrations");
        let resp = client.get(&coll).await.expect("GET unknown smf-regs");
        assert_eq!(resp.status, 200, "unknown UE collection GET must be 200");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body,
            json!([]),
            "unknown UE must yield an empty array, not a panic"
        );

        // Unknown UE, per-PDU GET -> 404 ProblemDetails (also no panic).
        let single = format!("{coll}/5");
        let resp = client.get(&single).await.expect("GET unknown smf-reg/5");
        assert_eq!(resp.status, 404);

        // Success path: PUT a full SmfRegistration then GET the actual stored
        // values back (not a hardcoded summary). A new registration is 201.
        let supi = "imsi-001019900000077";
        let coll = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations");
        let single = format!("{coll}/5");
        let reg = json!({
            "smfInstanceId": "11111111-2222-3333-4444-555555555555",
            "pduSessionId": 5,
            "singleNssai": {"sst": 2, "sd": "000001"},
            "dnn": "ims",
            "plmnId": {"mcc": "001", "mnc": "01"}
        });
        let resp = client.put_json(&single, &reg).await.expect("PUT smf-reg");
        assert_eq!(resp.status, 201, "new SmfRegistration must be 201 Created");

        // Per-PDU GET returns the ACTUAL registered document.
        let resp = client.get(&single).await.expect("GET smf-reg/5");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got["smfInstanceId"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(got["singleNssai"], json!({"sst": 2, "sd": "000001"}));
        assert_eq!(got["dnn"], "ims");
        assert_eq!(got["plmnId"], json!({"mcc": "001", "mnc": "01"}));
        assert_eq!(got["pduSessionId"], 5);

        let resp = client.get(&coll).await.expect("GET smf-regs list");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let arr = body.as_array().expect("array");
        assert_eq!(arr.len(), 1, "one registration after PUT");
        assert_eq!(arr[0]["pduSessionId"], 5);
        assert_eq!(arr[0]["dnn"], "ims");
        assert_eq!(
            arr[0]["smfInstanceId"],
            "11111111-2222-3333-4444-555555555555"
        );

        // Replacing the same registration is 204 (not created).
        let resp = client
            .put_json(&single, &reg)
            .await
            .expect("re-PUT smf-reg");
        assert_eq!(resp.status, 204, "replace must be 204");

        // Missing mandatory IEs -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .put_json(&single, &json!({"dnn": "ims"}))
            .await
            .expect("PUT incomplete smf-reg");
        assert_eq!(resp.status, 400, "missing mandatory IEs must be 400");

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    /// exposure-data: subscription validation, AM/SM lifecycle with RFC 7396
    /// merge-patch, and ExposureDataChangeNotification delivery.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_exposure_data_lifecycle_and_notify() {
        // #1666: the notification client follows the SBI profile, and this
        // drives it at a loopback plaintext peer, i.e. a dev deployment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;
        let ue = "imsi-001019900000002";
        let am_path = format!("/nudr-dr/v2/exposure-data/{ue}/access-and-mobility-data");
        let sm_path = format!("/nudr-dr/v2/exposure-data/{ue}/session-management-data/5");

        // Strict-peer: subscription without notificationUri -> 400.
        let resp = client
            .post_json(
                "/nudr-dr/v2/exposure-data/subs-to-notify",
                &json!({"monitoredResourceUris": [am_path]}),
            )
            .await
            .expect("POST bad sub");
        assert_eq!(resp.status, 400);

        // Valid subscription -> 201 + Location.
        let resp = client
            .post_json(
                "/nudr-dr/v2/exposure-data/subs-to-notify",
                &json!({
                    "notificationUri": format!("http://127.0.0.1:{cb_port}/cb/exposure"),
                    "monitoredResourceUris": [format!("/nudr-dr/v2/exposure-data/{ue}")]
                }),
            )
            .await
            .expect("POST sub");
        assert_eq!(resp.status, 201);
        let sub_loc = resp.http.get_header("Location").expect("Location").clone();
        let sub_id = sub_loc.rsplit('/').next().unwrap().to_string();

        // PUT AM data -> 201; notification array with ueId + data.
        let am_data = json!({"roamingStatus": false, "timeZone": "+02:00"});
        let resp = client.put_json(&am_path, &am_data).await.expect("PUT am");
        assert_eq!(resp.status, 201);
        let (path, notify) = recv_notification(&mut rx).await;
        assert_eq!(path, "/cb/exposure");
        assert!(notify.is_array());
        assert_eq!(notify[0]["ueId"], ue);
        assert_eq!(notify[0]["accessAndMobilityData"]["roamingStatus"], false);

        // GET -> 200 lossless.
        let resp = client.get(&am_path).await.expect("GET am");
        assert_eq!(resp.status, 200);
        let stored: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored, am_data);

        // PATCH (merge-patch) -> 204 and merged result on GET.
        let mut req = SbiRequest::patch(&am_path);
        req.http
            .set_content(json!({"roamingStatus": true, "timeZone": null}).to_string());
        req.http
            .set_header("Content-Type", "application/merge-patch+json");
        let resp = client.send_request(req).await.expect("PATCH am");
        assert_eq!(resp.status, 204);
        let _ = recv_notification(&mut rx).await;
        let resp = client.get(&am_path).await.expect("GET merged");
        let stored: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored, json!({"roamingStatus": true}));

        // SM data lifecycle: PUT -> 201, GET, DELETE -> 204 with delResources.
        let sm_data = json!({"pduSessionStatus": "ACTIVE", "dnn": "internet",
                             "ipv4Addr": "10.45.0.2", "pduSessionId": 5});
        let resp = client.put_json(&sm_path, &sm_data).await.expect("PUT sm");
        assert_eq!(resp.status, 201);
        let (_, notify) = recv_notification(&mut rx).await;
        assert_eq!(notify[0]["pduSessionManagementData"][0]["dnn"], "internet");
        let resp = client.get(&sm_path).await.expect("GET sm");
        assert_eq!(resp.status, 200);
        let resp = client.delete(&sm_path).await.expect("DELETE sm");
        assert_eq!(resp.status, 204);
        let (_, notify) = recv_notification(&mut rx).await;
        assert!(notify[0]["delResources"][0]
            .as_str()
            .unwrap()
            .ends_with("session-management-data/5"));

        // DELETE AM -> 204; GET -> 404.
        let resp = client.delete(&am_path).await.expect("DELETE am");
        assert_eq!(resp.status, 204);
        let _ = recv_notification(&mut rx).await;
        let resp = client.get(&am_path).await.expect("GET deleted");
        assert_eq!(resp.status, 404);

        // Remove the subscription -> 204; second delete -> 404.
        let resp = client
            .delete(&format!(
                "/nudr-dr/v2/exposure-data/subs-to-notify/{sub_id}"
            ))
            .await
            .expect("DELETE sub");
        assert_eq!(resp.status, 204);
        let resp = client
            .delete(&format!(
                "/nudr-dr/v2/exposure-data/subs-to-notify/{sub_id}"
            ))
            .await
            .expect("DELETE sub again");
        assert_eq!(resp.status, 404);

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    /// #1939 item 1: an identifier carrying a percent-encoded `/` (TS 29.519
    /// `{appId}` is a free-form string) passes the SBI server's path check and
    /// reaches the router as ONE segment: the PFD document is created under it,
    /// read back under it, and the bare prefix is a different (absent) one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_encoded_slash_in_an_app_id_is_one_segment_1939() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, listener, _cb_port, _rx) = start_udr_and_listener().await;
        let pfd = json!({
            "applicationId": "vendor/app",
            "pfds": [{"pfdId": "pfd-1", "flowDescriptions": ["permit out ip from any to any"]}]
        });
        let created = client
            .put_json("/nudr-dr/v2/application-data/pfds/vendor%2Fapp", &pfd)
            .await
            .expect("PUT");
        let read = client
            .get("/nudr-dr/v2/application-data/pfds/vendor%2Fapp")
            .await
            .expect("GET");
        let prefix = client
            .get("/nudr-dr/v2/application-data/pfds/vendor")
            .await
            .expect("GET prefix");
        udr.stop().await.expect("stop");
        listener.stop().await.expect("stop");
        assert_eq!(created.status, 201, "{:?}", created.http.content);
        assert_eq!(read.status, 200, "{:?}", read.http.content);
        assert!(read
            .http
            .content
            .as_deref()
            .unwrap_or("")
            .contains("vendor/app"));
        assert_eq!(prefix.status, 404);
    }

    /// application-data: pfds + influenceData lifecycle, query filters, and
    /// TrafficInfluDataNotif delivery.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_application_data_lifecycle_and_notify() {
        // #1666: the notification client follows the SBI profile, and this
        // drives it at a loopback plaintext peer, i.e. a dev deployment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;

        // Strict-peer: PFD data without pfds -> 400.
        let resp = client
            .put_json(
                "/nudr-dr/v2/application-data/pfds/app-w42",
                &json!({"applicationId": "app-w42"}),
            )
            .await
            .expect("PUT bad pfd");
        assert_eq!(resp.status, 400);

        // Valid PFD -> 201 + Location; list contains it.
        let pfd = json!({
            "applicationId": "app-w42",
            "pfds": [{"pfdId": "pfd-1", "flowDescriptions": ["permit out ip from any to any"]}]
        });
        let resp = client
            .put_json("/nudr-dr/v2/application-data/pfds/app-w42", &pfd)
            .await
            .expect("PUT pfd");
        assert_eq!(resp.status, 201);
        let resp = client
            .get("/nudr-dr/v2/application-data/pfds")
            .await
            .expect("GET pfds");
        assert_eq!(resp.status, 200);
        let list: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(list
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["applicationId"] == "app-w42"));

        // Influence subscription (supis filter) -> 201.
        let resp = client
            .post_json(
                "/nudr-dr/v2/application-data/influenceData/subs-to-notify",
                &json!({
                    "notificationUri": format!("http://127.0.0.1:{cb_port}/cb/influence"),
                    "supis": ["imsi-001019900000003"]
                }),
            )
            .await
            .expect("POST influence sub");
        assert_eq!(resp.status, 201);

        // Strict-peer: subscription without any oneOf filter -> 400.
        let resp = client
            .post_json(
                "/nudr-dr/v2/application-data/influenceData/subs-to-notify",
                &json!({"notificationUri": "http://x/cb"}),
            )
            .await
            .expect("POST bad influence sub");
        assert_eq!(resp.status, 400);

        // Strict-peer: influence data without afAppId -> 400.
        let resp = client
            .put_json(
                "/nudr-dr/v2/application-data/influenceData/inf-w42",
                &json!({"dnn": "internet"}),
            )
            .await
            .expect("PUT bad influence");
        assert_eq!(resp.status, 400);

        // Valid influence data matching the subscription -> 201 + notify.
        let influ = json!({
            "afAppId": "app-w42",
            "dnn": "internet",
            "supi": "imsi-001019900000003",
            "trafficRoutes": [{"dnai": "edge-1"}]
        });
        let resp = client
            .put_json("/nudr-dr/v2/application-data/influenceData/inf-w42", &influ)
            .await
            .expect("PUT influence");
        assert_eq!(resp.status, 201);
        let (path, notify) = recv_notification(&mut rx).await;
        assert_eq!(path, "/cb/influence");
        assert!(notify.is_array());
        assert!(notify[0]["resUri"].as_str().unwrap().ends_with("inf-w42"));
        assert_eq!(notify[0]["trafficInfluData"]["afAppId"], "app-w42");

        // Collection read with filters.
        let mut req = SbiRequest::get("/nudr-dr/v2/application-data/influenceData");
        req.http.set_param("supis", "imsi-001019900000003");
        let resp = client.send_request(req).await.expect("GET influence");
        assert_eq!(resp.status, 200);
        let list: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        let mut req = SbiRequest::get("/nudr-dr/v2/application-data/influenceData");
        req.http.set_param("dnns", "no-such-dnn");
        let resp = client.send_request(req).await.expect("GET influence empty");
        let list: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(list.as_array().unwrap().is_empty());

        // DELETE influence -> 204 + deletion notification (resUri only).
        let resp = client
            .delete("/nudr-dr/v2/application-data/influenceData/inf-w42")
            .await
            .expect("DELETE influence");
        assert_eq!(resp.status, 204);
        let (_, notify) = recv_notification(&mut rx).await;
        assert!(notify[0]["resUri"].as_str().unwrap().ends_with("inf-w42"));
        assert!(notify[0].get("trafficInfluData").is_none());

        // DELETE pfd -> 204; GET -> 404.
        let resp = client
            .delete("/nudr-dr/v2/application-data/pfds/app-w42")
            .await
            .expect("DELETE pfd");
        assert_eq!(resp.status, 204);
        let resp = client
            .get("/nudr-dr/v2/application-data/pfds/app-w42")
            .await
            .expect("GET deleted pfd");
        assert_eq!(resp.status, 404);

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    /// PUT authentication-subscription provisioning path and PLMN-scoped
    /// provisioned-data validation (strict-peer rejections; the DB-backed
    /// success path requires MongoDB and is covered by E2E).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_auth_provisioning_and_plmn_validation() {
        // WSB-6: this test asserts the fail-closed no-DB 503 path; take the
        // backend lock so it cannot overlap with the WSB-6 tests that enable
        // the in-memory dbi test store.
        let _backend = DBI_BACKEND_LOCK.lock().await;
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let supi = "imsi-001019900000004";
        let auth_path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
        );

        // Missing authenticationMethod -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .put_json(
                &auth_path,
                &json!({"encPermanentKey": "00112233445566778899aabbccddeeff"}),
            )
            .await
            .expect("PUT no method");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");

        // Malformed key -> 400 MANDATORY_IE_INCORRECT.
        let resp = client
            .put_json(
                &auth_path,
                &json!({"authenticationMethod": "5G_AKA", "encPermanentKey": "zz"}),
            )
            .await
            .expect("PUT bad key");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_INCORRECT");

        // Valid body without a database -> 503 ProblemDetails (fail closed).
        let resp = client
            .put_json(
                &auth_path,
                &json!({
                    "authenticationMethod": "5G_AKA",
                    "encPermanentKey": "00112233445566778899aabbccddeeff",
                    "encOpcKey": "ffeeddccbbaa99887766554433221100",
                    "authenticationManagementField": "8000",
                    "sequenceNumber": {"sqnScheme": "NON_TIME_BASED", "sqn": "000000000020", "indLength": 5}
                }),
            )
            .await
            .expect("PUT valid");
        assert_eq!(resp.status, 503);

        // Invalid servingPlmnId in the PLMN-scoped provisioned-data layout -> 400.
        let resp = client
            .get(&format!(
                "/nudr-dr/v2/subscription-data/{supi}/12a45/provisioned-data/am-data"
            ))
            .await
            .expect("GET bad plmn");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_INCORRECT");

        // Valid PLMN routes through to the store, not a 400. #1534: no store is
        // open in this test process (the backend lock is held without the test
        // store), which is a system failure, not an unknown user.
        let resp = client
            .get(&format!(
                "/nudr-dr/v2/subscription-data/{supi}/00101/provisioned-data/am-data"
            ))
            .await
            .expect("GET good plmn");
        assert_eq!(resp.status, 500);
        assert_eq!(json_of(&resp)["cause"], "SYSTEM_FAILURE");

        udr.stop().await.expect("udr stops");
    }

    // ------------------------------------------------------------------
    // udrd-01: arp_json / build_sm_data pre-emption fields
    // ------------------------------------------------------------------

    /// TS 29.571 §5.5.3 Arp schema requires priorityLevel + preemptCap +
    /// preemptVuln.  Verify that build_sm_data emits all three and that
    /// the pre-emption mappings are correct:
    ///   pre_emption_capability == 1  → "MAY_PREEMPT"
    ///   pre_emption_vulnerability == 0 → "NOT_PREEMPTABLE"
    #[test]
    fn test_build_sm_data_arp_all_three_fields() {
        use nextgcore_dbi::types::{
            NextgcoreAmbr, NextgcoreArp, NextgcoreQos, NextgcoreSNssai, NextgcoreSession,
            NextgcoreSliceData, NextgcoreSubscriptionData,
        };

        let arp = NextgcoreArp {
            priority_level: 8,
            pre_emption_capability: 1,
            pre_emption_vulnerability: 0,
        };
        let sess = NextgcoreSession {
            name: Some("internet".to_string()),
            session_type: 1, // IPV4
            qos: NextgcoreQos {
                index: 9,
                arp,
                ..Default::default()
            },
            ambr: NextgcoreAmbr {
                uplink: 1_000_000_000,
                downlink: 1_000_000_000,
            },
            ..Default::default()
        };
        let slice = NextgcoreSliceData {
            s_nssai: NextgcoreSNssai::new(1, None),
            session: vec![sess],
            ..Default::default()
        };
        let data = NextgcoreSubscriptionData {
            slice: vec![slice],
            ..Default::default()
        };

        let result = build_sm_data(&data);

        let arr = result.as_array().expect("sm-data is array");
        assert_eq!(arr.len(), 1);
        let arp_val = &arr[0]["dnnConfigurations"]["internet"]["5gQosProfile"]["arp"];

        assert_eq!(arp_val["priorityLevel"], 8_u64, "priorityLevel must be 8");
        assert_eq!(
            arp_val["preemptCap"], "MAY_PREEMPT",
            "capability==1 → MAY_PREEMPT"
        );
        assert_eq!(
            arp_val["preemptVuln"], "NOT_PREEMPTABLE",
            "vulnerability==0 → NOT_PREEMPTABLE"
        );
    }

    /// Complementary case: capability==0 / vulnerability==1 flips both strings.
    #[test]
    fn test_build_sm_data_arp_not_preempt_preemptable() {
        use nextgcore_dbi::types::{
            NextgcoreAmbr, NextgcoreArp, NextgcoreQos, NextgcoreSNssai, NextgcoreSession,
            NextgcoreSliceData, NextgcoreSubscriptionData,
        };

        let arp = NextgcoreArp {
            priority_level: 1,
            pre_emption_capability: 0,
            pre_emption_vulnerability: 1,
        };
        let sess = NextgcoreSession {
            name: Some("ims".to_string()),
            session_type: 3, // IPV4V6
            qos: NextgcoreQos {
                index: 5,
                arp,
                ..Default::default()
            },
            ambr: NextgcoreAmbr {
                uplink: 0,
                downlink: 0,
            },
            ..Default::default()
        };
        let slice = NextgcoreSliceData {
            s_nssai: NextgcoreSNssai::new(1, None),
            session: vec![sess],
            ..Default::default()
        };
        let data = NextgcoreSubscriptionData {
            slice: vec![slice],
            ..Default::default()
        };

        let result = build_sm_data(&data);
        let arr = result.as_array().unwrap();
        let arp_val = &arr[0]["dnnConfigurations"]["ims"]["5gQosProfile"]["arp"];

        assert_eq!(
            arp_val["preemptCap"], "NOT_PREEMPT",
            "capability==0 → NOT_PREEMPT"
        );
        assert_eq!(
            arp_val["preemptVuln"], "PREEMPTABLE",
            "vulnerability==1 → PREEMPTABLE"
        );
    }

    // ------------------------------------------------------------------
    // udrd-02: format_ambr lossless unit selection
    // ------------------------------------------------------------------

    /// TS 29.571 BitRate — exact unit chosen so no precision is lost.
    #[test]
    fn test_format_ambr_precision() {
        // Round values pick the largest exact unit
        assert_eq!(format_ambr(1_000_000_000_000), "1 Tbps");
        assert_eq!(format_ambr(1_000_000_000), "1 Gbps");
        assert_eq!(format_ambr(1_000_000), "1 Mbps");
        assert_eq!(format_ambr(1_000), "1 Kbps");
        assert_eq!(format_ambr(1), "1 bps");
        assert_eq!(format_ambr(0), "0 bps");

        // Non-round values must NOT truncate: drop to next exact unit
        assert_eq!(
            format_ambr(1_500_000_000),
            "1500 Mbps",
            "1.5 Gbps must not truncate to 1 Gbps"
        );
        assert_eq!(
            format_ambr(1_200_000),
            "1200 Kbps",
            "1.2 Mbps must not truncate to 1 Mbps"
        );
        assert_eq!(
            format_ambr(12_345),
            "12345 bps",
            "non-round bps falls through to bps"
        );

        // All outputs must match the TS 29.571 BitRate pattern
        for bps in [
            1u64,
            999,
            1_000,
            1_001,
            1_500_000,
            2_000_000_000,
            5_000_000_000_000,
        ] {
            let s = format_ambr(bps);
            let valid_suffix = s.ends_with(" bps")
                || s.ends_with(" Kbps")
                || s.ends_with(" Mbps")
                || s.ends_with(" Gbps")
                || s.ends_with(" Tbps");
            assert!(valid_suffix, "BitRate pattern violated: {s}");
        }
    }

    // ------------------------------------------------------------------
    // udrd-03: parse_dataset_names
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_dataset_names() {
        // Single name
        let set = parse_dataset_names("AM").unwrap();
        assert!(set.contains("AM"));
        assert!(!set.contains("SM"));

        // Comma-separated, case-insensitive
        let set = parse_dataset_names("AM,SM").unwrap();
        assert!(set.contains("AM"));
        assert!(set.contains("SM"));
        assert!(!set.contains("SMF_SEL"));

        // Mixed case
        let set = parse_dataset_names("smf_sel").unwrap();
        assert!(set.contains("SMF_SEL"));

        // Empty → None
        assert!(parse_dataset_names("").is_none());

        // Whitespace trimming
        let set = parse_dataset_names("AM , SM").unwrap();
        assert!(set.contains("AM"));
        assert!(set.contains("SM"));
    }

    // ------------------------------------------------------------------
    // udrd-06: VarUeId routing
    // ------------------------------------------------------------------

    /// #1686, why `test_varueid_routing` enables the dbi test store: with no
    /// subscriber store at all, an `imsi-` read is the #1534 outage, 500
    /// SYSTEM_FAILURE, which is the CI failure. The 404 that test asserts is a
    /// reachable store's answer for an unprovisioned subscriber. Takes the store's
    /// lock, so no test has the store enabled meanwhile.
    ///
    /// REVERT-VERIFIED: with `test_varueid_routing` back on the bare lock (store
    /// off), it fails with the same 500 when run alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn with_no_subscriber_store_an_imsi_read_is_the_outage_500_1686() {
        let _backend = DBI_BACKEND_LOCK.lock().await;
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let resp = client
            .get("/nudr-dr/v2/subscription-data/imsi-001010000016861/authentication-data/authentication-subscription")
            .await
            .expect("GET imsi");
        udr.stop().await.expect("stop");
        assert_eq!(resp.status, 500, "no store: the #1534 outage");
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
        assert_eq!(problem["cause"], "SYSTEM_FAILURE");
    }

    /// Recognized VarUeId forms that are not DB-backed must return 404,
    /// not 400 INVALID_SUPI.  extgroupid- must return 501.
    /// imsi- and suci- must be unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_varueid_routing() {
        // #1686: the 404s below are a reachable store's "no such subscriber". With
        // no store at all the read is the #1534 outage (500), so this test used to
        // pass only while another test happened to have the dbi test store enabled.
        // It enables the store itself, under the store's lock.
        let _store = DbiTestStore::enable().await;
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());

        // imsi- is unchanged (404 for an unprovisioned subscriber, not 400)
        let resp = client
            .get("/nudr-dr/v2/subscription-data/imsi-001010000000001/authentication-data/authentication-subscription")
            .await
            .expect("GET imsi");
        assert_eq!(
            resp.status, 404,
            "imsi- should 404 (not provisioned), not 400"
        );

        // nai- is a valid VarUeId, returns 404 (not 400 INVALID_SUPI)
        let resp = client
            .get("/nudr-dr/v2/subscription-data/nai-user@example.com/authentication-data/authentication-subscription")
            .await
            .expect("GET nai");
        assert_eq!(resp.status, 404, "nai- should be 404, not 400");
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_ne!(
            problem["cause"], "INVALID_SUPI",
            "nai- must not be rejected as INVALID_SUPI"
        );

        // gci- is a valid VarUeId, returns 404
        let resp = client
            .get("/nudr-dr/v2/subscription-data/gci-001010000000001/authentication-data/authentication-subscription")
            .await
            .expect("GET gci");
        assert_eq!(resp.status, 404, "gci- should be 404");

        // extgroupid- returns 501 Not Implemented
        let resp = client
            .get("/nudr-dr/v2/subscription-data/extgroupid-grp001/authentication-data/authentication-subscription")
            .await
            .expect("GET extgroupid");
        assert_eq!(resp.status, 501, "extgroupid- must return 501");
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "NOT_SUPPORTED");

        // Unknown prefix still returns 400 INVALID_SUPI
        let resp = client
            .get("/nudr-dr/v2/subscription-data/bogus-12345/authentication-data/authentication-subscription")
            .await
            .expect("GET bogus");
        assert_eq!(resp.status, 400, "unknown prefix must still be 400");
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "INVALID_SUPI");

        udr.stop().await.expect("udr stops");
    }

    // ------------------------------------------------------------------
    // udrd-07: project_fields
    // ------------------------------------------------------------------

    #[test]
    fn test_project_fields_nested() {
        let value = json!({"a": {"b": 1, "c": 2}, "d": 3});

        // Single nested path
        let paths = vec!["/a/b".to_string()];
        let result = project_fields(&value, &paths);
        assert_eq!(result, json!({"a": {"b": 1}}));

        // Two paths at different levels
        let paths = vec!["/a/b".to_string(), "/d".to_string()];
        let result = project_fields(&value, &paths);
        assert_eq!(result, json!({"a": {"b": 1}, "d": 3}));

        // Root path returns whole doc
        let paths = vec!["/".to_string()];
        let result = project_fields(&value, &paths);
        assert_eq!(result, value);

        // Non-existent path silently omitted
        let paths = vec!["/z/y".to_string()];
        let result = project_fields(&value, &paths);
        assert_eq!(result, json!({}));

        // Empty paths → unchanged
        let result = project_fields(&value, &[]);
        assert_eq!(result, value);
    }

    // ------------------------------------------------------------------
    // udrd-08: SQN IND-zeroed normalization
    // ------------------------------------------------------------------

    /// TS 29.505 §5.4.2.23: SQN must have the low 5 (indLength) bits zeroed.
    #[test]
    fn test_sqn_ind_zeroed() {
        let mut info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo::default();
        // 0x23 = 0b100011 → IND bits [4:0] = 0b00011 = 3 → must be zeroed → 0x20
        info.sqn = 0x23;
        info.use_opc = true;
        let doc = build_auth_subscription_json("imsi-001010000000001", &info);
        let seq = &doc["sequenceNumber"];
        assert_eq!(seq["indLength"], 5);
        let sqn = seq["sqn"].as_str().unwrap();
        assert_eq!(sqn, "000000000020", "IND bits must be zeroed: 0x23 → 0x20");
        // Verify the low 5 bits of the parsed value are zero
        let sqn_val = u64::from_str_radix(sqn, 16).unwrap();
        assert_eq!(sqn_val & 0x1F, 0, "low 5 bits must be zero");
    }

    #[test]
    fn test_sqn_ind_zeroed_already_clean() {
        let mut info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo::default();
        // 0x20 already has IND bits zeroed → no change
        info.sqn = 0x20;
        info.use_opc = true;
        let doc = build_auth_subscription_json("imsi-001010000000002", &info);
        let sqn = doc["sequenceNumber"]["sqn"].as_str().unwrap();
        assert_eq!(sqn, "000000000020");
    }

    // ------------------------------------------------------------------
    // udrd-10: authenticationMethod defaults to 5G_AKA
    // ------------------------------------------------------------------

    /// NextgcoreDbiAuthInfo does not carry the provisioned authenticationMethod;
    /// the emitted value must default to "5G_AKA" per TS 33.501 §6.1.2.
    #[test]
    fn test_authentication_method_default_5g_aka() {
        let info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo::default();
        let doc = build_auth_subscription_json("imsi-001010000000001", &info);
        assert_eq!(
            doc["authenticationMethod"].as_str().unwrap(),
            "5G_AKA",
            "default authenticationMethod must be 5G_AKA"
        );
    }

    /// udrd#1: a provisioned non-default authenticationMethod (e.g. EAP_AKA_PRIME)
    /// must be served verbatim, not overwritten with 5G_AKA.
    #[test]
    fn test_authentication_method_served_from_db() {
        let info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo {
            authentication_method: "EAP_AKA_PRIME".to_string(),
            ..Default::default()
        };
        let doc = build_auth_subscription_json("imsi-001010000000003", &info);
        assert_eq!(
            doc["authenticationMethod"].as_str().unwrap(),
            "EAP_AKA_PRIME",
            "provisioned authenticationMethod must be served verbatim",
        );
    }

    // ------------------------------------------------------------------
    // udrd-12: sscModes derive documented default (SSC_MODE_1/2/3)
    // ------------------------------------------------------------------

    /// TS 29.505 §5.4.4: when no SSC-mode provisioning is in the DB schema,
    /// the default emitted must include SSC_MODE_1/2/3 (matching the legacy
    /// handler at nudr_handler.rs:627).
    #[test]
    fn test_ssc_modes_default() {
        use nextgcore_dbi::types::{
            NextgcoreAmbr, NextgcoreArp, NextgcoreQos, NextgcoreSNssai, NextgcoreSession,
            NextgcoreSliceData, NextgcoreSubscriptionData,
        };
        let sess = NextgcoreSession {
            name: Some("internet".to_string()),
            session_type: 1,
            qos: NextgcoreQos {
                index: 9,
                arp: NextgcoreArp::default(),
                ..Default::default()
            },
            ambr: NextgcoreAmbr {
                uplink: 1_000_000,
                downlink: 1_000_000,
            },
            ..Default::default()
        };
        let data = NextgcoreSubscriptionData {
            slice: vec![NextgcoreSliceData {
                s_nssai: NextgcoreSNssai::new(1, None),
                session: vec![sess],
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = build_sm_data(&data);
        let ssc = &result[0]["dnnConfigurations"]["internet"]["sscModes"];
        assert_eq!(ssc["defaultSscMode"], "SSC_MODE_1");
        let allowed = ssc["allowedSscModes"].as_array().unwrap();
        let modes: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
        assert!(modes.contains(&"SSC_MODE_1"), "must include SSC_MODE_1");
        assert!(modes.contains(&"SSC_MODE_2"), "must include SSC_MODE_2");
        assert!(modes.contains(&"SSC_MODE_3"), "must include SSC_MODE_3");
    }

    // ------------------------------------------------------------------
    // udrd-04/05: policy-data HTTP round-trip (store and retrieve)
    // ------------------------------------------------------------------

    /// PUT policy sm-data then GET returns the stored doc (not derived default).
    /// PUT am-data then GET returns stored doc.
    /// PUT ue-policy-set then GET returns stored doc.
    /// With no PUT, GET returns the documented default (derived or `{}`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_policy_data_store_and_retrieve() {
        let (udr, client, listener, _cb_port, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900000042";

        // --- am-data ---
        let am_path = format!("/nudr-dr/v2/policy-data/ues/{supi}/am-data");
        // No PUT yet → GET returns {} default
        let resp = client.get(&am_path).await.expect("GET am-data default");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({}), "default am-data must be {{}}");

        // PUT → 201 Created
        let am_doc = json!({"suppFeat": "0", "rfsp": 1});
        let resp = client
            .put_json(&am_path, &am_doc)
            .await
            .expect("PUT am-data");
        assert_eq!(resp.status, 201, "first PUT must be 201");

        // GET now returns stored doc
        let resp = client.get(&am_path).await.expect("GET am-data stored");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got, am_doc, "GET must return stored am-data");

        // Second PUT → 204 Replace
        let resp = client
            .put_json(&am_path, &am_doc)
            .await
            .expect("PUT am-data replace");
        assert_eq!(resp.status, 204, "second PUT must be 204");

        // --- sm-data ---
        let sm_path = format!("/nudr-dr/v2/policy-data/ues/{supi}/sm-data");
        let sm_doc = json!({"smPolicySnssaiData": {"01": {"snssai": {"sst": 1}}}});
        let resp = client
            .put_json(&sm_path, &sm_doc)
            .await
            .expect("PUT sm-data");
        assert_eq!(resp.status, 201, "first PUT must be 201");
        let resp = client.get(&sm_path).await.expect("GET sm-data");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got, sm_doc, "GET must return stored sm-data");

        // --- ue-policy-set ---
        let ue_path = format!("/nudr-dr/v2/policy-data/ues/{supi}/ue-policy-set");
        let ue_doc = json!({"subscPolicySections": {"01": {"upsi": []}}});
        let resp = client
            .put_json(&ue_path, &ue_doc)
            .await
            .expect("PUT ue-policy-set");
        assert_eq!(resp.status, 201, "first PUT must be 201");
        let resp = client.get(&ue_path).await.expect("GET ue-policy-set");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got, ue_doc, "GET must return stored ue-policy-set");

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    // ------------------------------------------------------------------
    // WSB-6: UDR must store exactly the SQN that is written — no
    // side-effect increments (TS 29.505 PATCH = apply PatchItemList only;
    // TS 33.102 Annex C.3: SQN advancement is the UDM/ARPF function).
    // ------------------------------------------------------------------

    /// Local copy of udmd's SQN advance (nextgcore-udmd main.rs
    /// `advance_sqn_ind`, TS 33.102 Annex C.3.2): SQN = SEQ[47:5] || IND[4:0],
    /// SEQ increments by 1 (one +32 step on the packed value), IND kept,
    /// masked to 48 bits. udmd is a bin-only crate so the function cannot be
    /// linked from here; the arithmetic is replicated verbatim.
    fn udm_advance_sqn_ind(sqn: u64) -> u64 {
        let seq = sqn >> 5;
        let ind = sqn & 0x1F;
        (((seq + 1) << 5) | ind) & 0x0000_FFFF_FFFF_FFFF
    }

    /// Provision an authentication subscription through the REAL PUT handler
    /// (TS 29.505 AuthenticationSubscription shape) and return the auth path.
    async fn wsb6_provision(client: &SbiClient, supi: &str, sqn: u64) -> String {
        let auth_path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
        );
        let resp = client
            .put_json(
                &auth_path,
                &json!({
                    "authenticationMethod": "5G_AKA",
                    "encPermanentKey": "465b5ce8b199b49faa5f0a2ee238a6bc",
                    "encOpcKey": "e8ed289deba952e4283b54e88e6183ca",
                    "authenticationManagementField": "8000",
                    "sequenceNumber": {
                        "sqnScheme": "NON_TIME_BASED",
                        "sqn": format!("{sqn:012x}"),
                        "indLength": 5
                    }
                }),
            )
            .await
            .expect("PUT provision");
        assert_eq!(resp.status, 201, "provisioning PUT must create (201)");
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(sqn),
            "provisioned SQN must be stored exactly"
        );
        auth_path
    }

    // ------------------------------------------------------------------
    // #86 secondary: PATCH reports failures, authentication-status persists
    // ------------------------------------------------------------------

    /// Spin up the UDR SBI server and return a client for it.
    async fn start_udr() -> (SbiServer, SbiClient) {
        // #2079: an anonymous loopback peer writes UDM context data under `dev`
        // only. Set, never reset (CONVENTIONS).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (addr_listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), addr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", addr.port());
        (udr, client)
    }

    /// A malformed / non-array / empty PATCH body must be REJECTED, not
    /// acknowledged with 204. Previously every one of these fell through to
    /// `SbiResponse::with_status(204)`, so a consumer could not tell an applied
    /// patch from a silently discarded one (TS 29.505 §5.2.2.x, TS 29.500
    /// §5.2.7 ProblemDetails).
    #[tokio::test]
    async fn patch_auth_subscription_rejects_unusable_bodies() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000861";
        let auth_path = wsb6_provision(&client, supi, 0x40).await;

        // Not JSON at all. Built directly because patch_json would serialise
        // the string INTO valid JSON, which is not the case under test.
        let resp = client
            .send_request(SbiRequest::patch(&auth_path).with_body("not json", "application/json"))
            .await
            .expect("PATCH garbage");
        assert_eq!(resp.status, 400, "a non-JSON body must be 400, never 204");

        // Valid JSON but not an array of PatchItem.
        let resp = client
            .patch_json(&auth_path, &json!({"op": "replace"}))
            .await
            .expect("PATCH object");
        assert_eq!(resp.status, 400, "a non-array body must be 400");

        // Empty array: PatchResult.report is minItems 1, so an empty patch list
        // can be reported neither as success nor as a failure item.
        let resp = client
            .patch_json(&auth_path, &json!([]))
            .await
            .expect("PATCH empty");
        assert_eq!(resp.status, 400, "an empty PatchItem array must be 400");

        // None of the rejected requests may have altered the stored SQN.
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(0x40),
            "a rejected PATCH must not change stored state"
        );
    }

    /// An unsupported patch path is reported in a PatchResult rather than
    /// silently dropped, and the reason names the failing operation index as
    /// TS 29.571 ReportItem recommends.
    #[tokio::test]
    async fn patch_auth_subscription_reports_unsupported_path() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000862";
        let auth_path = wsb6_provision(&client, supi, 0x40).await;

        let resp = client
            .patch_json(
                &auth_path,
                &json!([{"op": "replace", "path": "/encPermanentKey", "value": "00"}]),
            )
            .await
            .expect("PATCH unsupported path");
        assert_eq!(resp.status, 400);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let report = doc["report"].as_array().expect("PatchResult.report array");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0]["path"], "/encPermanentKey");
        assert!(
            report[0]["reason"].as_str().unwrap().contains("index= 0"),
            "reason should identify the failed operation index (TS 29.571)"
        );
    }

    /// A non-hex SQN must be REJECTED, leaving the stored value untouched.
    ///
    /// This is the silent-corruption case: the old handler did
    /// `u64::from_str_radix(sqn_hex, 16).unwrap_or(0)`, so "zzzz" became SQN 0
    /// -- a valid-looking sequence number written over good data, reported as
    /// 204 success.
    #[tokio::test]
    async fn patch_auth_subscription_rejects_non_hex_sqn_without_corrupting() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000863";
        let auth_path = wsb6_provision(&client, supi, 0x40).await;

        let resp = client
            .patch_json(
                &auth_path,
                &json!([{"op": "replace", "path": "/sequenceNumber/sqn", "value": "zzzz"}]),
            )
            .await
            .expect("PATCH non-hex");
        assert_eq!(resp.status, 400, "a non-hex SQN must be 400, never 204");
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(0x40),
            "the stored SQN must be UNCHANGED -- unwrap_or(0) used to write 0 here"
        );

        // Beyond the 48-bit SQN range (TS 33.102) is likewise rejected, not
        // truncated.
        let resp = client
            .patch_json(
                &auth_path,
                &json!([{"op": "replace", "path": "/sequenceNumber/sqn",
                         "value": "1000000000000"}]),
            )
            .await
            .expect("PATCH oversized");
        assert_eq!(resp.status, 400);
        assert_eq!(nextgcore_dbi::test_store::stored_sqn(supi), Some(0x40));
    }

    /// PUT stores the AuthEvent and GET serves it back; previously the body was
    /// acknowledged with 204 and DISCARDED, and GET fell through to 405
    /// (TS 29.505 authentication-status, TS 29.503 AuthEvent, TS 33.501
    /// §6.1.4 result storage).
    #[tokio::test]
    async fn auth_status_put_get_delete_roundtrip() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000864";
        let base = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );

        // Nothing stored yet: 404 DATA_NOT_FOUND, NOT 405 method-not-allowed.
        let resp = client.get(&base).await.expect("GET empty");
        assert_eq!(
            resp.status, 404,
            "GET must be a defined operation returning 404 when absent, not 405"
        );

        let event = json!({
            "nfInstanceId": "b2c3d4e5-0000-4000-8000-000000000001",
            "success": true,
            "timeStamp": "2026-08-08T12:00:00Z",
            "authType": "5G_AKA",
            "servingNetworkName": "5G:mnc099.mcc999.3gppnetwork.org"
        });
        // TS 29.505 defines ONLY 204 for a successful PUT on this resource --
        // no 201 -- unlike smf-registrations, which does define 201 Created.
        let resp = client.put_json(&base, &event).await.expect("PUT event");
        assert_eq!(
            resp.status, 204,
            "PUT success on auth-status is 204, never 201"
        );

        // GET returns the stored AuthEvent verbatim.
        let resp = client.get(&base).await.expect("GET stored");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["nfInstanceId"], event["nfInstanceId"]);
        assert_eq!(doc["authType"], "5G_AKA");
        assert_eq!(doc["success"], true);

        // Re-PUT replaces, also 204.
        let resp = client.put_json(&base, &event).await.expect("PUT again");
        assert_eq!(resp.status, 204, "replacing an existing resource is 204");

        // DELETE removes it; a second GET is 404 again.
        let resp = client.delete(&base).await.expect("DELETE");
        assert_eq!(resp.status, 204);
        let resp = client.get(&base).await.expect("GET after delete");
        assert_eq!(resp.status, 404);
    }

    /// A PUT missing any required AuthEvent attribute is rejected.
    #[tokio::test]
    async fn auth_status_put_rejects_missing_required_ie() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000865";
        let base = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );

        // authType omitted (TS 29.503 AuthEvent requires it).
        let resp = client
            .put_json(
                &base,
                &json!({
                    "nfInstanceId": "b2c3d4e5-0000-4000-8000-000000000002",
                    "success": true,
                    "timeStamp": "2026-08-08T12:00:00Z",
                    "servingNetworkName": "5G:mnc099.mcc999.3gppnetwork.org"
                }),
            )
            .await
            .expect("PUT incomplete");
        assert_eq!(resp.status, 400);
        // And nothing was stored.
        let resp = client.get(&base).await.expect("GET after reject");
        assert_eq!(resp.status, 404);
    }

    /// The individual `.../{servingNetworkName}` form keys independently, so two
    /// serving networks coexist for one SUPI and the collection GET returns the
    /// most recent.
    #[tokio::test]
    async fn auth_status_individual_form_keys_per_serving_network() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000866";
        let base = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );
        let snn_a = "5G:mnc001.mcc001.3gppnetwork.org";
        let snn_b = "5G:mnc002.mcc002.3gppnetwork.org";

        let ev = |snn: &str, ok: bool| {
            json!({
                "nfInstanceId": "b2c3d4e5-0000-4000-8000-000000000003",
                "success": ok,
                "timeStamp": "2026-08-08T12:00:00Z",
                "authType": "5G_AKA",
                "servingNetworkName": snn
            })
        };

        let resp = client
            .put_json(&format!("{base}/{snn_a}"), &ev(snn_a, true))
            .await
            .expect("PUT A");
        assert_eq!(resp.status, 204);
        let resp = client
            .put_json(&format!("{base}/{snn_b}"), &ev(snn_b, false))
            .await
            .expect("PUT B");
        assert_eq!(
            resp.status, 204,
            "a different serving network is a distinct resource, still 204"
        );

        // Each is retrievable independently.
        let resp = client.get(&format!("{base}/{snn_a}")).await.expect("GET A");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["success"], true);
        assert_eq!(doc["servingNetworkName"], snn_a);

        let resp = client.get(&format!("{base}/{snn_b}")).await.expect("GET B");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["success"], false);

        // Collection GET yields the most recently stored one (B).
        let resp = client.get(&base).await.expect("GET collection");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["servingNetworkName"], snn_b);

        // A body whose servingNetworkName disagrees with the URI is rejected,
        // so the stored key can never contradict the URI used to GET it.
        let resp = client
            .put_json(&format!("{base}/{snn_a}"), &ev(snn_b, true))
            .await
            .expect("PUT mismatched");
        assert_eq!(resp.status, 400);

        // Deleting one leaves the other.
        let resp = client
            .delete(&format!("{base}/{snn_a}"))
            .await
            .expect("DELETE A");
        assert_eq!(resp.status, 204);
        let resp = client
            .get(&format!("{base}/{snn_b}"))
            .await
            .expect("GET B after deleting A");
        assert_eq!(resp.status, 200);
    }

    /// WSB-6 acceptance test: PATCH /sequenceNumber/sqn = X through the real
    /// SBI server + router + handler → the stored SQN is EXACTLY X (the old
    /// PATCH arm corrupted it to X+32 via an unconditional SQN increment).
    /// Reintroducing the increment makes this test fail.
    #[tokio::test]
    async fn wsb6_patch_stores_exact_sqn_no_side_effect() {
        let _store = DbiTestStore::enable().await;
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let supi = "imsi-999990000000601";
        let auth_path = wsb6_provision(&client, supi, 0x20).await;

        // udmd-shaped PATCH body — byte-identical PatchItemList to
        // udm_nudr_dr_send_auth_subscription_patch (nextgcore-udmd
        // sbi_path.rs): [{"op":"replace","path":"/sequenceNumber/sqn",...}].
        let x: u64 = 0x2020; // IND bits zero, so the served form is exact too
        let resp = client
            .patch_json(
                &auth_path,
                &json!([{
                    "op": "replace",
                    "path": "/sequenceNumber/sqn",
                    "value": format!("{x:012x}")
                }]),
            )
            .await
            .expect("PATCH sqn");
        assert_eq!(resp.status, 204);

        // Stored value must be exactly X — not X+32.
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(x),
            "UDR must store exactly the PATCHed SQN (TS 29.505); +32 means the \
             WSB-6 side-effect increment was reintroduced"
        );

        // And the real GET handler serves it back exactly.
        let resp = client.get(&auth_path).await.expect("GET auth-subscription");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["sequenceNumber"]["sqn"], format!("{x:012x}"));

        udr.stop().await.expect("udr stops");
    }

    /// WSB-6: the authentication-status PUT/DELETE arm must have NO SQN side
    /// effect (it previously incremented by +32 on every UDM confirmation).
    #[tokio::test]
    async fn wsb6_auth_status_put_delete_no_sqn_side_effect() {
        let _store = DbiTestStore::enable().await;
        // #2157: through `start_udr`, which declares the dev profile. The
        // auth-status PUT/DELETE is a write of the UDM's context data, admitted
        // under production only from a verified UDM (#2079), and this loopback
        // peer proves no identity; alone the PUT was 403, and it passed only
        // after a sibling had set Dev.
        let (udr, client) = start_udr().await;
        let supi = "imsi-999990000000602";
        let s0: u64 = 0x40;
        wsb6_provision(&client, supi, s0).await;
        let status_path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );

        // TS 29.503 AuthEvent body, as udmd PUTs it on auth confirmation
        // (udm_nudr_dr_send_auth_status_put passes the AUSF body verbatim).
        let resp = client
            .put_json(
                &status_path,
                &json!({
                    "nfInstanceId": "6874ed4b-262c-4a53-a8a4-e846a41ad0e8",
                    "success": true,
                    "timeStamp": "2026-07-01T00:00:00Z",
                    "authType": "5G_AKA",
                    "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"
                }),
            )
            .await
            .expect("PUT auth-status");
        assert_eq!(resp.status, 204);
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(s0),
            "auth-status PUT must not advance the stored SQN"
        );

        let resp = client
            .delete(&status_path)
            .await
            .expect("DELETE auth-status");
        assert_eq!(resp.status, 204);
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(s0),
            "auth-status DELETE must not advance the stored SQN"
        );

        udr.stop().await.expect("udr stops");
    }

    /// WSB-6 strict-peer sequence: emulate udmd's generate-AV flow (GET →
    /// client-side advance_sqn_ind → PATCH exact value → auth-status PUT on
    /// confirmation) N times against the REAL udrd handler stack. The stored
    /// SQN must advance EXACTLY one SEQ step per AV (previously 3: udmd's
    /// intended advance + PATCH-side +32 + auth-status +32). Includes one
    /// AUTS-resync iteration (TS 33.102 §6.3.5: resume from SQN_MS+1, then
    /// one advance) whose exact value — including nonzero IND bits — must be
    /// stored verbatim.
    #[tokio::test]
    async fn wsb6_udm_av_flow_advances_sqn_one_step_per_av() {
        let _store = DbiTestStore::enable().await;
        // #2157: through `start_udr`, which declares the dev profile. The
        // auth-status PUT/DELETE is a write of the UDM's context data, admitted
        // under production only from a verified UDM (#2079), and this loopback
        // peer proves no identity; alone the PUT was 403, and it passed only
        // after a sibling had set Dev.
        let (udr, client) = start_udr().await;
        let supi = "imsi-999990000000603";
        let s0: u64 = 0x20;
        let auth_path = wsb6_provision(&client, supi, s0).await;
        let status_path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );
        let auth_event = json!({
            "nfInstanceId": "6874ed4b-262c-4a53-a8a4-e846a41ad0e8",
            "success": true,
            "timeStamp": "2026-07-01T00:00:00Z",
            "authType": "5G_AKA",
            "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"
        });

        const N: u32 = 3;
        for _ in 0..N {
            // udmd reads the served SQN (GET), advances it client-side per
            // TS 33.102 C.3.2 and PATCHes the advanced value (udmd main.rs
            // step 6), then PUTs the AuthEvent on confirmation.
            let resp = client.get(&auth_path).await.expect("GET auth-subscription");
            assert_eq!(resp.status, 200);
            let doc: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let served =
                u64::from_str_radix(doc["sequenceNumber"]["sqn"].as_str().expect("sqn hex"), 16)
                    .expect("sqn parses");
            let advanced = udm_advance_sqn_ind(served);
            let resp = client
                .patch_json(
                    &auth_path,
                    &json!([{
                        "op": "replace",
                        "path": "/sequenceNumber/sqn",
                        "value": format!("{advanced:012x}")
                    }]),
                )
                .await
                .expect("PATCH sqn");
            assert_eq!(resp.status, 204);
            let resp = client
                .put_json(&status_path, &auth_event)
                .await
                .expect("PUT auth-status");
            assert_eq!(resp.status, 204);
        }

        // Exactly one SEQ step (+32) per AV — nothing more.
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(s0 + u64::from(N) * 32),
            "stored SQN must advance exactly one advance_sqn_ind step per AV"
        );

        // AUTS resync iteration: udmd resumes from SQN_MS+1 (main.rs resync
        // branch), then step 6 advances once and PATCHes; the exact value —
        // IND bits included — must be stored verbatim.
        let sqn_ms: u64 = 0xA0C5; // nonzero IND (5)
        let resync_next = udm_advance_sqn_ind((sqn_ms + 1) & 0x0000_FFFF_FFFF_FFFF);
        let resp = client
            .patch_json(
                &auth_path,
                &json!([{
                    "op": "replace",
                    "path": "/sequenceNumber/sqn",
                    "value": format!("{resync_next:012x}")
                }]),
            )
            .await
            .expect("PATCH resync sqn");
        assert_eq!(resp.status, 204);
        let resp = client
            .put_json(&status_path, &auth_event)
            .await
            .expect("PUT auth-status after resync");
        assert_eq!(resp.status, 204);
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(resync_next),
            "resynchronized SQN must be stored exactly (IND bits preserved, \
             no +32 corruption)"
        );

        udr.stop().await.expect("udr stops");
    }

    // ========================================================================
    // #87: the TS 29.505 / 29.519 / 29.504 resources that answered 404 or 405.
    // ========================================================================

    fn json_of(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("null"))
            .unwrap_or(serde_json::Value::Null)
    }

    fn amf_reg(instance: &str, non_3gpp: bool) -> serde_json::Value {
        let mut doc = json!({
            "amfInstanceId": instance,
            "deregCallbackUri": format!("http://{instance}/dereg"),
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": if non_3gpp { "VIRTUAL" } else { "NR" }
        });
        if non_3gpp {
            doc["imsVoPs"] = json!("HOMOGENEOUS_NON_SUPPORT");
        }
        doc
    }

    /// #87 gap 1: `amf-non-3gpp-access` is its own resource. It returned 404, so
    /// non-3GPP registration state could not be stored at all — and the UDM
    /// producer added in #84 writes exactly here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_amf_non_3gpp_access_round_trip() {
        let (udr, client, _listener, _cb_port, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008701";
        let three = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access");
        let non3 = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-non-3gpp-access");

        // Register over 3GPP first, so the assertions below can prove the two
        // resources are independent rather than aliases.
        let resp = client
            .put_json(&three, &amf_reg("amf-3gpp", false))
            .await
            .expect("PUT 3gpp");
        assert_eq!(resp.status, 201);

        // The non-3GPP schema additionally requires imsVoPs.
        let resp = client
            .put_json(&non3, &amf_reg("amf-n3", false))
            .await
            .expect("PUT non-3gpp without imsVoPs");
        assert_eq!(resp.status, 400);
        assert_eq!(json_of(&resp)["cause"], "MANDATORY_IE_MISSING");

        let doc = amf_reg("amf-n3", true);
        let resp = client.put_json(&non3, &doc).await.expect("PUT non-3gpp");
        assert_eq!(
            resp.status, 201,
            "amf-non-3gpp-access must be stored, not 404: {:?}",
            resp.http.content
        );
        assert_eq!(
            resp.http.get_header("Location").map(String::as_str),
            Some(non3.as_str())
        );

        let resp = client.get(&non3).await.expect("GET non-3gpp");
        assert_eq!(resp.status, 200);
        assert_eq!(json_of(&resp), doc, "round-trip equality");

        // The 3GPP registration is untouched by the non-3GPP one.
        let resp = client.get(&three).await.expect("GET 3gpp");
        assert_eq!(resp.status, 200);
        assert_eq!(json_of(&resp)["amfInstanceId"], "amf-3gpp");

        // PATCH and DELETE address only the addressed access.
        let resp = client
            .patch_json(&non3, &json!({"pei": "imeisv-1234567890123456"}))
            .await
            .expect("PATCH non-3gpp");
        assert_eq!(resp.status, 204);
        let resp = client.get(&non3).await.expect("GET after PATCH");
        assert_eq!(json_of(&resp)["pei"], "imeisv-1234567890123456");

        let resp = client.delete(&non3).await.expect("DELETE non-3gpp");
        assert_eq!(resp.status, 204);
        let resp = client.get(&non3).await.expect("GET after DELETE");
        assert_eq!(resp.status, 404);
        let resp = client
            .get(&three)
            .await
            .expect("GET 3gpp after non-3gpp delete");
        assert_eq!(
            resp.status, 200,
            "deleting the non-3GPP registration must not delete the 3GPP one"
        );

        udr.stop().await.expect("stop");
    }

    /// #87 gap 1: the `smf-registrations` PUT owes a `Location` header and the
    /// created representation, and PATCH must not be a 405.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_smf_registration_put_location_body_and_patch() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008702";
        let path = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/5");
        let doc = json!({
            "smfInstanceId": "smf-1",
            "pduSessionId": 5,
            "singleNssai": { "sst": 1, "sd": "000001" },
            "dnn": "internet",
            "plmnId": { "mcc": "001", "mnc": "01" }
        });

        let resp = client.put_json(&path, &doc).await.expect("PUT");
        assert_eq!(resp.status, 201);
        assert_eq!(
            resp.http.get_header("Location").map(String::as_str),
            Some(path.as_str()),
            "TS 29.505 requires Location on the 201"
        );
        assert_eq!(
            json_of(&resp)["smfInstanceId"],
            "smf-1",
            "the 201 must carry the created SmfRegistration"
        );

        // PATCH was a flat 405.
        let resp = client
            .patch_json(
                &path,
                &json!([{"op": "replace", "path": "/dnn", "value": "ims"}]),
            )
            .await
            .expect("PATCH");
        assert_eq!(
            resp.status, 204,
            "PATCH must be accepted: {:?}",
            resp.http.content
        );
        let resp = client.get(&path).await.expect("GET after PATCH");
        assert_eq!(json_of(&resp)["dnn"], "ims");

        // The id in the URI owns the resource: a patch cannot move it.
        let resp = client
            .patch_json(
                &path,
                &json!([{"op": "replace", "path": "/pduSessionId", "value": 9}]),
            )
            .await
            .expect("PATCH psi");
        assert_eq!(resp.status, 400, "pduSessionId is not patchable");

        udr.stop().await.expect("stop");
    }

    /// #87 gap 2: the remaining per-UE context documents and collections.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_context_data_smsf_ipsmgw_and_subscription_collections() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008703";
        let ctx = |r: &str| format!("/nudr-dr/v2/subscription-data/{supi}/context-data/{r}");

        for (resource, doc) in [
            (
                "smsf-3gpp-access",
                json!({"smsfInstanceId": "smsf-1", "plmnId": {"mcc": "001", "mnc": "01"}}),
            ),
            (
                "smsf-non-3gpp-access",
                json!({"smsfInstanceId": "smsf-2", "plmnId": {"mcc": "001", "mnc": "01"}}),
            ),
            ("ip-sm-gw", json!({"ipsmgwFqdn": "ipsmgw.example.org"})),
        ] {
            let path = ctx(resource);
            let resp = client.get(&path).await.expect("GET before");
            assert_eq!(resp.status, 404, "{resource} unprovisioned");
            let resp = client.put_json(&path, &doc).await.expect("PUT");
            assert_eq!(resp.status, 201, "{resource} PUT: {:?}", resp.http.content);
            let resp = client.get(&path).await.expect("GET after");
            assert_eq!(resp.status, 200);
            assert_eq!(json_of(&resp), doc, "{resource} round-trip");
            let resp = client.delete(&path).await.expect("DELETE");
            assert_eq!(resp.status, 204);
        }

        // sdm-subscriptions / ee-subscriptions collections.
        for resource in ["sdm-subscriptions", "ee-subscriptions"] {
            let member = format!("{}/sub-1", ctx(resource));
            let doc = json!({"nfInstanceId": "nf-1", "callbackReference": "http://nf/cb"});
            let resp = client.put_json(&member, &doc).await.expect("PUT member");
            assert_eq!(resp.status, 201, "{resource} member PUT");
            let resp = client.get(&ctx(resource)).await.expect("GET collection");
            assert_eq!(resp.status, 200);
            assert_eq!(
                json_of(&resp),
                json!([doc]),
                "{resource} collection lists this UE's members"
            );
            let resp = client.delete(&member).await.expect("DELETE member");
            assert_eq!(resp.status, 204);
            let resp = client.get(&member).await.expect("GET after delete");
            assert_eq!(resp.status, 404);
        }

        udr.stop().await.expect("stop");
    }

    /// #2079: the bodies the UDM context writes below carry.
    fn ctx_write_2079(method: &str, path: &str, body: Option<serde_json::Value>) -> SbiRequest {
        let req = match method {
            "PUT" => SbiRequest::put(path),
            "PATCH" => SbiRequest::patch(path),
            "POST" => SbiRequest::post(path),
            _ => SbiRequest::delete(path),
        };
        match body {
            Some(b) => req.with_json_body(&b).expect("json"),
            None => req,
        }
    }

    /// #2079: every UDM context-data write a non-UDM may attempt, with the
    /// resource scope its refusal names: `(method, path under the UE, body,
    /// scope)`.
    fn udm_context_writes_2079(
        ue: &str,
    ) -> Vec<(
        &'static str,
        String,
        Option<serde_json::Value>,
        &'static str,
    )> {
        use nextgcore_sbi::resource_scope::{
            NUDR_DR_REGISTRATIONS_WRITE as WRITE, NUDR_DR_SUBSCRIPTION_DATA as DATA,
        };
        let amf = json!({
            "amfInstanceId": "amf-intruder",
            "deregCallbackUri": "http://intruder.example.org/dereg",
            "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "cafe00"},
            "ratType": "NR",
            "imsVoPs": "HOMOGENEOUS_NON_SUPPORT"
        });
        let smf = json!({
            "smfInstanceId": "smf-intruder", "pduSessionId": 5,
            "singleNssai": {"sst": 1}, "dnn": "internet",
            "plmnId": {"mcc": "001", "mnc": "01"}
        });
        let smsf =
            json!({"smsfInstanceId": "smsf-intruder", "plmnId": {"mcc": "001", "mnc": "01"}});
        let sub = json!({"nfInstanceId": "nf-intruder", "callbackReference": "http://intruder/cb"});
        let event = json!({
            "nfInstanceId": "nf-intruder", "success": false,
            "timeStamp": "2026-11-19T00:00:00Z", "authType": "5G_AKA",
            "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"
        });
        let c = |r: &str| format!("{ue}/context-data/{r}");
        vec![
            ("PUT", c("amf-3gpp-access"), Some(amf.clone()), WRITE),
            ("PATCH", c("amf-3gpp-access"), Some(json!({"purgeFlag": true})), WRITE),
            ("DELETE", c("amf-3gpp-access"), None, WRITE),
            ("PUT", c("amf-non-3gpp-access"), Some(amf.clone()), WRITE),
            ("PUT", format!("{ue}/00101/context-data/amf-3gpp-access"), Some(amf), WRITE),
            ("PUT", c("smf-registrations/5"), Some(smf), WRITE),
            ("DELETE", c("smf-registrations/5"), None, WRITE),
            ("PUT", c("smsf-3gpp-access"), Some(smsf.clone()), WRITE),
            ("DELETE", c("smsf-3gpp-access"), None, WRITE),
            ("PUT", c("smsf-non-3gpp-access"), Some(smsf), WRITE),
            ("PUT", c("ip-sm-gw"), Some(json!({"ipsmgwFqdn": "intruder.example.org"})), WRITE),
            ("DELETE", c("ip-sm-gw"), None, WRITE),
            ("PUT", c("sdm-subscriptions/s1"), Some(sub.clone()), DATA),
            ("POST", c("sdm-subscriptions"), Some(sub.clone()), DATA),
            ("DELETE", c("sdm-subscriptions/s1"), None, DATA),
            ("PUT", c("ee-subscriptions/e1"), Some(sub.clone()), DATA),
            ("POST", c("ee-subscriptions"), Some(sub), DATA),
            ("DELETE", c("ee-subscriptions/e1"), None, DATA),
            (
                "PUT",
                format!("{ue}/authentication-data/authentication-status"),
                Some(event.clone()),
                DATA,
            ),
            (
                "PUT",
                format!("{ue}/authentication-data/authentication-status/5G:mnc001.mcc001.3gppnetwork.org"),
                Some(event),
                DATA,
            ),
            ("DELETE", format!("{ue}/authentication-data/authentication-status"), None, DATA),
        ]
    }

    /// #2079: the REAL router behind the UDR's OAuth2 listener (`udr_oauth2_listener`,
    /// the one `main` builds). A PCF, NEF or AUSF holds `nudr-dr` alone on this
    /// service (UDR_RESOURCE_SCOPES; TS 29.510 NOTE 11), so every write of the
    /// UDM's context data -- the NF registrations, the authentication status and
    /// the UDM's SDM / EE subscriptions -- is refused 403 `insufficient_scope`
    /// naming its TS 29.505 scope, a retry is refused the same way, and nothing
    /// is applied: each resource the UDM stored reads back unchanged (GETs stay on
    /// the service scope), and none the refused writes would have created exists.
    /// The UDM's token writes them all, `subscription-data` alone standing in for
    /// `registrations:write` as the yaml allows, and a repeated PUT stores one
    /// record.
    ///
    /// REVERT-VERIFIED: with `required_resource_scope` answering `None` for the
    /// context-data writes, the PCF's amf-3gpp-access PUT is applied and the
    /// `refused` assertion fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_non_udm_token_writes_no_udm_context_data_2079() {
        use nextgcore_sbi::resource_scope::{
            NUDR_DR_REGISTRATIONS_WRITE as WRITE, NUDR_DR_SUBSCRIPTION_DATA as DATA,
        };
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = udr_oauth2_listener(NextgcoreSbiServerConfig::new(udr_addr));
        cfg.oauth2_jwks = Some(stand_in::jwks_for(&sk, stand_in::TEST_NRF_KID));
        let udr = SbiServer::on_listener(cfg, udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let bearer = |scope: &str| {
            format!(
                "Bearer {}",
                stand_in::es256_access_token(&sk, stand_in::TEST_NRF_KID, "UDR", scope)
            )
        };
        // What the NRF grants a PCF, NEF or AUSF on nudr-dr, and the UDM.
        let other = bearer("nudr-dr");
        let udm = bearer(&format!("nudr-dr {DATA} {WRITE}"));
        let udm_alt = bearer(&format!("nudr-dr {DATA}"));
        let send = |req: SbiRequest, auth: &str| {
            let req = req.with_header("authorization", auth.to_string());
            let client = &client;
            async move { client.send_request(req).await.expect("response") }
        };
        let supi = "imsi-001010000020791";
        // #2113: the stand-in tokens' subject; the NRF vouches for it as a UDM
        // (here seeded), so a token's scope decides.
        nextgcore_sbi::owner_binding::seed_nf_type_for_test("consumer", nextgcore_sbi::NfType::Udm);
        let ue = format!("/nudr-dr/v2/subscription-data/{supi}");
        let c = |r: &str| format!("{ue}/context-data/{r}");

        // The UDM's own records, which the refused writes must leave alone.
        let amf = json!({
            "amfInstanceId": "amf-udm",
            "deregCallbackUri": "http://amf.example.org/dereg",
            "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "cafe00"},
            "ratType": "NR"
        });
        let smf = json!({
            "smfInstanceId": "smf-udm", "pduSessionId": 5,
            "singleNssai": {"sst": 1}, "dnn": "internet",
            "plmnId": {"mcc": "001", "mnc": "01"}
        });
        let smsf = json!({"smsfInstanceId": "smsf-udm", "plmnId": {"mcc": "001", "mnc": "01"}});
        let ipsmgw = json!({"ipsmgwFqdn": "ipsmgw.example.org"});
        let sub = json!({"nfInstanceId": "udm-1", "callbackReference": "http://udm/cb"});
        let event = json!({
            "nfInstanceId": "udm-1", "success": true,
            "timeStamp": "2026-11-19T00:00:00Z", "authType": "5G_AKA",
            "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"
        });
        let auth_status = format!("{ue}/authentication-data/authentication-status");
        let baseline = [
            (c("amf-3gpp-access"), amf.clone()),
            (c("smf-registrations/5"), smf.clone()),
            (c("smsf-3gpp-access"), smsf.clone()),
            (c("ip-sm-gw"), ipsmgw.clone()),
            (c("sdm-subscriptions/s1"), sub.clone()),
            (c("ee-subscriptions/e1"), sub.clone()),
            (auth_status.clone(), event.clone()),
        ];
        for (path, doc) in &baseline {
            let r = send(ctx_write_2079("PUT", path, Some(doc.clone())), &udm).await;
            assert!(
                r.status == 201 || r.status == 204,
                "the UDM provisions {path}: {} {:?}",
                r.status,
                r.http.content
            );
        }

        // Every write, twice (a retry is refused the same way).
        let mut answers = Vec::new();
        for _ in 0..2 {
            for (method, path, body, scope) in udm_context_writes_2079(&ue) {
                let r = send(ctx_write_2079(method, &path, body), &other).await;
                answers.push((method, path, scope, r));
            }
        }
        let mut after = Vec::new();
        for (path, _) in &baseline {
            after.push(send(SbiRequest::get(path), &other).await);
        }
        let absent_non3gpp = send(SbiRequest::get(c("amf-non-3gpp-access")), &other).await;
        let absent_plmn = send(
            SbiRequest::get(format!("{ue}/00101/context-data/amf-3gpp-access")),
            &other,
        )
        .await;
        let absent_smsf_n3 = send(SbiRequest::get(c("smsf-non-3gpp-access")), &other).await;
        let sdm_collection = send(SbiRequest::get(c("sdm-subscriptions")), &other).await;
        let ee_collection = send(SbiRequest::get(c("ee-subscriptions")), &other).await;

        // The UDM writes; `subscription-data` alone stands in for
        // `registrations:write`; a repeated PUT stores one record.
        let mut non3 = amf.clone();
        non3["imsVoPs"] = json!("HOMOGENEOUS_NON_SUPPORT");
        let alt = send(
            ctx_write_2079("PUT", &c("amf-non-3gpp-access"), Some(non3.clone())),
            &udm_alt,
        )
        .await;
        let first = send(
            ctx_write_2079("PUT", &c("smsf-non-3gpp-access"), Some(smsf.clone())),
            &udm,
        )
        .await;
        let again = send(
            ctx_write_2079("PUT", &c("smsf-non-3gpp-access"), Some(smsf.clone())),
            &udm,
        )
        .await;
        let stored = send(SbiRequest::get(c("smsf-non-3gpp-access")), &other).await;
        let udm_delete = send(ctx_write_2079("DELETE", &c("ip-sm-gw"), None), &udm).await;
        udr.stop().await.expect("stop");

        let challenge = |r: &SbiResponse| {
            r.http
                .get_header("www-authenticate")
                .cloned()
                .unwrap_or_default()
        };
        for (method, path, scope, r) in &answers {
            assert_eq!(
                r.status, 403,
                "refused: a non-UDM token must not {method} {path}: {:?}",
                r.http.content
            );
            assert!(
                challenge(r).contains(&format!("scope=\"{scope}\"")),
                "{method} {path}: {}",
                challenge(r)
            );
        }
        for ((path, doc), r) in baseline.iter().zip(&after) {
            assert_eq!(r.status, 200, "{path} reads on the service scope");
            assert_eq!(
                &json_of(r),
                doc,
                "{path} is unchanged by the refused writes"
            );
        }
        for r in [&absent_non3gpp, &absent_smsf_n3] {
            assert_eq!(r.status, 404, "a refused PUT created nothing");
        }
        // The servingPlmnId layout addresses the same AMF slot: still the UDM's.
        assert_eq!(
            json_of(&absent_plmn),
            amf,
            "the PLMN-scoped PUT changed nothing"
        );
        assert_eq!(
            json_of(&sdm_collection),
            json!([sub]),
            "no refused POST added a member"
        );
        assert_eq!(
            json_of(&ee_collection),
            json!([sub]),
            "no refused POST added a member"
        );
        assert_eq!(
            alt.status, 201,
            "subscription-data grants a registration write: {:?}",
            alt.http.content
        );
        assert_eq!(first.status, 201);
        assert_eq!(again.status, 204, "a repeated PUT replaces the one record");
        assert_eq!(json_of(&stored), smsf);
        assert_eq!(udm_delete.status, 204, "the UDM deletes its record");
    }

    /// #2079: the NF-type half of the gate, over the verified identity alone
    /// (`owner_binding::verified_consumer_id` and the certificate's RFC 9310 NF
    /// types). On the direct path the certificate decides: a PCF, NEF or AUSF
    /// certificate is refused even with a UDM-scoped token, a UDM certificate is
    /// admitted. Behind an SCP the token decides. With neither a token nor a
    /// typed certificate only `dev` admits. A certificate and token naming
    /// different NF instances are refused. GETs are never gated.
    ///
    /// REVERT-VERIFIED: with the certificate-type check removed, the PCF
    /// certificate carrying a UDM-scoped token is admitted and the
    /// `direct certificate decides` assertion fails.
    #[test]
    fn the_verified_nf_type_decides_a_udm_context_write_2079() {
        use nextgcore_sbi::resource_scope::NUDR_DR_REGISTRATIONS_WRITE as WRITE;
        let path =
            "/nudr-dr/v2/subscription-data/imsi-001010000020792/context-data/amf-3gpp-access";
        let req = |method: &str, cert: Option<(&str, &[&str])>, token: Option<(&str, &str)>| {
            let mut r = ctx_write_2079(method, path, None);
            if method == "GET" {
                r = SbiRequest::get(path);
            }
            if let Some((id, types)) = cert {
                r.peer_cert_nf_instance_id = Some(id.to_string());
                r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            }
            if let Some((sub, scope)) = token {
                r.oauth2_subject = Some(sub.to_string());
                r.oauth2_scope = Some(scope.to_string());
            }
            r
        };
        let udm_scope = format!("nudr-dr {WRITE}");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let refused = |r: &SbiRequest, production: bool| {
            rt.block_on(udm_context_write_refusal(r, production))
                .map(|resp| resp.status)
        };
        let (pcf, udm, scp) = ("pcf-0001", "udm-0001", "scp-0001");
        // #2113: a token-identified UDM is the NRF's to vouch for (here seeded).
        nextgcore_sbi::owner_binding::seed_nf_type_for_test(udm, nextgcore_sbi::NfType::Udm);
        for t in ["PCF", "NEF", "AUSF", "AMF", "SMF"] {
            assert_eq!(
                refused(
                    &req("PUT", Some((pcf, &[t])), Some((pcf, &udm_scope))),
                    true
                ),
                Some(403),
                "direct certificate decides: a {t} certificate with a UDM-scoped token"
            );
            assert_eq!(
                refused(&req("PUT", Some((pcf, &[t])), None), false),
                Some(403),
                "{t} certificate, no token"
            );
        }
        assert_eq!(
            refused(&req("PUT", Some((udm, &["UDM"])), None), true),
            None
        );
        assert_eq!(
            refused(
                &req("PUT", Some((udm, &["udm"])), Some((udm, &udm_scope))),
                true
            ),
            None
        );
        // Behind an SCP: the relayed consumer's token.
        assert_eq!(
            refused(
                &req("PUT", Some((scp, &["SCP"])), Some((pcf, "nudr-dr"))),
                true
            ),
            Some(403),
            "a PCF's token relayed by an SCP"
        );
        assert_eq!(
            refused(
                &req("PATCH", Some((scp, &["SCP"])), Some((udm, &udm_scope))),
                true
            ),
            None,
            "a UDM's token relayed by an SCP"
        );
        assert_eq!(
            refused(&req("PUT", Some((scp, &["SCP"])), None), true),
            Some(403),
            "an SCP with no token proves no UDM"
        );
        // #2113: a certificate naming a relay type plus another type is that
        // consumer's, not a relay's: it cannot pass a UDM's token through, and
        // it is typed by its certificate.
        assert_eq!(
            refused(
                &req("PUT", Some((scp, &["SCP", "PCF"])), Some((udm, &udm_scope))),
                true
            ),
            Some(403),
            "an [SCP, PCF] certificate relaying a UDM's token"
        );
        assert_eq!(
            refused(
                &req("PUT", Some((udm, &["PCF", "SCP"])), Some((udm, &udm_scope))),
                true
            ),
            Some(403),
            "a [PCF, SCP] certificate carrying the UDM's own id and token"
        );
        assert_eq!(
            refused(
                &req(
                    "PUT",
                    Some((scp, &["SCP", "SEPP"])),
                    Some((udm, &udm_scope))
                ),
                true
            ),
            None,
            "a relay-only certificate lets the UDM's token decide"
        );
        // No token and no typed certificate: production refuses, dev admits.
        assert_eq!(refused(&req("PUT", None, None), true), Some(403));
        assert_eq!(
            refused(&req("PUT", Some((udm, &[])), None), true),
            Some(403)
        );
        assert_eq!(refused(&req("PUT", None, None), false), None);
        // A token without the scope, even on a typeless path.
        assert_eq!(
            refused(&req("DELETE", None, Some((pcf, "nudr-dr"))), false),
            Some(403)
        );
        // Certificate and token naming different instances.
        assert_eq!(
            refused(
                &req("PUT", Some((udm, &["UDM"])), Some((pcf, &udm_scope))),
                true
            ),
            Some(403)
        );
        // GETs stay on the service scope.
        assert_eq!(
            refused(
                &req("GET", Some((pcf, &["PCF"])), Some((pcf, "nudr-dr"))),
                true
            ),
            None
        );
        assert_eq!(refused(&req("GET", None, None), true), None);
        // Resources outside the table are not gated here.
        let mut pp =
            SbiRequest::patch("/nudr-dr/v2/subscription-data/imsi-001010000020792/pp-data");
        pp.peer_cert_nf_types = vec!["PCF".to_string()];
        assert_eq!(refused(&pp, true), None);
    }

    /// #2079: through the real handler (`udr_sbi_request_handler`) a PCF
    /// certificate's amf-3gpp-access PUT is refused before any side effect: no
    /// record, no UE context, and no data-change notification to a subscriber
    /// of that resource; and it returns before the operation counter
    /// (`metrics::classify`) runs. The refusal is decided before the
    /// handler's first `.await`, so it completes on its first poll and a
    /// dropped (cancelled) refused request cannot have started anything. The
    /// UDM's PUT, on the same path, is stored and notified (the control).
    ///
    /// REVERT-VERIFIED: with the gate call removed from `udr_sbi_request_handler`,
    /// the PCF's PUT is stored and notified, and the `refused before routing`
    /// assertion fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_write_has_no_side_effect_2079() {
        use std::future::Future;
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;
        let supi = "imsi-001010000020793";
        let path = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access");
        let resp = client
            .post_json(
                "/nudr-dr/v2/subscription-data/subs-to-notify",
                &json!({
                    "ueId": supi,
                    "callbackReference": format!("http://127.0.0.1:{cb_port}/cb/2079"),
                    "monitoredResourceUris": [format!("http://udr{path}")]
                }),
            )
            .await
            .expect("subscribe");
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);
        let amf = |id: &str| {
            json!({
                "amfInstanceId": id,
                "deregCallbackUri": "http://amf.example.org/dereg",
                "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "cafe00"},
                "ratType": "NR"
            })
        };
        let as_peer = |id: &str, t: &str| {
            let mut r = ctx_write_2079("PUT", &path, Some(amf(id)));
            r.peer_cert_nf_instance_id = Some(format!("{id}-instance"));
            r.peer_cert_nf_types = vec![t.to_string()];
            r
        };
        let ue_known = || {
            nextgcore_udrd::context::udr_self()
                .read()
                .map(|c| c.ue_find(supi).is_some())
                .unwrap_or(false)
        };
        let ue_before = ue_known();

        let mut fut = Box::pin(udr_sbi_request_handler(as_peer("amf-pcf", "PCF")));
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let first_poll = fut.as_mut().poll(&mut cx);
        let refused = match first_poll {
            std::task::Poll::Ready(r) => r,
            std::task::Poll::Pending => panic!("a refusal completes on its first poll"),
        };
        // A refused request dropped before it is polled (a cancelled one) leaves
        // nothing either.
        drop(udr_sbi_request_handler(as_peer("amf-pcf-2", "PCF")));
        let stray = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
        let stored_after_refusal = AmfAccessSlot::ThreeGpp.get(supi);
        let ue_after = ue_known();

        let accepted = udr_sbi_request_handler(as_peer("amf-udm", "UDM")).await;
        let (notified, _) = recv_notification(&mut rx).await;
        udr.stop().await.expect("stop");
        listener.stop().await.expect("stop");

        assert_eq!(
            refused.status, 403,
            "refused before routing: {:?}",
            refused.http.content
        );
        assert!(stray.is_err(), "a refused write notifies nobody: {stray:?}");
        assert_eq!(stored_after_refusal, None, "a refused write stores nothing");
        assert_eq!(ue_after, ue_before, "a refused write adds no UE context");
        assert_eq!(accepted.status, 201, "{:?}", accepted.http.content);
        assert!(notified.contains("/cb/2079"), "{notified}");
        assert_eq!(
            AmfAccessSlot::ThreeGpp
                .get(supi)
                .map(|d| d["amfInstanceId"].clone()),
            Some(json!("amf-udm"))
        );
    }

    /// #2113 (R32 m2 on #2108): udrd's real gate, through the real handler
    /// (`udr_sbi_request_handler`), not a mock UDR. A certificate naming SCP
    /// plus PCF that passes on a UDM's token is the PCF's, not a relay's: the
    /// amf-3gpp-access PUT is refused 403 and nothing is stored, and the same
    /// certificate carrying the UDM's own id is refused as well (its
    /// certificate names no UDM). A relay-only SCP certificate passing the same
    /// token stores it (the control).
    ///
    /// REVERT-VERIFIED: with `owner_binding::is_relay_certificate` back to "any
    /// type is a relay type", the `[SCP, PCF]` PUT is stored and the
    /// `mixed certificate refused` assertion fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_mixed_relay_certificate_writes_no_udm_context_data_2113() {
        use nextgcore_sbi::resource_scope::NUDR_DR_REGISTRATIONS_WRITE as WRITE;
        let udm = "dddddddd-2113-4000-8000-0000000000d1";
        let scp = "eeeeeeee-2113-4000-8000-0000000000e1";
        nextgcore_sbi::owner_binding::seed_nf_type_for_test(udm, nextgcore_sbi::NfType::Udm);
        let supi = "imsi-001010000021131";
        let path = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access");
        let put = |amf: &str, cert: &str, types: &[&str]| {
            let mut r = ctx_write_2079(
                "PUT",
                &path,
                Some(json!({
                    "amfInstanceId": amf,
                    "deregCallbackUri": "http://amf.example.org/dereg",
                    "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "cafe00"},
                    "ratType": "NR"
                })),
            );
            r.peer_cert_nf_instance_id = Some(cert.to_string());
            r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            r.oauth2_subject = Some(udm.to_string());
            r.oauth2_scope = Some(format!("nudr-dr {WRITE}"));
            r
        };
        let mixed = udr_sbi_request_handler(put("amf-mixed", scp, &["SCP", "PCF"])).await;
        let own_id = udr_sbi_request_handler(put("amf-own", udm, &["PCF", "SCP"])).await;
        let stored_after_refusals = AmfAccessSlot::ThreeGpp.get(supi);
        let relayed = udr_sbi_request_handler(put("amf-relayed", scp, &["SCP"])).await;

        assert_eq!(
            mixed.status, 403,
            "mixed certificate refused: {:?}",
            mixed.http.content
        );
        assert_eq!(own_id.status, 403, "{:?}", own_id.http.content);
        assert_eq!(
            stored_after_refusals, None,
            "a refused write stores nothing"
        );
        assert_eq!(relayed.status, 201, "{:?}", relayed.http.content);
        assert_eq!(
            AmfAccessSlot::ThreeGpp
                .get(supi)
                .map(|d| d["amfInstanceId"].clone()),
            Some(json!("amf-relayed"))
        );
    }

    /// #2123 (R41 M1, M2), end to end with no seeded cache: a UDM reaching
    /// udrd through an SCP with its token is typed by a stand-in NRF that
    /// behaves as nrfd does -- 400 for a discovery without `requester-nf-type`
    /// (TS 29.510 mandatory, nrfd main.rs), and a profile hidden from a
    /// requester its `allowedNfTypes` leaves out (nrfd nnrf_handler.rs). The UDM
    /// profile carries UDR, as udmd's default now does. udrd registers its self
    /// instance as it does at startup (`register_self_instance`), so the lookup
    /// names UDR, the UDM's write is stored, and an AMF's token with the same
    /// scope is refused.
    ///
    /// REVERT-VERIFIED: with neither `register_self_instance` here nor the sbi
    /// `own_nf_type` fallback, the lookup carries no `requester-nf-type`, the
    /// NRF answers 400 and the `UDM via the SCP` assertion fails (403); with
    /// UDR dropped from the stand-in profile's allowedNfTypes, it fails the
    /// same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_udm_via_the_scp_is_typed_by_the_nrf_2123() {
        use nextgcore_sbi::resource_scope::NUDR_DR_REGISTRATIONS_WRITE as WRITE;
        const UDM: &str = "dddddddd-2123-4000-8000-0000000000d7";
        const AMF: &str = "aaaaaaaa-2123-4000-8000-0000000000a7";
        const SCP: &str = "eeeeeeee-2123-4000-8000-0000000000e7";
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let requesters: Arc<std::sync::Mutex<Vec<Option<String>>>> = Arc::default();
        let seen = requesters.clone();
        let (nrf, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let seen = seen.clone();
                async move {
                    let param = |k: &str| req.http.params.get(k).cloned();
                    let requester = param("requester-nf-type");
                    seen.lock().unwrap().push(requester.clone());
                    let Some(requester) = requester else {
                        return nextgcore_sbi::server::send_error(
                            400,
                            "Bad Request",
                            "requester-nf-type is mandatory",
                            Some("MANDATORY_QUERY_PARAM_MISSING"),
                        );
                    };
                    let profiles = [
                        (UDM, "UDM", vec!["AMF", "SMF", "AUSF", "PCF", "SCP", "UDR"]),
                        (AMF, "AMF", vec!["SMF", "UDM", "UDR", "SCP"]),
                    ];
                    let list: Vec<_> = profiles
                        .iter()
                        .filter(|(id, ty, allowed)| {
                            param("target-nf-instance-id").as_deref() == Some(*id)
                                && param("target-nf-type").as_deref() == Some(*ty)
                                && allowed.contains(&requester.as_str())
                        })
                        .map(|(id, ty, allowed)| {
                            json!({"nfInstanceId": id, "nfType": ty, "allowedNfTypes": allowed})
                        })
                        .collect();
                    SbiResponse::with_status(200)
                        .with_json_body(&json!({ "nfInstances": list }))
                        .expect("json")
                }
            })
            .await;
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{}", addr.port()))
            .await;
        register_self_instance().await;

        let supi = "imsi-001010000021237";
        let path = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access");
        let put = |sub: &str, amf: &str| {
            let mut r = ctx_write_2079(
                "PUT",
                &path,
                Some(json!({
                    "amfInstanceId": amf,
                    "deregCallbackUri": "http://amf.example.org/dereg",
                    "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "cafe00"},
                    "ratType": "NR"
                })),
            );
            r.peer_cert_nf_instance_id = Some(SCP.to_string());
            r.peer_cert_nf_types = vec!["SCP".to_string()];
            r.oauth2_subject = Some(sub.to_string());
            r.oauth2_scope = Some(format!("nudr-dr {WRITE}"));
            r
        };
        let by_amf = udr_sbi_request_handler(put(AMF, "amf-by-amf")).await;
        let stored_after_amf = AmfAccessSlot::ThreeGpp.get(supi);
        let by_udm = udr_sbi_request_handler(put(UDM, "amf-by-udm")).await;
        nrf.stop().await.ok();
        let requesters = requesters.lock().unwrap().clone();

        assert_eq!(
            by_udm.status, 201,
            "UDM via the SCP: {:?} (NRF saw requesters {requesters:?})",
            by_udm.http.content
        );
        assert_eq!(by_amf.status, 403, "{:?}", by_amf.http.content);
        assert_eq!(stored_after_amf, None, "the AMF's write stored nothing");
        assert_eq!(
            AmfAccessSlot::ThreeGpp
                .get(supi)
                .map(|d| d["amfInstanceId"].clone()),
            Some(json!("amf-by-udm"))
        );
        assert!(
            !requesters.is_empty() && requesters.iter().all(|r| r.as_deref() == Some("UDR")),
            "every lookup names the UDR: {requesters:?}"
        );
    }

    /// #2123 (R41 M1): udrd's startup registers its self instance as a UDR.
    ///
    /// REVERT-VERIFIED: with `register_self_instance` empty, this fails.
    #[tokio::test]
    async fn udrd_registers_its_self_instance_as_a_udr_2123() {
        register_self_instance().await;
        let me = nextgcore_sbi::context::global_context()
            .get_self_instance()
            .await
            .expect("a self instance");
        assert_eq!(me.nf_type, nextgcore_sbi::types::NfType::Udr);
        assert_eq!(
            me.id,
            nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Udr)
        );
    }

    /// #85's producers need these: the Parameter Provision documents and the
    /// identity translation the UDM reads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_pp_data_and_identity_data() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008704";

        // pp-data: PATCH provisions (an absent document starts empty), GET reads.
        let pp = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data");
        let resp = client.get(&pp).await.expect("GET pp-data");
        assert_eq!(resp.status, 404, "nothing provisioned yet");
        let resp = client
            .patch_json(
                &pp,
                &json!({"expectedUeBehaviourParameters": {"stationaryIndication": "STATIONARY"}}),
            )
            .await
            .expect("PATCH pp-data");
        assert_eq!(
            resp.status, 204,
            "PATCH provisions: {:?}",
            resp.http.content
        );
        let resp = client.get(&pp).await.expect("GET pp-data after");
        assert_eq!(resp.status, 200);
        assert_eq!(
            json_of(&resp)["expectedUeBehaviourParameters"]["stationaryIndication"],
            "STATIONARY"
        );

        // pp-data-store: one document per AF instance.
        let entry = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data-store/af-1");
        let doc =
            json!({"communicationCharacteristics": {"ppSubsRegTimer": {"subsRegTimer": 3600}}});
        let resp = client.put_json(&entry, &doc).await.expect("PUT entry");
        assert_eq!(resp.status, 201);
        let resp = client.get(&entry).await.expect("GET entry");
        assert_eq!(json_of(&resp), doc);
        let resp = client
            .get(&format!(
                "/nudr-dr/v2/subscription-data/{supi}/pp-data-store"
            ))
            .await
            .expect("GET entries");
        assert_eq!(json_of(&resp), json!([doc]));

        // identity-data, BOTH directions, against the subscriber-identity mirror
        // (no MongoDB): the GPSI -> SUPI direction is what a NEF needs and what
        // the UDM's id-translation-result reads.
        //
        // The DbiTestStore guard is mandatory rather than a nicety: the mirror is
        // process-global and its `disable()` is a kill switch, so provisioning it
        // without the lock races every other test that has it enabled -- which is
        // exactly the flake this comment replaced.
        let _dbi = DbiTestStore::enable().await;
        let gpsi_digits = "491721075400";
        nextgcore_dbi::test_store::provision_subscriber(supi, &[gpsi_digits]);
        for id in [supi.to_string(), format!("msisdn-{gpsi_digits}")] {
            let resp = client
                .get(&format!("/nudr-dr/v2/subscription-data/{id}/identity-data"))
                .await
                .expect("GET identity-data");
            assert_eq!(
                resp.status, 200,
                "identity-data must resolve {id}: {:?}",
                resp.http.content
            );
            let doc = json_of(&resp);
            assert_eq!(doc["supiList"], json!([supi]), "supiList for {id}");
            assert_eq!(
                doc["gpsiList"],
                json!([format!("msisdn-{gpsi_digits}")]),
                "gpsiList for {id}"
            );
        }
        // An identifier no subscriber holds is a 404, never a guessed SUPI.
        let resp = client
            .get("/nudr-dr/v2/subscription-data/msisdn-000000000000/identity-data")
            .await
            .expect("GET unknown identity-data");
        assert_eq!(resp.status, 404);

        udr.stop().await.expect("stop");
    }

    /// **nextgsim#480**: identity-data answers for an `extid-` GPSI, the key a
    /// NEF's T8 `externalId` reaches the UDR with (via the UDM's
    /// id-translation-result), and lists the External Identifier among the GPSIs
    /// when asked by SUPI (the direction the NEF's UE ID retrieval reads). The
    /// mirror's `extid` lookup is the Mongo `{extid: <value>}` query.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_identity_data_by_external_id() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let _dbi = DbiTestStore::enable().await;
        let supi = "imsi-001019900004801";
        let ext = "ue4801@fl.nextg";
        nextgcore_dbi::test_store::provision_subscriber_with_external_ids(
            supi,
            &["491721074801"],
            &[ext],
        );
        let gpsis = json!(["msisdn-491721074801", format!("extid-{ext}")]);
        for id in [supi.to_string(), format!("extid-{ext}")] {
            let resp = client
                .get(&format!("/nudr-dr/v2/subscription-data/{id}/identity-data"))
                .await
                .expect("GET identity-data");
            assert_eq!(
                resp.status, 200,
                "identity-data must resolve {id}: {:?}",
                resp.http.content
            );
            let doc = json_of(&resp);
            assert_eq!(doc["supiList"], json!([supi]), "supiList for {id}");
            assert_eq!(doc["gpsiList"], gpsis, "gpsiList for {id}");
        }
        // am-data's gpsis carry it too.
        let resp = client
            .get(&format!(
                "/nudr-dr/v2/subscription-data/{supi}/provisioned-data/am-data"
            ))
            .await
            .expect("GET am-data");
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        assert_eq!(json_of(&resp)["gpsis"], gpsis);
        // An External Identifier nobody holds is a 404, and an MSISDN's digits
        // under extid- match nothing: the lookup is by the extid field only.
        for id in ["extid-nobody@fl.nextg", "extid-491721074801"] {
            let resp = client
                .get(&format!("/nudr-dr/v2/subscription-data/{id}/identity-data"))
                .await
                .expect("GET unknown identity-data");
            assert_eq!(resp.status, 404, "{id}");
        }
        udr.stop().await.expect("stop");
    }

    /// A `{ueId}` whose type prefix is not one the subscriber store is keyed by is
    /// a 400 on every resource that looks the UE up, while each supported type
    /// still resolves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_ue_id_type_is_rejected() {
        let (udr, client) = start_udr().await;
        let _dbi = DbiTestStore::enable().await;
        let supi = "imsi-001019900004901";
        let ext = "ue4901@fl.nextg";
        nextgcore_dbi::test_store::provision_subscriber_with_external_ids(
            supi,
            &["491721074901"],
            &[ext],
        );

        // Each supported type passes validation and resolves the subscriber;
        // `nai-` is supported but this one is not provisioned.
        for id in [
            supi.to_string(),
            "msisdn-491721074901".to_string(),
            format!("extid-{ext}"),
        ] {
            let resp = client
                .get(&format!("/nudr-dr/v2/subscription-data/{id}/identity-data"))
                .await
                .expect("GET identity-data");
            assert_eq!(resp.status, 200, "{id}: {:?}", resp.http.content);
        }
        let resp = client
            .get("/nudr-dr/v2/subscription-data/nai-nobody@fl.nextg/identity-data")
            .await
            .expect("GET identity-data");
        assert_eq!(resp.status, 404, "nai-: {:?}", resp.http.content);

        for id in ["$x-1", "a.b-1", "-001010000000001", "foo-1"] {
            for path in [
                format!("/nudr-dr/v2/subscription-data/{id}/identity-data"),
                format!("/nudr-dr/v2/policy-data/ues/{id}/sm-data"),
                format!("/nudr-dr/v2/policy-data/ues/{id}/ue-policy-set"),
            ] {
                let resp = client.get(&path).await.expect("GET");
                assert_eq!(resp.status, 400, "{path}: {:?}", resp.http.content);
                assert_eq!(json_of(&resp)["cause"], "MANDATORY_IE_INCORRECT", "{path}");
            }
            let resp = client
                .put_json(
                    &format!(
                        "/nudr-dr/v2/subscription-data/{id}/authentication-data/authentication-subscription"
                    ),
                    &json!({
                        "authenticationMethod": "5G_AKA",
                        "encPermanentKey": "465b5ce8b199b49faa5f0a2ee238a6bc"
                    }),
                )
                .await
                .expect("PUT");
            assert_eq!(resp.status, 400, "PUT {id}: {:?}", resp.http.content);
        }
        udr.stop().await.expect("stop");
    }

    /// #87 gap 3: policy-data PATCH, the snssai/dnn filter, the documents that
    /// were absent, and a subs-to-notify round trip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_policy_data_patch_filter_and_notify() {
        // #1666: the notification client follows the SBI profile, and this
        // drives it at a loopback plaintext peer, i.e. a dev deployment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008705";
        let ues = |r: &str| format!("/nudr-dr/v2/policy-data/ues/{supi}/{r}");

        // --- subs-to-notify: the tree a PCF subscribes on (was absent) -------
        let cb_uri = format!("http://127.0.0.1:{cb_port}/cb/policy-change");
        let resp = client
            .post_json(
                "/nudr-dr/v2/policy-data/subs-to-notify",
                &json!({"notificationUri": cb_uri, "monitoredResourceUris": [ues("am-data")]}),
            )
            .await
            .expect("POST policy sub");
        assert_eq!(resp.status, 201, "policy subs-to-notify must exist");
        let sub_loc = resp.http.get_header("Location").expect("Location").clone();
        assert!(sub_loc.contains("/policy-data/subs-to-notify/"));
        // Mandatory members are enforced.
        let resp = client
            .post_json(
                "/nudr-dr/v2/policy-data/subs-to-notify",
                &json!({"notificationUri": cb_uri}),
            )
            .await
            .expect("POST bad sub");
        assert_eq!(resp.status, 400);

        // --- PATCH on am-data (was 405) + the notification -------------------
        let resp = client
            .patch_json(&ues("am-data"), &json!({"praInfos": {}}))
            .await
            .expect("PATCH am-data");
        assert_eq!(resp.status, 204, "am-data PATCH must be accepted");
        let (path, body) = recv_notification(&mut rx).await;
        assert!(path.contains("/cb/policy-change"), "notified at {path}");
        assert_eq!(body["ueId"], supi);
        assert_eq!(
            body["reportId"],
            ues("am-data"),
            "the notification names the changed resource: {body}"
        );

        // --- ue-policy-set PATCH (was 405) -----------------------------------
        let resp = client
            .patch_json(&ues("ue-policy-set"), &json!({"subscPolicySections": {}}))
            .await
            .expect("PATCH ue-policy-set");
        assert_eq!(resp.status, 204);

        // --- sm-data: PATCH, then the snssai/dnn filter ----------------------
        let sm_doc = json!({
            "smPolicySnssaiData": {
                "01-000001": {
                    "snssai": {"sst": 1, "sd": "000001"},
                    "smPolicyDnnData": {
                        "internet": {"dnn": "internet"},
                        "ims": {"dnn": "ims"}
                    }
                },
                "02": {
                    "snssai": {"sst": 2},
                    "smPolicyDnnData": {"iot": {"dnn": "iot"}}
                }
            }
        });
        let resp = client
            .put_json(&ues("sm-data"), &sm_doc)
            .await
            .expect("PUT sm-data");
        assert_eq!(resp.status, 201);

        // Unfiltered: the whole document (unchanged behaviour).
        let resp = client.get(&ues("sm-data")).await.expect("GET sm-data");
        assert_eq!(json_of(&resp), sm_doc);

        // Filtered by snssai: only that slice. The two provisioned slices differ,
        // so returning the whole document would fail this.
        // The JSON Snssai is percent-encoded, as a query value carrying `{`/`"`
        // must be (RFC 3986 §3.4) -- the UDR pct-decodes it.
        let resp = client
            .get(&format!("{}?snssai=%7B%22sst%22%3A2%7D", ues("sm-data")))
            .await
            .expect("GET sm-data sst=2");
        assert_eq!(resp.status, 200);
        let doc = json_of(&resp);
        assert_eq!(
            doc["smPolicySnssaiData"].as_object().map(|o| o.len()),
            Some(1),
            "exactly the requested slice: {doc}"
        );
        assert!(doc["smPolicySnssaiData"]["02"].is_object());

        // Filtered by snssai + dnn: only that DNN within that slice.
        let resp = client
            .get(&format!(
                "{}?snssai=%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D&dnn=ims",
                ues("sm-data")
            ))
            .await
            .expect("GET sm-data filtered");
        assert_eq!(resp.status, 200);
        let doc = json_of(&resp);
        let dnns = doc["smPolicySnssaiData"]["01-000001"]["smPolicyDnnData"]
            .as_object()
            .expect("smPolicyDnnData")
            .clone();
        assert_eq!(dnns.len(), 1, "only the requested DNN: {doc}");
        assert!(dnns.contains_key("ims"));

        // A filter that selects nothing is a 404, not an empty SmPolicyData a
        // PCF would install as "no policy applies".
        let resp = client
            .get(&format!("{}?snssai=%7B%22sst%22%3A9%7D", ues("sm-data")))
            .await
            .expect("GET sm-data sst=9");
        assert_eq!(resp.status, 404);

        // --- the documents that had no route at all --------------------------
        let usage_mon = format!("{}/um-1", ues("sm-data"));
        let resp = client
            .put_json(
                &usage_mon,
                &json!({"limitId": "um-1", "umLevel": "SESSION_LEVEL"}),
            )
            .await
            .expect("PUT usageMonId");
        assert_eq!(resp.status, 201, "sm-data/{{usageMonId}} must be routed");
        let resp = client.get(&usage_mon).await.expect("GET usageMonId");
        assert_eq!(json_of(&resp)["limitId"], "um-1");

        let plmn = "/nudr-dr/v2/policy-data/plmns/00101/ue-policy-set";
        let resp = client
            .put_json(plmn, &json!({"upsis": ["upsi-1"]}))
            .await
            .expect("PUT plmn ue-policy-set");
        assert_eq!(resp.status, 201);
        let resp = client.get(plmn).await.expect("GET plmn ue-policy-set");
        assert_eq!(json_of(&resp)["upsis"], json!(["upsi-1"]));
        let resp = client
            .get("/nudr-dr/v2/policy-data/plmns/nope/ue-policy-set")
            .await
            .expect("GET bad plmn");
        assert_eq!(resp.status, 400, "a malformed plmnId is refused");

        let sponsor = "/nudr-dr/v2/policy-data/sponsor-connectivity-data/sponsor-1";
        let resp = client
            .put_json(sponsor, &json!({"aspIds": ["asp-1"]}))
            .await
            .expect("PUT sponsor");
        assert_eq!(resp.status, 201);
        let resp = client.get(sponsor).await.expect("GET sponsor");
        assert_eq!(json_of(&resp)["aspIds"], json!(["asp-1"]));
        let resp = client
            .put_json(sponsor, &json!({}))
            .await
            .expect("PUT sponsor without aspIds");
        assert_eq!(resp.status, 400);

        let bdt = "/nudr-dr/v2/policy-data/bdt-data/bdt-1";
        let resp = client
            .put_json(
                bdt,
                &json!({"bdtRefId": "bdt-1", "aspId": "asp-1", "transPolicy": {"ratingGroup": 1}}),
            )
            .await
            .expect("PUT bdt-data");
        assert_eq!(resp.status, 201);
        // The URI owns the id.
        let resp = client
            .put_json(
                bdt,
                &json!({"bdtRefId": "other", "aspId": "asp-1", "transPolicy": {"ratingGroup": 1}}),
            )
            .await
            .expect("PUT bdt-data mismatched id");
        assert_eq!(resp.status, 400);
        let resp = client
            .get("/nudr-dr/v2/policy-data/bdt-data")
            .await
            .expect("GET bdt-data collection");
        assert_eq!(resp.status, 200);
        assert_eq!(json_of(&resp).as_array().map(|a| a.len()), Some(1));

        // Clean up the subscription so it cannot notify later tests.
        let sub_id = sub_loc.rsplit('/').next().expect("sub id");
        let resp = client
            .delete(&format!("/nudr-dr/v2/policy-data/subs-to-notify/{sub_id}"))
            .await
            .expect("DELETE sub");
        assert_eq!(resp.status, 204);

        drop(listener);
        udr.stop().await.expect("stop");
    }

    /// The `200 {}` vs `404` question the issue asks to settle explicitly: KEPT
    /// as `200 {}` for `am-data` and `ue-policy-set`, because those documents'
    /// members are all optional, so "this subscriber has no AM policy data" is a
    /// representable answer — while a `404` would also be the answer for "no such
    /// subscriber", collapsing two facts a PCF may want to distinguish. `sm-data`
    /// keeps its `404` for an unknown subscriber, since it has a derived default
    /// and absence there means the subscriber itself is missing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_unprovisioned_policy_documents_keep_200_empty() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008706";
        // #1534: a store that answers, and holds no such subscriber
        // (SubscriberNotFound). Without one the reads are a store outage (500).
        let _dbi = DbiTestStore::enable().await;
        nextgcore_dbi::test_store::provision_subscriber_document(
            "imsi-001019900018706",
            nextgcore_dbi::mongodb::bson::doc! { "imsi": "001019900018706" },
        );
        for resource in ["am-data", "ue-policy-set"] {
            let resp = client
                .get(&format!("/nudr-dr/v2/policy-data/ues/{supi}/{resource}"))
                .await
                .expect("GET");
            assert_eq!(
                resp.status, 200,
                "{resource} on an unprovisioned subscriber"
            );
            assert_eq!(json_of(&resp), json!({}), "{resource} empty document");
        }
        let resp = client
            .get(&format!("/nudr-dr/v2/policy-data/ues/{supi}/sm-data"))
            .await
            .expect("GET sm-data");
        assert_eq!(
            resp.status, 404,
            "sm-data has a derived default, so absence means no subscriber"
        );
        assert_eq!(json_of(&resp)["cause"], "USER_NOT_FOUND");
        udr.stop().await.expect("stop");
    }

    /// #87 gap 4: the five application-data datasets that answered
    /// "Unknown application-data resource".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_application_data_remaining_datasets() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        // Spec spellings (TS 29.519 §5.6): the issue's informal "af-qos-data" /
        // "eas-deployment-data" do not appear in the OpenAPI.
        let datasets: [(&str, &str, serde_json::Value); 6] = [
            (
                "bdtPolicyData",
                "bdt-1",
                json!({"bdtRefId": "bdt-1", "aspId": "asp-1"}),
            ),
            (
                "iptvConfigData",
                "cfg-1",
                json!({"afAppId": "app-1", "multiAccCtrls": {}, "supi": "imsi-1"}),
            ),
            ("serviceParamData", "svc-1", json!({"afAppId": "app-1"})),
            ("am-influence-data", "ami-1", json!({"afAppId": "app-1"})),
            ("af-qos-data-sets", "qos-1", json!({"afQosDataId": "qos-1"})),
            ("eas-deploy-data", "eas-1", json!({"dnn": "internet"})),
        ];
        for (collection, id, doc) in datasets {
            let path = format!("/nudr-dr/v2/application-data/{collection}/{id}");
            let resp = client.get(&path).await.expect("GET before");
            assert_eq!(
                resp.status, 404,
                "{collection} unprovisioned is DATA_NOT_FOUND, not an unknown resource"
            );
            assert_eq!(json_of(&resp)["cause"], "DATA_NOT_FOUND", "{collection}");

            let resp = client.put_json(&path, &doc).await.expect("PUT");
            assert_eq!(
                resp.status, 201,
                "{collection} PUT: {:?}",
                resp.http.content
            );
            let resp = client.get(&path).await.expect("GET after");
            assert_eq!(resp.status, 200);
            assert_eq!(json_of(&resp), doc, "{collection} round-trip");

            let resp = client
                .get(&format!("/nudr-dr/v2/application-data/{collection}"))
                .await
                .expect("GET collection");
            assert_eq!(resp.status, 200);
            assert_eq!(
                json_of(&resp),
                json!([doc]),
                "{collection} collection lists it"
            );
            let resp = client.delete(&path).await.expect("DELETE");
            assert_eq!(resp.status, 204);
        }
        // Mandatory members are enforced where the schema names them.
        let resp = client
            .put_json(
                "/nudr-dr/v2/application-data/iptvConfigData/cfg-2",
                &json!({"afAppId": "app-1"}),
            )
            .await
            .expect("PUT iptv without multiAccCtrls");
        assert_eq!(resp.status, 400);
        udr.stop().await.expect("stop");
    }

    /// #87 gap 5: `Nudr_GroupIDmap` was not routed at all, so the router's
    /// unknown-service 404 was the only answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_group_id_map_service() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        set_group_id_map(vec![
            GroupIdMapYaml {
                supi_prefix: String::new(),
                nf_group_ids: [("UDM".to_string(), "udm-grp-default".to_string())]
                    .into_iter()
                    .collect(),
            },
            GroupIdMapYaml {
                supi_prefix: "imsi-00101".to_string(),
                nf_group_ids: [
                    ("UDM".to_string(), "udm-grp-1".to_string()),
                    ("AUSF".to_string(), "ausf-grp-1".to_string()),
                ]
                .into_iter()
                .collect(),
            },
        ]);

        // subscriberId is mandatory, as is nf-type.
        let resp = client
            .get("/nudr-group-id-map/v1/nf-group-ids?nf-type=UDM")
            .await
            .expect("GET without subscriberId");
        assert_eq!(resp.status, 400);
        let resp = client
            .get("/nudr-group-id-map/v1/nf-group-ids?subscriberId=imsi-001010000000001")
            .await
            .expect("GET without nf-type");
        assert_eq!(resp.status, 400);

        // The longest matching prefix wins over the catch-all.
        let resp = client
            .get("/nudr-group-id-map/v1/nf-group-ids?nf-type=UDM,AUSF&subscriberId=imsi-001010000000001")
            .await
            .expect("GET nf-group-ids");
        assert_eq!(
            resp.status, 200,
            "the service must be reachable: {:?}",
            resp.http.content
        );
        assert_eq!(
            json_of(&resp),
            json!({"UDM": "udm-grp-1", "AUSF": "ausf-grp-1"})
        );

        // nf-type filters the map.
        let resp = client
            .get(
                "/nudr-group-id-map/v1/nf-group-ids?nf-type=AUSF&subscriberId=imsi-001010000000001",
            )
            .await
            .expect("GET filtered");
        assert_eq!(json_of(&resp), json!({"AUSF": "ausf-grp-1"}));

        // A subscriber outside every range, with no catch-all, is a 404.
        set_group_id_map(vec![GroupIdMapYaml {
            supi_prefix: "imsi-99999".to_string(),
            nf_group_ids: [("UDM".to_string(), "udm-grp-x".to_string())]
                .into_iter()
                .collect(),
        }]);
        let resp = client
            .get("/nudr-group-id-map/v1/nf-group-ids?nf-type=UDM&subscriberId=imsi-001010000000001")
            .await
            .expect("GET unmatched");
        assert_eq!(resp.status, 404);

        // Subscriptions CRUD.
        let resp = client
            .post_json(
                "/nudr-group-id-map/v1/nf-group-ids/subscriptions",
                &json!({"callbackReference": "http://nf/cb", "nfTypes": ["UDM"]}),
            )
            .await
            .expect("POST sub");
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("Location").expect("Location").clone();
        let sub_id = loc.rsplit('/').next().expect("sub id").to_string();
        let resp = client
            .get(&format!(
                "/nudr-group-id-map/v1/nf-group-ids/subscriptions/{sub_id}"
            ))
            .await
            .expect("GET sub");
        assert_eq!(resp.status, 200);
        let resp = client
            .delete(&format!(
                "/nudr-group-id-map/v1/nf-group-ids/subscriptions/{sub_id}"
            ))
            .await
            .expect("DELETE sub");
        assert_eq!(resp.status, 204);

        // routing-ids is recognised and refused rather than 404'd.
        let resp = client
            .get("/nudr-group-id-map/v1/routing-ids?subscriberId=imsi-001010000000001")
            .await
            .expect("GET routing-ids");
        assert_eq!(resp.status, 501);

        set_group_id_map(Vec::new());
        udr.stop().await.expect("stop");
    }

    #[test]
    fn test_udr_yaml_group_id_map() {
        let yaml = r#"
udr:
  group_id_map:
    - supi_prefix: "imsi-00101"
      nf_group_ids:
        UDM: udm-grp-1
        AUSF: ausf-grp-1
"#;
        let parsed: UdrYaml = serde_yaml::from_str(yaml).unwrap();
        let entries = parsed.udr.unwrap().group_id_map.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].supi_prefix, "imsi-00101");
        assert_eq!(
            entries[0].nf_group_ids.get("UDM").map(String::as_str),
            Some("udm-grp-1")
        );
    }

    /// `build_identity_data` maps a subscriber record to TS 29.505 `IdentityData`.
    #[test]
    fn test_build_identity_data_shapes() {
        let mut data = nextgcore_dbi::types::NextgcoreSubscriptionData::new();
        // No IMSI: nothing to answer with, and the handler turns that into a 404.
        assert_eq!(build_identity_data(&data), json!({}));

        data.imsi = Some("001010000000001".to_string());
        let mut msisdn = nextgcore_dbi::types::NextgcoreMsisdn::default();
        msisdn.bcd = "491721075400".to_string();
        data.msisdn.push(msisdn);
        data.num_of_msisdn = 1;
        assert_eq!(
            build_identity_data(&data),
            json!({
                "supiList": ["imsi-001010000000001"],
                "gpsiList": ["msisdn-491721075400"]
            }),
            "both lists use the same identity spelling as am-data's gpsis"
        );
    }

    /// **nextgsim#480**: a subscriber's External Identifiers are GPSIs too, in
    /// `extid-<username@realm>` form, in both `identity-data`'s `gpsiList` and
    /// `am-data`'s `gpsis`. Before, both lists carried only MSISDNs, so the UDM's
    /// `requested-gpsi-type=EXT_ID` had nothing to return and a NEF could never
    /// hand an AF an External Identifier.
    #[test]
    fn test_external_ids_are_extid_gpsis_in_identity_and_am_data() {
        let mut data = nextgcore_dbi::types::NextgcoreSubscriptionData::new();
        data.imsi = Some("001010000000480".to_string());
        let mut msisdn = nextgcore_dbi::types::NextgcoreMsisdn::default();
        msisdn.bcd = "491721075480".to_string();
        data.msisdn.push(msisdn);
        data.num_of_msisdn = 1;
        data.external_ids = vec!["ue013@fl.nextg".to_string(), "alt@fl.nextg".to_string()];
        let gpsis = json!([
            "msisdn-491721075480",
            "extid-ue013@fl.nextg",
            "extid-alt@fl.nextg"
        ]);
        assert_eq!(
            build_identity_data(&data),
            json!({"supiList": ["imsi-001010000000480"], "gpsiList": gpsis})
        );
        assert_eq!(build_am_data(&data)["gpsis"], gpsis);

        // An External Identifier alone is enough for a gpsiList.
        data.msisdn.clear();
        data.num_of_msisdn = 0;
        data.external_ids = vec!["ue013@fl.nextg".to_string()];
        assert_eq!(
            build_identity_data(&data)["gpsiList"],
            json!(["extid-ue013@fl.nextg"])
        );
        assert_eq!(
            build_am_data(&data)["gpsis"],
            json!(["extid-ue013@fl.nextg"])
        );
    }

    /// The snssai/dnn filter, unit-level: matching is field-wise on sst/sd, so it
    /// does not depend on how this UDR spells the map key.
    #[test]
    fn test_filter_sm_policy_data_matches_on_snssai_fields() {
        let doc = json!({
            "smPolicySnssaiData": {
                "MY-OWN-KEY": {
                    "snssai": {"sst": 1, "sd": "000001"},
                    "smPolicyDnnData": {"internet": {"dnn": "internet"}}
                }
            }
        });
        // Key spelling is irrelevant; sst+sd decide.
        let hit = filter_sm_policy_data(&doc, Some(&json!({"sst": 1, "sd": "000001"})), None)
            .expect("match");
        assert_eq!(
            hit["smPolicySnssaiData"].as_object().map(|o| o.len()),
            Some(1)
        );
        // sd is compared without leading-zero padding differences.
        assert!(
            filter_sm_policy_data(&doc, Some(&json!({"sst": 1, "sd": "0000001"})), None).is_some()
        );
        // A different slice selects nothing.
        assert!(filter_sm_policy_data(&doc, Some(&json!({"sst": 2})), None).is_none());
        // Right slice, wrong DNN: nothing.
        assert!(
            filter_sm_policy_data(&doc, Some(&json!({"sst": 1, "sd": "000001"})), Some("ims"))
                .is_none()
        );
        // No filter: unchanged.
        assert_eq!(filter_sm_policy_data(&doc, None, None), Some(doc));
    }
    // ------------------------------------------------------------------
    // algorithmId / encTopcKey in AuthenticationSubscription (#115)
    // ------------------------------------------------------------------

    fn auth_info_with(
        algorithm_id: &str,
        topc: Option<[u8; 32]>,
    ) -> nextgcore_dbi::subscription::NextgcoreDbiAuthInfo {
        let mut info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo {
            k: [0xab; 16],
            use_opc: true,
            opc: [0x55; 16],
            op: [0u8; 16],
            amf: [0x80, 0x00],
            rand: [0u8; 16],
            sqn: 0x21,
            authentication_method: "5G_AKA".to_string(),
            algorithm_id: algorithm_id.to_string(),
            topc: [0u8; 32],
            top: [0u8; 32],
            use_topc: false,
        };
        if let Some(topc) = topc {
            info.topc = topc;
            info.use_topc = true;
        }
        info
    }

    /// TS 29.505 §5.2.3: `algorithmId` and `encTopcKey` are served when provisioned.
    #[test]
    fn the_auth_subscription_serves_algorithm_id_and_enc_topc_key() {
        let topc = [0x7a; 32];
        let json = build_auth_subscription_json(
            "imsi-001010000000001",
            &auth_info_with("tuak", Some(topc)),
        );

        assert_eq!(json["algorithmId"], "tuak");
        assert_eq!(
            json["encTopcKey"].as_str().unwrap().len(),
            64,
            "a 256-bit TOPc serialises as 64 hex characters"
        );
        assert_eq!(
            json["encTopcKey"].as_str().unwrap(),
            "7a".repeat(32),
            "and it must be the bytes that were stored, not a re-derivation"
        );
        // The pre-existing members are untouched.
        assert_eq!(json["authenticationMethod"], "5G_AKA");
        assert_eq!(json["encPermanentKey"], "ab".repeat(16));
    }

    /// A subscriber with neither member serialises exactly as it did before #115.
    ///
    /// The members are OMITTED, not emitted as empty strings: TS 29.505 makes them 0..1,
    /// and an empty `algorithmId` is a value the UDM would have to interpret rather than
    /// the absence of one. This is the assertion that keeps every existing subscriber
    /// working.
    #[test]
    fn a_subscriber_without_them_serialises_as_before() {
        let json = build_auth_subscription_json("imsi-001010000000002", &auth_info_with("", None));
        assert!(
            json.get("algorithmId").is_none(),
            "absent, not empty: found {:?}",
            json.get("algorithmId")
        );
        assert!(json.get("encTopcKey").is_none(), "absent, not empty");
        // And the response still carries everything it always did.
        for member in [
            "authenticationMethod",
            "encPermanentKey",
            "encOpcKey",
            "authenticationManagementField",
            "supi",
            "sequenceNumber",
        ] {
            assert!(json.get(member).is_some(), "{member} must still be served");
        }
    }

    /// An `algorithmId` with no TOPc still serves the identifier: the UDR stores what it
    /// was given and does not second-guess the provisioning, which is what makes the
    /// UDM's own refusal the place that failure is reported.
    #[test]
    fn an_algorithm_id_without_a_topc_is_still_served() {
        let json =
            build_auth_subscription_json("imsi-001010000000003", &auth_info_with("tuak", None));
        assert_eq!(json["algorithmId"], "tuak");
        assert!(json.get("encTopcKey").is_none());
    }

    /// A 256-bit operator field must be exactly 64 hex characters at provisioning time.
    ///
    /// Rejecting here rather than at authentication time is the point: a short TOPc
    /// becomes a zero-padded key that authenticates against nothing, and the operator
    /// would see it as a UE-side MAC failure rather than as the typo it is.
    #[test]
    fn a_malformed_operator_field_is_refused_at_provisioning() {
        let ok = serde_json::json!({ "encTopcKey": "7a".repeat(32) });
        assert_eq!(
            validate_optional_key_256(&ok, "encTopcKey").unwrap(),
            Some("7a".repeat(32))
        );

        // Absent and empty are both fine — the normal case for every MILENAGE subscriber.
        assert_eq!(
            validate_optional_key_256(&serde_json::json!({}), "encTopcKey").unwrap(),
            None
        );
        assert_eq!(
            validate_optional_key_256(&serde_json::json!({ "encTopcKey": "" }), "encTopcKey")
                .unwrap(),
            None
        );

        // Too short, too long, and not hex are all 400.
        for bad in ["7a".repeat(16), "7a".repeat(33), "z".repeat(64)] {
            let body = serde_json::json!({ "encTopcKey": bad });
            let err = validate_optional_key_256(&body, "encTopcKey")
                .expect_err("a malformed 256-bit field must be refused");
            assert_eq!(
                err.status, 400,
                "and refused with 400, not silently dropped"
            );
        }
    }

    // ====================================================================
    // #264: the subscribed default DNN reaches smf-sel-data
    // ====================================================================

    /// A subscription with two DNNs on one slice; `flag_ims` flags the second as default.
    fn two_dnn_subscription(flag_ims: bool) -> nextgcore_dbi::types::NextgcoreSubscriptionData {
        use nextgcore_dbi::types::{
            NextgcoreSNssai, NextgcoreSession, NextgcoreSliceData, NextgcoreSubscriptionData,
        };
        let internet = NextgcoreSession {
            name: Some("internet".to_string()),
            default_dnn_indicator: false,
            ..Default::default()
        };
        let ims = NextgcoreSession {
            name: Some("ims".to_string()),
            default_dnn_indicator: flag_ims,
            ..Default::default()
        };
        NextgcoreSubscriptionData {
            slice: vec![NextgcoreSliceData {
                // `new(1, None)` rather than `NextgcoreSNssai { sst: 1, ..Default::default() }`:
                // `Default` leaves `sd.v` at 0, and `has_sd()` is `sd.v != NO_SD_VALUE`, so a
                // defaulted S-NSSAI claims to carry an SD of 0 and keys itself "01-000000".
                // The constructor writes the no-SD sentinel, which is what an SST-only
                // subscription actually looks like.
                s_nssai: NextgcoreSNssai::new(1, None),
                default_indicator: true,
                num_of_session: 2,
                session: vec![internet, ims],
            }],
            num_of_slice: 1,
            ..Default::default()
        }
    }

    /// The `dnnInfos` entry for `dnn` out of the single slice the fixture builds.
    fn dnn_info(smf_sel: &serde_json::Value, dnn: &str) -> serde_json::Value {
        smf_sel["subscribedSnssaiInfos"]["01"]["dnnInfos"]
            .as_array()
            .expect("dnnInfos must be an array")
            .iter()
            .find(|i| i["dnn"] == dnn)
            .unwrap_or_else(|| panic!("no dnnInfos entry for {dnn}"))
            .clone()
    }

    /// **#264**: a provisioned default DNN is emitted as `DnnInfo.defaultDnnIndicator`.
    ///
    /// Before this the emitter wrote `{"dnn": <name>}` and nothing else, so nothing in this
    /// tree could produce the flag TS 23.501 §5.6.1 selects on -- `smfd`'s
    /// `select_default_dnn` rule 1 reads exactly this member and could only ever fire
    /// against a third-party UDR.
    ///
    /// The member name is a literal against TS 29.503's `DnnInfo` because a misspelling is
    /// invisible: `select_default_dnn` would fall through to rule 2 or 3 and refuse the
    /// session, which reads as a provisioning mistake rather than a wire bug. `smfd`'s
    /// `select_default_dnn_uses_the_indicator_and_refuses_to_guess` covers the CONSUMING
    /// half with the same literal; this covers the producing half.
    #[test]
    fn a_provisioned_default_dnn_is_emitted_as_the_indicator() {
        let smf_sel = build_smf_selection_data(&two_dnn_subscription(true));

        assert_eq!(
            dnn_info(&smf_sel, "ims")["defaultDnnIndicator"],
            serde_json::json!(true),
            "the flagged DNN must carry defaultDnnIndicator: true (TS 29.503 DnnInfo)"
        );
    }

    /// **#264**: an UNflagged DNN omits the member rather than emitting `false`.
    ///
    /// The load-bearing half, and a deliberate choice rather than an omission. `smfd`'s
    /// rule 2 treats a single unflagged DNN as the unambiguous default and rule 3 refuses a
    /// multi-DNN set with none flagged; it can only tell those apart if "the operator did
    /// not flag this one" and "the operator considered and rejected this one" look the same
    /// on the wire. TS 29.503 types the member `boolean` with no default, so absence is how
    /// the spec says the subscription is silent.
    #[test]
    fn an_unflagged_dnn_omits_the_indicator_rather_than_emitting_false() {
        let smf_sel = build_smf_selection_data(&two_dnn_subscription(true));

        let internet = dnn_info(&smf_sel, "internet");
        assert!(
            internet.get("defaultDnnIndicator").is_none(),
            "an unflagged DNN must omit the member, not assert a considered false: got \
             {internet}"
        );
        assert_eq!(
            internet["dnn"],
            serde_json::json!("internet"),
            "control: the entry is still emitted, so this cannot pass by the DNN being \
             dropped altogether"
        );
    }

    /// **#264**: a subscription that flags nothing emits no indicator anywhere.
    ///
    /// The negative that keeps the emitter honest. Without it an emitter hardcoding `true`
    /// would pass the positive test above and every DNN would claim to be the default,
    /// which `select_default_dnn` would resolve to whichever came first -- exactly the
    /// arbitrary choice #204 exists to remove.
    #[test]
    fn a_subscription_flagging_nothing_emits_no_indicator() {
        let smf_sel = build_smf_selection_data(&two_dnn_subscription(false));

        for dnn in ["internet", "ims"] {
            assert!(
                dnn_info(&smf_sel, dnn).get("defaultDnnIndicator").is_none(),
                "{dnn} must carry no indicator when the operator flagged none"
            );
        }
    }

    // ========================================================================
    // #1775: am-data provisioning changes reach the subscription-data subscriber.
    // ========================================================================

    /// A subscriber document with UE-AMBR `ul_mbps`/`dl_mbps` (unit 2 = Mbps).
    fn ambr_document(
        imsi: &str,
        ul_mbps: i32,
        dl_mbps: i32,
    ) -> nextgcore_dbi::mongodb::bson::Document {
        nextgcore_dbi::mongodb::bson::doc! {
            "imsi": imsi,
            "ambr": {
                "uplink": { "value": ul_mbps, "unit": 2 },
                "downlink": { "value": dl_mbps, "unit": 2 },
            },
        }
    }

    /// A notify listener answering every POST with `status`, sending what it
    /// received into the channel.
    async fn status_listener(
        status: u16,
    ) -> (SbiServer, u16, mpsc::UnboundedReceiver<serde_json::Value>) {
        let (l, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let (tx, rx) = mpsc::unbounded_channel();
        let server = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), l);
        server
            .start(move |req: SbiRequest| {
                let tx = tx.clone();
                async move {
                    let body = req.http.content.clone().unwrap_or_default();
                    let _ = tx.send(serde_json::from_str(&body).unwrap_or_default());
                    SbiResponse::with_status(status)
                }
            })
            .await
            .expect("listener starts");
        (server, addr.port(), rx)
    }

    /// Subscribe at the UDR for `supi`'s am-data, notifying `port`; the id.
    async fn subscribe_am_data(client: &SbiClient, supi: &str, port: u16) -> String {
        let body = json!({
            "callbackReference":
                format!("http://127.0.0.1:{port}/nudm-callback/v1/{supi}/udr-data-change/t"),
            "monitoredResourceUris": [data_store::am_data_path(supi)],
        });
        let resp = client
            .post_json("/nudr-dr/v2/subscription-data/subs-to-notify", &body)
            .await
            .expect("POST subs-to-notify");
        assert_eq!(resp.status, 201);
        json_of(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string()
    }

    /// The notifications that `pass` sent `rx`, without waiting for more.
    fn drain(rx: &mut mpsc::UnboundedReceiver<serde_json::Value>) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Ok(v) = rx.try_recv() {
            out.push(v);
        }
        out
    }

    /// #1775, TS 23.502 §4.5.1 / TS 29.505 §5.4.2.6: a provisioning change of a
    /// watched UE's subscribed UE-AMBR and GPSI is told to the subscription-data
    /// subscriber as a DataChangeNotify on the am-data resource, one ChangeItem per
    /// changed member, the array replaced whole, each with its origValue. Told once:
    /// the next pass, with nothing changed, sends nothing; and nothing is sent before
    /// the change (the baseline is the am-data as it was at subscribe).
    ///
    /// REVERT-VERIFIED: with `am_data_watch_baseline` not called at subscribe the
    /// first pass records the baseline and the change made before it is never told
    /// (0 notifications); with the 2xx arm not advancing the state, the third pass
    /// sends the change again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provisioned_am_data_change_is_told_once_member_by_member_1775() {
        // Loopback plaintext peers; set and never reset (CONVENTIONS).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, _l, _p, _rx) = start_udr_and_listener().await;
        let _dbi = DbiTestStore::enable().await;
        let supi = "imsi-001019900017751";
        nextgcore_dbi::test_store::provision_subscriber_document(
            supi,
            ambr_document("001019900017751", 1, 2),
        );
        nextgcore_dbi::test_store::provision_subscriber(supi, &["4917751"]);
        let (udm, port, mut rx) = status_listener(204).await;
        let sub_id = subscribe_am_data(&client, supi, port).await;

        // The operator provisions a new UE-AMBR and MSISDN.
        nextgcore_dbi::test_store::provision_subscriber_document(
            supi,
            ambr_document("001019900017751", 5, 10),
        );
        nextgcore_dbi::test_store::provision_subscriber(supi, &["4917759"]);
        assert_eq!(am_data_watch_pass().await, 1, "the change is told");
        let told = drain(&mut rx);
        assert_eq!(told.len(), 1, "{told:?}");
        let n = &told[0];
        assert_eq!(n["ueId"], supi);
        let item = &n["notifyItems"][0];
        assert_eq!(item["resourceId"], data_store::am_data_path(supi));
        assert_eq!(
            item["changes"],
            json!([
                {"op": "REPLACE", "path": "/gpsis",
                 "newValue": ["msisdn-4917759"], "origValue": ["msisdn-4917751"]},
                {"op": "REPLACE", "path": "/subscribedUeAmbr",
                 "newValue": {"uplink": "5 Mbps", "downlink": "10 Mbps"},
                 "origValue": {"uplink": "1 Mbps", "downlink": "2 Mbps"}},
            ]),
            "one ChangeItem per changed member, arrays whole"
        );

        assert_eq!(am_data_watch_pass().await, 0, "told once");
        assert!(drain(&mut rx).is_empty());

        let resp = client
            .delete(&format!(
                "/nudr-dr/v2/subscription-data/subs-to-notify/{sub_id}"
            ))
            .await
            .expect("DELETE");
        assert_eq!(resp.status, 204);
        am_data_watch_pass().await;
        assert!(
            data_store::store()
                .doc_get(data_store::AM_DATA_NOTIFIED_COLLECTION, &sub_id)
                .is_none(),
            "a removed subscription's state goes with it"
        );
        udm.stop().await.expect("stop");
        udr.stop().await.expect("stop");
    }

    /// #1775 (TS 29.503 Table 6.1.5.2-3 at the subscriber): a 400 is a refusal and
    /// the same change is not resent, so a subscriber that keeps answering 400 is not
    /// sent it in a loop; a 503 is resent, but not before its backoff has passed
    /// (#1775 review MAJOR-2); a 404 says the subscription is gone, and it is removed
    /// here.
    ///
    /// REVERT-VERIFIED: with the 4xx arm leaving the state, the second pass to the
    /// 400 subscriber sends the change again; with the 404 arm not removing the
    /// subscription, it is still stored after the pass; with the backoff not
    /// checked, the 503 subscriber is sent to on the immediate next pass ("not
    /// before its backoff").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_change_is_not_resent_and_a_gone_subscription_is_removed_1775() {
        // Loopback plaintext peers; set and never reset (CONVENTIONS).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, _l, _p, _rx) = start_udr_and_listener().await;
        let _dbi = DbiTestStore::enable().await;
        let supi = "imsi-001019900017752";
        let imsi = "001019900017752";
        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 1, 2));
        let (refusing, refusing_port, mut refused) = status_listener(400).await;
        let (busy, busy_port, mut busy_rx) = status_listener(503).await;
        let (gone, gone_port, mut gone_rx) = status_listener(404).await;
        let _refusing_sub = subscribe_am_data(&client, supi, refusing_port).await;
        let busy_sub = subscribe_am_data(&client, supi, busy_port).await;
        let gone_sub = subscribe_am_data(&client, supi, gone_port).await;

        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 3, 4));
        assert_eq!(am_data_watch_pass().await, 0, "none answered 2xx");
        assert_eq!(drain(&mut refused).len(), 1);
        assert_eq!(drain(&mut busy_rx).len(), 1);
        assert_eq!(drain(&mut gone_rx).len(), 1);
        assert!(
            data_store::store().sub_get(&gone_sub).is_none(),
            "a 404 removes the subscription"
        );

        let t0 = std::time::Instant::now();
        let epoch = nextgcore_sbi::datetime::now_epoch_secs() as i64;
        am_data_watch_pass_at(t0, epoch).await;
        assert!(drain(&mut refused).is_empty(), "a refusal is not resent");
        assert!(drain(&mut busy_rx).is_empty(), "not before its backoff");
        am_data_watch_pass_at(t0 + AM_DATA_BACKOFF_MAX, epoch).await;
        assert!(drain(&mut refused).is_empty(), "a refusal is not resent");
        assert_eq!(
            drain(&mut busy_rx).len(),
            1,
            "a 503 is resent once its backoff has passed"
        );
        assert!(
            drain(&mut gone_rx).is_empty(),
            "a removed subscription is not sent to"
        );

        for id in data_store::am_data_watchers()
            .into_iter()
            .filter(|(ue, _)| ue == supi)
            .map(|(_, s)| s.id)
        {
            data_store::store().sub_remove(&id);
        }
        let _ = busy_sub;
        for s in [refusing, busy, gone] {
            s.stop().await.expect("stop");
        }
        udr.stop().await.expect("stop");
    }

    /// A TCP listener that accepts and never answers: a subscriber that is gone
    /// without a 404 (a pod replaced, its address now silent). Its port.
    async fn silent_listener() -> (tokio::task::JoinHandle<()>, u16) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = l.local_addr().expect("addr").port();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = l.accept().await {
                held.push(sock);
            }
        });
        (task, port)
    }

    /// Remove every subscription watching `supi`'s am-data.
    fn remove_watchers_of(supi: &str) {
        for id in data_store::am_data_watchers()
            .into_iter()
            .filter(|(ue, _)| ue == supi)
            .map(|(_, s)| s.id)
        {
            data_store::store().sub_remove(&id);
        }
    }

    /// **#1775 review MAJOR-2**: subscribers that never answer do not stall the pass
    /// for the others. Four silent subscribers and one live one watch a UE whose
    /// am-data changed. The pass notifies them concurrently, so it takes about one
    /// request timeout, not four, and the live one is told. The silent ones are then
    /// backed off: the next pass skips them and is quick.
    ///
    /// REVERT-VERIFIED: with `AM_DATA_WATCH_CONCURRENCY` 1 (one notification at a
    /// time, as before), the pass takes four timeouts ("concurrently"); with the
    /// backoff not checked, the second pass waits on them again ("backed off").
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn silent_subscribers_do_not_stall_the_watch_1775() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, _l, _p, _rx) = start_udr_and_listener().await;
        let _dbi = DbiTestStore::enable().await;
        let (supi, imsi) = ("imsi-001019900017754", "001019900017754");
        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 1, 2));
        let mut silent = Vec::new();
        for _ in 0..4 {
            let (task, port) = silent_listener().await;
            subscribe_am_data(&client, supi, port).await;
            silent.push(task);
        }
        let (live, live_port, mut live_rx) = status_listener(204).await;
        subscribe_am_data(&client, supi, live_port).await;
        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 3, 4));

        let t0 = std::time::Instant::now();
        let epoch = nextgcore_sbi::datetime::now_epoch_secs() as i64;
        assert_eq!(
            am_data_watch_pass_at(t0, epoch).await,
            1,
            "the live one is told"
        );
        let took = t0.elapsed();
        assert!(
            took < Duration::from_secs(5),
            "notified concurrently: one timeout, not four ({took:?})"
        );
        assert_eq!(drain(&mut live_rx).len(), 1);

        let t1 = std::time::Instant::now();
        assert_eq!(am_data_watch_pass_at(t1, epoch).await, 0);
        assert!(
            t1.elapsed() < Duration::from_secs(1),
            "the silent ones are backed off ({:?})",
            t1.elapsed()
        );
        remove_watchers_of(supi);
        for t in silent {
            t.abort();
        }
        live.stop().await.expect("stop");
        udr.stop().await.expect("stop");
    }

    /// **#1775 review MAJOR-2**: a subscriber that has answered only 5xx (or not at
    /// all) for `AM_DATA_DEAD_AFTER` is gone, and its subscription is removed, as on a
    /// 404. Before it was retried every pass, forever.
    ///
    /// REVERT-VERIFIED: with the dead arm cut, the subscription is still stored after
    /// an hour and a half of failures ("removed").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_subscriber_failing_for_an_hour_is_removed_1775() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, _l, _p, _rx) = start_udr_and_listener().await;
        let _dbi = DbiTestStore::enable().await;
        let (supi, imsi) = ("imsi-001019900017755", "001019900017755");
        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 1, 2));
        let (busy, busy_port, mut busy_rx) = status_listener(503).await;
        let id = subscribe_am_data(&client, supi, busy_port).await;
        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 3, 4));

        let t0 = std::time::Instant::now();
        let epoch = nextgcore_sbi::datetime::now_epoch_secs() as i64;
        for k in 0..=6u32 {
            am_data_watch_pass_at(t0 + AM_DATA_BACKOFF_MAX * 3 * k, epoch).await;
        }
        assert!(drain(&mut busy_rx).len() >= AM_DATA_DEAD_MIN_FAILURES as usize);
        assert!(
            data_store::store().sub_get(&id).is_none(),
            "removed once it failed for an hour"
        );
        remove_watchers_of(supi);
        busy.stop().await.expect("stop");
        udr.stop().await.expect("stop");
    }

    /// **#1775 review MAJOR-2**, TS 29.504 §5.2.2.6.2: a suggested `expiry` is
    /// confirmed in the 201, and once it passes the subscription is invalid: it is
    /// removed and not told of a change. A suggested expiry that has passed already,
    /// or is not a DateTime, is refused.
    ///
    /// REVERT-VERIFIED: with the expiry sweep cut from the pass, the expired
    /// subscription is told of the change ("not told") and kept ("removed").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_subscription_is_removed_and_not_told_1775() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, _l, _p, _rx) = start_udr_and_listener().await;
        let _dbi = DbiTestStore::enable().await;
        let (supi, imsi) = ("imsi-001019900017756", "001019900017756");
        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 1, 2));
        let (udm, port, mut rx) = status_listener(204).await;
        let now = nextgcore_sbi::datetime::now_epoch_secs();
        let expiry = nextgcore_sbi::datetime::epoch_to_rfc3339(now + 60);
        let body = |expiry: &str| {
            json!({
                "callbackReference": format!("http://127.0.0.1:{port}/cb/1776"),
                "monitoredResourceUris": [data_store::am_data_path(supi)],
                "expiry": expiry,
            })
        };
        let resp = client
            .post_json(
                "/nudr-dr/v2/subscription-data/subs-to-notify",
                &body(&expiry),
            )
            .await
            .expect("POST");
        assert_eq!(resp.status, 201);
        let v = json_of(&resp);
        assert_eq!(v["expiry"], expiry, "confirmed as suggested");
        let id = v["subscriptionId"].as_str().expect("id").to_string();
        for bad in [
            nextgcore_sbi::datetime::epoch_to_rfc3339(now - 1),
            "soon".to_string(),
        ] {
            let resp = client
                .post_json("/nudr-dr/v2/subscription-data/subs-to-notify", &body(&bad))
                .await
                .expect("POST");
            assert_eq!(resp.status, 400, "{bad}");
        }

        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 3, 4));
        am_data_watch_pass_at(std::time::Instant::now(), now as i64 + 61).await;
        assert!(drain(&mut rx).is_empty(), "not told once expired");
        assert!(data_store::store().sub_get(&id).is_none(), "removed");
        remove_watchers_of(supi);
        udm.stop().await.expect("stop");
        udr.stop().await.expect("stop");
    }

    /// **#1836, TS 29.504 §5.2.2.6.2, the UDR peer of the UDM's leg refresh.** A
    /// PATCH of `/expiry` extends the subscription's life: a pass after the first
    /// expiry keeps it. A PATCH whose expiry has passed or cannot be read is refused
    /// 400 and changes nothing, with a valid item beside it (validate before
    /// mutating). Once the expiry passes, the subscription is gone: the refresh is
    /// answered 404 (so the UDM subscribes again), also before a pass removed it.
    ///
    /// REVERT-VERIFIED: with `check_subscription_data_member` not checking `expiry`,
    /// the past one is answered 204 ("a past expiry is refused"); with
    /// `live_subscription_data_sub` not checking the expiry, the refresh of an
    /// expired subscription is answered 204 ("an expired leg answers 404").
    #[tokio::test]
    async fn a_leg_refresh_extends_it_and_a_gone_leg_answers_404_1836() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udr, client, _l, _p, _rx) = start_udr_and_listener().await;
        let _dbi = DbiTestStore::enable().await;
        let (supi, imsi) = ("imsi-001019900018361", "001019900018361");
        nextgcore_dbi::test_store::provision_subscriber_document(supi, ambr_document(imsi, 1, 2));
        let now = nextgcore_sbi::datetime::now_epoch_secs();
        let at = |secs: u64| nextgcore_sbi::datetime::epoch_to_rfc3339(secs);
        let resp = client
            .post_json(
                "/nudr-dr/v2/subscription-data/subs-to-notify",
                &json!({
                    "callbackReference": "http://127.0.0.1:9/cb/1836",
                    "monitoredResourceUris": [data_store::am_data_path(supi)],
                    "expiry": at(now + 60),
                }),
            )
            .await
            .expect("POST");
        assert_eq!(resp.status, 201);
        let id = json_of(&resp)["subscriptionId"]
            .as_str()
            .expect("id")
            .to_string();
        let path = format!("/nudr-dr/v2/subscription-data/subs-to-notify/{id}");
        let patch = |items: serde_json::Value| {
            let mut req = SbiRequest::patch(&path);
            req.http.content = Some(items.to_string());
            req
        };
        let refresh = |secs: u64| json!([{"op": "replace", "path": "/expiry", "value": at(secs)}]);
        let send = |req: SbiRequest| {
            let client = &client;
            async move { client.send_request(req).await.expect("answered").status }
        };

        assert_eq!(send(patch(refresh(now + 600))).await, 204, "refreshed");
        am_data_watch_pass_at(std::time::Instant::now(), now as i64 + 61).await;
        assert!(
            data_store::store().sub_get(&id).is_some(),
            "kept past its first expiry"
        );

        for bad in [
            json!([
                {"op": "replace", "path": "/callbackReference", "value": "http://127.0.0.1:9/x"},
                {"op": "replace", "path": "/expiry", "value": at(now - 1)},
            ]),
            json!([{"op": "replace", "path": "/expiry", "value": "soon"}]),
        ] {
            assert_eq!(
                send(patch(bad.clone())).await,
                400,
                "a past expiry is refused: {bad}"
            );
        }
        let held = data_store::store().sub_get(&id).expect("held");
        assert_eq!(held.body["expiry"], at(now + 600), "nothing applied");
        assert_eq!(held.body["callbackReference"], "http://127.0.0.1:9/cb/1836");

        // The expiry passes (set back, as time would), with no pass since.
        let mut body = held.body;
        body["expiry"] = json!(at(now - 5));
        data_store::store().sub_set_body(&id, body, None);
        assert_eq!(
            send(patch(refresh(now + 900))).await,
            404,
            "an expired leg answers 404"
        );
        assert!(data_store::store().sub_get(&id).is_none(), "and is removed");
        assert_eq!(send(patch(refresh(now + 900))).await, 404, "gone");
        remove_watchers_of(supi);
        udr.stop().await.expect("stop");
    }

    /// **#1836, UDR restart.** A leg's refreshed expiry and its am-data baseline are
    /// in the UDR's state file: a UDR started on that file still holds the
    /// subscription with the refreshed expiry, so the UDM's leg outlives the UDR
    /// restart and its refreshes go on being answered.
    ///
    /// REVERT-VERIFIED: with `sub_set_body` not persisting, the reloaded
    /// subscription has its first expiry ("the refreshed expiry").
    #[test]
    fn a_refreshed_leg_survives_a_udr_restart_1836() {
        let path = std::env::temp_dir().join(format!(
            "udr-1836-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let now = nextgcore_sbi::datetime::now_epoch_secs();
        let at = nextgcore_sbi::datetime::epoch_to_rfc3339;
        let id = {
            let ds = data_store::UdrDataStore::with_state_path(&path);
            let sub = ds.sub_create(SubKind::SubscriptionData, "http://udm/cb", json!({}));
            let body = json!({
                "callbackReference": "http://udm/cb",
                "monitoredResourceUris": ["/nudr-dr/v2/subscription-data/imsi-1/provisioned-data/am-data"],
                "expiry": at(now + 60),
                "subscriptionId": sub.id,
            });
            ds.sub_set_body(&sub.id, body.clone(), None);
            ds.doc_put(
                data_store::AM_DATA_NOTIFIED_COLLECTION,
                &sub.id,
                json!({"gpsis": ["1"]}),
            );
            let mut refreshed = body;
            refreshed["expiry"] = json!(at(now + 900));
            ds.sub_set_body(&sub.id, refreshed, None);
            sub.id
        };
        let restarted = data_store::UdrDataStore::with_state_path(&path);
        let sub = restarted
            .sub_get(&id)
            .expect("the leg survives the restart");
        assert_eq!(sub.body["expiry"], at(now + 900), "the refreshed expiry");
        assert_eq!(
            restarted.doc_get(data_store::AM_DATA_NOTIFIED_COLLECTION, &id),
            Some(json!({"gpsis": ["1"]})),
            "and its baseline"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// **#1775 review MAJOR-2**: one pass serves at most its bound of subscriptions,
    /// round-robin from where the previous pass stopped, so a pass's cost is bounded
    /// and every subscription is still served. Three subscriptions, two per pass:
    /// the first pass serves a and b, the second starts with c; a backed-off one is
    /// skipped; with room for all, every one is served and the cursor is cleared.
    ///
    /// REVERT-VERIFIED: with the cursor not kept (`next` always `None`), the second
    /// pass serves a and b again ("the third, next pass").
    #[test]
    fn a_pass_is_bounded_and_round_robin_1775() {
        let w: Vec<(String, data_store::StoredSub)> = ["a", "b", "c"]
            .iter()
            .map(|id| {
                (
                    format!("imsi-{id}"),
                    data_store::StoredSub {
                        id: id.to_string(),
                        kind: SubKind::SubscriptionData,
                        notify_uri: String::new(),
                        body: serde_json::Value::Null,
                        owner: None,
                    },
                )
            })
            .collect();
        let ids = |d: &[(String, data_store::StoredSub)]| -> Vec<String> {
            d.iter().map(|(_, s)| s.id.clone()).collect()
        };
        let (first, cursor) = am_data_due(&w, None, 2, |_| false);
        assert_eq!(ids(&first), ["a", "b"]);
        let (second, cursor) = am_data_due(&w, cursor.as_deref(), 2, |_| false);
        assert_eq!(ids(&second)[0], "c", "the third, next pass");
        let (third, _) = am_data_due(&w, cursor.as_deref(), 2, |_| false);
        assert_eq!(ids(&third), ["b", "c"]);
        let (skip, _) = am_data_due(&w, None, 2, |id| id == "a");
        assert_eq!(ids(&skip), ["b", "c"], "a backed-off one is skipped");
        let (all, cursor) = am_data_due(&w, Some("b"), 10, |_| false);
        assert_eq!(ids(&all), ["c", "a", "b"]);
        assert_eq!(cursor, None, "every one served");
    }

    /// #1775: the ChangeItems between two am-data documents: ADD, REMOVE (with the
    /// whole original array, TS 29.503 §5.2.2.5.2) and REPLACE, member by member, and
    /// none for an unchanged member; a member name is escaped as an RFC 6901 token.
    #[test]
    fn am_data_changes_are_member_by_member_1775() {
        let old = json!({"gpsis": ["msisdn-1"], "mpsPriority": true, "a/b": 1, "same": 2});
        let new = json!({"mcsPriority": true, "mpsPriority": false, "a/b": 2, "same": 2});
        assert_eq!(
            data_store::am_data_changes(&old, &new),
            json!([
                {"op": "REPLACE", "path": "/a~1b", "newValue": 2, "origValue": 1},
                {"op": "REMOVE", "path": "/gpsis", "origValue": ["msisdn-1"]},
                {"op": "ADD", "path": "/mcsPriority", "newValue": true},
                {"op": "REPLACE", "path": "/mpsPriority", "newValue": false, "origValue": true},
            ])
            .as_array()
            .cloned()
            .expect("array")
        );
    }

    // ========================================================================
    // #1797: no key material in a DataChangeNotify.
    // ========================================================================

    /// The next notification `rx` receives within `ms`, as (path, body).
    async fn next_notification(
        rx: &mut mpsc::UnboundedReceiver<(String, String)>,
        ms: u64,
    ) -> Option<(String, String)> {
        tokio::time::timeout(Duration::from_millis(ms), rx.recv())
            .await
            .ok()
            .flatten()
    }

    /// **#1797**, TS 33.501 §6.1.1 / TS 29.505 §5.2.2: an authentication-subscription
    /// provisioning PUT is notified to a subscriber monitoring that resource as a
    /// REPLACE of the whole resource with NO `newValue`: the change is told, the
    /// long-term key and the operator key are not. A subscriber that names the UE's
    /// `ueId` but monitors only its pp-data is not told of the authentication
    /// subscription at all, and is told of a pp-data change (the positive control).
    ///
    /// REVERT-VERIFIED: with `notified_value` returning the document for every
    /// resource, the notification carries `encPermanentKey` ("no key material");
    /// with the `ueId` match widening the subscription again (`ue_ok || uri_match`),
    /// the pp-data subscriber is told of the authentication subscription ("a ueId
    /// does not widen").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_authentication_subscription_change_is_notified_without_its_keys_1797() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _store = DbiTestStore::enable().await;
        let (udr, client, _listener, cb_port, mut rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900017971";
        let auth = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
        );
        let pp = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data");
        let mut ids = Vec::new();
        for (tag, monitored) in [("auth", &auth), ("pp", &pp)] {
            let resp = client
                .post_json(
                    "/nudr-dr/v2/subscription-data/subs-to-notify",
                    &json!({
                        "ueId": supi,
                        "callbackReference": format!("http://127.0.0.1:{cb_port}/cb-1797/{tag}"),
                        "monitoredResourceUris": [monitored],
                    }),
                )
                .await
                .expect("subscribe");
            assert_eq!(resp.status, 201);
            ids.push(
                json_of(&resp)["subscriptionId"]
                    .as_str()
                    .expect("id")
                    .to_string(),
            );
        }

        wsb6_provision(&client, supi, 0x40).await;
        let (path, body) = next_notification(&mut rx, 3000)
            .await
            .expect("the authentication-subscription change is notified");
        assert_eq!(
            path, "/cb-1797/auth",
            "to the subscriber monitoring it only"
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(v["notifyItems"][0]["resourceId"], auth);
        assert_eq!(
            v["notifyItems"][0]["changes"],
            json!([{"op": "REPLACE", "path": ""}]),
            "no key material: the change is told without its value: {body}"
        );
        for secret in [
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            "e8ed289deba952e4283b54e88e6183ca",
        ]
        .iter()
        .chain(nextgcore_udrd::data_store::KEY_MATERIAL_MEMBERS.iter())
        {
            assert!(!body.contains(secret), "{secret} leaked: {body}");
        }
        assert!(
            next_notification(&mut rx, 300).await.is_none(),
            "a ueId does not widen a pp-data subscription to the authentication data"
        );

        let resp = client
            .put_json(&pp, &json!({"communicationCharacteristics": {}}))
            .await
            .expect("PUT pp-data");
        assert_eq!(resp.status, 201);
        let (path, body) = next_notification(&mut rx, 3000)
            .await
            .expect("the pp-data change is notified");
        assert_eq!(path, "/cb-1797/pp");
        let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(
            v["notifyItems"][0]["changes"][0]["newValue"],
            json!({"communicationCharacteristics": {}}),
            "other resources still carry their value"
        );

        for id in ids {
            data_store::store().sub_remove(&id);
        }
        udr.stop().await.expect("stop");
    }

    /// #1797: key material is removed from any notified document at any depth, and an
    /// authentication subscription carries no value at all.
    #[test]
    fn notified_values_never_carry_key_material_1797() {
        use nextgcore_udrd::data_store::notified_value;
        let doc = json!({
            "keep": 1,
            "encPermanentKey": "k",
            "nested": [{"encOpcKey": "o", "encTopcKey": "t", "x": true}],
        });
        assert_eq!(
            notified_value("/nudr-dr/v2/subscription-data/imsi-1/pp-data", &doc),
            Some(json!({"keep": 1, "nested": [{"x": true}]}))
        );
        assert_eq!(
            notified_value(
                "/nudr-dr/v2/subscription-data/imsi-1/authentication-data/authentication-subscription",
                &json!({"sequenceNumber": {}})
            ),
            None
        );
    }
}

/// #1313 review: a config that does not parse now fails startup, so every
/// shipped config of this daemon must parse with its typed structs.
#[cfg(test)]
mod shipped_config_tests {
    #[test]
    fn the_shipped_configs_parse() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        for rel in [
            "docker/rust/configs/5gc/udr.yaml",
            "docker/rust/configs/5gc/udr-oauth2.yaml",
        ] {
            let text = std::fs::read_to_string(root.join(rel)).unwrap();
            serde_yaml::from_str::<super::UdrYaml>(&text).unwrap_or_else(|e| panic!("{rel}: {e}"));
        }
        let cm: serde_yaml::Value = serde_yaml::from_str(
            &std::fs::read_to_string(root.join("k8s/manifests/configmap.yaml")).unwrap(),
        )
        .unwrap();
        let text = cm["data"]["udr.yaml"]
            .as_str()
            .expect("the ConfigMap's udr.yaml");
        serde_yaml::from_str::<super::UdrYaml>(text).expect("k8s udr.yaml");
        // #1312 (#1317 review): and as the Helm chart renders it (CI installs helm
        // and sets NEXTGCORE_HELM_REQUIRED, so this is never skipped there).
        if let Some(text) = nextgcore_core::helm_render::helm_rendered_config(&root, "udr.yaml") {
            serde_yaml::from_str::<super::UdrYaml>(&text).expect("Helm udr.yaml");
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
            let profile =
                build_udr_nf_profile("id", host, 7777, nextgcore_sbi::types::UriScheme::Http);
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}

/// #1534: how each subscriber-store error is answered.
#[cfg(test)]
mod tests_store_read_failure_1534 {
    use super::store_read_failure;
    use nextgcore_dbi::DbiError;

    fn answer(e: DbiError) -> (u16, String) {
        let resp = store_read_failure("imsi-001010000001534", "test", &e);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
        (
            resp.status,
            body["cause"].as_str().unwrap_or("").to_string(),
        )
    }

    /// REVERT-VERIFIED: with `store_error_is_outage` always false, the outage
    /// errors answer 404.
    #[test]
    fn an_outage_is_500_an_unknown_user_404_and_a_bad_ue_id_400() {
        for e in [
            DbiError::NotInitialized,
            DbiError::Retry,
            DbiError::NoDbUri,
            DbiError::ParseError("decode".into()),
            DbiError::MongoDb(nextgcore_dbi::mongodb::error::Error::custom(
                "server selection timeout",
            )),
        ] {
            let label = format!("{e:?}");
            assert_eq!(answer(e), (500, "SYSTEM_FAILURE".into()), "{label}");
        }
        assert_eq!(
            answer(DbiError::SubscriberNotFound("imsi-1".into())),
            (404, "USER_NOT_FOUND".into())
        );
        assert_eq!(
            answer(DbiError::FieldNotFound("security".into())),
            (404, "DATA_NOT_FOUND".into())
        );
        assert_eq!(
            answer(DbiError::UnsupportedUeIdType("gci".into())),
            (400, "MANDATORY_IE_INCORRECT".into())
        );
    }
}

/// #1665: the outbound OAuth2 client follows the SBI security profile.
#[cfg(test)]
mod outbound_oauth2_1665_tests {
    use nextgcore_sbi::security::SbiProfile;
    use nextgcore_sbi::types::NfType;

    const NRF: &str = "http://127.0.0.10:7777";

    /// Under the `production` profile this UDR installs its token client with
    /// the `sbi.oauth2.require` knob off, so its service requests to the AMF, AUSF,
    /// SMF and UDM (which require a bearer under that profile, #63) carry one
    /// (TS 33.501 §13.4.1.1.2). Before #1665 it installed it only under the knob.
    #[test]
    fn the_production_profile_installs_the_outbound_oauth2_client_without_the_knob() {
        let oauth2 = super::outbound_oauth2_client(SbiProfile::Production, false, Some(NRF))
            .expect("production profile, knob off: the outbound OAuth2 client is installed");
        assert_eq!(oauth2.self_consumer().nf_type, NfType::Udr);
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
/// makes it TLS. This listener is cleartext only today (it has no TLS option and ignores NEXTGCORE_SBI_PROFILE; #1795), so this pins that the profile follows the config should it gain one. `main` passes the listener config's scheme in; the
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
            let profile = build_udr_nf_profile("udr-1791", "10.0.0.1", 7777, cfg.scheme);
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
    /// production half serves cleartext and the helper fails naming UDR.
    #[test]
    fn the_listener_follows_the_sbi_profile_1795() {
        nextgcore_sbi::test_support::assert_listener_follows_sbi_profile(
            nextgcore_sbi::types::NfType::Udr,
            super::sbi_listener_config,
        );
    }

    /// #1811 x #1795: under production the token requirement comes from the
    /// profile, and the K-read resource scope must come with it.
    ///
    /// REVERT-VERIFIED: with the resource-scope step removed from
    /// `sbi_listener_config`, the production listener has none and this fails.
    #[test]
    fn production_keeps_the_auth_subscription_resource_scope_1795() {
        use nextgcore_sbi::security::{SbiProfile, SbiSecurityPolicy, TlsPaths};
        let dir = std::env::temp_dir().join(format!("udrd-1795-rs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = |n: &str| {
            let p = dir.join(n);
            std::fs::write(&p, "pem").unwrap();
            p.display().to_string()
        };
        let policy = SbiSecurityPolicy {
            tls_paths: TlsPaths {
                cert: file("udr.crt"),
                key: file("udr.key"),
                ca_cert: file("ca.crt"),
                client_cert: Some(file("client.crt")),
                client_key: Some(file("client.key")),
            },
            ..SbiSecurityPolicy::production()
        };
        let addr: std::net::SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let base = super::NextgcoreSbiServerConfig::new(addr);
        let prod = super::sbi_listener_config(
            base.clone(),
            SbiProfile::Production,
            &policy,
            "https://127.0.0.10:7777",
        )
        .unwrap();
        assert!(prod.require_oauth2);
        assert!(
            prod.oauth2_resource_scopes.is_some(),
            "the K-read resource scope is enforced under production"
        );
        let dev =
            super::sbi_listener_config(base, SbiProfile::Dev, &policy, "https://127.0.0.10:7777")
                .unwrap();
        assert!(dev.oauth2_resource_scopes.is_none(), "dev adds nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
