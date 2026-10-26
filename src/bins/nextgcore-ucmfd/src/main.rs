//! NextGCore UCMF — UE radio Capability Management Function.
//!
//! TS 23.501 §5.4.4.1a / §6.2.21: the UCMF stores every UE Radio Capability ID
//! mapping in a PLMN and assigns every PLMN-assigned UE Radio Capability ID
//! (RACS). It exposes:
//!
//! - **Nucmf_UECapabilityManagement** (TS 29.673, `nucmf-uecm`): Resolve
//!   (`GET /dic-entries`, `GET /dic-entries/{dicEntryId}`), Assign
//!   (`POST /dic-entries`), Subscribe / Unsubscribe (`POST /subscriptions`,
//!   `DELETE /subscriptions/{id}`) and Notify (callback to `ucmfNotificationUri`).
//! - **Nucmf_Provisioning** (TS 29.675, `nucmf-provisioning`): create, read,
//!   replace, update and remove manufacturer-assigned dictionary entries, as
//!   offered to the NEF for AF provisioning.
//!
//! UE Radio Capability IDs are carried in the TS 29.571 form agreed with the
//! RAN side (base64 of the TS 24.501 §9.11.3.68 IE, `67 LL` included); see
//! [`racs_id`].
//!
//! Every dictionary entry is completed on creation (#585, [`rac`]): the format
//! it lacks is transcoded between TS 38.331 and TS 36.331, and the UE Radio
//! Capability for Paging of each format is derived from the full capability, as
//! TS 23.501 §5.4.4.1a requires of a UCMF in Mode of operation B. A format that
//! cannot be derived (the bytes are not a valid capability) stays absent, and a
//! request for it is answered `404 NO_DICTIONARY_ENTRY_FOUND` with a detail
//! saying so.
//!
//! **Gaps, stated rather than hidden:**
//! - Deleting a provisioning notifies the deletion of the PLMN-assigned IDs it
//!   took with it (`DELETION_OF_PLMN_ASSIGNED_IDS`). TS 29.673 has no event type
//!   for deleted manufacturer-assigned IDs, so their deletion is not notified
//!   (see `Ucmf::delete_provisioning`).
//! - `racsParamEps` / `racsParam5Gs` (TS 29.122 `RacsConfiguration`) are taken
//!   as hexadecimal octet strings. The TS 29.122 OpenAPI
//!   (`TS29122_RacsParameterProvisioning.yaml`) types them as plain `string`
//!   with no format, so the encoding is still this UCMF's choice.

mod context;
mod rac;
mod racs_id;

use anyhow::{Context as _, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use clap::Parser;
use context::{
    AssignError, Capabilities, DicEntry, ModeOfOperation, Notification, RacFormat, ResolveError,
    Ucmf,
};
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiPart, SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::{JwksCache, OAuth2Client};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_internal_error, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig as NextgcoreSbiServerConfig,
};
use nextgcore_sbi::types::NfType;
use racs_id::RacsId;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

/// TS 29.673 V20.0.0 / TS 29.675 OpenAPI `info.version`.
const UECM_API_FULL_VERSION: &str = "1.4.0-alpha.1";
const PROVISIONING_API_FULL_VERSION: &str = "1.3.0";
/// TS 29.673 §6.1.8: feature 1 ES3XX is mandatory.
const UECM_SUPPORTED_FEATURES: &str = "1";
const UECM_API: &str = "nucmf-uecm";
const PROVISIONING_API: &str = "nucmf-provisioning";
const CONTENT_NGAP: &str = "application/vnd.3gpp.ngap";
const CONTENT_S1AP: &str = "application/vnd.3gpp.s1ap";

const NOTIFY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How often write-behind state is flushed to the state file (#786). A crash
/// loses at most this much of the most recent changes; IDs are never reissued
/// (see `Ucmf::reserve_ids`).
const STATE_FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const NOTIFY_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct SbiOauth2Yaml {
    require: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    oauth2: Option<SbiOauth2Yaml>,
}

#[derive(Debug, Default, Deserialize)]
struct NrfYaml {
    uri: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UcmfSection {
    sbi: Option<SbiYaml>,
    nrf: Option<NrfYaml>,
    /// TS 23.003 §29.2 Version ID, two hexadecimal digits.
    version_id: Option<String>,
    /// TS 23.501 §5.4.4.1a mode of operation, "A" or "B".
    mode: Option<String>,
    state_file: Option<String>,
    /// Delete PLMN-assigned IDs under older Version IDs at startup.
    purge_outdated_ids: Option<bool>,
    /// Capacity limits (#786).
    limits: Option<LimitsYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct LimitsYaml {
    max_dic_entries: Option<usize>,
    max_subscriptions: Option<usize>,
    max_subscriptions_per_consumer: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct UcmfYaml {
    ucmf: Option<UcmfSection>,
}

/// NextGCore UCMF - UE radio Capability Management Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-ucmfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core UCMF (RACS, TS 23.501 5.4.4.1a / TS 29.673 / TS 29.675)", long_about = None)]
struct Args {
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/ucmf.yaml")]
    config: String,
    #[arg(short = 'e', long)]
    log_level: Option<String>,
    #[arg(long, default_value = nextgcore_core::sockaddr::DEFAULT_LISTEN_HOST)]
    sbi_addr: String,
    #[arg(long, default_value = "7777")]
    sbi_port: u16,

    /// The SBI host advertised in the NRF NFProfile and the `Location` / resource
    /// URIs (#1322). Without it, `NEXTGCORE_SBI_ADVERTISE`, else `--sbi-addr` when
    /// it is not a wildcard. A wildcard is never advertised.
    #[arg(long)]
    sbi_advertise: Option<String>,
    #[arg(long)]
    tls: bool,
    #[arg(long)]
    tls_cert: Option<String>,
    #[arg(long)]
    tls_key: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,
    /// TS 23.003 §29.2 Version ID (two hex digits); overrides the config file.
    #[arg(long)]
    version_id: Option<String>,
    /// Mode of operation, A or B (TS 23.501 §5.4.4.1a); overrides the config.
    #[arg(long)]
    mode: Option<String>,
    /// JSON snapshot file for the dictionary, subscriptions and provisionings.
    #[arg(long)]
    state_file: Option<String>,
    /// Dev override of `ucmf.sbi.oauth2.require`.
    #[arg(long)]
    oauth2_require: Option<bool>,
}

/// The settled configuration, from the YAML file with CLI overrides.
#[derive(Debug, PartialEq, Eq)]
struct Settings {
    nrf_uri: String,
    version_id: u8,
    mode: ModeOfOperation,
    state_file: Option<String>,
    purge_outdated_ids: bool,
    require_oauth2: bool,
    limits: context::Limits,
}

fn parse_version_id(s: &str) -> Result<u8> {
    let s = s.trim();
    anyhow::ensure!(
        s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit()),
        "version_id must be two hexadecimal digits (TS 23.003 §29.2), got '{s}'"
    );
    Ok(u8::from_str_radix(s, 16)?)
}

fn parse_mode(s: &str) -> Result<ModeOfOperation> {
    match s.trim() {
        "A" | "a" => Ok(ModeOfOperation::A),
        "B" | "b" => Ok(ModeOfOperation::B),
        other => anyhow::bail!("mode must be A or B (TS 23.501 §5.4.4.1a), got '{other}'"),
    }
}

fn settle(args: &Args, yaml: Option<&str>) -> Result<Settings> {
    let section = match yaml {
        Some(text) => serde_yaml::from_str::<UcmfYaml>(text)
            .context("invalid UCMF configuration")?
            .ucmf
            .unwrap_or_default(),
        None => UcmfSection::default(),
    };
    let version = args
        .version_id
        .as_deref()
        .or(section.version_id.as_deref())
        .unwrap_or("00");
    let mode = args
        .mode
        .as_deref()
        .or(section.mode.as_deref())
        .unwrap_or("B");
    Ok(Settings {
        nrf_uri: section
            .nrf
            .and_then(|n| n.uri)
            .unwrap_or_else(|| args.nrf_uri.clone()),
        version_id: parse_version_id(version)?,
        mode: parse_mode(mode)?,
        state_file: args.state_file.clone().or(section.state_file),
        purge_outdated_ids: section.purge_outdated_ids.unwrap_or(false),
        limits: {
            let d = context::Limits::default();
            let l = section.limits.unwrap_or_default();
            context::Limits {
                max_dic_entries: l.max_dic_entries.unwrap_or(d.max_dic_entries),
                max_subscriptions: l.max_subscriptions.unwrap_or(d.max_subscriptions),
                max_subscriptions_per_consumer: l
                    .max_subscriptions_per_consumer
                    .unwrap_or(d.max_subscriptions_per_consumer),
            }
        },
        require_oauth2: args.oauth2_require.unwrap_or_else(|| {
            section
                .sbi
                .and_then(|s| s.oauth2)
                .and_then(|o| o.require)
                .unwrap_or(false)
        }),
    })
}

// ---------------------------------------------------------------------------
// Process-wide state
// ---------------------------------------------------------------------------

static UCMF: OnceLock<Arc<RwLock<Ucmf>>> = OnceLock::new();
/// `{apiRoot}` this UCMF reports in `Location` headers.
static API_ROOT: OnceLock<String> = OnceLock::new();
static OAUTH2_CLIENT: OnceLock<Arc<OAuth2Client>> = OnceLock::new();

/// Poisoned state locks recovered (#725 review): each one is a request that
/// panicked under the lock, a defect to report.
static POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);
/// Requests refused at a capacity limit (#786).
static DICTIONARY_FULL_REFUSALS: AtomicU64 = AtomicU64::new(0);
static SUBSCRIPTION_LIMIT_REFUSALS: AtomicU64 = AtomicU64::new(0);

/// The Prometheus text this UCMF serves at `GET /metrics`.
fn render_metrics(ucmf: Option<&RwLock<Ucmf>>) -> String {
    let mut out = String::new();
    let mut metric = |name: &str, kind: &str, help: &str, value: u64| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    };
    metric(
        "ucmf_state_lock_poison_recoveries_total",
        "counter",
        "State locks recovered after a request panicked while holding them",
        POISON_RECOVERIES.load(Ordering::Relaxed),
    );
    metric(
        "ucmf_dictionary_full_refusals_total",
        "counter",
        "Assign requests refused because the dictionary is at ucmf.limits.max_dic_entries (provisioning refusals are not counted)",
        DICTIONARY_FULL_REFUSALS.load(Ordering::Relaxed),
    );
    metric(
        "ucmf_subscription_limit_refusals_total",
        "counter",
        "Subscribe requests refused at ucmf.limits.max_subscriptions or max_subscriptions_per_consumer",
        SUBSCRIPTION_LIMIT_REFUSALS.load(Ordering::Relaxed),
    );
    if let Some(ucmf) = ucmf {
        let u = read_state(ucmf);
        metric(
            "ucmf_dictionary_entries",
            "gauge",
            "Dictionary entries held",
            u.entry_count() as u64,
        );
        metric(
            "ucmf_subscriptions",
            "gauge",
            "Subscriptions held",
            u.subscription_count() as u64,
        );
    }
    out
}

/// The default `/metrics` port: one of its own. 9090 is the default of mmed,
/// sgwud and upfd, and on a shared host the second NF to bind it would lose its
/// metrics (#857 review).
const DEFAULT_METRICS_PORT: u16 = 9096;

/// Where `/metrics` listens: `UCMF_METRICS_ADDR` (`ip:port`), else the shared
/// default every NF uses (#837): `127.0.0.1` unless `NEXTGCORE_METRICS_BIND`
/// names the host, on [`DEFAULT_METRICS_PORT`]. The endpoint is
/// unauthenticated, so reaching it from another host is an operator's explicit
/// choice of a private address (or a scraping sidecar). A value that does not
/// parse falls back to the default and says so (#857 review), so an operator
/// learns why a scrape from another host fails.
fn metrics_addr(value: Option<&str>) -> SocketAddr {
    let default = nextgcore_metrics::nes_energy::metrics_bind_addr(DEFAULT_METRICS_PORT);
    match value {
        None => default,
        Some(v) => v.parse().unwrap_or_else(|_| {
            log::warn!(
                "UCMF_METRICS_ADDR '{v}' is not an ip:port; /metrics listens on {default} instead"
            );
            default
        }),
    }
}

/// #1322: `{scheme}://<advertised host>:<port>`, or why the UCMF must not start
/// (a wildcard bind with nothing reachable to advertise).
fn ucmf_api_root(
    scheme: &str,
    sbi: &nextgcore_core::sockaddr::SbiEndpoint,
) -> Result<String, String> {
    let host = sbi
        .registration_host()
        .map_err(|why| format!("refusing to start: {why}"))?;
    Ok(format!(
        "{scheme}://{}",
        nextgcore_sbi::uri_encode::uri_authority(host, sbi.port)
    ))
}

fn api_root() -> &'static str {
    API_ROOT.get().map(String::as_str).unwrap_or("http://ucmf")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    nextgcore_core::log::nf_log_builder(&nextgcore_core::log::nf_log_level(
        args.log_level.as_deref(),
        Some(&args.config),
    ))
    .init();
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore UCMF v{}", env!("CARGO_PKG_VERSION"));
    let yaml = std::fs::read_to_string(&args.config).ok();
    let settings = settle(&args, yaml.as_deref())?;
    log::info!(
        "UE radio Capability Management Function (TS 29.673 / TS 29.675): Version ID {:02X}, mode {:?}",
        settings.version_id,
        settings.mode
    );

    // Load the snapshot under the stored Version ID, then apply the configured
    // one so restored subscribers hear about a change.
    let mut ucmf = Ucmf::new(settings.version_id, settings.mode);
    ucmf.set_limits(settings.limits);
    log::info!("Capacity limits: {:?}", settings.limits);
    match ucmf.attach_store(settings.state_file.as_ref().map(PathBuf::from)) {
        Ok(true) => log::info!("Restored {} dictionary entries", ucmf.entry_count()),
        Ok(false) => {}
        Err(e) => log::error!("UCMF state not loaded, starting empty and NOT overwriting it: {e}"),
    }
    let mut startup_notes = Vec::new();
    startup_notes.extend(ucmf.set_version_id(settings.version_id, Utc::now()));
    if settings.purge_outdated_ids {
        startup_notes.extend(ucmf.purge_outdated_plmn_ids(Utc::now()));
    }
    // #786: with a state file, changes are written behind, by the flusher below,
    // instead of each one rewriting the whole snapshot under the state lock.
    if settings.state_file.is_some() {
        ucmf.set_write_behind(true);
    }
    let _ = UCMF.set(Arc::new(RwLock::new(ucmf)));
    if let Some(ucmf) = UCMF.get() {
        let ucmf = ucmf.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(STATE_FLUSH_INTERVAL);
            loop {
                tick.tick().await;
                flush_state(&ucmf).await;
            }
        });
    }

    let nf_instance_id = nextgcore_sbi::nf_instance_id::nf_instance_id(NfType::Ucmf).to_string();
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        ctrlc::set_handler(move || {
            log::info!("Received shutdown signal");
            shutdown.store(true, Ordering::SeqCst);
        })
        .context("installing the signal handler")?;
    }

    let scheme = if args.tls { "https" } else { "http" };
    // #1322: the advertised host, apart from the bind; never a wildcard. Checked
    // before the listener starts: the UCMF refuses to start rather than hand
    // 0.0.0.0 to a peer in a Location or resource URI.
    let sbi = nextgcore_core::sockaddr::SbiEndpoint::resolve(
        Some(&args.sbi_addr),
        Some(args.sbi_port),
        args.sbi_advertise.as_deref(),
        None,
        None,
        None,
        args.sbi_port,
    );
    let _ = API_ROOT.set(ucmf_api_root(scheme, &sbi).map_err(|why| anyhow::anyhow!(why))?);
    let addr: SocketAddr =
        nextgcore_core::sockaddr::parse_listen_addr(&args.sbi_addr, args.sbi_port)
            .context("Invalid SBI address")?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    nextgcore_core::sockaddr::warn_if_loopback_listener("SBI", &addr, "--sbi-addr");

    let mut sbi_config = NextgcoreSbiServerConfig::new(addr);
    if args.tls {
        let cert = args
            .tls_cert
            .as_deref()
            .unwrap_or("/etc/nextgcore/tls/server.crt");
        let key = args
            .tls_key
            .as_deref()
            .unwrap_or("/etc/nextgcore/tls/server.key");
        sbi_config = sbi_config.with_tls(key, cert);
    }
    if settings.require_oauth2 {
        // TS 33.501 §13.4.1: verify Bearer tokens against the NRF JWKS, with
        // this NF's type as the required audience.
        sbi_config.require_oauth2 = true;
        sbi_config.oauth2_jwks_uri =
            Some(JwksCache::for_nrf(&settings.nrf_uri).jwks_uri().to_string());
        sbi_config = sbi_config.with_expected_audience_nf_type(NfType::Ucmf);
        let _ = OAUTH2_CLIENT.set(Arc::new(OAuth2Client::new(
            &settings.nrf_uri,
            nf_instance_id.clone(),
            NfType::Ucmf,
        )));
        log::info!("OAuth2 enforcement enabled");
    }

    let sbi_server = SbiServer::new(sbi_config);
    sbi_server
        .start(ucmf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;
    log::info!("SBI server listening on {addr}");
    match nextgcore_metrics::nes_energy::serve_metrics(
        metrics_addr(std::env::var("UCMF_METRICS_ADDR").ok().as_deref()),
        Arc::new(|| render_metrics(UCMF.get().map(|u| u.as_ref()))),
    )
    .await
    {
        Ok((bound, _handle)) => log::info!("UCMF metrics on http://{bound}/metrics"),
        Err(e) => log::warn!("UCMF metrics endpoint not started: {e}"),
    }

    global_context().set_nrf_uri(&settings.nrf_uri).await;
    match match sbi.registration_host() {
        Ok(host) => register_with_nrf(host, sbi.port, scheme, &nf_instance_id).await,
        Err(why) => Err(why),
    } {
        Ok(()) => nextgcore_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5),
        Err(e) => log::warn!("NRF registration failed (will operate without NRF): {e}"),
    }
    for note in startup_notes {
        dispatch(note);
    }
    log::info!("NextGCore UCMF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    log::info!("Shutting down...");
    // Deregister before the listener goes away (TS 29.510 §5.2.2.4), stop
    // serving, and only then write the final snapshot, so no request served
    // after it is lost on a clean shutdown (#843 review).
    nextgcore_sbi::heartbeat::deregister_self().await;
    let stopped = sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"));
    if let Some(ucmf) = UCMF.get() {
        flush_state(ucmf).await;
    }
    stopped?;
    log::info!("UCMF shutdown complete");
    Ok(())
}

/// The TS 29.510 NFProfile this UCMF registers.
fn nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16, scheme: &str) -> Value {
    let service = |name: &str, version: &str, allowed: &[&str]| {
        json!({
            "serviceInstanceId": format!("{nf_instance_id}-{name}"),
            "serviceName": name,
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": version}],
            "scheme": scheme,
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
            "allowedNfTypes": allowed,
        })
    };
    let mut uecm = service(
        nextgcore_sbi::types::SbiServiceType::NucmfUecapabilitymanagement.to_name(),
        UECM_API_FULL_VERSION,
        &["AMF", "MME", "SCP"],
    );
    uecm["supportedFeatures"] = json!(UECM_SUPPORTED_FEATURES);
    let provisioning = service(
        nextgcore_sbi::types::SbiServiceType::NucmfProvisioning.to_name(),
        PROVISIONING_API_FULL_VERSION,
        &["NEF", "SCP"],
    );
    nextgcore_sbi::nf_addressing::classify_profile_host(
        json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "UCMF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": [uecm, provisioning],
            "allowedNfTypes": ["AMF", "MME", "NEF", "SCP"],
            "heartBeatTimer": 10,
        }),
        sbi_addr,
    )
}

async fn register_with_nrf(
    sbi_addr: &str,
    sbi_port: u16,
    scheme: &str,
    nf_instance_id: &str,
) -> Result<(), String> {
    let sbi_ctx = global_context();
    let Some(nrf_uri) = sbi_ctx.get_nrf_uri().await else {
        return Ok(());
    };
    let (host, port, _) = split_uri(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&host, port).await;
    let profile = nf_profile(nf_instance_id, sbi_addr, sbi_port, scheme);
    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let response = client
        .put_json(&path, &profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;
    match response.status {
        200 | 201 => {
            log::info!("UCMF registered with NRF (id={nf_instance_id})");
            nextgcore_sbi::heartbeat::set_registered_profile(&profile);
            Ok(())
        }
        s => Err(format!("NRF registration returned status {s}")),
    }
}

fn split_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
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
    match host_port.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?, path)),
        None => Some((host_port.to_string(), default_port, path)),
    }
}

/// Write the pending snapshot, if any (#786). The snapshot is taken under the
/// state lock; the file is written after the lock is released, on a blocking
/// thread, so requests are not held up by the disk.
async fn flush_state(ucmf: &Arc<RwLock<Ucmf>>) {
    let pending = write_state(ucmf).take_pending_write();
    if let Some((persister, generation, source)) = pending {
        // Serialised and written off the state lock (#843 review). A failed write
        // is logged by the persister; the next reservation retries it.
        let _ = tokio::task::spawn_blocking(move || persister.write(generation, &source.to_json()))
            .await;
    }
}

/// Deliver a notification to every subscriber, without blocking the caller.
fn dispatch(note: Notification) {
    for notification_uri in note.uris {
        let body = note.body.clone();
        tokio::spawn(async move {
            let Some((host, port, path)) = split_uri(&notification_uri) else {
                log::warn!(
                    "Invalid ucmfNotificationUri '{notification_uri}'",
                    notification_uri =
                        nextgcore_sbi::log_redact::redact_last_segment(&notification_uri)
                );
                return;
            };
            let mut client = SbiClient::new(
                SbiClientConfig::new(host, port)
                    .with_connect_timeout(NOTIFY_CONNECT_TIMEOUT)
                    .with_request_timeout(NOTIFY_REQUEST_TIMEOUT),
            );
            if let Some(oauth2) = OAUTH2_CLIENT.get() {
                client = client.with_oauth2(oauth2.clone(), NfType::Amf);
            }
            match client.post_json(&path, &body).await {
                Ok(r) if r.status == 204 || r.is_success() => {
                    log::debug!(
                        "UCMF notification delivered to {notification_uri}",
                        notification_uri =
                            nextgcore_sbi::log_redact::redact_last_segment(&notification_uri)
                    )
                }
                Ok(r) => log::warn!(
                    "UCMF notification to {notification_uri} returned {}",
                    r.status,
                    notification_uri =
                        nextgcore_sbi::log_redact::redact_last_segment(&notification_uri)
                ),
                Err(e) => log::warn!(
                    "UCMF notification to {notification_uri} failed: {e}",
                    notification_uri =
                        nextgcore_sbi::log_redact::redact_last_segment(&notification_uri)
                ),
            }
        });
    }
}

async fn ucmf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let Some(ucmf) = UCMF.get() else {
        return send_internal_error("UCMF not initialised");
    };
    let (response, notes) = handle(ucmf, &request, Utc::now());
    for note in notes {
        dispatch(note);
    }
    response
}

// ---------------------------------------------------------------------------
// Request handling (no I/O: returns the response and notifications to send)
// ---------------------------------------------------------------------------

fn handle(
    ucmf: &RwLock<Ucmf>,
    request: &SbiRequest,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    let method = request.header.method.as_str();
    let uri = request.header.uri.as_str();
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    log::debug!("UCMF SBI: {method} {path}");

    match parts.as_slice() {
        [UECM_API, "v1", "dic-entries"] => match method {
            "GET" => (resolve(&read_state(ucmf), request), Vec::new()),
            "POST" => assign(&mut write_state(ucmf), request, now),
            _ => (send_method_not_allowed(method, "dic-entries"), Vec::new()),
        },
        [UECM_API, "v1", "dic-entries", id] => match method {
            "GET" => (get_dic_entry(&read_state(ucmf), id, request), Vec::new()),
            _ => (
                send_method_not_allowed(method, "dic-entries/{dicEntryId}"),
                Vec::new(),
            ),
        },
        [UECM_API, "v1", "subscriptions"] => match method {
            "POST" => (subscribe(&mut write_state(ucmf), request, now), Vec::new()),
            _ => (send_method_not_allowed(method, "subscriptions"), Vec::new()),
        },
        [UECM_API, "v1", "subscriptions", id] => match method {
            "DELETE" => (unsubscribe(&mut write_state(ucmf), id), Vec::new()),
            _ => (
                send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
                Vec::new(),
            ),
        },
        [PROVISIONING_API, "v1", "provisionings"] => match method {
            "POST" => create_provisioning(&mut write_state(ucmf), request, now),
            _ => (send_method_not_allowed(method, "provisionings"), Vec::new()),
        },
        [PROVISIONING_API, "v1", "provisionings", id] => match method {
            "GET" => (get_provisioning(&read_state(ucmf), id), Vec::new()),
            "PUT" => replace_provisioning(&mut write_state(ucmf), id, request, now),
            "PATCH" => patch_provisioning(&mut write_state(ucmf), id, request, now),
            "DELETE" => delete_provisioning(&mut write_state(ucmf), id, now),
            _ => (
                send_method_not_allowed(method, "provisionings/{provisioningId}"),
                Vec::new(),
            ),
        },
        _ => (
            send_not_found(&format!("Resource not found: {path}"), None),
            Vec::new(),
        ),
    }
}

/// The UCMF state for reading. See [`write_state`] for why a poisoned lock is
/// taken rather than refused.
fn read_state(ucmf: &RwLock<Ucmf>) -> RwLockReadGuard<'_, Ucmf> {
    ucmf.read().unwrap_or_else(|poisoned| {
        log_poison_recovery();
        ucmf.clear_poison();
        poisoned.into_inner()
    })
}

/// The UCMF state for writing, even when an earlier request panicked while
/// holding it (#725).
///
/// Refusing a poisoned lock would make one panicking request answer `500` to
/// every later request on both services until the process restarts. Taking it
/// is sound because nothing that runs under the lock can leave the dictionary
/// half-changed when it unwinds: the request decoders validate before they
/// slice, the RRC codec calls are contained by `rac::guarded`, and the `Ucmf`
/// operations do no indexing or arithmetic that request data can make fail. So a
/// poisoned lock means a defect elsewhere, which is logged, not a torn state.
fn write_state(ucmf: &RwLock<Ucmf>) -> RwLockWriteGuard<'_, Ucmf> {
    ucmf.write().unwrap_or_else(|poisoned| {
        log_poison_recovery();
        ucmf.clear_poison();
        poisoned.into_inner()
    })
}

fn log_poison_recovery() {
    POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
    log::error!(
        "UCMF state lock was poisoned by a request that panicked; recovering it so \
         later requests are still served (#725). The panic above is a defect to report."
    );
}

/// The request's JSON body (the JSON part of a multipart body).
fn request_json(request: &SbiRequest) -> Option<Value> {
    request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
}

#[allow(clippy::result_large_err)] // the Err is the response to send, built once per request
fn rac_format(request: &SbiRequest) -> Result<Option<RacFormat>, SbiResponse> {
    match request.http.params.get("rac-format") {
        None => Ok(None),
        Some(f) => RacFormat::parse(f).map(Some).ok_or_else(|| {
            send_bad_request(
                &format!("unknown rac-format '{f}'"),
                Some("INVALID_QUERY_PARAM"),
            )
        }),
    }
}

fn resolve_error(e: ResolveError) -> SbiResponse {
    match e {
        ResolveError::NotFound => send_not_found("No dictionary entry matches the query", Some("NO_DICTIONARY_ENTRY_FOUND")),
        ResolveError::OutdatedVersionId => send_not_found(
            "The Version ID in the PLMN-assigned UE Radio Capability ID is out of date",
            Some("OUT_DATED_VERSION_ID_IN_RAC_ID"),
        ),
        ResolveError::FormatNotStored => send_not_found(
            "The dictionary entry does not hold the requested RAC format, and the format it holds could not be transcoded to it",
            Some("NO_DICTIONARY_ENTRY_FOUND"),
        ),
    }
}

/// TS 29.673 §5.2.2.2.1: `GET /dic-entries?ue-radio-capa-id=…[&rac-format=…]`.
/// `ue-radio-capa-id` is a `UeRadioCapaId` object, JSON in the query value
/// (TS 29.500 §6.? query-parameter JSON encoding).
fn resolve(u: &Ucmf, request: &SbiRequest) -> SbiResponse {
    let format = match rac_format(request) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let Some(raw) = request.http.params.get("ue-radio-capa-id") else {
        return send_bad_request(
            "ue-radio-capa-id is required",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    };
    let query: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => {
            return send_bad_request(
                "ue-radio-capa-id is not a UeRadioCapaId object",
                Some("INVALID_QUERY_PARAM"),
            )
        }
    };
    let field = query
        .get("plmnAssiUeRadioCapId")
        .or_else(|| query.get("manAssiUeRadioCapId"))
        .and_then(Value::as_str);
    let id = match field.map(RacsId::from_nucmf) {
        Some(Ok(id)) => id,
        Some(Err(e)) => {
            return send_bad_request(
                &format!("ue-radio-capa-id: {e}"),
                Some("INVALID_QUERY_PARAM"),
            )
        }
        None => {
            return send_bad_request(
                "ue-radio-capa-id carries no ID",
                Some("INVALID_QUERY_PARAM"),
            )
        }
    };
    // The ID type must agree with the member that carried it.
    let plmn_member = query.get("plmnAssiUeRadioCapId").is_some();
    if plmn_member != id.is_plmn_assigned() {
        return send_bad_request(
            "ID type does not match its UeRadioCapaId member",
            Some("INVALID_QUERY_PARAM"),
        );
    }
    match u.resolve(&id, format) {
        Ok(entry) => dic_entry_response(entry, format),
        Err(e) => resolve_error(e),
    }
}

/// TS 29.673 §5.2.2.2.2: `GET /dic-entries/{dicEntryId}`.
fn get_dic_entry(u: &Ucmf, id: &str, request: &SbiRequest) -> SbiResponse {
    let format = match rac_format(request) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let Ok(entry_id) = id.parse::<u32>() else {
        return send_bad_request("dicEntryId must be an integer", Some("INVALID_URI"));
    };
    match u.get_entry(entry_id, format) {
        Ok(entry) => dic_entry_response(entry, format),
        Err(e) => resolve_error(e),
    }
}

/// `DicEntryData` as JSON plus the binary parts it references, as a
/// `multipart/related` 200 (TS 29.673 §6.1.2.4).
fn dic_entry_response(e: &DicEntry, format: Option<RacFormat>) -> SbiResponse {
    let mut data = Map::new();
    data.insert("dicEntryId".into(), json!(e.id));
    data.insert("typeAllocationCode".into(), json!(e.tacs.first()));
    if let Some(id) = e.plmn_id {
        data.insert("plmnAssiUeRadioCapId".into(), json!(id.to_nucmf()));
    }
    if let Some(id) = e.man_id {
        data.insert("manAssiUeRadioCapId".into(), json!(id.to_nucmf()));
    }
    let want_5gs = format != Some(RacFormat::Eps);
    let want_eps = format != Some(RacFormat::FiveGs);
    let mut parts = Vec::new();
    for (name, bytes, content_type, wanted) in [
        (
            "ueRadioCapability5GS",
            &e.caps.cap_5gs,
            CONTENT_NGAP,
            want_5gs,
        ),
        (
            "ueRadioCapabilityEPS",
            &e.caps.cap_eps,
            CONTENT_S1AP,
            want_eps,
        ),
        (
            "ueRadioCap5GSForPaging",
            &e.caps.paging_5gs,
            CONTENT_NGAP,
            want_5gs,
        ),
        (
            "ueRadioCapEPSForPaging",
            &e.caps.paging_eps,
            CONTENT_S1AP,
            want_eps,
        ),
    ] {
        if let (Some(b), true) = (bytes, wanted) {
            data.insert(name.into(), json!({ "contentId": name }));
            parts.push(SbiPart::with_content(
                name,
                content_type,
                Bytes::from(b.clone()),
            ));
        }
    }
    let mut response = match SbiResponse::ok().with_json_body(&Value::Object(data)) {
        Ok(r) => r,
        Err(e) => return send_internal_error(&format!("encoding DicEntryData: {e}")),
    };
    for p in parts {
        response = response.with_part(p);
    }
    response
}

/// The binary part a `RefToBinaryData` member names, if any.
#[allow(clippy::result_large_err)] // the Err is the response to send, built once per request
fn referenced_part(
    request: &SbiRequest,
    json: &Value,
    member: &str,
) -> Result<Option<Vec<u8>>, SbiResponse> {
    let Some(reference) = json.get(member) else {
        return Ok(None);
    };
    let Some(cid) = reference.get("contentId").and_then(Value::as_str) else {
        return Err(send_bad_request(
            &format!("{member} is not a RefToBinaryData"),
            Some("INVALID_MSG_FORMAT"),
        ));
    };
    request
        .http
        .parts
        .iter()
        .find(|p| {
            p.content_id
                .as_deref()
                .map(|c| c.trim_matches(|ch| ch == '<' || ch == '>'))
                == Some(cid)
        })
        .map(|p| Some(p.data.to_vec()))
        .ok_or_else(|| {
            send_bad_request(
                &format!("{member} references missing part '{cid}'"),
                Some("INVALID_MSG_FORMAT"),
            )
        })
}

/// TS 29.673 §5.2.2.3 Assign: `POST /dic-entries` (multipart/related).
fn assign(
    u: &mut Ucmf,
    request: &SbiRequest,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    let Some(json) = request_json(request) else {
        return (
            send_bad_request("DicEntryCreateData is required", Some("INVALID_MSG_FORMAT")),
            Vec::new(),
        );
    };
    let Some(tac) = json.get("typeAllocationCode").and_then(Value::as_str) else {
        return (
            send_bad_request(
                "typeAllocationCode is required",
                Some("MANDATORY_IE_MISSING"),
            ),
            Vec::new(),
        );
    };
    #[allow(clippy::result_large_err)]
    let caps = (|| {
        Ok::<_, SbiResponse>(Capabilities {
            cap_5gs: referenced_part(request, &json, "ueRadioCapability5GS")?,
            cap_eps: referenced_part(request, &json, "ueRadioCapabilityEPS")?,
            paging_5gs: referenced_part(request, &json, "ueRadioCap5GSForPaging")?,
            paging_eps: referenced_part(request, &json, "ueRadioCapEPSForPaging")?,
        })
    })();
    let caps = match caps {
        Ok(c) => c,
        Err(r) => return (r, Vec::new()),
    };
    match u.assign(tac, caps, now) {
        Ok((entry_id, id, note)) => {
            let body = json!({ "plmnAssiUeRadioCapId": id.to_nucmf() });
            let response = SbiResponse::created()
                .with_header("Location", format!("{}/{UECM_API}/v1/dic-entries/{entry_id}", api_root()))
                .with_json_body(&body)
                .unwrap_or_else(|e| send_internal_error(&format!("encoding DicEntryCreatedData: {e}")));
            (response, note.into_iter().collect())
        }
        Err(AssignError::BadTac) => (
            send_bad_request("typeAllocationCode must be 8 digits (TS 29.571)", Some("INVALID_MSG_FORMAT")),
            Vec::new(),
        ),
        Err(AssignError::NoCapability) => (
            send_bad_request("UE radio capability information is required", Some("MANDATORY_IE_MISSING")),
            Vec::new(),
        ),
        Err(AssignError::ModeARequiresBothFormats) => (
            send_bad_request(
                "Mode of Operation A: both RAC formats are required for an unknown capability (TS 29.673 §5.2.2.3)",
                Some("MANDATORY_IE_MISSING"),
            ),
            Vec::new(),
        ),
        // TS 29.500 Table 5.2.7.2-1: INSUFFICIENT_RESOURCES is a 500 (#786).
        Err(AssignError::DictionaryFull) => (
            {
                DICTIONARY_FULL_REFUSALS.fetch_add(1, Ordering::Relaxed);
                send_error(
                500,
                "Internal Server Error",
                "The UE radio capability dictionary is full",
                Some("INSUFFICIENT_RESOURCES"),
                )
            },
            Vec::new(),
        ),
        Err(AssignError::IdSpaceExhausted) => (
            send_error(
                500,
                "Internal Server Error",
                "No RCI left under the current Version ID",
                Some("INSUFFICIENT_RESOURCES"),
            ),
            Vec::new(),
        ),
        // #843 review: no ID is handed out that the state file does not cover.
        Err(AssignError::StateNotPersisted) => (
            send_error(
                500,
                "Internal Server Error",
                "The UCMF state could not be written, so no ID can be assigned safely",
                Some("SYSTEM_FAILURE"),
            ),
            Vec::new(),
        ),
    }
}

/// TS 29.673 §5.2.2.4 Subscribe: `POST /subscriptions`.
fn subscribe(u: &mut Ucmf, request: &SbiRequest, now: DateTime<Utc>) -> SbiResponse {
    let Some(json) = request_json(request) else {
        return send_bad_request("CreateSubscription is required", Some("INVALID_MSG_FORMAT"));
    };
    let Some(uri) = json.get("ucmfNotificationUri").and_then(Value::as_str) else {
        return send_bad_request(
            "ucmfNotificationUri is required",
            Some("MANDATORY_IE_MISSING"),
        );
    };
    if split_uri(uri).is_none() || !(uri.starts_with("http://") || uri.starts_with("https://")) {
        return send_bad_request(
            "ucmfNotificationUri is not an http(s) URI",
            Some("INVALID_MSG_FORMAT"),
        );
    }
    let suggested = match json.get("suggestedExpires").and_then(Value::as_str) {
        None => None,
        Some(s) => match DateTime::parse_from_rfc3339(s) {
            Ok(t) => Some(t.with_timezone(&Utc)),
            Err(_) => {
                return send_bad_request(
                    "suggestedExpires is not a DateTime",
                    Some("INVALID_MSG_FORMAT"),
                )
            }
        },
    };
    let nf_id = json.get("nfId").and_then(Value::as_str).map(str::to_string);
    let sub = match u.subscribe(nf_id, uri.to_string(), suggested, now) {
        Ok(sub) => sub,
        // TS 29.500 Table 5.2.7.2-1: INSUFFICIENT_RESOURCES is a 500 (#786).
        Err(e) => {
            // MINOR 3 of the #857 review: the series counts the configured
            // limits only, not an exhausted ID space or a failed write.
            if matches!(
                e,
                context::SubscribeError::TooManySubscriptions
                    | context::SubscribeError::TooManyForConsumer
            ) {
                SUBSCRIPTION_LIMIT_REFUSALS.fetch_add(1, Ordering::Relaxed);
            }
            let (detail, cause) = match e {
                context::SubscribeError::TooManySubscriptions => (
                    "The UCMF holds its maximum number of subscriptions",
                    "INSUFFICIENT_RESOURCES",
                ),
                context::SubscribeError::TooManyForConsumer => (
                    "This consumer holds its maximum number of subscriptions",
                    "INSUFFICIENT_RESOURCES",
                ),
                context::SubscribeError::IdSpaceExhausted => {
                    ("No subscription ID is left", "INSUFFICIENT_RESOURCES")
                }
                context::SubscribeError::StateNotPersisted => (
                    "The UCMF state could not be written, so no subscription ID can be \
                     assigned safely",
                    "SYSTEM_FAILURE",
                ),
            };
            return send_error(500, "Internal Server Error", detail, Some(cause));
        }
    };
    let mut body = json!({ "dicEntryId": u.highest_entry_id() });
    if let Some(e) = sub.expires {
        body["confirmedExpires"] = json!(e.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    body["supportedFeatures"] = json!(UECM_SUPPORTED_FEATURES);
    SbiResponse::created()
        .with_header(
            "Location",
            format!("{}/{UECM_API}/v1/subscriptions/{}", api_root(), sub.id),
        )
        .with_json_body(&body)
        .unwrap_or_else(|e| send_internal_error(&format!("encoding CreatedSubscription: {e}")))
}

/// TS 29.673 §5.2.2.5 Unsubscribe.
fn unsubscribe(u: &mut Ucmf, id: &str) -> SbiResponse {
    if u.unsubscribe(id) {
        SbiResponse::no_content()
    } else {
        send_not_found(
            &format!("No subscription {id}"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

#[allow(clippy::result_large_err)] // the Err is the response to send, built once per request
fn racs_configs(request: &SbiRequest) -> Result<(Map<String, Value>, Option<String>), SbiResponse> {
    let json = request_json(request)
        .ok_or_else(|| send_bad_request("RacsData is required", Some("INVALID_MSG_FORMAT")))?;
    let configs = json
        .get("racsConfigs")
        .and_then(Value::as_object)
        .filter(|m| !m.is_empty())
        .cloned()
        .ok_or_else(|| {
            send_bad_request(
                "racsConfigs is required (minProperties 1)",
                Some("MANDATORY_IE_MISSING"),
            )
        })?;
    Ok((
        configs,
        json.get("suppFeat")
            .and_then(Value::as_str)
            .map(str::to_string),
    ))
}

fn racs_reports(failed: &[(String, &'static str)]) -> Vec<Value> {
    // TS 29.122 RacsFailureReport: one report per failure code.
    let mut by_code: Vec<(&str, Vec<&str>)> = Vec::new();
    for (id, code) in failed {
        match by_code.iter_mut().find(|(c, _)| c == code) {
            Some((_, ids)) => ids.push(id),
            None => by_code.push((code, vec![id])),
        }
    }
    by_code
        .into_iter()
        .map(|(code, ids)| json!({ "racsIds": ids, "failureCode": code }))
        .collect()
}

fn racs_data_body(p: &context::Provisioning, failed: &[(String, &'static str)]) -> Value {
    let mut body = json!({ "racsConfigs": p.configs });
    if let Some(f) = &p.supp_feat {
        body["suppFeat"] = json!(f);
    }
    if !failed.is_empty() {
        let reports: Map<String, Value> = racs_reports(failed)
            .into_iter()
            .enumerate()
            .map(|(i, r)| (i.to_string(), r))
            .collect();
        body["racsReports"] = Value::Object(reports);
    }
    body
}

fn all_failed(failed: &[(String, &'static str)]) -> SbiResponse {
    SbiResponse::with_status(500)
        .with_json_body(&racs_reports(failed))
        .unwrap_or_else(|e| send_internal_error(&format!("encoding RacsFailureReport: {e}")))
}

/// TS 29.675 §5.2.2.2: `POST /provisionings`.
fn create_provisioning(
    u: &mut Ucmf,
    request: &SbiRequest,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    let (configs, supp_feat) = match racs_configs(request) {
        Ok(c) => c,
        Err(r) => return (r, Vec::new()),
    };
    match u.create_provisioning(&configs, supp_feat, now) {
        (Some(p), failed, note) => {
            let response = SbiResponse::created()
                .with_header(
                    "Location",
                    format!(
                        "{}/{PROVISIONING_API}/v1/provisionings/{}",
                        api_root(),
                        p.id
                    ),
                )
                .with_json_body(&racs_data_body(&p, &failed))
                .unwrap_or_else(|e| send_internal_error(&format!("encoding RacsData: {e}")));
            (response, note.into_iter().collect())
        }
        (None, failed, _) => (all_failed(&failed), Vec::new()),
    }
}

fn get_provisioning(u: &Ucmf, id: &str) -> SbiResponse {
    match u.provisioning(id) {
        Some(p) => SbiResponse::ok()
            .with_json_body(&racs_data_body(p, &[]))
            .unwrap_or_else(|e| send_internal_error(&format!("encoding RacsData: {e}"))),
        None => send_not_found(&format!("No provisioning {id}"), Some("RESOURCE_NOT_FOUND")),
    }
}

type ProvisioningOutcome = Option<
    Result<
        (
            context::Provisioning,
            Vec<(String, &'static str)>,
            Vec<Notification>,
        ),
        Vec<(String, &'static str)>,
    >,
>;

fn provisioning_update_response(
    id: &str,
    outcome: ProvisioningOutcome,
) -> (SbiResponse, Vec<Notification>) {
    match outcome {
        None => (
            send_not_found(&format!("No provisioning {id}"), Some("RESOURCE_NOT_FOUND")),
            Vec::new(),
        ),
        Some(Err(failed)) => (all_failed(&failed), Vec::new()),
        Some(Ok((p, failed, notes))) => (
            SbiResponse::ok()
                .with_json_body(&racs_data_body(&p, &failed))
                .unwrap_or_else(|e| send_internal_error(&format!("encoding RacsData: {e}"))),
            notes,
        ),
    }
}

/// TS 29.675 §5.2.2.3: `PUT /provisionings/{id}`.
fn replace_provisioning(
    u: &mut Ucmf,
    id: &str,
    request: &SbiRequest,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    let (configs, supp_feat) = match racs_configs(request) {
        Ok(c) => c,
        Err(r) => return (r, Vec::new()),
    };
    provisioning_update_response(id, u.replace_provisioning(id, &configs, supp_feat, now))
}

/// TS 29.675 §5.2.2.3: `PATCH /provisionings/{id}` (`application/merge-patch+json`).
fn patch_provisioning(
    u: &mut Ucmf,
    id: &str,
    request: &SbiRequest,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    let (configs, _) = match racs_configs(request) {
        Ok(c) => c,
        Err(r) => return (r, Vec::new()),
    };
    provisioning_update_response(id, u.patch_provisioning(id, &configs, now))
}

/// TS 29.675 §5.2.2.4: `DELETE /provisionings/{id}`.
fn delete_provisioning(
    u: &mut Ucmf,
    id: &str,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    match u.delete_provisioning(id, now) {
        Some(note) => (SbiResponse::no_content(), note.into_iter().collect()),
        None => (
            send_not_found(&format!("No provisioning {id}"), Some("RESOURCE_NOT_FOUND")),
            Vec::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// #570: the AMF's Nucmf_UECapabilityManagement consumer (`nextgcore_amfd::racs`)
    /// against this UCMF over a real HTTP/2 SBI server: Assign, Resolve of the ID it
    /// returned, an unknown ID's 404, and Subscribe. The AMF finds the UCMF through
    /// `UCMF_SBI_ADDR`/`UCMF_SBI_PORT`, its no-NRF fallback.
    #[tokio::test]
    async fn the_amf_consumer_assigns_resolves_and_subscribes() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let ucmf = Arc::new(ucmf());
        let state = ucmf.clone();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let state = state.clone();
                async move { handle(&state, &req, Utc::now()).0 }
            })
            .await
            .expect("UCMF test server starts");
        // The server above is plaintext loopback: a dev-profile deployment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        std::env::set_var("UCMF_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UCMF_SBI_PORT", addr.port().to_string());

        let cap = [0x0Au8, 0x0B, 0x0C];
        let id = nextgcore_amfd::racs::ucmf_assign("35123456", &cap)
            .await
            .expect("Assign");
        // The UCMF's first ID at Version ID 05: digits 1 05 00000000000, packed low
        // nibble first -> 01 05 00 00 00 00 00 (TS 24.501 §9.11.3.68).
        assert_eq!(id, vec![0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // The same TAC and capability get the same ID back (TS 29.673 §5.2.2.3).
        assert_eq!(
            nextgcore_amfd::racs::ucmf_assign("35123456", &cap)
                .await
                .expect("re-Assign"),
            id
        );
        assert_eq!(
            nextgcore_amfd::racs::ucmf_resolve(&id)
                .await
                .expect("Resolve"),
            Some(cap.to_vec())
        );
        let unknown = [0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x90];
        assert_eq!(
            nextgcore_amfd::racs::ucmf_resolve(&unknown)
                .await
                .expect("Resolve"),
            None,
            "404 NO_DICTIONARY_ENTRY_FOUND"
        );
        nextgcore_amfd::racs::ucmf_subscribe("amf-1")
            .await
            .expect("Subscribe");
        let note = ucmf
            .write()
            .unwrap()
            .set_version_id(0x06, Utc::now())
            .expect("the AMF is subscribed");
        assert!(
            note.uris
                .iter()
                .any(|u| u.ends_with("/namf-callback/v1/ucmf-notify")),
            "notifications go to the AMF's callback: {:?}",
            note.uris
        );
        let _ = server.stop().await;
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-21T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn ucmf() -> RwLock<Ucmf> {
        RwLock::new(Ucmf::new(0x05, ModeOfOperation::B))
    }

    fn req(method: &str, uri: &str) -> SbiRequest {
        let mut r = SbiRequest::new();
        r.header.method = method.into();
        r.header.uri = uri.into();
        r
    }

    fn with_json(mut r: SbiRequest, v: Value) -> SbiRequest {
        r.http.content = Some(v.to_string());
        r
    }

    fn body(r: &SbiResponse) -> Value {
        serde_json::from_str(r.http.content.as_deref().unwrap_or("null")).unwrap()
    }

    fn assign_request(tac: &str, nr: &[u8]) -> SbiRequest {
        let mut r = with_json(
            req("POST", "/nucmf-uecm/v1/dic-entries"),
            json!({"typeAllocationCode": tac, "ueRadioCapability5GS": {"contentId": "nr"}}),
        );
        r.http.parts.push(SbiPart::with_content(
            "nr",
            CONTENT_NGAP,
            Bytes::from(nr.to_vec()),
        ));
        r
    }

    fn resolve_request(id_b64: &str, format: Option<&str>) -> SbiRequest {
        let mut r = req("GET", "/nucmf-uecm/v1/dic-entries");
        r.http.params.insert(
            "ue-radio-capa-id".into(),
            json!({"plmnAssiUeRadioCapId": id_b64}).to_string(),
        );
        if let Some(f) = format {
            r.http.params.insert("rac-format".into(), f.into());
        }
        r
    }

    #[test]
    fn assign_then_resolve_over_the_api() {
        let u = ucmf();
        let (r, notes) = handle(&u, &assign_request("35123456", &[0xAA, 0xBB]), now());
        assert_eq!(r.status, 201);
        assert!(notes.is_empty(), "no subscribers yet");
        assert_eq!(
            r.http.get_header("Location").map(String::as_str),
            Some("http://ucmf/nucmf-uecm/v1/dic-entries/1")
        );
        // TS 23.003: Version ID 05, RCI 0 → value octets 01 05 00 00 00 00 00.
        let id = body(&r)["plmnAssiUeRadioCapId"]
            .as_str()
            .unwrap()
            .to_string();
        let ie = base64::engine::general_purpose::STANDARD
            .decode(&id)
            .unwrap();
        assert_eq!(ie, [0x67, 0x07, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let (r, _) = handle(&u, &resolve_request(&id, Some("5GS")), now());
        assert_eq!(r.status, 200);
        let data = body(&r);
        assert_eq!(data["dicEntryId"], 1);
        assert_eq!(data["typeAllocationCode"], "35123456");
        assert_eq!(data["plmnAssiUeRadioCapId"], id);
        assert_eq!(
            data["ueRadioCapability5GS"]["contentId"],
            "ueRadioCapability5GS"
        );
        assert_eq!(r.http.parts.len(), 1);
        assert_eq!(r.http.parts[0].content_type.as_deref(), Some(CONTENT_NGAP));
        assert_eq!(&r.http.parts[0].data[..], &[0xAA, 0xBB]);

        let (r, _) = handle(&u, &req("GET", "/nucmf-uecm/v1/dic-entries/1"), now());
        assert_eq!(r.status, 200);
        assert_eq!(body(&r)["plmnAssiUeRadioCapId"], id);
    }

    /// #585 over the API: a 5GS-only Assign resolves in EPS format, with the S1AP
    /// capability and the EPS paging capability as binary parts.
    #[test]
    fn an_eps_resolve_of_a_5gs_assign_returns_the_transcoded_capability() {
        let u = ucmf();
        let nr = crate::rac::tests::cap_5gs();
        let (r, _) = handle(&u, &assign_request("35123456", &nr), now());
        assert_eq!(r.status, 201);
        let id = body(&r)["plmnAssiUeRadioCapId"]
            .as_str()
            .unwrap()
            .to_string();
        let (r, _) = handle(&u, &resolve_request(&id, Some("EPS")), now());
        assert_eq!(r.status, 200, "{:?}", body(&r));
        let data = body(&r);
        assert_eq!(
            data["ueRadioCapabilityEPS"]["contentId"],
            "ueRadioCapabilityEPS"
        );
        assert_eq!(
            data["ueRadioCapEPSForPaging"]["contentId"],
            "ueRadioCapEPSForPaging"
        );
        let part = |name: &str| {
            r.http
                .parts
                .iter()
                .find(|p| p.content_id.as_deref() == Some(name))
                .unwrap_or_else(|| panic!("no {name} part"))
        };
        assert_eq!(
            part("ueRadioCapabilityEPS").content_type.as_deref(),
            Some(CONTENT_S1AP)
        );
        assert_eq!(
            &part("ueRadioCapabilityEPS").data[..],
            &crate::rac::transcode_5gs_to_eps(&nr).unwrap()[..]
        );
        assert_eq!(
            &part("ueRadioCapEPSForPaging").data[..],
            &crate::rac::derive_paging_eps(&crate::rac::transcode_5gs_to_eps(&nr).unwrap())
                .unwrap()[..]
        );
    }

    #[test]
    fn deleting_a_provisioning_over_the_api_returns_the_deletion_notification() {
        let u = ucmf();
        let (r, _) = handle(
            &u,
            &with_json(
                req("POST", "/nucmf-uecm/v1/subscriptions"),
                json!({"ucmfNotificationUri": "http://amf:7777/racs-notify"}),
            ),
            now(),
        );
        assert_eq!(r.status, 201);
        let create = with_json(
            req("POST", "/nucmf-provisioning/v1/provisionings"),
            provisioning_body("0a0b"),
        );
        assert_eq!(handle(&u, &create, now()).0.status, 201);
        assert_eq!(
            handle(&u, &assign_request("35123456", &[0x0a, 0x0b]), now())
                .0
                .status,
            201,
            "the Assign matches the provisioned entry"
        );
        let (r, notes) = handle(
            &u,
            &req("DELETE", "/nucmf-provisioning/v1/provisionings/1"),
            now(),
        );
        assert_eq!(r.status, 204);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].uris, ["http://amf:7777/racs-notify"]);
        assert_eq!(notes[0].body["eventType"], "DELETION_OF_PLMN_ASSIGNED_IDS");
    }

    fn cause(r: &SbiResponse) -> Value {
        body(r)["cause"].clone()
    }

    #[test]
    fn resolve_errors_carry_the_spec_causes() {
        let u = ucmf();
        let (r, _) = handle(&u, &assign_request("35123456", &[1]), now());
        let id = body(&r)["plmnAssiUeRadioCapId"]
            .as_str()
            .unwrap()
            .to_string();
        let (r, _) = handle(&u, &resolve_request(&id, Some("EPS")), now());
        assert_eq!(
            (r.status, cause(&r)),
            (404, json!("NO_DICTIONARY_ENTRY_FOUND"))
        );
        let unknown = RacsId::plmn_assigned(5, 99).unwrap().to_nucmf();
        let (r, _) = handle(&u, &resolve_request(&unknown, None), now());
        assert_eq!(
            (r.status, cause(&r)),
            (404, json!("NO_DICTIONARY_ENTRY_FOUND"))
        );
        u.write().unwrap().set_version_id(6, now());
        let (r, _) = handle(&u, &resolve_request(&id, None), now());
        assert_eq!(
            (r.status, cause(&r)),
            (404, json!("OUT_DATED_VERSION_ID_IN_RAC_ID"))
        );
        let (r, _) = handle(&u, &resolve_request("not base64!", None), now());
        assert_eq!(r.status, 400);
        let (r, _) = handle(&u, &req("GET", "/nucmf-uecm/v1/dic-entries"), now());
        assert_eq!(
            (r.status, cause(&r)),
            (400, json!("MANDATORY_QUERY_PARAM_MISSING"))
        );
        // A manufacturer ID under the plmnAssi member is refused.
        let man = RacsId::from_digit_str("000007ed900000000abc")
            .unwrap()
            .to_nucmf();
        let (r, _) = handle(&u, &resolve_request(&man, None), now());
        assert_eq!(r.status, 400);
    }

    #[test]
    fn assign_refuses_malformed_input() {
        let u = ucmf();
        let (r, _) = handle(&u, &assign_request("1234", &[1]), now());
        assert_eq!(r.status, 400);
        let mut missing_part = assign_request("35123456", &[1]);
        missing_part.http.parts.clear();
        let (r, _) = handle(&u, &missing_part, now());
        assert_eq!(r.status, 400);
        let no_cap = with_json(
            req("POST", "/nucmf-uecm/v1/dic-entries"),
            json!({"typeAllocationCode": "35123456"}),
        );
        let (r, _) = handle(&u, &no_cap, now());
        assert_eq!((r.status, cause(&r)), (400, json!("MANDATORY_IE_MISSING")));
    }

    #[test]
    fn subscribe_notify_unsubscribe_over_the_api() {
        let u = ucmf();
        let sub = with_json(
            req("POST", "/nucmf-uecm/v1/subscriptions"),
            json!({"ucmfNotificationUri": "http://amf:7777/racs-notify", "nfId": "a1"}),
        );
        let (r, _) = handle(&u, &sub, now());
        assert_eq!(r.status, 201);
        let location = r.http.get_header("Location").cloned().unwrap();
        assert!(location.ends_with("/nucmf-uecm/v1/subscriptions/1"));
        assert_eq!(body(&r)["dicEntryId"], 0);
        assert!(body(&r)["confirmedExpires"].is_string());

        let (_, notes) = handle(&u, &assign_request("35123456", &[1]), now());
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].uris, ["http://amf:7777/racs-notify"]);
        assert_eq!(notes[0].body["eventType"], "CREATION_OF_DICTIONARY_ENTRY");
        assert_eq!(notes[0].body["dicEntryId"], 1);

        let (r, _) = handle(&u, &req("DELETE", "/nucmf-uecm/v1/subscriptions/1"), now());
        assert_eq!(r.status, 204);
        let (r, _) = handle(&u, &req("DELETE", "/nucmf-uecm/v1/subscriptions/1"), now());
        assert_eq!(
            (r.status, cause(&r)),
            (404, json!("SUBSCRIPTION_NOT_FOUND"))
        );
        let bad = with_json(
            req("POST", "/nucmf-uecm/v1/subscriptions"),
            json!({"nfId": "a1"}),
        );
        assert_eq!(handle(&u, &bad, now()).0.status, 400);
    }

    const MAN: &str = "000007ed900000000abc";

    fn provisioning_body(nr_hex: &str) -> Value {
        json!({"racsConfigs": {MAN: {"imeiTacs": ["35123456"], "racsParam5Gs": nr_hex}}})
    }

    #[test]
    fn provisioning_lifecycle_over_the_api() {
        let u = ucmf();
        let create = with_json(
            req("POST", "/nucmf-provisioning/v1/provisionings"),
            provisioning_body("0a0b"),
        );
        let (r, _) = handle(&u, &create, now());
        assert_eq!(r.status, 201);
        assert!(r
            .http
            .get_header("Location")
            .unwrap()
            .ends_with("/nucmf-provisioning/v1/provisionings/1"));
        assert_eq!(body(&r)["racsConfigs"][MAN]["racsParam5Gs"], "0a0b");

        // The provisioned manufacturer-assigned ID now resolves.
        let mut q = req("GET", "/nucmf-uecm/v1/dic-entries");
        let man = RacsId::from_digit_str(MAN).unwrap().to_nucmf();
        q.http.params.insert(
            "ue-radio-capa-id".into(),
            json!({"manAssiUeRadioCapId": man}).to_string(),
        );
        let (r, _) = handle(&u, &q, now());
        assert_eq!(r.status, 200);
        assert_eq!(body(&r)["manAssiUeRadioCapId"], man);

        // A duplicate RACS ID: nothing provisioned → 500 with RacsFailureReport.
        let (r, _) = handle(&u, &create, now());
        assert_eq!(r.status, 500);
        assert_eq!(
            body(&r),
            json!([{"racsIds": [MAN], "failureCode": "RACS_ID_DUPLICATED"}])
        );

        let (r, _) = handle(
            &u,
            &req("GET", "/nucmf-provisioning/v1/provisionings/1"),
            now(),
        );
        assert_eq!(r.status, 200);
        let patch = with_json(
            req("PATCH", "/nucmf-provisioning/v1/provisionings/1"),
            json!({"racsConfigs": {MAN: {"racsParam5Gs": "ff"}}}),
        );
        let (r, _) = handle(&u, &patch, now());
        assert_eq!(r.status, 200);
        assert_eq!(body(&r)["racsConfigs"][MAN]["racsParam5Gs"], "ff");
        let put = with_json(
            req("PUT", "/nucmf-provisioning/v1/provisionings/1"),
            provisioning_body("0c"),
        );
        assert_eq!(handle(&u, &put, now()).0.status, 200);
        let (r, _) = handle(
            &u,
            &req("DELETE", "/nucmf-provisioning/v1/provisionings/1"),
            now(),
        );
        assert_eq!(r.status, 204);
        let (r, _) = handle(
            &u,
            &req("DELETE", "/nucmf-provisioning/v1/provisionings/1"),
            now(),
        );
        assert_eq!(r.status, 404);
        let (r, _) = handle(&u, &q, now());
        assert_eq!(r.status, 404);
    }

    // ----------------------------------------------------------------- #725

    /// The issue's request: `"aéa"` is four bytes, passed the even-length check,
    /// and panicked slicing across the `é` with the state write lock held.
    const BAD_RACS_BODY: &str = r#"{"racsConfigs":{"000007ed900000000abc":{"imeiTacs":["12345678"],"racsParam5Gs":"aéa"}}}"#;

    fn raw_body(mut r: SbiRequest, body: &str) -> SbiRequest {
        r.http.content = Some(body.to_string());
        r
    }

    /// Assign a capability and resolve it by entry ID: both locks, both services.
    fn assert_still_serving(u: &RwLock<Ucmf>) {
        let (r, _) = handle(u, &assign_request("35123456", &[0x5A]), now());
        assert_eq!(
            r.status,
            201,
            "Assign after the bad request: {:?}",
            body(&r)
        );
        let entry = r
            .http
            .get_header("Location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        let (r, _) = handle(
            u,
            &req("GET", &format!("/nucmf-uecm/v1/dic-entries/{entry}")),
            now(),
        );
        assert_eq!(
            r.status,
            200,
            "Resolve after the bad request: {:?}",
            body(&r)
        );
        assert!(!u.is_poisoned());
    }

    #[test]
    fn a_non_ascii_racs_param_is_other_reason_and_the_ucmf_keeps_serving() {
        let u = ucmf();
        let (r, _) = handle(
            &u,
            &raw_body(
                req("POST", "/nucmf-provisioning/v1/provisionings"),
                BAD_RACS_BODY,
            ),
            now(),
        );
        assert_eq!(r.status, 500);
        assert_eq!(
            body(&r),
            json!([{"racsIds": [MAN], "failureCode": "OTHER_REASON"}])
        );
        assert!(
            !u.is_poisoned(),
            "the bad request must not poison the state lock"
        );

        // The same value through PUT and PATCH of an existing provisioning.
        let create = with_json(
            req("POST", "/nucmf-provisioning/v1/provisionings"),
            provisioning_body("0a0b"),
        );
        assert_eq!(handle(&u, &create, now()).0.status, 201);
        for method in ["PUT", "PATCH"] {
            let (r, _) = handle(
                &u,
                &raw_body(
                    req(method, "/nucmf-provisioning/v1/provisionings/1"),
                    BAD_RACS_BODY,
                ),
                now(),
            );
            assert_eq!(r.status, 500, "{method}");
            assert_eq!(body(&r)[0]["failureCode"], "OTHER_REASON", "{method}");
        }
        // A refused replace leaves the provisioning as it was.
        let (r, _) = handle(
            &u,
            &req("GET", "/nucmf-provisioning/v1/provisionings/1"),
            now(),
        );
        assert_eq!(body(&r)["racsConfigs"][MAN]["racsParam5Gs"], "0a0b");
        assert_still_serving(&u);
    }

    /// Whatever panics under the lock, later requests are still served: the
    /// lock is recovered, not refused with `500 "UCMF state lock poisoned"`.
    #[test]
    fn a_poisoned_state_lock_is_recovered_not_refused() {
        let u = Arc::new(ucmf());
        let held = u.clone();
        let _ = std::thread::spawn(move || {
            let _guard = held.write().unwrap();
            panic!("a request handler panicking with the state write lock held");
        })
        .join();
        assert!(u.is_poisoned(), "the test must start from a poisoned lock");
        let (r, _) = handle(&u, &req("GET", "/nucmf-uecm/v1/dic-entries/1"), now());
        assert_eq!(
            (r.status, cause(&r)),
            (404, json!("NO_DICTIONARY_ENTRY_FOUND"))
        );
        assert!(!u.is_poisoned());
        assert_still_serving(&u);

        // Poisoned again, and this time the first request after is a write.
        let held = u.clone();
        let _ = std::thread::spawn(move || {
            let _guard = held.write().unwrap();
            panic!("again");
        })
        .join();
        assert!(u.is_poisoned());
        assert_still_serving(&u);
    }

    /// The issue's scenario end to end over HTTP/2: the bad provisioning, then
    /// good requests on both services, through the real SBI server (whose
    /// `catch_handler_panic` is what used to hide the poisoning).
    #[tokio::test]
    async fn over_http_a_bad_racs_param_is_refused_and_the_next_requests_are_served() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let state = Arc::new(ucmf());
        let shared = state.clone();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let state = shared.clone();
                async move { handle(&state, &req, Utc::now()).0 }
            })
            .await
            .expect("UCMF test server starts");
        let client = SbiClient::with_host_port("127.0.0.1", addr.port());
        let send = |r: SbiRequest| {
            let client = &client;
            async move { client.send_request(r).await.expect("the UCMF answers") }
        };
        let json_of = |r: &SbiResponse| -> Value {
            serde_json::from_str(r.http.content.as_deref().unwrap_or("null")).unwrap()
        };
        let bad: Value = serde_json::from_str(BAD_RACS_BODY).unwrap();

        let r = send(
            SbiRequest::post("/nucmf-provisioning/v1/provisionings")
                .with_json_body(&bad)
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, 500);
        assert_eq!(json_of(&r)[0]["failureCode"], "OTHER_REASON");

        let r = send(
            SbiRequest::post("/nucmf-provisioning/v1/provisionings")
                .with_json_body(&provisioning_body("0a0b"))
                .unwrap(),
        )
        .await;
        assert_eq!(
            r.status,
            201,
            "a good provisioning after the bad one: {:?}",
            json_of(&r)
        );
        let r = send(
            SbiRequest::patch("/nucmf-provisioning/v1/provisionings/1")
                .with_json_body(&bad)
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, 500);
        let r = send(SbiRequest::get("/nucmf-provisioning/v1/provisionings/1")).await;
        assert_eq!(r.status, 200);
        assert_eq!(json_of(&r)["racsConfigs"][MAN]["racsParam5Gs"], "0a0b");
        // Nucmf_UECapabilityManagement too: the provisioned entry by its ID.
        let r = send(SbiRequest::get("/nucmf-uecm/v1/dic-entries/1")).await;
        assert_eq!(r.status, 200, "{:?}", json_of(&r));
        assert_eq!(
            json_of(&r)["manAssiUeRadioCapId"],
            RacsId::from_digit_str(MAN).unwrap().to_nucmf()
        );
        assert!(!state.is_poisoned());
        let _ = server.stop().await;
    }

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        fn method() -> impl Strategy<Value = &'static str> {
            prop_oneof![
                Just("GET"),
                Just("POST"),
                Just("PUT"),
                Just("PATCH"),
                Just("DELETE")
            ]
        }

        fn path() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("/nucmf-provisioning/v1/provisionings".to_string()),
                Just("/nucmf-provisioning/v1/provisionings/1".to_string()),
                Just("/nucmf-uecm/v1/dic-entries".to_string()),
                Just("/nucmf-uecm/v1/subscriptions".to_string()),
                "/nucmf-(uecm|provisioning)/v1/[a-z-]{0,12}/.{0,8}",
            ]
        }

        /// JSON values shaped like the request bodies, with arbitrary leaves.
        fn json_leaf() -> impl Strategy<Value = Value> {
            prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::from),
                any::<i64>().prop_map(Value::from),
                any::<String>().prop_map(Value::from),
                "[0-9a-f]{0,64}".prop_map(Value::from),
                // Mostly hex, now and then a multi-byte character (#725).
                "[0-9a-fA-Fé€]{0,16}".prop_map(Value::from),
                "[0-9]{8}".prop_map(|t| json!([t])),
            ]
        }

        fn body() -> impl Strategy<Value = String> {
            let config = proptest::collection::btree_map(
                prop_oneof![
                    Just("imeiTacs".to_string()),
                    Just("racsParam5Gs".to_string()),
                    Just("racsParamEps".to_string()),
                    ".{0,6}",
                ],
                json_leaf(),
                0..4,
            );
            // A well-formed RacsConfiguration whose parameter alone is arbitrary,
            // so the hex decoder is reached on most cases rather than few.
            let well_formed = (
                "0[0-9a-f]{19}",
                "[0-9a-fA-Fé€ ]{0,16}|.{0,16}",
                any::<bool>(),
            )
                .prop_map(|(key, param, eps)| {
                    let member = if eps { "racsParamEps" } else { "racsParam5Gs" };
                    json!({"racsConfigs": {key: {"imeiTacs": ["35123456"], member: param}}})
                        .to_string()
                });
            prop_oneof![
                2 => well_formed,
                1 => proptest::collection::btree_map("0[0-9a-f]{19}|.{0,22}", config, 0..3)
                    .prop_map(|m| json!({ "racsConfigs": m }).to_string()),
                1 => proptest::collection::btree_map(".{0,24}", json_leaf(), 0..4)
                    .prop_map(|m| json!(m).to_string()),
                1 => any::<String>(),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            /// Arbitrary requests at every route: each is answered, none panics,
            /// and afterwards the UCMF still serves a good Assign and Resolve.
            #[test]
            fn arbitrary_requests_never_panic_or_wedge_the_ucmf(
                reqs in proptest::collection::vec(
                    (method(), path(), body(), proptest::collection::vec(any::<u8>(), 0..48)),
                    1..6,
                ),
            ) {
                let u = ucmf();
                for (m, p, b, part) in reqs {
                    let mut r = raw_body(req(m, &p), &b);
                    r.http.parts.push(SbiPart::with_content("nr", CONTENT_NGAP, Bytes::from(part)));
                    let (resp, _) = handle(&u, &r, now());
                    prop_assert!((200..600).contains(&resp.status));
                    prop_assert!(!u.is_poisoned());
                }
                assert_still_serving(&u);
            }

            /// Assign with arbitrary capability bytes in every format.
            #[test]
            fn an_assign_with_arbitrary_capability_bytes_is_answered(
                parts in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 4),
            ) {
                let u = ucmf();
                let names = ["ueRadioCapability5GS", "ueRadioCapabilityEPS", "ueRadioCap5GSForPaging", "ueRadioCapEPSForPaging"];
                let mut j = json!({"typeAllocationCode": "35123456"});
                let mut r = req("POST", "/nucmf-uecm/v1/dic-entries");
                for (name, bytes) in names.iter().zip(parts) {
                    j[*name] = json!({"contentId": name});
                    r.http.parts.push(SbiPart::with_content(*name, CONTENT_NGAP, Bytes::from(bytes)));
                }
                let r = with_json(r, j);
                let (resp, _) = handle(&u, &r, now());
                prop_assert!(resp.status == 201 || resp.status == 400, "{}", resp.status);
                prop_assert!(!u.is_poisoned());
            }
        }
    }

    /// #786: past the caps, Assign and Subscribe answer 500
    /// INSUFFICIENT_RESOURCES (TS 29.500 Table 5.2.7.2-1).
    #[test]
    fn past_the_caps_assign_and_subscribe_are_insufficient_resources() {
        let u = ucmf();
        u.write().unwrap().set_limits(context::Limits {
            max_dic_entries: 1,
            max_subscriptions: 1,
            max_subscriptions_per_consumer: 1,
        });
        assert_eq!(
            handle(&u, &assign_request("35123456", &[1]), now())
                .0
                .status,
            201
        );
        let (r, _) = handle(&u, &assign_request("35123456", &[2]), now());
        assert_eq!(
            (r.status, cause(&r)),
            (500, json!("INSUFFICIENT_RESOURCES"))
        );
        let sub = || {
            with_json(
                req("POST", "/nucmf-uecm/v1/subscriptions"),
                json!({"ucmfNotificationUri": "http://amf:7777/racs-notify"}),
            )
        };
        assert_eq!(handle(&u, &sub(), now()).0.status, 201);
        let (r, _) = handle(&u, &sub(), now());
        assert_eq!(
            (r.status, cause(&r)),
            (500, json!("INSUFFICIENT_RESOURCES"))
        );
    }

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-ucmfd"]);
        assert_eq!(args.sbi_addr, "127.0.0.1");
    }

    #[test]
    fn the_limits_are_configurable() {
        let args = Args::parse_from(["nextgcore-ucmfd"]);
        let s = settle(&args, None).unwrap();
        assert_eq!(s.limits, context::Limits::default());
        let yaml =
            "ucmf:\n  limits:\n    max_dic_entries: 5\n    max_subscriptions_per_consumer: 2\n";
        let s = settle(&args, Some(yaml)).unwrap();
        assert_eq!(
            s.limits,
            context::Limits {
                max_dic_entries: 5,
                max_subscriptions: context::Limits::default().max_subscriptions,
                max_subscriptions_per_consumer: 2,
            }
        );
    }

    /// The metrics text carries the poison-recovery counter and the gauges, and
    /// the endpoint defaults to loopback.
    #[test]
    fn metrics_report_poison_recoveries_and_capacity() {
        let u = Arc::new(ucmf());
        handle(&u, &assign_request("35123456", &[1]), now());
        let before = POISON_RECOVERIES.load(Ordering::Relaxed);
        let held = u.clone();
        let _ = std::thread::spawn(move || {
            let _guard = held.write().unwrap();
            panic!("poison");
        })
        .join();
        handle(&u, &req("GET", "/nucmf-uecm/v1/dic-entries/1"), now());
        assert!(POISON_RECOVERIES.load(Ordering::Relaxed) > before);
        let text = render_metrics(Some(&u));
        assert!(text.contains("# TYPE ucmf_state_lock_poison_recoveries_total counter\n"));
        assert!(text.contains("\nucmf_dictionary_entries 1\n"), "{text}");
        assert!(text.contains("\nucmf_subscriptions 0\n"));
        assert_eq!(metrics_addr(None), SocketAddr::from(([127, 0, 0, 1], 9096)));
        assert_eq!(
            metrics_addr(Some("not-an-address")),
            SocketAddr::from(([127, 0, 0, 1], 9096)),
            "a bad value falls back to loopback"
        );
        assert_eq!(
            metrics_addr(Some("10.0.0.5:9100")),
            "10.0.0.5:9100".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn unknown_paths_and_methods_are_refused() {
        let u = ucmf();
        assert_eq!(
            handle(&u, &req("GET", "/nucmf-uecm/v1/nope"), now())
                .0
                .status,
            404
        );
        assert_eq!(
            handle(&u, &req("PUT", "/nucmf-uecm/v1/dic-entries"), now())
                .0
                .status,
            405
        );
        assert_eq!(
            handle(&u, &req("GET", "/nucmf-uecm/v1/dic-entries/x"), now())
                .0
                .status,
            400
        );
    }

    #[test]
    fn the_nf_profile_advertises_both_ucmf_services() {
        let p = nf_profile("id-1", "10.0.0.9", 7777, "http");
        assert_eq!(p["nfType"], "UCMF");
        let names: Vec<&str> = p["nfServices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["serviceName"].as_str().unwrap())
            .collect();
        // TS 29.510 ServiceName values.
        assert_eq!(
            names,
            ["nucmf-uecapabilitymanagement", "nucmf-provisioning"]
        );
        assert_eq!(p["nfServices"][0]["supportedFeatures"], "1");
    }

    #[test]
    fn configuration_is_settled_from_yaml_with_cli_overrides() {
        let args = Args::parse_from(["nextgcore-ucmfd"]);
        let yaml = "ucmf:\n  nrf:\n    uri: http://nrf:7777\n  version_id: \"0A\"\n  mode: A\n  state_file: /tmp/u.json\n";
        let s = settle(&args, Some(yaml)).unwrap();
        assert_eq!(s.nrf_uri, "http://nrf:7777");
        assert_eq!(s.version_id, 0x0A);
        assert_eq!(s.mode, ModeOfOperation::A);
        assert_eq!(s.state_file.as_deref(), Some("/tmp/u.json"));
        let args = Args::parse_from(["nextgcore-ucmfd", "--version-id", "1f", "--mode", "B"]);
        let s = settle(&args, Some(yaml)).unwrap();
        assert_eq!((s.version_id, s.mode), (0x1F, ModeOfOperation::B));
        assert!(settle(
            &Args::parse_from(["nextgcore-ucmfd", "--version-id", "100"]),
            None
        )
        .is_err());
    }
}

/// #1322: no wildcard reaches the apiRoot (Location headers, resource URIs).
#[cfg(test)]
mod tests_api_root_1322 {
    use super::ucmf_api_root;
    use nextgcore_core::sockaddr::SbiEndpoint;

    #[test]
    fn the_api_root_is_the_advertised_host_never_a_wildcard() {
        let ep = |host: &str, advertise: Option<&str>| SbiEndpoint {
            host: host.into(),
            port: 7777,
            advertise: advertise.map(str::to_string),
        };
        assert_eq!(
            ucmf_api_root("https", &ep("0.0.0.0", Some("10.0.0.39"))).unwrap(),
            "https://10.0.0.39:7777"
        );
        for wildcard in ["0.0.0.0", "::"] {
            let e = ucmf_api_root("http", &ep(wildcard, None)).unwrap_err();
            assert!(e.starts_with("refusing to start"), "{e}");
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
            let profile = nf_profile("id", host, 7777, "http");
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}
