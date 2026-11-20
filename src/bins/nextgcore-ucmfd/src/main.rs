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
use nextgcore_sbi::owner_binding; // #1862, on the shared #1865 helper
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
use nextgcore_sbi::client::SbiClient;
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
use std::collections::BTreeMap;
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
    /// Nucmf_Provisioning policy (#1939).
    provisioning: Option<ProvisioningYaml>,
}

/// `ucmf.provisioning` (#1939). Both members optional; absent means no
/// restriction beyond the NEF / AF consumer rule and the creator binding.
#[derive(Debug, Default, Deserialize)]
struct ProvisioningYaml {
    /// NF Instance IDs of the AFs trusted to provision directly (TS 29.675
    /// §4.1.3.2). Absent: any AF that reaches this SBI.
    trusted_afs: Option<Vec<String>>,
    /// Consumer NF Instance ID -> TS 23.003 §29.2 Vendor IDs (8 hex digits) it
    /// may provision. Absent or empty: no restriction.
    vendor_ids: Option<BTreeMap<String, Vec<String>>>,
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
    provisioning: context::ProvisioningPolicy,
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
        provisioning: {
            let p = section.provisioning.unwrap_or_default();
            let mut vendor_ids = BTreeMap::new();
            for (consumer, vendors) in p.vendor_ids.unwrap_or_default() {
                let parsed = vendors
                    .iter()
                    .map(|v| {
                        let v = v.trim();
                        anyhow::ensure!(
                            v.len() == 8 && v.chars().all(|c| c.is_ascii_hexdigit()),
                            "ucmf.provisioning.vendor_ids.{consumer}: a Vendor ID is 8 \
                             hexadecimal digits (TS 23.003 §29.2), got '{v}'"
                        );
                        Ok(u32::from_str_radix(v, 16)?)
                    })
                    .collect::<Result<Vec<u32>>>()?;
                vendor_ids.insert(consumer, parsed);
            }
            context::ProvisioningPolicy {
                trusted_afs: p.trusted_afs,
                vendor_ids,
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

/// #1665: the outbound OAuth2 client this UCMF installs at startup: under the
/// `production` SBI profile or the `sbi.oauth2.require` knob, when an NRF is
/// configured (see [`nextgcore_sbi::oauth::outbound_oauth2_client`]).
fn outbound_oauth2_client(
    profile: nextgcore_sbi::security::SbiProfile,
    require_oauth2: bool,
    nrf_uri: Option<&str>,
) -> Option<Arc<OAuth2Client>> {
    nextgcore_sbi::oauth::outbound_oauth2_client(profile, require_oauth2, nrf_uri, NfType::Ucmf)
}

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

/// #1795: the UCMF's SBI listener under the SBI security profile. Under
/// `production`: TLS from `policy`'s certificate paths (whatever `--tls` or the
/// config file said), the client certificate verified against its CA, and an
/// access token required, with UCMF as the audience and the NRF's JWKS unless
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
        nextgcore_sbi::types::NfType::Ucmf,
        nrf_uri,
    )
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
    ucmf.set_provisioning_policy(settings.provisioning.clone());
    log::info!("Provisioning policy: {:?}", settings.provisioning);
    // #1989 review m1: both rules are opt-in; say so where an operator looks.
    if nextgcore_sbi::security::SbiProfile::resolve().is_production()
        && settings.provisioning.trusted_afs.is_none()
        && settings.provisioning.vendor_ids.is_empty()
    {
        log::warn!(
            "ucmf.provisioning sets neither trusted_afs nor vendor_ids: any NEF, and any AF that \
             reaches this SBI, may provision manufacturer-assigned RACS IDs of any vendor \
             (TS 29.675 §4.1.3.2). Configure them to restrict provisioning."
        );
    }
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
    // #1665: the outbound token client follows the SBI security profile as well
    // as the knob. The production profile's AMF/AUSF/SMF/UDM demand a token on
    // every service request (TS 33.501 §13.4.1.1.2), whatever this listener asks.
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    if let Some(oauth2) = outbound_oauth2_client(
        sbi_profile,
        settings.require_oauth2,
        Some(&settings.nrf_uri),
    ) {
        let _ = OAUTH2_CLIENT.set(oauth2);
        // #1667: the same client gives this NF's own NRF calls their access token.
        nextgcore_sbi::nrf_tls::set_nrf_oauth2_client(OAUTH2_CLIENT.get().cloned());
    }
    if settings.require_oauth2 {
        // TS 33.501 §13.4.1: verify Bearer tokens against the NRF JWKS, with
        // this NF's type as the required audience.
        sbi_config.require_oauth2 = true;
        sbi_config.oauth2_jwks_uri =
            Some(JwksCache::for_nrf(&settings.nrf_uri).jwks_uri().to_string());
        sbi_config = sbi_config.with_expected_audience_nf_type(NfType::Ucmf);
        log::info!("OAuth2 enforcement enabled");
    }
    // #1795: the listener follows the SBI security profile.
    let sbi_config = sbi_listener_config(
        sbi_config,
        sbi_profile,
        &nextgcore_sbi::security::SbiSecurityPolicy::for_profile(sbi_profile),
        &settings.nrf_uri,
    )
    .map_err(|e| anyhow::anyhow!("SBI security profile: {e}"))?;

    let sbi_server = SbiServer::new(sbi_config);
    sbi_server
        .start(ucmf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;
    log::info!("SBI server listening on {addr}");
    let ucmf_metrics_addr = metrics_addr(std::env::var("UCMF_METRICS_ADDR").ok().as_deref());
    match nextgcore_metrics::nes_energy::serve_metrics(
        ucmf_metrics_addr,
        Arc::new(|| render_metrics(UCMF.get().map(|u| u.as_ref()))),
    )
    .await
    {
        Ok((bound, _handle)) => log::info!("UCMF metrics on http://{bound}/metrics"),
        // #2056: fatal at start-up under the production profile.
        Err(e) => {
            nextgcore_metrics::nf::listener_bind_failed("UCMF", "metrics", ucmf_metrics_addr, &e)
        }
    }

    global_context().set_nrf_uri(&settings.nrf_uri).await;
    // #1482: a failed attempt is retried in the background, and the heartbeat
    // starts after the one that succeeds.
    match sbi.registration_host() {
        Ok(host) => {
            let (host, port, id) = (host.to_string(), sbi.port, nf_instance_id.clone());
            nextgcore_sbi::heartbeat::register_or_retry(
                "UCMF",
                Default::default(),
                move || {
                    let (host, id) = (host.clone(), id.clone());
                    async move {
                        register_with_nrf(&host, port, scheme, &id)
                            .await
                            .map(|()| Some(id))
                    }
                },
                |nf_instance_id| {
                    nextgcore_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5)
                },
            )
            .await;
        }
        Err(e) => log::warn!("NRF registration not attempted (will operate without NRF): {e}"),
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
        // #1939 item 4: no SCP. An SCP forwards the consumer's token, or asks the
        // NRF for one ON BEHALF of the consumer, with the consumer's NF type
        // (TS 33.501 §13.4.1.2); listed here it could obtain a provisioning
        // token of its own.
        &["NEF", "AF"],
    );
    nextgcore_sbi::nf_addressing::classify_profile_host(
        json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "UCMF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": [uecm, provisioning],
            "allowedNfTypes": ["AMF", "MME", "NEF", "AF", "SCP"],
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
                nextgcore_sbi::security::sbi_peer_client_config(&host, port)
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
    // #1989 review M1: who may provision is decided before `handle`, here,
    // because proving a caller relayed by an SCP is a NEF takes an NRF lookup.
    if is_provisioning_path(&request.header.uri) {
        let policy = read_state(ucmf).provisioning_policy().clone();
        if let Some(refusal) = provisioner_refusal(&policy, &request, caller_is_nef).await {
            return refusal;
        }
    }
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

    // #1916: Nucmf_Provisioning is the NEF's and the AF's (TS 29.675 §4.1.3.2),
    // never an AMF's, whatever nucmf token it holds. Refused before any lookup.
    if parts.first() == Some(&PROVISIONING_API) {
        if let Some(refusal) = refuse_provisioning_consumer(request) {
            return (refusal, Vec::new());
        }
    }

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
            "DELETE" => (unsubscribe(&mut write_state(ucmf), id, request), Vec::new()),
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
            "GET" => (get_provisioning(&read_state(ucmf), id, request), Vec::new()),
            "PUT" => replace_provisioning(&mut write_state(ucmf), id, request, now),
            "PATCH" => patch_provisioning(&mut write_state(ucmf), id, request, now),
            "DELETE" => delete_provisioning(&mut write_state(ucmf), id, request, now),
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
    // #1862: bound to the identity this process verified, not the claimed nfId.
    let owner = match owner_binding::owner_for_new_resource(request, "Subscribe") {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
    let sub = match u.subscribe_owned(nf_id, uri.to_string(), suggested, now, owner) {
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

/// TS 29.673 §5.2.2.5 Unsubscribe, by the consumer that subscribed only
/// (#1862): another NF gets 403 and the subscription stays.
fn unsubscribe(u: &mut Ucmf, id: &str, request: &SbiRequest) -> SbiResponse {
    if let Some(sub) = u.subscription(id) {
        if let Some(refused) =
            owner_binding::refuse_non_owner(sub.owner.as_deref(), request, "Unsubscribe")
        {
            return refused;
        }
    }
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
    // #1916: bound to the creating NEF / AF's verified identity; disagreeing
    // identities create nothing.
    let owner = match provisioning_owner_in(request, production_profile()) {
        Ok(owner) => owner,
        Err(refusal) => return (*refusal, Vec::new()),
    };
    let (configs, refused) = vet_racs_ids(u.provisioning_policy(), request, configs);
    if configs.is_empty() {
        return (all_failed(&refused), Vec::new());
    }
    match u.create_provisioning_owned(&configs, supp_feat, now, owner) {
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
                .with_json_body(&racs_data_body(&p, &[failed, refused].concat()))
                .unwrap_or_else(|e| send_internal_error(&format!("encoding RacsData: {e}")));
            (response, note.into_iter().collect())
        }
        (None, failed, _) => (all_failed(&[failed, refused].concat()), Vec::new()),
    }
}

fn get_provisioning(u: &Ucmf, id: &str, request: &SbiRequest) -> SbiResponse {
    if let Some(refusal) = refuse_non_creator(u, id, request, "Get provisioning") {
        return refusal;
    }
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

/// TS 29.675 §4.1.3.2: the known Nucmf_Provisioning consumers.
const PROVISIONING_CONSUMER_NF_TYPES: &[&str] = &["NEF", "AF"];

/// The `403` for a caller whose verified client certificate names an NF type
/// that is not a Nucmf_Provisioning consumer (#1916). A relay certificate (SCP,
/// SEPP) says nothing about the consumer, so it is left to the token, whose
/// `nucmf-provisioning` scope the NRF grants only to the NF types this UCMF's
/// profile allows ([`nf_profile`]). No certificate (`dev`) changes nothing.
fn refuse_provisioning_consumer(request: &SbiRequest) -> Option<SbiResponse> {
    let types = &request.peer_cert_nf_types;
    let is = |set: &[&str]| {
        types
            .iter()
            .any(|t| set.iter().any(|s| s.eq_ignore_ascii_case(t)))
    };
    if types.is_empty() || is(owner_binding::RELAY_NF_TYPES) || is(PROVISIONING_CONSUMER_NF_TYPES) {
        return None;
    }
    let why = format!(
        "Nucmf_Provisioning is consumed by the NEF and the AF only (TS 29.675 §4.1.3.2); \
         the requester's certificate names {types:?}"
    );
    log::debug!("{why}");
    Some(nextgcore_sbi::server::send_forbidden(&why, None))
}

/// Whether `uri` names the Nucmf_Provisioning API.
fn is_provisioning_path(uri: &str) -> bool {
    let path = uri.split('?').next().unwrap_or(uri);
    path.trim_start_matches('/').split('/').next() == Some(PROVISIONING_API)
}

/// The `403` for a caller that may not provision directly when
/// `ucmf.provisioning.trusted_afs` is set (#1939 item 5; #1989 review M1), or
/// `None` to go on. TS 29.675 §4.1.3.2: the NEF provisions (also for an
/// untrusted AF), and a TRUSTED AF provisions directly.
///
/// Decided by the caller's VERIFIED identity, never by what its certificate
/// type alone suggests (an SCP's certificate says nothing about the consumer,
/// and a certificate may name no type at all):
/// - a listed trusted AF is admitted;
/// - anyone else must prove it is a NEF: by the NF types of its own certificate
///   when it calls directly, otherwise (relayed by an SCP or SEPP, identified by
///   a token alone, or a certificate naming no types) by its NRF profile, via
///   `is_nef`, which fails closed;
/// - a caller with no verified identity, or two that disagree, is refused.
///
/// Unset `trusted_afs` admits everyone here (the #1916 rules still apply).
async fn provisioner_refusal<F, Fut>(
    policy: &context::ProvisioningPolicy,
    request: &SbiRequest,
    is_nef: F,
) -> Option<SbiResponse>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<bool, String>>,
{
    policy.trusted_afs.as_ref()?;
    let refuse = |why: String| {
        let why = format!("only the NEF or a trusted AF provisions (TS 29.675 §4.1.3.2): {why}");
        log::debug!("{why}");
        Some(nextgcore_sbi::server::send_forbidden(&why, None))
    };
    let caller = match owner_binding::verified_consumer_id(request) {
        Ok(Some(caller)) => caller,
        Ok(None) => return refuse("the requester has no verified identity".into()),
        Err(why) => return refuse(why),
    };
    if policy.trusts_af(Some(&caller)) {
        return None;
    }
    let types = &request.peer_cert_nf_types;
    let relayed = types.iter().any(|t| {
        owner_binding::RELAY_NF_TYPES
            .iter()
            .any(|r| r.eq_ignore_ascii_case(t))
    });
    let direct_typed = request.peer_cert_nf_instance_id.is_some() && !relayed && !types.is_empty();
    if direct_typed {
        if types.iter().any(|t| t.eq_ignore_ascii_case("NEF")) {
            return None;
        }
        return refuse(format!(
            "{caller} is not in ucmf.provisioning.trusted_afs and its certificate names {types:?}"
        ));
    }
    match is_nef(caller.clone()).await {
        Ok(true) => None,
        Ok(false) => refuse(format!(
            "{caller} is not in ucmf.provisioning.trusted_afs and its NRF profile is not a NEF"
        )),
        Err(why) => refuse(format!(
            "{caller} is not in ucmf.provisioning.trusted_afs and could not be shown to be a NEF \
             ({why})"
        )),
    }
}

/// #1998: how long an NRF answer about whether a caller is a NEF is reused.
const NEF_LOOKUP_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// #1998: at most this many cached answers; a full cache drops the expired
/// ones, then everything, rather than grow.
const NEF_LOOKUP_CACHE_MAX: usize = 1024;

/// #1998: verified NF Instance ID (lowercase) -> (it is a NEF, when learnt).
/// Positive and negative answers both; a failed lookup is never cached (it
/// fails closed, and the next request asks again). As ausfd's
/// `CALLER_TYPE_CACHE` (#1964).
static NEF_LOOKUP_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, (bool, std::time::Instant)>>,
> = std::sync::OnceLock::new();

/// #2025: the one test lock for [`NEF_LOOKUP_CACHE`], declared beside it. Every
/// test that reads or writes the cache holds it, so tests run in parallel
/// cannot see each other's answers (or a `clear()` when it fills up).
#[cfg(test)]
pub(crate) static NEF_LOOKUP_CACHE_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

fn nef_lookup_cache(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, (bool, std::time::Instant)>> {
    NEF_LOOKUP_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Whether NF instance `id` is a NEF, per its NRF profile, reusing an answer
/// for [`NEF_LOOKUP_TTL`] (#1998: every provisioning request by a relayed or
/// token-identified NEF used to cost one NRF query). Keyed by the caller's
/// VERIFIED identity, which is all `provisioner_refusal` passes; an `Err` from
/// `lookup` is returned and not cached, so it keeps failing closed.
async fn cached_nef_lookup<F, Fut>(id: String, lookup: F) -> Result<bool, String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<bool, String>>,
{
    let key = id.to_ascii_lowercase();
    if let Some((is_nef, at)) = nef_lookup_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .copied()
    {
        if at.elapsed() < NEF_LOOKUP_TTL {
            return Ok(is_nef);
        }
    }
    let is_nef = lookup(id).await?;
    let mut cache = nef_lookup_cache().lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= NEF_LOOKUP_CACHE_MAX {
        cache.retain(|_, (_, at)| at.elapsed() < NEF_LOOKUP_TTL);
        if cache.len() >= NEF_LOOKUP_CACHE_MAX {
            cache.clear();
        }
    }
    cache.insert(key, (is_nef, std::time::Instant::now()));
    Ok(is_nef)
}

/// Whether NF instance `id` is a NEF, per its NRF profile, cached
/// ([`cached_nef_lookup`], #1998).
async fn caller_is_nef(id: String) -> Result<bool, String> {
    cached_nef_lookup(id, nrf_says_nef).await
}

/// Whether NF instance `id` is a NEF, per its NRF profile (#1989 review M1; the
/// pattern of ausfd's `caller_is`, #1964). Yes only when the NFDiscovery result
/// names `id` itself as a NEF, so an NRF that ignores the instance filter cannot
/// vouch for it. `Err` (no NRF, no answer, an unparsable one) fails closed.
///
/// The discovery names `requester-nf-type=UCMF`, so the NRF also applies the
/// NEF profile's `allowedNfTypes` (TS 29.510 §6.1.6.2.2 NFProfile): a NEF whose profile
/// does not allow the UCMF is not returned, and is refused here (#1998).
async fn nrf_says_nef(id: String) -> Result<bool, String> {
    let sbi_ctx = global_context();
    let nrf_uri = sbi_ctx
        .get_nrf_uri()
        .await
        .ok_or("no NRF is configured to look the caller up")?;
    let (host, port, _) = split_uri(&nrf_uri).ok_or("invalid NRF URI")?;
    let client = sbi_ctx.get_client(&host, port).await;
    let path = format!(
        "/nnrf-disc/v1/nf-instances?target-nf-type=NEF&requester-nf-type=UCMF&target-nf-instance-id={id}"
    );
    let resp = client
        .get(&path)
        .await
        .map_err(|e| format!("NRF lookup failed: {e}"))?;
    if resp.status != 200 {
        return Err(format!("NRF lookup returned {}", resp.status));
    }
    let json: Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or(""))
        .map_err(|e| format!("NRF lookup answer does not parse: {e}"))?;
    Ok(json["nfInstances"].as_array().is_some_and(|list| {
        list.iter().any(|p| {
            p["nfInstanceId"]
                .as_str()
                .is_some_and(|i| i.eq_ignore_ascii_case(&id))
                && p["nfType"]
                    .as_str()
                    .is_some_and(|t| t.eq_ignore_ascii_case("NEF"))
        })
    }))
}

/// #1939 item 3: split `configs` into the RACS IDs `request`'s caller may
/// provision under `policy` and the refused ones, reported `OTHER_REASON`
/// (TS 29.122 Table 5.16.2.2.3-1 has no more specific code). A `null` (a PATCH
/// removing an ID from the caller's own provisioning) is never refused.
fn vet_racs_ids(
    policy: &context::ProvisioningPolicy,
    request: &SbiRequest,
    configs: Map<String, Value>,
) -> (Map<String, Value>, Vec<(String, &'static str)>) {
    let caller = owner_binding::verified_consumer_id(request).ok().flatten();
    let mut refused = Vec::new();
    let allowed = configs
        .into_iter()
        .filter(|(key, value)| {
            let ok = value.is_null() || policy.may_provision(caller.as_deref(), key);
            if !ok {
                log::debug!(
                    "Provisioning of {key} refused: its Vendor ID is not configured for {}",
                    caller.as_deref().unwrap_or("<unidentified>")
                );
                refused.push((key.clone(), context::RACS_OTHER_REASON));
            }
            ok
        })
        .collect();
    (allowed, refused)
}

/// `outcome` with the RACS IDs [`vet_racs_ids`] refused reported too.
fn with_refused(
    outcome: ProvisioningOutcome,
    refused: Vec<(String, &'static str)>,
) -> ProvisioningOutcome {
    outcome.map(|r| match r {
        Ok((p, mut failed, notes)) => {
            failed.extend(refused);
            Ok((p, failed, notes))
        }
        Err(mut failed) => {
            failed.extend(refused);
            Err(failed)
        }
    })
}

/// The `403` for a caller other than the NEF / AF that created provisioning
/// `id` (#1916), or `None` to go on (also when there is no such resource, so the
/// handler answers its own `404`).
fn refuse_non_creator(
    u: &Ucmf,
    id: &str,
    request: &SbiRequest,
    operation: &str,
) -> Option<SbiResponse> {
    refuse_non_creator_in(u, id, request, operation, production_profile())
}

fn refuse_non_creator_in(
    u: &Ucmf,
    id: &str,
    request: &SbiRequest,
    operation: &str,
    production: bool,
) -> Option<SbiResponse> {
    let p = u.provisioning(id)?;
    if p.owner.is_none() && production {
        // DECISIONS 2026-11-18: an ownerless record is frozen under production.
        // A provisioning can come from a NEF or an AF, so the first caller is not
        // adopted: with the sequential IDs those records carry, it would be
        // whoever guessed first.
        let why = format!(
            "provisioning {id} predates its owner binding and is frozen under the production \
             SBI profile"
        );
        log::debug!("{operation} refused: {why}");
        return Some(nextgcore_sbi::server::send_forbidden(
            &format!("{operation}: {why}"),
            None,
        ));
    }
    owner_binding::refuse_non_owner(p.owner.as_deref(), request, operation)
}

/// Whether this process runs the production SBI profile (#1916).
fn production_profile() -> bool {
    nextgcore_sbi::security::SbiProfile::resolve().is_production()
}

/// The owner a Nucmf_Provisioning_Create records (#1916): the caller's verified
/// identity. Under production a caller with none is refused `403` before
/// anything is provisioned, so every new provisioning has an owner. The
/// production listener already demands a token and a client certificate (#1845),
/// so this is defence in depth, not the only gate.
fn provisioning_owner_in(
    request: &SbiRequest,
    production: bool,
) -> Result<Option<String>, Box<SbiResponse>> {
    const OP: &str = "Nucmf_Provisioning_Create";
    // The profile is the caller's `production`, not the process's: a test that
    // passes it explicitly must not depend on another test's profile override.
    match owner_binding::owner_for_new_resource_with(request, OP, production)? {
        None if production => {
            let why = "the requester has no verified identity; under the production SBI \
                       profile every provisioning is bound to its creator (TS 33.501 §13.4.1)";
            log::debug!("{OP} refused: {why}");
            Err(Box::new(nextgcore_sbi::server::send_forbidden(
                &format!("{OP}: {why}"),
                None,
            )))
        }
        owner => Ok(owner),
    }
}

/// TS 29.675 §5.2.2.3: `PUT /provisionings/{id}`.
fn replace_provisioning(
    u: &mut Ucmf,
    id: &str,
    request: &SbiRequest,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    if let Some(refusal) = refuse_non_creator(u, id, request, "Nucmf_Provisioning_Update") {
        return (refusal, Vec::new());
    }
    let (configs, supp_feat) = match racs_configs(request) {
        Ok(c) => c,
        Err(r) => return (r, Vec::new()),
    };
    let (configs, refused) = vet_racs_ids(u.provisioning_policy(), request, configs);
    if configs.is_empty() {
        // Nothing the caller may hold: the resource is left unchanged.
        return (all_failed(&refused), Vec::new());
    }
    let outcome = u.replace_provisioning(id, &configs, supp_feat, now);
    provisioning_update_response(id, with_refused(outcome, refused))
}

/// TS 29.675 §5.2.2.3: `PATCH /provisionings/{id}` (`application/merge-patch+json`).
fn patch_provisioning(
    u: &mut Ucmf,
    id: &str,
    request: &SbiRequest,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    if let Some(refusal) = refuse_non_creator(u, id, request, "Nucmf_Provisioning_Update") {
        return (refusal, Vec::new());
    }
    let (configs, _) = match racs_configs(request) {
        Ok(c) => c,
        Err(r) => return (r, Vec::new()),
    };
    let (configs, refused) = vet_racs_ids(u.provisioning_policy(), request, configs);
    if configs.is_empty() {
        return (all_failed(&refused), Vec::new());
    }
    let outcome = u.patch_provisioning(id, &configs, now);
    provisioning_update_response(id, with_refused(outcome, refused))
}

/// TS 29.675 §5.2.2.4: `DELETE /provisionings/{id}`.
fn delete_provisioning(
    u: &mut Ucmf,
    id: &str,
    request: &SbiRequest,
    now: DateTime<Utc>,
) -> (SbiResponse, Vec<Notification>) {
    if let Some(refusal) = refuse_non_creator(u, id, request, "Nucmf_Provisioning_Delete") {
        return (refusal, Vec::new());
    }
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
                .any(|u| *u == nextgcore_amfd::racs::notification_uri()),
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
        // #1916: the router now reads the SBI profile (production refuses an
        // anonymous provisioning). These tests drive it as `dev`, and never reset
        // the override; a test that means production passes it in explicitly.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
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
                as_nf_1862(
                    req("POST", "/nucmf-uecm/v1/subscriptions"),
                    Some(AMF_A_1862),
                ),
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
            as_nf_1862(
                req("POST", "/nucmf-uecm/v1/subscriptions"),
                Some(AMF_A_1862),
            ),
            json!({"ucmfNotificationUri": "http://amf:7777/racs-notify", "nfId": "a1"}),
        );
        let (r, _) = handle(&u, &sub, now());
        assert_eq!(r.status, 201);
        let location = r.http.get_header("Location").cloned().unwrap();
        let id = location
            .strip_prefix(&format!("{}/nucmf-uecm/v1/subscriptions/", api_root()))
            .expect("Location names the subscription")
            .to_string();
        assert_eq!(id.len(), 32, "#1862: not a sequential id: {id}");
        assert_eq!(body(&r)["dicEntryId"], 0);
        assert!(body(&r)["confirmedExpires"].is_string());

        let (_, notes) = handle(&u, &assign_request("35123456", &[1]), now());
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].uris, ["http://amf:7777/racs-notify"]);
        assert_eq!(notes[0].body["eventType"], "CREATION_OF_DICTIONARY_ENTRY");
        assert_eq!(notes[0].body["dicEntryId"], 1);

        let doc = format!("/nucmf-uecm/v1/subscriptions/{id}");
        let (r, _) = handle(
            &u,
            &as_nf_1862(req("DELETE", &doc), Some(AMF_A_1862)),
            now(),
        );
        assert_eq!(r.status, 204);
        let (r, _) = handle(
            &u,
            &as_nf_1862(req("DELETE", &doc), Some(AMF_A_1862)),
            now(),
        );
        assert_eq!(
            (r.status, cause(&r)),
            (404, json!("SUBSCRIPTION_NOT_FOUND"))
        );
        let bad = with_json(
            as_nf_1862(
                req("POST", "/nucmf-uecm/v1/subscriptions"),
                Some(AMF_A_1862),
            ),
            json!({"nfId": "a1"}),
        );
        assert_eq!(handle(&u, &bad, now()).0.status, 400);
    }

    const AMF_A_1862: &str = "aaaaaaaa-1862-4000-8000-00000000000a";
    const AMF_B_1862: &str = "bbbbbbbb-1862-4000-8000-00000000000b";

    fn as_nf_1862(mut r: SbiRequest, who: Option<&str>) -> SbiRequest {
        r.oauth2_subject = who.map(str::to_string);
        r
    }

    /// #1862, TS 29.673 §5.2.2.5 / TS 33.501 §13.4.1: a subscription is bound to
    /// the verified identity that created it, not to its self-declared `nfId`.
    /// Another NF, or an anonymous caller, gets 403 and the AMF keeps hearing
    /// about dictionary changes; the owner unsubscribes.
    #[test]
    fn only_the_subscriber_unsubscribes_1862() {
        let u = ucmf();
        let sub = as_nf_1862(
            with_json(
                req("POST", "/nucmf-uecm/v1/subscriptions"),
                // The nfId claims B's identity: it must not become the owner.
                json!({"ucmfNotificationUri": "http://amf-a:7777/racs-notify", "nfId": AMF_B_1862}),
            ),
            Some(AMF_A_1862),
        );
        let (r, _) = handle(&u, &sub, now());
        assert_eq!(r.status, 201);
        let location = r.http.get_header("Location").cloned().unwrap();
        let id = location.rsplit('/').next().unwrap().to_string();
        let doc = format!("/nucmf-uecm/v1/subscriptions/{id}");

        for who in [Some(AMF_B_1862), None] {
            let (r, _) = handle(&u, &as_nf_1862(req("DELETE", &doc), who), now());
            assert_eq!(r.status, 403, "{who:?}");
            assert!(
                body(&r)["detail"]
                    .as_str()
                    .unwrap_or_default()
                    .contains(&format!("belongs to NF instance {AMF_A_1862}")),
                "{who:?}: {}",
                body(&r)
            );
        }
        // Still subscribed: the next dictionary entry is notified to A.
        let (_, notes) = handle(&u, &assign_request("35123456", &[1]), now());
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].uris, ["http://amf-a:7777/racs-notify"]);

        let (r, _) = handle(
            &u,
            &as_nf_1862(req("DELETE", &doc), Some(AMF_A_1862)),
            now(),
        );
        assert_eq!(r.status, 204, "the subscriber unsubscribes");
        let (_, notes) = handle(&u, &assign_request("35123457", &[2]), now());
        assert!(notes.is_empty(), "and is no longer notified");
    }

    /// #1862: a caller whose token and certificate disagree subscribes nothing.
    #[test]
    fn disagreeing_identities_subscribe_nothing_1862() {
        let u = ucmf();
        let mut r = as_nf_1862(
            with_json(
                req("POST", "/nucmf-uecm/v1/subscriptions"),
                json!({"ucmfNotificationUri": "http://amf-a:7777/racs-notify"}),
            ),
            Some(AMF_A_1862),
        );
        r.peer_cert_nf_instance_id = Some(AMF_B_1862.to_string());
        let (r, _) = handle(&u, &r, now());
        assert_eq!(r.status, 403);
        let (_, notes) = handle(&u, &assign_request("35123456", &[1]), now());
        assert!(notes.is_empty(), "no subscription was created");
    }

    const NEF_A_1916: &str = "aaaaaaaa-1916-4000-8000-00000000000a";
    const NEF_B_1916: &str = "bbbbbbbb-1916-4000-8000-00000000000b";

    /// #1916, TS 29.675 §4.2.3-§4.2.4 / TS 33.501 §13.4.1: a provisioning is
    /// bound to the NEF that created it. Another NEF, or an anonymous caller,
    /// gets 403 on GET, PUT, PATCH and DELETE, and the dictionary entry it
    /// provisioned keeps resolving unchanged; the creator then manages it.
    #[test]
    fn only_the_creating_nef_manages_a_provisioning_1916() {
        let u = ucmf();
        let create = as_nf_1862(
            with_json(
                req("POST", "/nucmf-provisioning/v1/provisionings"),
                provisioning_body("0a0b"),
            ),
            Some(NEF_A_1916),
        );
        let (r, _) = handle(&u, &create, now());
        assert_eq!(r.status, 201);
        let doc = r.http.get_header("Location").unwrap().to_string();
        let doc = &doc[doc.find("/nucmf-provisioning").unwrap()..];
        let id = doc.rsplit('/').next().unwrap().to_string();
        let resolves_0a0b = |u: &RwLock<Ucmf>| {
            read_state(u)
                .provisioning(&id)
                .is_some_and(|p| p.configs[MAN]["racsParam5Gs"] == "0a0b")
        };
        assert!(resolves_0a0b(&u));

        for who in [Some(NEF_B_1916), None] {
            for r in [
                req("GET", doc),
                with_json(req("PUT", doc), provisioning_body("0c")),
                with_json(req("PATCH", doc), json!({"racsConfigs": {MAN: null}})),
                req("DELETE", doc),
            ] {
                let method = r.header.method.clone();
                let (r, notes) = handle(&u, &as_nf_1862(r, who), now());
                assert_eq!(r.status, 403, "{method} by {who:?}");
                assert!(
                    body(&r)["detail"]
                        .as_str()
                        .unwrap_or_default()
                        .contains(&format!("belongs to NF instance {NEF_A_1916}")),
                    "{method} by {who:?}: {}",
                    body(&r)
                );
                assert!(notes.is_empty());
            }
        }
        assert!(resolves_0a0b(&u), "the provisioning is untouched");

        let (r, _) = handle(
            &u,
            &as_nf_1862(
                with_json(req("PUT", doc), provisioning_body("0c")),
                Some(NEF_A_1916),
            ),
            now(),
        );
        assert_eq!(r.status, 200, "the creator replaces it: {:?}", body(&r));
        let (r, _) = handle(&u, &as_nf_1862(req("GET", doc), Some(NEF_A_1916)), now());
        assert_eq!(body(&r)["racsConfigs"][MAN]["racsParam5Gs"], "0c");
        let (r, _) = handle(&u, &as_nf_1862(req("DELETE", doc), Some(NEF_A_1916)), now());
        assert_eq!(r.status, 204, "and deletes it");
    }

    /// #1916, TS 29.675 §4.1.3.2: only the NEF and the AF consume
    /// Nucmf_Provisioning. A caller whose verified certificate names another NF
    /// type (an AMF holding a nucmf token) is refused before anything is
    /// created; a NEF or AF certificate, or one relayed through an SCP, is not.
    #[test]
    fn an_amf_certificate_cannot_provision_1916() {
        let u = ucmf();
        let create = |types: &[&str]| {
            let mut r = with_json(
                req("POST", "/nucmf-provisioning/v1/provisionings"),
                provisioning_body("0a0b"),
            );
            r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            r
        };
        let (r, _) = handle(&u, &create(&["AMF"]), now());
        assert_eq!(r.status, 403);
        assert!(
            body(&r)["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("consumed by the NEF and the AF only"),
            "{}",
            body(&r)
        );
        assert!(
            read_state(&u).provisioning("1").is_none(),
            "nothing created"
        );
        // The same refusal on an existing resource, before its lookup.
        let (r, _) = handle(&u, &create(&["NEF"]), now());
        assert_eq!(r.status, 201);
        let mut del = req("DELETE", "/nucmf-provisioning/v1/provisionings/1");
        del.peer_cert_nf_types = vec!["AMF".into()];
        assert_eq!(handle(&u, &del, now()).0.status, 403);
        assert!(read_state(&u).provisioning("1").is_some());
        // An AF, a NEF, or a relay (whose certificate is not the consumer's) passes.
        for types in ["AF", "NEF", "SCP"] {
            let mut get = req("GET", "/nucmf-provisioning/v1/provisionings/1");
            get.peer_cert_nf_types = vec![types.into()];
            assert_eq!(handle(&u, &get, now()).0.status, 200, "{types}");
        }
    }

    /// #1916 (DECISIONS 2026-11-18): under the production profile an anonymous
    /// create provisions nothing, and an ownerless provisioning (restored from a
    /// pre-#1916 state file) is frozen for every caller. Under `dev` both are as
    /// before. The profile is passed in: flipping the process-wide override would
    /// race the tests that set Dev.
    #[test]
    fn production_refuses_anonymous_creates_and_freezes_ownerless_provisionings_1916() {
        let anon = with_json(
            req("POST", "/nucmf-provisioning/v1/provisionings"),
            provisioning_body("0a0b"),
        );
        assert_eq!(provisioning_owner_in(&anon, true).unwrap_err().status, 403);
        assert_eq!(provisioning_owner_in(&anon, false).ok(), Some(None));
        assert_eq!(
            provisioning_owner_in(&as_nf_1862(anon.clone(), Some(NEF_A_1916)), true).ok(),
            Some(Some(NEF_A_1916.to_string()))
        );

        let u = ucmf();
        assert_eq!(handle(&u, &anon, now()).0.status, 201, "dev: ownerless");
        let state = read_state(&u);
        for who in [Some(NEF_A_1916), Some(NEF_B_1916), None] {
            let r = as_nf_1862(req("DELETE", "/nucmf-provisioning/v1/provisionings/1"), who);
            let refused = refuse_non_creator_in(&state, "1", &r, "Delete", true)
                .unwrap_or_else(|| panic!("{who:?} reached a frozen provisioning"));
            assert_eq!(refused.status, 403);
            assert!(body(&refused)["detail"]
                .as_str()
                .unwrap()
                .contains("frozen"));
            assert!(refuse_non_creator_in(&state, "1", &r, "Delete", false).is_none());
        }
    }

    /// #1916: the provisioning routes use the production-aware helpers, so the
    /// rules above are what the router applies. Each call appears twice: at its
    /// site and in this test.
    #[test]
    fn the_provisioning_routes_judge_under_the_real_profile_1916() {
        let src = include_str!("main.rs");
        assert_eq!(
            src.matches("provisioning_owner_in(request, production_profile())")
                .count(),
            2
        );
        assert_eq!(
            src.matches("refuse_non_creator_in(u, id, request, operation, production_profile())")
                .count(),
            2
        );
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
                as_nf_1862(
                    req("POST", "/nucmf-uecm/v1/subscriptions"),
                    Some(AMF_A_1862),
                ),
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

    /// #1939 item 4: the NRF may issue a provisioning token to a NEF or an AF,
    /// never to an SCP in its own right (it asks on the consumer's behalf).
    #[test]
    fn no_scp_holds_a_provisioning_token_of_its_own_1939() {
        let p = nf_profile("id-1", "10.0.0.9", 7777, "http");
        assert_eq!(p["nfServices"][1]["serviceName"], "nucmf-provisioning");
        assert_eq!(
            p["nfServices"][1]["allowedNfTypes"],
            serde_json::json!(["NEF", "AF"])
        );
        // The UECM service is unchanged: its SCP forwards for AMFs and MMEs.
        assert_eq!(
            p["nfServices"][0]["allowedNfTypes"],
            serde_json::json!(["AMF", "MME", "SCP"])
        );
    }

    /// #1939 items 3 and 5: `ucmf.provisioning` is read from the config, a bad
    /// Vendor ID refuses to start, and absent means no restriction.
    #[test]
    fn the_provisioning_policy_is_settled_from_yaml_1939() {
        let args = Args::parse_from(["nextgcore-ucmfd"]);
        let yaml = "ucmf:\n  provisioning:\n    trusted_afs: [af-1]\n    vendor_ids:\n      nef-1: [\"00007ED9\"]\n";
        let s = settle(&args, Some(yaml)).unwrap();
        assert_eq!(s.provisioning.trusted_afs, Some(vec!["af-1".to_string()]));
        assert_eq!(s.provisioning.vendor_ids.get("nef-1"), Some(&vec![0x7ED9]));
        let bad = "ucmf:\n  provisioning:\n    vendor_ids:\n      nef-1: [\"7ED9\"]\n";
        assert!(
            settle(&args, Some(bad)).is_err(),
            "a Vendor ID is 8 hex digits"
        );
        assert_eq!(
            settle(&args, None).unwrap().provisioning,
            context::ProvisioningPolicy::default()
        );
    }

    /// #1939 item 3: with `vendor_ids` configured, a NEF provisions only RACS IDs
    /// under its own Vendor IDs. Another manufacturer's ID is refused per RACS ID
    /// (`OTHER_REASON`) and never enters the dictionary, so it cannot be squatted
    /// first-come; the configured NEF then provisions it. A PUT or PATCH cannot
    /// smuggle one in either.
    #[test]
    fn a_nef_provisions_only_its_own_vendor_ids_1939() {
        let u = ucmf();
        // MAN's Vendor ID is 0x00007ED9.
        u.write()
            .unwrap()
            .set_provisioning_policy(context::ProvisioningPolicy {
                trusted_afs: None,
                vendor_ids: [
                    (NEF_A_1916.to_string(), vec![0x7ED9]),
                    (NEF_B_1916.to_string(), vec![0x1234]),
                ]
                .into_iter()
                .collect(),
            });
        let create = |who: Option<&str>| {
            as_nf_1862(
                with_json(
                    req("POST", "/nucmf-provisioning/v1/provisionings"),
                    provisioning_body("0a0b"),
                ),
                who,
            )
        };
        let resolves = |u: &RwLock<Ucmf>| read_state(u).entry_count() > 0;
        for squatter in [Some(NEF_B_1916), None] {
            let (r, notes) = handle(&u, &create(squatter), now());
            assert_eq!(r.status, 500, "{squatter:?}: {:?}", body(&r));
            assert_eq!(body(&r)[0]["racsIds"][0], MAN, "{:?}", body(&r));
            assert_eq!(body(&r)[0]["failureCode"], "OTHER_REASON");
            assert!(notes.is_empty());
            assert!(!resolves(&u), "{squatter:?} squatted the ID");
        }
        let (r, _) = handle(&u, &create(Some(NEF_A_1916)), now());
        assert_eq!(r.status, 201, "{:?}", body(&r));
        assert!(resolves(&u));

        // B's own provisioning cannot take A's ID by PUT or PATCH either.
        let other = "000001234000000000ab";
        let (r, _) = handle(
            &u,
            &as_nf_1862(
                with_json(
                    req("POST", "/nucmf-provisioning/v1/provisionings"),
                    json!({"racsConfigs": {other: {"imeiTacs": ["35123457"], "racsParam5Gs": "0c"}}}),
                ),
                Some(NEF_B_1916),
            ),
            now(),
        );
        assert_eq!(r.status, 201, "{:?}", body(&r));
        let doc = r.http.get_header("Location").unwrap().to_string();
        let doc = doc[doc.find("/nucmf-provisioning").unwrap()..].to_string();
        let before = read_state(&u).entry_count();
        for r in [
            with_json(req("PUT", &doc), provisioning_body("0d")),
            with_json(
                req("PATCH", &doc),
                json!({"racsConfigs": {MAN: {"imeiTacs": ["35123458"], "racsParam5Gs": "0e"}}}),
            ),
        ] {
            let method = r.header.method.clone();
            let (r, _) = handle(&u, &as_nf_1862(r, Some(NEF_B_1916)), now());
            assert_eq!(r.status, 500, "{method}: {:?}", body(&r));
            assert_eq!(
                read_state(&u).entry_count(),
                before,
                "{method} changed the dictionary"
            );
        }
    }

    /// #1939 item 5, #1989 review M1: with `trusted_afs` configured, trust is decided
    /// by the caller's VERIFIED identity, not by its certificate type alone. A listed
    /// AF is admitted however it arrives. Anyone else must prove it is a NEF: by its
    /// own certificate when direct, else by its NRF profile, which fails closed. So an
    /// untrusted AF relayed by an SCP, one with a certificate that names no type, and
    /// one with a token alone are all refused; a NEF behind an SCP is admitted only
    /// when the NRF says it is a NEF. Unconfigured, nothing is judged here.
    #[tokio::test]
    async fn only_the_nef_or_a_trusted_af_provisions_1989() {
        let af_ok = "aaaaaaaa-1939-4000-8000-0000000000af";
        let af_other = "bbbbbbbb-1939-4000-8000-0000000000af";
        // (certificate NF types, certificate NF Instance ID, token sub)
        let caller = |types: &[&str], cert: Option<&str>, token: Option<&str>| {
            let mut r = as_nf_1862(
                with_json(
                    req("POST", "/nucmf-provisioning/v1/provisionings"),
                    provisioning_body("0a0b"),
                ),
                token,
            );
            r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            r.peer_cert_nf_instance_id = cert.map(str::to_string);
            r
        };
        let scp = "cccccccc-1939-4000-8000-000000000scp";
        let nrf_nef_is = |nef: &'static str| {
            move |id: String| async move { Ok::<bool, String>(id.eq_ignore_ascii_case(nef)) }
        };
        let nrf_down = |_id: String| async { Err::<bool, String>("no NRF".into()) };

        let open = context::ProvisioningPolicy::default();
        assert!(
            provisioner_refusal(&open, &caller(&["AF"], Some(af_other), None), nrf_down)
                .await
                .is_none(),
            "unconfigured: not judged"
        );

        let policy = context::ProvisioningPolicy {
            trusted_afs: Some(vec![af_ok.to_string()]),
            vendor_ids: BTreeMap::new(),
        };
        let refused = |r: Option<SbiResponse>, what: &str| {
            let r = r.unwrap_or_else(|| panic!("{what}: admitted"));
            assert_eq!(r.status, 403, "{what}");
            assert!(
                body(&r)["detail"].as_str().unwrap().contains("trusted AF"),
                "{what}: {:?}",
                body(&r)
            );
        };
        // An untrusted AF: direct, via an SCP, with a typeless certificate, token only.
        refused(
            provisioner_refusal(&policy, &caller(&["AF"], Some(af_other), None), nrf_down).await,
            "direct AF certificate",
        );
        refused(
            provisioner_refusal(
                &policy,
                &caller(&["SCP"], Some(scp), Some(af_other)),
                nrf_nef_is(NEF_A_1916),
            )
            .await,
            "untrusted AF via an SCP",
        );
        refused(
            provisioner_refusal(
                &policy,
                &caller(&[], Some(af_other), None),
                nrf_nef_is(NEF_A_1916),
            )
            .await,
            "typeless certificate",
        );
        refused(
            provisioner_refusal(
                &policy,
                &caller(&[], None, Some(af_other)),
                nrf_nef_is(NEF_A_1916),
            )
            .await,
            "token only",
        );
        refused(
            provisioner_refusal(&policy, &caller(&[], None, None), nrf_down).await,
            "anonymous",
        );
        // A NEF behind an SCP, but the NRF cannot be asked: fails closed.
        refused(
            provisioner_refusal(
                &policy,
                &caller(&["SCP"], Some(scp), Some(NEF_A_1916)),
                nrf_down,
            )
            .await,
            "NEF via an SCP with no NRF",
        );

        // Admitted: the trusted AF however it arrives, a NEF by certificate, a NEF
        // behind an SCP or with a typeless certificate by its NRF profile.
        for (r, what) in [
            (caller(&["AF"], Some(af_ok), None), "trusted AF direct"),
            (
                caller(&["SCP"], Some(scp), Some(af_ok)),
                "trusted AF via an SCP",
            ),
            (caller(&["NEF"], Some(NEF_B_1916), None), "NEF certificate"),
        ] {
            assert!(
                provisioner_refusal(&policy, &r, nrf_down).await.is_none(),
                "{what}"
            );
        }
        for r in [
            caller(&["SCP"], Some(scp), Some(NEF_A_1916)),
            caller(&[], Some(NEF_A_1916), None),
        ] {
            assert!(
                provisioner_refusal(&policy, &r, nrf_nef_is(NEF_A_1916))
                    .await
                    .is_none(),
                "{r:?}"
            );
        }
    }

    /// #1989 review M1: the provisioning API is judged by [`provisioner_refusal`]
    /// with the real NRF lookup, in the handler every request goes through.
    #[test]
    fn the_handler_judges_provisioners_with_the_nrf_lookup_1989() {
        let src = include_str!("main.rs");
        let call = "provisioner_refusal(&policy, &request, caller_is_nef).await";
        assert_eq!(src.matches(call).count(), 2, "the call and this test");
        assert!(is_provisioning_path(
            "/nucmf-provisioning/v1/provisionings/1?x=1"
        ));
        assert!(!is_provisioning_path("/nucmf-uecm/v1/dic-entries"));
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

/// #1665: the outbound OAuth2 client follows the SBI security profile.
#[cfg(test)]
mod outbound_oauth2_1665_tests {
    use nextgcore_sbi::security::SbiProfile;
    use nextgcore_sbi::types::NfType;

    const NRF: &str = "http://127.0.0.10:7777";

    /// Under the `production` profile this UCMF installs its token client with
    /// the `sbi.oauth2.require` knob off, so its service requests to the AMF, AUSF,
    /// SMF and UDM (which require a bearer under that profile, #63) carry one
    /// (TS 33.501 §13.4.1.1.2). Before #1665 it installed it only under the knob.
    #[test]
    fn the_production_profile_installs_the_outbound_oauth2_client_without_the_knob() {
        let oauth2 = super::outbound_oauth2_client(SbiProfile::Production, false, Some(NRF))
            .expect("production profile, knob off: the outbound OAuth2 client is installed");
        assert_eq!(oauth2.self_consumer().nf_type, NfType::Ucmf);
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

/// #1795: the listener `main` builds follows the SBI security profile.
#[cfg(test)]
mod sbi_profile_tests_1795 {
    /// REVERT-VERIFIED: with `sbi_listener_config` returning its input, the
    /// production half serves cleartext and the helper fails naming UCMF.
    #[test]
    fn the_listener_follows_the_sbi_profile_1795() {
        nextgcore_sbi::test_support::assert_listener_follows_sbi_profile(
            nextgcore_sbi::types::NfType::Ucmf,
            super::sbi_listener_config,
        );
    }
}

/// #1998: the NRF answer about a caller being a NEF is reused for its TTL.
#[cfg(test)]
mod nef_lookup_cache_tests_1998 {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    /// **#2025.** Every test fn in this file that touches the NEF lookup cache
    /// (`cached_nef_lookup(`, `caller_is_nef(`, `nef_lookup_cache()`) holds
    /// [`NEF_LOOKUP_CACHE_TEST_LOCK`]: a test that does not can race another
    /// one's entries, as R30's probe raced the #1998 test.
    ///
    /// REVERT-VERIFIED: with the lock taken out of the #1998 test, this fails
    /// naming it.
    #[test]
    fn every_test_touching_the_nef_lookup_cache_holds_its_lock_2025() {
        let src = include_str!("main.rs");
        let tests = &src[src.find("#[cfg(test)]\nmod ").expect("test modules")..];
        let touches = ["cached_nef_lookup(", "caller_is_nef(", "nef_lookup_cache()"];
        let mut unlocked = Vec::new();
        let mut checked = 0;
        for chunk in tests
            .split("\n    async fn ")
            .chain(tests.split("\n    fn "))
            .skip(1)
        {
            let name: String = chunk.chars().take_while(|c| *c != '(').collect();
            // The fn body: up to the next item at this indentation.
            let body = chunk.split("\n    }\n").next().unwrap_or(chunk);
            if name.contains("_2025") || !touches.iter().any(|t| body.contains(t)) {
                continue;
            }
            checked += 1;
            if !body.contains("NEF_LOOKUP_CACHE_TEST_LOCK.lock()") {
                unlocked.push(name);
            }
        }
        assert!(checked >= 1, "the scan finds the #1998 test");
        assert!(
            unlocked.is_empty(),
            "tests touching the cache without its lock: {unlocked:?}"
        );
    }

    /// **#1998.** A second provisioning request by the same verified NEF costs
    /// no NRF query; a refusal is reused too; a failed lookup is not cached (it
    /// keeps failing closed and the next request asks again); an expired answer
    /// is asked again; and the key is the verified ID, case-insensitively.
    ///
    /// REVERT-VERIFIED: with `cached_nef_lookup` never reading the cache, the
    /// second call queries again and the first assertion on the count fails;
    /// with a failed lookup cached as `false`, the second failure is `Ok`.
    #[tokio::test]
    async fn the_nef_lookup_is_cached_by_verified_id_and_fails_closed_1998() {
        let _cache = NEF_LOOKUP_CACHE_TEST_LOCK.lock().await;
        let asked = Arc::new(AtomicUsize::new(0));
        let counting = |answer: Result<bool, String>| {
            let asked = asked.clone();
            move |_id: String| {
                asked.fetch_add(1, SeqCst);
                async move { answer }
            }
        };
        let nef = "19980000-0000-4000-8000-00000000000A".to_string();
        assert_eq!(
            cached_nef_lookup(nef.clone(), counting(Ok(true))).await,
            Ok(true)
        );
        assert_eq!(
            cached_nef_lookup(nef.to_ascii_lowercase(), counting(Ok(false))).await,
            Ok(true),
            "reused, whatever the lookup would say now"
        );
        assert_eq!(asked.load(SeqCst), 1, "one NRF query for two requests");

        let not_nef = "19980000-0000-4000-8000-00000000000b".to_string();
        assert_eq!(
            cached_nef_lookup(not_nef.clone(), counting(Ok(false))).await,
            Ok(false)
        );
        assert_eq!(
            cached_nef_lookup(not_nef, counting(Ok(true))).await,
            Ok(false)
        );
        assert_eq!(asked.load(SeqCst), 2, "a refusal is reused too");

        let unknown = "19980000-0000-4000-8000-00000000000c".to_string();
        assert!(
            cached_nef_lookup(unknown.clone(), counting(Err("NRF down".into())))
                .await
                .is_err()
        );
        assert!(cached_nef_lookup(unknown, counting(Err("NRF down".into())))
            .await
            .is_err());
        assert_eq!(asked.load(SeqCst), 4, "a failure is never cached");

        // Expired: asked again, and the new answer replaces the old.
        nef_lookup_cache()
            .lock()
            .unwrap()
            .get_mut(&nef.to_ascii_lowercase())
            .expect("cached")
            .1 = std::time::Instant::now() - NEF_LOOKUP_TTL;
        assert_eq!(cached_nef_lookup(nef, counting(Ok(false))).await, Ok(false));
        assert_eq!(asked.load(SeqCst), 5, "an expired answer is asked again");
    }
}
