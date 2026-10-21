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
//! **Gaps, stated rather than hidden:**
//! - No transcoding between TS 36.331 and TS 38.331 formats. TS 23.501 requires
//!   it of a UCMF serving a PLMN with RACS in both EPS and 5GS in Mode of
//!   Operation B; this UCMF answers a request for a format it does not hold
//!   with `404 NO_DICTIONARY_ENTRY_FOUND` and a detail saying so.
//! - No generation of UE Radio Capability for Paging from the full capability;
//!   paging capabilities are stored and returned only as provided.
//! - `racsParamEps` / `racsParam5Gs` (TS 29.122 `RacsConfiguration`) are taken
//!   as hexadecimal octet strings; the TS 29.122 OpenAPI was not available to
//!   confirm their encoding.

mod context;
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
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
    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,
    #[arg(long, default_value = "7777")]
    sbi_port: u16,
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

fn api_root() -> &'static str {
    API_ROOT.get().map(String::as_str).unwrap_or("http://ucmf")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(args.log_level.as_str()),
    )
    .format_timestamp_millis()
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
    let _ = UCMF.set(Arc::new(RwLock::new(ucmf)));

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

    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let scheme = if args.tls { "https" } else { "http" };
    let _ = API_ROOT.set(format!("{scheme}://{}:{}", args.sbi_addr, args.sbi_port));

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

    global_context().set_nrf_uri(&settings.nrf_uri).await;
    match register_with_nrf(&args.sbi_addr, args.sbi_port, scheme, &nf_instance_id).await {
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
    // Deregister before the listener goes away (TS 29.510 §5.2.2.4).
    nextgcore_sbi::heartbeat::deregister_self().await;
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
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
    json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "UCMF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [uecm, provisioning],
        "allowedNfTypes": ["AMF", "MME", "NEF", "SCP"],
        "heartBeatTimer": 10,
    })
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

/// Deliver a notification to every subscriber, without blocking the caller.
fn dispatch(note: Notification) {
    for uri in note.uris {
        let body = note.body.clone();
        tokio::spawn(async move {
            let Some((host, port, path)) = split_uri(&uri) else {
                log::warn!("Invalid ucmfNotificationUri '{uri}'");
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
                    log::debug!("UCMF notification delivered to {uri}")
                }
                Ok(r) => log::warn!("UCMF notification to {uri} returned {}", r.status),
                Err(e) => log::warn!("UCMF notification to {uri} failed: {e}"),
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

    let lock_poisoned = || (send_internal_error("UCMF state lock poisoned"), Vec::new());
    match parts.as_slice() {
        [UECM_API, "v1", "dic-entries"] => match method {
            "GET" => match ucmf.read() {
                Ok(u) => (resolve(&u, request), Vec::new()),
                Err(_) => lock_poisoned(),
            },
            "POST" => match ucmf.write() {
                Ok(mut u) => assign(&mut u, request, now),
                Err(_) => lock_poisoned(),
            },
            _ => (send_method_not_allowed(method, "dic-entries"), Vec::new()),
        },
        [UECM_API, "v1", "dic-entries", id] => match method {
            "GET" => match ucmf.read() {
                Ok(u) => (get_dic_entry(&u, id, request), Vec::new()),
                Err(_) => lock_poisoned(),
            },
            _ => (
                send_method_not_allowed(method, "dic-entries/{dicEntryId}"),
                Vec::new(),
            ),
        },
        [UECM_API, "v1", "subscriptions"] => match method {
            "POST" => match ucmf.write() {
                Ok(mut u) => (subscribe(&mut u, request, now), Vec::new()),
                Err(_) => lock_poisoned(),
            },
            _ => (send_method_not_allowed(method, "subscriptions"), Vec::new()),
        },
        [UECM_API, "v1", "subscriptions", id] => match method {
            "DELETE" => match ucmf.write() {
                Ok(mut u) => (unsubscribe(&mut u, id), Vec::new()),
                Err(_) => lock_poisoned(),
            },
            _ => (
                send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
                Vec::new(),
            ),
        },
        [PROVISIONING_API, "v1", "provisionings"] => match method {
            "POST" => match ucmf.write() {
                Ok(mut u) => create_provisioning(&mut u, request, now),
                Err(_) => lock_poisoned(),
            },
            _ => (send_method_not_allowed(method, "provisionings"), Vec::new()),
        },
        [PROVISIONING_API, "v1", "provisionings", id] => match ucmf.write() {
            Ok(mut u) => match method {
                "GET" => (get_provisioning(&u, id), Vec::new()),
                "PUT" => replace_provisioning(&mut u, id, request, now),
                "PATCH" => patch_provisioning(&mut u, id, request, now),
                "DELETE" => (delete_provisioning(&mut u, id), Vec::new()),
                _ => (
                    send_method_not_allowed(method, "provisionings/{provisioningId}"),
                    Vec::new(),
                ),
            },
            Err(_) => lock_poisoned(),
        },
        _ => (
            send_not_found(&format!("Resource not found: {path}"), None),
            Vec::new(),
        ),
    }
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
            "The dictionary entry does not hold the requested RAC format and this UCMF does not transcode",
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
        Err(AssignError::IdSpaceExhausted) => (
            send_error(
                500,
                "Internal Server Error",
                "No RCI left under the current Version ID",
                Some("INSUFFICIENT_RESOURCES"),
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
    let sub = u.subscribe(nf_id, uri.to_string(), suggested, now);
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
            Option<Notification>,
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
        Some(Ok((p, failed, note))) => (
            SbiResponse::ok()
                .with_json_body(&racs_data_body(&p, &failed))
                .unwrap_or_else(|e| send_internal_error(&format!("encoding RacsData: {e}"))),
            note.into_iter().collect(),
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
fn delete_provisioning(u: &mut Ucmf, id: &str) -> SbiResponse {
    if u.delete_provisioning(id) {
        SbiResponse::no_content()
    } else {
        send_not_found(&format!("No provisioning {id}"), Some("RESOURCE_NOT_FOUND"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

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
