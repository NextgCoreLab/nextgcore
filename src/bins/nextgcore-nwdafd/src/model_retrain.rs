//! Demo `d441e-model-retrain` (nextgsim#468), PR 2: the AnLF side of
//! MTLF→AnLF model provisioning. Cargo feature `demo-d441e-model-retrain`,
//! off by default, and active only with the `demo:` block on.
//!
//! TS 23.288 §6.2A.0 (23288-k10 l.8707-8731): an NWDAF containing AnLF is
//! configured with, or discovers, NWDAFs containing MTLF and retrieves trained
//! ML Models from them. An nwdafd with `nwdaf.role: anlf` and this demo on:
//!
//! 1. **Finds the MTLF.** `nwdaf.anlf.mtlf_uri` if set, else Nnrf_NFDiscovery
//!    for an NWDAF offering `nnwdaf-mlmodelprovision` (not itself).
//! 2. **Subscribes.** `Nnwdaf_MLModelProvision_Subscribe` for NF_LOAD with
//!    `suppFeats` ModelProvisionExt and `mlEvRepCon.mlAccuracyThreshold`
//!    (§6.2E.2 step 2: "may include an ML Model accuracy threshold"), retried
//!    until accepted, under the OAuth2 client when one is configured.
//! 3. **Takes the Notify** on `/nnwdaf-callback/v1/mtlf-model-notify/{token}`
//!    on the existing SBI listener (204; an unknown token is 404). The token
//!    (a v4 UUID, 122 random bits) is redacted from logs
//!    (`log_redact::CALLBACK_TOKEN_SEGMENTS`).
//! 4. **Downloads and verifies** `mLFileAddr.mLModelUrl` and
//!    `<url>.manifest.json` with nextgsim#463's checks, in order: manifest
//!    shape, sha256 of the bytes, opset and graph inputs/outputs, the ONNX
//!    parse, every golden vector. Any failure refuses the model and keeps the
//!    one in use (`model refused (sha256 mismatch)`).
//! 5. **Loads** a verified model as this NWDAF's NF_LOAD predictor.
//!
//! # Modes
//! `retrain` and `no-retrain` select what the MTLF does on an accuracy drop
//! (PR 4). The AnLF behaves the same in both; this PR logs the mode.
//!
//! # Limitation: the callback under OAuth2 enforcement
//! TS 33.501 §13.4.1 (33501-k20 l.14458): "The OAuth 2.0 framework does not
//! apply to the notification operation". The callback authenticates by its
//! 122-bit token (a v4 UUID), and the MTLF sends no bearer. But
//! `nextgcore-sbi`'s `require_oauth2` checks every route, so an AnLF with
//! `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` answers the Notify with 401 and never gets
//! a model. That is nextgcore#1421, the same as the #465/#466 callbacks, and is
//! fixed there; until then the AnLF must run without SBI OAuth2 enforcement.
//!
//! # Download limits
//! Models are fetched only from the subscribed MTLF's `host:port`, each GET
//! (body included) within [`FETCH_TIMEOUT`] and [`MAX_MODEL_BYTES`]. Loads apply
//! in Notify order: a fetch finished after a later Notify's is dropped.
//!
//! # Honesty
//! The manifest comes from the same MTLF as the bytes, so the sha256 proves the
//! transfer, not the provenance (TS 33.501 Annex X.10 is not implemented). The
//! model is OLS in a single `LinearRegressor`; nothing here claims it is good.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};

use crate::context::{AnalyticsId, NwdafContext};
use crate::ml_service::InferenceModel;
use crate::role::Role;

/// The demo key (nextgsim#458 convention).
pub const DEMO_KEY: &str = "d441e-model-retrain";
/// `retrain` (the main arm) and `no-retrain` (the MTLF never refits).
pub const MODES: &[&str] = &["retrain", "no-retrain"];

/// What this binary registers under the `demo-d441e-model-retrain` feature.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: MODES,
    requires: &[],
};

/// The notify callback path segment; the next segment is the token.
pub const CALLBACK_SEGMENT: &str = "mtlf-model-notify";

/// The accuracy threshold the AnLF subscribes with, in percent (TS 29.520
/// `mlAccuracyThreshold`, 0..100), unless `nwdaf.anlf.accuracy_threshold`.
pub const DEFAULT_ACCURACY_THRESHOLD: u8 = 70;

/// The event the AnLF asks a model for: the one nwdafd's predictor serves.
pub const MODEL_EVENT: AnalyticsId = AnalyticsId::NfLoad;

/// The largest model or manifest body the AnLF reads. A real artefact is a few
/// hundred bytes (the reader caps the window at `MAX_SAMPLES`).
pub const MAX_MODEL_BYTES: usize = 1024 * 1024;

/// How long one GET (head and body) may take before the model is refused.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The `nwdaf.anlf` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnlfConfig {
    /// `http://host:port` of the MTLF; `None` = discover at the NRF.
    pub mtlf_uri: Option<String>,
    /// Percent, 0..100.
    pub accuracy_threshold: u8,
}

impl Default for AnlfConfig {
    fn default() -> Self {
        Self {
            mtlf_uri: None,
            accuracy_threshold: DEFAULT_ACCURACY_THRESHOLD,
        }
    }
}

/// Parse `nwdaf.anlf` (absent = the defaults). A malformed block is an error.
pub fn anlf_config_from_root(root: &serde_yaml::Value) -> Result<AnlfConfig, String> {
    let mut cfg = AnlfConfig::default();
    let Some(block) = root.get("nwdaf").and_then(|n| n.get("anlf")) else {
        return Ok(cfg);
    };
    let map = block.as_mapping().ok_or("nwdaf.anlf must be a mapping")?;
    for (k, v) in map {
        match k.as_str() {
            Some("mtlf_uri") => {
                let uri = v.as_str().ok_or("nwdaf.anlf.mtlf_uri must be a string")?;
                if crate::notification_dispatcher::parse_notify_uri(uri).is_none() {
                    return Err(format!("nwdaf.anlf.mtlf_uri {uri:?} is not an http(s) URI"));
                }
                cfg.mtlf_uri = Some(uri.trim_end_matches('/').to_string());
            }
            Some("accuracy_threshold") => {
                cfg.accuracy_threshold = v
                    .as_u64()
                    .filter(|t| *t <= 100)
                    .and_then(|t| u8::try_from(t).ok())
                    .ok_or("nwdaf.anlf.accuracy_threshold must be an integer 0..100")?;
            }
            _ => return Err(format!("unknown key nwdaf.anlf.{k:?}")),
        }
    }
    Ok(cfg)
}

/// What start-up decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The demo is off: nothing of this module runs.
    Off,
    /// The demo is on, but this instance is no AnLF-only NWDAF: no client.
    On { mode: String, role: Role },
    /// The demo is on and this is an AnLF: run the client.
    Client { mode: String, config: AnlfConfig },
}

/// Decide from the active mode, the role and the config root.
pub fn resolve(mode: Option<&str>, role: Role, root: &serde_yaml::Value) -> Result<Plan, String> {
    let Some(mode) = mode else {
        return Ok(Plan::Off);
    };
    if role == Role::Anlf {
        Ok(Plan::Client {
            mode: mode.to_string(),
            config: anlf_config_from_root(root)?,
        })
    } else {
        Ok(Plan::On {
            mode: mode.to_string(),
            role,
        })
    }
}

/// Log the decision (start-up).
pub fn announce(plan: &Plan) {
    match plan {
        Plan::Off => {}
        Plan::On { mode, role } => nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "model-retrain: on (mode={mode}, role={}; no AnLF client)",
            role.as_str()
        ),
        Plan::Client { mode, config } => nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "model-retrain: on (mode={mode}, role=anlf; AnLF client to {}, threshold={:.2})",
            config
                .mtlf_uri
                .as_deref()
                .unwrap_or("an MTLF discovered at the NRF"),
            f64::from(config.accuracy_threshold) / 100.0
        ),
    }
}

/// The model this AnLF has verified and loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub version: String,
    pub sha256: String,
    pub url: String,
}

/// The AnLF's state: its callback token, what it loaded, and counters.
#[derive(Debug)]
pub struct Anlf {
    /// A v4 UUID: 122 random bits.
    token: String,
    /// What is loaded, and the sequence number of the Notify that loaded it.
    state: Mutex<LoadState>,
    /// Sequence numbers handed to Notifies, in arrival order.
    next_seq: AtomicU64,
    /// `host:port` of the MTLF subscribed to: the only origin models are
    /// fetched from.
    mtlf: Mutex<Option<(String, u16)>>,
    subscribed: AtomicBool,
    verified: AtomicU64,
    refused: AtomicU64,
}

#[derive(Debug, Default)]
struct LoadState {
    loaded: Option<Loaded>,
    applied_seq: u64,
}

impl Default for Anlf {
    fn default() -> Self {
        Self::new()
    }
}

impl Anlf {
    pub fn new() -> Self {
        Self {
            token: uuid::Uuid::new_v4().simple().to_string(),
            state: Mutex::new(LoadState::default()),
            next_seq: AtomicU64::new(0),
            mtlf: Mutex::new(None),
            subscribed: AtomicBool::new(false),
            verified: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }

    /// The `notifUri` the AnLF subscribes with.
    pub fn notify_uri(&self, sbi_base: &str) -> String {
        format!(
            "{}/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/{}",
            sbi_base.trim_end_matches('/'),
            self.token
        )
    }

    pub fn loaded(&self) -> Option<Loaded> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .loaded
            .clone()
    }

    /// The next Notify sequence number (1, 2, ...).
    pub fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Record the MTLF subscribed to; models are fetched only from it.
    pub fn set_mtlf(&self, host: &str, port: u16) {
        *self.mtlf.lock().unwrap_or_else(|p| p.into_inner()) = Some((host.to_string(), port));
    }

    fn mtlf(&self) -> Option<(String, u16)> {
        self.mtlf.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn counts(&self) -> (u64, u64) {
        (
            self.verified.load(Ordering::Relaxed),
            self.refused.load(Ordering::Relaxed),
        )
    }
}

static ANLF: OnceLock<Anlf> = OnceLock::new();

/// The process's AnLF state, once the client was started.
pub fn anlf() -> Option<&'static Anlf> {
    ANLF.get()
}

/// The TS 29.520 `NwdafMLModelProvSubsc` the AnLF sends.
pub fn subscription_body(notify_uri: &str, threshold: u8) -> Value {
    json!({
        "mLEventSubscs": [{
            "mLEvent": MODEL_EVENT.as_str(),
            // The oneOf [mLEvent, mLEventFilter] (Table 5.4.6.2.3-1 NOTE 2):
            // an empty filter, i.e. no restriction.
            "mLEventFilter": {},
            "mlEvRepCon": { "mlAccuracyThreshold": threshold },
        }],
        "notifUri": notify_uri,
        "suppFeats": crate::ml_service::MLMODELPROVISION_SUPPORTED_FEATURES,
    })
}

/// An MTLF to subscribe to: where, and how to name it in logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlfTarget {
    pub host: String,
    pub port: u16,
    /// Its `nfInstanceId`, or the configured URI.
    pub id: String,
}

/// The first NWDAF in a TS 29.510 `SearchResult` offering
/// `nnwdaf-mlmodelprovision` that is not `own_id`.
pub fn mtlf_from_search_result(result: &Value, own_id: &str) -> Option<MtlfTarget> {
    for inst in result.get("nfInstances")?.as_array()? {
        let id = inst
            .get("nfInstanceId")
            .and_then(Value::as_str)
            .unwrap_or("");
        if inst.get("nfType").and_then(Value::as_str) != Some("NWDAF") || id == own_id {
            continue;
        }
        let Some(service) = inst
            .get("nfServices")
            .and_then(Value::as_array)
            .and_then(|s| {
                s.iter().find(|s| {
                    s.get("serviceName").and_then(Value::as_str) == Some("nnwdaf-mlmodelprovision")
                })
            })
        else {
            continue;
        };
        let ep = service
            .get("ipEndPoints")
            .and_then(Value::as_array)
            .and_then(|e| e.first());
        let host = ep
            .and_then(|e| e.get("ipv4Address"))
            .and_then(Value::as_str)
            .or_else(|| service.get("fqdn").and_then(Value::as_str))
            .or_else(|| {
                inst.get("ipv4Addresses")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
            })
            .or_else(|| inst.get("fqdn").and_then(Value::as_str));
        let port = ep
            .and_then(|e| e.get("port"))
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(80);
        if let Some(host) = host {
            return Some(MtlfTarget {
                host: host.to_string(),
                port,
                id: id.to_string(),
            });
        }
    }
    None
}

fn client(host: &str, port: u16) -> nextgcore_sbi::SbiClient {
    let c = crate::notification_dispatcher::notify_client(host, port);
    match crate::oauth2_client() {
        Some(oauth2) => c.with_oauth2(oauth2, nextgcore_sbi::types::NfType::Nwdaf),
        None => c,
    }
}

/// Resolve the MTLF: the configured URI, else discovery at `nrf_uri`.
pub async fn find_mtlf(
    config: &AnlfConfig,
    nrf_uri: &str,
    own_id: &str,
) -> Result<MtlfTarget, String> {
    if let Some(uri) = &config.mtlf_uri {
        let (host, port, _) = crate::notification_dispatcher::parse_notify_uri(uri)
            .ok_or_else(|| format!("invalid MTLF URI {uri:?}"))?;
        return Ok(MtlfTarget {
            host,
            port,
            id: uri.clone(),
        });
    }
    let (nrf_host, nrf_port, nrf_base) = crate::notification_dispatcher::parse_notify_uri(nrf_uri)
        .ok_or_else(|| format!("invalid NRF URI {nrf_uri:?}"))?;
    let disc = format!(
        "{}/nnrf-disc/v1/nf-instances?target-nf-type=NWDAF&requester-nf-type=NWDAF\
         &service-names=nnwdaf-mlmodelprovision",
        nrf_base.trim_end_matches('/')
    );
    let resp = crate::notification_dispatcher::notify_client(&nrf_host, nrf_port)
        .get(&disc)
        .await
        .map_err(|e| format!("MTLF discovery at the NRF failed: {e}"))?;
    if resp.status != 200 {
        return Err(format!("MTLF discovery answered {}", resp.status));
    }
    let result: Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or(""))
        .map_err(|e| format!("MTLF discovery answer is not JSON: {e}"))?;
    mtlf_from_search_result(&result, own_id)
        .ok_or_else(|| "the NRF knows no other NWDAF offering nnwdaf-mlmodelprovision".to_string())
}

/// One subscribe attempt. The MTLF's answer on 201.
pub async fn subscribe_once(
    anlf: &Anlf,
    target: &MtlfTarget,
    sbi_base: &str,
    threshold: u8,
) -> Result<Value, String> {
    let body = subscription_body(&anlf.notify_uri(sbi_base), threshold);
    let resp = client(&target.host, target.port)
        .post_json("/nnwdaf-mlmodelprovision/v1/subscriptions", &body)
        .await
        .map_err(|e| {
            format!(
                "Nnwdaf_MLModelProvision_Subscribe to {} failed: {e}",
                target.id
            )
        })?;
    if resp.status != 201 {
        return Err(format!(
            "Nnwdaf_MLModelProvision_Subscribe to {} answered {}",
            target.id, resp.status
        ));
    }
    let created: Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or(""))
        .map_err(|e| format!("subscription answer is not JSON: {e}"))?;
    let ext = created
        .get("suppFeats")
        .and_then(Value::as_str)
        .is_some_and(|f| {
            crate::ml_service::supp_feats_has(f, crate::ml_service::FEATURE_MODEL_PROVISION_EXT)
        });
    anlf.set_mtlf(&target.host, target.port);
    anlf.subscribed.store(true, Ordering::Relaxed);
    if ext {
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "subscribed to MTLF {} threshold={:.2}",
            target.id,
            f64::from(threshold) / 100.0
        );
    } else {
        nextgcore_demo::demo_log!(
            warn,
            DEMO_KEY,
            "subscribed to MTLF {} without ModelProvisionExt: the threshold {:.2} is not honoured",
            target.id,
            f64::from(threshold) / 100.0
        );
    }
    Ok(created)
}

/// Subscribe, retrying 2 s doubling to 30 s, until the MTLF accepts.
pub async fn run_client(config: AnlfConfig, nrf_uri: String, sbi_base: String, own_id: String) {
    let anlf = ANLF.get_or_init(Anlf::new);
    let mut backoff = Duration::from_secs(2);
    loop {
        let attempt = async {
            let target = find_mtlf(&config, &nrf_uri, &own_id).await?;
            subscribe_once(anlf, &target, &sbi_base, config.accuracy_threshold).await
        };
        match attempt.await {
            Ok(_) => return,
            Err(e) => {
                nextgcore_demo::demo_log!(warn, DEMO_KEY, "{e}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// Start the AnLF client (start-up, after the SBI server is up).
pub fn spawn_client(config: AnlfConfig, nrf_uri: String, sbi_base: String, own_id: String) {
    let _ = ANLF.get_or_init(Anlf::new);
    tokio::spawn(run_client(config, nrf_uri, sbi_base, own_id));
}

/// Constant-time token comparison.
fn token_matches(expected: &str, got: &str) -> bool {
    let (e, g) = (expected.as_bytes(), got.as_bytes());
    e.len() == g.len() && e.iter().zip(g).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The model URLs a `Nnwdaf_MLModelProvision_Notify` body names for
/// [`MODEL_EVENT`], or why the body is not one.
pub fn model_urls(body: &Value) -> Result<Vec<String>, String> {
    let notifs = body
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("the body is not a non-empty array of NwdafMLModelProvNotif")?;
    let mut urls = Vec::new();
    for n in notifs {
        if n.get("subscriptionId").and_then(Value::as_str).is_none() {
            return Err("NwdafMLModelProvNotif without subscriptionId".into());
        }
        let events = n
            .get("eventNotifs")
            .and_then(Value::as_array)
            .ok_or("NwdafMLModelProvNotif without eventNotifs")?;
        for e in events {
            if e.get("event").and_then(Value::as_str) != Some(MODEL_EVENT.as_str()) {
                continue;
            }
            if let Some(url) = e
                .get("mLFileAddr")
                .and_then(|a| a.get("mLModelUrl"))
                .and_then(Value::as_str)
            {
                if !urls.iter().any(|u| u == url) {
                    urls.push(url.to_string());
                }
            }
        }
    }
    Ok(urls)
}

/// `POST /nnwdaf-callback/v1/mtlf-model-notify/{token}`: store the
/// notification and answer 204 (TS 29.520 §4.5.2.4.2), then fetch and verify
/// in the background. No client running, or a token this process did not hand
/// out: 404. Not a notification: 400.
pub fn handle_model_notify(
    anlf: Option<&'static Anlf>,
    ctx: Arc<RwLock<NwdafContext>>,
    token: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let Some(anlf) = anlf.filter(|a| token_matches(&a.token, token)) else {
        return nextgcore_sbi::server::send_not_found("no such callback", None);
    };
    let body = request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<Value>(c).ok());
    let urls = match body.as_ref().map(model_urls) {
        Some(Ok(urls)) => urls,
        Some(Err(e)) => return nextgcore_sbi::server::send_bad_request(&e, None),
        None => return nextgcore_sbi::server::send_bad_request("body is not JSON", None),
    };
    for url in urls {
        let ctx = ctx.clone();
        // Numbered in arrival order, so a slow earlier fetch cannot replace a
        // model a later Notify already loaded.
        let seq = anlf.next_seq();
        tokio::spawn(async move {
            let _ = fetch_verify_load(anlf, &ctx, &url, seq, FETCH_TIMEOUT).await;
        });
    }
    SbiResponse::with_status(204)
}

/// Why a model was refused (nextgsim#463's `RefusalReason`, the subset that
/// applies to a `LinearRegressor` read without ONNX Runtime).
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    /// The URL names another origin than the MTLF subscribed to.
    ForeignHost(String),
    Unreachable(String),
    ManifestInvalid(String),
    Sha256Mismatch {
        expected: String,
        actual: String,
    },
    NotOnnx(String),
    OpsetMismatch {
        expected: i64,
        actual: Option<i64>,
    },
    SignatureMismatch(String),
    GoldenMismatch {
        index: usize,
        expected: f32,
        actual: f32,
    },
}

impl Refusal {
    /// The short form logged in `model refused (<kind>)`.
    pub fn kind(&self) -> &'static str {
        match self {
            Refusal::ForeignHost(_) => "foreign host",
            Refusal::Unreachable(_) => "unreachable",
            Refusal::ManifestInvalid(_) => "manifest invalid",
            Refusal::Sha256Mismatch { .. } => "sha256 mismatch",
            Refusal::NotOnnx(_) => "not onnx",
            Refusal::OpsetMismatch { .. } => "opset mismatch",
            Refusal::SignatureMismatch(_) => "signature mismatch",
            Refusal::GoldenMismatch { .. } => "golden mismatch",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::ForeignHost(e)
            | Refusal::Unreachable(e)
            | Refusal::ManifestInvalid(e)
            | Refusal::NotOnnx(e) => {
                write!(f, "{}: {e}", self.kind())
            }
            Refusal::SignatureMismatch(e) => write!(f, "{}: {e}", self.kind()),
            Refusal::Sha256Mismatch { expected, actual } => {
                write!(f, "sha256 mismatch: manifest {expected}, bytes {actual}")
            }
            Refusal::OpsetMismatch { expected, actual } => {
                write!(f, "opset mismatch: manifest {expected}, model {actual:?}")
            }
            Refusal::GoldenMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "golden mismatch: golden[{index}] expected {expected}, model {actual}"
            ),
        }
    }
}

/// nextgsim#463's `ModelManifest`, field for field.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub opset: i64,
    pub inputs: Vec<TensorSpec>,
    pub outputs: Vec<TensorSpec>,
    pub golden: Vec<Golden>,
    pub tolerance: f32,
    #[serde(default)]
    pub inference_name: Option<String>,
    #[serde(default)]
    pub training_type: Option<String>,
    #[serde(default)]
    pub producer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct TensorSpec {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Golden {
    pub input_shape: Vec<i64>,
    pub input: Vec<f32>,
    pub output_shape: Vec<i64>,
    pub output: Vec<f32>,
}

impl Manifest {
    /// Parse and sanity-check (nextgsim#463 `ModelManifest::validate`).
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        let m: Self = serde_json::from_str(text)
            .map_err(|e| Refusal::ManifestInvalid(format!("not a model manifest: {e}")))?;
        let bad = |s: String| Err(Refusal::ManifestInvalid(s));
        if m.id.is_empty() || m.version.is_empty() {
            return bad("id and version must be non-empty".into());
        }
        if !crate::model_store::is_sha256_hex(&m.sha256) {
            return bad(format!(
                "sha256 {:?} is not 64 lowercase hex digits",
                m.sha256
            ));
        }
        if m.inputs.is_empty() || m.outputs.is_empty() {
            return bad("inputs and outputs must be non-empty".into());
        }
        if !(m.tolerance.is_finite() && m.tolerance >= 0.0) {
            return bad(format!("tolerance {} must be finite and >= 0", m.tolerance));
        }
        if m.golden.is_empty() {
            return bad("golden must hold at least one vector".into());
        }
        for (i, g) in m.golden.iter().enumerate() {
            // One row of `width` inputs per output, at least one row: a
            // zero-row golden would make the golden check vacuous.
            let shaped = matches!(
                (g.input_shape.as_slice(), g.output_shape.as_slice()),
                ([r, w], [ro, 1]) if *r >= 1 && *w >= 1 && ro == r
            );
            if !shaped {
                return bad(format!(
                    "golden[{i}] shapes {:?} -> {:?} are not [rows>=1, n] -> [rows, 1]",
                    g.input_shape, g.output_shape
                ));
            }
            for (what, shape, len) in [
                ("input", &g.input_shape, g.input.len()),
                ("output", &g.output_shape, g.output.len()),
            ] {
                let elems = shape.iter().try_fold(1usize, |acc, &d| {
                    usize::try_from(d).ok().and_then(|d| acc.checked_mul(d))
                });
                if elems != Some(len) {
                    return bad(format!(
                        "golden[{i}].{what} has {len} values for shape {shape:?}"
                    ));
                }
            }
        }
        Ok(m)
    }
}

/// Verify `bytes` against `manifest`; the loadable model on a pass.
pub fn verify(
    bytes: &[u8],
    manifest: &Manifest,
) -> Result<crate::onnx_model::OnnxLinearRegressor, Refusal> {
    let actual = crate::model_store::sha256_hex(bytes);
    if actual != manifest.sha256 {
        return Err(Refusal::Sha256Mismatch {
            expected: manifest.sha256.clone(),
            actual,
        });
    }
    let sig = crate::onnx_model::signature(bytes).map_err(Refusal::NotOnnx)?;
    if sig.default_opset != Some(manifest.opset) {
        return Err(Refusal::OpsetMismatch {
            expected: manifest.opset,
            actual: sig.default_opset,
        });
    }
    let same = |a: &[crate::onnx_model::TensorSig], b: &[TensorSpec]| {
        a.len() == b.len()
            && a.iter()
                .zip(b)
                .all(|(x, y)| x.name == y.name && x.dtype == y.dtype && x.shape == y.shape)
    };
    if !same(&sig.inputs, &manifest.inputs) || !same(&sig.outputs, &manifest.outputs) {
        return Err(Refusal::SignatureMismatch(format!(
            "model {:?} -> {:?}, manifest {:?} -> {:?}",
            sig.inputs, sig.outputs, manifest.inputs, manifest.outputs
        )));
    }
    let model_id = format!("mtlf:{}:v{}", manifest.id, manifest.version);
    let model = crate::onnx_model::OnnxLinearRegressor::from_bytes(bytes, &model_id)
        .map_err(Refusal::NotOnnx)?;
    let (coef, intercept) = model
        .linear_form()
        .ok_or_else(|| Refusal::NotOnnx("the LinearRegressor has no linear form".to_string()))?;
    for (index, g) in manifest.golden.iter().enumerate() {
        let width = coef.len();
        if g.input_shape.len() != 2 || g.input_shape[1] != width as i64 {
            return Err(Refusal::ManifestInvalid(format!(
                "golden[{index}] input shape {:?} does not fit {width} coefficients",
                g.input_shape
            )));
        }
        for (row, x) in g.input.chunks(width).enumerate() {
            // ONNX LinearRegressor: Y = X·coefᵀ + intercept, in float32.
            let y = coef
                .iter()
                .zip(x)
                .fold(intercept as f32, |acc, (c, x)| acc + (*c as f32) * x);
            let expected = g.output.get(row).copied().unwrap_or(f32::NAN);
            if (y - expected).abs() > manifest.tolerance || !y.is_finite() {
                return Err(Refusal::GoldenMismatch {
                    index,
                    expected,
                    actual: y,
                });
            }
        }
    }
    Ok(model)
}

/// Fetch `url` and `<url>.manifest.json` from the MTLF: each GET, body
/// included, within `timeout`, and each body within [`MAX_MODEL_BYTES`].
pub async fn fetch(url: &str, timeout: Duration) -> Result<(Vec<u8>, String), Refusal> {
    let (host, port, path) = crate::notification_dispatcher::parse_notify_uri(url)
        .ok_or_else(|| Refusal::Unreachable(format!("{url:?} is not an http(s) URL")))?;
    let mut c = nextgcore_sbi::SbiClient::new(
        nextgcore_sbi::SbiClientConfig::new(&host, port)
            .with_connect_timeout(timeout)
            .with_request_timeout(timeout)
            .with_max_response_body(MAX_MODEL_BYTES),
    );
    if let Some(oauth2) = crate::oauth2_client() {
        c = c.with_oauth2(oauth2, nextgcore_sbi::types::NfType::Nwdaf);
    }
    let get = |what: &'static str, path: String| {
        let c = &c;
        async move {
            match tokio::time::timeout(timeout, c.get(&path)).await {
                Err(_) => Err(Refusal::Unreachable(format!(
                    "GET {what} did not complete within {timeout:?}"
                ))),
                Ok(Err(e)) => Err(Refusal::Unreachable(format!("GET {what}: {e}"))),
                Ok(Ok(r)) if r.status != 200 => Err(Refusal::Unreachable(format!(
                    "GET {what} answered {}",
                    r.status
                ))),
                Ok(Ok(r)) => Ok(r),
            }
        }
    };
    let model = get("model", path.clone()).await?;
    let bytes = model
        .http
        .binary_content
        .map(|b| b.to_vec())
        .ok_or_else(|| Refusal::Unreachable("the model is not application/octet-stream".into()))?;
    let manifest = get(
        "manifest",
        format!("{path}{}", crate::model_store::MANIFEST_SUFFIX),
    )
    .await?;
    Ok((bytes, manifest.http.content.unwrap_or_default()))
}

/// Fetch, verify and, on a pass, load the model at `url` into `ctx`. A refusal
/// keeps the model in use.
///
/// `seq` is the Notify's arrival number ([`Anlf::next_seq`]): a result older
/// than the model already loaded is dropped (`Ok(None)`), so a late v1 cannot
/// replace v2. Only the subscribed MTLF's `host:port` is fetched from.
pub async fn fetch_verify_load(
    anlf: &Anlf,
    ctx: &RwLock<NwdafContext>,
    url: &str,
    seq: u64,
    timeout: Duration,
) -> Result<Option<Loaded>, Refusal> {
    let outcome = async {
        let origin = crate::notification_dispatcher::parse_notify_uri(url)
            .map(|(h, p, _)| (h, p))
            .ok_or_else(|| Refusal::Unreachable(format!("{url:?} is not an http(s) URL")))?;
        match anlf.mtlf() {
            Some(mtlf) if mtlf == origin => {}
            mtlf => {
                return Err(Refusal::ForeignHost(format!(
                    "{}:{} is not the subscribed MTLF {}",
                    origin.0,
                    origin.1,
                    mtlf.map(|(h, p)| format!("{h}:{p}"))
                        .unwrap_or_else(|| "(none)".into())
                )))
            }
        }
        let (bytes, manifest) = fetch(url, timeout).await?;
        let manifest = Manifest::from_json(&manifest)?;
        let model = verify(&bytes, &manifest)?;
        Ok::<_, Refusal>((manifest, model))
    }
    .await;
    let keeping = || {
        anlf.loaded()
            .map(|l| format!("v{}", l.version))
            .unwrap_or_else(|| "the local predictor".to_string())
    };
    match outcome {
        Ok((manifest, model)) => {
            let loaded = Loaded {
                version: manifest.version.clone(),
                sha256: manifest.sha256.clone(),
                url: url.to_string(),
            };
            // Check the order and swap under one lock, so two fetches that
            // finish together apply in Notify order.
            let mut state = anlf.state.lock().unwrap_or_else(|p| p.into_inner());
            if seq < state.applied_seq {
                nextgcore_demo::demo_log!(
                    info,
                    DEMO_KEY,
                    "model v{} from {url} superseded by a later notify; keeping v{}",
                    loaded.version,
                    state
                        .loaded
                        .as_ref()
                        .map(|l| l.version.as_str())
                        .unwrap_or("?")
                );
                return Ok(None);
            }
            state.applied_seq = seq;
            if state
                .loaded
                .as_ref()
                .is_some_and(|l| l.sha256 == loaded.sha256)
            {
                return Ok(Some(loaded));
            }
            {
                let guard = ctx.read().unwrap_or_else(|p| p.into_inner());
                guard.lock_engine().set_predictor(Box::new(model));
            }
            state.loaded = Some(loaded.clone());
            drop(state);
            anlf.verified.fetch_add(1, Ordering::Relaxed);
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "model v{} verified sha256={} from {url}",
                loaded.version,
                loaded.sha256
            );
            Ok(Some(loaded))
        }
        Err(refusal) => {
            anlf.refused.fetch_add(1, Ordering::Relaxed);
            nextgcore_demo::demo_log!(
                warn,
                DEMO_KEY,
                "model refused ({}) from {url}: {refusal}; keeping {}",
                refusal.kind(),
                keeping()
            );
            Err(refusal)
        }
    }
}

/// This module's `/metrics` families.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    let a = anlf();
    nextgcore_metrics::nf::write_metric(
        out,
        "nwdaf_anlf_client_active",
        "gauge",
        "1 while this NWDAF runs the d441e AnLF model client (nextgsim#468)",
        u8::from(a.is_some()),
    );
    nextgcore_metrics::nf::write_metric(
        out,
        "nwdaf_anlf_mtlf_subscribed",
        "gauge",
        "1 once an MTLF accepted the AnLF's MLModelProvision subscription (nextgsim#468)",
        u8::from(a.is_some_and(|a| a.subscribed.load(Ordering::Relaxed))),
    );
    let (verified, refused) = a.map(Anlf::counts).unwrap_or((0, 0));
    nextgcore_metrics::nf::write_header(
        out,
        "nwdaf_anlf_models_total",
        "counter",
        "Provisioned models by outcome: verified and loaded, or refused (nextgsim#468)",
    );
    let _ = writeln!(
        out,
        "nwdaf_anlf_models_total{{outcome=\"verified\"}} {verified}"
    );
    let _ = writeln!(
        out,
        "nwdaf_anlf_models_total{{outcome=\"refused\"}} {refused}"
    );
}

#[cfg(test)]
mod tests;
