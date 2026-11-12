//! User Data Congestion analytics from RAN cell reports (nextgsim#465, demo
//! `d441a-congestion-loop`). Cargo feature `demo-d441a-congestion-loop`, off by
//! default.
//!
//! TS 23.288 §6.8.1 (`23288-k10.txt:16336-16365`): the NWDAF *"collects
//! measurements per cell and uses the measurements to determine user data
//! congestion analytics"*, for a consumer that *"may be an NF (e.g. NEF, AF,
//! PCF)"*. Table 6.8.2-1 (`:16424-16445`) names the inputs: OAM performance
//! measurements (e.g. *"Radio Resource Utilization"*) and the AMF's UE location;
//! how the NWDAF derives the Network Status Indication *"is not specified"*.
//!
//! This module is those inputs and the answer:
//!
//! 1. **Ingest** (non-normative). `POST /nnwdaf-randata/v1/cell-reports` on the
//!    existing SBI listener takes one cell's measured downlink occupancy per
//!    reporting window from the nextgsim gNB, standing in for the OAM PM path of
//!    TS 23.288 §6.2.3. It is a service request, not a notification, so OAuth2
//!    applies (TS 33.501 §13.4.1): every report must carry an NRF-issued token
//!    for audience NWDAF and scope `nnwdaf-randata`, verified here against the
//!    NRF's JWKS **whatever the listener's own `require_oauth2` setting** (fail
//!    closed: no or bad token 401, wrong scope 403, keys unavailable 503, and
//!    nothing is ingested). The route is checked here rather than by turning on
//!    listener-wide OAuth2 because that would also reject amfd's token-less
//!    UES_IN_AREA notify on the same listener (nextgcore#1421).
//! 2. **UE count** (TS 23.288 Table 6.8.2-1 "UE Location", AMF). For each
//!    reported TAI the NWDAF subscribes at the AMF to `UES_IN_AREA_REPORT`
//!    (TS 29.518 §5.3.1) through #466's Namf_EventExposure client, and logs the
//!    AMF's `numberOfUes` beside the gNB's connected-UE count: a cross-check, not
//!    an input to the congestion level.
//! 3. **Answer.** `Nnwdaf_AnalyticsInfo` `USER_DATA_CONGESTION` builds TS 29.520
//!    `userDataCongInfos` (`UserDataCongestionInfo`, Table 5.1.6.2.17-1;
//!    `CongestionInfo`, Table 5.1.6.2.18-1) per reported cell in the requested
//!    `networkArea`, `nsi.congLevel` = the cell's downlink occupancy in percent.
//!    No ana-req, or a past one: statistics. A future one: the gNB's prediction,
//!    with `confidence`. No fresh report: 204.
//!
//! # Modes
//!
//! nwdafd acts on the demo being enabled and logs the mode. The mode selects what
//! the gNB exports (`no-loop`: nothing, so this NWDAF answers 204); the PCF picks
//! statistics or predictions through `ana-req`.
//!
//! # Honesty
//!
//! The cell capacity and the occupancy are the simulator's (a token-bucket queue
//! at a configured capacity). Occupancy as `congLevel` is this implementation's
//! NSI derivation, which TS 23.288 leaves unspecified. The prediction is the
//! gNB's 8-sample least-squares fit, not a model trained here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};

/// The demo key (nextgsim#458 convention).
pub const DEMO_KEY: &str = "d441a-congestion-loop";
/// Modes, shared with the gNB and pcfd.
pub const MODES: &[&str] = &["statistics", "prediction", "no-loop"];

/// What this binary registers under the `demo-d441a-congestion-loop` feature.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: MODES,
    requires: &[],
};

/// The non-normative ingest service, advertised in `nfServices` while serving so
/// the NRF can grant a token for it.
pub const SERVICE_NAME: &str = "nnwdaf-randata";
/// Who may get a token for [`SERVICE_NAME`]: the gNB's exporter registers as an
/// AF (TS 23.288 §6.1 trusted AF), the NF type nearest an OAM PM producer that
/// TS 29.510 `NFType` has.
pub const SERVICE_ALLOWED_NF_TYPES: &[&str] = &["AF"];

/// The AMF callback path segment; the next segment is the token. Listed in
/// `nextgcore_sbi::log_redact::CALLBACK_TOKEN_SEGMENTS`.
pub const CALLBACK_SEGMENT: &str = "amf-ues-in-area-notify";

/// A report older than this many reporting windows is stale.
pub const STALE_WINDOWS: u64 = 3;
/// ... and never fresher than this, whatever window the gNB uses.
pub const MIN_STALENESS_MS: u64 = 3_000;
/// Reports kept per cell, for a statistics window.
pub const HISTORY: usize = 120;
/// Cells and TAIs one process tracks. The ingest is AF-only behind an NRF
/// token, but one authenticated client must not grow the store (and the AMF
/// subscription tasks, one per TAI) without bound.
pub const MAX_CELLS: usize = 64;
pub const MAX_TAIS: usize = 16;

static SERVING: AtomicBool = AtomicBool::new(false);
static CALLBACK_TOKEN: OnceLock<String> = OnceLock::new();
static JWKS: OnceLock<nextgcore_sbi::oauth::JwksCache> = OnceLock::new();
static STORE: OnceLock<CellStore> = OnceLock::new();

/// Report outcomes for `/metrics`.
static INGESTED: AtomicU64 = AtomicU64::new(0);
static UNAUTHORIZED: AtomicU64 = AtomicU64::new(0);
static FORBIDDEN: AtomicU64 = AtomicU64::new(0);
static MALFORMED: AtomicU64 = AtomicU64::new(0);
static UNAVAILABLE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static SERVING_ON_THIS_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only: serve USER_DATA_CONGESTION on this thread for the guard's lifetime
/// without touching the process-wide flag (the `amf_mobility` pattern).
#[cfg(test)]
pub(crate) struct ServingOnThisThread;

#[cfg(test)]
impl ServingOnThisThread {
    pub(crate) fn new() -> Self {
        SERVING_ON_THIS_THREAD.with(|s| s.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for ServingOnThisThread {
    fn drop(&mut self) {
        SERVING_ON_THIS_THREAD.with(|s| s.set(false));
    }
}

/// Whether this process serves the ingest route and USER_DATA_CONGESTION: the
/// demo block is active (any mode).
pub fn serving() -> bool {
    #[cfg(test)]
    if SERVING_ON_THIS_THREAD.with(|s| s.get()) {
        return true;
    }
    SERVING.load(Ordering::Relaxed)
}

/// Decide once at start-up, before the NRF registration, from the active mode.
/// `nrf_uri` is where the ingest route fetches the keys it verifies tokens with.
pub fn install(mode: Option<&str>, nrf_uri: &str) {
    let Some(mode) = mode else { return };
    SERVING.store(true, Ordering::Relaxed);
    if !nrf_uri.is_empty() {
        let _ = JWKS.set(nextgcore_sbi::oauth::JwksCache::for_nrf(nrf_uri));
    }
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "user-data-congestion: on (mode={mode}; ingest at /{SERVICE_NAME}/v1/cell-reports, \
         OAuth2 scope {SERVICE_NAME} required; USER_DATA_CONGESTION served)"
    );
}

/// The process's cell-report store.
pub fn store() -> &'static CellStore {
    STORE.get_or_init(CellStore::default)
}

/// The JWKS the process verifies ingest tokens with, if an NRF is configured.
fn jwks() -> Option<&'static nextgcore_sbi::oauth::JwksCache> {
    JWKS.get()
}

/// One cell's identity as reported: PLMN and NR cell id (TS 29.571 `Ncgi`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellKey {
    pub mcc: String,
    pub mnc: String,
    /// 9 hex digits, uppercased.
    pub nr_cell_id: String,
}

impl CellKey {
    fn ncgi_json(&self) -> Value {
        json!({ "plmnId": { "mcc": self.mcc, "mnc": self.mnc }, "nrCellId": self.nr_cell_id })
    }
}

impl std::fmt::Display for CellKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}-{}", self.mcc, self.mnc, self.nr_cell_id)
    }
}

/// A TAI as reported (TS 29.571 `Tai`), the AMF UES_IN_AREA area key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaiKey {
    pub mcc: String,
    pub mnc: String,
    /// Six uppercase hex digits ([`canonical_tac`]): TS 29.571 `Tac` is 4 or 6
    /// digits, and amfd writes a TAC below 0x10000 with 4, so the same TAI must
    /// compare equal in either spelling.
    pub tac: String,
}

/// A 4- or 6-hex-digit TAC as six uppercase digits.
pub fn canonical_tac(tac: &str) -> Option<String> {
    if !matches!(tac.len(), 4 | 6) || !tac.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(tac, 16)
        .ok()
        .map(|v| format!("{v:06X}"))
}

impl TaiKey {
    fn json(&self) -> Value {
        json!({ "plmnId": { "mcc": self.mcc, "mnc": self.mnc }, "tac": self.tac })
    }
}

impl std::fmt::Display for TaiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}-{}", self.mcc, self.mnc, self.tac)
    }
}

/// The gNB's prediction for a cell.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Prediction {
    pub occupancy_pct: f64,
    pub horizon_ms: u64,
    /// 0..=100.
    pub confidence: u64,
}

/// One accepted cell report.
#[derive(Debug, Clone, PartialEq)]
pub struct CellReport {
    pub cell: CellKey,
    pub tai: TaiKey,
    /// End of the reporting window, unix ms.
    pub ts_ms: u64,
    pub window_ms: u64,
    pub capacity_kbps: u64,
    pub dl_served_kbps: u64,
    pub occupancy_pct: f64,
    pub connected_ues: u64,
    pub prediction: Option<Prediction>,
}

impl CellReport {
    /// Whether this report is too old to describe the cell at `now_ms`.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        let limit = (self.window_ms * STALE_WINDOWS).max(MIN_STALENESS_MS);
        now_ms.saturating_sub(self.ts_ms) > limit
    }
}

fn hex_field(v: &Value, key: &str, len: &[usize]) -> Result<String, String> {
    let s = v
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} is required"))?;
    if !len.contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{key} {s:?} must be {len:?} hex digits"));
    }
    Ok(s.to_ascii_uppercase())
}

fn plmn(v: &Value, what: &str) -> Result<(String, String), String> {
    let p = v
        .get("plmnId")
        .ok_or_else(|| format!("{what}.plmnId is required"))?;
    let digits = |k: &str, lens: &[usize]| -> Result<String, String> {
        let s = p
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{what}.plmnId.{k} is required"))?;
        if !lens.contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{what}.plmnId.{k} {s:?} is not {lens:?} digits"));
        }
        Ok(s.to_string())
    };
    Ok((digits("mcc", &[3])?, digits("mnc", &[2, 3])?))
}

fn number(v: &Value, key: &str) -> Result<f64, String> {
    v.get(key)
        .and_then(Value::as_f64)
        .filter(|n| n.is_finite() && *n >= 0.0)
        .ok_or_else(|| format!("{key} must be a non-negative number"))
}

fn uint(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be a non-negative integer"))
}

/// Parse a cell report body (the contract with the nextgsim gNB exporter).
pub fn parse_report(body: &Value) -> Result<CellReport, String> {
    let ncgi = body.get("ncgi").ok_or("ncgi is required")?;
    let (mcc, mnc) = plmn(ncgi, "ncgi")?;
    let nr_cell_id = hex_field(ncgi, "nrCellId", &[9])?;
    let tai_v = body.get("tai").ok_or("tai is required")?;
    let (tmcc, tmnc) = plmn(tai_v, "tai")?;
    let tac = canonical_tac(&hex_field(tai_v, "tac", &[4, 6])?).ok_or("tai.tac is not a TAC")?;
    let ts = body
        .get("timeStamp")
        .and_then(Value::as_str)
        .ok_or("timeStamp is required")?;
    let ts_ms = chrono::DateTime::parse_from_rfc3339(ts)
        .map_err(|e| format!("timeStamp {ts:?} is not RFC 3339: {e}"))?
        .timestamp_millis();
    let ts_ms = u64::try_from(ts_ms).map_err(|_| "timeStamp is before 1970".to_string())?;
    let window_ms = uint(body, "windowMs")?;
    if window_ms == 0 {
        return Err("windowMs must be positive".into());
    }
    let capacity_kbps = uint(body, "capacityKbps")?;
    if capacity_kbps == 0 {
        return Err("capacityKbps must be positive".into());
    }
    let occupancy_pct = number(body, "occupancyPct")?;
    if occupancy_pct > 100.0 {
        return Err(format!("occupancyPct {occupancy_pct} exceeds 100"));
    }
    let prediction = match body.get("prediction") {
        None | Some(Value::Null) => None,
        Some(p) => {
            let occupancy_pct = number(p, "occupancyPct")?.min(100.0);
            let confidence = uint(p, "confidence")?;
            if confidence > 100 {
                return Err(format!("prediction.confidence {confidence} exceeds 100"));
            }
            Some(Prediction {
                occupancy_pct,
                horizon_ms: uint(p, "horizonMs")?,
                confidence,
            })
        }
    };
    Ok(CellReport {
        cell: CellKey {
            mcc,
            mnc,
            nr_cell_id,
        },
        tai: TaiKey {
            mcc: tmcc,
            mnc: tmnc,
            tac,
        },
        ts_ms,
        window_ms,
        capacity_kbps,
        dl_served_kbps: uint(body, "dlServedKbps")?,
        occupancy_pct,
        connected_ues: uint(body, "connectedUes")?,
        prediction,
    })
}

/// Cell reports and AMF UE counts, by cell and TAI.
#[derive(Debug, Default)]
pub struct CellStore {
    cells: Mutex<BTreeMap<CellKey, Vec<CellReport>>>,
    ues_in_area: Mutex<HashMap<TaiKey, u64>>,
    /// TAIs an AMF subscription has been started for.
    subscribed: Mutex<HashSet<TaiKey>>,
}

impl CellStore {
    /// Keep `report`, newest last, at most [`HISTORY`] per cell. False (and
    /// nothing kept) for a new cell beyond [`MAX_CELLS`].
    pub fn ingest(&self, report: CellReport) -> bool {
        if let Ok(mut cells) = self.cells.lock() {
            if !cells.contains_key(&report.cell) && cells.len() >= MAX_CELLS {
                return false;
            }
            let list = cells.entry(report.cell.clone()).or_default();
            list.push(report);
            if list.len() > HISTORY {
                let excess = list.len() - HISTORY;
                list.drain(..excess);
            }
            return true;
        }
        false
    }

    /// The newest report per cell.
    pub fn latest(&self) -> Vec<CellReport> {
        self.cells
            .lock()
            .map(|c| c.values().filter_map(|l| l.last().cloned()).collect())
            .unwrap_or_default()
    }

    /// Every kept report of `cell` with a timestamp in `[from_ms, to_ms]`.
    pub fn between(&self, cell: &CellKey, from_ms: u64, to_ms: u64) -> Vec<CellReport> {
        self.cells
            .lock()
            .ok()
            .and_then(|c| {
                c.get(cell).map(|l| {
                    l.iter()
                        .filter(|r| r.ts_ms >= from_ms && r.ts_ms <= to_ms)
                        .cloned()
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    /// The cells with any report.
    pub fn cells(&self) -> Vec<CellKey> {
        self.cells
            .lock()
            .map(|c| c.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The AMF's last `numberOfUes` for `tai`.
    pub fn ues_in_area(&self, tai: &TaiKey) -> Option<u64> {
        self.ues_in_area
            .lock()
            .ok()
            .and_then(|m| m.get(tai).copied())
    }

    fn set_ues_in_area(&self, tai: TaiKey, n: u64) {
        if let Ok(mut m) = self.ues_in_area.lock() {
            m.insert(tai, n);
        }
    }

    /// True the first time `tai` is seen, so the caller starts its subscription;
    /// false beyond [`MAX_TAIS`].
    fn first_sight(&self, tai: &TaiKey) -> bool {
        self.subscribed
            .lock()
            .map(|mut s| {
                if s.contains(tai) || s.len() >= MAX_TAIS {
                    return false;
                }
                s.insert(tai.clone())
            })
            .unwrap_or(false)
    }
}

/// Why a cell report was refused, and its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No, malformed or unverifiable bearer token (401).
    Unauthorized(String),
    /// A valid token whose scope does not cover [`SERVICE_NAME`] (403).
    Forbidden(String),
    /// The keys to verify with are unavailable (503).
    Unavailable(String),
}

/// Verify the request's bearer token: audience NWDAF, scope [`SERVICE_NAME`].
/// Returns the token's `sub` (the exporter's nfInstanceId).
pub async fn verify_token(
    jwks: Option<&nextgcore_sbi::oauth::JwksCache>,
    request: &SbiRequest,
) -> Result<String, Refusal> {
    use nextgcore_sbi::error::SbiError;
    let Some(jwks) = jwks else {
        return Err(Refusal::Unavailable(
            "no NRF is configured, so no token can be verified".into(),
        ));
    };
    let header = request.http.get_header("authorization").map(|s| s.as_str());
    let claims = match jwks.authorize_aud(header, Some("NWDAF")).await {
        Ok(c) => c,
        Err(SbiError::AuthorizationFailed(m)) => return Err(Refusal::Unauthorized(m)),
        Err(e) => return Err(Refusal::Unavailable(e.to_string())),
    };
    if let Err(e) = nextgcore_sbi::oauth::check_token_scope(&claims.scope, SERVICE_NAME) {
        return Err(Refusal::Forbidden(e.to_string()));
    }
    Ok(claims.sub)
}

/// What [`ingest_report`] decided, for the caller (the route) to act on.
#[derive(Debug)]
pub struct Ingested {
    pub response: SbiResponse,
    /// Set the first time a TAI is reported: the caller subscribes at the AMF.
    pub new_tai: Option<TaiKey>,
}

/// `POST /nnwdaf-randata/v1/cell-reports` against an explicit store and JWKS.
pub async fn ingest_report(
    store: &CellStore,
    jwks: Option<&nextgcore_sbi::oauth::JwksCache>,
    request: &SbiRequest,
) -> Ingested {
    let done = |response| Ingested {
        response,
        new_tai: None,
    };
    if !serving() {
        return done(nextgcore_sbi::server::send_not_found(
            "no such resource",
            None,
        ));
    }
    let sub = match verify_token(jwks, request).await {
        Ok(sub) => sub,
        Err(refusal) => {
            let (counter, resp) = match &refusal {
                Refusal::Unauthorized(m) => (
                    &UNAUTHORIZED,
                    nextgcore_sbi::server::send_unauthorized(m, None).with_header(
                        "WWW-Authenticate",
                        "Bearer realm=\"5gc-sbi\", error=\"invalid_token\"",
                    ),
                ),
                Refusal::Forbidden(m) => (
                    &FORBIDDEN,
                    nextgcore_sbi::server::send_forbidden(m, None).with_header(
                        "WWW-Authenticate",
                        "Bearer realm=\"5gc-sbi\", error=\"insufficient_scope\"",
                    ),
                ),
                Refusal::Unavailable(m) => (
                    &UNAVAILABLE,
                    nextgcore_sbi::server::send_error(503, "Service Unavailable", m, None),
                ),
            };
            counter.fetch_add(1, Ordering::Relaxed);
            nextgcore_demo::demo_log!(
                warn,
                DEMO_KEY,
                "ran-ingest refused ({}): {refusal:?}; nothing ingested",
                resp.status
            );
            return done(resp);
        }
    };
    let body = match request
        .http
        .content
        .as_deref()
        .map(serde_json::from_str::<Value>)
    {
        Some(Ok(v)) => v,
        _ => {
            MALFORMED.fetch_add(1, Ordering::Relaxed);
            return done(nextgcore_sbi::server::send_bad_request(
                "a JSON cell report is required",
                Some("INVALID_MSG_FORMAT"),
            ));
        }
    };
    let report = match parse_report(&body) {
        Ok(r) => r,
        Err(e) => {
            MALFORMED.fetch_add(1, Ordering::Relaxed);
            return done(nextgcore_sbi::server::send_bad_request(
                &e,
                Some("MANDATORY_IE_INCORRECT"),
            ));
        }
    };
    let amf = store
        .ues_in_area(&report.tai)
        .map_or_else(|| "-".to_string(), |n| n.to_string());
    let predicted = report.prediction.map_or_else(String::new, |p| {
        format!(
            " predicted={:.1}% conf={} horizon_ms={}",
            p.occupancy_pct, p.confidence, p.horizon_ms
        )
    });
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "ran-ingest cell={} tai={} occupancy={:.1}% served_kbps={}/{} connected_ues={} \
         amf_ues_in_area={amf}{predicted} from={sub}",
        report.cell,
        report.tai,
        report.occupancy_pct,
        report.dl_served_kbps,
        report.capacity_kbps,
        report.connected_ues,
    );
    let tai = report.tai.clone();
    if !store.ingest(report) {
        MALFORMED.fetch_add(1, Ordering::Relaxed);
        return done(nextgcore_sbi::server::send_error(
            429,
            "Too Many Requests",
            &format!("this NWDAF tracks at most {MAX_CELLS} cells"),
            None,
        ));
    }
    let new_tai = store.first_sight(&tai).then_some(tai);
    INGESTED.fetch_add(1, Ordering::Relaxed);
    Ingested {
        response: SbiResponse::with_status(204),
        new_tai,
    }
}

/// The route: [`ingest_report`] on the process store, then the AMF subscription
/// for a TAI seen for the first time.
pub async fn handle_cell_report(request: &SbiRequest) -> SbiResponse {
    let out = ingest_report(store(), jwks(), request).await;
    if let (Some(tai), Some(ctx)) = (out.new_tai, AMF_SUB_CTX.get()) {
        spawn_ues_in_area_subscriber(ctx.clone(), tai);
    }
    out.response
}

// ── AMF UES_IN_AREA_REPORT (TS 29.518 §5.3.1, Table 6.2.6.2.5-1) ─────────────

/// What the AMF subscription needs from start-up.
#[derive(Debug, Clone)]
pub struct AmfSubContext {
    pub nrf_uri: String,
    pub sbi_base: String,
    pub nf_id: String,
}

static AMF_SUB_CTX: OnceLock<AmfSubContext> = OnceLock::new();

/// Record what [`handle_cell_report`] subscribes with. Call once at start-up.
pub fn set_amf_sub_context(ctx: AmfSubContext) {
    let _ = AMF_SUB_CTX.set(ctx);
}

/// This process's callback token: a UUID v4, so 122 random bits, as hex.
pub fn callback_token() -> &'static str {
    CALLBACK_TOKEN.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
}

/// The `AmfCreateEventSubscription` body: UES_IN_AREA_REPORT for any UE in
/// `tai`, with an immediate report (NOTE 8: last known location) so the count is
/// known before the next registration.
pub fn ues_in_area_body(sbi_base: &str, nf_id: &str, tai: &TaiKey, expiry_rfc3339: &str) -> Value {
    json!({
        "subscription": {
            "eventList": [{
                "type": "UES_IN_AREA_REPORT",
                "immediateFlag": true,
                "areaList": [{ "presenceInfo": { "trackingAreaList": [tai.json()] } }],
            }],
            "eventNotifyUri": format!(
                "{}/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/{}",
                sbi_base.trim_end_matches('/'),
                callback_token()
            ),
            "notifyCorrelationId": format!("nwdaf-udc-{tai}"),
            "nfId": nf_id,
            "anyUE": true,
            "options": { "trigger": "CONTINUOUS", "expiry": expiry_rfc3339 },
        }
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn rfc3339_secs(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .unwrap_or_default()
        .to_rfc3339()
}

fn rfc3339_ms(ms: u64) -> String {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Hold a UES_IN_AREA_REPORT subscription for `tai` for the life of the process:
/// subscribe (2 s doubling to 30 s), renew, re-subscribe when the AMF lost it.
pub async fn maintain_ues_in_area(ctx: AmfSubContext, tai: TaiKey) {
    let lifetime = crate::amf_mobility::Lifetime::DEFAULT;
    loop {
        let mut backoff = Duration::from_secs(2);
        let sub = loop {
            match subscribe_ues_in_area(store(), &ctx, &tai, unix_now() + lifetime.ttl.as_secs())
                .await
            {
                Ok(sub) => break sub,
                Err(e) => {
                    nextgcore_demo::demo_log!(
                        warn,
                        DEMO_KEY,
                        "AMF UES_IN_AREA_REPORT subscription for tai={tai}: {e}; retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        };
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "subscribed to AMF UES_IN_AREA_REPORT tai={tai} id={}",
            sub.id
        );
        loop {
            tokio::time::sleep(lifetime.renew_every).await;
            match crate::amf_mobility::renew_once(&sub, unix_now() + lifetime.ttl.as_secs()).await {
                Ok(()) => {}
                Err(crate::amf_mobility::RenewError::Gone) => break,
                Err(crate::amf_mobility::RenewError::Other(e)) => {
                    nextgcore_demo::demo_log!(
                        warn,
                        DEMO_KEY,
                        "renewing UES_IN_AREA_REPORT subscription {}: {e}",
                        sub.id
                    );
                }
            }
        }
    }
}

fn spawn_ues_in_area_subscriber(ctx: AmfSubContext, tai: TaiKey) {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::spawn(maintain_ues_in_area(ctx, tai));
    }
}

/// The TAI of the first area in a UES_IN_AREA_REPORT's `areaList`.
fn report_tai(report: &Value) -> Option<TaiKey> {
    let tai = report
        .get("areaList")?
        .as_array()?
        .first()?
        .pointer("/presenceInfo/trackingAreaList/0")?;
    let (mcc, mnc) = plmn(tai, "tai").ok()?;
    let tac = canonical_tac(tai.get("tac")?.as_str()?)?;
    Some(TaiKey { mcc, mnc, tac })
}

/// `POST /nnwdaf-callback/v1/amf-ues-in-area-notify/{token}`. A token this
/// process did not hand out, or a process not serving: 404, nothing kept.
pub fn handle_ues_in_area_notify(
    store: &CellStore,
    token: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let genuine = CALLBACK_TOKEN.get().is_some_and(|t| {
        t.len() == token.len()
            && t.bytes()
                .zip(token.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    });
    if !serving() || !genuine {
        return nextgcore_sbi::server::send_not_found(
            "no such AMF event subscription callback",
            Some("RESOURCE_URI_STRUCTURE_NOT_FOUND"),
        );
    }
    let body: Value = match request
        .http
        .content
        .as_deref()
        .map(serde_json::from_str::<Value>)
    {
        Some(Ok(v)) if v.get("reportList").is_some_and(Value::is_array) => v,
        _ => {
            return nextgcore_sbi::server::send_bad_request(
                "an AmfEventNotification with a reportList is required",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    keep_ues_in_area(store, &body);
    SbiResponse::with_status(204)
}

/// Keep every UES_IN_AREA_REPORT's `numberOfUes` of a `reportList`: a notify's,
/// or the immediate reports in the subscription's 201.
fn keep_ues_in_area(store: &CellStore, body: &Value) {
    for r in body
        .get("reportList")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if r.get("type").and_then(Value::as_str) != Some("UES_IN_AREA_REPORT") {
            continue;
        }
        let (Some(tai), Some(n)) = (report_tai(r), r.get("numberOfUes").and_then(Value::as_u64))
        else {
            continue;
        };
        nextgcore_demo::demo_log!(info, DEMO_KEY, "ues-in-area tai={tai} numberOfUes={n}");
        store.set_ues_in_area(tai, n);
    }
}

/// One UES_IN_AREA_REPORT subscribe for `tai`, keeping the AMF's immediate
/// report (NOTE 8: the UEs' last known location) from the 201.
pub async fn subscribe_ues_in_area(
    store: &CellStore,
    ctx: &AmfSubContext,
    tai: &TaiKey,
    expiry_secs: u64,
) -> Result<crate::amf_mobility::AmfSubscription, String> {
    let body = ues_in_area_body(&ctx.sbi_base, &ctx.nf_id, tai, &rfc3339_secs(expiry_secs));
    let (sub, created) =
        crate::amf_mobility::subscribe_with_body_answer(&ctx.nrf_uri, &body).await?;
    keep_ues_in_area(store, &created);
    Ok(sub)
}

// ── USER_DATA_CONGESTION answer ─────────────────────────────────────────────

/// What the consumer asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    /// Statistics: the newest fresh report, or the mean over a past window
    /// `[start_ms, end_ms]`.
    Statistics(Option<(u64, u64)>),
    /// A prediction for the future window `[start_ms, end_ms]`.
    Prediction { start_ms: u64, end_ms: u64 },
}

/// The cells of `event-filter.networkArea` (TS 29.554 `NetworkAreaInfo`): `ncgis`
/// and/or `tais`. `Err` when absent or naming nothing (TS 29.520 §4.3.2.2.2: the
/// area is mandatory for an any-UE USER_DATA_CONGESTION request).
pub fn area_filter(event_filter: Option<&str>) -> Result<(Vec<CellKey>, Vec<TaiKey>), String> {
    let raw = event_filter
        .filter(|s| !s.is_empty())
        .ok_or("event-filter.networkArea is required for USER_DATA_CONGESTION with anyUe")?;
    let v: Value =
        serde_json::from_str(raw).map_err(|e| format!("event-filter is not JSON: {e}"))?;
    let area = v
        .get("networkArea")
        .ok_or("event-filter.networkArea is required for USER_DATA_CONGESTION with anyUe")?;
    let mut cells = Vec::new();
    for n in area
        .get("ncgis")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (mcc, mnc) = plmn(n, "networkArea.ncgis[]")?;
        cells.push(CellKey {
            mcc,
            mnc,
            nr_cell_id: hex_field(n, "nrCellId", &[9])?,
        });
    }
    let mut tais = Vec::new();
    for t in area
        .get("tais")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (mcc, mnc) = plmn(t, "networkArea.tais[]")?;
        tais.push(TaiKey {
            mcc,
            mnc,
            tac: canonical_tac(&hex_field(t, "tac", &[4, 6])?)
                .ok_or("networkArea.tais[].tac is not a TAC")?,
        });
    }
    if cells.is_empty() && tais.is_empty() {
        return Err("event-filter.networkArea names no ncgis or tais this NWDAF can match".into());
    }
    Ok((cells, tais))
}

fn in_area(r: &CellReport, cells: &[CellKey], tais: &[TaiKey]) -> bool {
    cells.contains(&r.cell) || tais.contains(&r.tai)
}

/// The `userDataCongInfos` for the area, at `now_ms`. Empty when no cell in the
/// area has data for the ask.
pub fn user_data_cong_infos(
    store: &CellStore,
    cells: &[CellKey],
    tais: &[TaiKey],
    ask: Ask,
    now_ms: u64,
) -> Vec<Value> {
    let mut out = Vec::new();
    for latest in store.latest() {
        if !in_area(&latest, cells, tais) {
            continue;
        }
        let info = match ask {
            Ask::Statistics(None) => {
                if latest.is_stale(now_ms) {
                    continue;
                }
                json!({
                    "congType": "USER_PLANE",
                    "timeIntev": {
                        "startTime": rfc3339_ms(latest.ts_ms.saturating_sub(latest.window_ms)),
                        "stopTime": rfc3339_ms(latest.ts_ms),
                    },
                    "nsi": { "congLevel": latest.occupancy_pct.round() as u64 },
                })
            }
            Ask::Statistics(Some((from, to))) => {
                let window = store.between(&latest.cell, from, to);
                if window.is_empty() {
                    continue;
                }
                let mean =
                    window.iter().map(|r| r.occupancy_pct).sum::<f64>() / window.len() as f64;
                json!({
                    "congType": "USER_PLANE",
                    "timeIntev": { "startTime": rfc3339_ms(from), "stopTime": rfc3339_ms(to) },
                    "nsi": { "congLevel": mean.round() as u64 },
                })
            }
            Ask::Prediction { start_ms, end_ms } => {
                let Some(p) = latest.prediction.filter(|_| !latest.is_stale(now_ms)) else {
                    continue;
                };
                json!({
                    "congType": "USER_PLANE",
                    "timeIntev": { "startTime": rfc3339_ms(start_ms), "stopTime": rfc3339_ms(end_ms) },
                    "nsi": { "congLevel": p.occupancy_pct.round() as u64 },
                    // Table 5.1.6.2.18-1: "Shall be present if the analytics result
                    // is a prediction".
                    "confidence": p.confidence,
                })
            }
        };
        out.push(json!({
            "networkArea": { "ncgis": [latest.cell.ncgi_json()] },
            "congestionInfo": info,
        }));
    }
    out
}

/// The USER_DATA_CONGESTION arm of `GET /nnwdaf-analyticsinfo/v1/analytics`.
///
/// `any_ue` / `names_ues` come from `tgt-ue`; `period` from `ana-req` as
/// `(start, end, is_statistics)`.
pub fn udc_response(
    store: &CellStore,
    any_ue: bool,
    names_ues: bool,
    event_filter: Option<&str>,
    period: Option<(
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
        bool,
    )>,
    now: chrono::DateTime<chrono::Utc>,
) -> SbiResponse {
    if !any_ue && !names_ues {
        return nextgcore_sbi::server::send_bad_request(
            "USER_DATA_CONGESTION requires tgt-ue (supis or anyUe) (TS 29.520 §4.3.2.2.2)",
            Some("MANDATORY_QUERY_PARAM_INCORRECT"),
        );
    }
    if !any_ue {
        // §6.8.1: for a UE ID the NWDAF determines the UE's area. This arm keeps
        // no UE-to-cell mapping, so there is no analytics for that scope.
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "udc: tgt-ue names UEs; this NWDAF resolves no UE to a cell for \
             USER_DATA_CONGESTION → 204"
        );
        return SbiResponse::with_status(204);
    }
    let (cells, tais) = match area_filter(event_filter) {
        Ok(a) => a,
        Err(e) => return nextgcore_sbi::server::send_bad_request(&e, Some("INVALID_QUERY_PARAM")),
    };
    let ms = |t: chrono::DateTime<chrono::Utc>| t.timestamp_millis().max(0) as u64;
    let ask = match period {
        None => Ask::Statistics(None),
        Some((s, e, true)) => Ask::Statistics(Some((ms(s), ms(e)))),
        Some((s, e, false)) => Ask::Prediction {
            start_ms: ms(s),
            end_ms: ms(e),
        },
    };
    let infos = user_data_cong_infos(store, &cells, &tais, ask, ms(now));
    let kind = match ask {
        Ask::Prediction { .. } => "prediction",
        Ask::Statistics(_) => "statistics",
    };
    if infos.is_empty() {
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "udc GET USER_DATA_CONGESTION kind={kind} → 204 (no fresh cell report in the area)"
        );
        if let Ask::Statistics(Some(_)) = ask {
            return nextgcore_sbi::server::send_error(
                500,
                "Internal Server Error",
                "no cell report was collected inside the requested analytics target period",
                Some("UNAVAILABLE_DATA"),
            );
        }
        return SbiResponse::with_status(204);
    }
    for i in &infos {
        let ci = &i["congestionInfo"];
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "udc GET USER_DATA_CONGESTION kind={kind} cell={} congLevel={}{} → 200",
            i["networkArea"]["ncgis"][0]["nrCellId"]
                .as_str()
                .unwrap_or("?"),
            ci["nsi"]["congLevel"],
            ci.get("confidence")
                .map_or_else(String::new, |c| format!(" confidence={c}"))
        );
    }
    let (start, expiry) = match period {
        Some((s, e, _)) => (s, e),
        None => (now, now + chrono::Duration::seconds(10)),
    };
    let body = json!({
        "userDataCongInfos": infos,
        "start": start.to_rfc3339(),
        "expiry": expiry.to_rfc3339(),
        "timeStampGen": now.to_rfc3339(),
    });
    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// The `nnwdaf-randata` `NFService` for the NRF profile.
pub fn nf_service(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> Value {
    json!({
        "serviceInstanceId": format!("{nf_instance_id}-{SERVICE_NAME}"),
        "serviceName": SERVICE_NAME,
        "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
        "allowedNfTypes": SERVICE_ALLOWED_NF_TYPES,
    })
}

/// This module's `/metrics` families.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    nextgcore_metrics::nf::write_metric(
        out,
        "nwdaf_udc_serving",
        "gauge",
        "1 when USER_DATA_CONGESTION is served from RAN cell reports (nextgsim#465)",
        u8::from(serving()),
    );
    nextgcore_metrics::nf::write_header(
        out,
        "nwdaf_ran_cell_reports_total",
        "counter",
        "RAN cell reports by outcome (nextgsim#465)",
    );
    for (result, n) in [
        ("ingested", &INGESTED),
        ("unauthorized", &UNAUTHORIZED),
        ("forbidden", &FORBIDDEN),
        ("malformed", &MALFORMED),
        ("unavailable", &UNAVAILABLE),
    ] {
        let _ = writeln!(
            out,
            "nwdaf_ran_cell_reports_total{{result=\"{result}\"}} {}",
            n.load(Ordering::Relaxed)
        );
    }
    let latest = store().latest();
    if !latest.is_empty() {
        nextgcore_metrics::nf::write_header(
            out,
            "nwdaf_ran_cell_occupancy_pct",
            "gauge",
            "Last reported downlink occupancy per cell, percent",
        );
        for r in &latest {
            let _ = writeln!(
                out,
                "nwdaf_ran_cell_occupancy_pct{{cell=\"{}\"}} {:.1}",
                r.cell, r.occupancy_pct
            );
        }
        nextgcore_metrics::nf::write_header(
            out,
            "nwdaf_ran_connected_ues",
            "gauge",
            "Connected UEs per cell, as the gNB reports them",
        );
        for r in &latest {
            let _ = writeln!(
                out,
                "nwdaf_ran_connected_ues{{cell=\"{}\"}} {}",
                r.cell, r.connected_ues
            );
        }
        nextgcore_metrics::nf::write_header(
            out,
            "nwdaf_amf_ues_in_area",
            "gauge",
            "numberOfUes from the AMF's UES_IN_AREA_REPORT per reported TAI",
        );
        for r in &latest {
            if let Some(n) = store().ues_in_area(&r.tai) {
                let _ = writeln!(out, "nwdaf_amf_ues_in_area{{tai=\"{}\"}} {n}", r.tai);
            }
        }
    }
}

/// Unix ms now; exposed for the analytics handler.
pub fn now_ms() -> u64 {
    unix_now_ms()
}

#[cfg(test)]
mod tests;
