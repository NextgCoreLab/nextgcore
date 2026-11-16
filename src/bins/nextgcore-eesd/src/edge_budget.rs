//! nextgsim#471 (demo `d443a-edge-budget`): the EES picks the EAS on a
//! UPF-measured communication budget plus the EAS's compute.
//!
//! # What it adds (only with the cargo feature AND the `demo:` block on)
//! - A `QOS_MON` consumer: at startup eesd subscribes to `Nsmf_EventExposure`
//!   (TS 29.508 §4.2.2.2) at `ees.edge_budget.smf_uri`, for any UE
//!   (`anyUeInd`), PERIODIC every `rep_period_s`, negotiating QoSMonitoring
//!   (`supportedFeatures` "10", feature 5). It checks the subscription every
//!   [`CHECK_INTERVAL`] and re-creates it on a 404 (an SMF restart loses it).
//! - The notification route `/d443a-edge-budget/qos-mon/<token>` on the
//!   existing SBI listener, authenticated by its unguessable path token (128
//!   bits from the OS RNG, minted at startup): a wrong or missing token is a
//!   404, the notification is dropped and counted, and nothing it carried is
//!   used.
//!
//!   TS 33.501 §13.4.1 (*"The OAuth 2.0 framework does not apply to the
//!   notification operation"*) and TS 29.500 §6.7.3 mean smfd's notify carries
//!   no token. The route is registered through the shared callback exemption
//!   (#1519's `OAuth2CallbackExemption`, `POST /d443a-edge-budget/qos-mon/{token}`
//!   with [`token_is_current`] as the check), which eesd's per-route gate
//!   consults (#1525): a token-less notify on the current token is admitted;
//!   with any other path token it is held to the bearer (401, so the route is no
//!   token-validity oracle). A notify that does carry a bearer needs scope
//!   [`SCOPE`].
//! - The selection policy (TS 24.558 §5.2.2.2 step 1 iii) B), *"based on EES
//!   local policies"*): with `easSelReqInd`, the EASes that matched the AC
//!   profiles are ranked on a budget and filtered by the deadline
//!   (`ees.edge_budget.deadline_ms`, the EES local policy, default 15 ms):
//!   - `measured-budget`: `rtDelays[0] + 2·N6(EAS) + ceil(reqComp / avlComp)`,
//!     the UE↔PSA round trip from the latest QOS_MON report, the one-way N6
//!     delay to the EAS from the SMF's N6 delay results (#1502, carried in the
//!     notification's vendor-specific member), and the compute stand-in;
//!   - `static`: the EAS's advertised `maxRespTime`.
//!
//!   No EAS within the deadline → 404 ("matching EAS not identified",
//!   §5.2.2.2, decided by this local policy). Each kept EAS carries its budget
//!   as `achievableLatency` in a vendor-specific member.
//! - `/metrics` (`EES_METRICS_PORT`, `NEXTGCORE_METRICS_BIND`, loopback by
//!   default): `nextg_demo_enabled`, `eees_selection_total{src}`,
//!   `eees_d443a_qos_mon_notifications_total{outcome}` and
//!   `eees_d443a_qos_mon_subscribed`.
//!
//! # Honesty labels
//! - The deadline is EES local policy, not the AC's `respTime`: `respTime` is a
//!   DurationSec (TS 24.558 Table 6.2.5.2.5-1), which cannot carry 15 ms.
//! - `reqComp` is a string in TS 24.558; it is read as an integer here, and the
//!   compute term `ceil(reqComp / avlComp)` ms is a stand-in, not a model.
//! - The N3 term is the most recent QOS_MON report of any UE (single-UE
//!   simplification): an EEC registration carries no SUPI, and its source
//!   address is the UPF's.
//! - The RAN part of `rtDelays` is what the gNB states, not what it measures.
//! - `measured-budget` with no current QOS_MON report (none yet, older than
//!   three report periods, or no subscription) ranks on the advertisement and
//!   says so: `src=static-fallback`.
//! - An EAS whose measured budget cannot be formed (no N6 endpoint, no current
//!   N6 result, no `avlComp` for a `reqComp`) is not within the deadline: the
//!   EES cannot show that it is. Its budget is logged as `?<why>`.
//!
//! # Vendor-specific members
//! TS 29.500 §6.6.3: `vendorSpecific-nnnnnn`, nnnnnn the IANA Private
//! Enterprise Number. NextgCoreLab has none, so [`VENDOR_MEMBER`] uses 32473,
//! the PEN RFC 5612 reserves for documentation and examples. smfd writes the
//! same member name.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::{SbiClient, SbiClientConfig, UriScheme};
use serde_json::Value;

use crate::eec::{AcProfile, EecRegistration};
use crate::types::{DiscoveredEas, EasProfile};

/// The demo key (nextgsim#458 convention).
pub const DEMO_KEY: &str = "d443a-edge-budget";
/// `measured-budget` (the demo) and `static` (the baseline).
pub const MODES: &[&str] = &["measured-budget", "static"];

/// What this binary registers under the `demo-d443a-edge-budget` feature.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: MODES,
    requires: &[],
};

/// The TS 29.500 §6.6.3 vendor-specific member (PEN 32473, RFC 5612).
pub const VENDOR_MEMBER: &str = "vendorSpecific-032473";

/// The first path segment of the notification route; the token is the third.
pub const ROUTE_ROOT: &str = "d443a-edge-budget";
/// The second path segment of the notification route.
pub const ROUTE_QOS_MON: &str = "qos-mon";
/// The OAuth2 scope of the notification route (eesd's convention: the apiName).
pub const SCOPE: &str = "d443a-edge-budget";

/// The deadline when `deadline_ms` is not configured.
pub const DEFAULT_DEADLINE_MS: u32 = 15;
/// The QOS_MON report period when `rep_period_s` is not configured.
pub const DEFAULT_REP_PERIOD_S: u32 = 2;
/// How often the subscription is checked (and re-created on a 404).
pub const CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// A report older than this many report periods is not current.
pub const STALE_PERIODS: u32 = 3;

/// The `notifId` of the subscription (TS 29.508: the consumer's correlator).
pub const NOTIF_ID: &str = "eesd-d443a-edge-budget";

// ============================================================================
// Configuration
// ============================================================================

/// The demo mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    MeasuredBudget,
    Static,
}

impl Mode {
    pub fn parse(mode: &str) -> Option<Self> {
        match mode {
            "measured-budget" => Some(Self::MeasuredBudget),
            "static" => Some(Self::Static),
            _ => None,
        }
    }
}

/// The `ees.edge_budget` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `http(s)://host:port` of the SMF; `None`: no QOS_MON subscription.
    pub smf_uri: Option<String>,
    /// EES local policy: the response-time deadline, ms.
    pub deadline_ms: u32,
    /// The QOS_MON `repPeriod`, s.
    pub rep_period_s: u32,
    /// The N6 measurement endpoint of an EAS, by `easId`. An EAS not listed is
    /// measured at the first address of its registered `endPt`.
    pub eas_n6_endpoints: BTreeMap<String, IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            smf_uri: None,
            deadline_ms: DEFAULT_DEADLINE_MS,
            rep_period_s: DEFAULT_REP_PERIOD_S,
            eas_n6_endpoints: BTreeMap::new(),
        }
    }
}

fn positive_u32(v: &serde_yaml::Value, what: &str) -> Result<u32, String> {
    v.as_u64()
        .filter(|n| *n > 0)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("ees.edge_budget.{what} must be a positive integer"))
}

/// Parse `ees.edge_budget` from the config root (absent: the defaults). A
/// malformed block, or an unknown key, is an error that fails start-up.
pub fn config_from_root(root: &serde_yaml::Value) -> Result<Config, String> {
    let mut cfg = Config::default();
    let Some(block) = root.get("ees").and_then(|e| e.get("edge_budget")) else {
        return Ok(cfg);
    };
    if block.is_null() {
        return Ok(cfg);
    }
    let map = block
        .as_mapping()
        .ok_or("ees.edge_budget must be a mapping")?;
    for (k, v) in map {
        match k.as_str() {
            Some("smf_uri") => {
                let uri = v
                    .as_str()
                    .ok_or("ees.edge_budget.smf_uri must be a string")?;
                if parse_uri(uri).is_none() {
                    return Err(format!(
                        "ees.edge_budget.smf_uri {uri:?} is not an http(s)://host:port URI"
                    ));
                }
                cfg.smf_uri = Some(uri.trim_end_matches('/').to_string());
            }
            Some("deadline_ms") => cfg.deadline_ms = positive_u32(v, "deadline_ms")?,
            Some("rep_period_s") => cfg.rep_period_s = positive_u32(v, "rep_period_s")?,
            Some("eas_n6_endpoints") => {
                let m = v
                    .as_mapping()
                    .ok_or("ees.edge_budget.eas_n6_endpoints must be a mapping easId: ip")?;
                for (id, ip) in m {
                    let id = id
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .ok_or("ees.edge_budget.eas_n6_endpoints: an easId must be a string")?;
                    let ip: IpAddr = ip.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                        format!("ees.edge_budget.eas_n6_endpoints.{id} must be an IP address")
                    })?;
                    cfg.eas_n6_endpoints.insert(id.to_string(), canonical(ip));
                }
            }
            _ => return Err(format!("unknown key ees.edge_budget.{k:?}")),
        }
    }
    Ok(cfg)
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_canonical(),
        v4 => v4,
    }
}

/// `(scheme, host, port)` of an `http(s)://host:port[/]` URI.
fn parse_uri(uri: &str) -> Option<(UriScheme, String, u16)> {
    let (scheme, rest, default_port) = if let Some(r) = uri.strip_prefix("https://") {
        (UriScheme::Https, r, 443)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (UriScheme::Http, r, 80)
    } else {
        return None;
    };
    let authority = rest.trim_end_matches('/');
    if authority.is_empty() || authority.contains('/') {
        return None;
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, tail) = v6.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => default_port,
            None => return None,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), default_port),
        }
    };
    (!host.is_empty()).then_some((scheme, host, port))
}

// ============================================================================
// Process state
// ============================================================================

/// What start-up decided, with the demo on.
#[derive(Debug, Clone)]
pub struct Plan {
    pub mode: Mode,
    pub config: Config,
    /// The notification path token.
    pub token: String,
}

static PLAN: RwLock<Option<Arc<Plan>>> = RwLock::new(None);

/// The latest QOS_MON report.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// `rtDelays[0]`, ms: the UE↔PSA UPF round trip.
    pub rt_ms: u32,
    /// The SUPI it was reported for (single-UE simplification, logged).
    pub supi: Option<String>,
    /// One-way N6 delay (average), ms, by measurement endpoint.
    pub n6_ms: BTreeMap<IpAddr, u32>,
    pub at: Instant,
}

static LATEST: Mutex<Option<Sample>> = Mutex::new(None);

/// Serialises the tests that touch [`PLAN`] or [`LATEST`]. Declared beside them
/// (one lock per process-global).
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`TEST_LOCK`], recovering a poisoned guard. Taken after
/// `auth::GLOBAL_STATE_TEST_LOCK` when a test holds both.
#[cfg(test)]
pub(crate) fn lock_for_test() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The decisions, by budget source.
pub static SELECTIONS: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "eees_selection_total",
        "EAS selections for an EEC registration, by budget source (nextgsim#471 demo)",
        &["src", "result"],
    );

/// QOS_MON notifications at the demo route, by outcome.
pub static NOTIFICATIONS: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "eees_d443a_qos_mon_notifications_total",
        "QOS_MON notifications received at the demo callback, by outcome (nextgsim#471 demo)",
        &["outcome"],
    );

static SUBSCRIBED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn plan() -> Option<Arc<Plan>> {
    PLAN.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Whether the demo is on (its route served, its policy applied).
pub fn serving() -> bool {
    plan().is_some()
}

/// A fresh notification path token: 16 bytes from the OS RNG, as 32 hex digits
/// (128 random bits). An RNG failure fails start-up.
pub fn mint_token() -> Result<String, String> {
    use rand::TryRngCore as _;
    let mut b = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .map_err(|e| format!("cannot draw the QOS_MON callback token from the OS RNG: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// The subscription this process holds at the SMF, `(smf_uri, Location)`, so
/// that shutdown can delete it (#1523 review M1).
static HELD: Mutex<Option<(String, String)>> = Mutex::new(None);

/// Set once shutdown starts: the subscriber creates nothing after it.
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Wakes the subscriber out of a backoff or check-interval sleep at shutdown.
static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// The running subscriber task, so shutdown can wait for an in-flight
/// Subscribe to settle (#1523 re-review r3) instead of dropping it with the
/// runtime.
static SUBSCRIBER: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);

/// Sleep `d`, or less if shutdown wakes the subscriber.
async fn nap(d: Duration) {
    tokio::select! {
        _ = tokio::time::sleep(d) => {}
        _ = WAKE.notified() => {}
    }
}

/// Subscribe failures, by reason. `refused` (401/403) is the stuck state of an
/// SMF that enforces OAuth2: this EES sends no access token (nextgcore#1529).
pub static SUBSCRIBE_FAILURES: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "eees_d443a_qos_mon_subscribe_failures_total",
        "QOS_MON Subscribe attempts at the SMF that failed, by reason (nextgsim#471 demo)",
        &["reason"],
    );

/// Install the start-up decision. `None` is the demo off: nothing here runs.
pub fn install(plan: Option<Plan>) {
    if let Some(p) = &plan {
        nextgcore_demo::demo_log!(
            warn,
            DEMO_KEY,
            "edge-budget: on (mode={}, deadline={} ms local policy, QOS_MON from {}, \
             N6 endpoints {:?}); the QOS_MON callback is authenticated by its path \
             token (OAuth2 callback exemption, TS 33.501 §13.4.1)",
            mode_str(p.mode),
            p.config.deadline_ms,
            p.config
                .smf_uri
                .as_deref()
                .unwrap_or("nowhere (no smf_uri: no subscription)"),
            p.config.eas_n6_endpoints
        );
    }
    *PLAN.write().unwrap_or_else(|e| e.into_inner()) = plan.map(Arc::new);
}

fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::MeasuredBudget => "measured-budget",
        Mode::Static => "static",
    }
}

/// Test only: forget the latest report.
#[cfg(test)]
pub(crate) fn clear_for_test() {
    *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = None;
    SUBSCRIBED.store(false, std::sync::atomic::Ordering::SeqCst);
    SHUTTING_DOWN.store(false, std::sync::atomic::Ordering::SeqCst);
    *HELD.lock().unwrap_or_else(|e| e.into_inner()) = None;
    if let Some(h) = SUBSCRIBER.lock().unwrap_or_else(|e| e.into_inner()).take() {
        h.abort();
    }
}

/// Test only: the subscription held at the SMF.
#[cfg(test)]
pub(crate) fn held_for_test() -> Option<(String, String)> {
    HELD.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Test only: the latest report.
#[cfg(test)]
pub(crate) fn latest_for_test() -> Option<Sample> {
    LATEST.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Test only: store a report.
#[cfg(test)]
pub(crate) fn set_latest_for_test(s: Option<Sample>) {
    *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = s;
}

// ============================================================================
// The QOS_MON notification route
// ============================================================================

/// Equal without an early exit on the first differing byte.
fn same_token(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether `token` is the notification path token of this process: the check
/// of the route's OAuth2 callback exemption (#1525). Constant-time.
pub fn token_is_current(token: &str) -> bool {
    plan().is_some_and(|p| same_token(token, &p.token))
}

/// `POST /d443a-edge-budget/qos-mon/<token>`, after the OAuth2 gate. `None` when the demo is off: the
/// route does not exist and the caller answers as it did before.
pub fn on_notify(token: &str, request: &SbiRequest) -> Option<SbiResponse> {
    plan()?;
    if !token_is_current(token) {
        NOTIFICATIONS.inc(&["wrong-token"]);
        nextgcore_demo::demo_log!(
            warn,
            DEMO_KEY,
            "QOS_MON notification with a wrong path token: dropped (404)"
        );
        return Some(nextgcore_sbi::server::send_not_found(
            "Resource not found",
            None,
        ));
    }
    if request.header.method != "POST" {
        return Some(nextgcore_sbi::server::send_method_not_allowed(
            &request.header.method,
            "qos-mon/{token}",
        ));
    }
    let Some(body) = request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<Value>(c).ok())
    else {
        NOTIFICATIONS.inc(&["malformed"]);
        return Some(nextgcore_sbi::server::send_bad_request(
            "Body is not an NsmfEventExposureNotification",
            Some("INVALID_MSG_FORMAT"),
        ));
    };
    if body.get("notifId").and_then(Value::as_str) != Some(NOTIF_ID) {
        NOTIFICATIONS.inc(&["other-notif-id"]);
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "QOS_MON notification for notifId {:?}, not ours: ignored",
            body.get("notifId")
        );
        return Some(SbiResponse::with_status(204));
    }
    let mut used = false;
    for e in body
        .get("eventNotifs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if e.get("event").and_then(Value::as_str) != Some("QOS_MON") {
            continue;
        }
        if let Some(sample) = sample_of(e) {
            nextgcore_demo::demo_log!(
                debug,
                DEMO_KEY,
                "QOS_MON report for supi={}",
                sample.supi.as_deref().unwrap_or("?")
            );
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "QOS_MON rt={} ms n6=[{}]",
                sample.rt_ms,
                sample
                    .n6_ms
                    .iter()
                    .map(|(ip, ms)| format!("{ip}={ms}ms"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = Some(sample);
            used = true;
        }
    }
    NOTIFICATIONS.inc(&[if used { "accepted" } else { "no-delay" }]);
    Some(SbiResponse::with_status(204))
}

/// A QOS_MON `EventNotification` as a [`Sample`]: `None` without an `rtDelays`.
fn sample_of(e: &Value) -> Option<Sample> {
    let rt_ms = e
        .get("rtDelays")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())?;
    let mut n6_ms = BTreeMap::new();
    for d in e
        .get(VENDOR_MEMBER)
        .and_then(|v| v.get("n6Delays"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let ip = d
            .get("endpoint")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<IpAddr>().ok());
        let avg = d
            .get("avgMs")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        if let (Some(ip), Some(avg)) = (ip, avg) {
            n6_ms.insert(canonical(ip), avg);
        }
    }
    Some(Sample {
        rt_ms,
        supi: e.get("supi").and_then(Value::as_str).map(str::to_string),
        n6_ms,
        at: Instant::now(),
    })
}

// ============================================================================
// Ranking
// ============================================================================

/// Where a decision's budgets came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Src {
    /// `measured-budget`, from a current QOS_MON report.
    Measured,
    /// `static`: the advertisement.
    Static,
    /// `measured-budget` with no current QOS_MON report: the advertisement.
    StaticFallback,
}

impl Src {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "upf-n3+upf-n6",
            Self::Static => "static",
            Self::StaticFallback => "static-fallback",
        }
    }
}

/// One candidate EAS: its profile and the `reqComp` the AC asks of it.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub eas: EasProfile,
    pub req_comp: Option<String>,
}

/// One candidate's budget, ms, or why it has none.
pub type Budget = Result<u32, &'static str>;

/// A ranking.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub src: Src,
    /// `(easId, budget)` per candidate, in the candidates' order.
    pub budgets: Vec<(String, Budget)>,
    /// Indices into the candidates within the deadline, by budget then by the
    /// candidates' order.
    pub selected: Vec<usize>,
}

/// The N6 measurement endpoint of `eas`: configured, else its first `endPt`
/// address.
fn n6_endpoint(cfg: &Config, eas: &EasProfile) -> Option<IpAddr> {
    if let Some(ip) = cfg.eas_n6_endpoints.get(&eas.eas_id) {
        return Some(*ip);
    }
    eas.end_pt
        .ipv4_addrs
        .iter()
        .chain(eas.end_pt.ipv6_addrs.iter())
        .flatten()
        .find_map(|s| s.parse::<IpAddr>().ok())
        .map(canonical)
}

/// `ceil(reqComp / avlComp)` ms (the stand-in); 0 when the AC asks no compute.
fn compute_ms(req_comp: Option<&str>, eas: &EasProfile) -> Budget {
    let Some(req) = req_comp else {
        return Ok(0);
    };
    let req: u64 = req.trim().parse().map_err(|_| "reqcomp-not-integer")?;
    let avl = eas
        .svc_kpi
        .as_ref()
        .and_then(|k| k.avl_comp)
        .filter(|a| *a > 0)
        .ok_or("no-avlcomp")?;
    Ok(u32::try_from(req.div_ceil(u64::from(avl))).unwrap_or(u32::MAX))
}

/// Rank `candidates` under `mode`, with `sample` the latest QOS_MON report (if
/// current) and `deadline_ms` the local policy.
pub fn rank(
    mode: Mode,
    cfg: &Config,
    candidates: &[Candidate],
    sample: Option<&Sample>,
) -> Decision {
    let advertised = |c: &Candidate| -> Budget {
        c.eas
            .svc_kpi
            .as_ref()
            .and_then(|k| k.max_resp_time_ms)
            .ok_or("no-maxresptime")
    };
    let (src, budgets): (Src, Vec<Budget>) = match (mode, sample) {
        (Mode::Static, _) => (Src::Static, candidates.iter().map(advertised).collect()),
        (Mode::MeasuredBudget, None) => (
            Src::StaticFallback,
            candidates.iter().map(advertised).collect(),
        ),
        (Mode::MeasuredBudget, Some(s)) => (
            Src::Measured,
            candidates
                .iter()
                .map(|c| {
                    let ip = n6_endpoint(cfg, &c.eas).ok_or("no-n6-endpoint")?;
                    let n6 = *s.n6_ms.get(&ip).ok_or("no-n6")?;
                    let compute = compute_ms(c.req_comp.as_deref(), &c.eas)?;
                    Ok(s.rt_ms
                        .saturating_add(n6.saturating_mul(2))
                        .saturating_add(compute))
                })
                .collect(),
        ),
    };
    let mut selected: Vec<usize> = budgets
        .iter()
        .enumerate()
        .filter(|(_, b)| matches!(b, Ok(ms) if *ms <= cfg.deadline_ms))
        .map(|(i, _)| i)
        .collect();
    // Stable: equal budgets keep the candidates' (AC profile, then `eass`) order.
    selected.sort_by_key(|i| budgets[*i].unwrap_or(u32::MAX));
    Decision {
        src,
        budgets: candidates
            .iter()
            .map(|c| c.eas.eas_id.clone())
            .zip(budgets)
            .collect(),
        selected,
    }
}

/// The latest QOS_MON report, if current (within [`STALE_PERIODS`] periods).
fn current_sample(cfg: &Config) -> Option<Sample> {
    let window = Duration::from_secs(u64::from(cfg.rep_period_s) * u64::from(STALE_PERIODS));
    LATEST
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .filter(|s| s.at.elapsed() <= window)
}

/// The candidates of a registration: the matched EASes, each with the
/// `reqComp` of the first AC profile naming it (`minimumReqSvcKPIs`, else
/// `expectedSvcKPIs`).
pub fn candidates(profs: &[AcProfile], matched: Vec<EasProfile>) -> Vec<Candidate> {
    matched
        .into_iter()
        .map(|eas| {
            let req_comp = profs
                .iter()
                .flat_map(|p| p.eass.iter().flatten())
                .find(|d| d.eas_id == eas.eas_id)
                .and_then(|d| {
                    d.minimum_req_svc_kpis
                        .as_ref()
                        .and_then(|k| k.req_comp.clone())
                        .or_else(|| {
                            d.expected_svc_kpis
                                .as_ref()
                                .and_then(|k| k.req_comp.clone())
                        })
                });
            Candidate { eas, req_comp }
        })
        .collect()
}

/// What the demo selected for one EEC registration.
#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    /// The kept EASes, by budget.
    pub discovered: Vec<DiscoveredEas>,
    /// The AC profiles (acId) none of whose EASes is within the deadline: the
    /// caller lists them in `unfulfillAcProfs` with REQ_UNFULFILLED (TS 24.558
    /// §5.2.2.2 step 3 ii), `24558-k00.txt:1263-1270`).
    pub unfulfilled: Vec<String>,
}

/// The demo's selection for an EEC registration that asked for one
/// (`easSelReqInd`), from the EASes the AC profiles matched. `None` when the
/// demo is off (the caller selects as before).
///
/// Per AC profile, as TS 24.558 §5.2.2.2 decides it: a profile none of whose
/// EASes is within the deadline is unfulfilled and reported in the successful
/// response (step 3 ii), `24558-k00.txt:1263-1270`); only when no EAS of any
/// profile is within it is the request refused, `Some(Err(detail))`, which the
/// caller answers 404 (step 1, `:1239-1243`).
pub fn select(
    reg: &EecRegistration,
    matched: Vec<EasProfile>,
) -> Option<Result<Selection, String>> {
    let plan = plan()?;
    let profs = reg.ac_profs.clone().unwrap_or_default();
    let cands = candidates(&profs, matched);
    let sample = match plan.mode {
        Mode::MeasuredBudget => current_sample(&plan.config),
        Mode::Static => None,
    };
    let d = rank(plan.mode, &plan.config, &cands, sample.as_ref());
    let ac: Vec<&str> = profs
        .iter()
        .filter(|p| p.eass.as_ref().is_some_and(|e| !e.is_empty()))
        .map(|p| p.ac_id.as_str())
        .collect();
    let selected: Vec<&str> = d
        .selected
        .iter()
        .map(|i| cands[*i].eas.eas_id.as_str())
        .collect();
    let budgets: Vec<String> = d
        .budgets
        .iter()
        .map(|(id, b)| match b {
            Ok(ms) => format!("{id}={ms}"),
            Err(why) => format!("{id}=?{why}"),
        })
        .collect();
    let n3 = sample
        .as_ref()
        .map(|s| format!(" n3_rt={}", s.rt_ms))
        .unwrap_or_default();
    if let Some(s) = &sample {
        nextgcore_demo::demo_log!(
            debug,
            DEMO_KEY,
            "EES-SEL n3 from the report for supi={}",
            s.supi.as_deref().unwrap_or("?")
        );
    }
    let result = if selected.is_empty() { "404" } else { "201" };
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "EES-SEL ac={} src={} selected=[{}] budget=[{}] deadline={}{n3} result={result}",
        ac.join(","),
        d.src.as_str(),
        selected.join(","),
        budgets.join(","),
        plan.config.deadline_ms
    );
    SELECTIONS.inc(&[d.src.as_str(), result]);
    if d.selected.is_empty() {
        return Some(Err(format!(
            "No matching EAS identified: none of the {} candidate EAS(es) is within the {} ms \
             deadline (EES local policy, budget source {})",
            cands.len(),
            plan.config.deadline_ms,
            d.src.as_str()
        )));
    }
    // An AC profile the base matcher already listed (e.g. EAS_NOT_AVAILABLE)
    // keeps that, more specific, reason and is not listed twice (#1523 review r2).
    let already: Vec<String> = reg
        .unfulfilled()
        .into_iter()
        .filter_map(|u| u.ac_id.clone())
        .collect();
    let unfulfilled: Vec<String> = profs
        .iter()
        .filter(|p| !already.contains(&p.ac_id))
        .filter(|p| {
            p.eass.as_ref().is_some_and(|e| {
                !e.is_empty() && !e.iter().any(|x| selected.contains(&x.eas_id.as_str()))
            })
        })
        .map(|p| p.ac_id.clone())
        .collect();
    if !unfulfilled.is_empty() {
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "EES-SEL AC profile(s) [{}] have no EAS within the deadline: unfulfilled \
             (REQ_UNFULFILLED)",
            unfulfilled.join(",")
        );
    }
    let discovered = d
        .selected
        .iter()
        .map(|i| {
            let ms = d.budgets[*i].1.unwrap_or(u32::MAX);
            DiscoveredEas {
                eas: cands[*i].eas.clone(),
                vendor_specific: Some(serde_json::json!({
                    "achievableLatency": ms,
                    "budgetSrc": d.src.as_str(),
                })),
            }
        })
        .collect();
    Some(Ok(Selection {
        discovered,
        unfulfilled,
    }))
}

// ============================================================================
// The QOS_MON subscription
// ============================================================================

/// The subscription document (TS 29.508 `NsmfEventExposure`).
pub fn subscription_body(notif_uri: &str, rep_period_s: u32) -> Value {
    serde_json::json!({
        "notifId": NOTIF_ID,
        "notifUri": notif_uri,
        "eventSubs": [{ "event": "QOS_MON" }],
        "anyUeInd": true,
        "notifMethod": "PERIODIC",
        "repPeriod": rep_period_s,
        // Feature 5, QoSMonitoring (TS 29.508 Table 5.8-1; TS 29.571 §5.2.2: bit 4).
        "supportedFeatures": "10",
    })
}

/// The notification URI eesd gives the SMF: its advertised SBI host and port.
pub fn notif_uri(tls: bool, host: &str, port: u16, token: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("{scheme}://{host}:{port}/{ROUTE_ROOT}/{ROUTE_QOS_MON}/{token}")
}

fn client(smf_uri: &str) -> Option<SbiClient> {
    let (scheme, host, port) = parse_uri(smf_uri)?;
    Some(SbiClient::new(
        SbiClientConfig::new(host, port)
            .with_scheme(scheme)
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3))
            .with_pool_size(1),
    ))
}

/// What the subscription check found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Check {
    Alive,
    Gone,
    Unreachable(String),
}

/// Run the subscriber until the process ends: subscribe, then check every
/// `interval` and re-create on a 404.
pub async fn run_subscriber(
    smf_uri: String,
    notif_uri: String,
    rep_period_s: u32,
    interval: Duration,
) {
    let Some(client) = client(&smf_uri) else {
        return;
    };
    let mut location: Option<String> = None;
    let mut backoff = Duration::from_secs(1);
    loop {
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        match &location {
            None => {
                let req = SbiRequest::post("/nsmf-event-exposure/v1/subscriptions").with_body(
                    subscription_body(&notif_uri, rep_period_s).to_string(),
                    nextgcore_sbi::constants::content_type::APPLICATION_JSON,
                );
                match client.send_request(req).await {
                    Ok(resp) if resp.status == 201 => {
                        let loc = resp
                            .http
                            .get_header("location")
                            .map(|l| path_of(l))
                            .unwrap_or_default();
                        nextgcore_demo::demo_log!(
                            info,
                            DEMO_KEY,
                            "Nsmf_EventExposure_Subscribe QOS_MON (anyUeInd, PERIODIC {rep_period_s} s, \
                             QoSMonitoring) at {smf_uri}: 201 {loc}"
                        );
                        SUBSCRIBED.store(true, std::sync::atomic::Ordering::SeqCst);
                        *HELD.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some((smf_uri.clone(), loc.clone()));
                        // #1523 review r2: shutdown started while the POST was in
                        // flight, so `release_subscription` found nothing to delete.
                        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                            delete_held(Duration::from_secs(2)).await;
                            return;
                        }
                        location = Some(loc);
                        backoff = Duration::from_secs(1);
                    }
                    other => {
                        let (reason, why) = match other {
                            Ok(r) if r.status == 401 || r.status == 403 => {
                                ("refused", format!("status {}", r.status))
                            }
                            Ok(r) => ("rejected", format!("status {}", r.status)),
                            Err(e) => ("unreachable", format!("{e}")),
                        };
                        SUBSCRIBE_FAILURES.inc(&[reason]);
                        if reason == "refused" {
                            nextgcore_demo::demo_log!(
                                warn,
                                DEMO_KEY,
                                "Nsmf_EventExposure_Subscribe QOS_MON REFUSED by the SMF at \
                                 {smf_uri} ({why}): this EES sends no OAuth2 access token \
                                 (nextgcore#1529), so measured-budget ranks on the advertisement \
                                 (src=static-fallback); retrying in {backoff:?}"
                            );
                        } else {
                            nextgcore_demo::demo_log!(
                                warn,
                                DEMO_KEY,
                                "Nsmf_EventExposure_Subscribe QOS_MON at {smf_uri} failed \
                                 ({why}); retrying in {backoff:?}"
                            );
                        }
                        nap(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                        continue;
                    }
                }
            }
            Some(loc) => {
                let check = match client.send_request(SbiRequest::get(loc.clone())).await {
                    Ok(r) if r.status == 200 => Check::Alive,
                    Ok(r) if r.status == 404 => Check::Gone,
                    Ok(r) => Check::Unreachable(format!("status {}", r.status)),
                    Err(e) => Check::Unreachable(format!("{e}")),
                };
                match check {
                    Check::Alive => {}
                    Check::Gone => {
                        nextgcore_demo::demo_log!(
                            warn,
                            DEMO_KEY,
                            "QOS_MON subscription {loc} is gone at the SMF (restarted?): \
                             re-creating it"
                        );
                        SUBSCRIBED.store(false, std::sync::atomic::Ordering::SeqCst);
                        *HELD.lock().unwrap_or_else(|e| e.into_inner()) = None;
                        location = None;
                        continue;
                    }
                    Check::Unreachable(why) => log::debug!(
                        "[demo:{DEMO_KEY}] QOS_MON subscription check at {smf_uri}: {why}"
                    ),
                }
            }
        }
        nap(interval).await;
    }
}

/// Delete the subscription this process holds at the SMF (graceful shutdown,
/// #1523 review M1), within `timeout`; best effort. The subscriber creates no new
/// one afterwards. A crash (SIGKILL) leaves the subscription at the SMF: smfd
/// implements no `expiry` (TS 29.508 `NsmfEventExposure.expiry`), so it stays
/// until smfd restarts. Returns the DELETE's status, if one was sent.
///
/// Then it waits, within the same `timeout`, for the subscriber started by
/// [`start_subscriber`] to finish: a Subscribe still in flight either fails, or
/// its 201 is DELETEd by the subscriber itself. Past the bound the task is
/// aborted (one subscription may then be left, as with a crash).
pub async fn release_subscription(timeout: Duration) -> Option<u16> {
    let deadline = tokio::time::Instant::now() + timeout;
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::SeqCst);
    WAKE.notify_one();
    let status = delete_held(timeout).await;
    let handle = SUBSCRIBER.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(mut h) = handle {
        if tokio::time::timeout_at(deadline, &mut h).await.is_err() {
            nextgcore_demo::demo_log!(
                warn,
                DEMO_KEY,
                "QOS_MON subscriber did not settle within {timeout:?} of shutdown: aborted \
                 (a Subscribe still in flight may leave one subscription at the SMF)"
            );
            h.abort();
        }
    }
    status
}

/// Spawn [`run_subscriber`] and keep its handle for [`release_subscription`].
pub fn start_subscriber(smf_uri: String, notif_uri: String, rep_period_s: u32, interval: Duration) {
    let h = tokio::spawn(run_subscriber(smf_uri, notif_uri, rep_period_s, interval));
    if let Some(old) = SUBSCRIBER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .replace(h)
    {
        old.abort();
    }
}

/// DELETE the held subscription, if any (whoever takes `HELD` first sends it).
async fn delete_held(timeout: Duration) -> Option<u16> {
    let (smf_uri, loc) = HELD.lock().unwrap_or_else(|e| e.into_inner()).take()?;
    SUBSCRIBED.store(false, std::sync::atomic::Ordering::SeqCst);
    let client = client(&smf_uri)?;
    let status = match tokio::time::timeout(
        timeout,
        client.send_request(SbiRequest::delete(loc.clone())),
    )
    .await
    {
        Ok(Ok(r)) => Some(r.status),
        Ok(Err(e)) => {
            nextgcore_demo::demo_log!(warn, DEMO_KEY, "QOS_MON unsubscribe {loc}: {e}");
            None
        }
        Err(_) => {
            nextgcore_demo::demo_log!(warn, DEMO_KEY, "QOS_MON unsubscribe {loc}: timed out");
            None
        }
    };
    if let Some(st) = status {
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "Nsmf_EventExposure_Unsubscribe QOS_MON at {smf_uri}: {st} {loc}"
        );
    }
    status
}

/// The path of a `Location` value (absolute or already a path).
fn path_of(location: &str) -> String {
    let rest = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"));
    match rest {
        Some(r) => r
            .find('/')
            .map(|i| r[i..].to_string())
            .unwrap_or_else(|| "/".into()),
        None => location.to_string(),
    }
}

/// Spawn [`run_subscriber`] when the demo is on and `smf_uri` is set.
pub fn spawn_subscriber(tls: bool, host: &str, port: u16) {
    let Some(plan) = plan() else {
        return;
    };
    let Some(smf_uri) = plan.config.smf_uri.clone() else {
        nextgcore_demo::demo_log!(
            warn,
            DEMO_KEY,
            "no ees.edge_budget.smf_uri: no QOS_MON subscription, so measured-budget ranks on \
             the advertisement (src=static-fallback)"
        );
        return;
    };
    let uri = notif_uri(tls, host, port, &plan.token);
    start_subscriber(smf_uri, uri, plan.config.rep_period_s, CHECK_INTERVAL);
}

// ============================================================================
// /metrics
// ============================================================================

/// The demo's `/metrics` body.
pub fn render_metrics() -> String {
    let mut out = String::new();
    nextgcore_demo::render_installed_metrics(&mut out);
    SELECTIONS.render(&mut out);
    NOTIFICATIONS.render(&mut out);
    SUBSCRIBE_FAILURES.render(&mut out);
    nextgcore_metrics::nf::write_metric(
        &mut out,
        "eees_d443a_qos_mon_subscribed",
        "gauge",
        "1 while the demo's QOS_MON subscription is held at the SMF (nextgsim#471 demo)",
        u64::from(SUBSCRIBED.load(std::sync::atomic::Ordering::SeqCst)),
    );
    out
}

#[cfg(test)]
#[path = "edge_budget_tests.rs"]
pub(crate) mod tests;
