//! Demo `d441e-model-retrain` (nextgsim#468), PR 3: AnLF-assisted ML Model
//! accuracy monitoring, `Nnwdaf_MLModelMonitor` (TS 29.520 §4.7,
//! `TS29520_Nnwdaf_MLModelMonitor.yaml`). Cargo feature
//! `demo-d441e-model-retrain` and the `demo:` block; the service is optional in
//! the spec and stays demo-gated as the ticket asks. With the block off every
//! route here is 404 and nothing is advertised or sent.
//!
//! TS 23.288 §6.2E.2 steps 4-7 and §6.2E.3.2 (23288-k10 l.10262-10275,
//! l.10401-10432):
//!
//! 1. **Register** (AnLF → MTLF). When the AnLF starts using a provisioned
//!    model it `POST`s an `MLModelMonitorReg` (`consumerId`, `modelId` = the
//!    notified `modelUniqueId`, `modelAccuInd`, `mLEvent`) to the MTLF's
//!    `/registrations`, and deregisters the previous model's registration.
//! 2. **Subscribe** (MTLF → AnLF; the AnLF is the producer). On a
//!    registration the MTLF discovers the AnLF by `consumerId` at the NRF and
//!    `POST`s an `MLModelMonitorSub` (`modelIds`, `notificationUri`,
//!    `notifCorrId`, `accuThreshold`, `eventReportReq` PERIODIC) to the AnLF's
//!    `/subscriptions`.
//! 3. **Notify** (AnLF → MTLF). Every `repPeriod` the AnLF reports an
//!    `MLModelMonitorNotify` with `modelAccuInfos[].mlModelAcc`: the accuracy of
//!    its model on its own recent data, a one-step-ahead backtest over the
//!    newest points of each NF's load series, `1 - mean |error|` in percent
//!    (the `FeedbackCollector` definition, not the §5C.1 methods), and
//!    `accuMeetInd`.
//! 4. **MTLF feedback.** Each report feeds the MTLF's `FeedbackRegistry`
//!    (rolling over [`FEEDBACK_WINDOW`] reports). When the rolling accuracy
//!    first drops below the threshold the MTLF logs `retrain requested` in
//!    mode `retrain`, or that it will not retrain in mode `no-retrain`. The
//!    refit and the re-provisioning of the new version are `model_refit`
//!    (PR 4), run from the MTLF's upkeep.
//!
//! **Bounds and peer restarts** (review of #1473):
//!
//! - Each producer map holds at most [`MAX_REGISTRATIONS`] /
//!   [`MAX_SUBSCRIPTIONS`] entries; past that a create is refused with 500
//!   `INSUFFICIENT_RESOURCES` (TS 29.500 Table 5.2.7.2-1). A registration from
//!   the same `consumerId` for the same `modelId` replaces the older one.
//! - `repPeriod` is raised to at least [`MIN_REPORT_PERIOD_SECS`].
//! - The AnLF sends every due Notify of a tick concurrently, at most the
//!   subscription cap at once, each time-boxed to [`NOTIFY_BUDGET`], so a dead
//!   `notificationUri` costs a tick at most one budget and never delays the
//!   others.
//! - A Notify answered 404 means the resource is gone (TS 29.500 §5.2.7.2): the
//!   AnLF drops that subscription, and when it served the registration the
//!   AnLF holds, registers again. The MTLF answers 404 for an unknown token
//!   (it restarted) and for a `notifCorrId` that is not a live registration.
//!   The AnLF also registers again when its registration has had no
//!   subscription for [`ORPHAN_GRACE_SECS`].
//! - The MTLF audits a registration idle for [`AUDIT_AFTER_SECS`] by
//!   re-sending its subscription (`PUT`, §4.7.2.4.3): 404 means the AnLF lost it
//!   (it restarted) and the registration is dropped. A registration with no
//!   report and no successful audit for [`REGISTRATION_EXPIRY_SECS`] expires.
//!
//! The notify callback `/nnwdaf-callback/v1/mlmodel-monitor-notify/{token}`
//! authenticates by its 122-bit token (TS 33.501 §13.4.1: no OAuth2 on
//! notifications) and has the same OAuth2-enforcement limitation as the model
//! notify (nextgcore#1421).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::Duration;

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_bad_request, send_not_found};
use serde_json::{json, Value};

use crate::context::NwdafContext;
use crate::model_retrain::DEMO_KEY;
use crate::role::Role;

/// The service this module serves.
pub const SERVICE_NAME: &str = "nnwdaf-mlmodelmonitor";
/// TS 29.520 §4.7.1.2: the known consumers are NWDAFs.
pub const ALLOWED_NF_TYPES: &[&str] = &["NWDAF"];
/// The MTLF's notify callback segment; the next segment is the token.
pub const CALLBACK_SEGMENT: &str = "mlmodel-monitor-notify";
/// The reporting period the MTLF asks for, and the AnLF's default.
pub const DEFAULT_REPORT_PERIOD_SECS: u64 = 30;
/// Reports the MTLF's rolling accuracy is taken over.
pub const FEEDBACK_WINDOW: usize = 3;
/// Newest points per NF series the AnLF's backtest covers.
pub const BACKTEST_POINTS: usize = 20;
/// The most registrations an MTLF holds.
pub const MAX_REGISTRATIONS: usize = 64;
/// The most subscriptions an AnLF holds.
pub const MAX_SUBSCRIPTIONS: usize = 64;
/// The shortest `repPeriod` an AnLF reports at; a shorter one is raised to it.
pub const MIN_REPORT_PERIOD_SECS: u64 = 5;
/// How long one Notify may take before the AnLF gives up on it for this tick.
pub const NOTIFY_BUDGET: Duration = Duration::from_secs(5);
/// The MTLF audits a registration with no report for this long.
pub const AUDIT_AFTER_SECS: u64 = 3 * DEFAULT_REPORT_PERIOD_SECS;
/// The MTLF drops a registration with no report and no answered audit for
/// this long.
pub const REGISTRATION_EXPIRY_SECS: u64 = 10 * DEFAULT_REPORT_PERIOD_SECS;
/// The AnLF registers again when its registration has had no subscription
/// for this long (the MTLF's Subscribe retries take about a minute).
pub const ORPHAN_GRACE_SECS: u64 = 120;
/// The AnLF retries a failed Register this often.
pub const REGISTER_RETRY_SECS: u64 = 10;
/// The cause of a refused create at the cap (TS 29.500 Table 5.2.7.2-1).
pub const INSUFFICIENT_RESOURCES: &str = "INSUFFICIENT_RESOURCES";

/// One MTLF-side registration (an `MLModelMonitorReg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub consumer_id: Option<String>,
    pub model_id: u64,
    /// The `accuThreshold` the MTLF subscribes with (percent).
    pub threshold: u8,
    /// `(host, port, subscriptionId)` of the subscription at the AnLF.
    pub anlf_subscription: Option<(String, u16, String)>,
    /// When the registration last showed life (created, subscribed, a report,
    /// an answered audit), unix seconds.
    pub last_seen: u64,
    /// An audit of this registration is in flight.
    pub auditing: bool,
}

/// One AnLF-side subscription (an `MLModelMonitorSub`).
#[derive(Debug, Clone, PartialEq)]
pub struct MonitorSub {
    pub model_ids: Vec<u64>,
    pub notification_uri: String,
    pub notif_corr_id: String,
    pub accu_threshold: Option<u8>,
    pub period_secs: u64,
    pub last_report: Option<u64>,
}

/// The registration the AnLF holds at the MTLF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldRegistration {
    pub id: String,
    pub model_id: u64,
    pub host: String,
    pub port: u16,
}

/// The registration the AnLF wants: its model, at this MTLF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub host: String,
    pub port: u16,
    pub model_id: u64,
}

/// The AnLF's view of its registration's health, in the reporter's clock.
#[derive(Debug, Default)]
struct Upkeep {
    /// Since when the held registration has had no subscription.
    orphan_since: Option<u64>,
    /// The last Register attempt the reporter started.
    last_attempt: Option<u64>,
}

/// The process's monitoring state, for either role.
#[derive(Debug)]
pub struct Monitor {
    pub mode: String,
    pub role: Role,
    /// This NF's SBI base (callback URIs) and instance id (`consumerId`).
    pub sbi_base: String,
    pub own_id: String,
    pub nrf_uri: String,
    token: String,
    next_id: AtomicU64,
    /// The cap of each producer map ([`MAX_REGISTRATIONS`],
    /// [`MAX_SUBSCRIPTIONS`]).
    cap: usize,
    /// The time box of one Notify ([`NOTIFY_BUDGET`]).
    notify_budget: Duration,
    // MTLF side
    registrations: Mutex<HashMap<String, Registration>>,
    feedback: Mutex<crate::ml_service::FeedbackRegistry>,
    received: AtomicU64,
    // AnLF side
    subscriptions: Mutex<HashMap<String, MonitorSub>>,
    held: Mutex<Option<HeldRegistration>>,
    wanted: Mutex<Option<Wanted>>,
    upkeep: Mutex<Upkeep>,
    /// Serialises Register / Deregister at the MTLF.
    registering: tokio::sync::Mutex<()>,
    /// A reporter-started Register is in flight.
    reconciling: AtomicBool,
    sent: AtomicU64,
    /// The NF instance whose series the AnLF judges its model on and the MTLF
    /// retrains on (PR 4's seeded series); `None` = every NF series.
    pub series: Option<String>,
    /// The MTLF's retrains (PR 4).
    pub(crate) refit: Mutex<crate::model_refit::RefitState>,
}

impl Monitor {
    pub fn new(mode: &str, role: Role, sbi_base: &str, own_id: &str, nrf_uri: &str) -> Self {
        Self {
            mode: mode.to_string(),
            role,
            sbi_base: sbi_base.trim_end_matches('/').to_string(),
            own_id: own_id.to_string(),
            nrf_uri: nrf_uri.to_string(),
            token: uuid::Uuid::new_v4().simple().to_string(),
            next_id: AtomicU64::new(0),
            cap: if role == Role::Anlf {
                MAX_SUBSCRIPTIONS
            } else {
                MAX_REGISTRATIONS
            },
            notify_budget: NOTIFY_BUDGET,
            registrations: Mutex::new(HashMap::new()),
            feedback: Mutex::new(crate::ml_service::FeedbackRegistry::new()),
            received: AtomicU64::new(0),
            subscriptions: Mutex::new(HashMap::new()),
            held: Mutex::new(None),
            wanted: Mutex::new(None),
            upkeep: Mutex::new(Upkeep::default()),
            registering: tokio::sync::Mutex::new(()),
            reconciling: AtomicBool::new(false),
            sent: AtomicU64::new(0),
            series: None,
            refit: Mutex::new(crate::model_refit::RefitState::default()),
        }
    }

    /// The same, judging and retraining on NF instance `series` only.
    pub fn with_series(mut self, series: Option<&str>) -> Self {
        self.series = series.map(str::to_string);
        self
    }

    /// The same, with another map cap and Notify time box (tests).
    pub fn with_limits(mut self, cap: usize, notify_budget: Duration) -> Self {
        self.cap = cap;
        self.notify_budget = notify_budget;
        self
    }

    fn client(&self, host: &str, port: u16) -> nextgcore_sbi::SbiClient {
        client(host, port).with_client_identity(nextgcore_sbi::types::NfType::Nwdaf, &self.own_id)
    }

    fn id(&self, prefix: &str) -> String {
        format!(
            "{prefix}-{}-{}",
            self.next_id.fetch_add(1, Ordering::Relaxed) + 1,
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        )
    }

    /// The MTLF's `notificationUri` for its subscriptions at AnLFs.
    pub fn notify_uri(&self) -> String {
        format!(
            "{}/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/{}",
            self.sbi_base, self.token
        )
    }

    pub fn registration(&self, id: &str) -> Option<Registration> {
        lock(&self.registrations).get(id).cloned()
    }

    pub fn subscription(&self, id: &str) -> Option<MonitorSub> {
        lock(&self.subscriptions).get(id).cloned()
    }

    pub fn held(&self) -> Option<HeldRegistration> {
        lock(&self.held).clone()
    }

    /// The live registrations of `model_id`.
    fn registrations_of(&self, model_id: u64) -> Vec<String> {
        lock(&self.registrations)
            .iter()
            .filter(|(_, r)| r.model_id == model_id)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// `(rolling accuracy, reports)` of registration `id`. The MTLF keeps one
    /// collector per registration, so a new registration starts afresh.
    pub fn rolling_of(&self, registration_id: &str) -> Option<(f64, usize)> {
        lock(&self.feedback)
            .collector(registration_id)
            .map(|c| (c.rolling_accuracy(), c.sample_count()))
    }

    /// `(rolling accuracy, reports)` the MTLF holds for `model_id`: the
    /// registration of it with the most reports.
    pub fn rolling(&self, model_id: u64) -> Option<(f64, usize)> {
        self.registrations_of(model_id)
            .iter()
            .filter_map(|id| self.rolling_of(id))
            .max_by_key(|(_, n)| *n)
    }

    /// Whether the rolling accuracy of `model_id` fell below the threshold at
    /// any live registration of it.
    pub fn below_threshold(&self, model_id: u64) -> bool {
        let ids = self.registrations_of(model_id);
        let fb = lock(&self.feedback);
        ids.iter()
            .any(|id| fb.collector(id).is_some_and(|c| c.retrain_requested()))
    }

    pub fn registration_count(&self) -> usize {
        lock(&self.registrations).len()
    }

    pub fn subscription_count(&self) -> usize {
        lock(&self.subscriptions).len()
    }

    /// Drop registration `id` and its collector; unsubscribe at the AnLF in
    /// the background. The removed registration, if it was live.
    fn drop_registration(&'static self, id: &str, unsubscribe: bool) -> Option<Registration> {
        let reg = lock(&self.registrations).remove(id)?;
        lock(&self.feedback).unregister_model(id);
        if let (true, Some((host, port, sub))) = (unsubscribe, reg.anlf_subscription.clone()) {
            tokio::spawn(async move {
                let _ = self
                    .client(&host, port)
                    .delete(&format!("/{SERVICE_NAME}/v1/subscriptions/{sub}"))
                    .await;
            });
        }
        Some(reg)
    }

    /// Whether the MTLF requested a retrain of `model_id`: below the
    /// threshold, in mode `retrain`. Mode `no-retrain` never requests one.
    pub fn retrain_requested(&self, model_id: u64) -> bool {
        self.mode == "retrain" && self.below_threshold(model_id)
    }

    /// A live registration `id` of `model_id` with its collector (tests).
    #[cfg(test)]
    pub(crate) fn insert_registration_for_test(&self, id: &str, model_id: u64) {
        lock(&self.registrations).insert(
            id.to_string(),
            Registration {
                consumer_id: None,
                model_id,
                threshold: crate::model_retrain::DEFAULT_ACCURACY_THRESHOLD,
                anlf_subscription: None,
                last_seen: unix_now(),
                auditing: false,
            },
        );
        lock(&self.feedback).register_model_with(
            id.to_string(),
            FEEDBACK_WINDOW,
            f64::from(crate::model_retrain::DEFAULT_ACCURACY_THRESHOLD) / 100.0,
        );
    }

    /// Record an accuracy report for registration `id` (tests).
    #[cfg(test)]
    pub(crate) fn record_for_test(&self, id: &str, accuracy: f64) {
        lock(&self.feedback).record_accuracy(id, accuracy);
    }

    pub fn counts(&self) -> (u64, u64) {
        (
            self.sent.load(Ordering::Relaxed),
            self.received.load(Ordering::Relaxed),
        )
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

static MONITOR: OnceLock<Monitor> = OnceLock::new();

/// Install the process's monitor (start-up, demo on). A second call is ignored.
pub fn install(monitor: Monitor) -> &'static Monitor {
    MONITOR.get_or_init(|| monitor)
}

/// The process's monitor, while the demo is on.
pub fn monitor() -> Option<&'static Monitor> {
    MONITOR.get()
}

/// The NFService this NWDAF advertises while the demo is on.
pub fn nf_service(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> Value {
    json!({
        "serviceInstanceId": format!("{nf_instance_id}-{SERVICE_NAME}"),
        "serviceName": SERVICE_NAME,
        "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
        "allowedNfTypes": ALLOWED_NF_TYPES,
    })
}

fn client(host: &str, port: u16) -> nextgcore_sbi::SbiClient {
    let c = crate::notification_dispatcher::notify_client(host, port);
    match crate::oauth2_client() {
        Some(oauth2) => c.with_oauth2(oauth2, nextgcore_sbi::types::NfType::Nwdaf),
        None => c,
    }
}

fn body_json(request: &SbiRequest) -> Option<Value> {
    request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
}

fn uint(v: Option<&Value>) -> Option<u64> {
    v.and_then(Value::as_u64)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rfc3339(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .unwrap_or_default()
        .to_rfc3339()
}

fn created(location: String, body: &Value) -> SbiResponse {
    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_json_body(body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Route `/nnwdaf-mlmodelmonitor/v1/<rest>`. `/registrations` is served by an
/// MTLF, `/subscriptions` by an AnLF-only NWDAF; with the demo off, or on the
/// other role, both are 404.
pub fn route(
    monitor: Option<&'static Monitor>,
    ctx: &RwLock<NwdafContext>,
    method: &str,
    rest: &[&str],
    request: &SbiRequest,
) -> SbiResponse {
    let Some(m) = monitor else {
        return send_not_found("Nnwdaf_MLModelMonitor is not served", None);
    };
    let not_allowed = || nextgcore_sbi::server::send_method_not_allowed(method, &rest.join("/"));
    match rest {
        ["registrations"] if m.role.serves_mtlf() => match method {
            "POST" => {
                let guard = ctx.read().unwrap_or_else(|p| p.into_inner());
                handle_register(m, &guard, request)
            }
            _ => not_allowed(),
        },
        ["registrations", id] if m.role.serves_mtlf() => match method {
            "DELETE" => handle_deregister(m, id),
            _ => not_allowed(),
        },
        ["subscriptions"] if m.role == Role::Anlf => match method {
            "POST" => handle_subscribe(m, None, request),
            _ => not_allowed(),
        },
        ["subscriptions", id] if m.role == Role::Anlf => match method {
            "PUT" => handle_subscribe(m, Some(id), request),
            "DELETE" => handle_unsubscribe(m, id),
            _ => not_allowed(),
        },
        _ => send_not_found("no such Nnwdaf_MLModelMonitor resource on this NWDAF", None),
    }
}

// ── MTLF: Register / Deregister, Subscribe at the AnLF, the Notify callback ──

/// Parse an `MLModelMonitorReg`: `modelId` required; `oneOf` `consumerId` /
/// `consumerSetId`.
pub fn parse_registration(body: &Value) -> Result<(Option<String>, u64), String> {
    let model_id = uint(body.get("modelId")).ok_or("modelId is a mandatory Uinteger")?;
    let consumer = body.get("consumerId").and_then(Value::as_str);
    let set = body.get("consumerSetId").and_then(Value::as_str);
    match (consumer, set) {
        (Some(c), None) => Ok((Some(c.to_string()), model_id)),
        (None, Some(_)) => Ok((None, model_id)),
        _ => Err("exactly one of consumerId and consumerSetId is required".into()),
    }
}

fn insufficient_resources(what: &str, cap: usize) -> SbiResponse {
    nextgcore_sbi::server::send_error(
        500,
        "Internal Server Error",
        &format!("this NWDAF holds its maximum of {cap} {what}"),
        Some(INSUFFICIENT_RESOURCES),
    )
}

/// `POST /registrations` (§4.7.2.2.2): 201 + `Location`, then Subscribe at the
/// AnLF in the background. A `modelId` this MTLF did not provision is 400. A
/// registration from the same `consumerId` for the same `modelId` replaces the
/// older one (that AnLF restarted, or registered again); past the cap, 500
/// `INSUFFICIENT_RESOURCES`.
pub fn handle_register(
    m: &'static Monitor,
    ctx: &NwdafContext,
    request: &SbiRequest,
) -> SbiResponse {
    let Some(body) = body_json(request) else {
        return send_bad_request("body is not JSON", Some("INVALID_MSG_FORMAT"));
    };
    let (consumer_id, model_id) = match parse_registration(&body) {
        Ok(r) => r,
        Err(e) => return send_bad_request(&e, Some("MANDATORY_IE_MISSING")),
    };
    if ctx.model_version_by_unique_id(model_id).is_none() {
        return send_bad_request(
            &format!("modelId {model_id} is not a model this MTLF provisioned"),
            Some("MANDATORY_IE_INCORRECT"),
        );
    }
    // The registering AnLF's own ML-provision threshold, else the default.
    let threshold = consumer_id
        .as_deref()
        .and_then(|c| ctx.ml_prov_accuracy_threshold(crate::model_retrain::MODEL_EVENT, c))
        .unwrap_or(crate::model_retrain::DEFAULT_ACCURACY_THRESHOLD);
    let id = m.id("reg");
    let replaced: Vec<String> = {
        let mut regs = lock(&m.registrations);
        let replaced: Vec<String> = regs
            .iter()
            .filter(|(_, r)| {
                consumer_id.is_some() && r.consumer_id == consumer_id && r.model_id == model_id
            })
            .map(|(k, _)| k.clone())
            .collect();
        if regs.len() - replaced.len() >= m.cap {
            return insufficient_resources("MLModelMonitor registrations", m.cap);
        }
        regs.insert(
            id.clone(),
            Registration {
                consumer_id: consumer_id.clone(),
                model_id,
                threshold,
                anlf_subscription: None,
                last_seen: unix_now(),
                auditing: false,
            },
        );
        replaced
    };
    for old in replaced {
        m.drop_registration(&old, true);
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "MLModelMonitor registration {old} replaced by {id} (same consumer and modelId)"
        );
    }
    lock(&m.feedback).register_model_with(
        id.clone(),
        FEEDBACK_WINDOW,
        f64::from(threshold) / 100.0,
    );
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "MLModelMonitor registered: consumer={} modelId={model_id} registrationId={id}",
        consumer_id.as_deref().unwrap_or("(set)")
    );
    // §6.2E.2 step 5: "the NWDAF containing MTLF may subscribe to the NWDAF
    // containing AnLF".
    tokio::spawn(subscribe_at_anlf_retrying(m, id.clone()));
    created(
        format!("/{SERVICE_NAME}/v1/registrations/{id}"),
        &json!({
            "consumerId": consumer_id,
            "modelId": model_id,
            "modelAccuInd": body.get("modelAccuInd").cloned().unwrap_or(json!(true)),
            "mLEvent": crate::model_retrain::MODEL_EVENT.as_str(),
        }),
    )
}

/// The MLModelMonitorSub the MTLF sends for a registration.
pub fn subscription_body(
    m: &Monitor,
    registration_id: &str,
    model_id: u64,
    threshold: u8,
) -> Value {
    json!({
        "modelIds": [model_id],
        "notificationUri": m.notify_uri(),
        "notifCorrId": registration_id,
        "accuThreshold": threshold,
        "eventReportReq": { "notifMethod": "PERIODIC", "repPeriod": DEFAULT_REPORT_PERIOD_SECS },
        "mLEvent": crate::model_retrain::MODEL_EVENT.as_str(),
    })
}

/// The `nnwdaf-mlmodelmonitor` endpoint of NWDAF `instance` in a TS 29.510
/// `SearchResult`.
pub fn endpoint_of(result: &Value, instance: &str) -> Option<(String, u16)> {
    let inst = result
        .get("nfInstances")?
        .as_array()?
        .iter()
        .find(|i| i.get("nfInstanceId").and_then(Value::as_str) == Some(instance))?;
    let service = inst
        .get("nfServices")
        .and_then(Value::as_array)?
        .iter()
        .find(|s| s.get("serviceName").and_then(Value::as_str) == Some(SERVICE_NAME))?;
    let ep = service
        .get("ipEndPoints")
        .and_then(Value::as_array)
        .and_then(|e| e.first());
    let host = ep
        .and_then(|e| e.get("ipv4Address"))
        .and_then(Value::as_str)
        .or_else(|| service.get("fqdn").and_then(Value::as_str))
        .or_else(|| inst.get("fqdn").and_then(Value::as_str))?;
    let port = ep
        .and_then(|e| e.get("port"))
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(80);
    Some((host.to_string(), port))
}

/// §6.2E.2 step 5: find the registering AnLF at the NRF by `consumerId` and
/// subscribe to its accuracy reports. Records the subscription on success; if
/// the registration ended meanwhile, unsubscribes again.
pub async fn subscribe_at_anlf(m: &Monitor, registration_id: &str) -> Result<String, String> {
    let reg = m
        .registration(registration_id)
        .ok_or("the registration is gone")?;
    let threshold = reg.threshold;
    let consumer = reg
        .consumer_id
        .clone()
        .ok_or("a consumerSetId-only registration names no AnLF to subscribe to")?;
    let (nrf_host, nrf_port, nrf_base) =
        crate::notification_dispatcher::parse_notify_uri(&m.nrf_uri)
            .ok_or_else(|| format!("invalid NRF URI {:?}", m.nrf_uri))?;
    let disc = format!(
        "{}/nnrf-disc/v1/nf-instances?target-nf-type=NWDAF&requester-nf-type=NWDAF\
         &target-nf-instance-id={consumer}&service-names={SERVICE_NAME}",
        nrf_base.trim_end_matches('/')
    );
    let resp = crate::notification_dispatcher::notify_client(&nrf_host, nrf_port)
        .get(&disc)
        .await
        .map_err(|e| format!("AnLF discovery at the NRF failed: {e}"))?;
    if resp.status != 200 {
        return Err(format!("AnLF discovery answered {}", resp.status));
    }
    let result: Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or(""))
        .map_err(|e| format!("AnLF discovery answer is not JSON: {e}"))?;
    let (host, port) = endpoint_of(&result, &consumer)
        .ok_or_else(|| format!("the NRF knows no {SERVICE_NAME} at NWDAF {consumer}"))?;
    let body = subscription_body(m, registration_id, reg.model_id, threshold);
    let c = m.client(&host, port);
    let resp = c
        .post_json(&format!("/{SERVICE_NAME}/v1/subscriptions"), &body)
        .await
        .map_err(|e| format!("Nnwdaf_MLModelMonitor_Subscribe to {consumer} failed: {e}"))?;
    if resp.status != 201 {
        return Err(format!(
            "Nnwdaf_MLModelMonitor_Subscribe to {consumer} answered {}",
            resp.status
        ));
    }
    let sub_id = resp
        .http
        .get_header("Location")
        .and_then(|l| l.rsplit('/').next().map(String::from))
        .ok_or("the 201 carries no Location")?;
    let recorded = match lock(&m.registrations).get_mut(registration_id) {
        Some(r) => {
            r.anlf_subscription = Some((host, port, sub_id.clone()));
            r.last_seen = unix_now();
            true
        }
        None => false,
    };
    if !recorded {
        // Deregistered while the Subscribe was in flight: undo it, or the AnLF
        // reports for a registration nobody holds.
        let _ = c
            .delete(&format!("/{SERVICE_NAME}/v1/subscriptions/{sub_id}"))
            .await;
        return Err(format!(
            "registration {registration_id} ended during the Subscribe; unsubscribed {sub_id}"
        ));
    }
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "MLModelMonitor subscribed at AnLF {consumer} sub={sub_id} modelId={} threshold={:.2}",
        reg.model_id,
        f64::from(threshold) / 100.0
    );
    Ok(sub_id)
}

/// Subscribe at the AnLF, retrying 2 s doubling to 30 s, at most 6 attempts.
pub async fn subscribe_at_anlf_retrying(m: &'static Monitor, registration_id: String) {
    let mut backoff = Duration::from_secs(2);
    for _ in 0..6 {
        match subscribe_at_anlf(m, &registration_id).await {
            Ok(_) => return,
            Err(e) if m.registration(&registration_id).is_none() => {
                nextgcore_demo::demo_log!(info, DEMO_KEY, "{e}; not retrying");
                return;
            }
            Err(e) => {
                nextgcore_demo::demo_log!(warn, DEMO_KEY, "{e}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// `DELETE /registrations/{id}` (§4.7.2.3.2): 204, and Unsubscribe at the AnLF.
pub fn handle_deregister(m: &'static Monitor, id: &str) -> SbiResponse {
    let Some(reg) = m.drop_registration(id, true) else {
        return send_not_found(&format!("no registration {id}"), None);
    };
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "MLModelMonitor deregistered: registrationId={id} modelId={}",
        reg.model_id
    );
    SbiResponse::with_status(204)
}

/// One MTLF upkeep pass at `now` (unix seconds): audit each registration idle
/// for [`AUDIT_AFTER_SECS`] by re-sending its subscription to the AnLF
/// (`PUT`, §4.7.2.4.3; 404 = the AnLF lost it, the registration is dropped),
/// and expire one idle for [`REGISTRATION_EXPIRY_SECS`]. Returns the
/// registrations dropped.
pub async fn audit_tick(m: &'static Monitor, now: u64) -> usize {
    let (expired, audits) = {
        let mut regs = lock(&m.registrations);
        let mut expired = Vec::new();
        let mut audits = Vec::new();
        for (id, r) in regs.iter_mut() {
            let idle = now.saturating_sub(r.last_seen);
            if idle >= REGISTRATION_EXPIRY_SECS {
                expired.push(id.clone());
            } else if idle >= AUDIT_AFTER_SECS && !r.auditing {
                if let Some(sub) = r.anlf_subscription.clone() {
                    r.auditing = true;
                    audits.push((id.clone(), r.model_id, r.threshold, sub));
                }
            }
        }
        (expired, audits)
    };
    let mut dropped = 0;
    for id in expired {
        if m.drop_registration(&id, true).is_some() {
            dropped += 1;
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "MLModelMonitor registration {id} expired: no report for {REGISTRATION_EXPIRY_SECS}s"
            );
        }
    }
    let mut set = tokio::task::JoinSet::new();
    for (id, model_id, threshold, (host, port, sub)) in audits {
        let body = subscription_body(m, &id, model_id, threshold);
        let budget = m.notify_budget;
        set.spawn(async move {
            let c = m.client(&host, port);
            let path = format!("/{SERVICE_NAME}/v1/subscriptions/{sub}");
            let put = c.put_json(&path, &body);
            let status = match tokio::time::timeout(budget, put).await {
                Ok(Ok(r)) => Some(r.status),
                _ => None,
            };
            (id, status)
        });
    }
    while let Some(Ok((id, status))) = set.join_next().await {
        match status {
            Some(404) => {
                if m.drop_registration(&id, false).is_some() {
                    dropped += 1;
                    nextgcore_demo::demo_log!(
                        info,
                        DEMO_KEY,
                        "MLModelMonitor registration {id} dropped: the AnLF no longer holds its subscription"
                    );
                }
            }
            Some(s) if (200..300).contains(&s) => {
                if let Some(r) = lock(&m.registrations).get_mut(&id) {
                    r.last_seen = now;
                    r.auditing = false;
                }
            }
            _ => {
                if let Some(r) = lock(&m.registrations).get_mut(&id) {
                    r.auditing = false;
                }
            }
        }
    }
    dropped
}

/// Run the MTLF upkeep on `ctx` every 5 s for the life of the process (demo
/// on): audits, expiry, and (PR 4) the retrain of a model below the threshold.
pub fn spawn_upkeep(m: &'static Monitor, ctx: std::sync::Arc<RwLock<NwdafContext>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            audit_tick(m, unix_now()).await;
            crate::model_refit::refit_tick(m, &ctx);
        }
    });
}

/// `POST /nnwdaf-callback/v1/mlmodel-monitor-notify/{token}`: an AnLF's
/// `MLModelMonitorNotify` (§4.7.2.6.2). The whole body is checked before any
/// entry is recorded. Each `mlModelAcc` of the registration's model feeds that
/// registration's collector; the first drop of the rolling accuracy below the
/// threshold is logged per the mode. 204; an unknown token, or a `notifCorrId`
/// that is not a live registration, 404 (the AnLF then drops the subscription
/// and registers again); a body that is not a notification 400.
pub fn handle_notify(m: Option<&Monitor>, token: &str, request: &SbiRequest) -> SbiResponse {
    let Some(m) = m.filter(|m| m.role.serves_mtlf() && token_matches(&m.token, token)) else {
        return send_not_found("no such callback", None);
    };
    let Some(body) = body_json(request) else {
        return send_bad_request("body is not JSON", None);
    };
    let Some(corr) = body.get("notifCorrId").and_then(Value::as_str) else {
        return send_bad_request("notifCorrId is mandatory", None);
    };
    let infos = body.get("modelAccuInfos").and_then(Value::as_array);
    if infos.is_none() && body.get("anaFeedbacks").and_then(Value::as_array).is_none() {
        return send_bad_request("modelAccuInfos or anaFeedbacks is required", None);
    }
    // Validate every entry first: a bad one refuses the whole report.
    let mut reports = Vec::new();
    for info in infos.into_iter().flatten() {
        let Some(model_id) = uint(info.get("modelId")) else {
            return send_bad_request("MLModelAccuracyInfo.modelId is a mandatory Uinteger", None);
        };
        match info.get("mlModelAcc") {
            None => {}
            Some(v) => match v.as_u64().filter(|a| *a <= 100) {
                Some(acc) => reports.push((model_id, acc)),
                None => return send_bad_request("mlModelAcc is a percentage 0..100", None),
            },
        }
    }
    let reg_model = match lock(&m.registrations).get_mut(corr) {
        Some(r) => {
            r.last_seen = unix_now();
            r.model_id
        }
        None => {
            return send_not_found(&format!("no MLModelMonitor registration {corr}"), None);
        }
    };
    m.received.fetch_add(1, Ordering::Relaxed);
    for (model_id, acc) in reports {
        if model_id != reg_model {
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "accuracy report for modelId={model_id} ignored: registration {corr} is for {reg_model}"
            );
            continue;
        }
        let accuracy = acc as f64 / 100.0;
        let Some((rolling, n, threshold, crossed)) =
            lock(&m.feedback).record_accuracy(corr, accuracy)
        else {
            continue;
        };
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "accuracy {accuracy:.2} reported for modelId={model_id} ({corr}); rolling {rolling:.2} over {n}"
        );
        if crossed {
            if m.mode == "retrain" {
                nextgcore_demo::demo_log!(
                    warn,
                    DEMO_KEY,
                    "accuracy {rolling:.2} < {threshold:.2}: retrain requested (modelId={model_id})"
                );
            } else {
                nextgcore_demo::demo_log!(
                    warn,
                    DEMO_KEY,
                    "accuracy {rolling:.2} < {threshold:.2}: mode {}, no retrain (modelId={model_id})",
                    m.mode
                );
            }
        }
    }
    SbiResponse::with_status(204)
}

fn token_matches(expected: &str, got: &str) -> bool {
    let (e, g) = (expected.as_bytes(), got.as_bytes());
    e.len() == g.len() && e.iter().zip(g).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── AnLF: Register at the MTLF, the Subscribe producer, the reporter ─────────

/// §6.2E.3.2: register the use of model `model_id` at the MTLF, after
/// deregistering the model this AnLF used before. This is also the
/// registration the reporter keeps alive (see [`report_tick`]).
pub async fn register_at_mtlf(
    m: &Monitor,
    mtlf: (String, u16),
    model_id: u64,
) -> Result<HeldRegistration, String> {
    *lock(&m.wanted) = Some(Wanted {
        host: mtlf.0.clone(),
        port: mtlf.1,
        model_id,
    });
    let _serial = m.registering.lock().await;
    register_locked(m, mtlf, model_id).await
}

/// [`register_at_mtlf`] under `m.registering`.
async fn register_locked(
    m: &Monitor,
    mtlf: (String, u16),
    model_id: u64,
) -> Result<HeldRegistration, String> {
    let c = m.client(&mtlf.0, mtlf.1);
    if let Some(old) = m.held() {
        if old.model_id == model_id && (old.host.as_str(), old.port) == (mtlf.0.as_str(), mtlf.1) {
            return Ok(old);
        }
        let _ = c
            .delete(&format!("/{SERVICE_NAME}/v1/registrations/{}", old.id))
            .await;
        *lock(&m.held) = None;
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "MLModelMonitor deregistered modelId={} at MTLF",
            old.model_id
        );
    }
    let body = json!({
        "consumerId": m.own_id,
        "modelId": model_id,
        "modelAccuInd": true,
        "mLEvent": crate::model_retrain::MODEL_EVENT.as_str(),
    });
    let resp = c
        .post_json(&format!("/{SERVICE_NAME}/v1/registrations"), &body)
        .await
        .map_err(|e| format!("Nnwdaf_MLModelMonitor_Register failed: {e}"))?;
    if resp.status != 201 {
        return Err(format!(
            "Nnwdaf_MLModelMonitor_Register answered {}",
            resp.status
        ));
    }
    let id = resp
        .http
        .get_header("Location")
        .and_then(|l| l.rsplit('/').next().map(String::from))
        .ok_or("the 201 carries no Location")?;
    let held = HeldRegistration {
        id: id.clone(),
        model_id,
        host: mtlf.0,
        port: mtlf.1,
    };
    *lock(&m.held) = Some(held.clone());
    lock(&m.upkeep).orphan_since = None;
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "MLModelMonitor registered at MTLF {}:{} modelId={model_id} registrationId={id}",
        held.host,
        held.port
    );
    Ok(held)
}

/// The registration this AnLF holds was lost at the MTLF (its Notify was
/// answered 404): forget it, so the reporter registers again at once.
fn registration_lost(m: &Monitor, registration_id: &str) {
    let mut held = lock(&m.held);
    if held.as_ref().is_some_and(|h| h.id == registration_id) {
        *held = None;
        lock(&m.upkeep).last_attempt = None;
        nextgcore_demo::demo_log!(
            warn,
            DEMO_KEY,
            "MLModelMonitor registration {registration_id} is gone at the MTLF; registering again"
        );
    }
}

/// Keep the wanted registration alive, in the reporter's clock `now`:
/// - none held (lost, or the Register failed): Register, at most every
///   [`REGISTER_RETRY_SECS`];
/// - held, but no subscription for it for [`ORPHAN_GRACE_SECS`] (the MTLF never
///   subscribed, or dropped it): Deregister it and Register again.
fn reconcile(m: &'static Monitor, now: u64) {
    let Some(want) = lock(&m.wanted).clone() else {
        return;
    };
    if m.reconciling.load(Ordering::Acquire) {
        return;
    }
    let held = m.held();
    let act = {
        let mut up = lock(&m.upkeep);
        match &held {
            None => {
                let due = up
                    .last_attempt
                    .is_none_or(|t| now >= t + REGISTER_RETRY_SECS);
                if due {
                    up.last_attempt = Some(now);
                }
                due
            }
            Some(h) => {
                let served = lock(&m.subscriptions)
                    .values()
                    .any(|s| s.notif_corr_id == h.id);
                if served {
                    up.orphan_since = None;
                    false
                } else {
                    let since = *up.orphan_since.get_or_insert(now);
                    if now >= since + ORPHAN_GRACE_SECS {
                        up.orphan_since = None;
                        nextgcore_demo::demo_log!(
                            warn,
                            DEMO_KEY,
                            "MLModelMonitor registration {} has had no subscription for {ORPHAN_GRACE_SECS}s; registering again",
                            h.id
                        );
                        true
                    } else {
                        false
                    }
                }
            }
        }
    };
    if !act || m.reconciling.swap(true, Ordering::AcqRel) {
        return;
    }
    tokio::spawn(async move {
        {
            let _serial = m.registering.lock().await;
            // Only if nothing changed meanwhile (a new model, a lost one).
            if m.held() == held && lock(&m.wanted).as_ref() == Some(&want) {
                if let Some(old) = held {
                    let _ = m
                        .client(&old.host, old.port)
                        .delete(&format!("/{SERVICE_NAME}/v1/registrations/{}", old.id))
                        .await;
                    *lock(&m.held) = None;
                }
                if let Err(e) = register_locked(m, (want.host, want.port), want.model_id).await {
                    nextgcore_demo::demo_log!(warn, DEMO_KEY, "{e}");
                }
            }
        }
        m.reconciling.store(false, Ordering::Release);
    });
}

/// Parse an `MLModelMonitorSub`: `modelIds` (minItems 1), `notificationUri`,
/// `notifCorrId` required; `accuThreshold` 0..100; `eventReportReq.repPeriod`,
/// raised to at least [`MIN_REPORT_PERIOD_SECS`] (the representation returned
/// carries the period applied).
pub fn parse_subscription(body: &Value) -> Result<MonitorSub, String> {
    let model_ids: Vec<u64> = body
        .get("modelIds")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or("modelIds is a mandatory non-empty array")?
        .iter()
        .map(|v| v.as_u64().ok_or("modelIds holds Uintegers"))
        .collect::<Result<_, _>>()?;
    let notification_uri = body
        .get("notificationUri")
        .and_then(Value::as_str)
        .filter(|u| crate::notification_dispatcher::parse_notify_uri(u).is_some())
        .ok_or("notificationUri is a mandatory http(s) URI")?
        .to_string();
    let notif_corr_id = body
        .get("notifCorrId")
        .and_then(Value::as_str)
        .ok_or("notifCorrId is mandatory")?
        .to_string();
    let accu_threshold = match body.get("accuThreshold") {
        None => None,
        Some(v) => Some(
            v.as_u64()
                .filter(|t| *t <= 100)
                .ok_or("accuThreshold is an integer 0..100")? as u8,
        ),
    };
    let period_secs = body
        .get("eventReportReq")
        .and_then(|r| r.get("repPeriod"))
        .and_then(Value::as_u64)
        .filter(|p| *p > 0)
        .unwrap_or(DEFAULT_REPORT_PERIOD_SECS)
        .max(MIN_REPORT_PERIOD_SECS);
    Ok(MonitorSub {
        model_ids,
        notification_uri,
        notif_corr_id,
        accu_threshold,
        period_secs,
        last_report: None,
    })
}

fn sub_json(id: &str, s: &MonitorSub) -> Value {
    let mut v = json!({
        "modelIds": s.model_ids,
        "notificationUri": s.notification_uri,
        "notifCorrId": s.notif_corr_id,
        "eventReportReq": { "notifMethod": "PERIODIC", "repPeriod": s.period_secs },
        "subscriptionId": id,
    });
    if let Some(t) = s.accu_threshold {
        v["accuThreshold"] = json!(t);
    }
    v
}

/// `POST /subscriptions` (201 + `Location`; past the cap 500
/// `INSUFFICIENT_RESOURCES`) or `PUT /subscriptions/{id}` (200; 404 if
/// unknown), §4.7.2.4.
pub fn handle_subscribe(m: &Monitor, id: Option<&str>, request: &SbiRequest) -> SbiResponse {
    let Some(body) = body_json(request) else {
        return send_bad_request("body is not JSON", Some("INVALID_MSG_FORMAT"));
    };
    let sub = match parse_subscription(&body) {
        Ok(s) => s,
        Err(e) => return send_bad_request(&e, Some("MANDATORY_IE_MISSING")),
    };
    match id {
        None => {
            let mut subs = lock(&m.subscriptions);
            if subs.len() >= m.cap {
                return insufficient_resources("MLModelMonitor subscriptions", m.cap);
            }
            let id = m.id("mmsub");
            let echo = sub_json(&id, &sub);
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "MLModelMonitor subscription {id} from MTLF: modelIds={:?} every {}s",
                sub.model_ids,
                sub.period_secs
            );
            subs.insert(id.clone(), sub);
            created(format!("/{SERVICE_NAME}/v1/subscriptions/{id}"), &echo)
        }
        Some(id) => {
            let mut subs = lock(&m.subscriptions);
            let Some(old) = subs.get(id) else {
                return send_not_found(&format!("no subscription {id}"), None);
            };
            // An update keeps the reporting phase.
            let sub = MonitorSub {
                last_report: old.last_report,
                ..sub
            };
            let echo = sub_json(id, &sub);
            subs.insert(id.to_string(), sub);
            SbiResponse::with_status(200)
                .with_json_body(&echo)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
    }
}

/// `DELETE /subscriptions/{id}` (§4.7.2.5.2): 204, or 404.
pub fn handle_unsubscribe(m: &Monitor, id: &str) -> SbiResponse {
    match lock(&m.subscriptions).remove(id) {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(&format!("no subscription {id}"), None),
    }
}

/// The accuracy of the AnLF's current model on its own recent data: `(percent,
/// points)`, or `None` with no point to judge it on. `only` restricts it to one
/// NF instance's series (the monitor's [`Monitor::series`]).
pub fn measure(ctx: &RwLock<NwdafContext>, only: Option<&str>) -> Option<(u8, usize)> {
    let guard = ctx.read().unwrap_or_else(|p| p.into_inner());
    let (sum, n) = guard.lock_engine().backtest_nf_load(BACKTEST_POINTS, only);
    if n == 0 {
        return None;
    }
    let acc = (1.0 - sum / n as f64).clamp(0.0, 1.0);
    Some(((acc * 100.0).round() as u8, n))
}

/// The `MLModelMonitorNotify` for one report.
pub fn notify_body(
    sub: &MonitorSub,
    model_id: u64,
    pct: u8,
    n: usize,
    from: u64,
    to: u64,
) -> Value {
    let mut v = json!({
        "notifCorrId": sub.notif_corr_id,
        "modelAccuInfos": [{
            "modelId": model_id,
            "mlModelAcc": pct,
            "inferenceNum": n,
            "monitorInterval": { "startTime": rfc3339(from), "stopTime": rfc3339(to) },
        }],
        "mLEvent": crate::model_retrain::MODEL_EVENT.as_str(),
    });
    if let Some(t) = sub.accu_threshold {
        v["accuMeetInd"] = json!(pct >= t);
    }
    v
}

/// One reporter pass at `now`: keep the registration alive ([`reconcile`]),
/// then every due subscription naming `current` (the AnLF's model's
/// `modelUniqueId`) gets a Notify. The Notifies go out concurrently (at most
/// the subscription cap), each time-boxed to the monitor's budget, so a dead
/// `notificationUri` neither stalls the tick nor delays another report. A
/// Notify answered 404 drops its subscription (the resource is gone); if that
/// subscription served the registration this AnLF holds, it registers again.
/// Returns how many Notifies were accepted.
pub async fn report_tick(
    m: &'static Monitor,
    ctx: &RwLock<NwdafContext>,
    current: Option<u64>,
    now: u64,
) -> usize {
    reconcile(m, now);
    let Some(model_id) = current else { return 0 };
    let due: Vec<(String, MonitorSub)> = lock(&m.subscriptions)
        .iter()
        .filter(|(_, s)| s.model_ids.contains(&model_id))
        .filter(|(_, s)| s.last_report.is_none_or(|t| now >= t + s.period_secs))
        .map(|(id, s)| (id.clone(), s.clone()))
        .collect();
    if due.is_empty() {
        return 0;
    }
    let Some((pct, n)) = measure(ctx, m.series.as_deref()) else {
        return 0;
    };
    let mut set = tokio::task::JoinSet::new();
    for (id, sub) in due {
        let Some((host, port, path)) =
            crate::notification_dispatcher::parse_notify_uri(&sub.notification_uri)
        else {
            continue;
        };
        let from = sub
            .last_report
            .unwrap_or(now.saturating_sub(sub.period_secs));
        let body = notify_body(&sub, model_id, pct, n, from, now);
        if let Some(s) = lock(&m.subscriptions).get_mut(&id) {
            s.last_report = Some(now);
        }
        let budget = m.notify_budget;
        set.spawn(async move {
            let c = crate::notification_dispatcher::notify_client(&host, port);
            let post = c.post_json(&path, &body);
            let outcome = match tokio::time::timeout(budget, post).await {
                Ok(Ok(r)) => Ok(r.status),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err(format!("no answer within {budget:?}")),
            };
            (id, sub.notif_corr_id, outcome)
        });
    }
    let mut sent = 0;
    while let Some(Ok((id, corr, outcome))) = set.join_next().await {
        match outcome {
            Ok(s) if (200..300).contains(&s) => {
                sent += 1;
                m.sent.fetch_add(1, Ordering::Relaxed);
                nextgcore_demo::demo_log!(
                    info,
                    DEMO_KEY,
                    "accuracy {:.2} (n={n}) reported for modelId={model_id} sub={id}",
                    f64::from(pct) / 100.0
                );
            }
            Ok(404) => {
                lock(&m.subscriptions).remove(&id);
                nextgcore_demo::demo_log!(
                    warn,
                    DEMO_KEY,
                    "MLModelMonitor notify sub={id} answered 404: subscription dropped"
                );
                registration_lost(m, &corr);
            }
            Ok(s) => nextgcore_demo::demo_log!(
                warn,
                DEMO_KEY,
                "MLModelMonitor notify sub={id} answered {s}"
            ),
            Err(e) => {
                nextgcore_demo::demo_log!(warn, DEMO_KEY, "MLModelMonitor notify sub={id}: {e}")
            }
        }
    }
    sent
}

/// The AnLF's model's `modelUniqueId`, from what `model_retrain` loaded.
pub fn current_model_id() -> Option<u64> {
    crate::model_retrain::anlf()
        .and_then(|a| a.loaded())
        .map(|l| crate::model_store::unique_id_of(&l.sha256))
}

/// Run the reporter for the life of the process (AnLF, demo on).
pub fn spawn_reporter(m: &'static Monitor) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            report_tick(m, &crate::nwdaf_self(), current_model_id(), unix_now()).await;
        }
    });
}

/// Called by `model_retrain` when the AnLF loaded a model: register its use at
/// the MTLF in the background.
pub fn on_model_loaded(mtlf: Option<(String, u16)>, sha256: &str) {
    let (Some(m), Some(mtlf)) = (monitor(), mtlf) else {
        return;
    };
    let model_id = crate::model_store::unique_id_of(sha256);
    tokio::spawn(async move {
        if let Err(e) = register_at_mtlf(m, mtlf, model_id).await {
            nextgcore_demo::demo_log!(warn, DEMO_KEY, "{e}");
        }
    });
}

/// This module's `/metrics` families.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    let (sent, received) = monitor().map(Monitor::counts).unwrap_or((0, 0));
    nextgcore_metrics::nf::write_header(
        out,
        "nwdaf_mlmodelmonitor_notifies_total",
        "counter",
        "Nnwdaf_MLModelMonitor accuracy notifies sent (AnLF) and received (MTLF) (nextgsim#468)",
    );
    let _ = writeln!(
        out,
        "nwdaf_mlmodelmonitor_notifies_total{{direction=\"sent\"}} {sent}"
    );
    let _ = writeln!(
        out,
        "nwdaf_mlmodelmonitor_notifies_total{{direction=\"received\"}} {received}"
    );
    nextgcore_metrics::nf::write_metric(
        out,
        "nwdaf_mlmodelmonitor_registrations",
        "gauge",
        "Nnwdaf_MLModelMonitor registrations this MTLF holds (nextgsim#468)",
        monitor().map(|m| lock(&m.registrations).len()).unwrap_or(0),
    );
    crate::model_refit::render_metrics(out, monitor());
}

#[cfg(test)]
mod tests;
