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
//!    refit itself is PR 4.
//!
//! The notify callback `/nnwdaf-callback/v1/mlmodel-monitor-notify/{token}`
//! authenticates by its 122-bit token (TS 33.501 §13.4.1: no OAuth2 on
//! notifications) and has the same OAuth2-enforcement limitation as the model
//! notify (nextgcore#1421).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// One MTLF-side registration (an `MLModelMonitorReg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub consumer_id: Option<String>,
    pub model_id: u64,
    /// `(host, port, subscriptionId)` of the subscription at the AnLF.
    pub anlf_subscription: Option<(String, u16, String)>,
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
    // MTLF side
    registrations: Mutex<HashMap<String, Registration>>,
    feedback: Mutex<crate::ml_service::FeedbackRegistry>,
    received: AtomicU64,
    // AnLF side
    subscriptions: Mutex<HashMap<String, MonitorSub>>,
    held: Mutex<Option<HeldRegistration>>,
    sent: AtomicU64,
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
            registrations: Mutex::new(HashMap::new()),
            feedback: Mutex::new(crate::ml_service::FeedbackRegistry::new()),
            received: AtomicU64::new(0),
            subscriptions: Mutex::new(HashMap::new()),
            held: Mutex::new(None),
            sent: AtomicU64::new(0),
        }
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

    /// `(rolling accuracy, reports)` the MTLF holds for `model_id`.
    pub fn rolling(&self, model_id: u64) -> Option<(f64, usize)> {
        lock(&self.feedback)
            .collector(&model_id.to_string())
            .map(|c| (c.rolling_accuracy(), c.sample_count()))
    }

    /// Whether the rolling accuracy of `model_id` fell below the threshold.
    pub fn below_threshold(&self, model_id: u64) -> bool {
        lock(&self.feedback)
            .collector(&model_id.to_string())
            .is_some_and(|c| c.retrain_requested())
    }

    /// Whether the MTLF requested a retrain of `model_id`: below the
    /// threshold, in mode `retrain`. Mode `no-retrain` never requests one.
    pub fn retrain_requested(&self, model_id: u64) -> bool {
        self.mode == "retrain" && self.below_threshold(model_id)
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

/// `POST /registrations` (§4.7.2.2.2): 201 + `Location`, then Subscribe at the
/// AnLF in the background. A `modelId` this MTLF did not provision is 400.
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
    let threshold = ctx
        .ml_prov_accuracy_threshold(crate::model_retrain::MODEL_EVENT)
        .unwrap_or(crate::model_retrain::DEFAULT_ACCURACY_THRESHOLD);
    let id = m.id("reg");
    lock(&m.registrations).insert(
        id.clone(),
        Registration {
            consumer_id: consumer_id.clone(),
            model_id,
            anlf_subscription: None,
        },
    );
    lock(&m.feedback).register_model_with(
        model_id.to_string(),
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
    tokio::spawn(subscribe_at_anlf_retrying(m, id.clone(), threshold));
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
/// subscribe to its accuracy reports. Records the subscription on success.
pub async fn subscribe_at_anlf(
    m: &Monitor,
    registration_id: &str,
    threshold: u8,
) -> Result<String, String> {
    let reg = m
        .registration(registration_id)
        .ok_or("the registration is gone")?;
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
    let resp = client(&host, port)
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
    if let Some(r) = lock(&m.registrations).get_mut(registration_id) {
        r.anlf_subscription = Some((host, port, sub_id.clone()));
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
pub async fn subscribe_at_anlf_retrying(
    m: &'static Monitor,
    registration_id: String,
    threshold: u8,
) {
    let mut backoff = Duration::from_secs(2);
    for _ in 0..6 {
        match subscribe_at_anlf(m, &registration_id, threshold).await {
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
pub fn handle_deregister(m: &Monitor, id: &str) -> SbiResponse {
    let Some(reg) = lock(&m.registrations).remove(id) else {
        return send_not_found(&format!("no registration {id}"), None);
    };
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "MLModelMonitor deregistered: registrationId={id} modelId={}",
        reg.model_id
    );
    if let Some((host, port, sub)) = reg.anlf_subscription {
        tokio::spawn(async move {
            let _ = client(&host, port)
                .delete(&format!("/{SERVICE_NAME}/v1/subscriptions/{sub}"))
                .await;
        });
    }
    SbiResponse::with_status(204)
}

/// `POST /nnwdaf-callback/v1/mlmodel-monitor-notify/{token}`: an AnLF's
/// `MLModelMonitorNotify` (§4.7.2.6.2). Each `mlModelAcc` feeds the
/// `FeedbackRegistry`; the first drop of the rolling accuracy below the
/// threshold is logged per the mode. 204; an unknown token 404; a body that is
/// not a notification 400.
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
    m.received.fetch_add(1, Ordering::Relaxed);
    for info in infos.into_iter().flatten() {
        let (Some(model_id), Some(acc)) = (uint(info.get("modelId")), uint(info.get("mlModelAcc")))
        else {
            continue;
        };
        if acc > 100 {
            return send_bad_request("mlModelAcc is a percentage 0..100", None);
        }
        let accuracy = acc as f64 / 100.0;
        let Some((rolling, n, threshold, crossed)) =
            lock(&m.feedback).record_accuracy(&model_id.to_string(), accuracy)
        else {
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "accuracy report for unregistered modelId={model_id} ignored ({corr})"
            );
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
/// deregistering the model this AnLF used before.
pub async fn register_at_mtlf(
    m: &Monitor,
    mtlf: (String, u16),
    model_id: u64,
) -> Result<HeldRegistration, String> {
    let c = client(&mtlf.0, mtlf.1);
    if let Some(old) = m.held() {
        if old.model_id == model_id {
            return Ok(old);
        }
        let _ = c
            .delete(&format!("/{SERVICE_NAME}/v1/registrations/{}", old.id))
            .await;
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
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "MLModelMonitor registered at MTLF {}:{} modelId={model_id} registrationId={id}",
        held.host,
        held.port
    );
    Ok(held)
}

/// Parse an `MLModelMonitorSub`: `modelIds` (minItems 1), `notificationUri`,
/// `notifCorrId` required; `accuThreshold` 0..100; `eventReportReq.repPeriod`.
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
        .unwrap_or(DEFAULT_REPORT_PERIOD_SECS);
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

/// `POST /subscriptions` (201 + `Location`) or `PUT /subscriptions/{id}` (200;
/// 404 if unknown), §4.7.2.4.
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
            let id = m.id("mmsub");
            let echo = sub_json(&id, &sub);
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "MLModelMonitor subscription {id} from MTLF: modelIds={:?} every {}s",
                sub.model_ids,
                sub.period_secs
            );
            lock(&m.subscriptions).insert(id.clone(), sub);
            created(format!("/{SERVICE_NAME}/v1/subscriptions/{id}"), &echo)
        }
        Some(id) => {
            let mut subs = lock(&m.subscriptions);
            if !subs.contains_key(id) {
                return send_not_found(&format!("no subscription {id}"), None);
            }
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
/// points)`, or `None` with no point to judge it on.
pub fn measure(ctx: &RwLock<NwdafContext>) -> Option<(u8, usize)> {
    let guard = ctx.read().unwrap_or_else(|p| p.into_inner());
    let (sum, n) = guard.lock_engine().backtest_nf_load(BACKTEST_POINTS);
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

/// One reporter pass at `now`: every due subscription naming `current` (the
/// AnLF's model's `modelUniqueId`) gets a Notify. Returns how many were sent.
pub async fn report_tick(
    m: &Monitor,
    ctx: &RwLock<NwdafContext>,
    current: Option<u64>,
    now: u64,
) -> usize {
    let Some(model_id) = current else { return 0 };
    let due: Vec<(String, MonitorSub)> = lock(&m.subscriptions)
        .iter()
        .filter(|(_, s)| s.model_ids.contains(&model_id))
        .filter(|(_, s)| s.last_report.is_none_or(|t| now >= t + s.period_secs))
        .map(|(id, s)| (id.clone(), s.clone()))
        .collect();
    let Some((pct, n)) = measure(ctx) else {
        return 0;
    };
    let mut sent = 0;
    for (id, sub) in due {
        let from = sub
            .last_report
            .unwrap_or(now.saturating_sub(sub.period_secs));
        let body = notify_body(&sub, model_id, pct, n, from, now);
        let Some((host, port, path)) =
            crate::notification_dispatcher::parse_notify_uri(&sub.notification_uri)
        else {
            continue;
        };
        if let Some(s) = lock(&m.subscriptions).get_mut(&id) {
            s.last_report = Some(now);
        }
        match crate::notification_dispatcher::notify_client(&host, port)
            .post_json(&path, &body)
            .await
        {
            Ok(r) if r.is_success() => {
                sent += 1;
                m.sent.fetch_add(1, Ordering::Relaxed);
                nextgcore_demo::demo_log!(
                    info,
                    DEMO_KEY,
                    "accuracy {:.2} (n={n}) reported for modelId={model_id} sub={id}",
                    f64::from(pct) / 100.0
                );
            }
            Ok(r) => nextgcore_demo::demo_log!(
                warn,
                DEMO_KEY,
                "MLModelMonitor notify sub={id} answered {}",
                r.status
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
}

#[cfg(test)]
mod tests;
