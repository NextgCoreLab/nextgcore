//! The PCF's QoS monitoring policy for packet delay (#2208).
//!
//! TS 23.501 §5.33.3.1: "When SMF receives the authorized QoS Monitoring policy
//! for packet delay in a PCC rule from the PCF ..., SMF configures the UPF(s) and
//! NG-RAN to perform delay measurements according to the method selected: per QoS
//! Flow per UE QoS measurement (§5.33.3.2) or per GTP-U Path measurement
//! (§5.33.3.3)", the choice being "subject to the operators' configuration". TS
//! 29.512 §4.2.3.25.1 carries the policy as `QosMonitoringData` instances in the
//! decision's `qosMonDecs`, referenced from a PCC rule's `refQosMon`; "When the
//! SMF receives the PCC rule, the SMF shall send a QoS Monitoring request to the
//! PSA UPF via N4 ... and NG-RAN via N2".
//!
//! This module holds, per session, what the PCF's decisions installed (applied as
//! the deltas TS 29.512 §4.2.6.1 makes them, [`apply`]), and turns each referenced
//! instance into the PSA's SRR (TS 29.244 §5.24.4, IE 242). The SRR itself, its
//! N4 lifecycle and the NG-RAN leg are `qos_mon`'s, the same as for a QOS_MON
//! subscription: an SRR serving instance `qmId` is keyed `pcc:<qmId>` there.
//!
//! - **Method** ([`Method`], `smf.qos_monitoring.method`): `per_qos_flow` (the
//!   default, GTPUPM 0) or `gtpu_path` (GTPUPM 1, TS 29.244 §8.2.167). With
//!   `gtpu_path` and a PSA that advertised GPQM, the PSA's UL PDR also gets
//!   Transport Delay Reporting (IE 271, §5.24.5.3) naming its preceding UL GTP-U
//!   peer (`qos_mon::sync_transport_delay`). A PSA without GPQM is asked for the
//!   per QoS flow method, and that is logged.
//! - **Reports** (TS 29.512 §4.2.3.25.1, §4.2.4.24): to the instance's
//!   `notifyUri` with its `notifyCorreId` (the SMF bypassing the PCF, an
//!   `Nsmf_EventExposure_Notify` QOS_MON, TS 29.508), else to the PCF in an
//!   Npcf_SMPolicyControl_Update with QOS_MONITORING and `qosMonReports` when the
//!   PCF provisioned that trigger, else to nobody (logged).
//!
//! Not modelled, stated: QoS monitoring parameter types other than packet delay
//! (congestion, data rate, available bitrate: an instance naming one is not
//! monitored), the UPF's direct notification (`directNotifInd`: reports still go
//! through the SMF to the `notifyUri`), and `dataCollAppId` (UPEAS). The policy is
//! held in memory, like `qos_mon`'s SRRs: after a restart the next decision for
//! the session installs it again.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::Value;

use crate::event_exposure::QosMonResult;
use crate::policy::{QosMonDelta, RuleQosMon};
use nextgcore_pfcp::qos_monitoring::{
    PacketDelayThresholds, QosMonitoringPerQosFlowControlInformation, ReportingFrequency,
    RequestedQosMonitoring,
};

/// The key prefix of a `qos_mon` SRR that serves a PCF QoS monitoring decision.
pub const REQUESTER_PREFIX: &str = "pcc:";

/// How the delay between the NG-RAN and the PSA UPF is measured (TS 23.501
/// §5.33.3.1: "subject to the operators' configuration").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Per QoS Flow per UE (§5.33.3.2): the PSA sends QMP-marked DL packets and
    /// takes the N3 delay from the NG-RAN's time stamps. GTPUPM 0.
    #[default]
    PerQosFlow,
    /// Per GTP-U path (§5.33.3.3): every UPF of the session measures the delay to
    /// its preceding GTP-U peer with Echo, and the PSA adds them up. GTPUPM 1.
    GtpuPath,
}

/// `smf.qos_monitoring` in the SMF's YAML.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosMonitoringYaml {
    /// Act on the PCF's QoS monitoring policy (#2208 review M1): offer
    /// QosMonitoring (24) and PacketDelayFailureReport (73) in the SM policy
    /// create, and provision the decisions. Off by default, so a default SMF's
    /// N7 and N4 are what they were.
    #[serde(default)]
    pub pcc: bool,
    #[serde(default)]
    pub method: Method,
}

static METHOD: AtomicU8 = AtomicU8::new(0);

static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Enable the PCF's QoS monitoring policy (startup: `smf.qos_monitoring.pcc`).
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::SeqCst);
}

/// Whether the PCF's QoS monitoring policy is acted on.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

/// Configure the measurement method (startup).
pub fn set_method(m: Method) {
    METHOD.store(m as u8, Ordering::SeqCst);
}

/// The configured measurement method.
pub fn method() -> Method {
    match METHOD.load(Ordering::SeqCst) {
        1 => Method::GtpuPath,
        _ => Method::PerQosFlow,
    }
}

/// One `QosMonitoringData` instance (TS 29.512 §5.6.2.40) for packet delay, as
/// the SMF acts on it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QosMonPolicy {
    pub dl: bool,
    pub ul: bool,
    pub rp: bool,
    pub event_triggered: bool,
    pub periodic: bool,
    /// `repThreshDl` / `repThreshUl` / `repThreshRp`, ms.
    pub thresholds: PacketDelayThresholds,
    /// `waitTime`, s.
    pub wait_time: Option<u32>,
    /// `repPeriod`, s.
    pub rep_period: Option<u32>,
    /// `notifyUri` and `notifyCorreId`: the SMF reports there, bypassing the PCF.
    pub notify: Option<(String, Option<String>)>,
}

/// The Measurement Period when a Periodic instance names no `repPeriod`.
const DEFAULT_PERIOD_SECS: u32 = crate::qos_mon::DEFAULT_PERIOD_SECS;

fn secs(v: Option<&Value>) -> Option<u32> {
    v.and_then(Value::as_u64)
        .map(|n| n.min(u32::MAX as u64) as u32)
}

/// Parse instance `v` (TS 29.512 §4.2.3.25.1). `Err` names why the SMF cannot
/// act on it: another parameter type, nothing it can measure, or an
/// event-triggered request without the threshold of a parameter it names.
pub fn parse_policy(v: &Value) -> Result<QosMonPolicy, String> {
    match v.get("qosMonParamType").and_then(Value::as_str) {
        None | Some("PACKET_DELAY") => {}
        Some(other) => return Err(format!("qosMonParamType {other} is not packet delay")),
    }
    let params: Vec<&str> = v
        .get("reqQosMonParams")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let freqs: Vec<&str> = v
        .get("repFreqs")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut p = QosMonPolicy {
        dl: params.contains(&"DOWNLINK"),
        ul: params.contains(&"UPLINK"),
        rp: params.contains(&"ROUND_TRIP"),
        event_triggered: freqs.contains(&"EVENT_TRIGGERED"),
        periodic: freqs.contains(&"PERIODIC"),
        wait_time: secs(v.get("waitTime")),
        rep_period: secs(v.get("repPeriod")).filter(|p| *p > 0),
        ..Default::default()
    };
    if !(p.dl || p.ul || p.rp) {
        return Err("reqQosMonParams names no DOWNLINK, UPLINK or ROUND_TRIP".into());
    }
    if !(p.event_triggered || p.periodic) {
        return Err("repFreqs names neither EVENT_TRIGGERED nor PERIODIC".into());
    }
    if p.event_triggered {
        let ms = |k: &str| secs(v.get(k));
        p.thresholds = PacketDelayThresholds {
            downlink: ms("repThreshDl").filter(|_| p.dl),
            uplink: ms("repThreshUl").filter(|_| p.ul),
            round_trip: ms("repThreshRp").filter(|_| p.rp),
        };
        for (wanted, got, name) in [
            (p.dl, p.thresholds.downlink, "repThreshDl"),
            (p.ul, p.thresholds.uplink, "repThreshUl"),
            (p.rp, p.thresholds.round_trip, "repThreshRp"),
        ] {
            if wanted && got.is_none() {
                return Err(format!("EVENT_TRIGGERED without {name}"));
            }
        }
    }
    if let Some(uri) = v.get("notifyUri").and_then(Value::as_str) {
        let corre = v
            .get("notifyCorreId")
            .and_then(Value::as_str)
            .map(str::to_string);
        p.notify = Some((uri.to_string(), corre));
    }
    Ok(p)
}

impl QosMonPolicy {
    /// The PSA's QoS Monitoring per QoS flow Control Information (IE 242, TS
    /// 29.244 Table 7.5.2.9-3) for `qfi`, GTPUPM set when `gtpupm`.
    pub fn control(&self, qfi: u8, gtpupm: bool) -> QosMonitoringPerQosFlowControlInformation {
        QosMonitoringPerQosFlowControlInformation {
            qfis: vec![qfi],
            requested_qos_monitoring: RequestedQosMonitoring {
                dlpd: self.dl,
                ulpd: self.ul,
                rppd: self.rp,
                gtpupm,
                ..Default::default()
            },
            reporting_frequency: ReportingFrequency {
                evett: self.event_triggered,
                perio: self.periodic,
            },
            // C: with EVETT (Table 7.5.2.9-3).
            packet_delay_thresholds: self.event_triggered.then_some(self.thresholds),
            // C: "shall be present if event triggered QoS monitoring reporting is
            // required" (Table 7.5.2.9-3). `waitTime`, else 0 (review minor 1).
            minimum_wait_time: self.event_triggered.then_some(self.wait_time.unwrap_or(0)),
            // C: with PERIO the reporting period, and with EVETT the period that
            // detects a measurement failure (TS 29.244 §5.24.4.2): present either
            // way, `repPeriod` else the SMF's default (TS 23.501 §5.33.3.1, "local
            // configuration"; review minor 1).
            measurement_period: Some(self.rep_period.unwrap_or(DEFAULT_PERIOD_SECS)),
            extra: Vec::new(),
        }
    }
}

/// What the PCF's decisions installed on one session.
#[derive(Debug, Clone, Default)]
struct Session {
    /// `qosMonDecs`, by QoS Monitoring Data ID, as the PCF wrote them.
    decs: BTreeMap<String, Value>,
    /// `refQosMon` of each PCC rule that has one.
    refs: BTreeMap<String, Vec<String>>,
    /// QOS_MONITORING is among the policy control request triggers.
    pcf_trigger: bool,
    /// PacketDelayFailureReport was negotiated.
    pdfr: bool,
}

impl Session {
    fn is_empty(&self) -> bool {
        self.decs.is_empty() && self.refs.is_empty() && !self.pcf_trigger && !self.pdfr
    }
}

/// Sessions with PCF QoS monitoring state, by SM context reference. Tests that
/// touch it, or [`METHOD`], hold `qos_mon::TEST_LOCK`: every reader of either is
/// on `qos_mon`'s paths, so one lock covers them (collapsed, not added).
static SESSIONS: Mutex<Option<HashMap<String, Session>>> = Mutex::new(None);

/// Sets the method for a test and puts the default back when dropped, a failed
/// assertion included. Held under `qos_mon::TEST_LOCK`.
#[cfg(test)]
pub(crate) struct MethodForTest;

#[cfg(test)]
impl MethodForTest {
    pub(crate) fn set(m: Method) -> Self {
        set_method(m);
        Self
    }
}

#[cfg(test)]
impl Drop for MethodForTest {
    fn drop(&mut self) {
        set_method(Method::PerQosFlow);
    }
}

/// Turns `smf.qos_monitoring.pcc` on for a test and off again when dropped.
/// Held under `qos_mon::TEST_LOCK`, like [`MethodForTest`].
#[cfg(test)]
pub(crate) struct PccForTest;

#[cfg(test)]
impl PccForTest {
    pub(crate) fn on() -> Self {
        set_enabled(true);
        Self
    }
}

#[cfg(test)]
impl Drop for PccForTest {
    fn drop(&mut self) {
        set_enabled(false);
    }
}

fn with<T>(f: impl FnOnce(&mut HashMap<String, Session>) -> T) -> T {
    let mut g = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

#[cfg(test)]
pub(crate) fn clear_for_test() {
    with(|m| m.clear());
}

/// RFC 7396 merge patch of `patch` onto `target`.
fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(p) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Default::default());
    }
    let t = target.as_object_mut().expect("an object");
    for (k, v) in p {
        if v.is_null() {
            t.remove(k);
        } else {
            merge_patch(t.entry(k.clone()).or_insert(Value::Null), v);
        }
    }
}

/// Apply a decision's QoS monitoring delta to session `r` (TS 29.512 §4.2.6.1:
/// a map entry carries what was added or modified, `null` removes it; a modified
/// `QosMonitoringData` keeps what it does not restate). Returns whether the
/// instances the session's PCC rules reference changed.
pub fn apply(r: &str, d: &QosMonDelta) -> bool {
    if d.is_empty() {
        return false;
    }
    if !enabled() {
        // QosMonitoring was not offered (review M1): a PCF that sends its members
        // anyway is not acted on.
        log::debug!(
            "ref={r}: QoS monitoring members in a decision, but smf.qos_monitoring.pcc is off"
        );
        return false;
    }
    let (changed, invalid) = with(|m| {
        let s = m.entry(r.to_string()).or_default();
        let before = owned(&referenced(s));
        if d.decs_cleared {
            s.decs.clear();
        }
        for (id, v) in &d.decs {
            match v {
                None => {
                    s.decs.remove(id);
                }
                Some(patch) => merge_patch(s.decs.entry(id.clone()).or_insert(Value::Null), patch),
            }
        }
        for (rule, what) in &d.rules {
            match what {
                RuleQosMon::Removed | RuleQosMon::RefsRemoved => {
                    s.refs.remove(rule);
                }
                RuleQosMon::Refs(v) if !v.is_empty() => {
                    s.refs.insert(rule.clone(), v.clone());
                }
                RuleQosMon::Refs(_) | RuleQosMon::Unchanged => {}
            }
        }
        if let Some(t) = d.qos_monitoring_trigger {
            s.pcf_trigger = t;
        }
        if let Some(f) = d.packet_delay_failure_report {
            s.pdfr = f;
        }
        let after = owned(&referenced(s));
        // An instance newly referenced or changed that cannot be acted on is said so.
        let invalid: Vec<(String, String)> = after
            .iter()
            .filter(|(id, v)| before.get(*id) != Some(*v))
            .filter_map(|(id, v)| parse_policy(v).err().map(|e| (id.clone(), e)))
            .collect();
        let changed = before != after;
        if s.is_empty() {
            m.remove(r);
        }
        (changed, invalid)
    });
    for (id, e) in invalid {
        log::warn!(
            "ref={r}: QoS monitoring decision {id} is not monitored: {e} (TS 29.512 §4.2.3.25.1)"
        );
    }
    changed
}

/// The instances the session's PCC rules reference that the session holds.
fn referenced(s: &Session) -> BTreeMap<&str, &Value> {
    s.refs
        .values()
        .flatten()
        .filter_map(|id| s.decs.get_key_value(id))
        .map(|(k, v)| (k.as_str(), v))
        .collect()
}

fn owned(m: &BTreeMap<&str, &Value>) -> BTreeMap<String, Value> {
    m.iter()
        .map(|(k, v)| (k.to_string(), (*v).clone()))
        .collect()
}

/// The session is released: its policy goes with it.
pub fn forget(r: &str) {
    with(|m| m.remove(r));
}

/// The `qos_mon` keys of the SRRs session `r` needs: one per referenced instance
/// the SMF can act on.
pub fn requesters(r: &str) -> Vec<String> {
    with(|m| {
        m.get(r)
            .map(|s| {
                referenced(s)
                    .into_iter()
                    .filter(|(_, v)| parse_policy(v).is_ok())
                    .map(|(id, _)| format!("{REQUESTER_PREFIX}{id}"))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// The policy of instance `qm_id` on session `r`, while a PCC rule references it.
pub fn policy(r: &str, qm_id: &str) -> Option<QosMonPolicy> {
    with(|m| {
        let s = m.get(r)?;
        referenced(s).get(qm_id).and_then(|v| parse_policy(v).ok())
    })
}

/// The PCC rules of session `r` that reference instance `qm_id`, sorted.
pub fn rules_of(r: &str, qm_id: &str) -> Vec<String> {
    with(|m| {
        m.get(r)
            .map(|s| {
                s.refs
                    .iter()
                    .filter(|(_, v)| v.iter().any(|q| q == qm_id))
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Where a report of instance `qm_id` goes (TS 29.512 §4.2.3.25.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The instance's `notifyUri`, with its `notifyCorreId`.
    Notify(String, Option<String>),
    /// The PCF, which provisioned QOS_MONITORING.
    Pcf,
    /// Nobody asked for it.
    Nobody,
}

/// Where a report of instance `qm_id` on session `r` goes.
pub fn target(r: &str, qm_id: &str) -> Target {
    let trigger = with(|m| m.get(r).is_some_and(|s| s.pcf_trigger));
    match policy(r, qm_id).and_then(|p| p.notify) {
        Some((uri, corre)) => Target::Notify(uri, corre),
        None if trigger => Target::Pcf,
        None => Target::Nobody,
    }
}

/// Whether PacketDelayFailureReport was negotiated with the PCF for `r`.
fn pdfr(r: &str) -> bool {
    with(|m| m.get(r).is_some_and(|s| s.pdfr))
}

/// The delay members of one report (TS 29.512 Table 5.6.2.42-1, TS 29.508
/// §4.2.3.2 item 12): one element each (NOTE: the UPF reports one measurement per
/// report), `pdmf` only when PacketDelayFailureReport was negotiated. `None` when
/// that leaves nothing to report.
pub fn delay_members(r: &QosMonResult, pdfr: bool) -> Option<serde_json::Map<String, Value>> {
    let mut o = serde_json::Map::new();
    for (name, v) in [
        ("ulDelays", r.ul_delay),
        ("dlDelays", r.dl_delay),
        ("rtDelays", r.rt_delay),
    ] {
        if let Some(v) = v {
            o.insert(name.into(), serde_json::json!([v]));
        }
    }
    if r.failure && pdfr {
        o.insert("pdmf".into(), Value::Bool(true));
    }
    (!o.is_empty()).then_some(o)
}

/// The PCF's `QosMonitoringReport` (TS 29.512 §5.6.2.42) for instance `qm_id`.
pub fn pcf_report(r: &str, qm_id: &str, result: &QosMonResult) -> Option<Value> {
    let mut o = delay_members(result, pdfr(r))?;
    o.insert(
        "refPccRuleIds".into(),
        serde_json::json!(rules_of(r, qm_id)),
    );
    Some(Value::Object(o))
}

/// The `NsmfEventExposureNotification` sent to a `notifyUri` (TS 29.508
/// §4.2.2.2, Table 5.6.2.3-1: `notifId` is the `notifyCorreId`).
pub fn direct_notification(
    corre: Option<&str>,
    supi: &str,
    psi: u8,
    result: &QosMonResult,
    pdfr: bool,
) -> Option<Value> {
    let mut e = delay_members(result, pdfr)?;
    e.insert(
        "event".into(),
        Value::from(crate::event_exposure::event::QOS_MON),
    );
    e.insert(
        "timeStamp".into(),
        Value::from(nextgcore_sbi::datetime::epoch_to_rfc3339(
            nextgcore_sbi::datetime::now_epoch_secs(),
        )),
    );
    e.insert("supi".into(), Value::from(supi));
    e.insert("pduSeId".into(), Value::from(psi));
    Some(serde_json::json!({
        "notifId": corre.unwrap_or_default(),
        "eventNotifs": [Value::Object(e)],
    }))
}

/// Deliver a report of instance `qm_id` of session `r` to its target.
pub async fn deliver(r: &str, qm_id: &str, result: &QosMonResult) {
    let Some(b) = crate::lookup_policy_binding(r) else {
        return;
    };
    match target(r, qm_id) {
        Target::Nobody => log::info!(
            "ref={r}: QoS monitoring report of decision {qm_id}: no notifyUri and no \
             QOS_MONITORING trigger, reported to nobody"
        ),
        Target::Notify(uri, corre) => {
            let Some(body) = direct_notification(corre.as_deref(), &b.supi, b.psi, result, pdfr(r))
            else {
                log::info!(
                    "ref={r}: QoS monitoring report of decision {qm_id} carries nothing to notify"
                );
                return;
            };
            crate::event_exposure::post_notification(
                &uri,
                &format!("QoS monitoring decision {qm_id}"),
                &body,
                crate::event_exposure::event::QOS_MON,
                &b.supi,
                b.psi,
            )
            .await;
        }
        Target::Pcf => {
            let Some(report) = pcf_report(r, qm_id, result) else {
                log::info!(
                    "ref={r}: QoS monitoring report of decision {qm_id} carries nothing to report"
                );
                return;
            };
            crate::report_qos_monitoring_to_pcf(r, report).await;
        }
    }
}

#[cfg(test)]
#[path = "pcc_qos_mon_tests.rs"]
mod tests;
