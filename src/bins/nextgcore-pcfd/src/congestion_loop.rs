//! The User Data Congestion Session-AMBR controller (nextgsim#465, demo
//! `d441a-congestion-loop`). Cargo feature `demo-d441a-congestion-loop` (which
//! implies `intent-loop`), off by default, and active only with the demo block.
//!
//! TS 23.503 §6.1.1.3 (`23503-k20.txt:2773-2777`, `:2893-2906`): the PCF may use
//! NWDAF User Data Congestion analytics, and they lead to an *"SM Policy
//! Association modification to update the policies in the SMF"*. This is that
//! loop for one Area of Interest:
//!
//! 1. **Observe.** Every `poll_ms`, `Nnwdaf_AnalyticsInfo` `USER_DATA_CONGESTION`
//!    (TS 29.520 §4.3.2.2.2) for `tgt-ue` anyUe and `event-filter.networkArea`
//!    = the configured cells; mode `prediction` asks for a future period
//!    (`ana-req.offsetPeriod`), the other modes for statistics. The level is the
//!    highest `nsi.congLevel` of the answer. A 204 or a failure is no data.
//! 2. **Decide** ([`Controller::step`]), with guardrails: only sessions on the
//!    configured slice and DNN, never a `protected_supis` UE, only the
//!    `best_effort_supis` UEs when that list is set, at most `max_sessions`
//!    throttled, a cap never below `floor_kbps` nor above the subscribed AMBR.
//!    Throttle at `congLevel >= throttle_at`; restore once the level has stayed
//!    below `restore_below` for `restore_after_polls` polls and the throttle is
//!    at least `min_hold_secs` old; with no data for `fail_open_secs`, restore
//!    (fail open). Between the two thresholds nothing changes.
//! 3. **Act.** A throttle writes the cap into the override layer
//!    ([`crate::ambr_override`]) and sends `Npcf_SMPolicyControl_UpdateNotify`;
//!    the notify's decision is `min(subscribed, cap)`, which smfd applies as a
//!    full replacement (#1387), pushes to the UPF QER and to the UE over N1
//!    (#1385). A restore clears the cap and notifies the subscribed value.
//!    `dry_run` logs the action and does neither.
//!
//! # Honesty
//!
//! Choosing UE-B by a configured list is PCF local policy; TS 23.503 targets
//! *"UEs reported as heavy users"* via Data Dispersion analytics, which this
//! does not implement. The thresholds and the cap are implementation choices.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::ambr_override::{self, Cap};

/// The demo key (nextgsim#458 convention), shared with the gNB and nwdafd.
pub const DEMO_KEY: &str = "d441a-congestion-loop";
/// Modes, shared with the gNB and nwdafd.
pub const MODES: &[&str] = &["statistics", "prediction", "no-loop"];

/// What pcfd registers under the feature.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: MODES,
    requires: &[],
};

/// The `pcf.congestion_loop` block, as written. Unknown fields fail start-up.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LoopYaml {
    /// The Area of Interest, as NR cells.
    pub cells: Option<Vec<CellYaml>>,
    /// Only sessions on this slice SST (absent: any).
    pub sst: Option<u8>,
    /// Only sessions on this DNN (absent: any).
    pub dnn: Option<String>,
    /// Never throttled.
    pub protected_supis: Option<Vec<String>>,
    /// When set, only these are throttled.
    pub best_effort_supis: Option<Vec<String>>,
    pub throttle_kbps: Option<u64>,
    pub floor_kbps: Option<u64>,
    pub throttle_at: Option<u64>,
    pub restore_below: Option<u64>,
    pub restore_after_polls: Option<u32>,
    pub min_hold_secs: Option<u64>,
    pub fail_open_secs: Option<u64>,
    pub max_sessions: Option<usize>,
    pub poll_ms: Option<u64>,
    pub prediction_horizon_secs: Option<u64>,
    pub dry_run: Option<bool>,
}

/// One AoI cell.
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CellYaml {
    pub mcc: String,
    pub mnc: String,
    /// 9 hex digits (TS 29.571 `NrCellId`).
    pub nr_cell_id: String,
}

/// The resolved settings.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub cells: Vec<CellYaml>,
    pub sst: Option<u8>,
    pub dnn: Option<String>,
    pub protected_supis: Vec<String>,
    pub best_effort_supis: Vec<String>,
    pub throttle_kbps: u64,
    pub floor_kbps: u64,
    pub throttle_at: u64,
    pub restore_below: u64,
    pub restore_after_polls: u32,
    pub min_hold_secs: u64,
    pub fail_open_secs: u64,
    pub max_sessions: usize,
    pub poll_ms: u64,
    pub prediction_horizon_secs: u64,
    pub dry_run: bool,
}

impl Settings {
    /// Resolve the block; `Err` fails start-up (a throttle on live sessions must
    /// not run on a guessed configuration).
    pub fn from_yaml(y: &LoopYaml) -> Result<Self, String> {
        let cells = y.cells.clone().unwrap_or_default();
        if cells.is_empty() {
            return Err("pcf.congestion_loop.cells must name at least one NR cell".into());
        }
        for c in &cells {
            if c.nr_cell_id.len() != 9 || !c.nr_cell_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!(
                    "pcf.congestion_loop.cells: nr_cell_id {:?} is not 9 hex digits",
                    c.nr_cell_id
                ));
            }
            if c.mcc.len() != 3 || !matches!(c.mnc.len(), 2 | 3) {
                return Err(format!(
                    "pcf.congestion_loop.cells: PLMN {}/{} is not 3+2/3 digits",
                    c.mcc, c.mnc
                ));
            }
        }
        let s = Self {
            cells: cells
                .into_iter()
                .map(|c| CellYaml {
                    nr_cell_id: c.nr_cell_id.to_ascii_uppercase(),
                    ..c
                })
                .collect(),
            sst: y.sst,
            dnn: y.dnn.clone(),
            protected_supis: y.protected_supis.clone().unwrap_or_default(),
            best_effort_supis: y.best_effort_supis.clone().unwrap_or_default(),
            throttle_kbps: y.throttle_kbps.unwrap_or(1000),
            floor_kbps: y.floor_kbps.unwrap_or(500),
            throttle_at: y.throttle_at.unwrap_or(80),
            restore_below: y.restore_below.unwrap_or(30),
            restore_after_polls: y.restore_after_polls.unwrap_or(3).max(1),
            min_hold_secs: y.min_hold_secs.unwrap_or(10),
            fail_open_secs: y.fail_open_secs.unwrap_or(30),
            max_sessions: y.max_sessions.unwrap_or(4),
            poll_ms: y.poll_ms.unwrap_or(1000).max(100),
            prediction_horizon_secs: y.prediction_horizon_secs.unwrap_or(5).max(1),
            dry_run: y.dry_run.unwrap_or(false),
        };
        if s.floor_kbps == 0 {
            return Err("pcf.congestion_loop.floor_kbps must be positive".into());
        }
        if s.restore_below >= s.throttle_at {
            return Err(format!(
                "pcf.congestion_loop: restore_below ({}) must be below throttle_at ({})",
                s.restore_below, s.throttle_at
            ));
        }
        if s.max_sessions == 0 {
            return Err("pcf.congestion_loop.max_sessions must be positive".into());
        }
        for supi in &s.best_effort_supis {
            if s.protected_supis.contains(supi) {
                return Err(format!(
                    "pcf.congestion_loop: {supi} is both protected and best-effort"
                ));
            }
        }
        Ok(s)
    }

    /// The cap a throttle installs on a session subscribed at `subscribed_bps`:
    /// `throttle_kbps`, never below `floor_kbps`, never above the subscription.
    pub fn cap_for(&self, subscribed_bps: u64) -> u64 {
        (self.throttle_kbps.max(self.floor_kbps) * 1000).min(subscribed_bps)
    }
}

/// The `pcf.congestion_loop` block of a config root. `Ok(None)` when absent.
pub fn settings_from_root(root: &serde_yaml::Value) -> Result<Option<Settings>, String> {
    let Some(block) = root.get("pcf").and_then(|p| p.get("congestion_loop")) else {
        return Ok(None);
    };
    let y: LoopYaml =
        serde_yaml::from_value(block.clone()).map_err(|e| format!("pcf.congestion_loop: {e}"))?;
    Settings::from_yaml(&y).map(Some)
}

/// One observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// The highest `nsi.congLevel` in the answer.
    pub cong_level: u64,
    /// `confidence`, for a prediction.
    pub confidence: Option<u64>,
}

/// The highest `congLevel` of a USER_DATA_CONGESTION `AnalyticsData` body.
pub fn observation_from_body(body: &Value) -> Option<Observation> {
    body.get("userDataCongInfos")?
        .as_array()?
        .iter()
        .filter_map(|i| {
            let ci = i.get("congestionInfo")?;
            Some(Observation {
                cong_level: ci.pointer("/nsi/congLevel")?.as_u64()?,
                confidence: ci.get("confidence").and_then(Value::as_u64),
            })
        })
        .max_by_key(|o| o.cong_level)
}

/// The query of the USER_DATA_CONGESTION GET, as `(name, value)` pairs.
pub fn query(settings: &Settings, prediction: bool) -> Vec<(&'static str, String)> {
    let ncgis: Vec<Value> = settings
        .cells
        .iter()
        .map(|c| json!({"plmnId": {"mcc": c.mcc, "mnc": c.mnc}, "nrCellId": c.nr_cell_id}))
        .collect();
    let mut q = vec![
        ("event-id", "USER_DATA_CONGESTION".to_string()),
        ("tgt-ue", json!({"anyUe": true}).to_string()),
        (
            "event-filter",
            json!({"networkArea": {"ncgis": ncgis}}).to_string(),
        ),
    ];
    if prediction {
        q.push((
            "ana-req",
            json!({"offsetPeriod": settings.prediction_horizon_secs}).to_string(),
        ));
    }
    q
}

/// A session the controller may act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub sess_id: u64,
    pub sm_policy_id: String,
    pub supi: String,
    pub sst: u8,
    pub dnn: Option<String>,
    pub has_notification_uri: bool,
}

/// What [`Controller::step`] decided for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Throttle {
        sess_id: u64,
        sm_policy_id: String,
        supi: String,
    },
    Restore {
        sess_id: u64,
        sm_policy_id: String,
        supi: String,
        why: &'static str,
    },
}

/// Why nothing changed this poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    NoRanData,
    WithinBand,
    BelowThreshold,
    Throttled,
    NoCandidate,
    AtMaxSessions,
}

impl Hold {
    fn as_str(self) -> &'static str {
        match self {
            Hold::NoRanData => "hold(no-ran-data)",
            Hold::WithinBand => "hold(within-band)",
            Hold::BelowThreshold => "hold(below-threshold)",
            Hold::Throttled => "hold(throttled)",
            Hold::NoCandidate => "hold(no-candidate)",
            Hold::AtMaxSessions => "hold(max-sessions)",
        }
    }
}

#[derive(Debug, Clone)]
struct Throttled {
    sess_id: u64,
    supi: String,
    since_ms: u64,
}

/// The controller's state: the sessions it throttled, and for how long the level
/// has been low or absent.
#[derive(Debug, Default)]
pub struct Controller {
    throttled: BTreeMap<String, Throttled>,
    low_polls: u32,
    no_data_since_ms: Option<u64>,
}

impl Controller {
    /// The sessions this controller has throttled, by smPolicyId.
    pub fn throttled(&self) -> Vec<String> {
        self.throttled.keys().cloned().collect()
    }

    fn eligible<'a>(s: &Settings, c: &'a Candidate) -> Option<&'a Candidate> {
        let ok = c.has_notification_uri
            && s.sst.is_none_or(|sst| sst == c.sst)
            && s.dnn.as_deref().is_none_or(|d| c.dnn.as_deref() == Some(d))
            && !s.protected_supis.contains(&c.supi)
            && (s.best_effort_supis.is_empty() || s.best_effort_supis.contains(&c.supi));
        ok.then_some(c)
    }

    /// One poll: the observation (None = no data), the live sessions, now.
    /// Returns the actions, or why there are none.
    pub fn step(
        &mut self,
        s: &Settings,
        obs: Option<Observation>,
        sessions: &[Candidate],
        now_ms: u64,
    ) -> Result<Vec<Action>, Hold> {
        // A throttled session that is gone needs no restore; forget it.
        self.throttled
            .retain(|id, _| sessions.iter().any(|c| &c.sm_policy_id == id));
        let restore_all = |me: &mut Self, why: &'static str| -> Vec<Action> {
            let out = me
                .throttled
                .iter()
                .map(|(id, t)| Action::Restore {
                    sess_id: t.sess_id,
                    sm_policy_id: id.clone(),
                    supi: t.supi.clone(),
                    why,
                })
                .collect();
            me.throttled.clear();
            me.low_polls = 0;
            out
        };
        let Some(obs) = obs else {
            let since = *self.no_data_since_ms.get_or_insert(now_ms);
            if !self.throttled.is_empty() && now_ms.saturating_sub(since) >= s.fail_open_secs * 1000
            {
                return Ok(restore_all(self, "fail-open(no-ran-data)"));
            }
            return Err(Hold::NoRanData);
        };
        self.no_data_since_ms = None;

        if obs.cong_level >= s.throttle_at {
            self.low_polls = 0;
            let mut out = Vec::new();
            let mut any_candidate = false;
            for c in sessions.iter().filter_map(|c| Self::eligible(s, c)) {
                any_candidate = true;
                if self.throttled.contains_key(&c.sm_policy_id) {
                    continue;
                }
                if self.throttled.len() >= s.max_sessions {
                    break;
                }
                self.throttled.insert(
                    c.sm_policy_id.clone(),
                    Throttled {
                        sess_id: c.sess_id,
                        supi: c.supi.clone(),
                        since_ms: now_ms,
                    },
                );
                out.push(Action::Throttle {
                    sess_id: c.sess_id,
                    sm_policy_id: c.sm_policy_id.clone(),
                    supi: c.supi.clone(),
                });
            }
            return match (out.is_empty(), any_candidate, self.throttled.is_empty()) {
                (false, _, _) => Ok(out),
                (true, false, _) => Err(Hold::NoCandidate),
                (true, true, false) if self.throttled.len() >= s.max_sessions => {
                    Err(Hold::AtMaxSessions)
                }
                _ => Err(Hold::Throttled),
            };
        }

        if obs.cong_level < s.restore_below {
            if self.throttled.is_empty() {
                self.low_polls = 0;
                return Err(Hold::BelowThreshold);
            }
            self.low_polls += 1;
            let held = self
                .throttled
                .values()
                .all(|t| now_ms.saturating_sub(t.since_ms) >= s.min_hold_secs * 1000);
            if self.low_polls >= s.restore_after_polls && held {
                return Ok(restore_all(self, "below-threshold"));
            }
            return Err(Hold::Throttled);
        }

        self.low_polls = 0;
        Err(if self.throttled.is_empty() {
            Hold::WithinBand
        } else {
            Hold::Throttled
        })
    }
}

/// The candidates from the PCF's live sessions.
fn candidates() -> Vec<Candidate> {
    let all = match crate::context::pcf_self().read() {
        Ok(ctx) => ctx.sess_all(),
        Err(_) => return Vec::new(),
    };
    all.into_iter()
        .filter_map(|sess| {
            let supi = crate::sbi_path::session_supi(&sess)?;
            Some(Candidate {
                sess_id: sess.id,
                sm_policy_id: sess.sm_policy_id.clone(),
                supi,
                sst: sess.s_nssai.sst,
                dnn: sess.dnn.clone(),
                has_notification_uri: sess.notification_uri.is_some(),
            })
        })
        .collect()
}

fn observed(obs: Option<Observation>) -> String {
    match obs {
        None => "unavailable".into(),
        Some(o) => match o.confidence {
            Some(c) => format!("congLevel={} confidence={c}", o.cong_level),
            None => format!("congLevel={}", o.cong_level),
        },
    }
}

/// Carry out `action`: write or clear the cap, then notify the SMF. Returns the
/// cap installed (throttle) for the log.
pub fn execute(s: &Settings, action: &Action, obs: Option<Observation>) {
    let ctx = crate::context::pcf_self();
    match action {
        Action::Throttle {
            sess_id,
            sm_policy_id,
            supi,
        } => {
            let sess = ctx.read().ok().and_then(|c| c.sess_find_by_id(*sess_id));
            let subscribed = sess.as_ref().and_then(|sess| {
                crate::sbi_path::session_data_for_reevaluation(sess, supi, "congestion-loop")
            });
            let Some(sd) = subscribed else {
                nextgcore_demo::demo_log!(
                    warn,
                    DEMO_KEY,
                    "congestion-loop: no session data for {supi}; not throttled"
                );
                return;
            };
            let cap = Cap {
                uplink_bps: s.cap_for(sd.ambr_uplink),
                downlink_bps: s.cap_for(sd.ambr_downlink),
            };
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "congestion-loop: observed={}(ran-user-data-congestion) action=throttle(supi={supi}) \
                 sm_policy_id={sm_policy_id} ambr={}/{} bps (subscribed {}/{} bps, floor {} kbps){}",
                observed(obs),
                cap.uplink_bps,
                cap.downlink_bps,
                sd.ambr_uplink,
                sd.ambr_downlink,
                s.floor_kbps,
                if s.dry_run { " dry-run" } else { "" }
            );
            if s.dry_run {
                return;
            }
            ambr_override::set(sm_policy_id, DEMO_KEY, cap);
            crate::sbi_path::pcf_sbi_send_smpolicycontrol_update_notify(*sess_id);
        }
        Action::Restore {
            sess_id,
            sm_policy_id,
            supi,
            why,
        } => {
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "congestion-loop: observed={}(ran-user-data-congestion) action=restore(supi={supi}) \
                 sm_policy_id={sm_policy_id} reason={why}{}",
                observed(obs),
                if s.dry_run { " dry-run" } else { "" }
            );
            if s.dry_run {
                return;
            }
            if ambr_override::clear(sm_policy_id, DEMO_KEY) {
                crate::sbi_path::pcf_sbi_send_smpolicycontrol_update_notify(*sess_id);
            }
        }
    }
}

/// One USER_DATA_CONGESTION GET at the NWDAF the NRF names.
async fn observe(s: &Settings, prediction: bool) -> Option<Observation> {
    let ep = match crate::sbi_path::pcf_discover_endpoint("NWDAF", "nnwdaf-analyticsinfo").await {
        Ok(Some(ep)) => ep,
        Ok(None) => return None,
        Err(e) => {
            log::debug!("congestion-loop: NWDAF discovery failed: {e}");
            return None;
        }
    };
    let client = crate::sbi_path::client_for(&ep, nextgcore_sbi::types::NfType::Nwdaf);
    let mut request = nextgcore_sbi::message::SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics");
    for (k, v) in query(s, prediction) {
        request = request.with_param(k, v);
    }
    match client.send_request(request).await {
        Ok(resp) if resp.status == 200 => resp
            .http
            .content
            .as_deref()
            .and_then(|c| serde_json::from_str::<Value>(c).ok())
            .as_ref()
            .and_then(observation_from_body),
        Ok(resp) => {
            log::debug!(
                "congestion-loop: USER_DATA_CONGESTION status={}",
                resp.status
            );
            None
        }
        Err(e) => {
            log::debug!("congestion-loop: USER_DATA_CONGESTION GET failed: {e}");
            None
        }
    }
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Start the controller when the demo is active. `settings` is the resolved
/// `pcf.congestion_loop` block; an active demo without one fails start-up at
/// the caller.
pub fn spawn(settings: Settings, mode: &'static str) {
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "congestion-loop: on (mode={mode}; asking USER_DATA_CONGESTION {} for {} cell(s); \
         throttle at congLevel>={} to {} kbps (floor {} kbps), restore below {}; protected={:?} \
         best_effort={:?} max_sessions={}{})",
        if mode == "prediction" {
            "predictions"
        } else {
            "statistics"
        },
        settings.cells.len(),
        settings.throttle_at,
        settings.throttle_kbps.max(settings.floor_kbps),
        settings.floor_kbps,
        settings.restore_below,
        settings.protected_supis,
        settings.best_effort_supis,
        settings.max_sessions,
        if settings.dry_run { "; dry-run" } else { "" }
    );
    tokio::spawn(run(settings, mode == "prediction"));
}

async fn run(s: Settings, prediction: bool) {
    let mut controller = Controller::default();
    let mut ticker = tokio::time::interval(Duration::from_millis(s.poll_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_hold: Option<Hold> = None;
    loop {
        ticker.tick().await;
        let obs = observe(&s, prediction).await;
        match controller.step(&s, obs, &candidates(), unix_now_ms()) {
            Ok(actions) => {
                last_hold = None;
                for a in &actions {
                    execute(&s, a, obs);
                }
            }
            Err(hold) => {
                // A hold is logged when it changes, not every poll.
                if last_hold != Some(hold) {
                    nextgcore_demo::demo_log!(
                        info,
                        DEMO_KEY,
                        "congestion-loop: observed={}(ran-user-data-congestion) action={} \
                         throttled={}",
                        observed(obs),
                        hold.as_str(),
                        controller.throttled().len()
                    );
                    last_hold = Some(hold);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings::from_yaml(&LoopYaml {
            cells: Some(vec![CellYaml {
                mcc: "999".into(),
                mnc: "70".into(),
                nr_cell_id: "000000010".into(),
            }]),
            protected_supis: Some(vec!["imsi-v".into()]),
            best_effort_supis: Some(vec!["imsi-b".into()]),
            ..LoopYaml::default()
        })
        .expect("settings")
    }

    fn cand(id: u64, supi: &str) -> Candidate {
        Candidate {
            sess_id: id,
            sm_policy_id: format!("pol-{id}"),
            supi: supi.into(),
            sst: 1,
            dnn: Some("internet".into()),
            has_notification_uri: true,
        }
    }

    fn level(n: u64) -> Option<Observation> {
        Some(Observation {
            cong_level: n,
            confidence: None,
        })
    }

    /// Criterion: "UE-V is never throttled; one throttle and one restore per
    /// session". A ramp, a plateau above, a throttled plateau at 40 (between the
    /// thresholds), and the stop: exactly one throttle of UE-B and one restore,
    /// none of UE-V, and the restore waits for the hold time and three low polls.
    #[test]
    fn a_ramp_throttles_the_best_effort_ue_once_and_restores_once() {
        let s = settings();
        let sessions = [cand(1, "imsi-v"), cand(2, "imsi-b")];
        let mut c = Controller::default();
        let mut actions = Vec::new();
        let mut t = 0u64;
        let mut feed = |c: &mut Controller, lvl: u64, polls: u64, actions: &mut Vec<Action>| {
            for _ in 0..polls {
                if let Ok(a) = c.step(&s, level(lvl), &sessions, t) {
                    actions.extend(a);
                }
                t += 1000;
            }
        };
        for lvl in [20, 40, 60, 79] {
            feed(&mut c, lvl, 1, &mut actions);
        }
        assert!(actions.is_empty(), "no throttle below throttle_at");
        feed(&mut c, 96, 5, &mut actions);
        feed(&mut c, 40, 30, &mut actions); // throttled: UE-V 1 Mbps + UE-B 1 Mbps of 5
        feed(&mut c, 20, 2, &mut actions);
        assert_eq!(actions.len(), 1, "{actions:?}");
        feed(&mut c, 20, 5, &mut actions);
        assert_eq!(
            actions,
            vec![
                Action::Throttle {
                    sess_id: 2,
                    sm_policy_id: "pol-2".into(),
                    supi: "imsi-b".into()
                },
                Action::Restore {
                    sess_id: 2,
                    sm_policy_id: "pol-2".into(),
                    supi: "imsi-b".into(),
                    why: "below-threshold"
                },
            ]
        );
    }

    /// The restore waits for `min_hold_secs` even when the level falls at once.
    #[test]
    fn a_restore_waits_for_the_hold_time() {
        let s = settings();
        let sessions = [cand(2, "imsi-b")];
        let mut c = Controller::default();
        assert!(c.step(&s, level(90), &sessions, 0).is_ok());
        for t in 1..9 {
            assert_eq!(
                c.step(&s, level(5), &sessions, t * 1000),
                Err(Hold::Throttled),
                "t={t}s"
            );
        }
        assert!(matches!(
            c.step(&s, level(5), &sessions, 10_000).as_deref(),
            Ok([Action::Restore { .. }])
        ));
    }

    /// No data while throttled: hold, then fail open after `fail_open_secs`.
    #[test]
    fn no_data_holds_then_fails_open() {
        let s = settings();
        let sessions = [cand(2, "imsi-b")];
        let mut c = Controller::default();
        assert_eq!(c.step(&s, None, &sessions, 0), Err(Hold::NoRanData));
        assert!(c.step(&s, level(90), &sessions, 1000).is_ok());
        assert_eq!(c.step(&s, None, &sessions, 2000), Err(Hold::NoRanData));
        assert!(matches!(
            c.step(&s, None, &sessions, 32_000).as_deref(),
            Ok([Action::Restore {
                why: "fail-open(no-ran-data)",
                ..
            }])
        ));
    }

    /// Guardrails: slice, DNN, protected, best-effort list, notification URI and
    /// max_sessions.
    #[test]
    fn the_guardrails_choose_the_sessions() {
        let mut s = settings();
        s.best_effort_supis.clear();
        s.sst = Some(1);
        s.dnn = Some("internet".into());
        s.max_sessions = 2;
        let mut other_slice = cand(3, "imsi-c");
        other_slice.sst = 2;
        let mut other_dnn = cand(4, "imsi-d");
        other_dnn.dnn = Some("ims".into());
        let mut no_uri = cand(5, "imsi-e");
        no_uri.has_notification_uri = false;
        let sessions = [
            cand(1, "imsi-v"),
            other_slice,
            other_dnn,
            no_uri,
            cand(6, "imsi-f"),
            cand(7, "imsi-g"),
            cand(8, "imsi-h"),
        ];
        let mut c = Controller::default();
        let got = c.step(&s, level(99), &sessions, 0).expect("throttles");
        let supis: Vec<&str> = got
            .iter()
            .map(|a| match a {
                Action::Throttle { supi, .. } => supi.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(supis, ["imsi-f", "imsi-g"], "max_sessions 2, guardrails");
        assert_eq!(
            c.step(&s, level(99), &sessions, 1000),
            Err(Hold::AtMaxSessions)
        );
    }

    #[test]
    fn the_cap_respects_floor_and_subscription() {
        let mut s = settings();
        assert_eq!(s.cap_for(22_000_000), 1_000_000);
        assert_eq!(s.cap_for(800_000), 800_000, "never above subscribed");
        s.throttle_kbps = 100;
        assert_eq!(s.cap_for(22_000_000), 500_000, "never below the floor");
    }

    #[test]
    fn the_block_is_strict() {
        let root = |y: &str| serde_yaml::from_str::<serde_yaml::Value>(y).unwrap();
        assert_eq!(settings_from_root(&root("pcf: {}")), Ok(None));
        assert!(settings_from_root(&root("pcf: {congestion_loop: {}}")).is_err());
        assert!(settings_from_root(&root(
            "pcf: {congestion_loop: {cells: [{mcc: '999', mnc: '70', nr_cell_id: '000000010'}], bogus: 1}}"
        ))
        .is_err());
        assert!(settings_from_root(&root(
            "pcf: {congestion_loop: {cells: [{mcc: '999', mnc: '70', nr_cell_id: '000000010'}], throttle_at: 30, restore_below: 40}}"
        ))
        .is_err());
        let s = settings_from_root(&root(
            "pcf: {congestion_loop: {cells: [{mcc: '999', mnc: '70', nr_cell_id: '00000001a'}]}}",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(s.cells[0].nr_cell_id, "00000001A");
        assert_eq!((s.floor_kbps, s.throttle_kbps), (500, 1000), "defaults");
    }

    #[test]
    fn the_query_and_the_answer() {
        let s = settings();
        let q = query(&s, false);
        assert_eq!(q[0], ("event-id", "USER_DATA_CONGESTION".to_string()));
        assert!(q.iter().all(|(k, _)| *k != "ana-req"));
        let f: Value = serde_json::from_str(&q[2].1).unwrap();
        assert_eq!(f["networkArea"]["ncgis"][0]["nrCellId"], "000000010");
        let p = query(&s, true);
        assert_eq!(p[3].0, "ana-req");
        let body = json!({"userDataCongInfos": [
            {"networkArea": {}, "congestionInfo": {"nsi": {"congLevel": 40}}},
            {"networkArea": {}, "congestionInfo": {"nsi": {"congLevel": 96}, "confidence": 80}},
        ]});
        assert_eq!(
            observation_from_body(&body),
            Some(Observation {
                cong_level: 96,
                confidence: Some(80)
            })
        );
        assert_eq!(observation_from_body(&json!({})), None);
    }
}
