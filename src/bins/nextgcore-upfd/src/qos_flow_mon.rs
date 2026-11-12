//! Per QoS flow per UE QoS monitoring for packet delay (TS 29.244 §5.24.4,
//! QFQM), #1389 part 3.
//!
//! The SMF provisions an SRR with QoS Monitoring per QoS flow Control
//! Information IEs (IE 242, Table 7.5.2.9-3) in a PFCP Session Establishment or
//! Modification (§5.39.2). For each monitored QoS flow this PSA UPF
//! (§5.24.4.3, TS 23.501 §5.33.3.2):
//! - sets QMP and a DL Sending Time Stamp (T1) in the DL PDU Session Container
//!   (TS 38.415 §5.5.2.1) of a downlink G-PDU of that flow, or sends a dummy
//!   G-PDU (no T-PDU, TS 29.281 §5.2.2.7) when the flow carries no traffic;
//! - takes T4 when the NG-RAN's UL PDU Session Container (§5.5.2.2) comes back
//!   with T1 repeated, T2 and T3, and the RAN part of the DL/UL delay;
//! - computes the UPF to UE DL, UL and round-trip delays (TS 23.501 §5.33.3.2)
//!   and reports them in QoS Monitoring Report IEs (IE 247) in a PFCP Session
//!   Report Request: on a threshold (Event Triggered, with the Minimum Wait
//!   Time), at the end of each Measurement Period (Periodic), as a packet delay
//!   measurement failure when no answer came for a Measurement Period, and once
//!   more when the SMF stops the monitoring.
//!
//! Off unless `--qos-flow-monitoring` is set: only then is QFQM advertised and
//! an SRR acted on, so with the flag off no G-PDU changes.
//!
//! Delay arithmetic (TS 23.501 §5.33.3.2):
//! - N3 part, clocks NOT synchronised (the default): DL = UL = (T2-T1+T4-T3)/2.
//! - N3 part, clocks synchronised (`--qos-flow-monitoring-clock-synced`):
//!   DL = T2-T1, UL = T4-T3.
//! - UE to PSA: the N3 part plus the RAN part the NG-RAN returned (DL/UL Delay
//!   Result, ms, §5.5.3.14/16); round trip = DL + UL.
//!
//! Limitations, stated honestly:
//! - Only packet delay via RAN and UPF time stamps (GTPUPM = 0) is measured. A
//!   control asking for GTP-U path based delay (GTPUPM = 1, which needs an
//!   I-UPF), congestion, data rate or available bitrate is not acted on: those
//!   are other features (QMCON, QMDRM, ...), not advertised here.
//! - A RAN that returns no Delay Result contributes 0 ms for its part, so the
//!   reported delay is then the N3 part only.
//! - Direct reporting to a Local NEF or AF (DRQOS) is not supported; every
//!   report goes to the SMF.

use nextgcore_pfcp::qos_monitoring::{
    PacketDelayThresholds, QosMonitoringMeasurement, QosMonitoringPerQosFlowControlInformation,
    QosMonitoringReport,
};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime};

/// At most this many SRRs per session, controls per SRR and QFIs per control
/// are kept (the rest are ignored and logged): bounded state per session.
pub const MAX_SRRS: usize = 16;
pub const MAX_CONTROLS_PER_SRR: usize = 16;
pub const MAX_QFIS_PER_CONTROL: usize = 64;

/// Outstanding QMP probes kept per flow; an older one is forgotten.
const MAX_OUTSTANDING: usize = 8;

/// A probe unanswered after this long is forgotten.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Seconds from the NTP prime epoch (1900) to the Unix epoch (RFC 5905 §6).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// `t` as an RFC 5905 §6 64-bit NTP timestamp (32 bits of seconds, 32 of
/// fraction): the format of every TS 38.415 QoS monitoring time stamp.
pub fn ntp64(t: SystemTime) -> u64 {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = (d.as_secs() + NTP_UNIX_OFFSET) & 0xffff_ffff;
    let frac = (u64::from(d.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// `later - earlier` of two 64-bit NTP timestamps, in microseconds (negative
/// when `later` is earlier). Wrapping, so an era rollover between them is fine.
pub fn ntp_diff_us(later: u64, earlier: u64) -> i64 {
    let d = later.wrapping_sub(earlier) as i64 as i128;
    ((d * 1_000_000) >> 32) as i64
}

/// Whole milliseconds, rounded up (never under-reported); negative is 0.
fn ms_ceil(us: i64) -> u32 {
    if us <= 0 {
        return 0;
    }
    (us as u64).div_ceil(1000).min(u32::MAX as u64) as u32
}

/// One NG-RAN answer to a QMP probe: the four TS 23.501 §5.33.3.2 times and the
/// RAN part of the delay, if the NG-RAN stated it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QmpAnswer {
    pub t1: u64,
    pub t2: u64,
    pub t3: u64,
    pub t4: u64,
    pub dl_ran_ms: Option<u32>,
    pub ul_ran_ms: Option<u32>,
}

/// The UPF to UE packet delays of one answer, milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Delays {
    pub dl: u32,
    pub ul: u32,
    pub rp: u32,
}

impl QmpAnswer {
    /// The DL, UL and round-trip delay between the UPF and the UE (TS 23.501
    /// §5.33.3.2), with the N3 part taken per `clock_synced`.
    pub fn delays(&self, clock_synced: bool) -> Delays {
        let dl_n3 = ntp_diff_us(self.t2, self.t1);
        let ul_n3 = ntp_diff_us(self.t4, self.t3);
        // The N3 round trip (T2-T1)+(T4-T3) is free of any clock offset: taken
        // raw, so a skewed clock that clamps one direction does not inflate it.
        let rtt_n3 = (dl_n3 + ul_n3).max(0);
        let (dl_n3, ul_n3) = if clock_synced {
            (dl_n3.max(0), ul_n3.max(0))
        } else {
            // (T2-T1+T4-T3)/2: the clock offset cancels in the sum.
            let half = rtt_n3 / 2;
            (half, half)
        };
        let dl_ran = self.dl_ran_ms.unwrap_or(0);
        let ul_ran = self.ul_ran_ms.unwrap_or(0);
        Delays {
            dl: ms_ceil(dl_n3).saturating_add(dl_ran),
            ul: ms_ceil(ul_n3).saturating_add(ul_ran),
            rp: ms_ceil(rtt_n3)
                .saturating_add(dl_ran)
                .saturating_add(ul_ran),
        }
    }
}

/// One QoS Monitoring per QoS flow Control Information, as acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowControl {
    pub qfis: Vec<u8>,
    pub dl: bool,
    pub ul: bool,
    pub rp: bool,
    pub event: bool,
    pub periodic: bool,
    pub thresholds: PacketDelayThresholds,
    pub min_wait: Duration,
    pub period: Option<Duration>,
}

impl FlowControl {
    /// The control this UPF acts on, or `None` (logged) when it asks for nothing
    /// this UPF measures: no packet delay, or GTP-U path based delay (GTPUPM).
    pub fn from_ie(ie: &QosMonitoringPerQosFlowControlInformation) -> Option<Self> {
        let r = ie.requested_qos_monitoring;
        if r.gtpupm {
            log::warn!(
                "QoS Monitoring per QoS flow Control Information for QFI(s) {:?} asks for \
                 GTP-U path based delay (GTPUPM): not supported, not monitored",
                ie.qfis
            );
            return None;
        }
        if !(r.dlpd || r.ulpd || r.rppd) {
            log::warn!(
                "QoS Monitoring per QoS flow Control Information for QFI(s) {:?} requests no \
                 packet delay (only congestion, data rate or available bitrate, which are \
                 not supported): not monitored",
                ie.qfis
            );
            return None;
        }
        let f = ie.reporting_frequency;
        if !(f.evett || f.perio) {
            log::warn!(
                "QoS Monitoring per QoS flow Control Information for QFI(s) {:?} has neither \
                 Event Triggered nor Periodic reporting: not monitored",
                ie.qfis
            );
            return None;
        }
        let mut qfis: Vec<u8> = Vec::new();
        for q in &ie.qfis {
            if !qfis.contains(q) {
                qfis.push(*q);
            }
        }
        if qfis.len() > MAX_QFIS_PER_CONTROL {
            log::warn!(
                "QoS Monitoring per QoS flow Control Information names {} QFIs: only the \
                 first {MAX_QFIS_PER_CONTROL} are monitored",
                qfis.len()
            );
            qfis.truncate(MAX_QFIS_PER_CONTROL);
        }
        Some(Self {
            qfis,
            dl: r.dlpd,
            ul: r.ulpd,
            rp: r.rppd,
            event: f.evett,
            periodic: f.perio,
            thresholds: ie.packet_delay_thresholds.unwrap_or_default(),
            min_wait: Duration::from_secs(ie.minimum_wait_time.unwrap_or(0) as u64),
            period: ie
                .measurement_period
                .filter(|p| *p > 0)
                .map(|p| Duration::from_secs(p as u64)),
        })
    }

    /// Whether `d` matches or exceeds a threshold of a parameter this control
    /// requests (§5.39.2: "matches or exceeds").
    fn exceeds(&self, d: &Delays) -> bool {
        let t = &self.thresholds;
        (self.dl && t.downlink.is_some_and(|x| d.dl >= x))
            || (self.ul && t.uplink.is_some_and(|x| d.ul >= x))
            || (self.rp && t.round_trip.is_some_and(|x| d.rp >= x))
    }

    fn measurement(&self, d: &Delays) -> QosMonitoringMeasurement {
        QosMonitoringMeasurement {
            downlink_packet_delay: self.dl.then_some(d.dl),
            uplink_packet_delay: self.ul.then_some(d.ul),
            round_trip_packet_delay: self.rp.then_some(d.rp),
            ..Default::default()
        }
    }

    fn same_measurement(&self, other: &Self) -> bool {
        (self.dl, self.ul, self.rp) == (other.dl, other.ul, other.rp)
    }
}

/// The reporting state of one control for one QFI.
#[derive(Debug, Clone)]
struct FlowState {
    /// The most recent measurement, and when it was taken.
    last: Option<(Delays, Instant)>,
    /// The sums of the current Measurement Period (Periodic reporting).
    sum: (u64, u64, u64),
    count: u32,
    period_start: Instant,
    period_start_wall: SystemTime,
    /// When the last threshold report went out (Minimum Wait Time).
    last_event_report: Option<Instant>,
    /// A measurement that matched a threshold during the Minimum Wait Time:
    /// reported when the wait is over (§5.39.2).
    pending_event: Option<Delays>,
    /// Since when no answer came (the start, or the last answer).
    silent_since: Instant,
    /// A measurement failure was reported for the current silence.
    failure_reported: bool,
}

impl FlowState {
    fn new(now: Instant, wall: SystemTime) -> Self {
        Self {
            last: None,
            sum: (0, 0, 0),
            count: 0,
            period_start: now,
            period_start_wall: wall,
            last_event_report: None,
            pending_event: None,
            silent_since: now,
            failure_reported: false,
        }
    }

    fn average(&self) -> Option<Delays> {
        let n = self.count as u64;
        (n > 0).then(|| Delays {
            dl: (self.sum.0 / n) as u32,
            ul: (self.sum.1 / n) as u32,
            rp: (self.sum.2 / n) as u32,
        })
    }
}

#[derive(Debug, Clone)]
struct Control {
    cfg: FlowControl,
    flows: HashMap<u8, FlowState>,
}

impl Control {
    fn new(cfg: FlowControl, now: Instant, wall: SystemTime) -> Self {
        let flows = cfg
            .qfis
            .iter()
            .map(|q| (*q, FlowState::new(now, wall)))
            .collect();
        Self { cfg, flows }
    }
}

/// The QMP probes of one monitored QoS flow.
#[derive(Debug, Clone, Default)]
struct Probe {
    /// The next downlink G-PDU of the flow carries a QMP.
    due: bool,
    /// T1 of each QMP sent, with when it was sent.
    outstanding: VecDeque<(u64, Instant)>,
    /// A downlink G-PDU of the flow went out since the last round.
    dl_seen: bool,
}

#[derive(Debug, Clone, Default)]
struct SessionMon {
    /// SRR ID -> its controls.
    srrs: Vec<(u8, Vec<Control>)>,
    probes: HashMap<u8, Probe>,
}

impl SessionMon {
    /// A T1 for `wall` that no outstanding probe of this session holds, so an
    /// answer names exactly one probe even when two go out in the same instant.
    /// Unique per session only, never forced ahead of the clock: after a clock
    /// step back, T1 is the clock again (#1451 review m3).
    fn fresh_t1(&self, wall: SystemTime) -> u64 {
        let mut t1 = ntp64(wall);
        while self
            .probes
            .values()
            .any(|p| p.outstanding.iter().any(|(t, _)| *t == t1))
        {
            t1 = t1.wrapping_add(1);
        }
        t1
    }

    fn monitored_qfis(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for (_, ctls) in &self.srrs {
            for c in ctls {
                for q in &c.cfg.qfis {
                    if !out.contains(q) {
                        out.push(*q);
                    }
                }
            }
        }
        out
    }

    /// Keep one probe state per monitored QFI, and only those.
    fn sync_probes(&mut self) {
        let qfis = self.monitored_qfis();
        self.probes.retain(|q, _| qfis.contains(q));
        for q in qfis {
            self.probes.entry(q).or_default();
        }
    }
}

/// A QoS Monitoring Report for one SRR of one session.
pub type SrrReport = (u8, QosMonitoringReport);

/// A dummy downlink G-PDU to send: session, QFI and its T1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DummyProbe {
    pub upf_seid: u64,
    pub qfi: u8,
    pub t1: u64,
}

/// What a monitoring round produced.
#[derive(Debug, Default)]
pub struct Round {
    pub dummies: Vec<DummyProbe>,
    pub reports: Vec<(u64, Vec<SrrReport>)>,
}

/// The per QoS flow monitor of every session.
#[derive(Debug, Default)]
pub struct QosFlowMonitor {
    sessions: HashMap<u64, SessionMon>,
    clock_synced: bool,
}

/// Decode the controls of one SRR, keeping those this UPF acts on.
pub fn controls_of(ies: &[QosMonitoringPerQosFlowControlInformation]) -> Vec<FlowControl> {
    let mut out: Vec<FlowControl> = ies.iter().filter_map(FlowControl::from_ie).collect();
    if out.len() > MAX_CONTROLS_PER_SRR {
        log::warn!(
            "{} QoS Monitoring per QoS flow Control Information IEs in one SRR: only the \
             first {MAX_CONTROLS_PER_SRR} are used",
            out.len()
        );
        out.truncate(MAX_CONTROLS_PER_SRR);
    }
    out
}

fn report(
    qfi: u8,
    m: QosMonitoringMeasurement,
    wall: SystemTime,
    start: Option<SystemTime>,
) -> QosMonitoringReport {
    QosMonitoringReport {
        qfi,
        qos_monitoring_measurement: m,
        time_stamp: crate::data_plane::ntp_secs(wall),
        start_time: start.map(crate::data_plane::ntp_secs),
        extra: Vec::new(),
    }
}

impl QosFlowMonitor {
    /// `clock_synced`: the NG-RAN and this UPF are time synchronised, so the
    /// one-way N3 delays are T2-T1 and T4-T3 (TS 23.501 §5.33.3.2).
    pub fn new(clock_synced: bool) -> Self {
        Self {
            sessions: HashMap::new(),
            clock_synced,
        }
    }

    pub fn is_active(&self) -> bool {
        !self.sessions.is_empty()
    }

    /// The QFIs monitored on `upf_seid` (sorted), for tests and logs.
    pub fn monitored_qfis(&self, upf_seid: u64) -> Vec<u8> {
        let mut v = self
            .sessions
            .get(&upf_seid)
            .map(|s| s.monitored_qfis())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }

    /// The SRR IDs monitored on `upf_seid` (sorted).
    pub fn srr_ids(&self, upf_seid: u64) -> Vec<u8> {
        let mut v: Vec<u8> = self
            .sessions
            .get(&upf_seid)
            .map(|s| s.srrs.iter().map(|(id, _)| *id).collect())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }

    fn drop_if_idle(&mut self, upf_seid: u64) {
        if self
            .sessions
            .get(&upf_seid)
            .is_some_and(|s| s.srrs.is_empty())
        {
            self.sessions.remove(&upf_seid);
        }
    }

    /// Create (or, for an SRR ID already held, replace) an SRR's controls.
    /// An SRR with no control this UPF acts on is not kept.
    pub fn create_srr(
        &mut self,
        upf_seid: u64,
        srr_id: u8,
        controls: Vec<FlowControl>,
        now: Instant,
        wall: SystemTime,
    ) {
        let sess = self.sessions.entry(upf_seid).or_default();
        sess.srrs.retain(|(id, _)| *id != srr_id);
        if !controls.is_empty() {
            if sess.srrs.len() >= MAX_SRRS {
                log::warn!(
                    "SEID {upf_seid:#x}: SRR {srr_id} not monitored, the session already has \
                     {MAX_SRRS} QoS monitoring SRRs"
                );
            } else {
                let ctls = controls
                    .into_iter()
                    .map(|c| Control::new(c, now, wall))
                    .collect();
                sess.srrs.push((srr_id, ctls));
            }
        }
        sess.sync_probes();
        self.drop_if_idle(upf_seid);
    }

    /// Update SRR (§5.39.2): the new list of controls replaces the old one. A
    /// control that measures the same parameters of a QFI keeps its ongoing
    /// measurement, which is judged against the new thresholds (§5.24.4.3);
    /// what is no longer monitored is reported once more (the stop report).
    pub fn update_srr(
        &mut self,
        upf_seid: u64,
        srr_id: u8,
        controls: Vec<FlowControl>,
        now: Instant,
        wall: SystemTime,
    ) -> Vec<SrrReport> {
        let old = self
            .sessions
            .get_mut(&upf_seid)
            .and_then(|s| {
                let i = s.srrs.iter().position(|(id, _)| *id == srr_id)?;
                Some(s.srrs.remove(i).1)
            })
            .unwrap_or_default();
        let mut new: Vec<Control> = controls
            .into_iter()
            .map(|c| Control::new(c, now, wall))
            .collect();
        let mut carried: Vec<(usize, u8)> = Vec::new();
        for c in new.iter_mut() {
            for (q, st) in c.flows.iter_mut() {
                let prior = old.iter().enumerate().find_map(|(i, o)| {
                    (o.cfg.same_measurement(&c.cfg) && !carried.contains(&(i, *q)))
                        .then(|| o.flows.get(q).map(|s| (i, s.clone())))
                        .flatten()
                });
                if let Some((i, s)) = prior {
                    carried.push((i, *q));
                    *st = s;
                    // The ongoing measurement against the new threshold.
                    if c.cfg.event {
                        if let Some((d, _)) = st.last {
                            if c.cfg.exceeds(&d) {
                                st.pending_event = Some(d);
                            }
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        for (i, o) in old.iter().enumerate() {
            for (q, st) in &o.flows {
                if !carried.contains(&(i, *q)) {
                    if let Some((d, _)) = st.last {
                        out.push((srr_id, report(*q, o.cfg.measurement(&d), wall, None)));
                    }
                }
            }
        }
        if !new.is_empty() {
            let sess = self.sessions.entry(upf_seid).or_default();
            sess.srrs.push((srr_id, new));
        }
        if let Some(s) = self.sessions.get_mut(&upf_seid) {
            s.sync_probes();
        }
        self.drop_if_idle(upf_seid);
        out
    }

    /// Remove SRR: monitoring stops, and what was measured is reported
    /// (§5.24.4.3: "When receiving instruction from the SMF to stop ...").
    pub fn remove_srr(&mut self, upf_seid: u64, srr_id: u8, wall: SystemTime) -> Vec<SrrReport> {
        let Some(sess) = self.sessions.get_mut(&upf_seid) else {
            return Vec::new();
        };
        let Some(i) = sess.srrs.iter().position(|(id, _)| *id == srr_id) else {
            return Vec::new();
        };
        let (_, ctls) = sess.srrs.remove(i);
        sess.sync_probes();
        self.drop_if_idle(upf_seid);
        let mut out = Vec::new();
        for c in &ctls {
            for (q, st) in &c.flows {
                if let Some((d, _)) = st.last {
                    out.push((srr_id, report(*q, c.cfg.measurement(&d), wall, None)));
                }
            }
        }
        out
    }

    /// The association is gone: every session's monitoring is dropped.
    pub fn clear(&mut self) {
        self.sessions.clear();
    }

    /// The session is gone: everything about it is dropped.
    pub fn remove_session(&mut self, upf_seid: u64) {
        self.sessions.remove(&upf_seid);
    }

    /// A downlink G-PDU of `qfi` on `upf_seid` is about to go out at `now`:
    /// the T1 to stamp in it when a QMP is due, else `None`.
    pub fn on_downlink(
        &mut self,
        upf_seid: u64,
        qfi: u8,
        now: Instant,
        wall: SystemTime,
    ) -> Option<u64> {
        let sess = self.sessions.get_mut(&upf_seid)?;
        let p = sess.probes.get_mut(&qfi)?;
        p.dl_seen = true;
        if !p.due {
            return None;
        }
        p.due = false;
        let t1 = sess.fresh_t1(wall);
        push_outstanding(sess.probes.get_mut(&qfi)?, t1, now);
        Some(t1)
    }

    /// A UL PDU Session Container with QMP arrived on `upf_seid`. Returns `None`
    /// when it answers no probe of this session (stale, duplicate or forged);
    /// else the reports the measurement triggers (Event Triggered).
    pub fn on_answer(
        &mut self,
        upf_seid: u64,
        answer: &QmpAnswer,
        now: Instant,
        wall: SystemTime,
    ) -> Option<(u8, Delays, Vec<SrrReport>)> {
        let clock_synced = self.clock_synced;
        let sess = self.sessions.get_mut(&upf_seid)?;
        // The flow is the one the T1 was sent on: the NG-RAN may answer on the
        // session's default UL QoS flow, whatever flow the probe was for.
        let qfi = sess.probes.iter_mut().find_map(|(q, p)| {
            let i = p.outstanding.iter().position(|(t1, _)| *t1 == answer.t1)?;
            p.outstanding.remove(i);
            Some(*q)
        })?;
        let d = answer.delays(clock_synced);
        let mut out = Vec::new();
        for (srr_id, ctls) in sess.srrs.iter_mut() {
            for c in ctls.iter_mut() {
                let Some(st) = c.flows.get_mut(&qfi) else {
                    continue;
                };
                st.last = Some((d, now));
                st.sum.0 += d.dl as u64;
                st.sum.1 += d.ul as u64;
                st.sum.2 += d.rp as u64;
                st.count += 1;
                st.silent_since = now;
                st.failure_reported = false;
                if c.cfg.event && c.cfg.exceeds(&d) {
                    let waited = st
                        .last_event_report
                        .is_none_or(|t| now.saturating_duration_since(t) >= c.cfg.min_wait);
                    if waited {
                        st.last_event_report = Some(now);
                        st.pending_event = None;
                        out.push((*srr_id, report(qfi, c.cfg.measurement(&d), wall, None)));
                    } else {
                        st.pending_event = Some(d);
                    }
                }
            }
        }
        Some((qfi, d, out))
    }

    /// One monitoring round at `now`: the dummy G-PDUs to send for flows that
    /// carried no downlink traffic, and the reports due (Periodic, a threshold
    /// report held back by the Minimum Wait Time, a measurement failure).
    pub fn round(&mut self, now: Instant, wall: SystemTime) -> Round {
        let mut out = Round::default();
        for (seid, sess) in self.sessions.iter_mut() {
            let mut qfis: Vec<u8> = sess.probes.keys().copied().collect();
            qfis.sort_unstable();
            for q in qfis {
                let t1 = sess.fresh_t1(wall);
                let p = sess.probes.get_mut(&q).expect("listed above");
                p.outstanding
                    .retain(|(_, sent)| now.saturating_duration_since(*sent) < PROBE_TIMEOUT);
                // A QMP is due every round. It rides on the flow's next downlink
                // packet when the flow carried traffic since the last round; with
                // none, or when the last round's QMP found no packet, it goes out
                // at once in a dummy G-PDU (§5.24.4.3).
                let recent = std::mem::take(&mut p.dl_seen);
                if p.due || !recent {
                    p.due = false;
                    push_outstanding(p, t1, now);
                    out.dummies.push(DummyProbe {
                        upf_seid: *seid,
                        qfi: q,
                        t1,
                    });
                } else {
                    p.due = true;
                }
            }
            let mut reports = Vec::new();
            for (srr_id, ctls) in sess.srrs.iter_mut() {
                for c in ctls.iter_mut() {
                    let mut qfis: Vec<u8> = c.flows.keys().copied().collect();
                    qfis.sort_unstable();
                    for q in qfis {
                        let st = c.flows.get_mut(&q).expect("listed above");
                        if c.cfg.event {
                            if let Some(d) = st.pending_event {
                                let waited = st.last_event_report.is_none_or(|t| {
                                    now.saturating_duration_since(t) >= c.cfg.min_wait
                                });
                                if waited {
                                    st.pending_event = None;
                                    st.last_event_report = Some(now);
                                    reports.push((
                                        *srr_id,
                                        report(q, c.cfg.measurement(&d), wall, None),
                                    ));
                                }
                            }
                        }
                        let Some(period) = c.cfg.period else {
                            continue;
                        };
                        if c.cfg.periodic
                            && now.saturating_duration_since(st.period_start) >= period
                        {
                            let start = st.period_start_wall;
                            let m = match st.average() {
                                Some(avg) => c.cfg.measurement(&avg),
                                None => failure(),
                            };
                            reports.push((*srr_id, report(q, m, wall, Some(start))));
                            if st.count == 0 {
                                st.failure_reported = true;
                            }
                            st.sum = (0, 0, 0);
                            st.count = 0;
                            // Anchored, not reset to `now`: the round's
                            // scheduling jitter must not push the next report a
                            // whole probe interval late (#1451 review M1, as
                            // #772 for URRs). After a stall, catch up to the
                            // period containing `now`.
                            while now.saturating_duration_since(st.period_start) >= period {
                                st.period_start += period;
                                st.period_start_wall += period;
                            }
                        } else if !c.cfg.periodic
                            && !st.failure_reported
                            && now.saturating_duration_since(st.silent_since) > period
                        {
                            // Event Triggered with no answer for a Measurement
                            // Period: a packet delay measurement failure.
                            st.failure_reported = true;
                            reports.push((*srr_id, report(q, failure(), wall, None)));
                        }
                    }
                }
            }
            if !reports.is_empty() {
                out.reports.push((*seid, reports));
            }
        }
        out.reports.sort_by_key(|(s, _)| *s);
        out
    }
}

/// PLMF: no time stamp came back for a Measurement Period (§5.24.4.3); the
/// delay fields are absent with it (§8.2.171).
fn failure() -> QosMonitoringMeasurement {
    QosMonitoringMeasurement {
        packet_delay_measurement_failure: true,
        ..Default::default()
    }
}

fn push_outstanding(p: &mut Probe, t1: u64, now: Instant) {
    if p.outstanding.len() == MAX_OUTSTANDING {
        p.outstanding.pop_front();
    }
    p.outstanding.push_back((t1, now));
}

#[cfg(test)]
#[path = "qos_flow_mon_tests.rs"]
mod tests;
