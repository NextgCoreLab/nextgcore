//! N6 delay measurement and reporting (TS 29.244 §5.33.8, UN6DM), #1389 part 2.
//!
//! Stage 2 (TS 23.501 §5.8.2.23): the SMF has candidate PSA UPFs measure the
//! N6 delay towards the application side (EAS IP addresses), and uses the
//! result for PSA UPF (re)selection or EAS (re)discovery (TS 23.548 §6.2.3.2).
//!
//! The SMF provisions N6 Delay Measurement Control Information (IE 355,
//! Table 7.4.4.1.4-1) in a PFCP Association Setup or Update Request
//! (§5.33.8.2). For each measurement endpoint it names, this UPF:
//! - acts as a STAMP Session-Sender (IETF RFC 8762, §5.33.8.3) towards the
//!   endpoint's Session-Reflector, port 862 unless the Protocol Specific
//!   Configuration Parameters (IE 378) give another;
//! - takes the one-way delay as half the round trip, less the reflector's own
//!   turnaround (T3 - T2), as the §5.33.8.3 NOTE allows;
//! - reports in a PFCP Node Report Request (N6DR, N6 Delay Measurement Report
//!   IE 356, Table 7.4.5.1.8-1): immediately (IRE), every measurement period
//!   (PER) and/or when the average, minimum or maximum delay matches or exceeds
//!   its threshold (EVT), at most once per minimum waiting time per kind and
//!   endpoint, with a report deferred to the end of the wait when a threshold
//!   was hit during it;
//! - reports a failure (N6 Delay Measurement Failure Information, IE 376) when
//!   the endpoint does not answer, keeps retrying with a growing period, and
//!   reports again as soon as a measurement succeeds.
//!
//! OFF unless `--n6-delay-measurement` is set: only then is UN6DM advertised
//! (which grows the UP Function Features IE to 10 octets, §8.2.25) and IE 355
//! acted on.
//!
//! Limitations, stated honestly:
//! - **Departure from TS 33.501 clause T.5.** Only the unauthenticated mode of
//!   STAMP is implemented. T.5 says a measurement protocol should not be used
//!   without authentication, integrity and anti-replay protection. When the SMF
//!   asks for integrity or confidentiality protection (Security Mode (STAMP)
//!   INTP or CONP set, IE 390, or an HMAC Key, IE 391), this UPF does not
//!   probe and reports a failure (cause Unspecified) instead.
//! - TWAMP and OWAMP are not implemented. An endpoint that offers neither
//!   STAMP is reported as a failure (cause Unspecified) and not probed.
//! - The probes leave through the host routing table. The provisioned Network
//!   Instance is echoed in the reports but does not select an interface.
//! - With no Minimum Waiting Time provisioned, the locally configured one is
//!   [`DEFAULT_MIN_WAIT`] (§5.33.8.2 NOTE). With no threshold provisioned, no
//!   event-triggered report is sent.

use nextgcore_pfcp::qos_monitoring::{
    MeasurementEndpointAddress, MeasurementReportingType, N6DelayMeasurementControlInformation,
    N6DelayMeasurementFailureInformation, N6DelayMeasurementInformation,
    N6DelayMeasurementProtocols, N6DelayMeasurementReport, TypedIe,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

/// The STAMP well-known UDP port (IETF RFC 8762 §4.1).
pub const STAMP_PORT: u16 = 862;
/// Length of an unauthenticated STAMP test packet, sent and reflected (RFC 8762
/// §4.2.1, §4.3.1).
pub const STAMP_LEN: usize = 44;

/// At most this many control instances, and this many endpoints per instance:
/// the SMF is an authenticated association, but the UPF should not probe an
/// unbounded host list.
pub const MAX_CONTROLS: usize = 16;
pub const MAX_ENDPOINTS_PER_CONTROL: usize = 64;

/// A probe unanswered after this long is a miss.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Consecutive misses that make an endpoint "cannot be measured" (§5.33.8.3).
pub const FAIL_AFTER: u32 = 3;
/// The retry period of a failed endpoint doubles after each failed attempt, up
/// to this (§5.33.8.3: "e.g. by increasing the period after each failed
/// attempt").
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// The local Minimum Waiting Time when the SMF provisions none (§5.33.8.2 NOTE).
pub const DEFAULT_MIN_WAIT: Duration = Duration::from_secs(5);
/// Samples the event-triggered judgement of the average and minimum covers.
pub const EVT_SAMPLES: usize = 10;

/// Security Mode (STAMP), IE 390 (§8.2.273), and HMAC Key (STAMP), IE 391
/// (§8.2.274): members of the Protocol Specific Configuration Parameters.
const IE_SECURITY_MODE_STAMP: u16 = 390;
const IE_HMAC_KEY_STAMP: u16 = 391;

/// One provisioned N6 Delay Measurement Control Information instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N6Control {
    pub id: u16,
    pub endpoints: Vec<IpAddr>,
    pub network_instance: Vec<u8>,
    /// The Session-Reflector port, and whether the SMF provisioned it.
    pub port: u16,
    pub port_provisioned: bool,
    /// The failure cause to report when this UPF cannot measure these
    /// endpoints as asked (no common protocol, or security it cannot give).
    pub cannot_measure: Option<u8>,
    pub reporting: MeasurementReportingType,
    pub period: Option<Duration>,
    pub avg_threshold_ms: Option<u32>,
    pub min_threshold_ms: Option<u32>,
    pub max_threshold_ms: Option<u32>,
    pub min_wait: Duration,
}

impl N6Control {
    /// Validate and convert IE 355. `Err` names why the instance is not used.
    pub fn from_ie(ie: &N6DelayMeasurementControlInformation) -> Result<Self, String> {
        let r = ie.measurement_reporting_type;
        // §5.33.8.2: "Periodic reporting and event triggered reporting shall be
        // exclusive from each other"; and at least one type is requested.
        if r.per && r.evt {
            return Err("both periodic and event-triggered reporting requested".into());
        }
        if !(r.per || r.evt || r.ire) {
            return Err("no Measurement Reporting Type flag set".into());
        }
        // Table 7.4.4.1.4-1: the Measurement Period is C, present for PER.
        let period = ie
            .measurement_period
            .filter(|p| *p > 0)
            .map(|p| Duration::from_secs(p as u64));
        if r.per && period.is_none() {
            return Err("periodic reporting without a Measurement Period".into());
        }
        let mut endpoints: Vec<IpAddr> = Vec::new();
        for a in &ie.measurement_endpoint_addresses {
            let ips = a
                .ipv4
                .map(IpAddr::from)
                .into_iter()
                .chain(a.ipv6.map(|v| IpAddr::from(v).to_canonical()));
            for ip in ips {
                if !endpoints.contains(&ip) {
                    endpoints.push(ip);
                }
            }
        }
        if endpoints.len() > MAX_ENDPOINTS_PER_CONTROL {
            log::warn!(
                "N6 Delay Measurement Control Information {} names {} endpoints: only the \
                 first {MAX_ENDPOINTS_PER_CONTROL} are measured",
                ie.id,
                endpoints.len()
            );
            endpoints.truncate(MAX_ENDPOINTS_PER_CONTROL);
        }
        let stamp = ie.measurement_protocols.iter().any(|p| p.stamp);
        let (mut port, mut port_provisioned, mut secured) = (STAMP_PORT, false, false);
        for p in ie.extra.iter().filter(|x| {
            x.ie_type == nextgcore_pfcp::ie::IeType::ProtocolSpecificConfigurationParameters as u16
        }) {
            let members = crate::n4_build::ParsedIe::parse_all(&p.data);
            let for_stamp = members.iter().any(|m| {
                m.ie_type == N6DelayMeasurementProtocols::IE_TYPE as u16
                    && N6DelayMeasurementProtocols::decode_value(&m.value).is_ok_and(|v| v.stamp)
            });
            if !for_stamp {
                continue;
            }
            for m in &members {
                match m.ie_type {
                    t if t == nextgcore_pfcp::ie::IeType::MeasurementEndpointPortNumber as u16
                        && m.value.len() >= 2 =>
                    {
                        port = u16::from_be_bytes([m.value[0], m.value[1]]);
                        port_provisioned = true;
                    }
                    IE_SECURITY_MODE_STAMP => {
                        secured |= m.value.first().is_some_and(|b| b & 0x03 != 0);
                    }
                    IE_HMAC_KEY_STAMP => secured = true,
                    _ => {}
                }
            }
        }
        let cannot_measure = if !stamp {
            log::warn!(
                "N6 Delay Measurement Control Information {}: the endpoints offer no STAMP, \
                 the only protocol this UPF implements: reporting a failure",
                ie.id
            );
            Some(N6DelayMeasurementFailureInformation::UNSPECIFIED)
        } else if secured {
            log::warn!(
                "N6 Delay Measurement Control Information {}: authenticated or encrypted \
                 STAMP requested, but this UPF implements only unauthenticated STAMP: \
                 reporting a failure",
                ie.id
            );
            Some(N6DelayMeasurementFailureInformation::UNSPECIFIED)
        } else {
            None
        };
        if r.evt
            && ie.average_packet_delay_threshold.is_none()
            && ie.minimum_packet_delay_threshold.is_none()
            && ie.maximum_packet_delay_threshold.is_none()
        {
            log::warn!(
                "N6 Delay Measurement Control Information {}: event-triggered reporting with \
                 no threshold: no event report will be sent",
                ie.id
            );
        }
        Ok(Self {
            id: ie.id,
            endpoints,
            network_instance: ie.network_instance.clone(),
            port,
            port_provisioned,
            cannot_measure,
            reporting: r,
            period,
            avg_threshold_ms: ie.average_packet_delay_threshold,
            min_threshold_ms: ie.minimum_packet_delay_threshold,
            max_threshold_ms: ie.maximum_packet_delay_threshold,
            min_wait: ie
                .minimum_waiting_time
                .map(|t| crate::path_qos::timer_duration(t.unit, t.value).unwrap_or(Duration::MAX))
                .unwrap_or(DEFAULT_MIN_WAIT),
        })
    }
}

/// The samples of one endpoint since its last periodic report.
#[derive(Debug, Clone)]
struct Window {
    start: SystemTime,
    sum_ms: u64,
    count: u32,
    min_ms: u32,
    max_ms: u32,
}

impl Window {
    fn new(start: SystemTime) -> Self {
        Self {
            start,
            sum_ms: 0,
            count: 0,
            min_ms: u32::MAX,
            max_ms: 0,
        }
    }

    fn add(&mut self, ms: u32) {
        self.sum_ms += ms as u64;
        self.count += 1;
        self.min_ms = self.min_ms.min(ms);
        self.max_ms = self.max_ms.max(ms);
    }

    fn info(&self) -> N6DelayMeasurementInformation {
        N6DelayMeasurementInformation {
            average_packet_delay: (self.sum_ms / self.count.max(1) as u64) as u32,
            minimum_packet_delay: Some(self.min_ms),
            maximum_packet_delay: Some(self.max_ms),
        }
    }
}

#[derive(Debug, Clone)]
struct Endpoint {
    window: Window,
    recent: VecDeque<u32>,
    period_start: Instant,
    immediate_sent: bool,
    /// When the last event report of each kind (avg, min, max) went out, and
    /// whether one is owed at the end of the minimum waiting time.
    last_evt: [Option<Instant>; 3],
    deferred: [bool; 3],
    misses: u32,
    replied: bool,
    failed: bool,
    backoff: Duration,
    next_probe: Instant,
    outstanding: bool,
}

impl Endpoint {
    fn new(now: Instant, wall: SystemTime) -> Self {
        Self {
            window: Window::new(wall),
            recent: VecDeque::with_capacity(EVT_SAMPLES),
            period_start: now,
            immediate_sent: false,
            last_evt: [None; 3],
            deferred: [false; 3],
            misses: 0,
            replied: false,
            failed: false,
            backoff: Duration::ZERO,
            next_probe: now,
            outstanding: false,
        }
    }

    fn recent_info(&self) -> N6DelayMeasurementInformation {
        let n = self.recent.len().max(1) as u64;
        N6DelayMeasurementInformation {
            average_packet_delay: (self.recent.iter().map(|&d| d as u64).sum::<u64>() / n) as u32,
            minimum_packet_delay: self.recent.iter().copied().min(),
            maximum_packet_delay: self.recent.iter().copied().max(),
        }
    }
}

#[derive(Debug, Clone)]
struct Probe {
    id: u16,
    to: SocketAddr,
    sent: Instant,
    t1: u64,
}

/// A STAMP test packet to send: its sequence number, destination and bytes.
pub type StampProbe = (u32, SocketAddr, [u8; STAMP_LEN]);

/// The monitor: what to measure, the outstanding probes, and the statistics.
#[derive(Debug)]
pub struct N6DelayMonitor {
    controls: BTreeMap<u16, N6Control>,
    state: HashMap<(u16, IpAddr), Endpoint>,
    pending: HashMap<u32, Probe>,
    next_seq: u32,
    /// Failure reports owed for controls this UPF cannot measure, sent on the
    /// next round (after the Association Setup/Update Response).
    failures_due: Vec<(u16, IpAddr)>,
    interval: Duration,
}

impl Default for N6DelayMonitor {
    fn default() -> Self {
        Self {
            controls: BTreeMap::new(),
            state: HashMap::new(),
            pending: HashMap::new(),
            next_seq: 0,
            failures_due: Vec::new(),
            interval: Duration::from_secs(1),
        }
    }
}

/// NTP 64-bit timestamp (RFC 5905 §6) of `t`.
pub fn ntp64(t: SystemTime) -> u64 {
    const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs().wrapping_add(NTP_UNIX_OFFSET) & 0xffff_ffff;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// The duration of an NTP 64-bit interval `later - earlier`, `None` if negative.
fn ntp_span(later: u64, earlier: u64) -> Option<Duration> {
    let d = later.checked_sub(earlier)?;
    Some(Duration::from_nanos(
        (((d as u128) * 1_000_000_000) >> 32) as u64,
    ))
}

/// An unauthenticated STAMP Session-Sender test packet (RFC 8762 §4.2.1, with
/// the RFC 8972 SSID field left 0): Sequence Number, Timestamp (NTP), Error
/// Estimate, then zeros. The Error Estimate says "not synchronized" (S = 0),
/// NTP format (Z = 0), multiplier 1 (RFC 4656 §4.1.2: never 0).
pub fn stamp_test_packet(seq: u32, t1: u64) -> [u8; STAMP_LEN] {
    let mut p = [0u8; STAMP_LEN];
    p[0..4].copy_from_slice(&seq.to_be_bytes());
    p[4..12].copy_from_slice(&t1.to_be_bytes());
    p[12..14].copy_from_slice(&0x0001u16.to_be_bytes());
    p
}

fn u32_at(p: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(p[at..at + 4].try_into().unwrap())
}

fn u64_at(p: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(p[at..at + 8].try_into().unwrap())
}

impl N6DelayMonitor {
    /// The probe interval of a healthy endpoint.
    pub fn set_probe_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    /// An Association Setup Request: the new association's provisioning
    /// replaces whatever was there (none clears it).
    pub fn configure(&mut self, ies: &[N6DelayMeasurementControlInformation]) {
        self.clear();
        for ie in ies {
            self.upsert(ie);
        }
    }

    /// The IE 355 values of an Association Update Request (§5.33.8.2):
    /// - an empty value stops every measurement;
    /// - an ID alone stops that instance;
    /// - an ID with the other IEs adds the instance, or replaces all of it;
    /// - instances not named are kept unmodified.
    pub fn apply_update(&mut self, values: &[Vec<u8>]) {
        for v in values {
            if v.is_empty() {
                log::info!("N6 delay measurement: all instances stopped by the SMF");
                self.clear();
                continue;
            }
            let members = crate::n4_build::ParsedIe::parse_all(v);
            let id_type = nextgcore_pfcp::ie::IeType::N6DelayMeasurementControlInformationId as u16;
            if members.len() == 1 && members[0].ie_type == id_type && members[0].value.len() >= 2 {
                let id = u16::from_be_bytes([members[0].value[0], members[0].value[1]]);
                log::info!("N6 delay measurement: instance {id} stopped by the SMF");
                self.remove(id);
                continue;
            }
            match N6DelayMeasurementControlInformation::decode_value(v) {
                Ok(ie) => self.upsert(&ie),
                Err(e) => log::warn!("N6 Delay Measurement Control Information ignored: {e}"),
            }
        }
    }

    fn upsert(&mut self, ie: &N6DelayMeasurementControlInformation) {
        let ctl = match N6Control::from_ie(ie) {
            Ok(c) => c,
            Err(e) => {
                log::warn!(
                    "N6 Delay Measurement Control Information {} ignored: {e}",
                    ie.id
                );
                return;
            }
        };
        if !self.controls.contains_key(&ctl.id) && self.controls.len() >= MAX_CONTROLS {
            log::warn!(
                "N6 Delay Measurement Control Information {} ignored: {MAX_CONTROLS} instances \
                 are already provisioned",
                ctl.id
            );
            return;
        }
        self.remove(ctl.id);
        if ctl.cannot_measure.is_some() {
            self.failures_due
                .extend(ctl.endpoints.iter().map(|ip| (ctl.id, *ip)));
        }
        log::info!(
            "N6 delay measurement instance {} provisioned: endpoints {:?} port {} reporting \
             {:?}",
            ctl.id,
            ctl.endpoints,
            ctl.port,
            ctl.reporting
        );
        self.controls.insert(ctl.id, ctl);
    }

    fn remove(&mut self, id: u16) {
        self.controls.remove(&id);
        self.state.retain(|(i, _), _| *i != id);
        self.pending.retain(|_, p| p.id != id);
        self.failures_due.retain(|(i, _)| *i != id);
    }

    pub fn clear(&mut self) {
        self.controls.clear();
        self.state.clear();
        self.pending.clear();
        self.failures_due.clear();
    }

    pub fn is_active(&self) -> bool {
        !self.controls.is_empty()
    }

    pub fn controls(&self) -> impl Iterator<Item = &N6Control> {
        self.controls.values()
    }

    /// One round at `now`: the probes to send and the reports that are due
    /// (failures, periodic reports, and event reports deferred by the minimum
    /// waiting time).
    pub fn round(
        &mut self,
        now: Instant,
        wall: SystemTime,
    ) -> (Vec<StampProbe>, Vec<N6DelayMeasurementReport>) {
        let mut reports = Vec::new();
        for (id, ip) in std::mem::take(&mut self.failures_due) {
            if let Some(c) = self.controls.get(&id) {
                let cause = c.cannot_measure.unwrap_or_default();
                reports.push(report(c, ip, c.reporting, None, Some(cause), None, wall));
            }
        }

        // Probes that timed out are misses.
        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_duration_since(p.sent) >= PROBE_TIMEOUT)
            .map(|(s, _)| *s)
            .collect();
        for seq in expired {
            let Some(p) = self.pending.remove(&seq) else {
                continue;
            };
            let ip = p.to.ip();
            let (Some(c), Some(st)) = (self.controls.get(&p.id), self.state.get_mut(&(p.id, ip)))
            else {
                continue;
            };
            st.outstanding = false;
            st.misses += 1;
            if st.misses < FAIL_AFTER {
                continue;
            }
            st.backoff = if st.backoff.is_zero() {
                self.interval.saturating_mul(2)
            } else {
                st.backoff.saturating_mul(2)
            }
            .min(MAX_BACKOFF);
            st.next_probe = now + st.backoff;
            if !st.failed {
                st.failed = true;
                let cause = if st.replied {
                    N6DelayMeasurementFailureInformation::CONNECTION_LOST
                } else {
                    N6DelayMeasurementFailureInformation::CONNECTION_ESTABLISHMENT_FAILURE
                };
                log::warn!(
                    "N6 delay measurement towards {}: no STAMP reply to {} probes, reporting \
                     failure cause {cause}",
                    p.to,
                    st.misses
                );
                reports.push(report(c, ip, c.reporting, None, Some(cause), None, wall));
            }
        }

        // Periodic and deferred event reports.
        for ((id, ip), st) in self.state.iter_mut() {
            let Some(c) = self.controls.get(id) else {
                continue;
            };
            if let (true, Some(period)) = (c.reporting.per, c.period) {
                if now.saturating_duration_since(st.period_start) >= period {
                    st.period_start = now;
                    if st.window.count > 0 {
                        let r = MeasurementReportingType {
                            per: true,
                            ..Default::default()
                        };
                        let start = st.window.start;
                        reports.push(report(
                            c,
                            *ip,
                            r,
                            Some(st.window.info()),
                            None,
                            Some(start),
                            wall,
                        ));
                    }
                    st.window = Window::new(wall);
                }
            }
            if c.reporting.evt && !st.recent.is_empty() {
                let mut fire = false;
                for k in 0..3 {
                    let waited = st.last_evt[k]
                        .is_none_or(|t| now.saturating_duration_since(t) >= c.min_wait);
                    if st.deferred[k] && waited {
                        st.deferred[k] = false;
                        st.last_evt[k] = Some(now);
                        fire = true;
                    }
                }
                if fire {
                    reports.push(evt_report(c, *ip, st, wall));
                }
            }
        }

        // Probes due.
        let mut probes = Vec::new();
        for c in self.controls.values() {
            if c.cannot_measure.is_some() {
                continue;
            }
            for ip in &c.endpoints {
                let st = self
                    .state
                    .entry((c.id, *ip))
                    .or_insert_with(|| Endpoint::new(now, wall));
                if st.outstanding || now < st.next_probe {
                    continue;
                }
                let seq = self.next_seq;
                self.next_seq = self.next_seq.wrapping_add(1);
                let t1 = ntp64(wall);
                let to = SocketAddr::new(*ip, c.port);
                st.outstanding = true;
                st.next_probe = now + if st.failed { st.backoff } else { self.interval };
                self.pending.insert(
                    seq,
                    Probe {
                        id: c.id,
                        to,
                        sent: now,
                        t1,
                    },
                );
                probes.push((seq, to, stamp_test_packet(seq, t1)));
            }
        }
        (probes, reports)
    }

    /// A datagram from `from` on the STAMP socket, received at `now`. Returns
    /// the reports it triggers when it is the reflection of one of our probes.
    pub fn on_reply(
        &mut self,
        from: SocketAddr,
        pkt: &[u8],
        now: Instant,
        wall: SystemTime,
    ) -> Vec<N6DelayMeasurementReport> {
        if pkt.len() < STAMP_LEN {
            return Vec::new();
        }
        // RFC 8762 §4.3.1: the reflected packet carries the Session-Sender
        // Sequence Number at octet 24 and the Session-Sender Timestamp at 28.
        let seq = u32_at(pkt, 24);
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        let matches = self
            .pending
            .get(&seq)
            .is_some_and(|p| p.to == from && p.t1 == u64_at(pkt, 28));
        if !matches {
            return Vec::new();
        }
        let p = self.pending.remove(&seq).expect("checked above");
        let mut rtt = now.saturating_duration_since(p.sent);
        // Less the reflector's turnaround, Timestamp (T3, octet 4) minus Receive
        // Timestamp (T2, octet 16), when it is plausible.
        if let Some(turn) = ntp_span(u64_at(pkt, 4), u64_at(pkt, 16)) {
            if u64_at(pkt, 16) != 0 && turn < rtt {
                rtt -= turn;
            }
        }
        let delay = crate::path_qos::path_delay_ms(rtt);
        let ip = from.ip();
        let (Some(c), Some(st)) = (self.controls.get(&p.id), self.state.get_mut(&(p.id, ip)))
        else {
            return Vec::new();
        };
        log::debug!("N6 delay probe to {from}: RTT {rtt:?}, one-way {delay} ms");
        st.outstanding = false;
        st.misses = 0;
        st.replied = true;
        let recovered = std::mem::take(&mut st.failed);
        st.backoff = Duration::ZERO;
        if recovered {
            // Back to the normal probe interval, not the failure backoff.
            st.next_probe = p.sent + self.interval;
        }
        st.window.add(delay);
        if st.recent.len() == EVT_SAMPLES {
            st.recent.pop_front();
        }
        st.recent.push_back(delay);

        let mut out = Vec::new();
        // IRE: "as soon as it has performed N6 delay measurements"; and after a
        // failure, "a new measurement report ... as soon as it has performed N6
        // delay measurements" (§5.33.8.3).
        if (c.reporting.ire && !st.immediate_sent) || recovered {
            st.immediate_sent = true;
            let info = N6DelayMeasurementInformation {
                average_packet_delay: delay,
                minimum_packet_delay: Some(delay),
                maximum_packet_delay: Some(delay),
            };
            let r = MeasurementReportingType {
                ire: true,
                ..Default::default()
            };
            out.push(report(c, ip, r, Some(info), None, None, wall));
        }
        if c.reporting.evt {
            let recent = st.recent_info();
            let hit = [
                c.avg_threshold_ms
                    .is_some_and(|t| recent.average_packet_delay >= t),
                c.min_threshold_ms
                    .is_some_and(|t| recent.minimum_packet_delay.unwrap_or(delay) >= t),
                c.max_threshold_ms.is_some_and(|t| delay >= t),
            ];
            let mut fire = false;
            for (k, h) in hit.iter().enumerate() {
                if !h {
                    continue;
                }
                let waited =
                    st.last_evt[k].is_none_or(|t| now.saturating_duration_since(t) >= c.min_wait);
                if waited {
                    st.last_evt[k] = Some(now);
                    st.deferred[k] = false;
                    fire = true;
                } else {
                    st.deferred[k] = true;
                }
            }
            if fire {
                out.push(evt_report(c, ip, st, wall));
            }
        }
        out
    }
}

fn evt_report(
    c: &N6Control,
    ip: IpAddr,
    st: &Endpoint,
    wall: SystemTime,
) -> N6DelayMeasurementReport {
    let r = MeasurementReportingType {
        evt: true,
        ..Default::default()
    };
    report(c, ip, r, Some(st.recent_info()), None, None, wall)
}

fn report(
    c: &N6Control,
    ip: IpAddr,
    reporting: MeasurementReportingType,
    information: Option<N6DelayMeasurementInformation>,
    failure: Option<u8>,
    start: Option<SystemTime>,
    wall: SystemTime,
) -> N6DelayMeasurementReport {
    let measurement_endpoint_address = match ip {
        IpAddr::V4(a) => MeasurementEndpointAddress {
            ipv4: Some(a.octets()),
            ipv6: None,
        },
        IpAddr::V6(a) => MeasurementEndpointAddress {
            ipv4: None,
            ipv6: Some(a.octets()),
        },
    };
    N6DelayMeasurementReport {
        measurement_endpoint_address,
        network_instance: c.network_instance.clone(),
        measurement_reporting_type: reporting,
        time_stamp: crate::data_plane::ntp_secs(wall),
        start_time: start.map(crate::data_plane::ntp_secs),
        information,
        failure_information: failure.map(|cause| N6DelayMeasurementFailureInformation { cause }),
        measurement_endpoint_port_number: c.port_provisioned.then_some(c.port),
        extra: vec![],
    }
}

/// The STAMP Session-Sender task: every 100 ms a round of
/// [`N6DelayMonitor::round`]; replies are handled as they arrive. Runs until
/// shutdown. The sockets are ephemeral-port client sockets: a datagram is only
/// used when it reflects a probe this UPF sent to that very address and port.
pub async fn run_n6_delay_measurement(
    dp: std::sync::Arc<crate::data_plane::DataPlane>,
    interval: Duration,
) {
    use std::sync::atomic::Ordering;
    use tokio::net::UdpSocket;
    dp.n6_delay.lock().unwrap().set_probe_interval(interval);
    let v4 = match UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(s) => Some(std::sync::Arc::new(s)),
        Err(e) => {
            log::error!("N6 delay measurement: no IPv4 STAMP socket: {e}");
            None
        }
    };
    let v6 = match UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).await {
        Ok(s) => Some(std::sync::Arc::new(s)),
        Err(e) => {
            log::warn!("N6 delay measurement: no IPv6 STAMP socket: {e}");
            None
        }
    };
    for sock in [v4.clone(), v6.clone()].into_iter().flatten() {
        let dp = dp.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while !dp.shutdown.load(Ordering::Relaxed) {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                let reports = dp.n6_delay.lock().unwrap().on_reply(
                    from,
                    &buf[..n],
                    Instant::now(),
                    SystemTime::now(),
                );
                if !reports.is_empty() {
                    dp.send_report_event(crate::data_plane::UpfReportEvent::N6DelayReport {
                        reports,
                    });
                }
            }
        });
    }
    log::info!("N6 delay measurement enabled (STAMP Session-Sender, probe interval {interval:?})");
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    loop {
        tick.tick().await;
        if dp.shutdown.load(Ordering::Relaxed) {
            break;
        }
        let (probes, reports) = dp
            .n6_delay
            .lock()
            .unwrap()
            .round(Instant::now(), SystemTime::now());
        for (_, to, pkt) in probes {
            let sock = if to.is_ipv4() { &v4 } else { &v6 };
            if let Some(s) = sock {
                if let Err(e) = s.send_to(&pkt, to).await {
                    log::debug!("N6 delay probe to {to} failed: {e}");
                }
            }
        }
        if !reports.is_empty() {
            dp.send_report_event(crate::data_plane::UpfReportEvent::N6DelayReport { reports });
        }
    }
}

#[cfg(test)]
#[path = "n6_delay_tests.rs"]
mod tests;
