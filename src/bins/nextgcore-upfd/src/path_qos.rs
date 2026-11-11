//! Per GTP-U path QoS monitoring (TS 29.244 §5.24.5, GPQM), #1389 part 1.
//!
//! The SMF provisions GTP-U Path QoS Control Information (IE 238) in a PFCP
//! Association Setup or Update Request (§5.24.5.2). For each GTP-U path it
//! names, by remote peer address or by interface type, this UPF:
//! - sends GTP-U Echo Requests of its own at the probe interval and times the
//!   Echo Responses;
//! - takes the path delay as RTT/2 plus the UPF internal processing time;
//! - reports a GTP-U Path QoS Report (IE 239) in a PFCP Node Report Request:
//!   immediately (IRE), at the end of each measurement period (PER) and/or
//!   when the average, minimum or maximum delay exceeds its threshold (THR),
//!   with the minimum waiting time between two threshold reports of the same
//!   kind for the same peer.
//!
//! OFF unless `--gtpu-path-qos-monitoring` is set: only then is GPQM
//! advertised and IE 238 acted on. The probes use sequence numbers of their
//! own and never touch the TS 29.281 §7.2 path-management state, so path
//! failure detection is unchanged when the feature is on.
//!
//! Limitations, stated honestly:
//! - The UPF internal processing time is taken as 0 ms: it is not measured.
//! - The probes are not marked with the requested DSCP, so no DSCP is reported.
//! - Paths selected by interface type: N3 is the gNB side of the live sessions.
//!   N9 by type is not tracked in this tree (no session records an N9 peer),
//!   so it is logged and only explicit peers are probed for it.

use nextgcore_pfcp::qos_monitoring::{
    GtpUPathInterfaceType, GtpUPathQosControlInformation, GtpUPathQosReport,
    QosInformationInGtpUPathQosReport, QosReportTrigger,
};
use nextgcore_pfcp::types::RemoteGtpUPeer;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

/// GTP-U port of an explicitly named remote peer (TS 29.281 §4.4.2).
pub const GTPU_PORT: u16 = 2152;

/// At most this many control instances are kept from one CP function, and
/// at most this many explicit peers per instance (the rest are ignored and
/// logged): the SMF is an authenticated association, but the UPF should not
/// probe an unbounded host list.
pub const MAX_CONTROLS: usize = 16;
pub const MAX_PEERS_PER_CONTROL: usize = 64;

/// Probe sequence numbers live in 0x8000..=0xFFFF. The §7.2 path table counts
/// from 1 upward; a response that matches both is credited to both.
const SEQ_BASE: u16 = 0x8000;

/// An Echo Request unanswered after this long is forgotten.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The Timer IE (§8.2.35) as a duration; `None` is "infinite".
pub fn timer_duration(unit: u8, value: u8) -> Option<Duration> {
    let v = value as u64;
    let secs = match unit {
        0 => 2 * v,
        1 => 60 * v,
        2 => 600 * v,
        3 => 3600 * v,
        4 => 36_000 * v,
        7 => return None,
        // "Other values shall be interpreted as multiples of 1 minute".
        _ => 60 * v,
    };
    Some(Duration::from_secs(secs))
}

/// One provisioned GTP-U Path QoS Control Information instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathQosControl {
    pub peers: Vec<IpAddr>,
    pub n3: bool,
    pub n9: bool,
    pub trigger: QosReportTrigger,
    pub period: Option<Duration>,
    pub avg_threshold_ms: Option<u32>,
    pub min_threshold_ms: Option<u32>,
    pub max_threshold_ms: Option<u32>,
    /// Zero when absent; `Duration::MAX` for an infinite Timer.
    pub min_wait: Duration,
}

impl PathQosControl {
    pub fn from_ie(ie: &GtpUPathQosControlInformation) -> Self {
        let mut peers: Vec<IpAddr> = ie
            .remote_gtpu_peers
            .iter()
            .flat_map(|p| {
                p.ipv4
                    .map(IpAddr::from)
                    .into_iter()
                    .chain(p.ipv6.map(|a| IpAddr::from(a).to_canonical()))
            })
            .collect();
        if peers.len() > MAX_PEERS_PER_CONTROL {
            log::warn!(
                "GTP-U Path QoS Control Information names {} peers: only the first {} are \
                 monitored",
                peers.len(),
                MAX_PEERS_PER_CONTROL
            );
            peers.truncate(MAX_PEERS_PER_CONTROL);
        }
        let itype = ie.gtpu_path_interface_type.unwrap_or_default();
        if itype.n9 {
            log::warn!(
                "GTP-U path QoS monitoring of N9 paths by interface type is not supported: \
                 only explicitly named peers are probed for it"
            );
        }
        Self {
            peers,
            n3: itype.n3,
            n9: itype.n9,
            trigger: ie.qos_report_trigger,
            period: ie
                .measurement_period
                .filter(|p| *p > 0)
                .map(|p| Duration::from_secs(p as u64)),
            avg_threshold_ms: ie.average_packet_delay_threshold,
            min_threshold_ms: ie.minimum_packet_delay_threshold,
            max_threshold_ms: ie.maximum_packet_delay_threshold,
            min_wait: ie
                .minimum_waiting_time
                .map(|t| timer_duration(t.unit, t.value).unwrap_or(Duration::MAX))
                .unwrap_or(Duration::ZERO),
        }
    }

    fn covers(&self, peer: IpAddr, n3_peers: &HashSet<IpAddr>) -> bool {
        self.peers.contains(&peer) || (self.n3 && n3_peers.contains(&peer))
    }
}

/// The delay samples of one (control, peer) since its last periodic report.
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

    fn avg_ms(&self) -> u32 {
        (self.sum_ms / self.count.max(1) as u64) as u32
    }
}

#[derive(Debug, Clone)]
struct PeerState {
    window: Window,
    period_start: Instant,
    immediate_sent: bool,
    /// When the last threshold report of each kind (avg, min, max) went out.
    last_thr: [Option<Instant>; 3],
}

/// The monitor: what to probe, the outstanding probes, and the statistics.
#[derive(Debug, Default)]
pub struct PathQosMonitor {
    controls: Vec<PathQosControl>,
    state: HashMap<(usize, IpAddr), PeerState>,
    pending: HashMap<(SocketAddr, u16), Instant>,
    next_seq: u16,
}

/// The one-way GTP-U path delay of an Echo round trip: RTT/2 plus the UPF
/// internal processing time (taken as 0), in whole milliseconds, rounded up.
pub fn path_delay_ms(rtt: Duration) -> u32 {
    let half_us = rtt.as_micros().div_ceil(2);
    half_us.div_ceil(1000).min(u32::MAX as u128) as u32
}

impl PathQosMonitor {
    /// Replace the provisioned controls (an Association Setup or Update that
    /// carries IE 238 replaces what was there; none clears them).
    pub fn configure(&mut self, ies: &[GtpUPathQosControlInformation]) {
        let mut controls: Vec<PathQosControl> = ies.iter().map(PathQosControl::from_ie).collect();
        if controls.len() > MAX_CONTROLS {
            log::warn!(
                "{} GTP-U Path QoS Control Information IEs: only the first {MAX_CONTROLS} \
                 are used",
                controls.len()
            );
            controls.truncate(MAX_CONTROLS);
        }
        self.controls = controls;
        self.state.clear();
        self.pending.clear();
    }

    pub fn clear(&mut self) {
        self.configure(&[]);
    }

    pub fn is_active(&self) -> bool {
        !self.controls.is_empty()
    }

    pub fn controls(&self) -> &[PathQosControl] {
        &self.controls
    }

    /// The paths to probe now: every explicit peer, and every N3 peer in use
    /// when a control asks for N3 by type.
    pub fn targets(&self, n3_in_use: &HashSet<SocketAddr>) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        let mut push = |a: SocketAddr| {
            if !out.contains(&a) {
                out.push(a);
            }
        };
        for c in &self.controls {
            for ip in &c.peers {
                push(SocketAddr::new(*ip, GTPU_PORT));
            }
            if c.n3 {
                let mut n3: Vec<_> = n3_in_use.iter().copied().collect();
                n3.sort();
                n3.into_iter().for_each(&mut push);
            }
        }
        out
    }

    /// Allocate the sequence number of a probe to `peer`, sent at `now`.
    pub fn probe_sent(&mut self, peer: SocketAddr, now: Instant) -> u16 {
        self.pending
            .retain(|_, sent| now.duration_since(*sent) < PROBE_TIMEOUT);
        let seq = SEQ_BASE | (self.next_seq & 0x7fff);
        self.next_seq = self.next_seq.wrapping_add(1);
        self.pending.insert((peer, seq), now);
        seq
    }

    /// An Echo Response from `peer` with `seq`, received at `now`. Returns
    /// the measured round trip when it answers one of our probes.
    pub fn on_echo_response(
        &mut self,
        peer: SocketAddr,
        seq: u16,
        now: Instant,
    ) -> Option<Duration> {
        let sent = self.pending.remove(&(peer, seq))?;
        Some(now.saturating_duration_since(sent))
    }

    /// Record a delay sample for `peer` and return the reports it triggers:
    /// the immediate report (once per configuration) and threshold reports.
    pub fn on_sample(
        &mut self,
        peer: IpAddr,
        delay_ms: u32,
        n3_peers: &HashSet<IpAddr>,
        now: Instant,
        wall: SystemTime,
    ) -> Vec<GtpUPathQosReport> {
        let mut out = Vec::new();
        for (i, c) in self.controls.iter().enumerate() {
            if !c.covers(peer, n3_peers) {
                continue;
            }
            let st = self.state.entry((i, peer)).or_insert_with(|| PeerState {
                window: Window::new(wall),
                period_start: now,
                immediate_sent: false,
                last_thr: [None; 3],
            });
            st.window.add(delay_ms);
            let n3 = n3_peers.contains(&peer);
            if c.trigger.ire && !st.immediate_sent {
                st.immediate_sent = true;
                out.push(report(
                    peer,
                    n3,
                    QosReportTrigger {
                        ire: true,
                        ..Default::default()
                    },
                    &st.window,
                    wall,
                ));
            }
            if c.trigger.thr {
                let w = &st.window;
                let exceeded = [
                    c.avg_threshold_ms.is_some_and(|t| w.avg_ms() > t),
                    c.min_threshold_ms.is_some_and(|t| w.min_ms > t),
                    c.max_threshold_ms.is_some_and(|t| delay_ms > t),
                ];
                let mut fire = false;
                for (k, hit) in exceeded.iter().enumerate() {
                    if !hit {
                        continue;
                    }
                    let waited = st.last_thr[k]
                        .is_none_or(|t| now.saturating_duration_since(t) >= c.min_wait);
                    if waited {
                        st.last_thr[k] = Some(now);
                        fire = true;
                    }
                }
                if fire {
                    out.push(report(
                        peer,
                        n3,
                        QosReportTrigger {
                            thr: true,
                            ..Default::default()
                        },
                        &st.window,
                        wall,
                    ));
                }
            }
        }
        out
    }

    /// The periodic reports due at `now`; each one starts a new window.
    pub fn due_periodic(
        &mut self,
        n3_peers: &HashSet<IpAddr>,
        now: Instant,
        wall: SystemTime,
    ) -> Vec<GtpUPathQosReport> {
        let mut out = Vec::new();
        for ((i, peer), st) in self.state.iter_mut() {
            let c = &self.controls[*i];
            let (true, Some(period)) = (c.trigger.per, c.period) else {
                continue;
            };
            if now.saturating_duration_since(st.period_start) < period {
                continue;
            }
            st.period_start = now;
            if st.window.count > 0 {
                out.push(report(
                    *peer,
                    n3_peers.contains(peer),
                    QosReportTrigger {
                        per: true,
                        ..Default::default()
                    },
                    &st.window,
                    wall,
                ));
            }
            st.window = Window::new(wall);
        }
        out
    }
}

fn report(
    peer: IpAddr,
    n3: bool,
    trigger: QosReportTrigger,
    w: &Window,
    wall: SystemTime,
) -> GtpUPathQosReport {
    let remote = match peer {
        IpAddr::V4(a) => RemoteGtpUPeer {
            ipv4: Some(a.octets()),
            ..Default::default()
        },
        IpAddr::V6(a) => RemoteGtpUPeer {
            ipv6: Some(a.octets()),
            ..Default::default()
        },
    };
    GtpUPathQosReport {
        remote_gtpu_peer: remote,
        gtpu_path_interface_type: n3.then_some(GtpUPathInterfaceType {
            n9: false,
            n3: true,
        }),
        qos_report_trigger: trigger,
        time_stamp: crate::data_plane::ntp_secs(wall),
        start_time: Some(crate::data_plane::ntp_secs(w.start)),
        qos_information: vec![QosInformationInGtpUPathQosReport {
            average_packet_delay: w.avg_ms(),
            minimum_packet_delay: Some(w.min_ms),
            maximum_packet_delay: Some(w.max_ms),
            dscp: None,
            extra: vec![],
        }],
        extra: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_pfcp::qos_monitoring::Timer;

    fn ctl(
        peers: Vec<IpAddr>,
        n3: bool,
        trigger: QosReportTrigger,
    ) -> GtpUPathQosControlInformation {
        GtpUPathQosControlInformation {
            remote_gtpu_peers: peers
                .iter()
                .map(|ip| match ip {
                    IpAddr::V4(a) => RemoteGtpUPeer {
                        ipv4: Some(a.octets()),
                        ..Default::default()
                    },
                    IpAddr::V6(a) => RemoteGtpUPeer {
                        ipv6: Some(a.octets()),
                        ..Default::default()
                    },
                })
                .collect(),
            gtpu_path_interface_type: n3.then_some(GtpUPathInterfaceType {
                n9: false,
                n3: true,
            }),
            qos_report_trigger: trigger,
            ..Default::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn delay_is_half_the_round_trip_rounded_up() {
        // §5.24.5.2: "adding RTT/2 and the UPF internal processing time".
        assert_eq!(path_delay_ms(Duration::from_millis(40)), 20);
        assert_eq!(path_delay_ms(Duration::from_micros(40_001)), 21);
        assert_eq!(path_delay_ms(Duration::from_micros(300)), 1);
        assert_eq!(path_delay_ms(Duration::ZERO), 0);
    }

    #[test]
    fn timer_ie_units_follow_table_8_2_35_1() {
        assert_eq!(timer_duration(0, 5), Some(Duration::from_secs(10)));
        assert_eq!(timer_duration(1, 2), Some(Duration::from_secs(120)));
        assert_eq!(timer_duration(3, 1), Some(Duration::from_secs(3600)));
        assert_eq!(timer_duration(7, 1), None);
        assert_eq!(timer_duration(5, 1), Some(Duration::from_secs(60)));
    }

    #[test]
    fn targets_are_explicit_peers_and_n3_in_use() {
        let mut m = PathQosMonitor::default();
        assert!(!m.is_active());
        m.configure(&[
            ctl(
                vec![ip("10.0.0.9")],
                false,
                QosReportTrigger {
                    per: true,
                    ..Default::default()
                },
            ),
            ctl(
                vec![],
                true,
                QosReportTrigger {
                    ire: true,
                    ..Default::default()
                },
            ),
        ]);
        assert!(m.is_active());
        let gnb: SocketAddr = "10.0.0.5:2152".parse().unwrap();
        let t = m.targets(&HashSet::from([gnb]));
        assert_eq!(t, vec!["10.0.0.9:2152".parse().unwrap(), gnb]);
        m.clear();
        assert!(m.targets(&HashSet::from([gnb])).is_empty());
    }

    #[test]
    fn only_our_probes_are_timed() {
        let mut m = PathQosMonitor::default();
        let peer: SocketAddr = "10.0.0.5:2152".parse().unwrap();
        let t0 = Instant::now();
        let seq = m.probe_sent(peer, t0);
        assert!(seq >= SEQ_BASE);
        // Another peer, or another seq, answers nothing.
        assert_eq!(
            m.on_echo_response("10.0.0.6:2152".parse().unwrap(), seq, t0),
            None
        );
        assert_eq!(m.on_echo_response(peer, seq ^ 1, t0), None);
        let rtt = m.on_echo_response(peer, seq, t0 + Duration::from_millis(30));
        assert_eq!(rtt, Some(Duration::from_millis(30)));
        // Answered once only.
        assert_eq!(
            m.on_echo_response(peer, seq, t0 + Duration::from_millis(31)),
            None
        );
    }

    #[test]
    fn immediate_report_once_then_periodic_windows() {
        let mut m = PathQosMonitor::default();
        let mut c = ctl(
            vec![ip("10.0.0.9")],
            false,
            QosReportTrigger {
                per: true,
                ire: true,
                thr: false,
            },
        );
        c.measurement_period = Some(10);
        m.configure(&[c]);
        let n3 = HashSet::new();
        let t0 = Instant::now();
        let w0 = SystemTime::now();
        let first = m.on_sample(ip("10.0.0.9"), 20, &n3, t0, w0);
        assert_eq!(first.len(), 1);
        assert!(first[0].qos_report_trigger.ire);
        assert_eq!(first[0].qos_information[0].average_packet_delay, 20);
        assert!(m.on_sample(ip("10.0.0.9"), 30, &n3, t0, w0).is_empty());
        // A peer no control names is not measured.
        assert!(m.on_sample(ip("10.9.9.9"), 99, &n3, t0, w0).is_empty());
        // Not due before the period.
        assert!(m
            .due_periodic(&n3, t0 + Duration::from_secs(9), w0)
            .is_empty());
        let per = m.due_periodic(&n3, t0 + Duration::from_secs(10), w0);
        assert_eq!(per.len(), 1);
        let q = &per[0].qos_information[0];
        assert!(per[0].qos_report_trigger.per);
        assert_eq!(
            (
                q.average_packet_delay,
                q.minimum_packet_delay,
                q.maximum_packet_delay
            ),
            (25, Some(20), Some(30))
        );
        // The next window starts empty: nothing measured, nothing reported.
        assert!(m
            .due_periodic(&n3, t0 + Duration::from_secs(20), w0)
            .is_empty());
    }

    #[test]
    fn threshold_reports_respect_the_minimum_waiting_time() {
        let mut m = PathQosMonitor::default();
        let mut c = ctl(
            vec![],
            true,
            QosReportTrigger {
                thr: true,
                ..Default::default()
            },
        );
        c.maximum_packet_delay_threshold = Some(25);
        c.minimum_waiting_time = Some(Timer { unit: 0, value: 5 }); // 10 s
        m.configure(&[c]);
        let gnb = ip("10.0.0.5");
        let n3 = HashSet::from([gnb]);
        let t0 = Instant::now();
        let w = SystemTime::now();
        assert!(m.on_sample(gnb, 20, &n3, t0, w).is_empty());
        let r = m.on_sample(gnb, 30, &n3, t0 + Duration::from_secs(1), w);
        assert_eq!(r.len(), 1);
        assert!(r[0].qos_report_trigger.thr);
        assert_eq!(r[0].gtpu_path_interface_type.map(|t| t.n3), Some(true));
        assert!(m
            .on_sample(gnb, 40, &n3, t0 + Duration::from_secs(5), w)
            .is_empty());
        assert_eq!(
            m.on_sample(gnb, 40, &n3, t0 + Duration::from_secs(11), w)
                .len(),
            1
        );
        // A gNB not in use is not covered by an N3-by-type control.
        assert!(m.on_sample(ip("10.0.0.6"), 99, &n3, t0, w).is_empty());
    }

    #[test]
    fn configuration_is_bounded() {
        let mut m = PathQosMonitor::default();
        let many: Vec<IpAddr> = (0..100u8).map(|i| IpAddr::from([10, 1, 0, i])).collect();
        let ies: Vec<_> = (0..20)
            .map(|_| {
                ctl(
                    many.clone(),
                    false,
                    QosReportTrigger {
                        ire: true,
                        ..Default::default()
                    },
                )
            })
            .collect();
        m.configure(&ies);
        assert_eq!(m.controls().len(), MAX_CONTROLS);
        assert_eq!(m.controls()[0].peers.len(), MAX_PEERS_PER_CONTROL);
    }
}
