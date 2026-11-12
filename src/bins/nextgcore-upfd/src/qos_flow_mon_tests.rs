use super::*;
use nextgcore_pfcp::qos_monitoring::{ReportingFrequency, RequestedQosMonitoring};

const SEID: u64 = 0x51;
const MS: u64 = (1u64 << 32) / 1000;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// NTP time `n` ms after an arbitrary base.
fn at(base: u64, n_ms: u64) -> u64 {
    base + n_ms * MS
}

fn ie(
    qfis: &[u8],
    dl: bool,
    ul: bool,
    rp: bool,
    evett: bool,
    perio: bool,
) -> QosMonitoringPerQosFlowControlInformation {
    QosMonitoringPerQosFlowControlInformation {
        qfis: qfis.to_vec(),
        requested_qos_monitoring: RequestedQosMonitoring {
            dlpd: dl,
            ulpd: ul,
            rppd: rp,
            ..Default::default()
        },
        reporting_frequency: ReportingFrequency { evett, perio },
        packet_delay_thresholds: None,
        minimum_wait_time: None,
        measurement_period: Some(2),
        extra: Vec::new(),
    }
}

fn ctl(i: QosMonitoringPerQosFlowControlInformation) -> FlowControl {
    FlowControl::from_ie(&i).expect("a packet delay control")
}

/// An answer to `t1` from an NG-RAN whose clock is `offset_ms` ahead, `n3_ms`
/// away each way, turning the probe round in 1 ms.
fn answer(t1: u64, n3_dl: u64, n3_ul: u64, offset_ms: u64) -> QmpAnswer {
    let t2 = at(t1, n3_dl + offset_ms);
    let t3 = at(t2, 1);
    let t4 = at(t1, n3_dl + 1 + n3_ul);
    QmpAnswer {
        t1,
        t2,
        t3,
        t4,
        dl_ran_ms: None,
        ul_ran_ms: None,
    }
}

#[test]
fn without_clock_sync_the_n3_delay_is_half_the_round_trip_and_the_offset_cancels() {
    let base = ntp64(SystemTime::now());
    let a = answer(base, 20, 20, 5000);
    assert_eq!(
        a.delays(false),
        Delays {
            dl: 20,
            ul: 20,
            rp: 40
        }
    );
}

#[test]
fn with_clock_sync_each_direction_is_its_own_one_way_delay() {
    let base = ntp64(SystemTime::now());
    let a = answer(base, 20, 40, 0);
    assert_eq!(
        a.delays(true),
        Delays {
            dl: 20,
            ul: 40,
            rp: 60
        }
    );
    // Unsynchronised, the same answer is split evenly.
    assert_eq!(
        a.delays(false),
        Delays {
            dl: 30,
            ul: 30,
            rp: 60
        }
    );
}

#[test]
fn the_ran_part_is_added_to_each_direction_and_to_the_round_trip() {
    let base = ntp64(SystemTime::now());
    let mut a = answer(base, 20, 20, 0);
    a.dl_ran_ms = Some(2);
    a.ul_ran_ms = Some(3);
    assert_eq!(
        a.delays(false),
        Delays {
            dl: 22,
            ul: 23,
            rp: 45
        }
    );
}

#[test]
fn a_clock_behind_never_yields_a_negative_one_way_delay() {
    let base = ntp64(SystemTime::now());
    // T2 earlier than T1: the NG-RAN clock is 50 ms behind.
    let t2 = base - 30 * MS;
    let a = QmpAnswer {
        t1: base,
        t2,
        t3: t2 + MS,
        t4: base + 41 * MS,
        dl_ran_ms: None,
        ul_ran_ms: None,
    };
    let d = a.delays(true);
    assert_eq!(d.dl, 0);
    assert!(d.ul > 0);
}

#[test]
fn ntp_differences_wrap_across_an_era() {
    let before = u64::MAX - 5 * MS;
    let after = before.wrapping_add(15 * MS);
    let us = ntp_diff_us(after, before);
    assert!((14_990..=15_000).contains(&us), "{us}");
    assert!(ntp_diff_us(before, after) < 0);
}

#[test]
fn ntp64_is_the_rfc_5905_era_0_layout() {
    let t = std::time::UNIX_EPOCH + Duration::from_millis(1_500);
    assert_eq!(ntp64(t), ((NTP_UNIX_OFFSET + 1) << 32) | (1u64 << 31));
}

#[test]
fn only_packet_delay_by_time_stamps_is_acted_on() {
    let mut i = ie(&[1], true, false, false, false, true);
    i.requested_qos_monitoring.gtpupm = true;
    assert!(FlowControl::from_ie(&i).is_none(), "GTPUPM needs an I-UPF");
    let mut i = ie(&[1], false, false, false, false, true);
    i.requested_qos_monitoring.dlci = true;
    assert!(FlowControl::from_ie(&i).is_none(), "congestion is not QFQM");
    let i = ie(&[1], true, false, false, false, false);
    assert!(FlowControl::from_ie(&i).is_none(), "no reporting frequency");
    assert!(
        FlowControl::from_ie(&ie(&[1, 1, 2], true, false, false, false, true))
            .is_some_and(|c| c.qfis == vec![1, 2])
    );
}

#[test]
fn an_idle_flow_is_probed_with_a_dummy_every_round_and_the_answer_measures() {
    let mut m = QosFlowMonitor::new(false);
    let now = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, true, true, false, true))],
        now,
        wall,
    );
    assert!(m.is_active());
    assert_eq!(m.monitored_qfis(SEID), vec![5]);

    let r = m.round(now, wall);
    assert_eq!(r.dummies.len(), 1);
    let p = r.dummies[0];
    assert_eq!((p.upf_seid, p.qfi), (SEID, 5));
    let r = m.round(now + ms(500), wall + ms(500));
    assert_eq!(r.dummies.len(), 1, "still idle: another dummy");

    let (qfi, d, _) = m
        .on_answer(SEID, &answer(p.t1, 10, 10, 0), now + ms(21), wall)
        .expect("answers the first dummy");
    assert_eq!(qfi, 5);
    assert_eq!(d.rp, 20, "the 1 ms NG-RAN turnaround (T3-T2) is not delay");
    assert!(
        m.on_answer(SEID, &answer(p.t1, 10, 10, 0), now + ms(22), wall)
            .is_none(),
        "the same T1 answers once"
    );
    assert!(
        m.on_answer(SEID, &answer(p.t1 + 7, 10, 10, 0), now, wall)
            .is_none(),
        "a T1 never sent answers nothing"
    );
    assert!(
        m.on_answer(SEID + 1, &answer(r.dummies[0].t1, 10, 10, 0), now, wall)
            .is_none(),
        "another session's probe"
    );
}

#[test]
fn a_flow_with_traffic_carries_the_qmp_on_its_next_downlink_packet() {
    let mut m = QosFlowMonitor::new(false);
    let now = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        now,
        wall,
    );
    assert_eq!(m.round(now, wall).dummies.len(), 1);
    // Traffic, but no QMP is due until the next round.
    assert_eq!(m.on_downlink(SEID, 5, now, wall), None);
    assert_eq!(m.on_downlink(SEID, 6, now, wall), None, "unmonitored QFI");
    let r = m.round(now + ms(500), wall);
    assert!(r.dummies.is_empty(), "traffic flows: no dummy");
    let t1 = m
        .on_downlink(SEID, 5, now + ms(501), wall)
        .expect("the QMP rides on this packet");
    assert_eq!(
        m.on_downlink(SEID, 5, now + ms(502), wall),
        None,
        "one per round"
    );
    assert!(m
        .on_answer(SEID, &answer(t1, 5, 5, 0), now + ms(512), wall)
        .is_some());
}

#[test]
fn a_qmp_due_that_finds_no_packet_goes_out_as_a_dummy_next_round() {
    let mut m = QosFlowMonitor::new(false);
    let now = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        now,
        wall,
    );
    let _ = m.round(now, wall);
    let _ = m.on_downlink(SEID, 5, now, wall);
    assert!(
        m.round(now + ms(500), wall).dummies.is_empty(),
        "due on the next packet"
    );
    // No packet came: the due QMP becomes a dummy.
    assert_eq!(m.round(now + ms(1000), wall).dummies.len(), 1);
}

#[test]
fn the_answer_names_the_probed_flow_even_on_the_default_uplink_flow() {
    let mut m = QosFlowMonitor::new(false);
    let now = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[1, 2], true, false, false, false, true))],
        now,
        wall,
    );
    let r = m.round(now, wall);
    let p2 = r.dummies.iter().find(|p| p.qfi == 2).unwrap();
    let (qfi, _, _) = m
        .on_answer(SEID, &answer(p2.t1, 5, 5, 0), now + ms(11), wall)
        .unwrap();
    assert_eq!(qfi, 2);
}

fn event_ie(qfi: u8, dl_thr: u32, min_wait: u32) -> QosMonitoringPerQosFlowControlInformation {
    let mut i = ie(&[qfi], true, false, false, true, false);
    i.packet_delay_thresholds = Some(PacketDelayThresholds {
        downlink: Some(dl_thr),
        uplink: None,
        round_trip: None,
    });
    i.minimum_wait_time = Some(min_wait);
    i
}

/// Probe once and answer with an `n3` ms delay each way at `now`.
fn probe_and_answer(
    m: &mut QosFlowMonitor,
    n3: u64,
    now: Instant,
    wall: SystemTime,
) -> Vec<SrrReport> {
    let r = m.round(now, wall);
    let t1 = r.dummies.first().expect("idle flow, dummy").t1;
    m.on_answer(SEID, &answer(t1, n3, n3, 0), now, wall)
        .unwrap()
        .2
}

#[test]
fn an_exceeded_threshold_reports_and_the_minimum_wait_time_holds_the_next_one() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    let mut i = event_ie(5, 20, 10);
    // No Measurement Period: no measurement failure report in the gaps.
    i.measurement_period = None;
    m.create_srr(SEID, 3, vec![ctl(i)], t0, wall);

    assert!(
        probe_and_answer(&mut m, 10, t0, wall).is_empty(),
        "under the threshold"
    );
    let r = probe_and_answer(&mut m, 25, t0 + ms(500), wall);
    assert_eq!(r.len(), 1);
    let (srr, rep) = &r[0];
    assert_eq!((*srr, rep.qfi), (3, 5));
    assert_eq!(
        rep.qos_monitoring_measurement.downlink_packet_delay,
        Some(25)
    );
    assert_eq!(
        rep.qos_monitoring_measurement.uplink_packet_delay, None,
        "not requested"
    );
    assert!(rep.start_time.is_none());

    // Within the Minimum Wait Time: held back, the most recent one kept.
    assert!(probe_and_answer(&mut m, 30, t0 + ms(1000), wall).is_empty());
    assert!(probe_and_answer(&mut m, 40, t0 + ms(1500), wall).is_empty());
    let r = m.round(t0 + ms(9000), wall);
    assert!(r.reports.is_empty(), "the wait is not over");
    let r = m.round(t0 + ms(10_600), wall);
    let reps = &r.reports.first().expect("sent once the wait is over").1;
    assert_eq!(
        reps[0].1.qos_monitoring_measurement.downlink_packet_delay,
        Some(40)
    );
}

#[test]
fn a_periodic_report_carries_the_average_of_its_period_and_its_start() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, true, true, false, true))],
        t0,
        wall,
    );
    let _ = probe_and_answer(&mut m, 10, t0, wall);
    let _ = probe_and_answer(&mut m, 20, t0 + ms(500), wall);
    let r = m.round(t0 + ms(2000), wall + ms(2000));
    let (seid, reps) = r.reports.first().expect("the period is over");
    assert_eq!(*seid, SEID);
    let meas = reps[0].1.qos_monitoring_measurement;
    // 10 and 20 ms each way: averages 15 and 30.
    assert_eq!(meas.downlink_packet_delay, Some(15));
    assert_eq!(meas.uplink_packet_delay, Some(15));
    assert_eq!(meas.round_trip_packet_delay, Some(30));
    assert!(!meas.packet_delay_measurement_failure);
    assert_eq!(
        reps[0].1.start_time,
        Some(crate::data_plane::ntp_secs(wall))
    );
}

#[test]
fn a_period_with_no_answer_is_reported_as_a_measurement_failure() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        t0,
        wall,
    );
    let _ = m.round(t0, wall);
    let r = m.round(t0 + ms(2000), wall);
    let meas = r.reports[0].1[0].1.qos_monitoring_measurement;
    assert!(meas.packet_delay_measurement_failure);
    assert_eq!(
        meas.downlink_packet_delay, None,
        "§8.2.171: no delay with PLMF"
    );
}

#[test]
fn event_triggered_reports_a_failure_once_per_silence() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    let mut i = event_ie(5, 20, 0);
    i.measurement_period = Some(2);
    m.create_srr(SEID, 1, vec![ctl(i)], t0, wall);
    assert!(m.round(t0 + ms(1000), wall).reports.is_empty());
    let r = m.round(t0 + ms(2100), wall);
    assert!(
        r.reports[0].1[0]
            .1
            .qos_monitoring_measurement
            .packet_delay_measurement_failure
    );
    assert!(m.round(t0 + ms(4500), wall).reports.is_empty(), "once");
    // An answer ends the silence; the next one is reported again.
    let _ = probe_and_answer(&mut m, 5, t0 + ms(5000), wall);
    assert!(!m.round(t0 + ms(7200), wall).reports.is_empty());
}

#[test]
fn removing_the_srr_stops_monitoring_and_reports_what_was_measured() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        t0,
        wall,
    );
    let _ = probe_and_answer(&mut m, 7, t0, wall);
    let r = m.remove_srr(SEID, 1, wall);
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].1.qos_monitoring_measurement.downlink_packet_delay,
        Some(7)
    );
    assert!(!m.is_active());
    assert!(
        m.round(t0 + ms(500), wall).dummies.is_empty(),
        "no probes any more"
    );
    assert!(m.remove_srr(SEID, 1, wall).is_empty(), "idempotent");
}

#[test]
fn an_update_keeps_the_ongoing_measurement_and_judges_it_by_the_new_threshold() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(SEID, 1, vec![ctl(event_ie(5, 100, 0))], t0, wall);
    assert!(
        probe_and_answer(&mut m, 30, t0, wall).is_empty(),
        "under 100 ms"
    );
    let stop = m.update_srr(SEID, 1, vec![ctl(event_ie(5, 25, 0))], t0, wall);
    assert!(stop.is_empty(), "QFI 5 is still monitored");
    let r = m.round(t0 + ms(10), wall);
    let rep = &r.reports.first().expect("30 ms now exceeds 25").1[0];
    assert_eq!(
        rep.1.qos_monitoring_measurement.downlink_packet_delay,
        Some(30)
    );
}

#[test]
fn an_update_that_drops_a_flow_reports_it_and_stops_probing_it() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5, 6], true, false, false, false, true))],
        t0,
        wall,
    );
    let r = m.round(t0, wall);
    for p in &r.dummies {
        let _ = m.on_answer(SEID, &answer(p.t1, 4, 4, 0), t0, wall);
    }
    let stop = m.update_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        t0,
        wall,
    );
    assert_eq!(stop.len(), 1);
    assert_eq!(stop[0].1.qfi, 6);
    assert_eq!(m.monitored_qfis(SEID), vec![5]);
    // An update with no control left is a stop of the whole SRR.
    let stop = m.update_srr(SEID, 1, Vec::new(), t0, wall);
    assert_eq!(stop.len(), 1);
    assert!(!m.is_active());
}

#[test]
fn a_removed_session_leaves_nothing_behind() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        t0,
        wall,
    );
    m.create_srr(SEID, 2, Vec::new(), t0, wall);
    assert_eq!(
        m.srr_ids(SEID),
        vec![1],
        "an SRR with nothing to monitor is not kept"
    );
    m.remove_session(SEID);
    assert!(!m.is_active());
    assert!(m.round(t0, wall).dummies.is_empty());
}

#[test]
fn every_probe_gets_a_t1_of_its_own_even_in_the_same_instant() {
    let mut m = QosFlowMonitor::new(false);
    let now = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[1, 2], true, false, false, false, true))],
        now,
        wall,
    );
    // QFI 1 carries traffic, QFI 2 is idle.
    let _ = m.round(now, wall);
    let _ = m.on_downlink(SEID, 1, now, wall);
    let later = wall + ms(500);
    let r = m.round(now, later);
    let dummy = r.dummies.iter().find(|p| p.qfi == 2).expect("idle flow").t1;
    let on_packet = m.on_downlink(SEID, 1, now, later).expect("due on QFI 1");
    assert_ne!(dummy, on_packet, "one wall clock instant, two probes");
    let (qfi, _, _) = m
        .on_answer(SEID, &answer(on_packet, 3, 3, 0), now, wall)
        .unwrap();
    assert_eq!(qfi, 1);
}

#[test]
fn periodic_reports_keep_their_cadence_under_round_jitter() {
    // #1451 review M1: rounds every 1 s with scheduling jitter, Measurement
    // Period 2 s. A period reset to the (late) round time made a later, less
    // late round fall just short, so one "2 s" period lasted 3 s.
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        t0,
        wall,
    );
    let jitter_us = [300u64, 100, 400, 50, 500, 200, 450, 0, 350, 150, 250, 20];
    let mut reported = Vec::new();
    for (k, j) in jitter_us.iter().enumerate() {
        let at = Duration::from_millis(1000 * k as u64) + Duration::from_micros(*j);
        let r = m.round(t0 + at, wall + at);
        if !r.reports.is_empty() {
            reported.push(k);
            let start = r.reports[0].1[0].1.start_time.unwrap();
            let want = crate::data_plane::ntp_secs(wall + Duration::from_secs(k as u64 - 2));
            assert_eq!(start, want, "round {k}: the period starts on its anchor");
        }
    }
    assert_eq!(reported, vec![2, 4, 6, 8, 10], "one report every 2 s");
}

#[test]
fn a_stalled_round_catches_up_to_the_current_period() {
    let mut m = QosFlowMonitor::new(false);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        t0,
        wall,
    );
    // Nothing ran for 7 s: one report, then the cadence resumes at 8 s.
    assert_eq!(m.round(t0 + ms(7000), wall).reports.len(), 1);
    assert!(m.round(t0 + ms(7500), wall).reports.is_empty());
    assert_eq!(m.round(t0 + ms(8000), wall).reports.len(), 1);
}

#[test]
fn with_clock_sync_a_skewed_clock_does_not_inflate_the_round_trip() {
    // #1451 review m2: true 10/10 ms, the NG-RAN clock 15 ms behind. The one-way
    // DL clamps to 0, but the round trip is offset-free: 20 ms, not 25.
    let base = ntp64(SystemTime::now());
    let t2 = base - 5 * MS; // T1 + 10 ms - 15 ms
    let a = QmpAnswer {
        t1: base,
        t2,
        t3: t2 + MS,
        t4: base + 21 * MS,
        dl_ran_ms: None,
        ul_ran_ms: None,
    };
    let d = a.delays(true);
    assert_eq!(d.dl, 0);
    assert_eq!(d.rp, 20);
}

#[test]
fn after_a_clock_step_back_t1_is_the_clock_again() {
    // #1451 review m3: T1 is unique among a session's outstanding probes, not a
    // global high-water mark that would stay ahead of a clock stepped back.
    let mut m = QosFlowMonitor::new(false);
    let now = Instant::now();
    let wall = SystemTime::now();
    m.create_srr(
        SEID,
        1,
        vec![ctl(ie(&[5], true, false, false, false, true))],
        now,
        wall,
    );
    let ahead = m.round(now, wall + Duration::from_secs(10)).dummies[0].t1;
    assert_eq!(ahead, ntp64(wall + Duration::from_secs(10)));
    let after_step = m.round(now, wall).dummies[0].t1;
    assert_eq!(after_step, ntp64(wall));
}
