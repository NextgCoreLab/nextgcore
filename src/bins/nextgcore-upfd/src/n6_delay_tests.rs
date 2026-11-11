use super::*;
use nextgcore_pfcp::ie::RawIe;
use nextgcore_pfcp::qos_monitoring::Timer;

const EP: [u8; 4] = [127, 0, 0, 1];

fn reporting(per: bool, evt: bool, ire: bool) -> MeasurementReportingType {
    MeasurementReportingType { per, evt, ire }
}

fn ctl(id: u16, r: MeasurementReportingType) -> N6DelayMeasurementControlInformation {
    N6DelayMeasurementControlInformation {
        id,
        measurement_endpoint_addresses: vec![MeasurementEndpointAddress {
            ipv4: Some(EP),
            ipv6: None,
        }],
        network_instance: b"\x08internet".to_vec(),
        measurement_protocols: vec![N6DelayMeasurementProtocols {
            stamp: true,
            ..Default::default()
        }],
        measurement_reporting_type: r,
        ..Default::default()
    }
}

/// Protocol Specific Configuration Parameters (IE 378) for STAMP with the given
/// member IEs (type, value) after the Measurement Protocol.
fn pscp_stamp(members: &[(u16, &[u8])]) -> RawIe {
    let mut v = Vec::new();
    v.extend_from_slice(&354u16.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.push(0x04); // STAMP
    for (t, val) in members {
        v.extend_from_slice(&t.to_be_bytes());
        v.extend_from_slice(&(val.len() as u16).to_be_bytes());
        v.extend_from_slice(val);
    }
    RawIe::new(378, bytes::Bytes::from(v))
}

/// What a STAMP Session-Reflector sends back for `probe` (RFC 8762 §4.3.1),
/// with Receive Timestamp `t2` and Timestamp `t3`.
fn reflect(probe: &[u8; STAMP_LEN], t2: u64, t3: u64) -> [u8; STAMP_LEN] {
    let mut r = [0u8; STAMP_LEN];
    r[0..4].copy_from_slice(&7u32.to_be_bytes());
    r[4..12].copy_from_slice(&t3.to_be_bytes());
    r[16..24].copy_from_slice(&t2.to_be_bytes());
    r[24..28].copy_from_slice(&probe[0..4]);
    r[28..36].copy_from_slice(&probe[4..12]);
    r[36..38].copy_from_slice(&probe[12..14]);
    r[40] = 255;
    r
}

fn monitor(ies: &[N6DelayMeasurementControlInformation]) -> N6DelayMonitor {
    let mut m = N6DelayMonitor::default();
    m.configure(ies);
    m
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Probe at `t0`, answered `rtt` later with no reflector turnaround.
fn measure(
    m: &mut N6DelayMonitor,
    t0: Instant,
    rtt: Duration,
    wall: SystemTime,
) -> (Vec<N6DelayMeasurementReport>, Vec<N6DelayMeasurementReport>) {
    let (probes, round) = m.round(t0, wall);
    assert_eq!(probes.len(), 1, "one endpoint, one probe");
    let (_, to, pkt) = probes[0];
    let replies = m.on_reply(to, &reflect(&pkt, 0, 0), t0 + rtt, wall);
    (round, replies)
}

#[test]
fn stamp_test_packet_is_rfc_8762_unauthenticated() {
    let p = stamp_test_packet(0x0102_0304, 0x1122_3344_5566_7788);
    assert_eq!(p.len(), 44);
    assert_eq!(&p[0..4], &[1, 2, 3, 4]);
    assert_eq!(&p[4..12], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    assert_eq!(&p[12..14], &[0x00, 0x01], "S=0 Z=0, multiplier 1");
    assert!(p[14..].iter().all(|b| *b == 0));
}

#[test]
fn ntp64_counts_from_1900() {
    let t = std::time::UNIX_EPOCH + Duration::from_millis(1500);
    let v = ntp64(t);
    assert_eq!(v >> 32, 2_208_988_801);
    assert_eq!((v & 0xffff_ffff) as u32, 0x8000_0000);
}

#[test]
fn control_validation_follows_the_sender_rules() {
    // §5.33.8.2: PER and EVT are exclusive; one type at least; PER needs a period.
    let mut both = ctl(1, reporting(true, true, false));
    both.measurement_period = Some(10);
    assert!(N6Control::from_ie(&both).is_err());
    assert!(N6Control::from_ie(&ctl(1, reporting(false, false, false))).is_err());
    assert!(N6Control::from_ie(&ctl(1, reporting(true, false, false))).is_err());
    let mut per = ctl(1, reporting(true, false, true));
    per.measurement_period = Some(10);
    let c = N6Control::from_ie(&per).unwrap();
    assert_eq!(c.period, Some(Duration::from_secs(10)));
    assert_eq!((c.port, c.port_provisioned), (STAMP_PORT, false));
    assert_eq!(c.cannot_measure, None);
    assert_eq!(
        c.min_wait, DEFAULT_MIN_WAIT,
        "local default (§5.33.8.2 NOTE)"
    );
}

#[test]
fn stamp_port_comes_from_the_protocol_specific_parameters() {
    let mut ie = ctl(1, reporting(false, false, true));
    ie.extra = vec![pscp_stamp(&[(379, &[0x1f, 0x90])])];
    let c = N6Control::from_ie(&ie).unwrap();
    assert_eq!((c.port, c.port_provisioned), (8080, true));
    assert_eq!(c.cannot_measure, None);
}

/// No STAMP among the endpoint's protocols, or STAMP with integrity or
/// confidentiality protection: not probed, and a failure is reported.
#[test]
fn unsupported_protocol_or_security_is_reported_as_failure() {
    let mut twamp = ctl(1, reporting(false, false, true));
    twamp.measurement_protocols = vec![N6DelayMeasurementProtocols {
        twamp: true,
        ..Default::default()
    }];
    let mut intp = ctl(2, reporting(false, false, true));
    intp.extra = vec![pscp_stamp(&[(390, &[0x01])])];
    let mut hmac = ctl(3, reporting(false, false, true));
    hmac.extra = vec![pscp_stamp(&[(391, &[0xaa; 16])])];
    let mut plain = ctl(4, reporting(false, false, true));
    plain.extra = vec![pscp_stamp(&[(390, &[0x00])])];
    let mut m = monitor(&[twamp, intp, hmac, plain]);
    let (probes, reports) = m.round(Instant::now(), SystemTime::now());
    assert_eq!(probes.len(), 1, "only the unauthenticated STAMP instance");
    assert_eq!(reports.len(), 3);
    for r in &reports {
        assert_eq!(
            r.failure_information.unwrap().cause,
            N6DelayMeasurementFailureInformation::UNSPECIFIED
        );
        assert!(r.information.is_none());
        assert_eq!(r.measurement_endpoint_address.ipv4, Some(EP));
    }
    // Owed once, not every round.
    let (_, again) = m.round(Instant::now() + ms(100), SystemTime::now());
    assert!(again.is_empty());
}

/// §5.33.8.3: an immediate report as soon as a measurement is made, the
/// one-way delay as half the round trip less the reflector's turnaround.
#[test]
fn immediate_report_is_half_the_round_trip_less_the_turnaround() {
    let mut m = monitor(&[ctl(1, reporting(false, false, true))]);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    let (probes, _) = m.round(t0, wall);
    let (_, to, pkt) = probes[0];
    assert_eq!(to, SocketAddr::from((EP, STAMP_PORT)));
    // 50 ms round trip, of which the reflector held it 10 ms: (50-10)/2 = 20.
    let t2 = ntp64(wall);
    let t3 = t2 + (10u64 << 32) / 1000;
    let reports = m.on_reply(to, &reflect(&pkt, t2, t3), t0 + ms(50), wall);
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert!(r.measurement_reporting_type.ire && !r.measurement_reporting_type.per);
    let info = r.information.unwrap();
    assert!(
        (20..=21).contains(&info.average_packet_delay),
        "{}",
        info.average_packet_delay
    );
    assert_eq!(r.network_instance, b"\x08internet".to_vec());
    assert!(r.failure_information.is_none());
    assert_eq!(r.measurement_endpoint_port_number, None);
    // Immediate is once per provisioning.
    let (_, again) = measure(&mut m, t0 + ms(1000), ms(50), wall);
    assert!(again.is_empty());
}

#[test]
fn a_reply_must_match_the_probe() {
    let mut m = monitor(&[ctl(1, reporting(false, false, true))]);
    let t0 = Instant::now();
    let wall = SystemTime::now();
    let (probes, _) = m.round(t0, wall);
    let (_, to, pkt) = probes[0];
    let good = reflect(&pkt, 0, 0);
    let other_host = SocketAddr::from(([127, 0, 0, 2], STAMP_PORT));
    assert!(m.on_reply(other_host, &good, t0 + ms(5), wall).is_empty());
    let other_port = SocketAddr::from((EP, 863));
    assert!(m.on_reply(other_port, &good, t0 + ms(5), wall).is_empty());
    let mut wrong_ts = good;
    wrong_ts[28] ^= 0xff;
    assert!(m.on_reply(to, &wrong_ts, t0 + ms(5), wall).is_empty());
    assert!(m.on_reply(to, &good[..40], t0 + ms(5), wall).is_empty());
    assert_eq!(m.on_reply(to, &good, t0 + ms(5), wall).len(), 1);
    // A replay of the same reflection is not a second sample.
    assert!(m.on_reply(to, &good, t0 + ms(6), wall).is_empty());
}

#[test]
fn periodic_report_carries_the_window_and_restarts_it() {
    let mut per = ctl(1, reporting(true, false, false));
    per.measurement_period = Some(2);
    let mut m = monitor(&[per]);
    m.set_probe_interval(ms(500));
    let t0 = Instant::now();
    let wall = SystemTime::now();
    for (i, rtt) in [20u64, 40, 60].iter().enumerate() {
        let (round, replies) = measure(&mut m, t0 + ms(500 * i as u64), ms(*rtt), wall);
        assert!(
            round.is_empty() && replies.is_empty(),
            "no report before the period"
        );
    }
    let (_, reports) = m.round(t0 + ms(2000), wall);
    let per: Vec<_> = reports
        .iter()
        .filter(|r| r.measurement_reporting_type.per)
        .collect();
    assert_eq!(per.len(), 1);
    let info = per[0].information.unwrap();
    assert_eq!(info.average_packet_delay, 20);
    assert_eq!(info.minimum_packet_delay, Some(10));
    assert_eq!(info.maximum_packet_delay, Some(30));
    assert!(per[0].start_time.is_some());
    // The next period starts empty: nothing to report without a sample.
    let (_, reports) = m.round(t0 + ms(4100), wall);
    assert!(reports.iter().all(|r| !r.measurement_reporting_type.per));
}

/// §5.33.8.3: an event report when a delay matches or exceeds the threshold;
/// none during the minimum waiting time, then one with the most recent
/// measurements as soon as it is over.
#[test]
fn event_report_honours_the_minimum_waiting_time() {
    let mut evt = ctl(1, reporting(false, true, false));
    evt.maximum_packet_delay_threshold = Some(30);
    evt.minimum_waiting_time = Some(Timer { unit: 0, value: 5 }); // 10 s
    let mut m = monitor(&[evt]);
    m.set_probe_interval(ms(1000));
    let t0 = Instant::now();
    let wall = SystemTime::now();
    let (_, r) = measure(&mut m, t0, ms(40), wall); // 20 ms
    assert!(r.is_empty(), "below the threshold");
    let (_, r) = measure(&mut m, t0 + ms(1000), ms(60), wall); // 30 ms: matches
    assert_eq!(r.len(), 1);
    assert!(r[0].measurement_reporting_type.evt);
    assert_eq!(r[0].information.unwrap().maximum_packet_delay, Some(30));
    let (_, r) = measure(&mut m, t0 + ms(2000), ms(100), wall); // 50 ms, in the wait
    assert!(r.is_empty(), "held by the minimum waiting time");
    let (_, r) = m.round(t0 + ms(11_000), wall);
    assert!(r.is_empty(), "still waiting");
    // The report that started the wait went out at 1060 ms (the reply).
    let (_, r) = m.round(t0 + ms(11_100), wall);
    assert_eq!(r.len(), 1, "owed report sent when the wait is over");
    assert!(r[0].measurement_reporting_type.evt);
    assert_eq!(r[0].information.unwrap().maximum_packet_delay, Some(50));
    let (_, r) = m.round(t0 + ms(11_200), wall);
    assert!(r.iter().all(|r| !r.measurement_reporting_type.evt), "once");
}

/// §5.33.8.3: an endpoint that does not answer is reported as a failure, then
/// retried with a growing period; the first measurement after it is reported
/// at once.
#[test]
fn unanswered_endpoint_fails_backs_off_and_recovers() {
    let mut per = ctl(1, reporting(true, false, false));
    per.measurement_period = Some(600);
    let mut m = monitor(&[per]);
    m.set_probe_interval(ms(1000));
    let t0 = Instant::now();
    let wall = SystemTime::now();
    let mut t = t0;
    let mut failures = Vec::new();
    let mut sent = 0;
    while t < t0 + Duration::from_secs(10) {
        let (p, r) = m.round(t, wall);
        sent += p.len();
        failures.extend(r);
        t += ms(100);
    }
    assert_eq!(failures.len(), 1, "one failure report per episode");
    assert_eq!(
        failures[0].failure_information.unwrap().cause,
        N6DelayMeasurementFailureInformation::CONNECTION_ESTABLISHMENT_FAILURE
    );
    assert!(failures[0].information.is_none());
    assert!(
        sent <= FAIL_AFTER as usize + 1,
        "retries back off: {sent} probes in 10 s"
    );
    // The endpoint answers again: reported at once, as immediate.
    let probes = loop {
        let (p, r) = m.round(t, wall);
        assert!(r.is_empty());
        if !p.is_empty() {
            break p;
        }
        t += ms(100);
    };
    let (_, to, pkt) = probes[0];
    let r = m.on_reply(to, &reflect(&pkt, 0, 0), t + ms(20), wall);
    assert_eq!(r.len(), 1);
    assert!(r[0].measurement_reporting_type.ire);
    assert_eq!(r[0].information.unwrap().average_packet_delay, 10);
    // Lost after it had answered: Connection Lost.
    let mut lost = Vec::new();
    let end = t + Duration::from_secs(10);
    while t < end {
        lost.extend(m.round(t, wall).1);
        t += ms(100);
    }
    let lost: Vec<_> = lost.iter().filter_map(|r| r.failure_information).collect();
    assert_eq!(
        lost,
        vec![N6DelayMeasurementFailureInformation {
            cause: N6DelayMeasurementFailureInformation::CONNECTION_LOST
        }]
    );
}

/// §5.33.8.2: an Update adds or replaces an instance by ID, an ID alone stops
/// it, a null-length IE stops all, and instances not named are kept.
#[test]
fn association_update_is_per_instance() {
    let mut m = monitor(&[
        ctl(1, reporting(false, false, true)),
        ctl(2, reporting(false, false, true)),
    ]);
    let enc = |ie: &N6DelayMeasurementControlInformation| {
        let mut b = bytes::BytesMut::new();
        ie.encode_value(&mut b);
        b.to_vec()
    };
    let mut new3 = ctl(3, reporting(false, false, true));
    new3.measurement_endpoint_addresses[0].ipv4 = Some([10, 0, 0, 3]);
    let mut replaced1 = ctl(1, reporting(false, false, true));
    replaced1.measurement_endpoint_addresses[0].ipv4 = Some([10, 0, 0, 1]);
    m.apply_update(&[enc(&new3), enc(&replaced1)]);
    let ids: Vec<u16> = m.controls().map(|c| c.id).collect();
    assert_eq!(ids, vec![1, 2, 3]);
    assert_eq!(
        m.controls().next().unwrap().endpoints,
        vec!["10.0.0.1".parse::<IpAddr>().unwrap()]
    );
    // ID alone: stop instance 2.
    let mut id_only = Vec::new();
    id_only.extend_from_slice(&377u16.to_be_bytes());
    id_only.extend_from_slice(&2u16.to_be_bytes());
    id_only.extend_from_slice(&2u16.to_be_bytes());
    m.apply_update(&[id_only]);
    let ids: Vec<u16> = m.controls().map(|c| c.id).collect();
    assert_eq!(ids, vec![1, 3]);
    // A malformed instance changes nothing.
    m.apply_update(&[vec![0x01, 0x79, 0x00, 0x02, 0x00]]);
    assert_eq!(m.controls().count(), 2);
    // Null length: stop all.
    m.apply_update(&[vec![]]);
    assert!(!m.is_active());
}

#[test]
fn at_most_max_controls_are_kept() {
    let ies: Vec<_> = (0..MAX_CONTROLS as u16 + 3)
        .map(|i| ctl(i, reporting(false, false, true)))
        .collect();
    let m = monitor(&ies);
    assert_eq!(m.controls().count(), MAX_CONTROLS);
}

/// The STAMP Session-Sender task against a reflector that holds every test
/// packet 40 ms: the immediate report reads about 20 ms, through the real
/// sockets and report channel.
#[tokio::test]
async fn sender_task_measures_an_injected_delay() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let reflector = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = reflector.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = reflector.recv_from(&mut buf).await else {
                return;
            };
            if n < STAMP_LEN {
                continue;
            }
            let mut probe = [0u8; STAMP_LEN];
            probe.copy_from_slice(&buf[..STAMP_LEN]);
            tokio::time::sleep(ms(40)).await;
            let _ = reflector.send_to(&reflect(&probe, 0, 0), from).await;
        }
    });
    let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
        AtomicBool::new(false),
    )));
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    dp.set_report_channel(tx);
    let mut ie = ctl(9, reporting(false, false, true));
    ie.extra = vec![pscp_stamp(&[(379, &port.to_be_bytes())])];
    dp.n6_delay.lock().unwrap().configure(&[ie]);
    let task = tokio::spawn(run_n6_delay_measurement(dp.clone(), ms(200)));
    let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("an N6 delay report within 5 s")
        .unwrap();
    dp.shutdown.store(true, Ordering::Relaxed);
    task.abort();
    let crate::data_plane::UpfReportEvent::N6DelayReport { reports } = ev else {
        panic!("unexpected event {ev:?}");
    };
    let r = &reports[0];
    assert!(r.measurement_reporting_type.ire);
    assert_eq!(r.measurement_endpoint_port_number, Some(port));
    let d = r.information.unwrap().average_packet_delay;
    assert!((20..=35).contains(&d), "injected 40 ms RTT, one-way {d} ms");
}
