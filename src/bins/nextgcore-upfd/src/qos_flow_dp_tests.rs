//! #1389 part 3: per QoS flow QoS monitoring through the real forwarding paths,
//! on real G-PDU bytes over UDP sockets (the gNB side is a test socket).

use super::*;
use crate::qos_flow_mon::{controls_of, ntp64};
use nextgcore_gtp::v1::types::{
    ExtensionHeaderType, Gtp1ExtHeader, PduSessionContainer, UlPduSessionInformation,
    UlQosMonitoringTimestamps,
};
use nextgcore_pfcp::qos_monitoring::{
    PacketDelayThresholds, QosMonitoringPerQosFlowControlInformation, ReportingFrequency,
    RequestedQosMonitoring,
};

const SEID: u64 = 0x1389;
const UL_TEID: u32 = 0x13891;
const DL_TEID: u32 = 0x13892;
const QFI: u8 = 9;
const NTP_MS: u64 = (1u64 << 32) / 1000;

struct Rig {
    dp: DataPlane,
    gnb: TokioUdpSocket,
    gnb_addr: SocketAddr,
    gtpu: Arc<TokioUdpSocket>,
    ue_ip: Ipv4Addr,
    sink: std::fs::File,
    reports: mpsc::Receiver<UpfReportEvent>,
}

async fn rig() -> Rig {
    let gtpu = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
    dp.gtpu_socket = Some(Arc::clone(&gtpu));
    let gnb = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let gnb_addr = gnb.local_addr().unwrap();
    let ue_ip = Ipv4Addr::new(10, 45, 13, 89);
    dp.add_session_from_pfcp(
        SEID,
        0x11389,
        ue_ip,
        UL_TEID,
        DL_TEID,
        gnb_addr,
        Some(1),
        Some(QFI),
    );
    let session = dp.sessions.find_by_seid(SEID).unwrap();
    for far in session.fars.write().unwrap().values_mut() {
        far.ohc_addr = None;
    }
    let (tx, reports) = mpsc::channel(16);
    dp.set_report_channel(tx);
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    Rig {
        dp,
        gnb,
        gnb_addr,
        gtpu,
        ue_ip,
        sink,
        reports,
    }
}

/// DL packet delay, Event Triggered at `dl_thr` ms with no Minimum Wait Time.
fn monitor_dl(dp: &DataPlane, qfi: u8, dl_thr: u32) {
    let ie = QosMonitoringPerQosFlowControlInformation {
        qfis: vec![qfi],
        requested_qos_monitoring: RequestedQosMonitoring {
            dlpd: true,
            ulpd: true,
            ..Default::default()
        },
        reporting_frequency: ReportingFrequency {
            evett: true,
            perio: false,
        },
        packet_delay_thresholds: Some(PacketDelayThresholds {
            downlink: Some(dl_thr),
            ..Default::default()
        }),
        minimum_wait_time: Some(0),
        measurement_period: None,
        extra: Vec::new(),
    };
    dp.with_qos_flow_monitor(|m| {
        m.create_srr(
            SEID,
            7,
            controls_of(&[ie]),
            std::time::Instant::now(),
            std::time::SystemTime::now(),
        )
    });
}

impl Rig {
    fn tun_fd(&self) -> RawFd {
        std::os::unix::io::AsRawFd::as_raw_fd(&self.sink)
    }

    fn dl_packet(&self) -> Vec<u8> {
        let mut pkt = tests_support::udp([8, 8, 8, 8], self.ue_ip.octets());
        tests_support::finalize(&mut pkt);
        pkt
    }

    async fn recv_gnb(&self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 2048];
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.gnb.recv_from(&mut buf),
        )
        .await
        .ok()?
        .unwrap();
        Some(buf[..r.0].to_vec())
    }

    async fn ul(&self, pkt: &[u8]) {
        self.dp
            .handle_uplink_packet(pkt, self.gnb_addr, self.tun_fd())
            .await;
    }
}

/// Minimal IPv4/UDP builders, local to these tests.
mod tests_support {
    pub fn udp(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&53u16.to_be_bytes());
        p[22..24].copy_from_slice(&1234u16.to_be_bytes());
        p[24..26].copy_from_slice(&8u16.to_be_bytes());
        p
    }
    pub fn finalize(p: &mut [u8]) {
        p[10] = 0;
        p[11] = 0;
        let c = super::ipv4_header_checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
    }
}

/// The DL PDU Session Container of a G-PDU the gNB received.
fn dl_container(pkt: &[u8]) -> nextgcore_gtp::v1::types::DlPduSessionInformation {
    match pdu_session_container_of(pkt) {
        Some(PduSessionContainer::Dl(dl)) => dl,
        other => panic!("a DL PDU Session Container, got {other:?}"),
    }
}

/// An NG-RAN's UL G-PDU on the session's uplink tunnel answering `t1`: T2 is
/// `dl_ms` after T1, T3 1 ms after T2, the RAN parts 2 and 3 ms.
fn ul_answer(t1: u64, dl_ms: u64, inner: &[u8]) -> Vec<u8> {
    let t2 = t1 + dl_ms * NTP_MS;
    let container = PduSessionContainer::Ul(UlPduSessionInformation {
        qfi: QFI,
        qos_monitoring: Some(UlQosMonitoringTimestamps {
            dl_sending_timestamp_repeated: t1,
            dl_received_timestamp: t2,
            ul_sending_timestamp: t2 + NTP_MS,
        }),
        dl_delay_result: Some(2),
        ul_delay_result: Some(3),
        ..Default::default()
    });
    let ext = Gtp1ExtHeader::pdu_session_container(&container);
    let mut ext_buf = bytes::BytesMut::new();
    ext.encode(
        &mut ext_buf,
        ExtensionHeaderType::NoMoreExtensionHeaders as u8,
    );
    let mut out = vec![0x34, 0xff];
    out.extend_from_slice(&((4 + ext_buf.len() + inner.len()) as u16).to_be_bytes());
    out.extend_from_slice(&UL_TEID.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, ExtensionHeaderType::PduSessionContainer as u8]);
    out.extend_from_slice(&ext_buf);
    out.extend_from_slice(inner);
    out
}

#[tokio::test]
async fn with_nothing_monitored_a_downlink_g_pdu_is_byte_identical() {
    let r = rig().await;
    let pkt = r.dl_packet();
    r.dp.handle_downlink_packet(&pkt, &r.gtpu).await;
    let got = r.recv_gnb().await.expect("forwarded");
    assert_eq!(got, encapsulate_dl_gpdu(&pkt, DL_TEID, Some(QFI)));
    // Monitoring another flow leaves this one's G-PDUs as they were.
    monitor_dl(&r.dp, 5, 1);
    let _ = r.dp.with_qos_flow_monitor(|m| {
        m.round(std::time::Instant::now(), std::time::SystemTime::now())
    });
    r.dp.handle_downlink_packet(&pkt, &r.gtpu).await;
    let got = r.recv_gnb().await.expect("forwarded");
    assert_eq!(got, encapsulate_dl_gpdu(&pkt, DL_TEID, Some(QFI)));
}

#[tokio::test]
async fn an_idle_monitored_flow_gets_a_dummy_g_pdu_with_qmp_and_t1() {
    let r = rig().await;
    monitor_dl(&r.dp, QFI, 1);
    let before = ntp64(std::time::SystemTime::now());
    r.dp.qos_flow_round().await;
    let got = r.recv_gnb().await.expect("a dummy G-PDU");
    let after = ntp64(std::time::SystemTime::now());
    let h = crate::gtp_path::parse_gtpu_header(&got).unwrap();
    assert_eq!(h.msg_type, gtpu_msg_type::GPDU);
    assert_eq!(h.teid, DL_TEID, "on the session's downlink tunnel");
    assert_eq!(h.header_len, got.len(), "no T-PDU (TS 29.281 §5.2.2.7)");
    let dl = dl_container(&got);
    assert_eq!(dl.qfi, QFI);
    let t1 = dl.dl_sending_timestamp.expect("QMP set, with T1");
    assert!((before..=after).contains(&t1), "T1 is the send time");
    // Octet 1 of the frame: PDU Type 0 and QMP (0x08), as TS 38.415 Figure
    // 5.5.2.1-1 has it.
    assert_eq!(got[13], 0x08);
}

#[tokio::test]
async fn a_flow_with_traffic_carries_the_qmp_on_a_real_packet_left_intact() {
    let r = rig().await;
    monitor_dl(&r.dp, QFI, 1);
    let pkt = r.dl_packet();
    assert_eq!(
        r.dp.qos_flow_round().await,
        1,
        "first round: idle, one dummy"
    );
    let _dummy = r.recv_gnb().await.expect("the dummy G-PDU");
    r.dp.handle_downlink_packet(&pkt, &r.gtpu).await;
    let plain = r.recv_gnb().await.unwrap();
    assert_eq!(
        dl_container(&plain).dl_sending_timestamp,
        None,
        "none due yet"
    );
    assert_eq!(r.dp.qos_flow_round().await, 0, "traffic flows: no dummy");
    r.dp.handle_downlink_packet(&pkt, &r.gtpu).await;
    let marked = r.recv_gnb().await.unwrap();
    assert!(
        dl_container(&marked).dl_sending_timestamp.is_some(),
        "QMP on it"
    );
    let h = crate::gtp_path::parse_gtpu_header(&marked).unwrap();
    assert_eq!(&marked[h.header_len..], &pkt[..], "the T-PDU is untouched");
    assert_eq!(r.dp.stats.dl_packets.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn the_ng_ran_answer_in_a_dummy_is_measured_reported_and_not_forwarded() {
    let mut r = rig().await;
    r.dp.set_qos_flow_clock_synced(true);
    monitor_dl(&r.dp, QFI, 5);
    r.dp.qos_flow_round().await;
    let t1 = dl_container(&r.recv_gnb().await.unwrap())
        .dl_sending_timestamp
        .unwrap();
    // A forged answer (a T1 never sent) measures nothing.
    r.ul(&ul_answer(t1 + 1, 10, &[])).await;
    assert!(r.reports.try_recv().is_err());
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    r.ul(&ul_answer(t1, 10, &[])).await;
    let Ok(UpfReportEvent::QosMonitoringReport { upf_seid, reports }) = r.reports.try_recv() else {
        panic!("12 ms exceeds the 5 ms threshold: a report");
    };
    assert_eq!(upf_seid, SEID);
    let (srr, rep) = &reports[0];
    assert_eq!((*srr, rep.qfi), (7, QFI));
    let m = rep.qos_monitoring_measurement;
    // Synchronised clocks: DL = T2-T1 (10 ms) + the RAN's 2 ms.
    assert_eq!(m.downlink_packet_delay, Some(12));
    // UL = T4-T3 (about 19 ms here) + the RAN's 3 ms.
    assert!(m.uplink_packet_delay.unwrap() >= 3 + 18, "{m:?}");
    assert_eq!(m.round_trip_packet_delay, None, "not requested");
    // The dummies were consumed: nothing to the TUN, no drop counted.
    assert_eq!(r.dp.stats.ul_packets.load(Ordering::Relaxed), 0);
    assert_eq!(
        r.dp.stats.dropped_packets.load(Ordering::Relaxed),
        0,
        "{}",
        r.dp.stats.summary()
    );
}

#[tokio::test]
async fn an_answer_riding_on_a_real_uplink_packet_is_measured_and_the_packet_forwarded() {
    let mut r = rig().await;
    monitor_dl(&r.dp, QFI, 1);
    r.dp.qos_flow_round().await;
    let t1 = dl_container(&r.recv_gnb().await.unwrap())
        .dl_sending_timestamp
        .unwrap();
    let mut inner = tests_support::udp(r.ue_ip.octets(), [8, 8, 8, 8]);
    tests_support::finalize(&mut inner);
    r.ul(&ul_answer(t1, 1, &inner)).await;
    assert_eq!(
        r.dp.stats.ul_packets.load(Ordering::Relaxed),
        1,
        "to the TUN"
    );
    assert!(matches!(
        r.reports.try_recv(),
        Ok(UpfReportEvent::QosMonitoringReport { .. })
    ));
}

#[tokio::test]
async fn with_nothing_monitored_a_dummy_uplink_g_pdu_is_still_a_malformed_drop() {
    let r = rig().await;
    r.ul(&ul_answer(ntp64(std::time::SystemTime::now()), 1, &[]))
        .await;
    assert_eq!(r.dp.stats.drops(DropReason::MalformedGtpu), 1);
}

#[tokio::test]
async fn a_removed_session_ends_its_monitoring() {
    let r = rig().await;
    monitor_dl(&r.dp, QFI, 1);
    assert!(r.dp.qos_flow_active());
    assert_eq!(r.dp.qos_flow_round().await, 1, "monitored: a dummy");
    r.dp.remove_session_from_pfcp(SEID);
    assert!(!r.dp.qos_flow_active());
    assert_eq!(r.dp.qos_flow_round().await, 0, "removed: none");
}

#[tokio::test]
async fn a_payload_less_answer_on_an_unknown_teid_is_a_malformed_drop() {
    // #1451 review m7: with monitoring on, it is still counted.
    let r = rig().await;
    monitor_dl(&r.dp, QFI, 1);
    let mut pkt = ul_answer(ntp64(std::time::SystemTime::now()), 1, &[]);
    pkt[4..8].copy_from_slice(&0xDEADu32.to_be_bytes());
    r.ul(&pkt).await;
    assert_eq!(
        r.dp.stats.drops(DropReason::MalformedGtpu),
        1,
        "{}",
        r.dp.stats.summary()
    );
}

#[tokio::test]
async fn an_answer_from_another_address_than_the_sessions_gnb_is_not_measured() {
    // #1451 review m8: after a path switch, the old gNB's answers in flight.
    let mut r = rig().await;
    monitor_dl(&r.dp, QFI, 1);
    assert_eq!(r.dp.qos_flow_round().await, 1);
    let t1 = dl_container(&r.recv_gnb().await.unwrap())
        .dl_sending_timestamp
        .unwrap();
    let old_gnb: SocketAddr = "127.0.0.77:2152".parse().unwrap();
    r.dp.handle_uplink_packet(&ul_answer(t1, 1, &[]), old_gnb, r.tun_fd())
        .await;
    assert!(r.reports.try_recv().is_err(), "not measured");
    // The probe is still outstanding: the session's gNB's answer measures it.
    r.ul(&ul_answer(t1, 1, &[])).await;
    assert!(matches!(
        r.reports.try_recv(),
        Ok(UpfReportEvent::QosMonitoringReport { .. })
    ));
}
