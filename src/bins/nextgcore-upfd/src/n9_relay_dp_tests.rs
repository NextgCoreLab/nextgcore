//! #1450: the I-UPF on N9, and Transport Delay Reporting, through the real
//! forwarding path on real G-PDU bytes over UDP sockets. The gNB and the PSA are
//! test sockets on GTP-U port 2152 of their own loopback addresses (a FAR's
//! Outer Header Creation names an address, and the data plane sends to 2152).

use super::*;
use crate::qos_flow_mon::controls_of;
use crate::transport_delay::TransportDelayPdr;
use nextgcore_gtp::v1::types::{
    DlPduSessionInformation, PduSessionContainer, UlPduSessionInformation,
};
use nextgcore_pfcp::qos_monitoring::{
    PacketDelayThresholds, QosMonitoringPerQosFlowControlInformation, ReportingFrequency,
    RequestedQosMonitoring,
};

const SEID: u64 = 0x1450;
/// The I-UPF's N3 uplink F-TEID (the gNB sends to it).
const UL_TEID: u32 = 0x14501;
/// The I-UPF's N9 downlink F-TEID (the PSA sends to it).
const N9_TEID: u32 = 0x14502;
/// The gNB's DL TEID and the PSA's UL N9 TEID.
const DL_TEID: u32 = 0x14503;
const PSA_TEID: u32 = 0x14504;
const QFI: u8 = 9;

/// A socket on `127.<net>.x.1:2152`, the first `x` free (#1373's idiom), so
/// concurrent test processes never collide.
async fn bind_2152(net: u8) -> (TokioUdpSocket, Ipv4Addr) {
    for x in 1..=254u8 {
        let ip = Ipv4Addr::new(127, net, x, 1);
        if let Ok(s) = TokioUdpSocket::bind((ip, GTPU_PORT)).await {
            return (s, ip);
        }
    }
    panic!("no free 127.{net}.x.1:2152");
}

struct Rig {
    dp: DataPlane,
    gnb: TokioUdpSocket,
    gnb_ip: Ipv4Addr,
    psa: TokioUdpSocket,
    psa_ip: Ipv4Addr,
    sink: std::fs::File,
    /// Held so report events have somewhere to go.
    _reports: mpsc::Receiver<UpfReportEvent>,
}

fn pdr(pdr_id: u16, source_interface: u8, far_id: u32) -> DataPlanePdr {
    DataPlanePdr {
        pdr_id,
        precedence: 100,
        source_interface,
        far_id: Some(far_id),
        qer_ids: Default::default(),
        urr_ids: Vec::new(),
        outer_header_removal: Some(0),
        sdf_rule: None,
        qfi: None,
    }
}

fn far(far_id: u32, destination_interface: u8, teid: u32, ip: Ipv4Addr) -> DataPlaneFar {
    DataPlaneFar {
        far_id,
        apply_action: FAR_ACTION_FORW,
        destination_interface,
        ohc_teid: Some(teid),
        ohc_addr: Some(IpAddr::V4(ip)),
        bar_id: None,
    }
}

/// An I-UPF session as TS 23.502 §4.3.2.2.1 provisions one: UL PDR 1 (Access,
/// on the N3 F-TEID) -> FAR 1 FORW toward the Core over N9 to the PSA; DL PDR 2
/// (Core, on the N9 F-TEID) -> FAR 2 FORW toward the Access side to the gNB. No
/// UE address: an I-UPF needs none.
async fn i_upf() -> Rig {
    let mut dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
    dp.gtpu_socket = Some(Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap()));
    let (gnb, gnb_ip) = bind_2152(14).await;
    let (psa, psa_ip) = bind_2152(15).await;
    let fars = HashMap::from([
        (1, far(1, SRC_INTF_CORE, PSA_TEID, psa_ip)),
        (2, far(2, SRC_INTF_ACCESS, DL_TEID, gnb_ip)),
    ]);
    let session = dp.add_established_session(
        SEID,
        0x11450,
        None,
        UL_TEID,
        DL_TEID,
        SocketAddr::new(IpAddr::V4(gnb_ip), GTPU_PORT),
        Some(QFI),
        EstablishedRules {
            pdrs: vec![pdr(1, SRC_INTF_ACCESS, 1), pdr(2, SRC_INTF_CORE, 2)],
            fars,
            own_tunnel_fars: HashSet::from([1]),
            qers: HashMap::new(),
            urrs: HashMap::new(),
            bars: HashMap::new(),
        },
    );
    session.pdr_teids.write().unwrap().insert(2, N9_TEID);
    dp.sessions.bind_ul_teid(N9_TEID, SEID);
    let (tx, reports) = mpsc::channel(16);
    dp.set_report_channel(tx);
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    Rig {
        dp,
        gnb,
        gnb_ip,
        psa,
        psa_ip,
        sink,
        _reports: reports,
    }
}

async fn recv(s: &TokioUdpSocket) -> Option<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_millis(500), s.recv_from(&mut buf))
        .await
        .ok()?
        .unwrap();
    Some(buf[..n].to_vec())
}

impl Rig {
    fn fd(&self) -> RawFd {
        std::os::unix::io::AsRawFd::as_raw_fd(&self.sink)
    }

    async fn send_as_gnb(&self, pkt: &[u8]) {
        let from = SocketAddr::new(IpAddr::V4(self.gnb_ip), GTPU_PORT);
        self.dp.handle_uplink_packet(pkt, from, self.fd()).await;
    }

    async fn send_as_psa(&self, pkt: &[u8]) {
        let from = SocketAddr::new(IpAddr::V4(self.psa_ip), GTPU_PORT);
        self.dp.handle_uplink_packet(pkt, from, self.fd()).await;
    }

    /// Transport Delay Reporting on PDR `pdr_id`, toward `peer`, with the delay to
    /// it set to `rtt_ms`/2 by one answered probe.
    fn transport_delay(&self, pdr_id: u16, peer: Ipv4Addr, rtt_ms: Option<u64>) {
        self.dp.with_transport_delay(|m| {
            m.set_pdr(
                SEID,
                pdr_id,
                Some(TransportDelayPdr {
                    peer: IpAddr::V4(peer),
                    dscp: None,
                }),
            );
            if let Some(rtt) = rtt_ms {
                let t0 = std::time::Instant::now();
                let (to, seq) = m.probes(t0)[0];
                m.on_echo_response(to, seq, t0 + std::time::Duration::from_millis(rtt));
            }
        });
    }
}

/// A G-PDU on `teid` with the PDU Session Container `c` and `inner`.
fn gpdu(teid: u32, c: &PduSessionContainer, inner: &[u8]) -> Vec<u8> {
    build_relay_gpdu(teid, Some(&c.encode_content()), inner)
}

fn ran_ul(dl: Option<u32>, ul: Option<u32>, n3n9: Option<u32>) -> PduSessionContainer {
    PduSessionContainer::Ul(UlPduSessionInformation {
        qfi: QFI,
        dl_delay_result: dl,
        ul_delay_result: ul,
        n3_n9_delay_result: n3n9,
        ..Default::default()
    })
}

fn inner_ul() -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 45, 14, 50]);
    p[16..20].copy_from_slice(&[8, 8, 8, 8]);
    let c = ipv4_header_checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p
}

/// The I-UPF forwards the uplink over N9 to the PSA, with the PDU Session
/// Container it arrived with (TS 29.244 §8.2.56 NOTE 1, TS 29.281 §5.2.2.7), and
/// never to its own data network.
///
/// REVERT-VERIFIED: with `gtpu_forward` refusing an uplink FAR, the packet goes to
/// the TUN and the PSA receives nothing.
#[tokio::test]
async fn an_i_upf_forwards_the_uplink_over_n9_with_its_container() {
    let r = i_upf().await;
    let c = PduSessionContainer::ul(QFI);
    let inner = inner_ul();
    r.send_as_gnb(&gpdu(UL_TEID, &c, &inner)).await;
    let got = recv(&r.psa).await.expect("forwarded to the PSA");
    assert_eq!(got, gpdu(PSA_TEID, &c, &inner), "PSA TEID, same container");
    assert!(recv(&r.gnb).await.is_none());
    assert_eq!(r.dp.stats.ul_packets.load(Ordering::Relaxed), 1);
    assert_eq!(r.dp.stats.dropped_packets.load(Ordering::Relaxed), 0);
}

/// #1450 criterion 1: an I-UPF given Transport Delay Reporting in its UL PDR adds
/// its delay to the preceding UL GTP-U peer (here the gNB) to the N3/N9 Delay
/// Result of a UL G-PDU carrying the RAN Delay Results, toward the PSA
/// (TS 29.244 §5.24.5.3, TS 38.415 §5.5.3.21).
///
/// Golden G-PDU, by hand (TS 29.281 §5.1, §5.2.1; TS 38.415 Figure 5.5.2.2-1):
/// 34 ff | Length 4 + 16 + 28 = 48 = 00 30 | TEID 00 01 45 04 | 00 00 00 85 |
/// 04 | 16 89 00000002 00000003 00000007 | 00 | the 28-octet T-PDU.
/// (Octet 1 0x16: PDU Type 1, DL and UL Delay Ind; octet 2 0x89: N3/N9 Delay Ind,
/// QFI 9; the delay is the 14 ms echo round trip / 2.)
///
/// REVERT-VERIFIED: with `onward_container` returning `None`, the PSA receives
/// the container without the N3/N9 Delay Result.
#[tokio::test]
async fn an_i_upf_with_transport_delay_reporting_adds_its_n3_delay_toward_the_psa() {
    let r = i_upf().await;
    r.transport_delay(1, r.gnb_ip, Some(14));
    let inner = inner_ul();
    r.send_as_gnb(&gpdu(UL_TEID, &ran_ul(Some(2), Some(3), None), &inner))
        .await;
    let got = recv(&r.psa).await.expect("forwarded to the PSA");
    let mut want = vec![
        0x34, 0xff, 0x00, 0x30, 0x00, 0x01, 0x45, 0x04, 0, 0, 0, 0x85, 0x04, 0x16, 0x89, 0, 0, 0,
        2, 0, 0, 0, 3, 0, 0, 0, 7, 0,
    ];
    want.extend_from_slice(&inner);
    assert_eq!(got, want);
    // A second I-UPF upstream already wrote 5 ms: the sum goes on.
    r.send_as_gnb(&gpdu(UL_TEID, &ran_ul(Some(2), Some(3), Some(5)), &inner))
        .await;
    let got = recv(&r.psa).await.unwrap();
    assert_eq!(
        pdu_session_container_of(&got),
        Some(ran_ul(Some(2), Some(3), Some(12)))
    );
}

/// #1450 criterion 3: off unless configured, the wire unchanged otherwise. With
/// no Transport Delay Reporting, with it but the delay not measured yet, and
/// with it on a frame carrying no RAN Delay Result, the container goes on
/// byte-identical.
///
/// REVERT-VERIFIED: with `add_n3_n9_delay` ignoring the RAN-field condition, the
/// third arm gains an N3/N9 Delay Result.
#[tokio::test]
async fn without_a_measured_transport_delay_the_container_goes_on_unchanged() {
    let r = i_upf().await;
    let inner = inner_ul();
    let ran = ran_ul(Some(2), Some(3), None);
    r.send_as_gnb(&gpdu(UL_TEID, &ran, &inner)).await;
    assert_eq!(recv(&r.psa).await.unwrap(), gpdu(PSA_TEID, &ran, &inner));
    r.transport_delay(1, r.gnb_ip, None);
    r.send_as_gnb(&gpdu(UL_TEID, &ran, &inner)).await;
    assert_eq!(
        recv(&r.psa).await.unwrap(),
        gpdu(PSA_TEID, &ran, &inner),
        "not measured yet"
    );
    r.transport_delay(1, r.gnb_ip, Some(14));
    let bare = PduSessionContainer::ul(QFI);
    r.send_as_gnb(&gpdu(UL_TEID, &bare, &inner)).await;
    assert_eq!(
        recv(&r.psa).await.unwrap(),
        gpdu(PSA_TEID, &bare, &inner),
        "no RAN Delay Result in it"
    );
}

/// The I-UPF forwards the PSA's downlink from N9 to the gNB with the PSA's DL
/// container (its QMP and T1 included), and QoS monitoring dummies both ways
/// (TS 29.281 §5.2.2.7: "An Intermediate UPF ... shall forward any received such
/// G-PDU messages together with the GTP-U PDU Session Container").
///
/// REVERT-VERIFIED: with `match_tunnel_pdr` trying only Access PDRs, the N9
/// downlink matches the UL PDR and goes to the TUN; with `relay_dummy` returning
/// `false`, the dummies are MalformedGtpu drops.
#[tokio::test]
async fn an_i_upf_forwards_n9_downlink_and_dummies_with_their_containers() {
    let r = i_upf().await;
    let dl = PduSessionContainer::Dl(DlPduSessionInformation {
        qfi: QFI,
        dl_sending_timestamp: Some(0x0102_0304_0506_0708),
        ..Default::default()
    });
    let mut inner = inner_ul();
    inner[12..16].copy_from_slice(&[8, 8, 8, 8]);
    inner[16..20].copy_from_slice(&[10, 45, 14, 50]);
    r.send_as_psa(&gpdu(N9_TEID, &dl, &inner)).await;
    assert_eq!(
        recv(&r.gnb).await.expect("to the gNB"),
        gpdu(DL_TEID, &dl, &inner)
    );
    assert_eq!(r.dp.stats.dl_packets.load(Ordering::Relaxed), 1);
    // The PSA's dummy toward the RAN, and the RAN's answer toward the PSA.
    r.send_as_psa(&gpdu(N9_TEID, &dl, &[])).await;
    assert_eq!(recv(&r.gnb).await.unwrap(), gpdu(DL_TEID, &dl, &[]));
    let answer = ran_ul(Some(2), Some(3), None);
    r.send_as_gnb(&gpdu(UL_TEID, &answer, &[])).await;
    assert_eq!(recv(&r.psa).await.unwrap(), gpdu(PSA_TEID, &answer, &[]));
    assert_eq!(r.dp.stats.dropped_packets.load(Ordering::Relaxed), 0);
    // A dummy with no container, or on a TEID no session holds, is malformed.
    r.send_as_psa(&build_relay_gpdu(N9_TEID, None, &[])).await;
    r.send_as_psa(&gpdu(0x7777, &dl, &[])).await;
    assert_eq!(r.dp.stats.drops(DropReason::MalformedGtpu), 2);
}

/// A PSA (directly on N3) given a GTPUPM control and Transport Delay Reporting.
async fn psa() -> (
    DataPlane,
    TokioUdpSocket,
    Ipv4Addr,
    mpsc::Receiver<UpfReportEvent>,
) {
    let mut dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
    dp.gtpu_socket = Some(Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap()));
    let (gnb, gnb_ip) = bind_2152(16).await;
    dp.add_session_from_pfcp(
        SEID,
        0x11450,
        Ipv4Addr::new(10, 45, 14, 50),
        UL_TEID,
        DL_TEID,
        SocketAddr::new(IpAddr::V4(gnb_ip), GTPU_PORT),
        Some(1),
        Some(QFI),
    );
    let (tx, rx) = mpsc::channel(16);
    dp.set_report_channel(tx);
    (dp, gnb, gnb_ip, rx)
}

fn gtpupm_control(dp: &DataPlane, thr: u32) {
    let ie = QosMonitoringPerQosFlowControlInformation {
        qfis: vec![QFI],
        requested_qos_monitoring: RequestedQosMonitoring {
            dlpd: true,
            ulpd: true,
            rppd: true,
            gtpupm: true,
            ..Default::default()
        },
        reporting_frequency: ReportingFrequency {
            evett: true,
            perio: false,
        },
        packet_delay_thresholds: Some(PacketDelayThresholds {
            downlink: Some(thr),
            ..Default::default()
        }),
        minimum_wait_time: Some(0),
        measurement_period: None,
        extra: Vec::new(),
    };
    let controls = controls_of(&[ie], true);
    assert_eq!(controls.len(), 1);
    dp.with_qos_flow_monitor(|m| {
        m.create_srr(
            SEID,
            3,
            controls,
            std::time::Instant::now(),
            std::time::SystemTime::now(),
        )
    });
}

/// #1450 criterion 2: a PSA given a GTPUPM control reports the per-flow delay
/// from GTP-U path monitoring (TS 23.501 §5.33.3.3, TS 29.244 §5.24.5.4): the
/// N3/N9 Delay Result the I-UPF wrote (7) plus its own delay to the preceding
/// peer (8 ms round trip: 4), plus the RAN DL 2 / UL 3: DL 13, UL 14, RTT 27. No
/// QMP goes out for the flow.
///
/// REVERT-VERIFIED: with `on_psa_transport_delay` not called from the uplink
/// path, no report comes.
#[tokio::test]
async fn a_psa_reports_the_gtpupm_delay_of_the_flow() {
    let (dp, gnb, _gnb_ip, mut reports) = psa().await;
    gtpupm_control(&dp, 10);
    let i_upf_ip = Ipv4Addr::new(127, 0, 0, 1);
    dp.with_transport_delay(|m| {
        m.set_pdr(
            SEID,
            1,
            Some(TransportDelayPdr {
                peer: IpAddr::V4(i_upf_ip),
                dscp: None,
            }),
        );
        let t0 = std::time::Instant::now();
        let (to, seq) = m.probes(t0)[0];
        m.on_echo_response(to, seq, t0 + std::time::Duration::from_millis(8));
    });
    assert_eq!(dp.qos_flow_round().await, 0, "no dummy for a GTPUPM flow");
    assert!(recv(&gnb).await.is_none());
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&sink);
    let from = SocketAddr::new(IpAddr::V4(i_upf_ip), GTPU_PORT);
    let pkt = gpdu(UL_TEID, &ran_ul(Some(2), Some(3), Some(7)), &inner_ul());
    dp.handle_uplink_packet(&pkt, from, fd).await;
    let Ok(UpfReportEvent::QosMonitoringReport {
        upf_seid,
        reports: r,
    }) = reports.try_recv()
    else {
        panic!("DL 13 ms >= 10: a report");
    };
    assert_eq!(upf_seid, SEID);
    let (srr, rep) = &r[0];
    assert_eq!((*srr, rep.qfi), (3, QFI));
    let m = rep.qos_monitoring_measurement;
    assert_eq!(
        (
            m.downlink_packet_delay,
            m.uplink_packet_delay,
            m.round_trip_packet_delay
        ),
        (Some(13), Some(14), Some(27))
    );
    assert_eq!(
        dp.stats.ul_packets.load(Ordering::Relaxed),
        1,
        "and the packet goes on to the data network"
    );
    // Directly on N3 (no I-UPF, no N3/N9 Delay Result): the PSA's own 4 ms.
    let pkt = gpdu(UL_TEID, &ran_ul(Some(9), Some(0), None), &inner_ul());
    dp.handle_uplink_packet(&pkt, from, fd).await;
    let Ok(UpfReportEvent::QosMonitoringReport { reports: r, .. }) = reports.try_recv() else {
        panic!("DL 13 ms >= 10: a report");
    };
    assert_eq!(
        r[0].1.qos_monitoring_measurement.downlink_packet_delay,
        Some(13)
    );
}

/// #1450 criterion 3: without Transport Delay Reporting the PSA takes no GTPUPM
/// sample, so nothing is reported (and the packet is forwarded as ever).
#[tokio::test]
async fn a_psa_without_transport_delay_reporting_takes_no_gtpupm_sample() {
    let (dp, _gnb, _ip, mut reports) = psa().await;
    gtpupm_control(&dp, 1);
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&sink);
    let pkt = gpdu(UL_TEID, &ran_ul(Some(2), Some(3), Some(7)), &inner_ul());
    dp.handle_uplink_packet(&pkt, "127.0.0.1:2152".parse().unwrap(), fd)
        .await;
    assert!(reports.try_recv().is_err());
    assert_eq!(dp.stats.ul_packets.load(Ordering::Relaxed), 1);
}

/// The probe round over real sockets: an Echo Request (TEID 0, S flag, the
/// sequence number in 0xC000..) to the preceding peer, whose Echo Response sets
/// the delay.
///
/// REVERT-VERIFIED: with the Echo Response branch not consulting the Transport
/// Delay monitor, the delay stays unknown.
#[tokio::test]
async fn the_probe_round_measures_the_preceding_peer_over_real_sockets() {
    let r = i_upf().await;
    r.transport_delay(1, r.gnb_ip, None);
    assert_eq!(r.dp.transport_delay_round().await, 1);
    let req = recv(&r.gnb).await.expect("an Echo Request");
    let h = crate::gtp_path::parse_gtpu_header(&req).unwrap();
    assert_eq!(h.msg_type, gtpu_msg_type::ECHO_REQUEST);
    let seq = h.seq_num.expect("S flag, a sequence number");
    assert!(seq >= crate::transport_delay::SEQ_BASE);
    assert_eq!(r.dp.with_transport_delay(|m| m.delay_for(SEID, 1)), None);
    r.send_as_gnb(&build_gtpu_echo_response(Some(seq))).await;
    assert!(r
        .dp
        .with_transport_delay(|m| m.delay_for(SEID, 1))
        .is_some());
}
