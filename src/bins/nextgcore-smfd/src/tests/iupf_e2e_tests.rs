//! #2208 end to end, in process: this SMF and two REAL UPFs (the `nextgcore_upfd`
//! library, #2208 step 1: its PFCP server, its data plane on real UDP sockets
//! with N6 on a datagram socket in place of the TUN device, and `runtime::start`,
//! the tasks the binary starts). One UPF is the PSA, the other the I-UPF that
//! `smf.intermediate_upf` names. A stand-in gNB (a UDP socket on port 2152)
//! answers GTP-U Echo after a fixed delay and sends uplink G-PDUs carrying the RAN
//! part of the delay (TS 38.415 §5.5.2.2: DL Delay Result 2 ms, UL 3 ms).
//!
//! The PCF's policy (a PCC rule with `refQosMon`, DL/UL/RTT, Periodic every 1 s)
//! comes in the create answer, and `smf.qos_monitoring.method` is `gtpu_path`.
//! Then:
//! - the SMF inserts the I-UPF on N9 (TS 23.502 §4.3.5.4), and the NG-RAN is
//!   given the I-UPF's N3 F-TEID;
//! - the I-UPF's UL PDR gets IE 271 toward the gNB, the PSA's toward the I-UPF,
//!   and the PSA an SRR with GTPUPM (TS 29.244 §5.24.5.3);
//! - the I-UPF measures the N3 delay (RTT/2 of its Echo to the gNB) and writes it
//!   into the N3/N9 Delay Result; the PSA adds its own N9 delay and the RAN part,
//!   and reports the per-flow delay;
//! - the SMF sends that delay to the PCF in `qosMonReports`.
//!
//! What this does not prove: the real binary's TUN path and its process wiring
//! (#2222, the nightly docker run), and a real gNB's time stamps.

use super::*;
use std::os::unix::io::RawFd;

use nextgcore_upfd::data_plane::DataPlane;
use nextgcore_upfd::pfcp_path::PfcpServer;
use nextgcore_upfd::runtime;

/// How long the stand-in gNB holds an Echo Response: the N3 delay the I-UPF
/// measures is half the round trip, so about this much.
const GNB_ECHO_HOLD_MS: u64 = 40;
const RAN_DL_MS: u32 = 2;
const RAN_UL_MS: u32 = 3;

struct Upf {
    pfcp: std::net::SocketAddr,
    /// The UPF's N4 session census.
    sessions: Arc<std::sync::atomic::AtomicUsize>,
    /// Its data plane, to read the Transport Delay Reporting it holds.
    dp: Arc<DataPlane>,
    ip: std::net::Ipv4Addr,
    runtime: runtime::Runtime,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    n6: (RawFd, RawFd),
}

impl Drop for Upf {
    fn drop(&mut self) {
        self.runtime.abort();
        self.shutdown.store(true, Ordering::SeqCst);
        unsafe {
            libc::close(self.n6.0);
            libc::close(self.n6.1);
        }
    }
}

/// A free `127.net.x.1` with UDP 2152 bound, the GTP-U port a UPF sends to.
async fn bind_2152(net: u8) -> (tokio::net::UdpSocket, std::net::Ipv4Addr) {
    for x in 1..=254u8 {
        let ip = std::net::Ipv4Addr::new(127, net, x, 1);
        if let Ok(s) = tokio::net::UdpSocket::bind((ip, 2152)).await {
            return (s, ip);
        }
    }
    panic!("no free 127.{net}.x.1:2152");
}

/// A UPF with GPQM and QFQM, its PFCP server and GTP-U socket on one address.
async fn upf(net: u8) -> Upf {
    let (sock, ip) = bind_2152(net).await;
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut dp = DataPlane::new(shutdown.clone());
    dp.gtpu_socket = Some(Arc::new(sock));
    *dp.local_gtpu_addr.write().unwrap() = ip;
    let (tx, rx) = tokio::sync::mpsc::channel(100);
    let server = PfcpServer::new((ip, 0).into(), shutdown.clone(), tx)
        .await
        .unwrap();
    server.set_allowed_peers(
        nextgcore_pfcp::peer_policy::PeerAllowlist::parse("127.0.0.0/8").unwrap(),
    );
    server.set_path_qos_monitoring(true);
    server.set_qos_flow_monitoring(true);
    let pfcp = server.local_addr().unwrap();
    let sessions = server.session_count_handle();
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
                0,
                fds.as_mut_ptr(),
            )
        },
        0
    );
    let dp = Arc::new(dp);
    let runtime = runtime::start(
        Arc::new(server),
        dp.clone(),
        rx,
        shutdown.clone(),
        runtime::RuntimeOptions {
            n6: runtime::N6::Fd(fds[0]),
            path_qos_probe_interval: Some(std::time::Duration::from_millis(100)),
            qos_flow_monitoring: Some((std::time::Duration::from_millis(100), false)),
            n6_delay_probe_interval: None,
        },
    );
    Upf {
        pfcp,
        sessions,
        dp,
        ip,
        runtime,
        shutdown,
        n6: (fds[0], fds[1]),
    }
}

/// The stand-in gNB: Echo Responses held [`GNB_ECHO_HOLD_MS`].
fn spawn_gnb_echo(sock: Arc<tokio::net::UdpSocket>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if n >= 12 && buf[1] == 1 {
                // Echo Request (TS 29.281 §7.2.1): answer with its sequence number.
                let mut resp = vec![0x32, 2, 0, 6];
                resp.extend_from_slice(&[0, 0, 0, 0]);
                resp.extend_from_slice(&buf[8..10]);
                resp.extend_from_slice(&[0, 0, 14, 0]);
                let s = sock.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(GNB_ECHO_HOLD_MS)).await;
                    let _ = s.send_to(&resp, from).await;
                });
            }
        }
    })
}

/// An uplink G-PDU on `teid` from the UE `ue`, its PDU Session Container carrying
/// the RAN DL and UL Delay Results (TS 38.415 §5.5.3.18-19).
fn ul_gpdu(teid: u32, qfi: u8, ue: [u8; 4]) -> Vec<u8> {
    use nextgcore_gtp::v1::types::{PduSessionContainer, UlPduSessionInformation};
    let c = PduSessionContainer::Ul(UlPduSessionInformation {
        qfi,
        dl_delay_result: Some(RAN_DL_MS),
        ul_delay_result: Some(RAN_UL_MS),
        ..Default::default()
    });
    let mut inner = vec![0u8; 28];
    inner[0] = 0x45;
    inner[2..4].copy_from_slice(&28u16.to_be_bytes());
    inner[8] = 64;
    inner[9] = 17;
    inner[12..16].copy_from_slice(&ue);
    inner[16..20].copy_from_slice(&[192, 0, 2, 1]);
    nextgcore_upfd::data_plane::build_relay_gpdu(teid, Some(&c.encode_content()), &inner).unwrap()
}

/// The SMF's N4 toward two in-process UPFs on one socket, the PSA as the pool's
/// only member and the other as the configured I-UPF; both associated.
async fn smf_toward(
    psa: &Upf,
    iupf_upf: &Upf,
) -> (tokio::task::JoinHandle<()>, Arc<pfcp_path::PfcpClient>) {
    let smf_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let psa_client = Arc::new(pfcp_path::PfcpClient::new(
        smf_sock.clone(),
        psa.pfcp,
        [127, 0, 0, 1],
    ));
    let iupf_client = Arc::new(pfcp_path::PfcpClient::new(
        smf_sock.clone(),
        iupf_upf.pfcp,
        [127, 0, 0, 1],
    ));
    let listener = spawn_pfcp_listener(smf_sock, vec![psa_client.clone(), iupf_client.clone()]);
    pfcp_path::set_global_pool(vec![psa_client.clone()]);
    iupf::set(Some((iupf_client.clone(), Vec::new())));
    psa_client.associate().await.expect("the PSA associates");
    iupf_client.associate().await.expect("the I-UPF associates");
    (listener, iupf_client)
}

/// Read one datagram from the test's end of a UPF's N6, waiting up to 3 s.
async fn n6_read(fd: RawFd) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 2048];
    for _ in 0..150 {
        let n = unsafe { libc::read(fd, out.as_mut_ptr() as *mut libc::c_void, out.len()) };
        if n > 0 {
            out.truncate(n as usize);
            return Some(out);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    None
}

/// #2208 step 2 (TS 23.502 §4.3.5.4): a session gets the I-UPF on N9 and its
/// traffic goes through it both ways. The NG-RAN is given the I-UPF's N3
/// F-TEID; an uplink G-PDU sent there leaves the PSA on N6; once the user plane
/// is active (the Update FAR 2 split: the I-UPF toward the gNB, the PSA toward
/// the I-UPF's N9 F-TEID) a downlink packet on the PSA's N6 reaches the gNB from
/// the I-UPF on the gNB's TEID. A release deletes the I-UPF's session with the
/// PSA's.
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_s_traffic_goes_through_the_i_upf_both_ways_2208() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = pfcp_path::N4_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    smf_context_init(64, 256, 512);
    std::env::remove_var("PCF_URI");
    let psa = upf(25).await;
    let iupf_upf = upf(26).await;
    let (listener, _) = smf_toward(&psa, &iupf_upf).await;

    let psi = 15u8;
    let n1_msg = n1(
        psi,
        1,
        gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
        &[0x91, 0x00],
    );
    let resp =
        handle_sm_context_create(&create_request("imsi-001010000022088", psi, &n1_msg)).await;
    assert_eq!(resp.status, 201, "created");
    let root: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
    let reference = root["smContextRef"].as_str().unwrap().to_string();
    let smf_seid = smf_n4_seid_for(&reference);
    let leg = iupf::leg_of(smf_seid).expect("the I-UPF is inserted");
    assert_eq!(
        iupf_upf.sessions.load(Ordering::SeqCst),
        1,
        "a session at the I-UPF"
    );
    assert_eq!(
        leg.n3.1,
        iupf_upf.ip.octets(),
        "the N3 F-TEID is the I-UPF's"
    );
    assert_eq!(leg.n9.1, iupf_upf.ip.octets());
    assert_eq!(
        leg.psa_ul.1,
        psa.ip.octets(),
        "the I-UPF forwards to the PSA"
    );
    let b = lookup_policy_binding(&reference).unwrap();

    // The NG-RAN is given the I-UPF's N3 F-TEID (the one the Setup Request
    // Transfer, a re-activation and a handover name).
    let n3 = lookup_upf_ul_endpoint(&reference).expect("an N3 endpoint for the NG-RAN");
    assert_eq!(n3, leg.n3, "the NG-RAN's uplink tunnel is the I-UPF's");

    // Uplink: gNB -> I-UPF (N3) -> PSA (N9) -> N6.
    let (gnb, gnb_ip) = bind_2152(27).await;
    let ul = ul_gpdu(n3.0, b.qfi, b.ue_ip);
    gnb.send_to(&ul, (iupf_upf.ip, 2152)).await.unwrap();
    let out = n6_read(psa.n6.1)
        .await
        .expect("the uplink leaves the PSA on N6");
    assert_eq!(&out[12..16], &b.ue_ip, "the UE's packet");

    // Activation, then downlink: N6 -> PSA -> I-UPF (N9) -> gNB (N3).
    pfcp_session_modify(
        smf_seid,
        lookup_upf_seid(&reference).unwrap(),
        0x2208,
        gnb_ip.octets(),
    )
    .await
    .expect("the user plane activates");
    let mut dl = [0u8; 28];
    dl[0] = 0x45;
    dl[2..4].copy_from_slice(&28u16.to_be_bytes());
    dl[8] = 64;
    dl[9] = 17;
    dl[12..16].copy_from_slice(&[192, 0, 2, 1]);
    dl[16..20].copy_from_slice(&b.ue_ip);
    let mut buf = vec![0u8; 2048];
    let mut got = None;
    for _ in 0..50 {
        unsafe { libc::write(psa.n6.1, dl.as_ptr() as *const libc::c_void, dl.len()) };
        if let Ok(Ok((n, from))) = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            gnb.recv_from(&mut buf),
        )
        .await
        {
            if n > 8 && buf[1] == 0xff {
                got = Some((buf[..n].to_vec(), from));
                break;
            }
        }
    }
    let (gpdu, from) = got.expect("the downlink reaches the gNB");
    assert_eq!(
        from.ip(),
        std::net::IpAddr::V4(iupf_upf.ip),
        "from the I-UPF"
    );
    assert_eq!(
        u32::from_be_bytes(gpdu[4..8].try_into().unwrap()),
        0x2208,
        "on the gNB's TEID"
    );

    // Release: both N4 sessions go.
    pfcp_session_delete(smf_seid, lookup_upf_seid(&reference).unwrap())
        .await
        .expect("the PSA session is deleted");
    assert!(
        iupf::leg_of(smf_seid).is_none(),
        "the I-UPF leg went with it"
    );
    assert_eq!(
        (
            psa.sessions.load(Ordering::SeqCst),
            iupf_upf.sessions.load(Ordering::SeqCst)
        ),
        (0, 0),
        "both UPFs' sessions are deleted"
    );

    listener.abort();
    cancel_gsm_timer_for_test(&reference);
    forget_seeded_session(&reference);
    iupf::set(None);
    pfcp_path::clear_global_upf_for_test();
}

/// #2208 criterion: the per-flow delay through an I-UPF, end to end.
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_per_flow_delay_through_an_i_upf_reaches_the_pcf_2208() {
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = pfcp_path::N4_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    let _e = event_exposure::lock_store();
    event_exposure::clear_for_test();
    qos_mon::clear_for_test();
    pcc_qos_mon::clear_for_test();
    let _pcc = pcc_qos_mon::PccForTest::on();
    let _method = pcc_qos_mon::MethodForTest::set(pcc_qos_mon::Method::GtpuPath);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    smf_context_init(64, 256, 512);

    // The two UPFs, and the SMF's N4 toward them.
    let psa = upf(22).await;
    let iupf_upf = upf(23).await;
    let (listener, _) = smf_toward(&psa, &iupf_upf).await;

    // The PCF: the policy in the create answer, QoS monitoring reports recorded.
    let reports: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
    let sink = reports.clone();
    let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let pcf_port = port_addr.port();
    let pcf = SbiServer::on_listener(
        SbiServerConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], pcf_port))),
        port_listener,
    );
    pcf.start(move |req: SbiRequest| {
        let sink = sink.clone();
        async move {
            if req.header.uri.ends_with("/sm-policies") {
                let mut d = serde_json::json!({
                    "sessRules": {},
                    "pccRules": { "r1": { "pccRuleId": "r1", "precedence": 10, "refQosMon": ["qm1"] } },
                    "qosMonDecs": { "qm1": {
                        "qmId": "qm1",
                        "reqQosMonParams": ["DOWNLINK", "UPLINK", "ROUND_TRIP"],
                        "repFreqs": ["PERIODIC"],
                        "repPeriod": 1,
                    }},
                    "policyCtrlReqTriggers": ["QOS_MONITORING"],
                });
                d["suppFeat"] = serde_json::json!("800100");
                return SbiResponse::with_status(201)
                    .with_header("Location", "/npcf-smpolicycontrol/v1/sm-policies/pol-2208e")
                    .with_body(d.to_string(), "application/json");
            }
            if req.header.uri.ends_with("/update") {
                if let Some(b) = req.http.content.as_deref().and_then(|c| serde_json::from_str(c).ok()) {
                    sink.lock().unwrap().push(b);
                }
                return SbiResponse::with_status(200).with_body("{}".to_string(), "application/json");
            }
            SbiResponse::with_status(204)
        }
    })
    .await
    .expect("stub PCF starts");
    std::env::set_var("PCF_URI", format!("http://127.0.0.1:{pcf_port}"));

    // The PDU session.
    let psi = 14u8;
    let n1_msg = n1(
        psi,
        1,
        gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
        &[0x91, 0x00],
    );
    let resp =
        handle_sm_context_create(&create_request("imsi-001010000022089", psi, &n1_msg)).await;
    assert_eq!(resp.status, 201, "created");
    let root: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
    let reference = root["smContextRef"].as_str().unwrap().to_string();
    let smf_seid = smf_n4_seid_for(&reference);
    let leg = iupf::leg_of(smf_seid).expect("the I-UPF is inserted");
    assert_eq!(
        leg.n3.1,
        iupf_upf.ip.octets(),
        "the N3 F-TEID is the I-UPF's"
    );
    assert_eq!(
        leg.psa_ul.1,
        psa.ip.octets(),
        "the I-UPF forwards to the PSA"
    );
    let b = lookup_policy_binding(&reference).unwrap();

    // The gNB answers PDU Session Resource Setup: the DL tunnel goes to the I-UPF.
    let (gnb, gnb_ip) = bind_2152(24).await;
    let gnb = Arc::new(gnb);
    let echo = spawn_gnb_echo(gnb.clone());
    pfcp_session_modify(
        smf_seid,
        lookup_upf_seid(&reference).unwrap(),
        0x2208,
        gnb_ip.octets(),
    )
    .await
    .expect("the user plane activates");
    qos_mon::on_user_plane_active(&reference);

    // Uplink for a few measurement periods. The first period can end before the
    // I-UPF's first Echo round to the gNB (an unknown N3 delay is not added,
    // #2197), so the report taken is one of a period that began after it: the
    // third with delays.
    let pkt = ul_gpdu(leg.n3.0, b.qfi, b.ue_ip);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut delays = None;
    while std::time::Instant::now() < deadline {
        let _ = gnb.send_to(&pkt, (iupf_upf.ip, 2152)).await;
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let got: Vec<serde_json::Value> = reports
            .lock()
            .unwrap()
            .iter()
            .flat_map(|b| b["qosMonReports"].as_array().cloned().unwrap_or_default())
            .filter(|r| r["dlDelays"].is_array())
            .collect();
        if got.len() >= 3 {
            delays = got.into_iter().nth(2);
            break;
        }
    }
    let r = delays.expect("QoS monitoring reports with delays reach the PCF");
    assert_eq!(r["refPccRuleIds"], serde_json::json!(["r1"]));
    let dl = r["dlDelays"][0].as_u64().unwrap();
    let ul = r["ulDelays"][0].as_u64().unwrap();
    let rt = r["rtDelays"][0].as_u64().unwrap();
    let n3 = GNB_ECHO_HOLD_MS / 2;
    // DL = N3 (the I-UPF's, ~hold/2) + N9 (the PSA's, ~0) + RAN DL; UL likewise.
    assert!(
        (RAN_DL_MS as u64 + n3..=RAN_DL_MS as u64 + n3 + 15).contains(&dl),
        "DL {dl} ms: RAN {RAN_DL_MS} + N3 ~{n3} + N9 ~0"
    );
    assert!(
        (RAN_UL_MS as u64 + n3..=RAN_UL_MS as u64 + n3 + 15).contains(&ul),
        "UL {ul} ms: RAN {RAN_UL_MS} + N3 ~{n3} + N9 ~0"
    );
    assert_eq!(rt, dl + ul, "RTT = DL + UL (TS 29.244 §5.24.5.4)");
    // Each UPF holds the IE 271 meant for it: the I-UPF toward the gNB (N3), the
    // PSA toward the I-UPF, as an N9 peer.
    let tdr = |u: &Upf, seid: u64| u.dp.with_transport_delay(|m| m.pdr(seid, 1));
    let at_iupf = tdr(&iupf_upf, leg.upf_seid).expect("the I-UPF's UL PDR has IE 271");
    assert_eq!(
        at_iupf.peer,
        std::net::IpAddr::V4(gnb_ip),
        "the I-UPF's preceding peer is the gNB"
    );
    assert!(!at_iupf.n9_peer);
    let at_psa =
        tdr(&psa, lookup_upf_seid(&reference).unwrap()).expect("the PSA's UL PDR has IE 271");
    assert_eq!(
        at_psa.peer,
        std::net::IpAddr::V4(iupf_upf.ip),
        "the PSA's preceding peer is the I-UPF"
    );
    assert!(at_psa.n9_peer, "an N9 peer (Destination Interface Core)");

    // Release: both N4 sessions go.
    std::env::remove_var("PCF_URI");
    pfcp_session_delete(smf_seid, lookup_upf_seid(&reference).unwrap())
        .await
        .expect("the PSA session is deleted");
    assert!(
        iupf::leg_of(smf_seid).is_none(),
        "the I-UPF leg went with it"
    );
    echo.abort();
    listener.abort();
    cancel_gsm_timer(&reference, timer::SmfTimerId::T3591);
    qos_mon::quiesce_for_test().await;
    cancel_gsm_timer_for_test(&reference);
    qos_mon::forget(&reference);
    pcc_qos_mon::clear_for_test();
    forget_seeded_session(&reference);
    iupf::set(None);
    pfcp_path::clear_global_upf_for_test();
    pcf.stop().await.ok();
}
