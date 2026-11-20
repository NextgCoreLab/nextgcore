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
    /// Its data plane, to read the rules it holds.
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

    // R43 M3: AN release (BUFF|NOCP): the PSA buffers, so the downlink reaches
    // nobody meanwhile; on re-activation the buffered packet comes out of the
    // I-UPF to the (new) gNB tunnel. The probes sent above are drained first.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    while let Ok(Ok(_)) = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        gnb.recv_from(&mut buf),
    )
    .await
    {}
    pfcp_deactivate_dl_far(smf_seid, lookup_upf_seid(&reference).unwrap())
        .await
        .expect("the user plane is released");
    let mut marked = dl;
    marked[4] = 0x22; // an IP identification that tells this packet apart
    marked[5] = 0x08;
    unsafe {
        libc::write(
            psa.n6.1,
            marked.as_ptr() as *const libc::c_void,
            marked.len(),
        )
    };
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(300),
            gnb.recv_from(&mut buf)
        )
        .await
        .is_err(),
        "nothing reaches the gNB while the session is idle"
    );
    pfcp_session_modify(
        smf_seid,
        lookup_upf_seid(&reference).unwrap(),
        0x220a,
        gnb_ip.octets(),
    )
    .await
    .expect("the user plane is re-activated");
    // The I-UPF first sends the End Marker on the old tunnel (SNDEM, TS 29.281
    // §7.3.2), then the buffered G-PDU on the new one.
    let mut end_marker_on_old = false;
    let (n, from) = loop {
        let (n, from) =
            tokio::time::timeout(std::time::Duration::from_secs(3), gnb.recv_from(&mut buf))
                .await
                .expect("the buffered packet is delivered")
                .unwrap();
        if buf[1] == 0xfe {
            end_marker_on_old |= u32::from_be_bytes(buf[4..8].try_into().unwrap()) == 0x2208;
            continue;
        }
        break (n, from);
    };
    assert!(
        end_marker_on_old,
        "the End Marker on the old tunnel, from the I-UPF"
    );
    assert_eq!(
        from.ip(),
        std::net::IpAddr::V4(iupf_upf.ip),
        "through the I-UPF"
    );
    assert_eq!(
        u32::from_be_bytes(buf[4..8].try_into().unwrap()),
        0x220a,
        "on the new tunnel"
    );
    assert!(
        buf[..n].windows(2).any(|w| w == [0x22, 0x08]),
        "the packet the PSA buffered"
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
        (RAN_DL_MS as u64 + n3..=RAN_DL_MS as u64 + n3 + 40).contains(&dl),
        "DL {dl} ms: RAN {RAN_DL_MS} + N3 ~{n3} + N9 ~0"
    );
    assert!(
        (RAN_UL_MS as u64 + n3..=RAN_UL_MS as u64 + n3 + 40).contains(&ul),
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
    let source_type = |u: &Upf, seid: u64| {
        u.dp.sessions
            .find_by_seid(seid)
            .and_then(|s| s.pdr_source_types.read().unwrap().get(&1).copied())
    };
    assert_eq!(
        source_type(&iupf_upf, leg.upf_seid),
        None,
        "no IE 160 at the I-UPF"
    );
    let at_psa =
        tdr(&psa, lookup_upf_seid(&reference).unwrap()).expect("the PSA's UL PDR has IE 271");
    assert_eq!(
        at_psa.peer,
        std::net::IpAddr::V4(iupf_upf.ip),
        "the PSA's preceding peer is the I-UPF"
    );
    assert_eq!(
        source_type(&psa, lookup_upf_seid(&reference).unwrap()),
        Some(iupf::INTERFACE_TYPE_N9),
        "the PSA's UL PDR says N9 (IE 160, TS 29.244 §8.2.118)"
    );

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

/// The I-UPF's FAR 2, as its data plane holds it: (Apply Action, OHC TEID).
fn iupf_far2(u: &Upf, upf_seid: u64) -> (u16, Option<u32>) {
    let s =
        u.dp.sessions
            .find_by_seid(upf_seid)
            .expect("the I-UPF's session");
    let fars = s.fars.read().unwrap();
    let f = &fars[&crate::DL_FAR_ID];
    (f.apply_action, f.ohc_teid)
}

/// A session on the stand-in PSA (which can refuse) with the real I-UPF, for the
/// failure-path tests (R43 M1/M2 on #2243).
async fn session_with_refusing_psa(
    iupf_upf: &Upf,
    supi: &str,
    psi: u8,
) -> (
    pfcp_path::stand_in::StandInUpf,
    String,
    u64,
    iupf::IupfLeg,
    tokio::task::JoinHandle<()>,
) {
    let (psa, reference, seid, leg, listener, _, _) =
        session_with_refusing_psa_on(iupf_upf, supi, psi, None).await;
    (psa, reference, seid, leg, listener)
}

/// [`session_with_refusing_psa`], with the I-UPF client's Session Deletion
/// timer shortened when given, and its socket and client returned too.
#[allow(clippy::type_complexity)]
async fn session_with_refusing_psa_on(
    iupf_upf: &Upf,
    supi: &str,
    psi: u8,
    deletion_timer: Option<(std::time::Duration, u32)>,
) -> (
    pfcp_path::stand_in::StandInUpf,
    String,
    u64,
    iupf::IupfLeg,
    tokio::task::JoinHandle<()>,
    Arc<tokio::net::UdpSocket>,
    Arc<pfcp_path::PfcpClient>,
) {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let psa = pfcp_path::stand_in::associated_upf().await;
    smf_context_init(64, 256, 512);
    std::env::remove_var("PCF_URI");
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut client = pfcp_path::PfcpClient::new(sock.clone(), iupf_upf.pfcp, [127, 0, 0, 1]);
    if let Some((t1, n1)) = deletion_timer {
        client = client.with_deletion_timer_for_test(t1, n1);
    }
    let client = Arc::new(client);
    let listener = spawn_pfcp_listener(sock.clone(), vec![client.clone()]);
    iupf::set(Some((client.clone(), Vec::new())));
    client.associate().await.expect("the I-UPF associates");
    let n1_msg = n1(
        psi,
        1,
        gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
        &[0x91, 0x00],
    );
    let resp = handle_sm_context_create(&create_request(supi, psi, &n1_msg)).await;
    assert_eq!(resp.status, 201, "created");
    let root: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
    let reference = root["smContextRef"].as_str().unwrap().to_string();
    let seid = smf_n4_seid_for(&reference);
    let leg = iupf::leg_of(seid).expect("the I-UPF is inserted");
    (psa, reference, seid, leg, listener, sock, client)
}

/// R43 M1 on #2243, failure-path properties 1 and 3: a split modification the
/// PSA refuses, or one cancelled between its halves, leaves both UPFs as they
/// were.
/// - Toward active, the I-UPF goes first: a PSA refusal puts the I-UPF's FAR 2
///   back to BUFF; a cancellation between the halves puts it back to the
///   previous NG-RAN tunnel.
/// - Toward idle (an Apply Action change), the PSA goes first: a PSA refusal
///   leaves the I-UPF untouched; a cancellation between the halves puts the
///   PSA's FAR 2 back to FORW toward the I-UPF.
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_split_the_psa_refuses_or_that_is_cancelled_applies_nothing_2208() {
    use crate::n4_build::apply_action::{BUFF, FORW};
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    let iupf_upf = upf(28).await;
    let (psa, reference, seid, leg, listener) =
        session_with_refusing_psa(&iupf_upf, "imsi-001010000022087", 6).await;
    let upf_seid = lookup_upf_seid(&reference).unwrap();
    assert_eq!(
        iupf_far2(&iupf_upf, leg.upf_seid).0 & FORW,
        0,
        "buffering at first"
    );

    // Toward active, the PSA refuses: the I-UPF is put back to BUFF.
    psa.reject_modification(1);
    assert!(pfcp_session_modify(seid, upf_seid, 0x2208, [127, 0, 0, 77])
        .await
        .is_err());
    let (action, ohc) = iupf_far2(&iupf_upf, leg.upf_seid);
    assert_eq!(
        (action & FORW, action & BUFF),
        (0, BUFF),
        "the I-UPF buffers again: {action:#x} {ohc:?}"
    );

    // Activated for real.
    pfcp_session_modify(seid, upf_seid, 0x2208, [127, 0, 0, 77])
        .await
        .expect("activated");
    assert_eq!(iupf_far2(&iupf_upf, leg.upf_seid), (FORW, Some(0x2208)));

    // Toward active, cancelled between the halves: back to the previous tunnel.
    let hold = iupf::BetweenLegs::arm();
    let task = tokio::spawn(async move {
        let _ = pfcp_session_modify(seid, upf_seid, 0x2209, [127, 0, 0, 78]).await;
    });
    hold.reached.notified().await;
    assert_eq!(
        iupf_far2(&iupf_upf, leg.upf_seid).1,
        Some(0x2209),
        "the I-UPF half is applied"
    );
    task.abort();
    let _ = task.await;
    drop(hold);
    wait_until(|| iupf_far2(&iupf_upf, leg.upf_seid).1 == Some(0x2208)).await;
    assert_eq!(
        iupf_far2(&iupf_upf, leg.upf_seid),
        (FORW, Some(0x2208)),
        "the previous tunnel"
    );

    // Toward idle, the PSA refuses: the PSA goes first, so the I-UPF is untouched.
    psa.reject_modification(1);
    assert!(pfcp_deactivate_dl_far(seid, upf_seid).await.is_err());
    assert_eq!(
        iupf_far2(&iupf_upf, leg.upf_seid),
        (FORW, Some(0x2208)),
        "the I-UPF still forwards"
    );

    // Toward idle, cancelled between the halves: the PSA's FAR 2 is put back to
    // FORW toward the I-UPF's N9 F-TEID, and the I-UPF never heard of it.
    psa.clear_seen();
    let hold = iupf::BetweenLegs::arm();
    let task = tokio::spawn(async move {
        let _ = pfcp_deactivate_dl_far(seid, upf_seid).await;
    });
    hold.reached.notified().await;
    task.abort();
    let _ = task.await;
    drop(hold);
    let n9 = leg.n9;
    wait_until(|| psa.modification_bodies().len() >= 2).await;
    let bodies = psa.modification_bodies();
    let restored = bodies.last().unwrap();
    let ohc = pfcp_path::find_ie(restored, 10)
        .and_then(|f| pfcp_path::find_ie(f, 11))
        .and_then(|fp| pfcp_path::find_ie(fp, 84));
    assert_eq!(
        ohc.map(|o| (
            u32::from_be_bytes(o[2..6].try_into().unwrap()),
            [o[6], o[7], o[8], o[9]]
        )),
        Some(n9),
        "the PSA's FAR 2 forwards to the I-UPF again"
    );
    assert_eq!(
        iupf_far2(&iupf_upf, leg.upf_seid),
        (FORW, Some(0x2208)),
        "the I-UPF never stopped"
    );

    // R43 on #2243, minor 2: cancelled while the first half (the PSA's) is in
    // flight: whether or not the PSA applied it, it is undone.
    psa.clear_seen();
    psa.delay_modifications(300);
    let task = tokio::spawn(async move {
        let _ = pfcp_deactivate_dl_far(seid, upf_seid).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    task.abort();
    let _ = task.await;
    wait_until(|| psa.modification_bodies().len() >= 2).await;
    psa.delay_modifications(0);
    let bodies = psa.modification_bodies();
    let ohc = pfcp_path::find_ie(bodies.last().unwrap(), 10)
        .and_then(|f| pfcp_path::find_ie(f, 11))
        .and_then(|fp| pfcp_path::find_ie(fp, 84));
    assert_eq!(
        ohc.map(|o| (
            u32::from_be_bytes(o[2..6].try_into().unwrap()),
            [o[6], o[7], o[8], o[9]]
        )),
        Some(n9),
        "undone even though the PSA's half was still in flight"
    );
    assert_eq!(iupf_far2(&iupf_upf, leg.upf_seid), (FORW, Some(0x2208)));

    listener.abort();
    iupf::forget(seid);
    cancel_gsm_timer_for_test(&reference);
    forget_seeded_session(&reference);
    iupf::set(None);
    drop(psa);
}

/// R43 M2 on #2243: a PSA session that goes without an N4 Deletion (here the
/// PSA's association is torn down, TS 23.527 §4.2) releases its I-UPF leg: the
/// I-UPF's session is deleted and the leg forgotten.
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_psa_teardown_deletes_the_i_upf_session_2208() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    let iupf_upf = upf(29).await;
    let (psa, reference, seid, _leg, listener) =
        session_with_refusing_psa(&iupf_upf, "imsi-001010000022086", 7).await;
    assert_eq!(iupf_upf.sessions.load(Ordering::SeqCst), 1);
    psa.client
        .teardown_association("test: the PSA restarted")
        .await;
    wait_until(|| iupf_upf.sessions.load(Ordering::SeqCst) == 0).await;
    assert_eq!(
        iupf_upf.sessions.load(Ordering::SeqCst),
        0,
        "the I-UPF's session is deleted"
    );
    assert!(iupf::leg_of(seid).is_none(), "and the leg forgotten");
    listener.abort();
    cancel_gsm_timer_for_test(&reference);
    forget_seeded_session(&reference);
    iupf::set(None);
    drop(psa);
}

/// The PSA's FAR 2 Apply Action in the last Session Modification the stand-in
/// PSA received, if it carried one.
fn last_psa_far2_action(psa: &pfcp_path::stand_in::StandInUpf) -> Option<u16> {
    let bodies = psa.modification_bodies();
    let far = pfcp_path::find_ie(bodies.last()?, 10)?;
    let id = pfcp_path::find_ie(far, 108)?;
    if u32::from_be_bytes(id.get(..4)?.try_into().ok()?) != crate::DL_FAR_ID {
        return None;
    }
    let a = pfcp_path::find_ie(far, 44)?;
    Some(u16::from(*a.first()?) | (u16::from(a.get(1).copied().unwrap_or(0)) << 8))
}

/// #2225, criterion 1 (TS 23.527 §4.3.4): the I-UPF's association is lost. Its
/// PSA session is alive, so it is deleted there, not flushed, and released (#39
/// when an AMF is known). The leg is forgotten. The I-UPF's session, which it
/// kept (no restart), waits in the deletion queue and is deleted once the I-UPF
/// is associated again (R43's fire-and-forget note on #2243).
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_i_upf_loss_releases_its_sessions_at_the_psa_2225() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    iupf::clear_pending_deletions();
    let iupf_upf = upf(30).await;
    let (psa, reference, seid, _leg, listener) =
        session_with_refusing_psa(&iupf_upf, "imsi-001010000022250", 5).await;
    assert_eq!(iupf_upf.sessions.load(Ordering::SeqCst), 1);
    let client = iupf::client().expect("the I-UPF");
    assert!(
        pfcp_path::holds_session_seid(iupf::leg_seid(seid)),
        "the leg is held"
    );
    psa.clear_seen();

    client
        .teardown_association("test: the I-UPF's heartbeat was lost")
        .await;
    assert!(iupf::leg_of(seid).is_none(), "the leg is forgotten");
    wait_until(|| {
        psa.seen()
            .contains(&pfcp_path::pfcp_message_type::SESSION_DELETION_REQUEST)
    })
    .await;
    assert!(
        psa.seen()
            .contains(&pfcp_path::pfcp_message_type::SESSION_DELETION_REQUEST),
        "the session is deleted at its live PSA: {:?}",
        psa.seen()
    );
    assert_eq!(
        iupf::pending_deletions(),
        1,
        "the I-UPF's session waits for the I-UPF"
    );
    assert_eq!(iupf_upf.sessions.load(Ordering::SeqCst), 1);

    client
        .associate()
        .await
        .expect("the I-UPF associates again");
    wait_until(|| iupf_upf.sessions.load(Ordering::SeqCst) == 0).await;
    assert_eq!(
        iupf_upf.sessions.load(Ordering::SeqCst),
        0,
        "the queued deletion reached the I-UPF"
    );
    wait_until(|| iupf::pending_deletions() == 0).await;
    assert_eq!(iupf::pending_deletions(), 0);

    listener.abort();
    cancel_gsm_timer_for_test(&reference);
    forget_seeded_session(&reference);
    iupf::set(None);
    drop(psa);
}

/// #2225, criterion 2 (TS 29.244 §5.10A, TS 23.527 §5.4): the I-UPF reports its
/// GTP-U path toward the NG-RAN failed, in a real Node Report Request through its
/// client's N4 engine.
/// - At once, the session's access side is deactivated: the PSA's FAR 2 gets
///   BUFF|NOCP and, through the split, the I-UPF's FAR 2 stops forwarding.
/// - After the hold, the session still points at the failed peer and is
///   released: deleted at the PSA, and its I-UPF session deleted with it.
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_i_upf_path_failure_deactivates_then_releases_its_sessions_2225() {
    use crate::n4_build::apply_action::{BUFF, FORW, NOCP};
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    up_path::reset_for_test();
    iupf::clear_pending_deletions();
    let iupf_upf = upf(31).await;
    let (psa, reference, seid, leg, listener) =
        session_with_refusing_psa(&iupf_upf, "imsi-001010000022251", 5).await;
    let upf_seid = lookup_upf_seid(&reference).unwrap();
    let gnb = [127, 0, 0, 81];
    pfcp_session_modify(seid, upf_seid, 0x2251, gnb)
        .await
        .expect("activated");
    assert_eq!(iupf_far2(&iupf_upf, leg.upf_seid), (FORW, Some(0x2251)));
    psa.clear_seen();
    up_path::set_hold_for_test(Some(std::time::Duration::from_millis(600)));

    // Node ID (IPv4) | Node Report Type UPFR | UPFR { Remote GTP-U Peer V4 gNB }.
    let mut body = vec![0, 60, 0, 5, 0];
    body.extend_from_slice(&iupf_upf.ip.octets());
    body.extend_from_slice(&[0, 101, 0, 1, 0x01]);
    body.extend_from_slice(&[0, 102, 0, 9, 0, 103, 0, 5, 0x02]);
    body.extend_from_slice(&gnb);
    let pkt = pfcp_path::encode_wire_message(
        pfcp_path::pfcp_message_type::NODE_REPORT_REQUEST,
        None,
        0x2251,
        &body,
    );
    let client = iupf::client().expect("the I-UPF");
    assert!(client.on_datagram(&pkt, iupf_upf.pfcp).await, "consumed");

    wait_until(|| last_psa_far2_action(&psa).is_some_and(|a| a & NOCP != 0)).await;
    let a = last_psa_far2_action(&psa).expect("the PSA's FAR 2 is updated");
    assert_eq!(
        (a & FORW, a & BUFF, a & NOCP),
        (0, BUFF, NOCP),
        "the PSA buffers"
    );
    wait_until(|| iupf_far2(&iupf_upf, leg.upf_seid).0 & FORW == 0).await;
    assert_eq!(
        iupf_far2(&iupf_upf, leg.upf_seid).0 & FORW,
        0,
        "the I-UPF stops forwarding toward the failed NG-RAN"
    );

    wait_until(|| {
        psa.seen()
            .contains(&pfcp_path::pfcp_message_type::SESSION_DELETION_REQUEST)
    })
    .await;
    assert!(
        psa.seen()
            .contains(&pfcp_path::pfcp_message_type::SESSION_DELETION_REQUEST),
        "released after the hold"
    );
    wait_until(|| iupf_upf.sessions.load(Ordering::SeqCst) == 0).await;
    assert_eq!(iupf_upf.sessions.load(Ordering::SeqCst), 0);

    up_path::reset_for_test();
    listener.abort();
    cancel_gsm_timer_for_test(&reference);
    forget_seeded_session(&reference);
    iupf::set(None);
    drop(psa);
}

/// #2225, criterion 3 (TS 23.527 §5.3.3.2): an Error Indication Report from the
/// I-UPF names its leg's SEID. It is accepted as the PSA session's (cause 1, with
/// the I-UPF's SEID in the header), and the session's user plane is deactivated,
/// not deleted: the I-UPF is controlled by this SMF.
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_i_upf_error_indication_report_is_its_psa_session_s_2225() {
    use crate::n4_build::apply_action::{BUFF, FORW, NOCP};
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    up_path::reset_for_test();
    let iupf_upf = upf(32).await;
    let (psa, reference, seid, leg, listener) =
        session_with_refusing_psa(&iupf_upf, "imsi-001010000022252", 5).await;
    let upf_seid = lookup_upf_seid(&reference).unwrap();
    let gnb = [127, 0, 0, 82];
    pfcp_session_modify(seid, upf_seid, 0x2252, gnb)
        .await
        .expect("activated");
    psa.clear_seen();

    // Report Type ERIR | Error Indication Report { Remote F-TEID V4 0x2252 gNB }.
    let mut body = vec![0, 39, 0, 1, 0x04];
    body.extend_from_slice(&[0, 99, 0, 13, 0, 21, 0, 9, 0x01, 0, 0, 0x22, 0x52]);
    body.extend_from_slice(&gnb);
    let pkt = pfcp_path::encode_wire_message(
        pfcp_path::pfcp_message_type::SESSION_REPORT_REQUEST,
        Some(leg.smf_seid),
        0x2252,
        &body,
    );
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = iupf::client().expect("the I-UPF");
    handle_pfcp_session_report_from(&sock, &pkt, peer.local_addr().unwrap(), Some(&client)).await;
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv(&mut buf))
        .await
        .expect("answered")
        .unwrap();
    let resp = &buf[..n];
    assert_eq!(
        resp[1],
        pfcp_path::pfcp_message_type::SESSION_REPORT_RESPONSE
    );
    assert_eq!(
        u64::from_be_bytes(resp[4..12].try_into().unwrap()),
        leg.upf_seid,
        "the I-UPF's SEID in the header (TS 29.244 §7.2.2.4.1)"
    );
    assert_eq!(pfcp_path::parse_cause(&resp[16..]), Some(1), "accepted");

    wait_until(|| last_psa_far2_action(&psa).is_some_and(|a| a & NOCP != 0)).await;
    let a = last_psa_far2_action(&psa).expect("the PSA's FAR 2 is updated");
    assert_eq!((a & FORW, a & BUFF), (0, BUFF), "the PSA buffers");
    wait_until(|| iupf_far2(&iupf_upf, leg.upf_seid).0 & FORW == 0).await;
    assert_eq!(iupf_far2(&iupf_upf, leg.upf_seid).0 & FORW, 0);
    assert!(
        !psa.seen()
            .contains(&pfcp_path::pfcp_message_type::SESSION_DELETION_REQUEST),
        "deactivated, not deleted"
    );

    // The I-UPF's N9 uplink rejected by the PSA (an Error Indication on the leg's
    // FAR 1): still the access side that is deactivated, the PSA's FAR 2, never
    // the PSA's own FAR 1, which is its N6.
    pfcp_session_modify(seid, upf_seid, 0x2252, gnb)
        .await
        .expect("active again");
    psa.clear_seen();
    let mut body = vec![0, 39, 0, 1, 0x04];
    body.extend_from_slice(&[0, 99, 0, 13, 0, 21, 0, 9, 0x01]);
    body.extend_from_slice(&leg.psa_ul.0.to_be_bytes());
    body.extend_from_slice(&leg.psa_ul.1);
    let pkt = pfcp_path::encode_wire_message(
        pfcp_path::pfcp_message_type::SESSION_REPORT_REQUEST,
        Some(leg.smf_seid),
        0x2253,
        &body,
    );
    handle_pfcp_session_report_from(&sock, &pkt, peer.local_addr().unwrap(), Some(&client)).await;
    wait_until(|| !psa.modification_bodies().is_empty()).await;
    let bodies = psa.modification_bodies();
    let far_ids: Vec<u32> = bodies
        .iter()
        .filter_map(|b| pfcp_path::find_ie(b, 10))
        .filter_map(|f| pfcp_path::find_ie(f, 108))
        .map(|id| u32::from_be_bytes(id[..4].try_into().unwrap()))
        .collect();
    assert_eq!(far_ids, vec![crate::DL_FAR_ID], "the PSA's FAR 2 only");

    up_path::reset_for_test();
    listener.abort();
    iupf::forget(seid);
    cancel_gsm_timer_for_test(&reference);
    forget_seeded_session(&reference);
    iupf::set(None);
    drop(psa);
}

/// #2225, criterion 3: a Downlink Data Report from the I-UPF (its FAR 2 has
/// BUFF|NOCP at AN release) names its leg's SEID, and pages the UE of the PSA
/// session through its serving AMF (TS 23.502 §4.2.3.3).
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_i_upf_downlink_data_report_pages_for_its_psa_session_2225() {
    use nextgcore_sbi::message::SbiResponse;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    let iupf_upf = upf(33).await;
    let (psa, reference, seid, leg, listener) =
        session_with_refusing_psa(&iupf_upf, "imsi-001010000022253", 5).await;

    let uris: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let sink = uris.clone();
    let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let amf = SbiServer::on_listener(
        SbiServerConfig::new(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            port_addr.port(),
        ))),
        port_listener,
    );
    amf.start(move |req: SbiRequest| {
        let sink = sink.clone();
        async move {
            sink.lock().unwrap().push(req.header.uri.clone());
            SbiResponse::with_status(200)
        }
    })
    .await
    .expect("amf start");
    {
        let ctx = smf_self();
        let c = ctx.read().unwrap();
        let mut sess = c.sess_find_by_sm_context_ref(&reference).expect("session");
        sess.up_cnx_state = context::UpCnxState::Deactivated;
        sess.sm_context_status_uri = Some(format!("http://127.0.0.1:{}", port_addr.port()));
        c.sess_update(&sess);
        let mut bindings = c.policy_bindings.write().unwrap();
        if let Some(b) = bindings.get_mut(&reference) {
            b.sm_context_status_uri = Some(format!("http://127.0.0.1:{}", port_addr.port()));
        }
        drop(bindings);
        drop(c);
    }

    // Report Type DLDR | Downlink Data Report { PDR ID 2 }.
    let body = [0, 39, 0, 1, 0x01, 0, 83, 0, 6, 0, 56, 0, 2, 0, 2];
    let pkt = pfcp_path::encode_wire_message(
        pfcp_path::pfcp_message_type::SESSION_REPORT_REQUEST,
        Some(leg.smf_seid),
        0x2253,
        &body,
    );
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = iupf::client().expect("the I-UPF");
    handle_pfcp_session_report_from(&sock, &pkt, "127.0.0.1:9".parse().unwrap(), Some(&client))
        .await;
    wait_until(|| !uris.lock().unwrap().is_empty()).await;
    let seen = uris.lock().unwrap().clone();
    assert!(
        seen.iter().any(|u| u.contains("/n1-n2-messages")),
        "the UE is paged through its AMF: {seen:?}"
    );

    let _ = amf.stop().await;
    listener.abort();
    iupf::forget(seid);
    cancel_gsm_timer_for_test(&reference);
    forget_seeded_session(&reference);
    iupf::set(None);
    drop(psa);
}

/// R45 M1 on #2268: a restarted I-UPF holds none of the old sessions, and counts
/// its SEIDs from the start again. The deletion queued at the loss names an old
/// I-UPF SEID that a new session's leg can now have. The new association does
/// not confirm retention, so the queue is dropped unsent, no resend pass starts,
/// and the new leg survives.
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_i_upf_gets_no_stale_deletion_and_its_new_leg_survives_2225() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    iupf::clear_pending_deletions();
    let old = upf(34).await;
    let (psa, reference, _seid, leg, listener, _, client) =
        session_with_refusing_psa_on(&old, "imsi-001010000022254", 5, None).await;
    client
        .teardown_association("test: the I-UPF's Recovery Time Stamp changed")
        .await;
    assert_eq!(
        iupf::pending_deletion_list(),
        vec![(leg.smf_seid, leg.upf_seid)],
        "queued at the loss"
    );

    // The restarted I-UPF: a fresh upfd, whose SEIDs start again.
    let fresh = upf(35).await;
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let restarted = Arc::new(pfcp_path::PfcpClient::new(
        sock.clone(),
        fresh.pfcp,
        [127, 0, 0, 1],
    ));
    let fresh_listener = spawn_pfcp_listener(sock, vec![restarted.clone()]);
    iupf::set(Some((restarted.clone(), Vec::new())));
    let passes = iupf::RETRY_PASSES.load(Ordering::SeqCst);
    let hold = iupf::BeforeRetry::arm();
    restarted
        .associate()
        .await
        .expect("the restarted I-UPF associates");
    assert_eq!(iupf::pending_deletions(), 0, "dropped: not retained");
    assert_eq!(
        iupf::RETRY_PASSES.load(Ordering::SeqCst),
        passes,
        "no deletion is resent to a restarted I-UPF"
    );

    // A new session's leg on the restarted I-UPF has the old leg's I-UPF SEID.
    let n1_msg = n1(
        6,
        1,
        gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
        &[0x91, 0x00],
    );
    let resp = handle_sm_context_create(&create_request("imsi-001010000022255", 6, &n1_msg)).await;
    assert_eq!(resp.status, 201, "created");
    let root: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
    let reference_b = root["smContextRef"].as_str().unwrap().to_string();
    let leg_b = iupf::leg_of(smf_n4_seid_for(&reference_b)).expect("a new leg");
    assert_eq!(leg_b.upf_seid, leg.upf_seid, "the SEID is reused");
    drop(hold);
    iupf::retry_pending_deletions();
    assert!(!iupf::retry_running(), "nothing to resend");
    assert_eq!(
        fresh.sessions.load(Ordering::SeqCst),
        1,
        "the new leg survives"
    );

    fresh_listener.abort();
    listener.abort();
    for r in [&reference, &reference_b] {
        iupf::forget(smf_n4_seid_for(r));
        cancel_gsm_timer_for_test(r);
        forget_seeded_session(r);
    }
    iupf::set(None);
    drop(psa);
}

/// R45 M2 on #2268 (R43's note on #2243): an ordinary leg deletion the I-UPF
/// does not answer is queued. At the next association, which confirms retention,
/// it is resent and reaches the I-UPF.
///
/// REVERT-VERIFIED: see the PR.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unanswered_leg_deletion_is_queued_and_resent_once_retained_2225() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _q = qos_mon::TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    iupf::clear_pending_deletions();
    let iupf_upf = upf(36).await;
    let (psa, reference, seid, leg, listener, sock, client) = session_with_refusing_psa_on(
        &iupf_upf,
        "imsi-001010000022256",
        5,
        Some((std::time::Duration::from_millis(50), 1)),
    )
    .await;
    let upf_seid = lookup_upf_seid(&reference).unwrap();
    // The I-UPF's answers are no longer read: its deletion goes unanswered.
    listener.abort();
    let _ = listener.await;
    let _ = pfcp_session_delete(seid, upf_seid).await;
    assert_eq!(
        iupf::pending_deletion_list(),
        vec![(leg.smf_seid, leg.upf_seid)],
        "queued"
    );
    // The I-UPF may have acted on it; only its answer went unread.

    let listener = spawn_pfcp_listener(sock, vec![client.clone()]);
    let passes = iupf::RETRY_PASSES.load(Ordering::SeqCst);
    client
        .associate()
        .await
        .expect("the I-UPF associates again");
    assert_eq!(
        iupf::RETRY_PASSES.load(Ordering::SeqCst),
        passes + 1,
        "the retaining I-UPF is sent the queue"
    );
    // Resent: the entry goes only when the I-UPF answers it.
    wait_until(|| iupf::pending_deletions() == 0).await;
    assert_eq!(iupf::pending_deletions(), 0, "resent and answered");
    assert_eq!(iupf_upf.sessions.load(Ordering::SeqCst), 0);

    listener.abort();
    cancel_gsm_timer_for_test(&reference);
    forget_seeded_session(&reference);
    iupf::set(None);
    drop(psa);
}

/// R45 M2 on #2268: the queue holds MAX_PENDING_DELETIONS, drops the oldest
/// beyond that, and takes each SMF SEID once.
#[tokio::test]
async fn the_deletion_queue_is_bounded_and_drops_the_oldest_2225() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    iupf::clear_pending_deletions();
    for i in 0..=iupf::MAX_PENDING_DELETIONS as u64 {
        iupf::queue_deletion(i, 100 + i);
    }
    let q = iupf::pending_deletion_list();
    assert_eq!(q.len(), iupf::MAX_PENDING_DELETIONS);
    assert_eq!(q.first(), Some(&(1, 101)), "the oldest went");
    assert_eq!(q.last(), Some(&(4096, 4196)));
    iupf::queue_deletion(5, 999);
    assert_eq!(
        iupf::pending_deletions(),
        iupf::MAX_PENDING_DELETIONS,
        "once"
    );
    iupf::queue_deletion(0, 100);
    assert_eq!(
        iupf::pending_deletion_list().first(),
        Some(&(2, 102)),
        "an evicted SEID can be queued again"
    );
    iupf::clear_pending_deletions();
}

/// R45 m1 on #2268: one resend pass at a time, and a pass stops at the first
/// deletion the I-UPF does not answer, leaving it and the rest queued in order.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resend_pass_is_single_and_stops_at_the_first_unanswered_2225() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    iupf::clear_pending_deletions();
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let heard = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = heard.clone();
    let ear = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while silent.recv(&mut buf).await.is_ok() {
            h.fetch_add(1, Ordering::SeqCst);
        }
    });
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = Arc::new(
        pfcp_path::PfcpClient::new(sock, silent_addr, [127, 0, 0, 1])
            .with_deletion_timer_for_test(std::time::Duration::from_millis(50), 0),
    );
    client.set_assoc_state_for_test(true, None, None).await;
    iupf::set(Some((client.clone(), Vec::new())));
    for i in 1..=3u64 {
        iupf::queue_deletion(iupf::leg_seid(i << 4), i);
    }
    let passes = iupf::RETRY_PASSES.load(Ordering::SeqCst);
    let hold = iupf::BeforeRetry::arm();
    iupf::retry_pending_deletions();
    hold.reached.notified().await;
    iupf::retry_pending_deletions();
    assert_eq!(
        iupf::RETRY_PASSES.load(Ordering::SeqCst),
        passes + 1,
        "a second setup starts no second pass"
    );
    drop(hold);
    wait_until(|| !iupf::retry_running()).await;
    assert!(!iupf::retry_running());
    assert_eq!(heard.load(Ordering::SeqCst), 1, "stopped at the first");
    assert_eq!(
        iupf::pending_deletion_list(),
        (1..=3u64)
            .map(|i| (iupf::leg_seid(i << 4), i))
            .collect::<Vec<_>>(),
        "all three still queued, in order"
    );
    ear.abort();
    iupf::clear_pending_deletions();
    iupf::set(None);
}
