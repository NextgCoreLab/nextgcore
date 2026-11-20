//! #2208 in process: this SMF and two REAL UPFs, through the `nextgcore_upfd`
//! library (#2208 step 1): its PFCP server, its data plane on real UDP sockets
//! with N6 on a datagram socket in place of the TUN device, and `runtime::start`,
//! which starts the tasks the binary starts. One UPF is the PSA, the other the
//! I-UPF that `smf.intermediate_upf` names. A UDP socket on port 2152 stands in
//! for the gNB.
//!
//! What this does not prove: the real binary's TUN path and its process wiring
//! (#2222, the nightly docker run).

use super::*;
use std::os::unix::io::RawFd;

use nextgcore_upfd::data_plane::DataPlane;
use nextgcore_upfd::pfcp_path::PfcpServer;
use nextgcore_upfd::runtime;

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
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let psa = pfcp_path::stand_in::associated_upf().await;
    smf_context_init(64, 256, 512);
    std::env::remove_var("PCF_URI");
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = Arc::new(pfcp_path::PfcpClient::new(
        sock.clone(),
        iupf_upf.pfcp,
        [127, 0, 0, 1],
    ));
    let listener = spawn_pfcp_listener(sock, vec![client.clone()]);
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
    (psa, reference, seid, leg, listener)
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
