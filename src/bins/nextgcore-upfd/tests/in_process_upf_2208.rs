//! #2208: the UPF run in-process through its library, the way another crate's
//! test runs it: the PFCP server, the data plane on a GTP-U socket with N6 on a
//! datagram socket in place of the TUN device, and `runtime::start`, the same
//! tasks the binary starts. An SMF stand-in associates, establishes a session
//! with an uplink PDR (CHOOSE F-TEID) and a FAR toward N6, and a G-PDU sent to
//! the F-TEID the UPF chose comes out on N6 as the inner IP packet.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::RawFd;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use nextgcore_upfd::data_plane::DataPlane;
use nextgcore_upfd::pfcp_path::PfcpServer;
use nextgcore_upfd::runtime;
use tokio::net::UdpSocket;

fn tlv(t: u16, v: &[u8]) -> Vec<u8> {
    let mut b = t.to_be_bytes().to_vec();
    b.extend_from_slice(&(v.len() as u16).to_be_bytes());
    b.extend_from_slice(v);
    b
}

fn pfcp(msg_type: u8, seid: Option<u64>, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    match seid {
        Some(seid) => {
            pkt.extend_from_slice(&[0x21, msg_type]);
            pkt.extend_from_slice(&((12 + payload.len()) as u16).to_be_bytes());
            pkt.extend_from_slice(&seid.to_be_bytes());
        }
        None => {
            pkt.extend_from_slice(&[0x20, msg_type]);
            pkt.extend_from_slice(&((4 + payload.len()) as u16).to_be_bytes());
        }
    }
    pkt.extend_from_slice(&seq.to_be_bytes()[1..4]);
    pkt.push(0);
    pkt.extend_from_slice(payload);
    pkt
}

/// The top-level IEs of a PFCP message (header skipped), as (type, value).
fn ies(msg: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let skip = if msg[0] & 0x01 != 0 { 16 } else { 8 };
    parse_ies(&msg[skip..])
}

fn parse_ies(d: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= d.len() {
        let t = u16::from_be_bytes([d[at], d[at + 1]]);
        let l = u16::from_be_bytes([d[at + 2], d[at + 3]]) as usize;
        out.push((t, d[at + 4..at + 4 + l].to_vec()));
        at += 4 + l;
    }
    out
}

/// Send `pkt` and return the UPF's message of type `want`, skipping the requests
/// the UPF sends on its own meanwhile (its first Heartbeat Request follows the
/// association at once).
async fn exchange(sock: &UdpSocket, to: SocketAddr, pkt: &[u8], want: u8) -> Vec<u8> {
    sock.send_to(pkt, to).await.unwrap();
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("the UPF answers")
            .unwrap();
        if n > 1 && buf[1] == want {
            buf.truncate(n);
            return buf;
        }
    }
}

/// A non-blocking datagram socket pair: (the UPF's N6 end, the test's end).
fn n6_pair() -> (RawFd, RawFd) {
    let mut fds = [0 as libc::c_int; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
            0,
            fds.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0, "socketpair");
    (fds[0], fds[1])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_upf_runs_in_process_and_forwards_uplink_to_n6_2208() {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (tx, rx) = tokio::sync::mpsc::channel(100);
    let server = PfcpServer::new("127.0.0.1:0".parse().unwrap(), shutdown.clone(), tx)
        .await
        .unwrap();
    server
        .set_allowed_peers(nextgcore_pfcp::peer_policy::PeerAllowlist::parse("127.0.0.1").unwrap());
    let pfcp_addr = server.local_addr().unwrap();
    let server = Arc::new(server);
    let mut dp = DataPlane::new(shutdown.clone());
    dp.bind_gtpu("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let gtpu_addr = dp.gtpu_socket.as_ref().unwrap().local_addr().unwrap();
    let dp = Arc::new(dp);
    let (upf_n6, test_n6) = n6_pair();
    let rt = runtime::start(
        server.clone(),
        dp.clone(),
        rx,
        shutdown.clone(),
        runtime::RuntimeOptions {
            n6: runtime::N6::Fd(upf_n6),
            path_qos_probe_interval: None,
            qos_flow_monitoring: None,
            n6_delay_probe_interval: None,
        },
    );

    let smf = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Association Setup (TS 29.244 §7.4.4.1): Node ID IPv4, Recovery Time Stamp.
    let mut a = tlv(60, &[0, 127, 0, 0, 1]);
    a.extend(tlv(96, &0xe8a0_0000u32.to_be_bytes()));
    let resp = exchange(&smf, pfcp_addr, &pfcp(5, None, 1, &a), 6).await;
    assert_eq!(resp[1], 6, "Association Setup Response");
    let cause = ies(&resp).into_iter().find(|(t, _)| *t == 19).unwrap().1;
    assert_eq!(cause, vec![1], "accepted");

    // Session Establishment: UL PDR (Access, CHOOSE F-TEID, UE 10.45.0.7 source,
    // OHR GTP-U/UDP/IPv4) -> FAR FORW toward Core (N6).
    let ue = Ipv4Addr::new(10, 45, 0, 7);
    let mut pdi = tlv(20, &[0]);
    pdi.extend(tlv(21, &[0x05]));
    let mut ue_ie = vec![0x02];
    ue_ie.extend_from_slice(&ue.octets());
    pdi.extend(tlv(93, &ue_ie));
    let mut pdr = tlv(56, &1u16.to_be_bytes());
    pdr.extend(tlv(29, &100u32.to_be_bytes()));
    pdr.extend(tlv(2, &pdi));
    pdr.extend(tlv(95, &[0]));
    pdr.extend(tlv(108, &1u32.to_be_bytes()));
    let mut far = tlv(108, &1u32.to_be_bytes());
    far.extend(tlv(44, &[0x02, 0x00]));
    far.extend(tlv(4, &tlv(42, &[1])));
    let mut est = tlv(60, &[0, 127, 0, 0, 1]);
    let mut fseid = vec![0x02];
    fseid.extend_from_slice(&0x2208u64.to_be_bytes());
    fseid.extend_from_slice(&[127, 0, 0, 1]);
    est.extend(tlv(57, &fseid));
    est.extend(tlv(1, &pdr));
    est.extend(tlv(3, &far));
    let resp = exchange(&smf, pfcp_addr, &pfcp(50, Some(0), 2, &est), 51).await;
    assert_eq!(resp[1], 51, "Session Establishment Response");
    let got = ies(&resp);
    assert_eq!(
        got.iter().find(|(t, _)| *t == 19).unwrap().1,
        vec![1],
        "accepted"
    );
    let created = &got.iter().find(|(t, _)| *t == 8).expect("Created PDR").1;
    let fteid = parse_ies(created)
        .into_iter()
        .find(|(t, _)| *t == 21)
        .expect("the F-TEID the UPF chose")
        .1;
    let teid = u32::from_be_bytes(fteid[1..5].try_into().unwrap());

    // A G-PDU from the gNB carrying an IPv4 packet from the UE.
    let mut ip = vec![
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 45, 0, 7, 192, 0, 2, 1,
    ];
    ip.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0, 8, 0, 0]);
    let mut gpdu = vec![0x30, 0xff];
    gpdu.extend_from_slice(&(ip.len() as u16).to_be_bytes());
    gpdu.extend_from_slice(&teid.to_be_bytes());
    gpdu.extend_from_slice(&ip);
    let gnb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut out = vec![0u8; 2048];
    let mut n = -1isize;
    // The session event is applied off the PFCP answer path: resend until it is in.
    for _ in 0..100 {
        gnb.send_to(&gpdu, gtpu_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        n = unsafe { libc::read(test_n6, out.as_mut_ptr() as *mut libc::c_void, out.len()) };
        if n > 0 {
            break;
        }
    }
    assert!(n > 0, "the inner IP packet comes out on N6");
    assert_eq!(&out[..n as usize], &ip[..], "exactly the inner packet");

    rt.abort();
    shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    unsafe {
        libc::close(upf_n6);
        libc::close(test_n6);
    }
}
