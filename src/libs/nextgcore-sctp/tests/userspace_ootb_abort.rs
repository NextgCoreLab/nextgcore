//! #1142: the userspace SCTP server tells its peers when their association is gone.
//!
//! - A restarted server answers the packets of an association it no longer has with
//!   an ABORT (RFC 9260 §8.4). Its peer (the gNB of a restarted AMF) then notices at
//!   once, instead of after Association.Max.Retrans.
//! - A stopping server ends its associations with a SHUTDOWN (§9.2).
//!
//! Both are driven with a minimal sctp-proto client over real UDP sockets.

#![cfg(feature = "sctp-proto")]

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use nextgcore_sctp::{SctpServer, SctpServerConfig, NGAP_PPID};
use sctp_proto::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Payload,
    PayloadProtocolIdentifier, Transmit,
};
use tokio::{net::UdpSocket, sync::oneshot, time::timeout};

/// The smallest sctp-proto client that can open an association, send on a
/// stream with a chosen PPID, and read one message back. nextgcore has no
/// production SCTP client (#205), so this lives in the test.
struct TestClient {
    socket: UdpSocket,
    endpoint: Endpoint,
    handle: AssociationHandle,
    association: Association,
    outbox: VecDeque<Transmit>,
}

impl TestClient {
    async fn connect(remote: SocketAddr) -> Self {
        Self::connect_with(remote, ClientConfig::new()).await
    }

    async fn connect_with(remote: SocketAddr, config: ClientConfig) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::new()), None);
        let (handle, association) = endpoint
            .connect(config, remote)
            .expect("initiate association");
        let mut client = Self {
            socket,
            endpoint,
            handle,
            association,
            outbox: VecDeque::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while client.association.is_handshaking() {
            assert!(Instant::now() < deadline, "handshake within 5 s");
            client.pump(Duration::from_millis(50)).await;
        }
        client
    }

    /// Flush outbound packets, then wait up to `wait` for one inbound packet.
    async fn pump(&mut self, wait: Duration) {
        while self.association.poll().is_some() {}
        if let Some(t) = self.association.poll_timeout() {
            if Instant::now() >= t {
                self.association.handle_timeout(Instant::now());
            }
        }
        while let Some(t) = self.association.poll_transmit(Instant::now()) {
            self.outbox.push_back(t);
        }
        while let Some(t) = self.endpoint.poll_transmit() {
            self.outbox.push_back(t);
        }
        while let Some(t) = self.outbox.pop_front() {
            if let Payload::RawEncode(chunks) = &t.payload {
                for c in chunks {
                    let _ = self.socket.send_to(c, t.remote).await;
                }
            }
        }
        let mut buf = vec![0u8; 65536];
        if let Ok(Ok((n, from))) = timeout(wait, self.socket.recv_from(&mut buf)).await {
            buf.truncate(n);
            if let Some((h, DatagramEvent::AssociationEvent(ev))) =
                self.endpoint
                    .handle(Instant::now(), from, None, None, Bytes::from(buf))
            {
                if h == self.handle {
                    self.association.handle_event(ev);
                }
            }
        }
    }

    async fn send(&mut self, stream_id: u16, data: &[u8], ppid: u32) {
        let ppi = PayloadProtocolIdentifier::from(ppid);
        let mut stream = match self.association.stream(stream_id) {
            Ok(s) => s,
            Err(_) => self
                .association
                .open_stream(stream_id, ppi)
                .expect("open stream"),
        };
        stream.write_with_ppi(data, ppi).expect("write");
        self.pump(Duration::from_millis(1)).await;
    }

    /// Wait for one message on `stream_id`; returns its payload and PPID.
    async fn recv_on(&mut self, stream_id: u16) -> (Vec<u8>, u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            while let Some(s) = self.association.accept_stream() {
                let _ = s.stream_identifier();
            }
            if let Ok(mut s) = self.association.stream(stream_id) {
                if let Ok(Some(chunks)) = s.read() {
                    let mut buf = vec![0u8; chunks.len()];
                    chunks.read(&mut buf).expect("read chunks");
                    return (buf, u32::from(chunks.ppi));
                }
            }
            assert!(Instant::now() < deadline, "echo within 5 s");
            self.pump(Duration::from_millis(20)).await;
        }
    }
}

/// Drive `server` until `stop` fires, then shut it down gracefully if `graceful`.
fn drive(mut server: SctpServer, stop: oneshot::Receiver<bool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut stop = stop;
        loop {
            if let Ok(graceful) = stop.try_recv() {
                if graceful {
                    let _ = server.shutdown_gracefully(Duration::from_secs(2)).await;
                }
                return;
            }
            if server.recv(Duration::from_millis(10)).await.is_err() {
                return;
            }
        }
    })
}

/// Pump `client` until its association is closed; how long that took, or `None`
/// after `within`.
async fn closed_within(client: &mut TestClient, within: Duration) -> Option<Duration> {
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if client.association.is_closed() {
            return Some(t0.elapsed());
        }
        client.pump(Duration::from_millis(20)).await;
    }
    client.association.is_closed().then(|| t0.elapsed())
}

/// **#1142, RFC 9260 §8.4.** The server restarts at the same address. The client's
/// next DATA belongs to an association the new server does not have, and is answered
/// with an ABORT carrying the T bit: the client's association closes within one round
/// trip, not after Association.Max.Retrans.
#[tokio::test]
async fn a_peer_of_a_restarted_server_is_aborted_on_its_next_packet() {
    let first = SctpServer::bind("127.0.0.1:0".parse().unwrap(), SctpServerConfig::default())
        .await
        .expect("bind");
    let addr = first.local_addr();
    let (stop_first, stopped) = oneshot::channel();
    let task = drive(first, stopped);
    let mut client = TestClient::connect(addr).await;

    // The server process dies: nothing is sent, the socket goes away.
    let _ = stop_first.send(false);
    task.await.expect("server task");
    let second = SctpServer::bind(addr, SctpServerConfig::default())
        .await
        .expect("rebind the same address");
    let (_keep, never) = oneshot::channel::<bool>();
    let _restarted = drive(second, never);

    client.send(0, b"initial ue message", NGAP_PPID).await;
    let took = closed_within(&mut client, Duration::from_secs(2))
        .await
        .expect("the restarted server's ABORT closes the client's association");
    assert!(
        took < Duration::from_secs(1),
        "within a round trip: {took:?}"
    );
}

/// **#1142, RFC 9260 §9.2.** A server that stops ends its associations with a
/// SHUTDOWN: the client's association closes, with no packet of its own needed.
#[tokio::test]
async fn a_stopping_server_shuts_its_associations_down() {
    let server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), SctpServerConfig::default())
        .await
        .expect("bind");
    let addr = server.local_addr();
    let (stop, stopped) = oneshot::channel();
    let task = drive(server, stopped);
    let mut client = TestClient::connect(addr).await;
    let _ = stop.send(true);
    let took = closed_within(&mut client, Duration::from_secs(3))
        .await
        .expect("the SHUTDOWN closes the client's association");
    assert!(took < Duration::from_secs(2), "{took:?}");
    task.await.expect("server task");
}

/// **#1142, RFC 9260 §8.5.1 B**, the receiving side (the patched sctp-proto the gNB
/// uses too): an ABORT with the T bit is accepted only under the peer's tag. One under
/// any other tag, from the same address, leaves the association up.
#[tokio::test]
async fn a_reflected_abort_is_accepted_only_under_the_peers_tag() {
    use std::sync::Mutex;
    let server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), SctpServerConfig::default())
        .await
        .expect("bind");
    let server_addr = server.local_addr();
    let (_keep, never) = oneshot::channel::<bool>();
    let _server = drive(server, never);

    // A relay that keeps the last client -> server packet, and injects packets
    // toward the client on request.
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("relay"));
    let relay_addr = relay.local_addr().unwrap();
    let last_up: Arc<Mutex<Option<(Vec<u8>, SocketAddr)>>> = Arc::default();
    let (sock, seen) = (Arc::clone(&relay), Arc::clone(&last_up));
    tokio::spawn(async move {
        let mut client = None;
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if from == server_addr {
                if let Some(c) = client {
                    let _ = sock.send_to(&buf[..n], c).await;
                }
            } else {
                client = Some(from);
                *seen.lock().unwrap() = Some((buf[..n].to_vec(), from));
                let _ = sock.send_to(&buf[..n], server_addr).await;
            }
        }
    });
    let mut client = TestClient::connect(relay_addr).await;
    client.send(0, b"x", NGAP_PPID).await;
    let (up, client_addr) = last_up.lock().unwrap().clone().expect("a client packet");
    let abort = nextgcore_sctp::ootb::ootb_response(&up).expect("an ABORT for it");

    // Under another tag: ignored.
    let mut probe = up.clone();
    probe[4] ^= 0xFF;
    let forged = nextgcore_sctp::ootb::ootb_response(&reseal(probe)).expect("an ABORT");
    relay.send_to(&forged, client_addr).await.unwrap();
    assert_eq!(
        closed_within(&mut client, Duration::from_millis(300)).await,
        None,
        "an ABORT under a foreign tag is dropped"
    );
    // Under the peer's tag, reflected: the association closes.
    relay.send_to(&abort, client_addr).await.unwrap();
    assert!(
        closed_within(&mut client, Duration::from_secs(1))
            .await
            .is_some(),
        "the reflected ABORT closes the association"
    );
}

/// `packet` with its SCTP checksum recomputed (CRC-32C, RFC 9260 Appendix A).
fn reseal(mut packet: Vec<u8>) -> Vec<u8> {
    packet[8..12].fill(0);
    let mut crc = !0u32;
    for &b in &packet {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0x82F6_3B78 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    packet[8..12].copy_from_slice(&(!crc).to_le_bytes());
    packet
}
