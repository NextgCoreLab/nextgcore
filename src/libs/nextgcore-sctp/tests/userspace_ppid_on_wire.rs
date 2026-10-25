//! The userspace (sctp-proto over UDP) [`SctpServer`] must put the right PPID on
//! the wire and report the true PPID on receive.
//!
//! A UDP relay sits between a minimal sctp-proto client (the gNB/eNB side) and
//! an [`SctpServer`] (the AMF/MME side) and records the Payload Protocol
//! Identifier of every DATA chunk it forwards, in each direction. The server
//! echoes each message back with the PPID it received, so one exchange checks
//! the client's send, the server's receive, the server's send and the client's
//! receive.
//!
//! Upstream sctp-proto maps every PPID outside the five WebRTC values to
//! `PayloadProtocolIdentifier::Unknown`, which serialises as 58, so NGAP (60,
//! TS 38.412 §7) and S1AP (18, TS 36.412 §7) went out as 58. On top of that the
//! server hard-coded NGAP_PPID on send and reported NGAP_PPID for anything it
//! received. nextgsim fixed the same defect in its copy (nextgsim #220); the
//! patched crate now lives at `src/vendor/sctp-proto`.

#![cfg(feature = "sctp-proto")]

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use nextgcore_sctp::{
    SctpServer, SctpServerConfig, ServerEvent, NEXTGCORE_SCTP_S1AP_PPID, NGAP_PPID,
};
use sctp_proto::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Payload,
    PayloadProtocolIdentifier, Transmit,
};
use tokio::{net::UdpSocket, sync::mpsc, time::timeout};

/// Direction of a DATA chunk seen by the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    ClientToServer,
    ServerToClient,
}

/// PPIDs of the DATA chunks (type 0) in one SCTP packet (RFC 9260 §3.3.1).
fn data_chunk_ppids(packet: &[u8]) -> Vec<u32> {
    let mut ppids = Vec::new();
    // 12-octet common header, then chunks padded to 4 octets.
    let mut off = 12;
    while off + 4 <= packet.len() {
        let ty = packet[off];
        let len = u16::from_be_bytes([packet[off + 2], packet[off + 3]]) as usize;
        if len < 4 || off + len > packet.len() {
            break;
        }
        // DATA: type, flags, length, TSN (4), stream id (2), SSN (2), PPID (4).
        if ty == 0 && len >= 16 {
            ppids.push(u32::from_be_bytes([
                packet[off + 12],
                packet[off + 13],
                packet[off + 14],
                packet[off + 15],
            ]));
        }
        off += (len + 3) & !3;
    }
    ppids
}

/// A UDP relay recording every DATA chunk PPID it forwards.
async fn spawn_relay(server: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<(Dir, u32)>>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind relay");
    let addr = sock.local_addr().expect("relay addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut client: Option<SocketAddr> = None;
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let pkt = &buf[..n];
            let (dir, to) = if from == server {
                match client {
                    Some(c) => (Dir::ServerToClient, c),
                    None => continue,
                }
            } else {
                client = Some(from);
                (Dir::ClientToServer, server)
            };
            for ppid in data_chunk_ppids(pkt) {
                log.lock().expect("relay log").push((dir, ppid));
            }
            let _ = sock.send_to(pkt, to).await;
        }
    });
    (addr, seen)
}

/// An SCTP server that echoes every message on its stream with the PPID it
/// reported on receive, and records those received PPIDs.
async fn spawn_echo_server() -> (SocketAddr, Arc<Mutex<Vec<u32>>>) {
    let mut server = SctpServer::bind(
        "127.0.0.1:0".parse().expect("addr"),
        SctpServerConfig::default(),
    )
    .await
    .expect("bind server");
    let addr = server.local_addr();
    let (tx, mut rx) = mpsc::unbounded_channel();
    server.set_event_sender(tx);
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&received);
    tokio::spawn(async move {
        loop {
            if server.recv(Duration::from_millis(10)).await.is_err() {
                return;
            }
            while let Ok(ev) = rx.try_recv() {
                if let ServerEvent::DataReceived {
                    association_id,
                    message,
                } = ev
                {
                    log.lock().expect("server log").push(message.ppid);
                    let _ = server
                        .send_with_ppid(
                            association_id,
                            message.stream_id,
                            &message.data,
                            message.ppid,
                        )
                        .await;
                }
            }
        }
    });
    (addr, received)
}

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

    /// Queue a message on `stream_id` without flushing it, so several writes go out
    /// together and reach the server in one batch.
    fn write(&mut self, stream_id: u16, data: &[u8], ppid: u32) {
        let ppi = PayloadProtocolIdentifier::from(ppid);
        let mut stream = match self.association.stream(stream_id) {
            Ok(s) => s,
            Err(_) => self
                .association
                .open_stream(stream_id, ppi)
                .expect("open stream"),
        };
        stream.write_with_ppi(data, ppi).expect("write");
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

#[tokio::test]
async fn ngap_and_s1ap_ppids_are_carried_verbatim_both_ways() {
    let (server_addr, server_received) = spawn_echo_server().await;
    let (relay_addr, wire) = spawn_relay(server_addr).await;
    let mut client = TestClient::connect(relay_addr).await;

    // Each message on its own stream: the server is driven per stream.
    client.send(0, b"ngap", NGAP_PPID).await;
    let (data, ngap_echo) = client.recv_on(0).await;
    assert_eq!(&data[..], b"ngap");
    client.send(1, b"s1ap", NEXTGCORE_SCTP_S1AP_PPID).await;
    let (data, s1ap_echo) = client.recv_on(1).await;
    assert_eq!(&data[..], b"s1ap");

    assert_eq!(
        *server_received.lock().expect("server log"),
        vec![NGAP_PPID, NEXTGCORE_SCTP_S1AP_PPID],
        "the server must report the PPID the client sent"
    );
    assert_eq!(ngap_echo, NGAP_PPID, "the client must receive PPID 60 back");
    assert_eq!(
        s1ap_echo, NEXTGCORE_SCTP_S1AP_PPID,
        "the client must receive PPID 18 back"
    );

    let wire = wire.lock().expect("relay log").clone();
    let pick = |d: Dir| {
        let mut v: Vec<u32> = wire
            .iter()
            .filter(|(x, _)| *x == d)
            .map(|(_, p)| *p)
            .collect();
        // Retransmissions may repeat a chunk.
        v.dedup();
        v
    };
    assert_eq!(
        pick(Dir::ClientToServer),
        vec![60, 18],
        "client -> server DATA chunk PPIDs on the wire"
    );
    assert_eq!(
        pick(Dir::ServerToClient),
        vec![60, 18],
        "server -> client DATA chunk PPIDs on the wire"
    );
}

/// `send` uses the server's configured PPID rather than a hard-coded NGAP 60,
/// so an S1-MME server on the userspace backend sends S1AP's 18.
#[tokio::test]
async fn send_uses_the_configured_ppid() {
    let config = SctpServerConfig {
        ppid: NEXTGCORE_SCTP_S1AP_PPID,
        ..SctpServerConfig::default()
    };
    let mut server = SctpServer::bind("127.0.0.1:0".parse().expect("addr"), config)
        .await
        .expect("bind server");
    let server_addr = server.local_addr();
    let (tx, mut rx) = mpsc::unbounded_channel();
    server.set_event_sender(tx);
    let (relay_addr, wire) = spawn_relay(server_addr).await;
    tokio::spawn(async move {
        loop {
            if server.recv(Duration::from_millis(10)).await.is_err() {
                return;
            }
            while let Ok(ev) = rx.try_recv() {
                if let ServerEvent::DataReceived {
                    association_id,
                    message,
                } = ev
                {
                    let _ = server
                        .send(association_id, message.stream_id, &message.data)
                        .await;
                }
            }
        }
    });
    let mut client = TestClient::connect(relay_addr).await;
    client.send(0, b"s1ap", NEXTGCORE_SCTP_S1AP_PPID).await;
    let (_, ppid) = client.recv_on(0).await;
    assert_eq!(ppid, NEXTGCORE_SCTP_S1AP_PPID);
    let s2c: Vec<u32> = wire
        .lock()
        .expect("relay log")
        .iter()
        .filter(|(d, _)| *d == Dir::ServerToClient)
        .map(|(_, p)| *p)
        .collect();
    assert!(
        !s2c.is_empty() && s2c.iter().all(|&p| p == NEXTGCORE_SCTP_S1AP_PPID),
        "server -> client PPIDs on the wire: {s2c:?}"
    );
}

/// **#813.** `outbound_streams` reports the NEGOTIATED count: the server's configured
/// maximum lowered to the inbound streams the peer offered (RFC 9260 §5.1.1), which is
/// the bound amfd keeps UE-associated NGAP streams under (TS 38.412 §7). And a message
/// the server sends on stream `n - 1` reaches the peer on that stream.
#[tokio::test]
async fn outbound_streams_is_the_negotiated_count() {
    for (server_max, client_inbound, negotiated) in [(4u16, 3u16, 3u16), (4, 16, 4), (2, 1, 1)] {
        let config = SctpServerConfig {
            max_outbound_streams: server_max,
            ..SctpServerConfig::default()
        };
        let mut server = SctpServer::bind("127.0.0.1:0".parse().expect("addr"), config)
            .await
            .expect("bind server");
        let server_addr = server.local_addr();
        let (tx, mut rx) = mpsc::unbounded_channel();
        server.set_event_sender(tx);
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
        let server_task = tokio::spawn(async move {
            loop {
                if server.recv(Duration::from_millis(10)).await.is_err() {
                    return;
                }
                while let Ok(ev) = rx.try_recv() {
                    if let ServerEvent::DataReceived { association_id, .. } = ev {
                        let n = server.outbound_streams(association_id);
                        let _ = seen_tx.send(n);
                        if let Some(n) = n {
                            let _ = server.send(association_id, n - 1, b"last").await;
                        }
                    }
                }
                assert_eq!(
                    server.outbound_streams(u64::MAX),
                    None,
                    "unknown association"
                );
            }
        });
        let transport = sctp_proto::TransportConfig::default()
            .with_max_num_inbound_streams(client_inbound)
            .with_max_num_outbound_streams(2);
        let mut client_config = ClientConfig::new();
        client_config.transport = Arc::new(transport);
        let mut client = TestClient::connect_with(server_addr, client_config).await;
        client.send(0, b"hello", NGAP_PPID).await;
        let reported = loop {
            if let Ok(n) = seen_rx.try_recv() {
                break n;
            }
            client.pump(Duration::from_millis(20)).await;
        };
        assert_eq!(
            reported,
            Some(negotiated),
            "server max {server_max}, client inbound {client_inbound}"
        );
        let (data, _) = client.recv_on(negotiated - 1).await;
        assert_eq!(&data[..], b"last", "delivered on the highest valid stream");
        server_task.abort();
    }
}

#[test]
fn the_relay_parser_reads_the_ppid_field() {
    // Common header (12) + one DATA chunk: type 0, flags 3, length 20, TSN 1,
    // stream 0, SSN 0, PPID 60, 4 octets of user data.
    let mut pkt = vec![0u8; 12];
    pkt.extend_from_slice(&[
        0, 3, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 60, b'n', b'g', b'a', b'p',
    ]);
    assert_eq!(data_chunk_ppids(&pkt), vec![60]);
}

/// An SCTP server that records `(stream, payload)` for every message it delivers.
async fn spawn_recording_server(
    config: SctpServerConfig,
) -> (SocketAddr, Arc<Mutex<Vec<(u16, Vec<u8>)>>>) {
    let mut server = SctpServer::bind("127.0.0.1:0".parse().expect("addr"), config)
        .await
        .expect("bind server");
    let addr = server.local_addr();
    let (tx, mut rx) = mpsc::unbounded_channel();
    server.set_event_sender(tx);
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&received);
    tokio::spawn(async move {
        loop {
            if server.recv(Duration::from_millis(10)).await.is_err() {
                return;
            }
            while let Ok(ev) = rx.try_recv() {
                if let ServerEvent::DataReceived { message, .. } = ev {
                    log.lock()
                        .expect("server log")
                        .push((message.stream_id, message.data.to_vec()));
                }
            }
        }
    });
    (addr, received)
}

/// #864: every message on every negotiated inbound stream is delivered, not only the
/// first one on a stream above 1. A gNB may carry each UE's signalling on its own
/// stream (TS 38.412 §7), so a second message on stream 2 or 3 must arrive too.
#[tokio::test]
async fn every_message_on_every_inbound_stream_is_delivered() {
    let config = SctpServerConfig {
        max_inbound_streams: 4,
        max_outbound_streams: 4,
        ..SctpServerConfig::default()
    };
    let (server_addr, received) = spawn_recording_server(config).await;
    let mut client = TestClient::connect(server_addr).await;

    let mut expected = Vec::new();
    for round in 0..2u8 {
        for stream in 0..4u16 {
            let payload = vec![b'm', stream as u8, round];
            client.send(stream, &payload, NGAP_PPID).await;
            expected.push((stream, payload));
        }
    }

    // Keep the client's side of the association running (SACKs, retransmissions)
    // until the server has delivered all eight messages.
    let deadline = Instant::now() + Duration::from_secs(5);
    while received.lock().expect("server log").len() < expected.len() {
        assert!(
            Instant::now() < deadline,
            "all eight messages within 5 s; got {:?}",
            received.lock().expect("server log")
        );
        client.pump(Duration::from_millis(20)).await;
    }

    // Per stream, in the order sent (streams are ordered, RFC 9260 §6.6).
    let got = received.lock().expect("server log").clone();
    for stream in 0..4u16 {
        let on = |v: &[(u16, Vec<u8>)]| {
            v.iter()
                .filter(|(s, _)| *s == stream)
                .map(|(_, d)| d.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(on(&got), on(&expected), "stream {stream}, in order");
    }
    assert_eq!(
        got.len(),
        expected.len(),
        "two messages on each of streams 0..=3"
    );
}

/// #864 review: several messages on one stream that reach the server in ONE batch are
/// all delivered, in order. The stream is drained, not read once per event batch.
#[tokio::test]
async fn a_burst_on_one_stream_is_drained_in_order() {
    let config = SctpServerConfig {
        max_inbound_streams: 4,
        max_outbound_streams: 4,
        ..SctpServerConfig::default()
    };
    let (server_addr, received) = spawn_recording_server(config).await;
    let mut client = TestClient::connect(server_addr).await;

    client.send(2, b"first", NGAP_PPID).await;
    for m in [&b"second"[..], b"third", b"fourth"] {
        client.write(2, m, NGAP_PPID);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while received.lock().expect("server log").len() < 4 {
        assert!(
            Instant::now() < deadline,
            "all four messages within 5 s; got {:?}",
            received.lock().expect("server log")
        );
        client.pump(Duration::from_millis(20)).await;
    }
    let got: Vec<(u16, Vec<u8>)> = received.lock().expect("server log").clone();
    assert_eq!(
        got,
        vec![
            (2, b"first".to_vec()),
            (2, b"second".to_vec()),
            (2, b"third".to_vec()),
            (2, b"fourth".to_vec()),
        ]
    );
}
