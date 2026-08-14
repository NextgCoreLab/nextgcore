//! Diameter transport layer (TCP and SCTP)
//!
//! Provides TCP and SCTP-based transport for Diameter messages per RFC 6733 §2.1.
//! Diameter uses a 4-byte length prefix in the message header for framing.
//! The first byte is the version, and the next 3 bytes are the message length.
//!
//! # Transports
//!
//! **TCP** is always available and is what every daemon in this tree currently
//! uses.
//!
//! **SCTP** requires the default-off `kernel-sctp` feature, which delegates to
//! [`nextgcore_sctp`]'s kernel backend (native `IPPROTO_SCTP` sockets, PPID 46).
//! RFC 6733 §2.1 says a Diameter *server* must support both TCP and SCTP, so
//! TCP-only is a conformance gap; the feature closes it where `libsctp` exists.
//!
//! The feature is off by default because it links `-lsctp`. A host without
//! `libsctp-dev` passes `cargo check` and `cargo build -p` and then fails at
//! LINK time (`ld: cannot find -lsctp`) — so making it default would break
//! builds that work today. `nextgcore_sctp`'s other backend (`sctp-proto`,
//! SCTP-over-UDP) is deliberately **not** used here: it is wire-compatible with
//! nextgsim but not with a standards SCTP peer, so it could not talk to a real
//! HSS or DRA and would close the gap on paper only.
//!
//! Runtime requirements: `libsctp-dev` at build time, `libsctp1` plus
//! `modprobe sctp` at run time.

use bytes::BytesMut;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::DiameterConfig;
use crate::error::{DiameterError, DiameterResult};
use crate::message::{DiameterMessage, DIAMETER_HEADER_SIZE};
use crate::peer::{DiameterPeer, PeerEvent, PeerState};
use crate::DIAMETER_PORT;

/// Maximum Diameter message size (default 64KB, RFC allows up to 16MB)
const MAX_MESSAGE_SIZE: usize = 65536;

/// The three operations [`crate::peer::DiameterPeer`] needs from a transport.
///
/// # Why this exists
///
/// `DiameterPeer` held a concrete `DiameterTransport` (TCP), so the peer state
/// machine — CER/CEA, watchdog, DPR — could not run over SCTP even once an SCTP
/// transport existed. The transport was reachable but nothing could drive
/// Diameter across it, which made the SCTP support real only at the byte level.
///
/// Deliberately narrow: `send`/`recv`/`shutdown` is the entire surface the peer
/// uses (verified by grepping every `self.transport.*` call), so widening it
/// would invite transports to differ in ways the state machine cannot honour.
/// Framing stays inside each implementation, since TCP is a byte stream that
/// must be reassembled while SCTP is message-oriented.
#[async_trait::async_trait]
pub trait DiameterTransportIo: Send {
    /// Send one encoded Diameter message.
    async fn send_message(&mut self, msg: &DiameterMessage) -> DiameterResult<()>;

    /// Receive the next complete Diameter message.
    async fn recv_message(&mut self) -> DiameterResult<DiameterMessage>;

    /// Close the connection.
    async fn close(&mut self) -> DiameterResult<()>;
}

#[async_trait::async_trait]
impl DiameterTransportIo for DiameterTransport {
    async fn send_message(&mut self, msg: &DiameterMessage) -> DiameterResult<()> {
        self.send(msg).await
    }

    async fn recv_message(&mut self) -> DiameterResult<DiameterMessage> {
        self.recv().await
    }

    async fn close(&mut self) -> DiameterResult<()> {
        self.shutdown().await
    }
}

/// Diameter transport connection wrapping a TCP stream
pub struct DiameterTransport {
    stream: TcpStream,
    read_buf: BytesMut,
    peer_addr: SocketAddr,
}

impl DiameterTransport {
    /// Wrap an existing TCP stream as a Diameter transport
    pub fn new(stream: TcpStream) -> DiameterResult<Self> {
        let peer_addr = stream.peer_addr()?;
        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            peer_addr,
        })
    }

    /// Connect to a remote Diameter peer
    pub async fn connect(addr: SocketAddr) -> DiameterResult<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::new(stream)
    }

    /// Connect to a remote Diameter peer with a timeout
    pub async fn connect_timeout(addr: SocketAddr, timeout: Duration) -> DiameterResult<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                DiameterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("connection to {addr} timed out after {timeout:?}"),
                ))
            })?
            .map_err(DiameterError::Io)?;
        Self::new(stream)
    }

    /// Get the remote peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Send a Diameter message
    pub async fn send(&mut self, msg: &DiameterMessage) -> DiameterResult<()> {
        let encoded = msg.encode();
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive a Diameter message
    ///
    /// Reads from the TCP stream, performing message framing based on the
    /// 3-byte length field in the Diameter header (bytes 1-3).
    pub async fn recv(&mut self) -> DiameterResult<DiameterMessage> {
        loop {
            // Try to parse a complete message from the buffer
            if let Some(msg) = self.try_parse_message()? {
                return Ok(msg);
            }

            // Read more data from the stream
            let n = self.stream.read_buf(&mut self.read_buf).await?;
            if n == 0 {
                return Err(DiameterError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed by peer",
                )));
            }
        }
    }

    /// Try to parse a complete Diameter message from the read buffer
    fn try_parse_message(&mut self) -> DiameterResult<Option<DiameterMessage>> {
        if self.read_buf.len() < DIAMETER_HEADER_SIZE {
            return Ok(None);
        }

        // Read message length from header bytes 1-3 (3-byte big-endian)
        let len_high = self.read_buf[1] as usize;
        let len_mid = self.read_buf[2] as usize;
        let len_low = self.read_buf[3] as usize;
        let msg_len = (len_high << 16) | (len_mid << 8) | len_low;

        if msg_len < DIAMETER_HEADER_SIZE {
            return Err(DiameterError::InvalidMessage(format!(
                "message length {msg_len} is less than header size"
            )));
        }

        if msg_len > MAX_MESSAGE_SIZE {
            return Err(DiameterError::InvalidMessage(format!(
                "message length {msg_len} exceeds maximum {MAX_MESSAGE_SIZE}"
            )));
        }

        // Check if we have the full message
        if self.read_buf.len() < msg_len {
            return Ok(None);
        }

        // Extract the message bytes and decode
        let msg_bytes = self.read_buf.split_to(msg_len);
        let mut bytes = msg_bytes.freeze();
        let msg = DiameterMessage::decode(&mut bytes)?;
        Ok(Some(msg))
    }

    /// Shutdown the transport connection
    pub async fn shutdown(&mut self) -> DiameterResult<()> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

/// Diameter TCP listener that accepts incoming connections
pub struct DiameterListener {
    listener: TcpListener,
}

impl DiameterListener {
    /// Bind to the given address
    pub async fn bind(addr: SocketAddr) -> DiameterResult<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    /// Bind to the default Diameter port on all interfaces
    pub async fn bind_default() -> DiameterResult<Self> {
        let addr: SocketAddr = ([0, 0, 0, 0], DIAMETER_PORT).into();
        Self::bind(addr).await
    }

    /// Accept a new incoming connection
    pub async fn accept(&self) -> DiameterResult<DiameterTransport> {
        let (stream, _addr) = self.listener.accept().await?;
        DiameterTransport::new(stream)
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> DiameterResult<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Run the listener, sending accepted transports to a channel
    pub async fn run(self, tx: mpsc::Sender<DiameterTransport>) -> DiameterResult<()> {
        loop {
            match self.accept().await {
                Ok(transport) => {
                    if tx.send(transport).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    log::warn!("Failed to accept Diameter connection: {e}");
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// DiameterServer - Accept connections and run peer state machines
// ============================================================================

/// Message handler callback type for application-level Diameter messages
pub type MessageHandler =
    Box<dyn Fn(DiameterMessage) -> Option<DiameterMessage> + Send + Sync + 'static>;

/// Diameter server that accepts connections and dispatches messages
pub struct DiameterServer {
    config: DiameterConfig,
    handler: std::sync::Arc<MessageHandler>,
}

impl DiameterServer {
    /// Create a new Diameter server
    pub fn new(config: DiameterConfig, handler: MessageHandler) -> Self {
        Self {
            config,
            handler: std::sync::Arc::new(handler),
        }
    }

    /// Run the server: listen for connections and dispatch messages
    pub async fn run(&self, addr: SocketAddr) -> DiameterResult<()> {
        let listener = DiameterListener::bind(addr).await?;
        log::info!(
            "Diameter server listening on {} as {}",
            listener.local_addr()?,
            self.config.diameter_id
        );

        loop {
            match listener.accept().await {
                Ok(transport) => {
                    let peer_addr = transport.peer_addr();
                    log::info!("Accepted Diameter connection from {peer_addr}");

                    let config = self.config.clone();
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(transport, &config, &handler).await
                        {
                            log::warn!("Peer {peer_addr} connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    log::warn!("Failed to accept Diameter connection: {e}");
                }
            }
        }
    }

    /// Handle a single peer connection (responder side)
    async fn handle_connection(
        transport: DiameterTransport,
        config: &DiameterConfig,
        handler: &MessageHandler,
    ) -> DiameterResult<()> {
        let mut peer = DiameterPeer::new_responder(transport, config);
        peer.start().await?;

        loop {
            let event = tokio::time::timeout(peer.watchdog_interval() * 3, peer.next_event()).await;

            match event {
                Ok(Ok(PeerEvent::Established {
                    origin_host,
                    origin_realm,
                })) => {
                    log::info!("Peer established: host={origin_host}, realm={origin_realm}");
                }
                Ok(Ok(PeerEvent::Message(msg))) => {
                    if msg.header.is_request() {
                        if let Some(answer) = handler(msg) {
                            peer.send_message(&answer).await?;
                        }
                    }
                }
                Ok(Ok(PeerEvent::WatchdogAck)) => {
                    log::trace!("Watchdog ack from peer");
                }
                Ok(Ok(PeerEvent::Disconnected)) => {
                    log::info!("Peer disconnected");
                    break;
                }
                Ok(Err(e)) => {
                    log::warn!("Peer error: {e}");
                    break;
                }
                Err(_) => {
                    log::warn!("Peer watchdog timeout, closing connection");
                    break;
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// DiameterClient - Initiate connection with reconnection support
// ============================================================================

/// Diameter client that connects to a remote peer and handles reconnection
pub struct DiameterClient {
    config: DiameterConfig,
    peer_addr: SocketAddr,
    peer: Option<DiameterPeer>,
    reconnect_interval: Duration,
    /// Inbound server-initiated requests (e.g. S6a CLR/IDR) received while
    /// waiting for an answer; consumed via [`DiameterClient::recv_inbound_request`].
    pending_requests: std::collections::VecDeque<DiameterMessage>,
    /// Hop-by-Hop identifier counter (RFC 6733 Section 3: unique per connection)
    hop_by_hop: u32,
    /// End-to-End identifier counter (RFC 6733 Section 3)
    end_to_end: u32,
}

impl DiameterClient {
    /// Create a new Diameter client
    pub fn new(config: DiameterConfig, peer_addr: SocketAddr) -> Self {
        let reconnect_interval = Duration::from_secs(config.timer_tc as u64);
        // RFC 6733: End-to-End ID should be set to a value whose low 20 bits
        // are derived from time on (re)start to avoid collisions.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let seed = (now.as_secs() as u32) << 20 | (now.subsec_nanos() & 0xFFFFF);
        Self {
            config,
            peer_addr,
            peer: None,
            reconnect_interval,
            pending_requests: std::collections::VecDeque::new(),
            hop_by_hop: seed,
            end_to_end: seed,
        }
    }

    fn next_hop_by_hop(&mut self) -> u32 {
        self.hop_by_hop = self.hop_by_hop.wrapping_add(1);
        self.hop_by_hop
    }

    fn next_end_to_end(&mut self) -> u32 {
        self.end_to_end = self.end_to_end.wrapping_add(1);
        self.end_to_end
    }

    /// Connect and perform CER/CEA exchange
    pub async fn connect(&mut self) -> DiameterResult<()> {
        let transport =
            DiameterTransport::connect_timeout(self.peer_addr, Duration::from_secs(5)).await?;

        let mut peer = DiameterPeer::new_initiator(transport, &self.config);
        peer.start().await?;

        // Wait for CEA
        match peer.next_event().await? {
            PeerEvent::Established {
                origin_host,
                origin_realm,
            } => {
                log::info!("Connected to Diameter peer: host={origin_host}, realm={origin_realm}");
                self.peer = Some(peer);
                Ok(())
            }
            _ => Err(DiameterError::Protocol(
                "unexpected event during CER/CEA exchange".into(),
            )),
        }
    }

    /// Connect with automatic retry
    pub async fn connect_with_retry(&mut self, max_retries: u32) -> DiameterResult<()> {
        for attempt in 0..max_retries {
            match self.connect().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    log::warn!(
                        "Connection attempt {} to {} failed: {e}",
                        attempt + 1,
                        self.peer_addr
                    );
                    if attempt + 1 < max_retries {
                        tokio::time::sleep(self.reconnect_interval).await;
                    }
                }
            }
        }
        Err(DiameterError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "failed to connect to {} after {max_retries} attempts",
                self.peer_addr
            ),
        )))
    }

    /// Check if the client is connected
    pub fn is_connected(&self) -> bool {
        self.peer
            .as_ref()
            .map(|p| p.state() == PeerState::Open)
            .unwrap_or(false)
    }

    /// Send an application-level Diameter request and wait for an answer.
    ///
    /// Hop-by-Hop and End-to-End identifiers are assigned per RFC 6733 if the
    /// message carries zero values; answers are matched on Hop-by-Hop ID.
    /// Peer-initiated requests received while waiting (e.g. S6a CLR/IDR) are
    /// queued and can be drained with [`DiameterClient::recv_inbound_request`].
    ///
    /// # Timeout
    ///
    /// Gives up after `config.request_timeout` seconds with
    /// [`DiameterError::RequestTimeout`]. This loop previously had no bound at
    /// all. It did handle `Disconnected`, so a peer that drops the TCP
    /// connection unblocks it -- but a peer that stays CONNECTED and simply never
    /// answers does not, and neither does one that keeps answering watchdogs
    /// while dropping application requests (`WatchdogAck` hits `continue`).
    /// Either case parked the caller forever.
    ///
    /// That is what makes it more than a hung request: `nextgcore-mmed` holds a
    /// process-global mutex across this call, so one unanswered AIR/ULR/PUR
    /// wedges the MME's entire S6a plane -- every subscriber's authentication,
    /// not just the one that stalled. Bounding the wait here contains that;
    /// removing the lock is tracked separately.
    ///
    /// The deadline covers the whole exchange rather than being reset per event,
    /// so a peer streaming watchdogs or unmatched answers cannot extend it
    /// indefinitely.
    pub async fn send_request(&mut self, msg: &DiameterMessage) -> DiameterResult<DiameterMessage> {
        let mut request = msg.clone();
        if request.header.hop_by_hop_id == 0 {
            request.header.hop_by_hop_id = self.next_hop_by_hop();
        }
        if request.header.end_to_end_id == 0 {
            request.header.end_to_end_id = self.next_end_to_end();
        }
        let hop_by_hop_id = request.header.hop_by_hop_id;
        let command = request.header.command_code;
        let timeout = Duration::from_secs(self.config.request_timeout as u64);

        let peer = self
            .peer
            .as_mut()
            .ok_or(DiameterError::Protocol("not connected".into()))?;

        peer.send_message(&request).await?;

        // Deadline is computed AFTER the send so a slow write does not eat into
        // the answer window.
        let deadline = tokio::time::Instant::now() + timeout;

        // Wait for the answer (handle any watchdog messages in between)
        loop {
            let event = match tokio::time::timeout_at(deadline, peer.next_event()).await {
                Ok(ev) => ev?,
                Err(_) => {
                    // The connection is left OPEN: a timeout is a stalled
                    // procedure, not necessarily a broken peer, and the watchdog
                    // (RFC 3539) owns the decision to tear a peer down. Tearing
                    // it down here would turn one slow subscriber lookup into a
                    // reconnect storm.
                    log::warn!(
                        "Diameter request (command {command}, hop-by-hop {hop_by_hop_id}) \
                         timed out after {}s with no answer",
                        timeout.as_secs()
                    );
                    return Err(DiameterError::RequestTimeout {
                        command,
                        seconds: timeout.as_secs(),
                    });
                }
            };
            match event {
                PeerEvent::Message(answer) => {
                    if answer.header.is_answer() && answer.header.hop_by_hop_id == hop_by_hop_id {
                        return Ok(answer);
                    }
                    if answer.header.is_request() {
                        // Peer-initiated request (e.g. CLR/IDR): queue for the
                        // application instead of silently dropping it.
                        self.pending_requests.push_back(answer);
                    }
                    // Unmatched answers are dropped
                }
                PeerEvent::WatchdogAck => continue,
                PeerEvent::Disconnected => {
                    self.peer = None;
                    return Err(DiameterError::Protocol("peer disconnected".into()));
                }
                _ => {}
            }
        }
    }

    /// Receive a peer-initiated request (e.g. S6a CLR/IDR from the HSS).
    ///
    /// Returns a queued request immediately if one is pending; otherwise waits
    /// up to `timeout` for one to arrive. Returns `Ok(None)` on timeout.
    pub async fn recv_inbound_request(
        &mut self,
        timeout: Duration,
    ) -> DiameterResult<Option<DiameterMessage>> {
        if let Some(msg) = self.pending_requests.pop_front() {
            return Ok(Some(msg));
        }
        let peer = self
            .peer
            .as_mut()
            .ok_or(DiameterError::Protocol("not connected".into()))?;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let event = match tokio::time::timeout_at(deadline, peer.next_event()).await {
                Ok(ev) => ev?,
                Err(_) => return Ok(None), // timeout
            };
            match event {
                PeerEvent::Message(msg) if msg.header.is_request() => return Ok(Some(msg)),
                PeerEvent::Message(_) => continue, // stale answer, drop
                PeerEvent::WatchdogAck => continue,
                PeerEvent::Disconnected => {
                    self.peer = None;
                    return Err(DiameterError::Protocol("peer disconnected".into()));
                }
                _ => continue,
            }
        }
    }

    /// Send an answer to a peer-initiated request.
    pub async fn send_answer(&mut self, msg: &DiameterMessage) -> DiameterResult<()> {
        let peer = self
            .peer
            .as_mut()
            .ok_or(DiameterError::Protocol("not connected".into()))?;
        peer.send_message(msg).await
    }

    /// Send a watchdog request
    pub async fn send_watchdog(&mut self) -> DiameterResult<()> {
        if let Some(ref mut peer) = self.peer {
            peer.send_watchdog().await
        } else {
            Err(DiameterError::Protocol("not connected".into()))
        }
    }

    /// Gracefully disconnect
    pub async fn disconnect(&mut self) -> DiameterResult<()> {
        if let Some(ref mut peer) = self.peer {
            peer.disconnect(crate::peer::DisconnectCause::Rebooting)
                .await?;
            // Wait for DPA
            if let Ok(PeerEvent::Disconnected) = peer.next_event().await {
                log::debug!("Received DPA, disconnect complete");
            }
        }
        self.peer = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::avp::{Avp, AvpData};
    use crate::message::DiameterMessage;

    #[tokio::test]
    async fn test_transport_send_recv() {
        // Bind listener on a random port
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        // Spawn a task to accept and echo
        let handle = tokio::spawn(async move {
            let mut server = listener.accept().await.unwrap();
            let msg = server.recv().await.unwrap();
            // Echo back as answer
            let answer = DiameterMessage::new_answer(&msg);
            server.send(&answer).await.unwrap();
            server.shutdown().await.unwrap();
        });

        // Connect and send a request
        let mut client = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut req = DiameterMessage::new_request(257, 0);
        req.add_avp(Avp::mandatory(
            264,
            AvpData::DiameterIdentity("client.example.com".to_string()),
        ));
        req.header.hop_by_hop_id = 1;
        req.header.end_to_end_id = 1;
        client.send(&req).await.unwrap();

        // Receive the answer
        let answer = client.recv().await.unwrap();
        assert!(answer.header.is_answer());
        assert_eq!(answer.header.command_code, 257);
        assert_eq!(answer.header.hop_by_hop_id, 1);

        client.shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_transport_multiple_messages() {
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut server = listener.accept().await.unwrap();
            for _ in 0..3 {
                let msg = server.recv().await.unwrap();
                let answer = DiameterMessage::new_answer(&msg);
                server.send(&answer).await.unwrap();
            }
            server.shutdown().await.unwrap();
        });

        let mut client = DiameterTransport::connect(listen_addr).await.unwrap();
        for i in 0..3u32 {
            let mut req = DiameterMessage::new_request(257, 0);
            req.header.hop_by_hop_id = i;
            req.header.end_to_end_id = i;
            client.send(&req).await.unwrap();

            let answer = client.recv().await.unwrap();
            assert!(answer.header.is_answer());
            assert_eq!(answer.header.hop_by_hop_id, i);
        }

        client.shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_connection_refused() {
        // Try connecting to a port that should not be listening
        let addr: SocketAddr = ([127, 0, 0, 1], 19999).into();
        let result = DiameterTransport::connect(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_timeout() {
        // Use a non-routable address to trigger timeout
        let addr: SocketAddr = ([192, 0, 2, 1], 3868).into();
        let result = DiameterTransport::connect_timeout(addr, Duration::from_millis(100)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_diameter_client_server() {
        use crate::config::DiameterConfig;

        let server_cfg = DiameterConfig {
            diameter_id: "hss.example.com".to_string(),
            diameter_realm: "example.com".to_string(),
            timer_tc: 30,
            ..Default::default()
        };

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        // Spawn server handling one connection
        let cfg = server_cfg.clone();
        let handle = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = crate::peer::DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            // Handle CER
            let _event = peer.next_event().await.unwrap();
            // Handle application request (AIR cmd=318)
            let event = peer.next_event().await.unwrap();
            match event {
                PeerEvent::Message(msg) => {
                    assert_eq!(msg.header.command_code, 318);
                    let mut answer = DiameterMessage::new_answer(&msg);
                    answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                    peer.send_message(&answer).await.unwrap();
                }
                _ => panic!("expected application message"),
            }
        });

        // Client side
        let client_cfg = DiameterConfig {
            diameter_id: "mme.example.com".to_string(),
            diameter_realm: "example.com".to_string(),
            timer_tc: 30,
            ..Default::default()
        };
        let mut client = DiameterClient::new(client_cfg, listen_addr);
        client.connect().await.unwrap();
        assert!(client.is_connected());

        // Send AIR
        let mut air = DiameterMessage::new_request(318, 16777251);
        air.header.hop_by_hop_id = 1;
        air.header.end_to_end_id = 1;
        air.add_avp(Avp::mandatory(
            1,
            AvpData::Utf8String("001010123456789".to_string()),
        ));

        let answer = client.send_request(&air).await.unwrap();
        assert!(answer.header.is_answer());
        assert_eq!(answer.header.command_code, 318);
        assert_eq!(answer.result_code(), Some(2001));

        handle.await.unwrap();
    }

    /// A server-initiated request (e.g. S6a CLR) must be deliverable to the
    /// client application via recv_inbound_request, and answerable.
    #[tokio::test]
    async fn test_client_receives_server_initiated_request() {
        use crate::config::DiameterConfig;

        let server_cfg = DiameterConfig {
            diameter_id: "hss.example.com".to_string(),
            diameter_realm: "example.com".to_string(),
            timer_tc: 30,
            ..Default::default()
        };

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let cfg = server_cfg.clone();
        let handle = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = crate::peer::DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            // CER/CEA
            let _ = peer.next_event().await.unwrap();
            // Send a CLR (cmd 317) to the client
            let mut clr = DiameterMessage::new_request(317, 16777251);
            clr.header.hop_by_hop_id = 77;
            clr.header.end_to_end_id = 77;
            clr.add_avp(Avp::mandatory(
                1,
                AvpData::Utf8String("001010123456789".to_string()),
            ));
            peer.send_message(&clr).await.unwrap();
            // Expect the CLA
            match peer.next_event().await.unwrap() {
                PeerEvent::Message(msg) => {
                    assert!(msg.header.is_answer());
                    assert_eq!(msg.header.command_code, 317);
                    assert_eq!(msg.header.hop_by_hop_id, 77);
                    assert_eq!(msg.result_code(), Some(2001));
                }
                _ => panic!("expected CLA"),
            }
        });

        let client_cfg = DiameterConfig {
            diameter_id: "mme.example.com".to_string(),
            diameter_realm: "example.com".to_string(),
            timer_tc: 30,
            ..Default::default()
        };
        let mut client = DiameterClient::new(client_cfg, listen_addr);
        client.connect().await.unwrap();

        let inbound = client
            .recv_inbound_request(Duration::from_secs(5))
            .await
            .unwrap()
            .expect("expected inbound CLR");
        assert!(inbound.header.is_request());
        assert_eq!(inbound.header.command_code, 317);

        let mut cla = DiameterMessage::new_answer(&inbound);
        cla.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
        client.send_answer(&cla).await.unwrap();

        handle.await.unwrap();
    }

    /// recv_inbound_request must time out cleanly when nothing arrives.
    #[tokio::test]
    async fn test_recv_inbound_request_timeout() {
        use crate::config::DiameterConfig;

        let server_cfg = DiameterConfig {
            diameter_id: "hss.example.com".to_string(),
            diameter_realm: "example.com".to_string(),
            timer_tc: 30,
            ..Default::default()
        };

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let cfg = server_cfg.clone();
        let handle = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = crate::peer::DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _ = peer.next_event().await.unwrap();
            // Hold the connection open briefly, sending nothing
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let client_cfg = DiameterConfig {
            diameter_id: "mme.example.com".to_string(),
            diameter_realm: "example.com".to_string(),
            timer_tc: 30,
            ..Default::default()
        };
        let mut client = DiameterClient::new(client_cfg, listen_addr);
        client.connect().await.unwrap();

        let inbound = client
            .recv_inbound_request(Duration::from_millis(100))
            .await
            .unwrap();
        assert!(inbound.is_none());

        handle.await.unwrap();
    }
}

// ============================================================================
// SCTP Transport
// ============================================================================

/// Transport kind selector for TCP or SCTP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterTransportKind {
    /// TCP transport
    Tcp,
    /// SCTP transport
    Sctp,
}

/// SCTP-based Diameter transport
///
/// Note: This is a stub implementation. Full SCTP support would require
/// integrating with an SCTP library like `sctp-rs` or similar.
/// For now, this provides the API structure.
#[cfg(feature = "kernel-sctp")]
pub struct SctpDiameterTransport {
    /// Underlying SCTP stream
    stream: SctpStream,
    /// Read buffer
    read_buf: BytesMut,
    /// Peer address
    peer_addr: SocketAddr,
    /// Default stream ID for sending
    default_stream_id: u16,
    /// Last received stream ID
    last_stream_id: u16,
}

#[cfg(feature = "kernel-sctp")]
impl SctpDiameterTransport {
    /// Wrap an established SCTP stream.
    ///
    /// Crate-private because `SctpStream` is: a caller outside this module could
    /// never construct the argument, so a `pub` signature advertised an API that
    /// could not be used. Construction goes through [`Self::connect`] or
    /// [`SctpDiameterListener::accept`].
    fn new(stream: SctpStream) -> DiameterResult<Self> {
        let peer_addr = stream.peer_addr()?;
        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            peer_addr,
            default_stream_id: 0,
            last_stream_id: 0,
        })
    }

    /// Connect to a remote Diameter peer via SCTP
    pub async fn connect(addr: SocketAddr) -> DiameterResult<Self> {
        let stream = SctpStream::connect(addr).await?;
        Self::new(stream)
    }

    /// Connect via SCTP unless the config disables it.
    ///
    /// This is the entry point a caller choosing a transport from configuration
    /// should use: it honours `DiameterConfigFlags::no_sctp`, which was declared
    /// but read nowhere before SCTP existed. Refusing here rather than silently
    /// falling back to TCP is deliberate -- a caller that asked for SCTP and got
    /// TCP without being told would misreport its own transport.
    pub async fn connect_checked(
        addr: SocketAddr,
        config: &DiameterConfig,
    ) -> DiameterResult<Self> {
        if config.flags.no_sctp {
            return Err(DiameterError::Protocol(
                "SCTP is disabled by configuration (flags.no_sctp)".into(),
            ));
        }
        Self::connect(addr).await
    }

    /// Get the remote peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Set the default stream ID for sending messages
    pub fn set_default_stream_id(&mut self, stream_id: u16) {
        self.default_stream_id = stream_id;
    }

    /// Send a Diameter message on the default stream
    pub async fn send(&mut self, msg: &DiameterMessage) -> DiameterResult<()> {
        self.send_on_stream(msg, self.default_stream_id).await
    }

    /// Send a Diameter message on a specific SCTP stream
    pub async fn send_on_stream(
        &mut self,
        msg: &DiameterMessage,
        stream_id: u16,
    ) -> DiameterResult<()> {
        let encoded = msg.encode();
        self.stream.send(&encoded, stream_id).await?;
        Ok(())
    }

    /// Receive a Diameter message from any stream
    pub async fn recv(&mut self) -> DiameterResult<DiameterMessage> {
        let (msg, _stream_id) = self.recv_with_stream_id().await?;
        Ok(msg)
    }

    /// Receive a Diameter message and return the stream ID it was received on
    pub async fn recv_with_stream_id(&mut self) -> DiameterResult<(DiameterMessage, u16)> {
        loop {
            // Try to parse a complete message from the buffer
            if let Some((msg, stream_id)) = self.try_parse_message()? {
                return Ok((msg, stream_id));
            }

            // Read more data from the SCTP stream
            let (n, stream_id) = self.stream.recv(&mut self.read_buf).await?;
            if n == 0 {
                return Err(DiameterError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed by peer",
                )));
            }

            // Store the stream ID for the parsed message
            self.last_stream_id = stream_id;
        }
    }

    /// Try to parse a complete message from the buffer
    fn try_parse_message(&mut self) -> DiameterResult<Option<(DiameterMessage, u16)>> {
        if self.read_buf.len() < DIAMETER_HEADER_SIZE {
            return Ok(None);
        }

        let len_high = self.read_buf[1] as usize;
        let len_mid = self.read_buf[2] as usize;
        let len_low = self.read_buf[3] as usize;
        let msg_len = (len_high << 16) | (len_mid << 8) | len_low;

        if msg_len < DIAMETER_HEADER_SIZE {
            return Err(DiameterError::InvalidMessage(format!(
                "message length {msg_len} is less than header size"
            )));
        }

        if self.read_buf.len() < msg_len {
            return Ok(None);
        }

        let msg_bytes = self.read_buf.split_to(msg_len);
        let mut bytes = msg_bytes.freeze();
        let msg = DiameterMessage::decode(&mut bytes)?;
        Ok(Some((msg, self.last_stream_id)))
    }

    /// Shutdown the SCTP transport
    pub async fn shutdown(&mut self) -> DiameterResult<()> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

#[cfg(feature = "kernel-sctp")]
#[async_trait::async_trait]
impl DiameterTransportIo for SctpDiameterTransport {
    async fn send_message(&mut self, msg: &DiameterMessage) -> DiameterResult<()> {
        // Uses the default stream; RFC 6733 does not require a specific one.
        self.send(msg).await
    }

    async fn recv_message(&mut self) -> DiameterResult<DiameterMessage> {
        self.recv().await
    }

    async fn close(&mut self) -> DiameterResult<()> {
        self.shutdown().await
    }
}

/// Convert an [`nextgcore_sctp::SctpError`] into an `io::Error`, PRESERVING the
/// original `ErrorKind` where the SCTP layer wrapped one.
///
/// This matters for `AsyncFd::try_io`, which decides whether an operation
/// would-block purely from `ErrorKind::WouldBlock`. `SctpError::{ReceiveFailed,
/// SendFailed}` carry the real `io::Error` from `last_os_error()`, so they are
/// unwrapped; anything else has no os error behind it and is stringified.
#[cfg(feature = "kernel-sctp")]
fn sctp_io_error(e: nextgcore_sctp::SctpError) -> std::io::Error {
    match e {
        nextgcore_sctp::SctpError::ReceiveFailed(inner)
        | nextgcore_sctp::SctpError::SendFailed(inner) => inner,
        other => std::io::Error::other(other.to_string()),
    }
}

/// Diameter Payload Protocol Identifier for SCTP (RFC 6733 §2.1.1).
///
/// 46 = "DIAMETER in a SCTP DATA chunk"; 47 is the DTLS/SCTP variant, which this
/// transport does not implement.
#[cfg(feature = "kernel-sctp")]
pub const DIAMETER_SCTP_PPID: u32 = 46;

/// SCTP stream backed by a real kernel SCTP socket.
///
/// # Why this shape
///
/// [`nextgcore_sctp::KernelSctpSocket`] is **synchronous** (a raw fd plus
/// `set_nonblocking`), while this transport is async. The bridge is tokio's
/// [`AsyncFd`](tokio::io::unix::AsyncFd) driving readiness on a *borrowed*
/// descriptor — the same pattern `nextgcore_sctp::kernel_server` already uses,
/// reused deliberately rather than reinvented. `FdRef` exists because the
/// `OwnedFd` lives in the socket: dropping the `AsyncFd` must only deregister
/// from the reactor, never close the fd.
///
/// # Runtime status
///
/// Type-checks anywhere; **links and runs only on Linux with `libsctp`**
/// (`-lsctp`). On a host without it, `cargo check` and `cargo build -p` succeed
/// while linking a test binary fails with `cannot find -lsctp` — which is
/// precisely how the previous stub shipped unexercised. This code has therefore
/// been compile-verified but **not** run against a peer; see the PR and the
/// follow-up task.
#[cfg(feature = "kernel-sctp")]
struct SctpStream {
    socket: std::sync::Arc<nextgcore_sctp::KernelSctpSocket>,
    async_fd: tokio::io::unix::AsyncFd<SctpFdRef>,
    peer_addr: SocketAddr,
}

/// Borrowed-fd shim so an `AsyncFd` can track readiness without owning the
/// descriptor. Mirrors `nextgcore_sctp::kernel_server::FdRef`, which is private
/// to that module.
#[cfg(feature = "kernel-sctp")]
struct SctpFdRef(std::os::fd::RawFd);

#[cfg(feature = "kernel-sctp")]
impl std::os::fd::AsRawFd for SctpFdRef {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

#[cfg(feature = "kernel-sctp")]
impl SctpStream {
    /// Wrap an established SCTP socket, registering it with the tokio reactor.
    fn from_socket(socket: nextgcore_sctp::KernelSctpSocket) -> std::io::Result<Self> {
        // AsyncFd requires a non-blocking descriptor: a blocking socket would
        // stall the whole runtime thread inside try_io instead of yielding.
        socket
            .set_nonblocking(true)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let peer_addr = socket.remote_addr().unwrap_or_else(|| socket.local_addr());
        let raw = std::os::fd::AsRawFd::as_raw_fd(&socket);
        let async_fd = tokio::io::unix::AsyncFd::new(SctpFdRef(raw))?;

        Ok(Self {
            socket: std::sync::Arc::new(socket),
            async_fd,
            peer_addr,
        })
    }

    async fn connect(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = nextgcore_sctp::KernelSctpSocket::client(addr, None)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Self::from_socket(socket)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    /// Send one Diameter message as a single SCTP message on `stream_id`.
    async fn send(&mut self, data: &[u8], stream_id: u16) -> std::io::Result<()> {
        loop {
            let mut ready = self.async_fd.writable().await?;
            let attempt = ready.try_io(|_| {
                // The inner io::Error must be surfaced UNWRAPPED: try_io only
                // recognises a would-block by its ErrorKind, and flattening
                // through `to_string()` erases it. That turned a routine EAGAIN
                // on a non-blocking socket into a fatal error -- which is what
                // the first real run of this code produced ("Send failed:
                // Resource temporarily unavailable (os error 11)").
                self.socket
                    .send(data, DIAMETER_SCTP_PPID, stream_id)
                    .map_err(sctp_io_error)
            });
            match attempt {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                // try_io cleared readiness: wait for the next writable edge.
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive one SCTP message, appending it to `buf` and reporting its stream.
    ///
    /// SCTP notifications (association up/down) are skipped rather than surfaced
    /// as data: feeding a notification into the Diameter framer would be parsed
    /// as a malformed header and kill the connection.
    async fn recv(&mut self, buf: &mut BytesMut) -> std::io::Result<(usize, u16)> {
        let mut scratch = vec![0u8; nextgcore_sctp::NEXTGCORE_MAX_SDU_LEN];
        loop {
            let mut ready = self.async_fd.readable().await?;
            let attempt = ready.try_io(|_| {
                // Unwrapped for the same reason as `send`; see the note there.
                self.socket.recv_msg(&mut scratch).map_err(sctp_io_error)
            });
            match attempt {
                Ok(Ok((0, _info, _flags))) => return Ok((0, 0)),
                Ok(Ok((n, info, flags))) => {
                    if flags & nextgcore_sctp::MSG_NOTIFICATION != 0 {
                        // Not application data; keep waiting for a real message.
                        continue;
                    }
                    buf.extend_from_slice(&scratch[..n]);
                    return Ok((n, info.stream_no));
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        // Dropping the Arc closes the OwnedFd inside KernelSctpSocket. There is
        // no half-close here: SCTP's graceful shutdown is an association-level
        // operation the socket wrapper does not expose.
        Ok(())
    }
}

/// SCTP Diameter listener, backed by a real kernel SCTP socket.
///
/// One-to-one (`SOCK_STREAM`) sockets with `accept`, matching
/// `nextgcore_sctp::kernel_server`: each peer association becomes its own
/// accepted socket, so an accepted transport behaves like the TCP one and needs
/// no association demultiplexing.
///
/// Same runtime caveat as [`SctpDiameterTransport`]: links only where `libsctp`
/// is present.
#[cfg(feature = "kernel-sctp")]
pub struct SctpDiameterListener {
    socket: nextgcore_sctp::KernelSctpSocket,
    async_fd: tokio::io::unix::AsyncFd<SctpFdRef>,
}

#[cfg(feature = "kernel-sctp")]
impl SctpDiameterListener {
    /// Bind and listen for SCTP associations on `addr`.
    pub async fn bind(addr: SocketAddr) -> DiameterResult<Self> {
        let socket = nextgcore_sctp::KernelSctpSocket::server(addr)
            .map_err(|e| DiameterError::Io(std::io::Error::other(e.to_string())))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| DiameterError::Io(std::io::Error::other(e.to_string())))?;
        let raw = std::os::fd::AsRawFd::as_raw_fd(&socket);
        let async_fd = tokio::io::unix::AsyncFd::new(SctpFdRef(raw)).map_err(DiameterError::Io)?;
        Ok(Self { socket, async_fd })
    }

    /// Bind for SCTP unless the config disables it. See
    /// [`SctpDiameterTransport::connect_checked`].
    pub async fn bind_checked(addr: SocketAddr, config: &DiameterConfig) -> DiameterResult<Self> {
        if config.flags.no_sctp {
            return Err(DiameterError::Protocol(
                "SCTP is disabled by configuration (flags.no_sctp)".into(),
            ));
        }
        Self::bind(addr).await
    }

    /// The bound local address.
    pub fn local_addr(&self) -> DiameterResult<SocketAddr> {
        Ok(self.socket.local_addr())
    }

    /// Accept the next SCTP association as a Diameter transport.
    pub async fn accept(&self) -> DiameterResult<SctpDiameterTransport> {
        loop {
            let mut ready = self.async_fd.readable().await.map_err(DiameterError::Io)?;
            let attempt = ready.try_io(|_| {
                // Unwrapped so a would-block is retried, not reported.
                self.socket.accept().map_err(sctp_io_error)
            });
            match attempt {
                Ok(Ok((sock, _peer))) => {
                    let stream = SctpStream::from_socket(sock).map_err(DiameterError::Io)?;
                    return SctpDiameterTransport::new(stream);
                }
                Ok(Err(e)) => return Err(DiameterError::Io(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod request_timeout_tests {
    //! `send_request` must not wait forever for an answer.
    //!
    //! Both tests use a peer that stays CONNECTED, because the pre-fix loop did
    //! already handle `Disconnected` -- a peer that drops the socket was never
    //! the hang. The hang needed a peer that completes CER/CEA and then either
    //! goes silent or answers only watchdogs, which is what these reproduce.
    use super::*;
    use crate::avp::{Avp, AvpData};
    use crate::config::DiameterConfig;
    use crate::message::DiameterMessage;

    /// Short window so the test is fast; the production default is 30s.
    const TEST_TIMEOUT_SECS: u32 = 1;

    fn client_config() -> DiameterConfig {
        DiameterConfig {
            diameter_id: "mme.example.com".to_string(),
            diameter_realm: "example.com".to_string(),
            request_timeout: TEST_TIMEOUT_SECS,
            ..Default::default()
        }
    }

    fn server_config() -> DiameterConfig {
        DiameterConfig {
            diameter_id: "hss.example.com".to_string(),
            diameter_realm: "example.com".to_string(),
            ..Default::default()
        }
    }

    /// A peer that answers CER then never answers the application request must
    /// produce RequestTimeout rather than parking the caller forever.
    #[tokio::test]
    async fn silent_peer_yields_request_timeout() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let cfg = server_config();
        let server = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = crate::peer::DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            // Receive the AIR and deliberately send NOTHING back, while holding
            // the connection open so the client cannot escape via Disconnected.
            let _air = peer.next_event().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let mut client = DiameterClient::new(client_config(), listen_addr);
        client.connect().await.unwrap();

        let air = DiameterMessage::new_request(318, 16777251);
        let result = client.send_request(&air).await;

        match result {
            Err(DiameterError::RequestTimeout { command, seconds }) => {
                assert_eq!(command, 318, "the stalled command is named");
                assert_eq!(seconds, u64::from(TEST_TIMEOUT_SECS));
            }
            other => panic!("expected RequestTimeout, got {other:?}"),
        }
        server.abort();
    }

    /// A peer that keeps the watchdog alive but never answers the request must
    /// also time out. This is the case the `PeerEvent::WatchdogAck => continue`
    /// arm would otherwise let run indefinitely, and it is why the deadline
    /// spans the whole exchange instead of being reset per event.
    #[tokio::test]
    async fn watchdog_traffic_does_not_extend_the_deadline() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let cfg = server_config();
        let server = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = crate::peer::DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            let _air = peer.next_event().await.unwrap();
            // Never answer the AIR, but keep sending watchdogs so the client
            // sees a steady stream of events it is designed to skip.
            loop {
                if peer.send_watchdog().await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        let mut client = DiameterClient::new(client_config(), listen_addr);
        client.connect().await.unwrap();

        let air = DiameterMessage::new_request(318, 16777251);
        let started = tokio::time::Instant::now();
        let result = client.send_request(&air).await;
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(DiameterError::RequestTimeout { .. })),
            "expected RequestTimeout, got {result:?}"
        );
        // Generous upper bound: the point is that it is BOUNDED, not that the
        // timer is precise under a loaded test runner.
        assert!(
            elapsed < Duration::from_secs(10),
            "watchdog traffic extended the deadline: {elapsed:?}"
        );
        server.abort();
    }

    /// The timeout must not break the normal path: a peer that answers promptly
    /// still gets its answer matched on Hop-by-Hop ID.
    #[tokio::test]
    async fn answering_peer_still_succeeds() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let cfg = server_config();
        let server = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = crate::peer::DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            if let PeerEvent::Message(msg) = peer.next_event().await.unwrap() {
                let mut answer = DiameterMessage::new_answer(&msg);
                answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                peer.send_message(&answer).await.unwrap();
            }
        });

        let mut client = DiameterClient::new(client_config(), listen_addr);
        client.connect().await.unwrap();

        let air = DiameterMessage::new_request(318, 16777251);
        let answer = client.send_request(&air).await.expect("answer expected");
        assert!(answer.header.is_answer());
        assert_eq!(answer.result_code(), Some(2001));
        server.abort();
    }
}

#[cfg(test)]
mod sctp_tests {
    use super::*;

    #[test]
    fn test_transport_kind() {
        assert_eq!(DiameterTransportKind::Tcp, DiameterTransportKind::Tcp);
        assert_ne!(DiameterTransportKind::Tcp, DiameterTransportKind::Sctp);
    }

    // The previous `test_sctp_not_implemented` asserted that `connect` returns an
    // error, which was only true of the stub. It is deleted rather than inverted:
    // the replacement assertion ("connect succeeds") needs a listening SCTP peer,
    // and this host cannot even LINK the feature (`ld: cannot find -lsctp`), so a
    // test here would be unrunnable rather than merely skipped.
    //
    // What remains verifiable without libsctp is the transport-kind plumbing
    // above. Runtime coverage requires a libsctp-equipped Linux host with
    // `modprobe sctp`; see the follow-up task and the PR's own scope note.
    /// Both transport kinds must be representable and distinct, so a caller can
    /// select SCTP even in a build where the feature is off.
    #[test]
    fn both_transport_kinds_are_selectable() {
        let kinds = [DiameterTransportKind::Tcp, DiameterTransportKind::Sctp];
        assert_eq!(kinds.len(), 2);
        assert_ne!(kinds[0], kinds[1]);
    }

    /// RFC 6733 §2.1.1 assigns PPID 46 to Diameter in an SCTP DATA chunk (47 is
    /// the DTLS variant, which this transport does not implement). Pinned because
    /// a wrong PPID is accepted by the socket layer and only rejected by the far
    /// end, which is an expensive place to discover a typo.
    #[cfg(feature = "kernel-sctp")]
    #[test]
    fn diameter_sctp_ppid_is_46() {
        assert_eq!(DIAMETER_SCTP_PPID, 46);
    }

    /// `flags.no_sctp` must be honoured, and must be honoured BEFORE any socket
    /// call -- which is what makes this assertion runnable on a host with no
    /// libsctp at all. The flag was declared but read nowhere until SCTP existed.
    #[cfg(feature = "kernel-sctp")]
    #[tokio::test]
    async fn no_sctp_flag_refuses_before_touching_a_socket() {
        let mut config = DiameterConfig::default();
        config.flags.no_sctp = true;
        // Port 1 on loopback: nothing listens, so a connect attempt would fail
        // for the WRONG reason. The refusal must come from the flag instead.
        let addr: SocketAddr = ([127, 0, 0, 1], 1).into();

        // Matched rather than `expect_err`: the Ok variants hold raw descriptors
        // and deliberately do not implement Debug.
        match SctpDiameterTransport::connect_checked(addr, &config).await {
            Err(e) => assert!(
                e.to_string().contains("no_sctp"),
                "the error must name the flag, got: {e}"
            ),
            Ok(_) => panic!("no_sctp must refuse to connect"),
        }

        match SctpDiameterListener::bind_checked(addr, &config).await {
            Err(e) => assert!(e.to_string().contains("no_sctp"), "got: {e}"),
            Ok(_) => panic!("no_sctp must refuse to bind"),
        }
    }

    // -----------------------------------------------------------------------
    // Real SCTP end-to-end
    //
    // These are the first tests to actually OPEN an SCTP socket. Everything
    // else under this feature is either pure logic or refuses before touching
    // the network, which is why the transport shipped unexercised: the code
    // type-checked, and on a host without libsctp it could not even link.
    //
    // Requirements: `libsctp` (to link) and the `sctp` kernel module loaded
    // (`modprobe sctp`). No root is needed at RUN time -- an unprivileged
    // process may open `IPPROTO_SCTP` SOCK_STREAM sockets, unlike raw sockets.
    // If the module is absent, `bind` fails with EPROTONOSUPPORT and these
    // tests fail loudly rather than silently passing, which is the intent: a
    // skipped test here would recreate the false confidence being fixed.
    // -----------------------------------------------------------------------

    #[cfg(feature = "kernel-sctp")]
    fn sctp_config(host: &str) -> DiameterConfig {
        DiameterConfig {
            diameter_id: host.to_string(),
            diameter_realm: "sctp.example.org".to_string(),
            ..Default::default()
        }
    }

    /// A full Diameter exchange over real SCTP: bind, connect, CER/CEA, then an
    /// AIR answered with an AIA.
    ///
    /// This covers the two parts of the transport that were least certain by
    /// inspection: the PPID-46 send path, and the `recv` loop's skipping of SCTP
    /// notifications (an unfiltered notification would enter the Diameter framer
    /// as a malformed header and kill the association).
    #[cfg(feature = "kernel-sctp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sctp_carries_a_full_diameter_exchange() {
        use crate::avp::{Avp, AvpData};
        use crate::peer::{DiameterPeer, PeerEvent};

        const AIR: u32 = 318;
        const S6A_APP: u32 = 16777251;

        // Port 0: the kernel assigns a free SCTP port, so concurrent test runs
        // cannot collide.
        let listener = SctpDiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .expect("SCTP bind failed -- is the sctp kernel module loaded?");
        let addr = listener.local_addr().expect("local_addr");
        assert_ne!(addr.port(), 0, "the kernel must assign a real port");

        // Responder: accept one association, complete CER/CEA, answer the AIR.
        let server = tokio::spawn(async move {
            let transport = listener.accept().await.expect("accept");
            let cfg = sctp_config("hss.sctp.example.org");
            let mut peer = DiameterPeer::new_responder_generic(transport, &cfg);
            peer.start().await.expect("responder start");

            match peer.next_event().await.expect("CER") {
                PeerEvent::Established { origin_host, .. } => {
                    assert_eq!(origin_host, "mme.sctp.example.org");
                }
                other => panic!("expected Established, got {other:?}"),
            }

            match peer.next_event().await.expect("AIR") {
                PeerEvent::Message(request) => {
                    assert_eq!(request.header.command_code, AIR);
                    let mut answer = DiameterMessage::new_answer(&request);
                    answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                    peer.send_message(&answer).await.expect("send AIA");
                }
                other => panic!("expected the AIR, got {other:?}"),
            }
        });

        // Initiator.
        let transport = SctpDiameterTransport::connect(addr)
            .await
            .expect("SCTP connect");
        let cfg = sctp_config("mme.sctp.example.org");
        let mut client = DiameterPeer::new_initiator_generic(transport, &cfg);
        client.start().await.expect("send CER");

        match client.next_event().await.expect("CEA") {
            PeerEvent::Established { origin_host, .. } => {
                assert_eq!(origin_host, "hss.sctp.example.org");
            }
            other => panic!("expected Established, got {other:?}"),
        }

        let air = DiameterMessage::new_request(AIR, S6A_APP);
        client.send_message(&air).await.expect("send AIR");

        match client.next_event().await.expect("AIA") {
            PeerEvent::Message(answer) => {
                assert!(answer.header.is_answer());
                assert_eq!(answer.result_code(), Some(2001));
            }
            other => panic!("expected the AIA, got {other:?}"),
        }

        server.await.expect("responder task");
    }

    /// Framing must survive messages larger than one read: SCTP is
    /// message-oriented, so this also proves a Diameter message is not being
    /// silently truncated at an SCTP message boundary.
    #[cfg(feature = "kernel-sctp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sctp_preserves_framing_for_a_large_message() {
        use crate::avp::{Avp, AvpData};

        let listener = SctpDiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .expect("SCTP bind");
        let addr = listener.local_addr().expect("local_addr");

        let server = tokio::spawn(async move {
            let mut transport = listener.accept().await.expect("accept");
            transport.recv().await.expect("recv large message")
        });

        let mut transport = SctpDiameterTransport::connect(addr)
            .await
            .expect("SCTP connect");

        // ~4KB of AVP payload: comfortably past the 4096-byte initial read
        // buffer, so the framer must reassemble rather than assume one read.
        let mut msg = DiameterMessage::new_request(316, 16777251);
        msg.add_avp(Avp::mandatory(
            crate::common::avp_code::USER_NAME,
            AvpData::Utf8String("x".repeat(4096)),
        ));
        let expected_len = msg.encode().len();
        transport.send(&msg).await.expect("send");

        let received = server.await.expect("server task");
        assert_eq!(received.header.command_code, 316);
        assert_eq!(
            received.encode().len(),
            expected_len,
            "the message must survive framing intact"
        );
        assert_eq!(
            received
                .find_avp(crate::common::avp_code::USER_NAME)
                .and_then(|a| a.as_utf8_string())
                .map(|s| s.len()),
            Some(4096)
        );
    }
}
