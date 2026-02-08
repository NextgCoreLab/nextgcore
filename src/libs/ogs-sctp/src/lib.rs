//! NextGCore SCTP Transport Library
//!
//! This crate provides SCTP socket operations with two implementation options:
//!
//! # Features
//! - `sctp-proto` (default): Pure Rust SCTP over UDP using sctp-proto
//!   - Wire-compatible with nextgsim for 5G simulation
//!   - No kernel dependencies, works on any platform
//!   - Requires both ends to use SCTP-over-UDP with sctp-proto
//!
//! - `kernel`: Linux kernel SCTP using native sockets
//!   - Requires `libsctp-dev` at build time, `libsctp1` at runtime
//!   - Requires SCTP kernel module: `sudo modprobe sctp`
//!   - Compatible with standard SCTP implementations (Open5GS, srsRAN, etc.)
//!   - Docker: use `38412:38412/sctp` port mapping
//!
//! # Docker SCTP Setup
//! To enable kernel SCTP in Docker:
//! 1. Load SCTP module on host: `sudo modprobe sctp`
//! 2. Verify: `lsmod | grep sctp`
//! 3. Use `/sctp` protocol in port mapping: `ports: ["38412:38412/sctp"]`
//!
//! # Wire Compatibility
//! The sctp-proto implementation is wire-compatible with nextgsim's SCTP,
//! allowing gNB (nextgsim) to connect to AMF (nextgcore) over SCTP-over-UDP.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ogs_core::pkbuf::OgsPkbuf;
use ogs_core::sockaddr::OgsSockaddr;

use thiserror::Error;
use tokio::sync::Mutex;

// Kernel SCTP module (Linux only, requires libsctp)
#[cfg(feature = "kernel")]
pub mod kernel;

#[cfg(feature = "kernel")]
pub use kernel::KernelSctpSocket;

// sctp-proto based server module
#[cfg(feature = "sctp-proto")]
pub mod server;

#[cfg(feature = "sctp-proto")]
pub use server::{SctpServer, SctpServerConfig, ServerError, ServerEvent};

// QUIC transport option (B13.3 - 6G forward-looking)
pub mod quic;

pub use quic::{
    QuicTransport, QuicServer, QuicConfig, TlsConfig as QuicTlsConfig,
    QuicConnectionState, QuicError, QuicResult, StreamMessage,
    CongestionController, QuicStats,
};

// ============================================================================
// Constants (matching 3GPP specifications)
// ============================================================================

/// S1AP SCTP port (3GPP TS 36.412)
pub const OGS_S1AP_SCTP_PORT: u16 = 36412;

/// SGsAP SCTP port (3GPP TS 29.118)
pub const OGS_SGSAP_SCTP_PORT: u16 = 29118;

/// NGAP SCTP port (3GPP TS 38.412)
pub const OGS_NGAP_SCTP_PORT: u16 = 38412;

/// S1AP PPID (Payload Protocol Identifier)
pub const OGS_SCTP_S1AP_PPID: u32 = 18;

/// X2AP PPID
pub const OGS_SCTP_X2AP_PPID: u32 = 27;

/// SGsAP PPID
pub const OGS_SCTP_SGSAP_PPID: u32 = 0;

/// NGAP PPID
pub const OGS_SCTP_NGAP_PPID: u32 = 60;

/// NGAP PPID (alias for server module compatibility)
pub const NGAP_PPID: u32 = 60;

/// Maximum SDU length
pub const OGS_MAX_SDU_LEN: usize = 8192;

/// MSG_NOTIFICATION flag for SCTP notifications
pub const MSG_NOTIFICATION: i32 = 0x8000;

/// MSG_EOR flag for end of record
pub const MSG_EOR: i32 = 0x80;

/// Default number of SCTP streams for NGAP
pub const DEFAULT_NUM_STREAMS: u16 = 2;

/// Default maximum message size (64KB)
pub const DEFAULT_MAX_MESSAGE_SIZE: u32 = 65536;

/// Default receive buffer size (256KB)
pub const DEFAULT_RECEIVE_BUFFER_SIZE: u32 = 262144;

// ============================================================================
// Error types
// ============================================================================

/// SCTP-specific errors
#[derive(Error, Debug)]
pub enum SctpError {
    #[error("Socket creation failed: {0}")]
    SocketCreation(io::Error),

    #[error("Bind failed: {0}")]
    BindFailed(io::Error),

    #[error("Connect failed: {0}")]
    ConnectFailed(io::Error),

    #[error("Listen failed: {0}")]
    ListenFailed(io::Error),

    #[error("Send failed: {0}")]
    SendFailed(io::Error),

    #[error("Receive failed: {0}")]
    ReceiveFailed(io::Error),

    #[error("Socket option failed: {0}")]
    SockoptFailed(io::Error),

    #[error("No valid address in list")]
    NoValidAddress,

    #[error("Invalid socket")]
    InvalidSocket,

    #[error("Association not established")]
    NotConnected,

    #[error("SCTP protocol error: {0}")]
    Protocol(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Association closed")]
    AssociationClosed,

    #[error("Stream error: {0}")]
    StreamError(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

pub type Result<T> = std::result::Result<T, SctpError>;

// ============================================================================
// SCTP Info structure
// ============================================================================

/// SCTP message information
#[derive(Debug, Clone, Default)]
pub struct OgsSctpInfo {
    /// Payload Protocol Identifier
    pub ppid: u32,
    /// Stream number
    pub stream_no: u16,
    /// Number of inbound streams
    pub inbound_streams: u16,
    /// Number of outbound streams
    pub outbound_streams: u16,
}

// ============================================================================
// SCTP Association State
// ============================================================================

/// SCTP association state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationState {
    Closed,
    CookieWait,
    CookieEchoed,
    Established,
    ShutdownPending,
    ShutdownSent,
    ShutdownReceived,
    ShutdownAckSent,
    Connecting,
    ShuttingDown,
}

// ============================================================================
// Received Message (for server module compatibility)
// ============================================================================

/// Received SCTP message
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub stream_id: u16,
    pub data: Bytes,
    pub ppid: u32,
}

// ============================================================================
// SCTP Events
// ============================================================================

/// SCTP association events
#[derive(Debug, Clone)]
pub enum SctpEvent {
    Connected,
    Disconnected,
    DataReceived(ReceivedMessage),
    StreamOpened(u16),
    StreamClosed(u16),
}

// ============================================================================
// SCTP Configuration
// ============================================================================

/// Configuration for SCTP association
#[derive(Debug, Clone)]
pub struct SctpConfig {
    pub max_outbound_streams: u16,
    pub max_inbound_streams: u16,
    pub max_message_size: u32,
    pub max_receive_buffer_size: u32,
    pub connect_timeout: Duration,
    pub rto_initial_ms: u64,
    pub rto_min_ms: u64,
    pub rto_max_ms: u64,
}

impl Default for SctpConfig {
    fn default() -> Self {
        Self {
            max_outbound_streams: DEFAULT_NUM_STREAMS,
            max_inbound_streams: DEFAULT_NUM_STREAMS,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_receive_buffer_size: DEFAULT_RECEIVE_BUFFER_SIZE,
            connect_timeout: Duration::from_secs(30),
            rto_initial_ms: 3000,
            rto_min_ms: 1000,
            rto_max_ms: 60000,
        }
    }
}

// ============================================================================
// Pure Rust SCTP using sctp-proto (userspace implementation)
// ============================================================================

#[cfg(feature = "sctp-proto")]
mod sctp_proto_impl {
    use super::*;
    use sctp_proto::{
        Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig,
        Event, Payload, PayloadProtocolIdentifier, TransportConfig, Transmit,
    };
    use std::collections::VecDeque;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tracing::{debug, info, trace, warn};

    /// SCTP association wrapper for NGAP transport using sctp-proto
    pub struct SctpAssociation {
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        endpoint: Endpoint,
        handle: AssociationHandle,
        association: Association,
        state: AssociationState,
        pending_transmits: VecDeque<Transmit>,
        event_tx: Option<mpsc::UnboundedSender<SctpEvent>>,
        config: SctpConfig,
    }

    impl SctpAssociation {
        /// Connect to a remote SCTP endpoint (AMF)
        pub async fn connect(remote_addr: SocketAddr, config: SctpConfig) -> Result<Self> {
            let local_addr: SocketAddr = if remote_addr.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            Self::connect_with_local(local_addr, remote_addr, config).await
        }

        /// Connect to a remote SCTP endpoint with a specific local address
        pub async fn connect_with_local(
            local_addr: SocketAddr,
            remote_addr: SocketAddr,
            config: SctpConfig,
        ) -> Result<Self> {
            info!("Connecting to SCTP endpoint at {}", remote_addr);

            // Bind UDP socket
            let socket = UdpSocket::bind(local_addr)
                .await
                .map_err(SctpError::BindFailed)?;
            let actual_local = socket.local_addr().map_err(SctpError::BindFailed)?;
            debug!("Bound to local address: {}", actual_local);

            // Create endpoint config
            let endpoint_config = EndpointConfig::new();
            let mut endpoint = Endpoint::new(Arc::new(endpoint_config), None);

            // Create transport config with builder pattern
            let transport_config = TransportConfig::default()
                .with_max_num_outbound_streams(config.max_outbound_streams)
                .with_max_num_inbound_streams(config.max_inbound_streams)
                .with_max_message_size(config.max_message_size)
                .with_max_receive_buffer_size(config.max_receive_buffer_size)
                .with_rto_initial_ms(config.rto_initial_ms)
                .with_rto_min_ms(config.rto_min_ms)
                .with_rto_max_ms(config.rto_max_ms);

            // Create client config
            let mut client_config = ClientConfig::new();
            client_config.transport = Arc::new(transport_config);

            // Initiate connection
            let (handle, association) = endpoint
                .connect(client_config, remote_addr)
                .map_err(|e| SctpError::ConnectFailed(io::Error::other(e.to_string())))?;

            let socket = Arc::new(socket);
            let mut assoc = Self {
                socket,
                remote_addr,
                local_addr: actual_local,
                endpoint,
                handle,
                association,
                state: AssociationState::Connecting,
                pending_transmits: VecDeque::new(),
                event_tx: None,
                config,
            };

            // Perform handshake
            assoc.perform_handshake().await?;

            Ok(assoc)
        }

        /// Perform SCTP 4-way handshake
        async fn perform_handshake(&mut self) -> Result<()> {
            let deadline = Instant::now() + self.config.connect_timeout;

            while self.state == AssociationState::Connecting {
                if Instant::now() > deadline {
                    return Err(SctpError::Timeout("Connection handshake timed out".into()));
                }

                // Flush any pending transmits
                self.flush_transmits().await?;

                // Poll for events
                self.poll_events();

                // Check if handshake completed
                if !self.association.is_handshaking() {
                    self.state = AssociationState::Established;
                    info!("SCTP association established with {}", self.remote_addr);
                    if let Some(tx) = &self.event_tx {
                        let _ = tx.send(SctpEvent::Connected);
                    }
                    return Ok(());
                }

                // Receive incoming packets with timeout
                let recv_timeout = Duration::from_millis(100);
                match timeout(recv_timeout, self.handle_incoming()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!("Error handling incoming packet: {}", e);
                    }
                    Err(_) => {
                        // Timeout, continue loop
                        trace!("Receive timeout, continuing handshake");
                    }
                }
            }

            Ok(())
        }

        /// Handle incoming UDP packets
        async fn handle_incoming(&mut self) -> Result<()> {
            let mut buf = vec![0u8; self.config.max_receive_buffer_size as usize];
            let (len, from) = self.socket.recv_from(&mut buf).await.map_err(SctpError::ReceiveFailed)?;
            buf.truncate(len);

            trace!("Received {} bytes from {}", len, from);

            let now = Instant::now();
            if let Some((handle, event)) = self.endpoint.handle(now, from, None, None, Bytes::from(buf)) {
                if handle == self.handle {
                    match event {
                        DatagramEvent::AssociationEvent(assoc_event) => {
                            self.association.handle_event(assoc_event);
                        }
                        DatagramEvent::NewAssociation(_) => {
                            // We're a client, ignore new associations
                            debug!("Ignoring new association event (client mode)");
                        }
                    }
                }
            }

            Ok(())
        }

        /// Poll for association events and process them
        fn poll_events(&mut self) {
            while let Some(event) = self.association.poll() {
                match event {
                    Event::Connected => {
                        debug!("Association connected event");
                        self.state = AssociationState::Established;
                    }
                    Event::AssociationLost { reason } => {
                        warn!("Association lost: {}", reason);
                        self.state = AssociationState::Closed;
                        if let Some(tx) = &self.event_tx {
                            let _ = tx.send(SctpEvent::Disconnected);
                        }
                    }
                    Event::Stream(stream_event) => {
                        trace!("Stream event: {:?}", stream_event);
                    }
                    Event::DatagramReceived => {
                        trace!("Datagram received event");
                    }
                }
            }

            // Handle timeouts
            if let Some(timeout_instant) = self.association.poll_timeout() {
                if Instant::now() >= timeout_instant {
                    self.association.handle_timeout(Instant::now());
                }
            }

            // Collect transmits from association
            while let Some(transmit) = self.association.poll_transmit(Instant::now()) {
                self.pending_transmits.push_back(transmit);
            }

            // Collect transmits from endpoint
            while let Some(transmit) = self.endpoint.poll_transmit() {
                self.pending_transmits.push_back(transmit);
            }
        }

        /// Flush pending transmits to the network
        async fn flush_transmits(&mut self) -> Result<()> {
            while let Some(transmit) = self.pending_transmits.pop_front() {
                match &transmit.payload {
                    Payload::RawEncode(chunks) => {
                        for chunk in chunks {
                            self.socket.send_to(chunk, transmit.remote).await.map_err(SctpError::SendFailed)?;
                            trace!("Sent {} bytes to {}", chunk.len(), transmit.remote);
                        }
                    }
                    Payload::PartialDecode(_) => {
                        // PartialDecode is for incoming packets, skip for outgoing
                        trace!("Skipping PartialDecode payload for transmit");
                    }
                }
            }
            Ok(())
        }

        /// Send data on a specific stream with NGAP PPID
        pub async fn send(&mut self, stream_id: u16, data: &[u8]) -> Result<()> {
            self.send_with_ppid(stream_id, data, NGAP_PPID).await
        }

        /// Send data on a specific stream with custom PPID
        pub async fn send_with_ppid(&mut self, stream_id: u16, data: &[u8], ppid: u32) -> Result<()> {
            if self.state != AssociationState::Established {
                return Err(SctpError::InvalidState(
                    "Cannot send: association not established".into(),
                ));
            }

            let ppi = PayloadProtocolIdentifier::from(ppid);

            let mut stream = self.association.open_stream(stream_id, ppi)
                .map_err(|e| SctpError::StreamError(e.to_string()))?;

            stream.write_with_ppi(data, ppi)
                .map_err(|e| SctpError::StreamError(e.to_string()))?;

            debug!("Queued {} bytes on stream {} with PPID {}", data.len(), stream_id, ppid);

            // Poll and flush
            self.poll_events();
            self.flush_transmits().await?;

            Ok(())
        }

        /// Receive a message (blocking)
        pub async fn recv(&mut self) -> Result<Option<ReceivedMessage>> {
            if self.state == AssociationState::Closed {
                return Err(SctpError::AssociationClosed);
            }

            loop {
                // Check for available data first
                if let Some(msg) = self.try_recv()? {
                    return Ok(Some(msg));
                }

                // Handle incoming packets
                self.handle_incoming().await?;
                self.poll_events();
                self.flush_transmits().await?;

                // Check state
                if self.state == AssociationState::Closed {
                    return Ok(None);
                }
            }
        }

        /// Try to receive a message (non-blocking)
        pub fn try_recv(&mut self) -> Result<Option<ReceivedMessage>> {
            // Accept any incoming streams
            while let Some(mut stream) = self.association.accept_stream() {
                let stream_id = stream.stream_identifier();
                debug!("Accepted stream {}", stream_id);

                if let Some(tx) = &self.event_tx {
                    let _ = tx.send(SctpEvent::StreamOpened(stream_id));
                }

                // Try to read from the stream
                if let Ok(Some(chunks)) = stream.read() {
                    let ppid = match chunks.ppi {
                        PayloadProtocolIdentifier::Dcep => 50,
                        PayloadProtocolIdentifier::String => 51,
                        PayloadProtocolIdentifier::Binary => 53,
                        PayloadProtocolIdentifier::StringEmpty => 56,
                        PayloadProtocolIdentifier::BinaryEmpty => 57,
                        PayloadProtocolIdentifier::Unknown => NGAP_PPID,
                    };
                    // Read all data from chunks into a buffer
                    let total_len = chunks.len();
                    if total_len > 0 {
                        let mut buf = vec![0u8; total_len];
                        if chunks.read(&mut buf).is_ok() {
                            let msg = ReceivedMessage {
                                stream_id,
                                data: Bytes::from(buf),
                                ppid,
                            };
                            debug!("Received {} bytes on stream {} with PPID {}", msg.data.len(), stream_id, msg.ppid);

                            if let Some(tx) = &self.event_tx {
                                let _ = tx.send(SctpEvent::DataReceived(msg.clone()));
                            }

                            return Ok(Some(msg));
                        }
                    }
                }
            }

            Ok(None)
        }

        /// Initiate graceful shutdown
        pub async fn shutdown(&mut self) -> Result<()> {
            if self.state == AssociationState::Closed {
                return Ok(());
            }

            info!("Initiating SCTP shutdown");
            self.state = AssociationState::ShuttingDown;

            let _ = self.association.shutdown();
            self.poll_events();
            self.flush_transmits().await?;

            // Wait for shutdown to complete with timeout
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.state == AssociationState::ShuttingDown && Instant::now() < deadline {
                if let Ok(Ok(())) = timeout(Duration::from_millis(100), self.handle_incoming()).await {}
                self.poll_events();
                self.flush_transmits().await?;

                if self.association.is_closed() {
                    break;
                }
            }

            self.state = AssociationState::Closed;
            if let Some(tx) = &self.event_tx {
                let _ = tx.send(SctpEvent::Disconnected);
            }

            info!("SCTP shutdown complete");
            Ok(())
        }

        /// Close the association immediately
        pub fn close(&mut self) {
            if self.state != AssociationState::Closed {
                let _ = self.association.close();
                self.state = AssociationState::Closed;
                if let Some(tx) = &self.event_tx {
                    let _ = tx.send(SctpEvent::Disconnected);
                }
            }
        }

        // Accessor methods

        /// Check if the association is established
        pub fn is_established(&self) -> bool {
            self.state == AssociationState::Established
        }

        /// Check if the association is closed
        pub fn is_closed(&self) -> bool {
            self.state == AssociationState::Closed
        }

        /// Get the current state
        pub fn state(&self) -> AssociationState {
            self.state
        }

        /// Get the remote address
        pub fn remote_addr(&self) -> SocketAddr {
            self.remote_addr
        }

        /// Get the local address
        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        /// Get the current RTT estimate
        pub fn rtt(&self) -> Duration {
            self.association.rtt()
        }

        /// Set the event sender for receiving association events
        pub fn set_event_sender(&mut self, tx: mpsc::UnboundedSender<SctpEvent>) {
            self.event_tx = Some(tx);
        }
    }

    impl Drop for SctpAssociation {
        fn drop(&mut self) {
            if self.state != AssociationState::Closed {
                self.close();
            }
        }
    }
}

#[cfg(feature = "sctp-proto")]
pub use sctp_proto_impl::SctpAssociation;

// ============================================================================
// Synchronous wrapper for compatibility with existing API
// ============================================================================

/// SCTP socket wrapper with write queue support (sync API)
pub struct OgsSctpSock {
    /// Socket type (SOCK_STREAM or SOCK_SEQPACKET)
    pub sock_type: i32,
    /// Local address
    pub local_addr: Option<OgsSockaddr>,
    /// Remote address
    pub remote_addr: Option<OgsSockaddr>,
    /// Write queue for buffered sending
    pub write_queue: VecDeque<OgsPkbuf>,
    /// Internal async socket (wrapped in mutex for sync access)
    #[cfg(feature = "sctp-proto")]
    inner: Option<Arc<Mutex<SctpAssociation>>>,
}

impl OgsSctpSock {
    /// Create a new SCTP socket wrapper
    pub fn new(sock_type: i32) -> Self {
        OgsSctpSock {
            sock_type,
            local_addr: None,
            remote_addr: None,
            write_queue: VecDeque::new(),
            #[cfg(feature = "sctp-proto")]
            inner: None,
        }
    }
}

/// SOCK_STREAM constant for compatibility
pub const SOCK_STREAM: i32 = 1;

/// SOCK_SEQPACKET constant for compatibility
pub const SOCK_SEQPACKET: i32 = 5;

impl Default for OgsSctpSock {
    fn default() -> Self {
        Self::new(SOCK_STREAM)
    }
}

// ============================================================================
// Helper functions for pkbuf SCTP parameters
// ============================================================================

/// Get PPID from packet buffer param[0]
#[inline]
pub fn ogs_sctp_ppid_in_pkbuf(pkbuf: &OgsPkbuf) -> u32 {
    pkbuf.param[0] as u32
}

/// Get stream number from packet buffer param[1]
#[inline]
pub fn ogs_sctp_stream_no_in_pkbuf(pkbuf: &OgsPkbuf) -> u16 {
    pkbuf.param[1] as u16
}

/// Set PPID in packet buffer param[0]
#[inline]
pub fn ogs_sctp_set_ppid_in_pkbuf(pkbuf: &mut OgsPkbuf, ppid: u32) {
    pkbuf.param[0] = ppid as u64;
}

/// Set stream number in packet buffer param[1]
#[inline]
pub fn ogs_sctp_set_stream_no_in_pkbuf(pkbuf: &mut OgsPkbuf, stream_no: u16) {
    pkbuf.param[1] = stream_no as u64;
}

// ============================================================================
// SCTP initialization
// ============================================================================

/// Initialize SCTP subsystem
pub fn ogs_sctp_init(_port: u16) {
    log::debug!("SCTP subsystem initialized (sctp-proto userspace)");
}

/// Finalize SCTP subsystem
pub fn ogs_sctp_final() {
    log::debug!("SCTP subsystem finalized");
}

// ============================================================================
// Write queue operations
// ============================================================================

/// Add packet to write queue
pub fn ogs_sctp_write_to_buffer(sctp: &mut OgsSctpSock, pkbuf: OgsPkbuf) {
    sctp.write_queue.push_back(pkbuf);
}

/// Flush write queue and destroy socket
pub fn ogs_sctp_flush_and_destroy(sctp: &mut OgsSctpSock) {
    sctp.local_addr = None;
    sctp.remote_addr = None;
    sctp.write_queue.clear();
    #[cfg(feature = "sctp-proto")]
    {
        sctp.inner = None;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // Constant Tests
    // ============================================================================

    #[test]
    fn test_constants() {
        assert_eq!(OGS_S1AP_SCTP_PORT, 36412);
        assert_eq!(OGS_NGAP_SCTP_PORT, 38412);
        assert_eq!(OGS_SGSAP_SCTP_PORT, 29118);
        assert_eq!(OGS_SCTP_S1AP_PPID, 18);
        assert_eq!(OGS_SCTP_NGAP_PPID, 60);
        assert_eq!(OGS_SCTP_X2AP_PPID, 27);
        assert_eq!(OGS_SCTP_SGSAP_PPID, 0);
        assert_eq!(NGAP_PPID, 60);
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_NUM_STREAMS, 2);
        assert_eq!(DEFAULT_MAX_MESSAGE_SIZE, 65536);
        assert_eq!(DEFAULT_RECEIVE_BUFFER_SIZE, 262144);
        assert_eq!(OGS_MAX_SDU_LEN, 8192);
    }

    #[test]
    fn test_msg_flags() {
        assert_eq!(MSG_NOTIFICATION, 0x8000);
        assert_eq!(MSG_EOR, 0x80);
    }

    #[test]
    fn test_sock_types() {
        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_SEQPACKET, 5);
    }

    // ============================================================================
    // OgsSctpInfo Tests
    // ============================================================================

    #[test]
    fn test_sctp_info_default() {
        let info = OgsSctpInfo::default();
        assert_eq!(info.ppid, 0);
        assert_eq!(info.stream_no, 0);
        assert_eq!(info.inbound_streams, 0);
        assert_eq!(info.outbound_streams, 0);
    }

    #[test]
    fn test_sctp_info_custom() {
        let info = OgsSctpInfo {
            ppid: 60,
            stream_no: 1,
            inbound_streams: 2,
            outbound_streams: 2,
        };
        assert_eq!(info.ppid, 60);
        assert_eq!(info.stream_no, 1);
        assert_eq!(info.inbound_streams, 2);
        assert_eq!(info.outbound_streams, 2);
    }

    #[test]
    fn test_sctp_info_clone() {
        let info1 = OgsSctpInfo {
            ppid: 60,
            stream_no: 1,
            inbound_streams: 2,
            outbound_streams: 2,
        };
        let info2 = info1.clone();
        assert_eq!(info1.ppid, info2.ppid);
        assert_eq!(info1.stream_no, info2.stream_no);
    }

    // ============================================================================
    // OgsSctpSock Tests
    // ============================================================================

    #[test]
    fn test_sctp_sock_default() {
        let sock = OgsSctpSock::default();
        assert_eq!(sock.sock_type, SOCK_STREAM);
        assert!(sock.local_addr.is_none());
        assert!(sock.remote_addr.is_none());
        assert!(sock.write_queue.is_empty());
    }

    #[test]
    fn test_sctp_sock_new_stream() {
        let sock = OgsSctpSock::new(SOCK_STREAM);
        assert_eq!(sock.sock_type, SOCK_STREAM);
    }

    #[test]
    fn test_sctp_sock_new_seqpacket() {
        let sock = OgsSctpSock::new(SOCK_SEQPACKET);
        assert_eq!(sock.sock_type, SOCK_SEQPACKET);
    }

    // ============================================================================
    // Packet Buffer Tests
    // ============================================================================

    #[test]
    fn test_pkbuf_ppid_stream() {
        let mut pkbuf = OgsPkbuf::new(100);

        ogs_sctp_set_ppid_in_pkbuf(&mut pkbuf, OGS_SCTP_NGAP_PPID);
        ogs_sctp_set_stream_no_in_pkbuf(&mut pkbuf, 5);

        assert_eq!(ogs_sctp_ppid_in_pkbuf(&pkbuf), OGS_SCTP_NGAP_PPID);
        assert_eq!(ogs_sctp_stream_no_in_pkbuf(&pkbuf), 5);
    }

    #[test]
    fn test_pkbuf_ppid_s1ap() {
        let mut pkbuf = OgsPkbuf::new(100);
        ogs_sctp_set_ppid_in_pkbuf(&mut pkbuf, OGS_SCTP_S1AP_PPID);
        assert_eq!(ogs_sctp_ppid_in_pkbuf(&pkbuf), OGS_SCTP_S1AP_PPID);
    }

    #[test]
    fn test_pkbuf_stream_zero() {
        let mut pkbuf = OgsPkbuf::new(100);
        ogs_sctp_set_stream_no_in_pkbuf(&mut pkbuf, 0);
        assert_eq!(ogs_sctp_stream_no_in_pkbuf(&pkbuf), 0);
    }

    #[test]
    fn test_pkbuf_stream_max() {
        let mut pkbuf = OgsPkbuf::new(100);
        ogs_sctp_set_stream_no_in_pkbuf(&mut pkbuf, u16::MAX);
        assert_eq!(ogs_sctp_stream_no_in_pkbuf(&pkbuf), u16::MAX);
    }

    // ============================================================================
    // Init/Final Tests
    // ============================================================================

    #[test]
    fn test_init_final() {
        ogs_sctp_init(0);
        ogs_sctp_final();
    }

    #[test]
    fn test_init_with_port() {
        ogs_sctp_init(38412);
        ogs_sctp_final();
    }

    #[test]
    fn test_multiple_init_final() {
        ogs_sctp_init(0);
        ogs_sctp_final();
        ogs_sctp_init(0);
        ogs_sctp_final();
    }

    // ============================================================================
    // Write Queue Tests
    // ============================================================================

    #[test]
    fn test_write_queue() {
        let mut sctp_sock = OgsSctpSock::new(SOCK_STREAM);

        let mut pkbuf1 = OgsPkbuf::new(100);
        pkbuf1.put_data(&[1, 2, 3, 4]);

        let mut pkbuf2 = OgsPkbuf::new(100);
        pkbuf2.put_data(&[5, 6, 7, 8]);

        ogs_sctp_write_to_buffer(&mut sctp_sock, pkbuf1);
        ogs_sctp_write_to_buffer(&mut sctp_sock, pkbuf2);

        assert_eq!(sctp_sock.write_queue.len(), 2);

        ogs_sctp_flush_and_destroy(&mut sctp_sock);
        assert!(sctp_sock.write_queue.is_empty());
    }

    #[test]
    fn test_write_queue_empty() {
        let mut sctp_sock = OgsSctpSock::new(SOCK_STREAM);
        assert!(sctp_sock.write_queue.is_empty());
        ogs_sctp_flush_and_destroy(&mut sctp_sock);
        assert!(sctp_sock.write_queue.is_empty());
    }

    #[test]
    fn test_write_queue_single_packet() {
        let mut sctp_sock = OgsSctpSock::new(SOCK_STREAM);
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_data(&[1, 2, 3]);
        ogs_sctp_write_to_buffer(&mut sctp_sock, pkbuf);
        assert_eq!(sctp_sock.write_queue.len(), 1);
    }

    // ============================================================================
    // Error Tests
    // ============================================================================

    #[test]
    fn test_error_display() {
        let err = SctpError::NotConnected;
        assert_eq!(format!("{err}"), "Association not established");
    }

    #[test]
    fn test_error_socket_creation() {
        let err = SctpError::SocketCreation(io::Error::other("test"));
        assert!(err.to_string().contains("Socket creation failed"));
    }

    #[test]
    fn test_error_bind_failed() {
        let err = SctpError::BindFailed(io::Error::new(io::ErrorKind::AddrInUse, "test"));
        assert!(err.to_string().contains("Bind failed"));
    }

    #[test]
    fn test_error_connect_failed() {
        let err = SctpError::ConnectFailed(io::Error::new(io::ErrorKind::ConnectionRefused, "test"));
        assert!(err.to_string().contains("Connect failed"));
    }

    #[test]
    fn test_error_listen_failed() {
        let err = SctpError::ListenFailed(io::Error::other("test"));
        assert!(err.to_string().contains("Listen failed"));
    }

    #[test]
    fn test_error_send_failed() {
        let err = SctpError::SendFailed(io::Error::new(io::ErrorKind::BrokenPipe, "test"));
        assert!(err.to_string().contains("Send failed"));
    }

    #[test]
    fn test_error_receive_failed() {
        let err = SctpError::ReceiveFailed(io::Error::new(io::ErrorKind::TimedOut, "test"));
        assert!(err.to_string().contains("Receive failed"));
    }

    #[test]
    fn test_error_sockopt_failed() {
        let err = SctpError::SockoptFailed(io::Error::new(io::ErrorKind::InvalidInput, "test"));
        assert!(err.to_string().contains("Socket option failed"));
    }

    #[test]
    fn test_error_no_valid_address() {
        let err = SctpError::NoValidAddress;
        assert!(err.to_string().contains("No valid address"));
    }

    #[test]
    fn test_error_invalid_socket() {
        let err = SctpError::InvalidSocket;
        assert!(err.to_string().contains("Invalid socket"));
    }

    #[test]
    fn test_error_protocol() {
        let err = SctpError::Protocol("test protocol error".to_string());
        assert!(err.to_string().contains("test protocol error"));
    }

    #[test]
    fn test_error_timeout() {
        let err = SctpError::Timeout("connection timeout".to_string());
        assert!(err.to_string().contains("connection timeout"));
    }

    #[test]
    fn test_error_association_closed() {
        let err = SctpError::AssociationClosed;
        assert!(err.to_string().contains("closed"));
    }

    #[test]
    fn test_error_stream_error() {
        let err = SctpError::StreamError("stream reset".to_string());
        assert!(err.to_string().contains("stream reset"));
    }

    #[test]
    fn test_error_invalid_state() {
        let err = SctpError::InvalidState("not established".to_string());
        assert!(err.to_string().contains("not established"));
    }

    // ============================================================================
    // SctpConfig Tests
    // ============================================================================

    #[test]
    fn test_sctp_config_default() {
        let config = SctpConfig::default();
        assert_eq!(config.max_outbound_streams, DEFAULT_NUM_STREAMS);
        assert_eq!(config.max_inbound_streams, DEFAULT_NUM_STREAMS);
        assert_eq!(config.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
        assert_eq!(config.max_receive_buffer_size, DEFAULT_RECEIVE_BUFFER_SIZE);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.rto_initial_ms, 3000);
        assert_eq!(config.rto_min_ms, 1000);
        assert_eq!(config.rto_max_ms, 60000);
    }

    #[test]
    fn test_sctp_config_custom() {
        let config = SctpConfig {
            max_outbound_streams: 4,
            max_inbound_streams: 4,
            max_message_size: 131072,
            max_receive_buffer_size: 524288,
            connect_timeout: Duration::from_secs(60),
            rto_initial_ms: 1000,
            rto_min_ms: 500,
            rto_max_ms: 30000,
        };
        assert_eq!(config.max_outbound_streams, 4);
        assert_eq!(config.max_inbound_streams, 4);
        assert_eq!(config.max_message_size, 131072);
        assert_eq!(config.connect_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_sctp_config_clone() {
        let config1 = SctpConfig::default();
        let config2 = config1.clone();
        assert_eq!(config1.max_outbound_streams, config2.max_outbound_streams);
        assert_eq!(config1.connect_timeout, config2.connect_timeout);
    }

    // ============================================================================
    // ReceivedMessage Tests
    // ============================================================================

    #[test]
    fn test_received_message() {
        let msg = ReceivedMessage {
            stream_id: 0,
            data: Bytes::from_static(b"test"),
            ppid: NGAP_PPID,
        };
        assert_eq!(msg.stream_id, 0);
        assert_eq!(msg.ppid, NGAP_PPID);
        assert_eq!(&msg.data[..], b"test");
    }

    #[test]
    fn test_received_message_clone() {
        let msg1 = ReceivedMessage {
            stream_id: 1,
            data: Bytes::from_static(b"hello"),
            ppid: 60,
        };
        let msg2 = msg1.clone();
        assert_eq!(msg1.stream_id, msg2.stream_id);
        assert_eq!(msg1.data, msg2.data);
        assert_eq!(msg1.ppid, msg2.ppid);
    }

    #[test]
    fn test_received_message_empty_data() {
        let msg = ReceivedMessage {
            stream_id: 0,
            data: Bytes::new(),
            ppid: 60,
        };
        assert!(msg.data.is_empty());
    }

    #[test]
    fn test_received_message_large_data() {
        let data = vec![0u8; 65536];
        let msg = ReceivedMessage {
            stream_id: 0,
            data: Bytes::from(data.clone()),
            ppid: 60,
        };
        assert_eq!(msg.data.len(), 65536);
    }

    // ============================================================================
    // SctpEvent Tests
    // ============================================================================

    #[test]
    fn test_sctp_event_connected() {
        let event = SctpEvent::Connected;
        match event {
            SctpEvent::Connected => {}
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_sctp_event_disconnected() {
        let event = SctpEvent::Disconnected;
        match event {
            SctpEvent::Disconnected => {}
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_sctp_event_data_received() {
        let msg = ReceivedMessage {
            stream_id: 0,
            data: Bytes::from_static(b"test"),
            ppid: 60,
        };
        let event = SctpEvent::DataReceived(msg);
        match event {
            SctpEvent::DataReceived(m) => {
                assert_eq!(m.stream_id, 0);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_sctp_event_stream_opened() {
        let event = SctpEvent::StreamOpened(5);
        match event {
            SctpEvent::StreamOpened(id) => assert_eq!(id, 5),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_sctp_event_stream_closed() {
        let event = SctpEvent::StreamClosed(3);
        match event {
            SctpEvent::StreamClosed(id) => assert_eq!(id, 3),
            _ => panic!("Wrong variant"),
        }
    }

    // ============================================================================
    // AssociationState Tests
    // ============================================================================

    #[test]
    fn test_association_state_equality() {
        assert_eq!(AssociationState::Closed, AssociationState::Closed);
        assert_eq!(AssociationState::Established, AssociationState::Established);
        assert_ne!(AssociationState::Closed, AssociationState::Established);
    }

    #[test]
    fn test_association_state_all_variants() {
        let states = [
            AssociationState::Closed,
            AssociationState::CookieWait,
            AssociationState::CookieEchoed,
            AssociationState::Established,
            AssociationState::ShutdownPending,
            AssociationState::ShutdownSent,
            AssociationState::ShutdownReceived,
            AssociationState::ShutdownAckSent,
            AssociationState::Connecting,
            AssociationState::ShuttingDown,
        ];
        // Ensure all states are unique
        for (i, s1) in states.iter().enumerate() {
            for (j, s2) in states.iter().enumerate() {
                if i != j {
                    assert_ne!(s1, s2);
                }
            }
        }
    }

    #[test]
    fn test_association_state_copy() {
        let state1 = AssociationState::Established;
        let state2 = state1;
        assert_eq!(state1, state2);
    }

    // ============================================================================
    // Server Tests (sctp-proto feature)
    // ============================================================================

    #[cfg(feature = "sctp-proto")]
    #[tokio::test]
    async fn test_server_bind() {
        let config = SctpServerConfig::default();
        let server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config).await;

        assert!(server.is_ok());
        let server = server.unwrap();
        assert!(server.is_running());
        assert_eq!(server.num_associations(), 0);
    }

    #[cfg(feature = "sctp-proto")]
    #[tokio::test]
    async fn test_server_bind_and_stop() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        let addr = server.local_addr();
        assert!(addr.port() > 0);

        server.stop();
        assert!(!server.is_running());
    }

    #[cfg(feature = "sctp-proto")]
    #[tokio::test]
    async fn test_multiple_servers() {
        let config = SctpServerConfig::default();

        let server1 = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config.clone())
            .await
            .unwrap();
        let server2 = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        assert_ne!(server1.local_addr(), server2.local_addr());
        assert!(server1.is_running());
        assert!(server2.is_running());
    }
}
