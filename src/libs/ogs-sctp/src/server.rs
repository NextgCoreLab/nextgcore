//! SCTP Server for accepting connections
//!
//! This module provides SCTP server functionality using `sctp-proto`.
//! It can accept multiple client connections and manage them.
//!
//! # Usage
//!
//! This server is designed for use in the AMF (or any SCTP server) to accept
//! connections from gNBs. Both nextgsim and nextgcore use this implementation
//! for wire-compatible SCTP-over-UDP communication.

use bytes::Bytes;
use sctp_proto::{
    Association, AssociationHandle, DatagramEvent, Endpoint, EndpointConfig, Event, Payload,
    PayloadProtocolIdentifier, ServerConfig, TransportConfig, Transmit,
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{net::UdpSocket, sync::mpsc, time::timeout};
use tracing::{debug, error, info, trace, warn};

use crate::{ReceivedMessage, NGAP_PPID};

/// Server errors
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Server not running")]
    NotRunning,
    #[error("Association not found: {0}")]
    AssociationNotFound(u64),
    #[error("Send error: {0}")]
    SendError(String),
}

pub type Result<T> = std::result::Result<T, ServerError>;

/// Server configuration
#[derive(Debug, Clone)]
pub struct SctpServerConfig {
    /// Maximum number of inbound streams per association
    pub max_inbound_streams: u16,
    /// Maximum number of outbound streams per association
    pub max_outbound_streams: u16,
    /// Maximum message size
    pub max_message_size: u32,
    /// Receive buffer size
    pub receive_buffer_size: u32,
}

impl Default for SctpServerConfig {
    fn default() -> Self {
        Self {
            max_inbound_streams: 2,
            max_outbound_streams: 2,
            max_message_size: 65536,
            receive_buffer_size: 262144,
        }
    }
}

/// Events from the server
#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// New association established
    NewAssociation {
        /// Association ID (internal handle)
        association_id: u64,
        /// Remote address
        remote_addr: SocketAddr,
    },
    /// Association closed
    AssociationClosed {
        association_id: u64,
        reason: String,
    },
    /// Data received from an association
    DataReceived {
        association_id: u64,
        message: ReceivedMessage,
    },
}

/// Managed association state
struct ManagedAssociation {
    #[allow(dead_code)]
    handle: AssociationHandle,
    association: Association,
    remote_addr: SocketAddr,
    pending_transmits: VecDeque<Transmit>,
}

/// SCTP Server using sctp-proto
///
/// This server accepts SCTP connections and manages multiple associations.
/// It uses the same `sctp-proto` library as nextgsim's SctpAssociation,
/// ensuring wire compatibility between gNB (client) and AMF (server).
pub struct SctpServer {
    /// UDP socket for SCTP-over-UDP
    socket: Arc<UdpSocket>,
    /// Local bind address
    local_addr: SocketAddr,
    /// SCTP endpoint
    endpoint: Endpoint,
    /// Active associations by their handle
    associations: HashMap<AssociationHandle, ManagedAssociation>,
    /// Map from remote address to handle (for lookups)
    addr_to_handle: HashMap<SocketAddr, AssociationHandle>,
    /// Next association ID (for external use)
    next_association_id: u64,
    /// Handle to external ID mapping
    handle_to_id: HashMap<AssociationHandle, u64>,
    /// ID to handle mapping
    id_to_handle: HashMap<u64, AssociationHandle>,
    /// Configuration
    config: SctpServerConfig,
    /// Event sender
    event_tx: Option<mpsc::UnboundedSender<ServerEvent>>,
    /// Running flag
    running: bool,
}

impl SctpServer {
    /// Create a new SCTP server bound to the given address
    pub async fn bind(addr: SocketAddr, config: SctpServerConfig) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;

        info!("SCTP server listening on {} (sctp-proto over UDP)", local_addr);

        // Create endpoint config
        let endpoint_config = EndpointConfig::new();

        // Create server config with transport settings
        let transport_config = TransportConfig::default()
            .with_max_num_inbound_streams(config.max_inbound_streams)
            .with_max_num_outbound_streams(config.max_outbound_streams)
            .with_max_message_size(config.max_message_size)
            .with_max_receive_buffer_size(config.receive_buffer_size);

        let mut server_config = ServerConfig::new();
        server_config.transport = Arc::new(transport_config);

        let endpoint = Endpoint::new(Arc::new(endpoint_config), Some(Arc::new(server_config)));

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            endpoint,
            associations: HashMap::new(),
            addr_to_handle: HashMap::new(),
            next_association_id: 1,
            handle_to_id: HashMap::new(),
            id_to_handle: HashMap::new(),
            config,
            event_tx: None,
            running: true,
        })
    }

    /// Get the local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get number of active associations
    pub fn num_associations(&self) -> usize {
        self.associations.len()
    }

    /// Set event sender for receiving server events
    pub fn set_event_sender(&mut self, tx: mpsc::UnboundedSender<ServerEvent>) {
        self.event_tx = Some(tx);
    }

    /// Poll for incoming data and events (non-blocking)
    pub async fn poll(&mut self) -> Result<bool> {
        if !self.running {
            return Err(ServerError::NotRunning);
        }

        // Try to receive incoming packets
        let mut buf = vec![0u8; self.config.receive_buffer_size as usize];

        match self.socket.try_recv_from(&mut buf) {
            Ok((len, from)) => {
                buf.truncate(len);
                trace!("Received {} bytes from {}", len, from);

                self.handle_datagram(from, Bytes::from(buf)).await?;
                Ok(true)
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available, process timeouts
                self.process_timeouts().await?;
                Ok(false)
            }
            Err(e) => Err(ServerError::Io(e)),
        }
    }

    /// Receive and process incoming data (blocking with timeout)
    pub async fn recv(&mut self, recv_timeout: Duration) -> Result<bool> {
        if !self.running {
            return Err(ServerError::NotRunning);
        }

        let mut buf = vec![0u8; self.config.receive_buffer_size as usize];

        match timeout(recv_timeout, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                buf.truncate(len);
                trace!("Received {} bytes from {}", len, from);

                self.handle_datagram(from, Bytes::from(buf)).await?;
                Ok(true)
            }
            Ok(Err(e)) => Err(ServerError::Io(e)),
            Err(_) => {
                // Timeout, process any pending timeouts
                self.process_timeouts().await?;
                Ok(false)
            }
        }
    }

    /// Handle an incoming datagram
    async fn handle_datagram(&mut self, from: SocketAddr, data: Bytes) -> Result<()> {
        let now = Instant::now();

        if let Some((handle, event)) = self.endpoint.handle(now, from, None, None, data) {
            match event {
                DatagramEvent::NewAssociation(association) => {
                    self.handle_new_association(handle, association, from).await?;
                }
                DatagramEvent::AssociationEvent(assoc_event) => {
                    self.handle_association_event(handle, assoc_event).await?;
                }
            }
        }

        // Flush any pending transmits
        self.flush_all_transmits().await?;

        Ok(())
    }

    /// Handle a new association
    async fn handle_new_association(
        &mut self,
        handle: AssociationHandle,
        association: Association,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let association_id = self.next_association_id;
        self.next_association_id += 1;

        info!(
            "New SCTP association from {} (id: {}, handle: {:?})",
            remote_addr, association_id, handle
        );

        let managed = ManagedAssociation {
            handle,
            association,
            remote_addr,
            pending_transmits: VecDeque::new(),
        };

        self.associations.insert(handle, managed);
        self.addr_to_handle.insert(remote_addr, handle);
        self.handle_to_id.insert(handle, association_id);
        self.id_to_handle.insert(association_id, handle);

        // Send event
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(ServerEvent::NewAssociation {
                association_id,
                remote_addr,
            });
        }

        Ok(())
    }

    /// Handle an association event
    async fn handle_association_event(
        &mut self,
        handle: AssociationHandle,
        event: sctp_proto::AssociationEvent,
    ) -> Result<()> {
        // First, handle the event and collect all necessary info
        let (events_to_process, check_data) = {
            if let Some(managed) = self.associations.get_mut(&handle) {
                managed.association.handle_event(event);

                // Collect events
                let mut events = Vec::new();
                let mut need_data_check = false;

                while let Some(evt) = managed.association.poll() {
                    match &evt {
                        Event::Stream(_) | Event::DatagramReceived => {
                            need_data_check = true;
                        }
                        _ => {}
                    }
                    events.push(evt);
                }

                // Collect transmits
                while let Some(transmit) = managed.association.poll_transmit(Instant::now()) {
                    managed.pending_transmits.push_back(transmit);
                }

                (events, need_data_check)
            } else {
                return Ok(());
            }
        };

        // Process events (no longer borrowing associations mutably)
        for evt in events_to_process {
            match evt {
                Event::Connected => {
                    debug!("Association {:?} connected", handle);
                }
                Event::AssociationLost { reason } => {
                    warn!("Association {:?} lost: {}", handle, reason);
                    if let Some(&id) = self.handle_to_id.get(&handle) {
                        if let Some(tx) = &self.event_tx {
                            let _ = tx.send(ServerEvent::AssociationClosed {
                                association_id: id,
                                reason: reason.to_string(),
                            });
                        }
                    }
                }
                Event::Stream(_) | Event::DatagramReceived => {
                    // Handled below
                }
            }
        }

        // Check for data if needed
        if check_data {
            self.check_for_data(handle)?;
        }

        Ok(())
    }

    /// Check for and handle received data
    fn check_for_data(&mut self, handle: AssociationHandle) -> Result<()> {
        if let Some(managed) = self.associations.get_mut(&handle) {
            // First, accept any new streams
            while let Some(mut stream) = managed.association.accept_stream() {
                let stream_id = stream.stream_identifier();
                debug!("Accepted stream {} on association {:?}", stream_id, handle);

                if let Ok(Some(chunks)) = stream.read() {
                    let total_len = chunks.len();
                    if total_len > 0 {
                        let mut buf = vec![0u8; total_len];
                        if chunks.read(&mut buf).is_ok() {
                            let ppid = match chunks.ppi {
                                PayloadProtocolIdentifier::Unknown => NGAP_PPID,
                                _ => NGAP_PPID, // Default to NGAP for 5G
                            };

                            let message = ReceivedMessage {
                                stream_id,
                                data: Bytes::from(buf),
                                ppid,
                            };

                            debug!(
                                "Received {} bytes on stream {} from {:?}",
                                message.data.len(),
                                stream_id,
                                handle
                            );

                            if let Some(&id) = self.handle_to_id.get(&handle) {
                                if let Some(tx) = &self.event_tx {
                                    let _ = tx.send(ServerEvent::DataReceived {
                                        association_id: id,
                                        message,
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Also check existing streams for data (stream 0 and 1 for NGAP)
            for stream_id in [0u16, 1] {
                if let Ok(mut stream) = managed.association.stream(stream_id) {
                    if let Ok(Some(chunks)) = stream.read() {
                        let total_len = chunks.len();
                        if total_len > 0 {
                            let mut buf = vec![0u8; total_len];
                            if chunks.read(&mut buf).is_ok() {
                                let ppid = match chunks.ppi {
                                    PayloadProtocolIdentifier::Unknown => NGAP_PPID,
                                    _ => NGAP_PPID,
                                };

                                let message = ReceivedMessage {
                                    stream_id,
                                    data: Bytes::from(buf),
                                    ppid,
                                };

                                debug!(
                                    "Received {} bytes on existing stream {} from {:?}",
                                    message.data.len(),
                                    stream_id,
                                    handle
                                );

                                if let Some(&id) = self.handle_to_id.get(&handle) {
                                    if let Some(tx) = &self.event_tx {
                                        let _ = tx.send(ServerEvent::DataReceived {
                                            association_id: id,
                                            message,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process timeouts for all associations
    async fn process_timeouts(&mut self) -> Result<()> {
        let now = Instant::now();

        for managed in self.associations.values_mut() {
            if let Some(timeout_instant) = managed.association.poll_timeout() {
                if now >= timeout_instant {
                    managed.association.handle_timeout(now);
                }
            }

            // Collect transmits
            while let Some(transmit) = managed.association.poll_transmit(now) {
                managed.pending_transmits.push_back(transmit);
            }
        }

        // Flush transmits
        self.flush_all_transmits().await?;

        Ok(())
    }

    /// Flush all pending transmits
    async fn flush_all_transmits(&mut self) -> Result<()> {
        // Collect all transmits first to avoid borrow issues
        let mut all_transmits: Vec<Transmit> = Vec::new();

        // Collect endpoint transmits
        while let Some(transmit) = self.endpoint.poll_transmit() {
            all_transmits.push(transmit);
        }

        // Collect association transmits
        for managed in self.associations.values_mut() {
            while let Some(transmit) = managed.pending_transmits.pop_front() {
                all_transmits.push(transmit);
            }
        }

        // Now send all collected transmits
        for transmit in all_transmits {
            self.send_transmit(&transmit).await?;
        }

        Ok(())
    }

    /// Send a transmit
    async fn send_transmit(&self, transmit: &Transmit) -> Result<()> {
        match &transmit.payload {
            Payload::RawEncode(chunks) => {
                for chunk in chunks {
                    self.socket.send_to(chunk, transmit.remote).await?;
                    trace!("Sent {} bytes to {}", chunk.len(), transmit.remote);
                }
            }
            Payload::PartialDecode(_) => {
                // Skip - this is for incoming packets
            }
        }
        Ok(())
    }

    /// Send data to a specific association
    pub async fn send(&mut self, association_id: u64, stream_id: u16, data: &[u8]) -> Result<()> {
        let handle = self
            .id_to_handle
            .get(&association_id)
            .ok_or(ServerError::AssociationNotFound(association_id))?;

        if let Some(managed) = self.associations.get_mut(handle) {
            let ppi = PayloadProtocolIdentifier::from(NGAP_PPID);

            // Try to get an existing stream first, fall back to opening a new one
            let mut stream = match managed.association.stream(stream_id) {
                Ok(s) => s,
                Err(_) => {
                    // Stream doesn't exist, try to open a new one
                    managed
                        .association
                        .open_stream(stream_id, ppi)
                        .map_err(|e| ServerError::SendError(e.to_string()))?
                }
            };

            stream
                .write_with_ppi(data, ppi)
                .map_err(|e| ServerError::SendError(e.to_string()))?;

            debug!(
                "Queued {} bytes to association {} on stream {}",
                data.len(),
                association_id,
                stream_id
            );

            // Collect and flush transmits
            while let Some(transmit) = managed.association.poll_transmit(Instant::now()) {
                managed.pending_transmits.push_back(transmit);
            }

            self.flush_all_transmits().await?;

            Ok(())
        } else {
            Err(ServerError::AssociationNotFound(association_id))
        }
    }

    /// Send data to an association by remote address
    pub async fn send_to_addr(
        &mut self,
        remote_addr: SocketAddr,
        stream_id: u16,
        data: &[u8],
    ) -> Result<()> {
        let handle = self
            .addr_to_handle
            .get(&remote_addr)
            .ok_or(ServerError::AssociationNotFound(0))?;

        if let Some(&id) = self.handle_to_id.get(handle) {
            self.send(id, stream_id, data).await
        } else {
            Err(ServerError::AssociationNotFound(0))
        }
    }

    /// Close a specific association
    pub fn close_association(&mut self, association_id: u64) -> Result<()> {
        if let Some(handle) = self.id_to_handle.remove(&association_id) {
            if let Some(mut managed) = self.associations.remove(&handle) {
                let _ = managed.association.close();
                self.addr_to_handle.remove(&managed.remote_addr);
                self.handle_to_id.remove(&handle);

                info!("Closed association {}", association_id);
            }
        }
        Ok(())
    }

    /// Stop the server
    pub fn stop(&mut self) {
        info!("Stopping SCTP server on {}", self.local_addr);
        self.running = false;

        // Close all associations
        for (_, mut managed) in self.associations.drain() {
            let _ = managed.association.close();
        }

        self.addr_to_handle.clear();
        self.handle_to_id.clear();
        self.id_to_handle.clear();
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get socket for external async operations
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }
}

impl Drop for SctpServer {
    fn drop(&mut self) {
        if self.running {
            self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = SctpServerConfig::default();
        assert_eq!(config.max_inbound_streams, 2);
        assert_eq!(config.max_outbound_streams, 2);
        assert_eq!(config.max_message_size, 65536);
        assert_eq!(config.receive_buffer_size, 262144);
    }

    #[test]
    fn test_server_config_custom() {
        let config = SctpServerConfig {
            max_inbound_streams: 4,
            max_outbound_streams: 4,
            max_message_size: 131072,
            receive_buffer_size: 524288,
        };
        assert_eq!(config.max_inbound_streams, 4);
        assert_eq!(config.max_outbound_streams, 4);
        assert_eq!(config.max_message_size, 131072);
        assert_eq!(config.receive_buffer_size, 524288);
    }

    #[tokio::test]
    async fn test_server_bind() {
        let config = SctpServerConfig::default();
        let server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config).await;

        assert!(server.is_ok());
        let server = server.unwrap();
        assert!(server.is_running());
        assert_eq!(server.num_associations(), 0);
    }

    #[tokio::test]
    async fn test_server_bind_ipv6() {
        let config = SctpServerConfig::default();
        let server = SctpServer::bind("[::1]:0".parse().unwrap(), config).await;

        assert!(server.is_ok());
        let server = server.unwrap();
        assert!(server.is_running());
        assert!(server.local_addr().is_ipv6());
    }

    #[tokio::test]
    async fn test_server_local_addr() {
        let config = SctpServerConfig::default();
        let server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        let addr = server.local_addr();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_server_stop() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        assert!(server.is_running());
        server.stop();
        assert!(!server.is_running());
    }

    #[tokio::test]
    async fn test_server_double_stop() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        server.stop();
        assert!(!server.is_running());
        // Second stop should be safe
        server.stop();
        assert!(!server.is_running());
    }

    #[tokio::test]
    async fn test_server_poll_not_running() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        server.stop();
        let result = server.poll().await;
        assert!(result.is_err());
        match result {
            Err(ServerError::NotRunning) => {}
            _ => panic!("Expected NotRunning error"),
        }
    }

    #[tokio::test]
    async fn test_server_recv_not_running() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        server.stop();
        let result = server.recv(Duration::from_millis(10)).await;
        assert!(result.is_err());
        match result {
            Err(ServerError::NotRunning) => {}
            _ => panic!("Expected NotRunning error"),
        }
    }

    #[tokio::test]
    async fn test_server_event_sender() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        server.set_event_sender(tx);

        // Verify we can receive (no events yet, so this should be empty)
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_server_socket_access() {
        let config = SctpServerConfig::default();
        let server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        let socket = server.socket();
        let addr = socket.local_addr().unwrap();
        assert_eq!(addr, server.local_addr());
    }

    #[tokio::test]
    async fn test_server_poll_timeout() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        // Poll with short timeout - should return false (no data)
        let result = server.recv(Duration::from_millis(10)).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_server_close_nonexistent_association() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        // Closing a non-existent association should be ok
        let result = server.close_association(999);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_server_send_to_nonexistent_association() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        // Sending to non-existent association should fail
        let result = server.send(999, 0, b"test").await;
        assert!(result.is_err());
        match result {
            Err(ServerError::AssociationNotFound(id)) => assert_eq!(id, 999),
            _ => panic!("Expected AssociationNotFound error"),
        }
    }

    #[tokio::test]
    async fn test_server_send_to_addr_nonexistent() {
        let config = SctpServerConfig::default();
        let mut server = SctpServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        // Sending to non-existent address should fail
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let result = server.send_to_addr(addr, 0, b"test").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_server_error_display() {
        let io_err = ServerError::Io(std::io::Error::other(
            "test error",
        ));
        assert!(io_err.to_string().contains("I/O error"));

        let not_running = ServerError::NotRunning;
        assert!(not_running.to_string().contains("not running"));

        let assoc_not_found = ServerError::AssociationNotFound(123);
        assert!(assoc_not_found.to_string().contains("123"));

        let send_err = ServerError::SendError("test".to_string());
        assert!(send_err.to_string().contains("test"));
    }

    #[test]
    fn test_server_event_variants() {
        let new_assoc = ServerEvent::NewAssociation {
            association_id: 1,
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
        };
        match new_assoc {
            ServerEvent::NewAssociation { association_id, .. } => {
                assert_eq!(association_id, 1);
            }
            _ => panic!("Wrong variant"),
        }

        let closed = ServerEvent::AssociationClosed {
            association_id: 2,
            reason: "test".to_string(),
        };
        match closed {
            ServerEvent::AssociationClosed { association_id, reason } => {
                assert_eq!(association_id, 2);
                assert_eq!(reason, "test");
            }
            _ => panic!("Wrong variant"),
        }

        let data = ServerEvent::DataReceived {
            association_id: 3,
            message: crate::ReceivedMessage {
                stream_id: 0,
                data: Bytes::from_static(b"test"),
                ppid: 60,
            },
        };
        match data {
            ServerEvent::DataReceived { association_id, message } => {
                assert_eq!(association_id, 3);
                assert_eq!(message.stream_id, 0);
                assert_eq!(message.ppid, 60);
            }
            _ => panic!("Wrong variant"),
        }
    }
}
