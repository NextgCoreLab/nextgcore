//! PFCP Integration Tests
//!
//! Tests for PFCP (Packet Forwarding Control Protocol) N4 interface
//! between SMF and UPF as specified in 3GPP TS 29.244.
//!
//! These tests verify:
//! - PFCP Association Setup/Release
//! - PFCP Session Establishment/Modification/Deletion
//! - PFCP Heartbeat mechanism
//! - Message encoding/decoding with actual UDP sockets

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use bytes::{Bytes, BytesMut};

use crate::common::{MessageCapture, CapturedMessage, MessageType, MessageField};

// Re-export PFCP types from the library
use ogs_pfcp::header::{PfcpHeader, PfcpMessageType};
use ogs_pfcp::message::{
    HeartbeatRequest, HeartbeatResponse,
    AssociationSetupRequest, AssociationSetupResponse,
    SessionEstablishmentRequest, SessionEstablishmentResponse,
    SessionDeletionRequest, SessionDeletionResponse,
    PfcpMessage, build_message, parse_message,
};
use ogs_pfcp::types::{NodeId, FSeid, PfcpCause};

/// Mock UPF for PFCP testing
pub struct MockUpf {
    socket: Option<TokioUdpSocket>,
    addr: SocketAddr,
    node_id: NodeId,
    recovery_timestamp: u32,
    sequence_number: u32,
    sessions: Arc<RwLock<std::collections::HashMap<u64, SessionContext>>>,
    capture: Arc<RwLock<MessageCapture>>,
    running: bool,
}

/// Session context stored by mock UPF
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub cp_seid: u64,
    pub up_seid: u64,
    pub cp_addr: SocketAddr,
}

impl MockUpf {
    /// Create a new mock UPF
    pub fn new(addr: SocketAddr, capture: Arc<RwLock<MessageCapture>>) -> Self {
        Self {
            socket: None,
            addr,
            node_id: NodeId::new_ipv4(addr.ip().to_string().parse::<std::net::Ipv4Addr>()
                .map(|ip| ip.octets())
                .unwrap_or([127, 0, 0, 1])),
            recovery_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            sequence_number: 0,
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
            capture,
            running: false,
        }
    }

    /// Bind the socket and start listening
    pub async fn start(&mut self) -> anyhow::Result<()> {
        let socket = TokioUdpSocket::bind(self.addr).await?;
        self.addr = socket.local_addr()?;
        self.socket = Some(socket);
        self.running = true;
        log::info!("Mock UPF started on {}", self.addr);
        Ok(())
    }

    /// Get the bound address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Process one incoming message and return response
    pub async fn process_one(&mut self) -> anyhow::Result<Option<(SocketAddr, BytesMut)>> {
        let socket = self.socket.as_ref().ok_or_else(|| anyhow::anyhow!("Socket not bound"))?;

        let mut buf = vec![0u8; 65535];
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let mut data = Bytes::copy_from_slice(&buf[..len]);

        // Parse the message
        let (header, message) = parse_message(&mut data)?;

        // Capture for test verification
        {
            let mut cap = self.capture.write().await;
            let msg_type = match header.message_type {
                PfcpMessageType::HeartbeatRequest => MessageType::HeartbeatRequest,
                PfcpMessageType::AssociationSetupRequest => MessageType::AssociationSetupRequest,
                PfcpMessageType::SessionEstablishmentRequest => MessageType::SessionEstablishmentRequest,
                PfcpMessageType::SessionDeletionRequest => MessageType::SessionDeletionRequest,
                _ => MessageType::Unknown(format!("{:?}", header.message_type)),
            };
            let captured = CapturedMessage::new(
                msg_type,
                Bytes::copy_from_slice(&buf[..len]),
                "SMF",
                "UPF",
            )
            .with_field("sequence_number", MessageField::Number(header.sequence_number as i64));

            if let Some(seid) = header.seid {
                let captured = captured.with_field("seid", MessageField::Number(seid as i64));
                cap.capture(captured);
            } else {
                cap.capture(captured);
            }
        }

        // Generate response
        let response = self.handle_message(header, message, peer).await?;

        Ok(response.map(|r| (peer, r)))
    }

    /// Handle incoming PFCP message and generate response
    async fn handle_message(
        &mut self,
        header: PfcpHeader,
        message: PfcpMessage,
        peer: SocketAddr,
    ) -> anyhow::Result<Option<BytesMut>> {
        match message {
            PfcpMessage::HeartbeatRequest(req) => {
                log::debug!("UPF received Heartbeat Request, recovery_ts={}", req.recovery_time_stamp);
                let response = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(
                    self.recovery_timestamp,
                ));
                let buf = build_message(&response, header.sequence_number, None);
                Ok(Some(buf))
            }

            PfcpMessage::AssociationSetupRequest(req) => {
                log::info!("UPF received Association Setup Request from {:?}", req.node_id);
                let response = PfcpMessage::AssociationSetupResponse(AssociationSetupResponse::new(
                    self.node_id.clone(),
                    PfcpCause::RequestAccepted,
                    self.recovery_timestamp,
                ));
                let buf = build_message(&response, header.sequence_number, None);
                Ok(Some(buf))
            }

            PfcpMessage::SessionEstablishmentRequest(req) => {
                log::info!("UPF received Session Establishment Request, CP-SEID={}", req.cp_f_seid.seid);

                // Allocate UP-SEID
                self.sequence_number += 1;
                let up_seid = self.sequence_number as u64;

                // Store session
                {
                    let mut sessions = self.sessions.write().await;
                    sessions.insert(up_seid, SessionContext {
                        cp_seid: req.cp_f_seid.seid,
                        up_seid,
                        cp_addr: peer,
                    });
                }

                let mut response = SessionEstablishmentResponse::new(PfcpCause::RequestAccepted);
                response.node_id = Some(self.node_id.clone());
                response.up_f_seid = Some(FSeid::new_ipv4(
                    up_seid,
                    self.addr.ip().to_string().parse::<std::net::Ipv4Addr>()
                        .map(|ip| ip.octets())
                        .unwrap_or([127, 0, 0, 1]),
                ));

                let response_msg = PfcpMessage::SessionEstablishmentResponse(response);
                let buf = build_message(&response_msg, header.sequence_number, Some(req.cp_f_seid.seid));
                Ok(Some(buf))
            }

            PfcpMessage::SessionDeletionRequest(_req) => {
                let seid = header.seid.unwrap_or(0);
                log::info!("UPF received Session Deletion Request, SEID={}", seid);

                // Remove session
                {
                    let mut sessions = self.sessions.write().await;
                    sessions.remove(&seid);
                }

                let response = PfcpMessage::SessionDeletionResponse(
                    SessionDeletionResponse::new(PfcpCause::RequestAccepted)
                );
                let buf = build_message(&response, header.sequence_number, header.seid);
                Ok(Some(buf))
            }

            _ => {
                log::warn!("UPF received unhandled message type: {:?}", header.message_type);
                Ok(None)
            }
        }
    }

    /// Send response back to peer
    pub async fn send_response(&self, peer: SocketAddr, response: &[u8]) -> anyhow::Result<()> {
        let socket = self.socket.as_ref().ok_or_else(|| anyhow::anyhow!("Socket not bound"))?;
        socket.send_to(response, peer).await?;
        Ok(())
    }

    /// Get session count
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Stop the mock UPF
    pub fn stop(&mut self) {
        self.running = false;
        self.socket = None;
        log::info!("Mock UPF stopped");
    }
}

/// Mock SMF for PFCP testing (simulates SMF sending requests to UPF)
pub struct MockSmf {
    socket: Option<TokioUdpSocket>,
    addr: SocketAddr,
    node_id: NodeId,
    recovery_timestamp: u32,
    sequence_number: u32,
    capture: Arc<RwLock<MessageCapture>>,
}

impl MockSmf {
    /// Create a new mock SMF
    pub fn new(addr: SocketAddr, capture: Arc<RwLock<MessageCapture>>) -> Self {
        Self {
            socket: None,
            addr,
            node_id: NodeId::new_ipv4(addr.ip().to_string().parse::<std::net::Ipv4Addr>()
                .map(|ip| ip.octets())
                .unwrap_or([127, 0, 0, 1])),
            recovery_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            sequence_number: 0,
            capture,
        }
    }

    /// Bind the socket
    pub async fn start(&mut self) -> anyhow::Result<()> {
        let socket = TokioUdpSocket::bind(self.addr).await?;
        self.addr = socket.local_addr()?;
        self.socket = Some(socket);
        log::info!("Mock SMF started on {}", self.addr);
        Ok(())
    }

    /// Get the bound address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get next sequence number
    fn next_sequence(&mut self) -> u32 {
        self.sequence_number += 1;
        self.sequence_number
    }

    /// Send heartbeat request and wait for response
    pub async fn send_heartbeat(&mut self, upf_addr: SocketAddr) -> anyhow::Result<HeartbeatResponse> {
        // Get values we need before borrowing socket
        let seq = self.next_sequence();
        let recovery_ts = self.recovery_timestamp;

        let socket = self.socket.as_ref().ok_or_else(|| anyhow::anyhow!("Socket not bound"))?;

        let request = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(recovery_ts));
        let buf = build_message(&request, seq, None);

        socket.send_to(&buf, upf_addr).await?;

        // Capture sent message
        {
            let mut cap = self.capture.write().await;
            cap.capture(CapturedMessage::new(
                MessageType::HeartbeatRequest,
                buf.clone().freeze(),
                "SMF",
                "UPF",
            ).with_field("sequence_number", MessageField::Number(seq as i64)));
        }

        // Wait for response
        let mut resp_buf = vec![0u8; 65535];
        let recv_future = socket.recv_from(&mut resp_buf);
        let (len, _) = timeout(Duration::from_secs(5), recv_future).await??;

        let mut data = Bytes::copy_from_slice(&resp_buf[..len]);
        let (header, message) = parse_message(&mut data)?;

        // Capture received message
        {
            let mut cap = self.capture.write().await;
            cap.capture(CapturedMessage::new(
                MessageType::HeartbeatResponse,
                Bytes::copy_from_slice(&resp_buf[..len]),
                "UPF",
                "SMF",
            ).with_field("sequence_number", MessageField::Number(header.sequence_number as i64)));
        }

        match message {
            PfcpMessage::HeartbeatResponse(resp) => Ok(resp),
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    /// Send association setup request and wait for response
    pub async fn send_association_setup(&mut self, upf_addr: SocketAddr) -> anyhow::Result<AssociationSetupResponse> {
        // Get values we need before borrowing socket
        let seq = self.next_sequence();
        let node_id = self.node_id.clone();
        let recovery_ts = self.recovery_timestamp;

        let socket = self.socket.as_ref().ok_or_else(|| anyhow::anyhow!("Socket not bound"))?;

        let request = PfcpMessage::AssociationSetupRequest(
            AssociationSetupRequest::new(node_id, recovery_ts)
        );
        let buf = build_message(&request, seq, None);

        socket.send_to(&buf, upf_addr).await?;

        // Capture sent message
        {
            let mut cap = self.capture.write().await;
            cap.capture(CapturedMessage::new(
                MessageType::AssociationSetupRequest,
                buf.clone().freeze(),
                "SMF",
                "UPF",
            ).with_field("sequence_number", MessageField::Number(seq as i64)));
        }

        // Wait for response
        let mut resp_buf = vec![0u8; 65535];
        let recv_future = socket.recv_from(&mut resp_buf);
        let (len, _) = timeout(Duration::from_secs(5), recv_future).await??;

        let mut data = Bytes::copy_from_slice(&resp_buf[..len]);
        let (header, message) = parse_message(&mut data)?;

        // Capture received message
        {
            let mut cap = self.capture.write().await;
            cap.capture(CapturedMessage::new(
                MessageType::AssociationSetupResponse,
                Bytes::copy_from_slice(&resp_buf[..len]),
                "UPF",
                "SMF",
            ).with_field("sequence_number", MessageField::Number(header.sequence_number as i64)));
        }

        match message {
            PfcpMessage::AssociationSetupResponse(resp) => Ok(resp),
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    /// Send session establishment request and wait for response
    pub async fn send_session_establishment(
        &mut self,
        upf_addr: SocketAddr,
        cp_seid: u64,
    ) -> anyhow::Result<SessionEstablishmentResponse> {
        // Get values we need before borrowing socket
        let seq = self.next_sequence();
        let node_id = self.node_id.clone();
        let addr = self.addr;

        let socket = self.socket.as_ref().ok_or_else(|| anyhow::anyhow!("Socket not bound"))?;

        let cp_f_seid = FSeid::new_ipv4(
            cp_seid,
            addr.ip().to_string().parse::<std::net::Ipv4Addr>()
                .map(|ip| ip.octets())
                .unwrap_or([127, 0, 0, 1]),
        );
        let request = PfcpMessage::SessionEstablishmentRequest(
            SessionEstablishmentRequest::new(node_id, cp_f_seid)
        );
        let buf = build_message(&request, seq, Some(0)); // SEID=0 for new session

        socket.send_to(&buf, upf_addr).await?;

        // Capture sent message
        {
            let mut cap = self.capture.write().await;
            cap.capture(CapturedMessage::new(
                MessageType::SessionEstablishmentRequest,
                buf.clone().freeze(),
                "SMF",
                "UPF",
            )
            .with_field("sequence_number", MessageField::Number(seq as i64))
            .with_field("cp_seid", MessageField::Number(cp_seid as i64)));
        }

        // Wait for response
        let mut resp_buf = vec![0u8; 65535];
        let recv_future = socket.recv_from(&mut resp_buf);
        let (len, _) = timeout(Duration::from_secs(5), recv_future).await??;

        let mut data = Bytes::copy_from_slice(&resp_buf[..len]);
        let (header, message) = parse_message(&mut data)?;

        // Capture received message
        {
            let mut cap = self.capture.write().await;
            cap.capture(CapturedMessage::new(
                MessageType::SessionEstablishmentResponse,
                Bytes::copy_from_slice(&resp_buf[..len]),
                "UPF",
                "SMF",
            ).with_field("sequence_number", MessageField::Number(header.sequence_number as i64)));
        }

        match message {
            PfcpMessage::SessionEstablishmentResponse(resp) => Ok(resp),
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    /// Send session deletion request and wait for response
    pub async fn send_session_deletion(
        &mut self,
        upf_addr: SocketAddr,
        seid: u64,
    ) -> anyhow::Result<SessionDeletionResponse> {
        // Get sequence number before borrowing socket
        let seq = self.next_sequence();

        let socket = self.socket.as_ref().ok_or_else(|| anyhow::anyhow!("Socket not bound"))?;

        let request = PfcpMessage::SessionDeletionRequest(SessionDeletionRequest::new());
        let buf = build_message(&request, seq, Some(seid));

        socket.send_to(&buf, upf_addr).await?;

        // Capture sent message
        {
            let mut cap = self.capture.write().await;
            cap.capture(CapturedMessage::new(
                MessageType::SessionDeletionRequest,
                buf.clone().freeze(),
                "SMF",
                "UPF",
            )
            .with_field("sequence_number", MessageField::Number(seq as i64))
            .with_field("seid", MessageField::Number(seid as i64)));
        }

        // Wait for response
        let mut resp_buf = vec![0u8; 65535];
        let recv_future = socket.recv_from(&mut resp_buf);
        let (len, _) = timeout(Duration::from_secs(5), recv_future).await??;

        let mut data = Bytes::copy_from_slice(&resp_buf[..len]);
        let (header, message) = parse_message(&mut data)?;

        // Capture received message
        {
            let mut cap = self.capture.write().await;
            cap.capture(CapturedMessage::new(
                MessageType::SessionDeletionResponse,
                Bytes::copy_from_slice(&resp_buf[..len]),
                "UPF",
                "SMF",
            ).with_field("sequence_number", MessageField::Number(header.sequence_number as i64)));
        }

        match message {
            PfcpMessage::SessionDeletionResponse(resp) => Ok(resp),
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    /// Stop the mock SMF
    pub fn stop(&mut self) {
        self.socket = None;
        log::info!("Mock SMF stopped");
    }
}


// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test PFCP heartbeat exchange
    #[tokio::test]
    async fn test_pfcp_heartbeat() {
        let _ = env_logger::try_init();

        let capture = Arc::new(RwLock::new(MessageCapture::new()));

        // Create and start mock UPF
        let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        upf.start().await.unwrap();
        let upf_addr = upf.addr();

        // Create and start mock SMF
        let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        smf.start().await.unwrap();

        // Spawn UPF handler
        let upf_handle = tokio::spawn(async move {
            if let Ok(Some((peer, response))) = upf.process_one().await {
                upf.send_response(peer, &response).await.ok();
            }
        });

        // SMF sends heartbeat
        let response = smf.send_heartbeat(upf_addr).await.unwrap();

        // Verify response
        assert!(response.recovery_time_stamp > 0);

        // Verify message sequence
        let cap = capture.read().await;
        assert!(cap.has_sequence(&[
            MessageType::HeartbeatRequest,
            MessageType::HeartbeatResponse,
        ]));

        upf_handle.await.ok();
    }

    /// Test PFCP association setup
    #[tokio::test]
    async fn test_pfcp_association_setup() {
        let _ = env_logger::try_init();

        let capture = Arc::new(RwLock::new(MessageCapture::new()));

        // Create and start mock UPF
        let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        upf.start().await.unwrap();
        let upf_addr = upf.addr();

        // Create and start mock SMF
        let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        smf.start().await.unwrap();

        // Spawn UPF handler
        let upf_handle = tokio::spawn(async move {
            if let Ok(Some((peer, response))) = upf.process_one().await {
                upf.send_response(peer, &response).await.ok();
            }
        });

        // SMF sends association setup
        let response = smf.send_association_setup(upf_addr).await.unwrap();

        // Verify response
        assert_eq!(response.cause, PfcpCause::RequestAccepted);
        assert!(response.recovery_time_stamp > 0);

        // Verify message sequence
        let cap = capture.read().await;
        assert!(cap.has_sequence(&[
            MessageType::AssociationSetupRequest,
            MessageType::AssociationSetupResponse,
        ]));

        upf_handle.await.ok();
    }

    /// Test PFCP session establishment
    #[tokio::test]
    async fn test_pfcp_session_establishment() {
        let _ = env_logger::try_init();

        let capture = Arc::new(RwLock::new(MessageCapture::new()));

        // Create and start mock UPF
        let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        upf.start().await.unwrap();
        let upf_addr = upf.addr();
        let upf_sessions = upf.sessions.clone();

        // Create and start mock SMF
        let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        smf.start().await.unwrap();

        // Spawn UPF handler
        let upf_handle = tokio::spawn(async move {
            if let Ok(Some((peer, response))) = upf.process_one().await {
                upf.send_response(peer, &response).await.ok();
            }
        });

        // SMF sends session establishment
        let cp_seid = 12345u64;
        let response = smf.send_session_establishment(upf_addr, cp_seid).await.unwrap();

        // Verify response
        assert_eq!(response.cause, PfcpCause::RequestAccepted);
        assert!(response.up_f_seid.is_some());
        let up_seid = response.up_f_seid.as_ref().unwrap().seid;
        assert!(up_seid > 0);

        // Verify session was created
        upf_handle.await.ok();
        let sessions = upf_sessions.read().await;
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&up_seid));

        // Verify message sequence
        let cap = capture.read().await;
        assert!(cap.has_sequence(&[
            MessageType::SessionEstablishmentRequest,
            MessageType::SessionEstablishmentResponse,
        ]));
    }

    /// Test PFCP session deletion
    #[tokio::test]
    async fn test_pfcp_session_deletion() {
        let _ = env_logger::try_init();

        let capture = Arc::new(RwLock::new(MessageCapture::new()));

        // Create and start mock UPF
        let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        upf.start().await.unwrap();
        let upf_addr = upf.addr();
        let upf_sessions = upf.sessions.clone();

        // Pre-populate a session
        {
            let mut sessions = upf_sessions.write().await;
            sessions.insert(1, SessionContext {
                cp_seid: 12345,
                up_seid: 1,
                cp_addr: "127.0.0.1:8806".parse().unwrap(),
            });
        }

        // Create and start mock SMF
        let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        smf.start().await.unwrap();

        // Spawn UPF handler
        let upf_handle = tokio::spawn(async move {
            if let Ok(Some((peer, response))) = upf.process_one().await {
                upf.send_response(peer, &response).await.ok();
            }
        });

        // SMF sends session deletion
        let response = smf.send_session_deletion(upf_addr, 1).await.unwrap();

        // Verify response
        assert_eq!(response.cause, PfcpCause::RequestAccepted);

        // Verify session was deleted
        upf_handle.await.ok();
        let sessions = upf_sessions.read().await;
        assert!(sessions.is_empty());

        // Verify message sequence
        let cap = capture.read().await;
        assert!(cap.has_sequence(&[
            MessageType::SessionDeletionRequest,
            MessageType::SessionDeletionResponse,
        ]));
    }

    /// Test full PFCP session lifecycle
    #[tokio::test]
    async fn test_pfcp_session_lifecycle() {
        let _ = env_logger::try_init();

        let capture = Arc::new(RwLock::new(MessageCapture::new()));

        // Create and start mock UPF
        let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        upf.start().await.unwrap();
        let upf_addr = upf.addr();

        // Create and start mock SMF
        let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        smf.start().await.unwrap();

        // Spawn UPF handler for 3 messages (association + establishment + deletion)
        let upf_handle = tokio::spawn(async move {
            // Process multiple messages
            for _ in 0..3 {
                if let Ok(Some((peer, response))) = upf.process_one().await {
                    upf.send_response(peer, &response).await.ok();
                }
            }
            upf.session_count().await
        });

        // 1. Association setup
        let assoc_resp = smf.send_association_setup(upf_addr).await.unwrap();
        assert_eq!(assoc_resp.cause, PfcpCause::RequestAccepted);

        // 2. Session establishment
        let cp_seid = 99999u64;
        let est_resp = smf.send_session_establishment(upf_addr, cp_seid).await.unwrap();
        assert_eq!(est_resp.cause, PfcpCause::RequestAccepted);
        let up_seid = est_resp.up_f_seid.unwrap().seid;

        // 3. Session deletion
        let del_resp = smf.send_session_deletion(upf_addr, up_seid).await.unwrap();
        assert_eq!(del_resp.cause, PfcpCause::RequestAccepted);

        // Verify final session count
        let final_count = upf_handle.await.unwrap();
        assert_eq!(final_count, 0, "All sessions should be deleted");

        // Verify complete message sequence (both SMF and UPF capture messages)
        let cap = capture.read().await;
        assert!(cap.has_sequence(&[
            MessageType::AssociationSetupRequest,
            MessageType::AssociationSetupResponse,
            MessageType::SessionEstablishmentRequest,
            MessageType::SessionEstablishmentResponse,
            MessageType::SessionDeletionRequest,
            MessageType::SessionDeletionResponse,
        ]));

        // Verify we have all expected message types (SMF sends 3 requests, UPF sends 3 responses,
        // and UPF also captures 3 incoming requests = 9 messages with current architecture)
        assert!(cap.count() >= 6, "Should have at least 6 messages total");
    }

    /// Test multiple concurrent sessions
    #[tokio::test]
    async fn test_pfcp_multiple_sessions() {
        let _ = env_logger::try_init();

        let capture = Arc::new(RwLock::new(MessageCapture::new()));

        // Create and start mock UPF
        let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        upf.start().await.unwrap();
        let upf_addr = upf.addr();

        // Create and start mock SMF
        let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
        smf.start().await.unwrap();

        // Spawn UPF handler for multiple messages
        let upf_handle = tokio::spawn(async move {
            for _ in 0..3 {
                if let Ok(Some((peer, response))) = upf.process_one().await {
                    upf.send_response(peer, &response).await.ok();
                }
            }
            upf.session_count().await
        });

        // Establish 3 sessions
        let mut up_seids = Vec::new();
        for i in 0..3 {
            let cp_seid = (i + 1) as u64 * 1000;
            let resp = smf.send_session_establishment(upf_addr, cp_seid).await.unwrap();
            assert_eq!(resp.cause, PfcpCause::RequestAccepted);
            up_seids.push(resp.up_f_seid.unwrap().seid);
        }

        // Verify all sessions were created
        let session_count = upf_handle.await.unwrap();
        assert_eq!(session_count, 3, "Should have 3 sessions");

        // Verify all UP-SEIDs are unique
        let unique_seids: std::collections::HashSet<_> = up_seids.iter().collect();
        assert_eq!(unique_seids.len(), 3, "All UP-SEIDs should be unique");
    }
}


// ============================================================================
// Property-based Tests
// ============================================================================

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// Property: Recovery timestamp is always preserved in heartbeat response
        #[test]
        fn prop_heartbeat_preserves_timestamp(ts in 1u32..u32::MAX) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let capture = Arc::new(RwLock::new(MessageCapture::new()));

                // Create mock UPF with specific timestamp
                let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
                upf.recovery_timestamp = ts;
                upf.start().await.unwrap();
                let upf_addr = upf.addr();

                // Create mock SMF
                let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
                smf.start().await.unwrap();

                // Spawn UPF handler
                let upf_handle = tokio::spawn(async move {
                    if let Ok(Some((peer, response))) = upf.process_one().await {
                        upf.send_response(peer, &response).await.ok();
                    }
                });

                // Send heartbeat and verify timestamp
                let response = smf.send_heartbeat(upf_addr).await.unwrap();
                prop_assert_eq!(response.recovery_time_stamp, ts);

                upf_handle.await.ok();
                Ok(())
            }).unwrap();
        }

        /// Property: Session ID is unique for each session establishment
        #[test]
        fn prop_session_ids_unique(cp_seids in prop::collection::vec(1u64..1000000, 2..5)) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let capture = Arc::new(RwLock::new(MessageCapture::new()));

                let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
                upf.start().await.unwrap();
                let upf_addr = upf.addr();

                let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
                smf.start().await.unwrap();

                let num_sessions = cp_seids.len();

                // Spawn UPF handler for all sessions
                let upf_handle = tokio::spawn(async move {
                    for _ in 0..num_sessions {
                        if let Ok(Some((peer, response))) = upf.process_one().await {
                            upf.send_response(peer, &response).await.ok();
                        }
                    }
                });

                // Establish sessions
                let mut up_seids = Vec::new();
                for cp_seid in cp_seids {
                    let resp = smf.send_session_establishment(upf_addr, cp_seid).await.unwrap();
                    if let Some(fseid) = resp.up_f_seid {
                        up_seids.push(fseid.seid);
                    }
                }

                upf_handle.await.ok();

                // Verify uniqueness
                let unique: std::collections::HashSet<_> = up_seids.iter().collect();
                prop_assert_eq!(unique.len(), up_seids.len(), "All UP-SEIDs must be unique");

                Ok(())
            }).unwrap();
        }

        /// Property: Sequence numbers are echoed in responses
        #[test]
        fn prop_sequence_number_echoed(seq in 1u32..1000000) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let capture = Arc::new(RwLock::new(MessageCapture::new()));

                let mut upf = MockUpf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
                upf.start().await.unwrap();
                let upf_addr = upf.addr();

                let mut smf = MockSmf::new("127.0.0.1:0".parse().unwrap(), capture.clone());
                smf.sequence_number = seq - 1; // So next will be seq
                smf.start().await.unwrap();

                // Spawn UPF handler
                let upf_handle = tokio::spawn(async move {
                    if let Ok(Some((peer, response))) = upf.process_one().await {
                        upf.send_response(peer, &response).await.ok();
                    }
                });

                // Send heartbeat
                let _ = smf.send_heartbeat(upf_addr).await.unwrap();

                upf_handle.await.ok();

                // Verify sequence number in captured messages
                let cap = capture.read().await;
                let responses = cap.messages_of_type(&MessageType::HeartbeatResponse);
                prop_assert_eq!(responses.len(), 1);
                prop_assert_eq!(responses[0].get_number("sequence_number"), Some(seq as i64));

                Ok(())
            }).unwrap();
        }
    }
}
