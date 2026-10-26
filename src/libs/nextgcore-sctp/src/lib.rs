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

use std::io;

use bytes::Bytes;
use nextgcore_core::pkbuf::NextgcorePkbuf;

use thiserror::Error;

// Kernel SCTP module (Linux only, requires libsctp)
#[cfg(feature = "kernel")]
pub mod kernel;

#[cfg(feature = "kernel")]
pub use kernel::KernelSctpSocket;

// Async kernel-SCTP NGAP server (T0.2b). Reuses the userspace server's event
// types, so it requires both features; the `kernel` primitive alone still
// builds standalone.
#[cfg(all(feature = "kernel", feature = "sctp-proto"))]
pub mod kernel_server;

#[cfg(all(feature = "kernel", feature = "sctp-proto"))]
pub use kernel_server::{Admission, KernelSctpServer, Refusal};

/// #1142: the answer to an out-of-the-blue packet (RFC 9260 §8.4).
pub mod ootb;

// sctp-proto based server module
#[cfg(feature = "sctp-proto")]
pub mod server;

#[cfg(feature = "sctp-proto")]
pub use server::{RecvOutcome, SctpServer, SctpServerConfig, ServerError, ServerEvent};

// QUIC transport option (B13.3 - 6G forward-looking)
pub mod quic;

pub use quic::{
    CongestionController, QuicConfig, QuicConnectionState, QuicError, QuicResult, QuicServer,
    QuicStats, QuicTransport, StreamMessage, TlsConfig as QuicTlsConfig,
};

// ============================================================================
// Constants (matching 3GPP specifications)
// ============================================================================

/// S1AP SCTP port (3GPP TS 36.412)
pub const NEXTGCORE_S1AP_SCTP_PORT: u16 = 36412;

/// SGsAP SCTP port (3GPP TS 29.118)
pub const NEXTGCORE_SGSAP_SCTP_PORT: u16 = 29118;

/// NGAP SCTP port (3GPP TS 38.412)
pub const NEXTGCORE_NGAP_SCTP_PORT: u16 = 38412;

/// S1AP PPID (Payload Protocol Identifier)
pub const NEXTGCORE_SCTP_S1AP_PPID: u32 = 18;

/// X2AP PPID
pub const NEXTGCORE_SCTP_X2AP_PPID: u32 = 27;

/// SBc-AP (MME - CBC) SCTP payload protocol identifier (TS 29.168 §4.1.3).
pub const NEXTGCORE_SCTP_SBCAP_PPID: u32 = 24;

/// SGsAP PPID
pub const NEXTGCORE_SCTP_SGSAP_PPID: u32 = 0;

/// NGAP PPID (TS 38.412 §7). The one spelling: it is also the name nextgsim's
/// SCTP layer uses for the same value, so a reader of either repo meets one name.
pub const NGAP_PPID: u32 = 60;

/// Maximum SDU length
pub const NEXTGCORE_MAX_SDU_LEN: usize = 8192;

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
pub struct NextgcoreSctpInfo {
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
// Helper functions for pkbuf SCTP parameters
// ============================================================================

/// Get PPID from packet buffer param[0]
#[inline]
pub fn nextgcore_sctp_ppid_in_pkbuf(pkbuf: &NextgcorePkbuf) -> u32 {
    pkbuf.param[0] as u32
}

/// Get stream number from packet buffer param[1]
#[inline]
pub fn nextgcore_sctp_stream_no_in_pkbuf(pkbuf: &NextgcorePkbuf) -> u16 {
    pkbuf.param[1] as u16
}

/// Set PPID in packet buffer param[0]
#[inline]
pub fn nextgcore_sctp_set_ppid_in_pkbuf(pkbuf: &mut NextgcorePkbuf, ppid: u32) {
    pkbuf.param[0] = ppid as u64;
}

/// Set stream number in packet buffer param[1]
#[inline]
pub fn nextgcore_sctp_set_stream_no_in_pkbuf(pkbuf: &mut NextgcorePkbuf, stream_no: u16) {
    pkbuf.param[1] = stream_no as u64;
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
        assert_eq!(NEXTGCORE_S1AP_SCTP_PORT, 36412);
        assert_eq!(NEXTGCORE_NGAP_SCTP_PORT, 38412);
        assert_eq!(NEXTGCORE_SGSAP_SCTP_PORT, 29118);
        assert_eq!(NEXTGCORE_SCTP_S1AP_PPID, 18);
        assert_eq!(NEXTGCORE_SCTP_X2AP_PPID, 27);
        assert_eq!(NEXTGCORE_SCTP_SGSAP_PPID, 0);
        assert_eq!(NGAP_PPID, 60);
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_NUM_STREAMS, 2);
        assert_eq!(DEFAULT_MAX_MESSAGE_SIZE, 65536);
        assert_eq!(DEFAULT_RECEIVE_BUFFER_SIZE, 262144);
        assert_eq!(NEXTGCORE_MAX_SDU_LEN, 8192);
    }

    #[test]
    fn test_msg_flags() {
        assert_eq!(MSG_NOTIFICATION, 0x8000);
        assert_eq!(MSG_EOR, 0x80);
    }

    // ============================================================================
    // NextgcoreSctpInfo Tests
    // ============================================================================

    #[test]
    fn test_sctp_info_default() {
        let info = NextgcoreSctpInfo::default();
        assert_eq!(info.ppid, 0);
        assert_eq!(info.stream_no, 0);
        assert_eq!(info.inbound_streams, 0);
        assert_eq!(info.outbound_streams, 0);
    }

    #[test]
    fn test_sctp_info_custom() {
        let info = NextgcoreSctpInfo {
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
        let info1 = NextgcoreSctpInfo {
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
    // Packet Buffer Tests
    // ============================================================================

    #[test]
    fn test_pkbuf_ppid_stream() {
        let mut pkbuf = NextgcorePkbuf::new(100);

        nextgcore_sctp_set_ppid_in_pkbuf(&mut pkbuf, NGAP_PPID);
        nextgcore_sctp_set_stream_no_in_pkbuf(&mut pkbuf, 5);

        assert_eq!(nextgcore_sctp_ppid_in_pkbuf(&pkbuf), NGAP_PPID);
        assert_eq!(nextgcore_sctp_stream_no_in_pkbuf(&pkbuf), 5);
    }

    #[test]
    fn test_pkbuf_ppid_s1ap() {
        let mut pkbuf = NextgcorePkbuf::new(100);
        nextgcore_sctp_set_ppid_in_pkbuf(&mut pkbuf, NEXTGCORE_SCTP_S1AP_PPID);
        assert_eq!(
            nextgcore_sctp_ppid_in_pkbuf(&pkbuf),
            NEXTGCORE_SCTP_S1AP_PPID
        );
    }

    #[test]
    fn test_pkbuf_stream_zero() {
        let mut pkbuf = NextgcorePkbuf::new(100);
        nextgcore_sctp_set_stream_no_in_pkbuf(&mut pkbuf, 0);
        assert_eq!(nextgcore_sctp_stream_no_in_pkbuf(&pkbuf), 0);
    }

    #[test]
    fn test_pkbuf_stream_max() {
        let mut pkbuf = NextgcorePkbuf::new(100);
        nextgcore_sctp_set_stream_no_in_pkbuf(&mut pkbuf, u16::MAX);
        assert_eq!(nextgcore_sctp_stream_no_in_pkbuf(&pkbuf), u16::MAX);
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
        let err =
            SctpError::ConnectFailed(io::Error::new(io::ErrorKind::ConnectionRefused, "test"));
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
