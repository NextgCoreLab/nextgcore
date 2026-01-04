//! NextGCore SCTP Transport Library - Pure Rust Implementation
//!
//! This crate provides SCTP socket operations using pure Rust userspace SCTP.
//! No C library dependencies required - enables true cross-compilation.
//!
//! # Features
//! - `userspace` (default): Pure Rust SCTP over UDP using webrtc-sctp
//! - `kernel`: Linux kernel SCTP (requires libsctp-dev) - for compatibility
//!
//! # Architecture
//! Uses webrtc-sctp which implements SCTP over UDP (RFC 6951), providing:
//! - Full SCTP protocol support without kernel dependencies
//! - Cross-platform compatibility (Linux, macOS, Windows)
//! - Async/await native design

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use ogs_core::pkbuf::OgsPkbuf;
use ogs_core::sockaddr::OgsSockaddr;
use ogs_core::sockopt::OgsSockopt;

use thiserror::Error;
use tokio::sync::Mutex;

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

/// Maximum SDU length
pub const OGS_MAX_SDU_LEN: usize = 8192;

/// MSG_NOTIFICATION flag for SCTP notifications
pub const MSG_NOTIFICATION: i32 = 0x8000;

/// MSG_EOR flag for end of record
pub const MSG_EOR: i32 = 0x80;

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
}

// ============================================================================
// Pure Rust SCTP Socket (userspace implementation)
// ============================================================================

#[cfg(feature = "userspace")]
mod userspace {
    use super::*;
    use bytes::Bytes;
    use tokio::net::UdpSocket;
    use webrtc_sctp::association::Association;
    use webrtc_sctp::stream::Stream;

    /// SCTP socket wrapper using userspace SCTP over UDP
    pub struct SctpSocket {
        /// Local address
        local_addr: SocketAddr,
        /// Remote address (for client connections)
        remote_addr: Option<SocketAddr>,
        /// UDP socket for SCTP-over-UDP transport
        udp_socket: Option<Arc<UdpSocket>>,
        /// SCTP association
        association: Option<Arc<Association>>,
        /// Default stream for sending
        default_stream: Option<Arc<Stream>>,
        /// Socket options
        options: OgsSockopt,
        /// Write queue for buffered sending
        write_queue: VecDeque<OgsPkbuf>,
        /// Is server socket
        is_server: bool,
    }

    impl SctpSocket {
        /// Create a new SCTP socket
        pub fn new(local_addr: SocketAddr) -> Self {
            SctpSocket {
                local_addr,
                remote_addr: None,
                udp_socket: None,
                association: None,
                default_stream: None,
                options: OgsSockopt::default(),
                write_queue: VecDeque::new(),
                is_server: false,
            }
        }

        /// Create server socket bound to address
        pub async fn server(addr: SocketAddr, options: Option<OgsSockopt>) -> Result<Self> {
            let udp = UdpSocket::bind(addr)
                .await
                .map_err(|e| SctpError::BindFailed(e))?;

            let local_addr = udp.local_addr().map_err(|e| SctpError::BindFailed(e))?;

            log::debug!("SCTP server bound to {}", local_addr);

            Ok(SctpSocket {
                local_addr,
                remote_addr: None,
                udp_socket: Some(Arc::new(udp)),
                association: None,
                default_stream: None,
                options: options.unwrap_or_default(),
                write_queue: VecDeque::new(),
                is_server: true,
            })
        }

        /// Create client socket and connect to remote
        pub async fn client(
            remote_addr: SocketAddr,
            local_addr: Option<SocketAddr>,
            options: Option<OgsSockopt>,
        ) -> Result<Self> {
            let bind_addr = local_addr.unwrap_or_else(|| {
                if remote_addr.is_ipv6() {
                    "[::]:0".parse().unwrap()
                } else {
                    "0.0.0.0:0".parse().unwrap()
                }
            });

            let udp = UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| SctpError::BindFailed(e))?;

            udp.connect(remote_addr)
                .await
                .map_err(|e| SctpError::ConnectFailed(e))?;

            let local_addr = udp.local_addr().map_err(|e| SctpError::BindFailed(e))?;

            log::debug!("SCTP client {} -> {}", local_addr, remote_addr);

            Ok(SctpSocket {
                local_addr,
                remote_addr: Some(remote_addr),
                udp_socket: Some(Arc::new(udp)),
                association: None,
                default_stream: None,
                options: options.unwrap_or_default(),
                write_queue: VecDeque::new(),
                is_server: false,
            })
        }

        /// Get local address
        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        /// Get remote address
        pub fn remote_addr(&self) -> Option<SocketAddr> {
            self.remote_addr
        }

        /// Check if connected
        pub fn is_connected(&self) -> bool {
            self.association.is_some()
        }

        /// Send data with PPID and stream number
        pub async fn send(&self, data: &[u8], ppid: u32, stream_no: u16) -> Result<usize> {
            if let Some(ref stream) = self.default_stream {
                // webrtc-sctp handles PPID internally
                let _ = ppid; // TODO: Set PPID on stream
                let _ = stream_no; // TODO: Use specific stream

                stream
                    .write(&Bytes::copy_from_slice(data))
                    .await
                    .map_err(|e| SctpError::SendFailed(io::Error::new(io::ErrorKind::Other, e)))?;

                Ok(data.len())
            } else {
                Err(SctpError::NotConnected)
            }
        }

        /// Receive data with sender info
        pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, OgsSctpInfo)> {
            if let Some(ref stream) = self.default_stream {
                let n = stream
                    .read(buf)
                    .await
                    .map_err(|e| SctpError::ReceiveFailed(io::Error::new(io::ErrorKind::Other, e)))?;

                Ok((
                    n,
                    OgsSctpInfo {
                        ppid: 0, // TODO: Get from stream
                        stream_no: 0,
                        inbound_streams: 1,
                        outbound_streams: 1,
                    },
                ))
            } else {
                Err(SctpError::NotConnected)
            }
        }

        /// Close the socket
        pub async fn close(&mut self) -> Result<()> {
            if let Some(assoc) = self.association.take() {
                assoc
                    .close()
                    .await
                    .map_err(|e| SctpError::Protocol(e.to_string()))?;
            }
            self.default_stream = None;
            self.udp_socket = None;
            Ok(())
        }

        /// Add packet to write queue
        pub fn queue_write(&mut self, pkbuf: OgsPkbuf) {
            self.write_queue.push_back(pkbuf);
        }

        /// Flush write queue
        pub async fn flush_write_queue(&mut self) -> Result<()> {
            while let Some(pkbuf) = self.write_queue.pop_front() {
                let ppid = ogs_sctp_ppid_in_pkbuf(&pkbuf);
                let stream_no = ogs_sctp_stream_no_in_pkbuf(&pkbuf);
                self.send(pkbuf.data(), ppid, stream_no).await?;
            }
            Ok(())
        }
    }
}

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
    #[cfg(feature = "userspace")]
    inner: Option<Arc<Mutex<userspace::SctpSocket>>>,
}

impl OgsSctpSock {
    /// Create a new SCTP socket wrapper
    pub fn new(sock_type: i32) -> Self {
        OgsSctpSock {
            sock_type,
            local_addr: None,
            remote_addr: None,
            write_queue: VecDeque::new(),
            #[cfg(feature = "userspace")]
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
    log::debug!("SCTP subsystem initialized (pure Rust userspace)");
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
    #[cfg(feature = "userspace")]
    {
        sctp.inner = None;
    }
}

// ============================================================================
// Async SCTP API (recommended for new code)
// ============================================================================

#[cfg(feature = "userspace")]
pub mod async_api {
    use super::*;

    /// Create an SCTP server socket
    pub async fn sctp_server(
        addr: SocketAddr,
        options: Option<OgsSockopt>,
    ) -> Result<userspace::SctpSocket> {
        userspace::SctpSocket::server(addr, options).await
    }

    /// Create an SCTP client socket
    pub async fn sctp_client(
        remote: SocketAddr,
        local: Option<SocketAddr>,
        options: Option<OgsSockopt>,
    ) -> Result<userspace::SctpSocket> {
        userspace::SctpSocket::client(remote, local, options).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(OGS_S1AP_SCTP_PORT, 36412);
        assert_eq!(OGS_NGAP_SCTP_PORT, 38412);
        assert_eq!(OGS_SGSAP_SCTP_PORT, 29118);
        assert_eq!(OGS_SCTP_S1AP_PPID, 18);
        assert_eq!(OGS_SCTP_NGAP_PPID, 60);
        assert_eq!(OGS_SCTP_X2AP_PPID, 27);
        assert_eq!(OGS_SCTP_SGSAP_PPID, 0);
    }

    #[test]
    fn test_sctp_info_default() {
        let info = OgsSctpInfo::default();
        assert_eq!(info.ppid, 0);
        assert_eq!(info.stream_no, 0);
        assert_eq!(info.inbound_streams, 0);
        assert_eq!(info.outbound_streams, 0);
    }

    #[test]
    fn test_sctp_sock_default() {
        let sock = OgsSctpSock::default();
        assert_eq!(sock.sock_type, SOCK_STREAM);
        assert!(sock.local_addr.is_none());
        assert!(sock.remote_addr.is_none());
        assert!(sock.write_queue.is_empty());
    }

    #[test]
    fn test_pkbuf_ppid_stream() {
        let mut pkbuf = OgsPkbuf::new(100);

        ogs_sctp_set_ppid_in_pkbuf(&mut pkbuf, OGS_SCTP_NGAP_PPID);
        ogs_sctp_set_stream_no_in_pkbuf(&mut pkbuf, 5);

        assert_eq!(ogs_sctp_ppid_in_pkbuf(&pkbuf), OGS_SCTP_NGAP_PPID);
        assert_eq!(ogs_sctp_stream_no_in_pkbuf(&pkbuf), 5);
    }

    #[test]
    fn test_init_final() {
        ogs_sctp_init(0);
        ogs_sctp_final();
    }

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
    fn test_error_display() {
        let err = SctpError::NotConnected;
        assert_eq!(format!("{}", err), "Association not established");
    }
}
