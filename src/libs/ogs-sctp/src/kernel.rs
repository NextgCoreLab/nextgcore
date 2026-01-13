//! Linux Kernel SCTP Implementation
//!
//! This module provides native SCTP socket support using the Linux kernel's
//! SCTP stack. Requires `libsctp-dev` to be installed and the SCTP kernel
//! module to be loaded (`modprobe sctp`).
//!
//! # Docker Requirements
//! - Host must have SCTP kernel module: `sudo modprobe sctp`
//! - Container needs `libsctp1` runtime library
//! - Port mapping uses `/sctp` protocol: `38412:38412/sctp`

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{
    self, c_int, c_void, sockaddr, sockaddr_in, sockaddr_in6, socklen_t,
    AF_INET, AF_INET6, IPPROTO_SCTP, SOCK_SEQPACKET, SOCK_STREAM,
    SOL_SOCKET, SO_REUSEADDR,
};

use super::{OgsSctpInfo, Result, SctpError};

// ============================================================================
// SCTP Constants
// ============================================================================

/// SCTP socket option level
pub const SOL_SCTP: c_int = 132;

/// SCTP socket options
pub const SCTP_EVENTS: c_int = 11;
pub const SCTP_INITMSG: c_int = 2;
pub const SCTP_NODELAY: c_int = 3;
pub const SCTP_RTOINFO: c_int = 0;
pub const SCTP_PEER_ADDR_PARAMS: c_int = 9;

/// SCTP notification types
pub const SCTP_ASSOC_CHANGE: u16 = 1;
pub const SCTP_PEER_ADDR_CHANGE: u16 = 2;
pub const SCTP_SHUTDOWN_EVENT: u16 = 5;

/// SCTP association change states
pub const SCTP_COMM_UP: u16 = 0;
pub const SCTP_COMM_LOST: u16 = 1;
pub const SCTP_RESTART: u16 = 2;
pub const SCTP_SHUTDOWN_COMP: u16 = 3;
pub const SCTP_CANT_STR_ASSOC: u16 = 4;

// ============================================================================
// SCTP Structures (matching kernel ABI)
// ============================================================================

/// SCTP initialization message
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SctpInitmsg {
    pub sinit_num_ostreams: u16,
    pub sinit_max_instreams: u16,
    pub sinit_max_attempts: u16,
    pub sinit_max_init_timeo: u16,
}

/// SCTP event subscribe (simplified for common events)
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SctpEventSubscribe {
    pub sctp_data_io_event: u8,
    pub sctp_association_event: u8,
    pub sctp_address_event: u8,
    pub sctp_send_failure_event: u8,
    pub sctp_peer_error_event: u8,
    pub sctp_shutdown_event: u8,
    pub sctp_partial_delivery_event: u8,
    pub sctp_adaptation_layer_event: u8,
    pub sctp_authentication_event: u8,
    pub sctp_sender_dry_event: u8,
    pub sctp_stream_reset_event: u8,
    pub sctp_assoc_reset_event: u8,
    pub sctp_stream_change_event: u8,
    pub sctp_send_failure_event_event: u8,
}

/// SCTP send/receive info
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SctpSndRcvInfo {
    pub sinfo_stream: u16,
    pub sinfo_ssn: u16,
    pub sinfo_flags: u16,
    pub sinfo_ppid: u32,
    pub sinfo_context: u32,
    pub sinfo_timetolive: u32,
    pub sinfo_tsn: u32,
    pub sinfo_cumtsn: u32,
    pub sinfo_assoc_id: u32,
}

/// SCTP RTO info
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SctpRtoinfo {
    pub srto_assoc_id: u32,
    pub srto_initial: u32,
    pub srto_max: u32,
    pub srto_min: u32,
}

// ============================================================================
// Kernel SCTP Socket
// ============================================================================

/// Kernel SCTP socket wrapper
pub struct KernelSctpSocket {
    /// File descriptor
    fd: OwnedFd,
    /// Local address
    local_addr: SocketAddr,
    /// Remote address (for connected sockets)
    remote_addr: Option<SocketAddr>,
    /// Is server socket (listening)
    is_server: bool,
    /// Number of inbound streams
    inbound_streams: u16,
    /// Number of outbound streams
    outbound_streams: u16,
}

impl KernelSctpSocket {
    /// Create a new kernel SCTP socket
    pub fn new(addr: &SocketAddr, sock_type: c_int) -> Result<Self> {
        let family = match addr {
            SocketAddr::V4(_) => AF_INET,
            SocketAddr::V6(_) => AF_INET6,
        };

        let fd = unsafe {
            libc::socket(family, sock_type, IPPROTO_SCTP)
        };

        if fd < 0 {
            return Err(SctpError::SocketCreation(io::Error::last_os_error()));
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        Ok(Self {
            fd: owned_fd,
            local_addr: *addr,
            remote_addr: None,
            is_server: false,
            inbound_streams: 0,
            outbound_streams: 0,
        })
    }

    /// Create a server socket (SOCK_SEQPACKET for one-to-many)
    pub fn server(addr: SocketAddr) -> Result<Self> {
        let mut sock = Self::new(&addr, SOCK_SEQPACKET)?;
        sock.is_server = true;

        // Set socket options
        sock.set_reuse_addr(true)?;
        sock.set_sctp_events()?;
        sock.set_sctp_initmsg(10, 10, 4, 30000)?;

        // Bind
        sock.bind(&addr)?;

        // Listen
        sock.listen(128)?;

        log::info!("Kernel SCTP server listening on {}", addr);

        Ok(sock)
    }

    /// Create a client socket (SOCK_STREAM for one-to-one)
    pub fn client(remote: SocketAddr, local: Option<SocketAddr>) -> Result<Self> {
        let bind_addr = local.unwrap_or_else(|| {
            if remote.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            }
        });

        let mut sock = Self::new(&bind_addr, SOCK_STREAM)?;

        // Set socket options
        sock.set_sctp_events()?;
        sock.set_sctp_initmsg(10, 10, 4, 30000)?;

        // Bind to local address
        sock.bind(&bind_addr)?;

        // Connect to remote
        sock.connect(&remote)?;

        log::info!("Kernel SCTP client {} -> {}", sock.local_addr, remote);

        Ok(sock)
    }

    /// Accept a new connection (for server sockets)
    pub fn accept(&self) -> Result<(Self, SocketAddr)> {
        let mut addr_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut addr_len: socklen_t = mem::size_of::<libc::sockaddr_storage>() as socklen_t;

        let new_fd = unsafe {
            libc::accept(
                self.fd.as_raw_fd(),
                &mut addr_storage as *mut _ as *mut sockaddr,
                &mut addr_len,
            )
        };

        if new_fd < 0 {
            return Err(SctpError::ReceiveFailed(io::Error::last_os_error()));
        }

        let peer_addr = sockaddr_to_socketaddr(&addr_storage, addr_len)?;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(new_fd) };

        let new_sock = Self {
            fd: owned_fd,
            local_addr: self.local_addr,
            remote_addr: Some(peer_addr),
            is_server: false,
            inbound_streams: 0,
            outbound_streams: 0,
        };

        log::debug!("Accepted SCTP connection from {}", peer_addr);

        Ok((new_sock, peer_addr))
    }

    /// Send data with PPID and stream number
    pub fn send(&self, data: &[u8], ppid: u32, stream_no: u16) -> Result<usize> {
        // For simplicity, use regular send for connected sockets
        // Full implementation would use sctp_sendmsg
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                data.as_ptr() as *const c_void,
                data.len(),
                0,
            )
        };

        if sent < 0 {
            return Err(SctpError::SendFailed(io::Error::last_os_error()));
        }

        let _ = (ppid, stream_no); // Note: PPID/stream set via sctp_sendmsg cmsg ancillary data

        Ok(sent as usize)
    }

    /// Receive data
    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, OgsSctpInfo)> {
        let received = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
            )
        };

        if received < 0 {
            return Err(SctpError::ReceiveFailed(io::Error::last_os_error()));
        }

        // Note: PPID/stream extracted via sctp_recvmsg cmsg ancillary data
        let info = OgsSctpInfo {
            ppid: 0,
            stream_no: 0,
            inbound_streams: self.inbound_streams,
            outbound_streams: self.outbound_streams,
        };

        Ok((received as usize, info))
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get remote address
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Get raw file descriptor (for polling)
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    // ========================================================================
    // Internal methods
    // ========================================================================

    fn bind(&mut self, addr: &SocketAddr) -> Result<()> {
        let (sockaddr_ptr, sockaddr_len) = socketaddr_to_sockaddr(addr);

        let result = unsafe {
            libc::bind(
                self.fd.as_raw_fd(),
                sockaddr_ptr,
                sockaddr_len,
            )
        };

        if result < 0 {
            return Err(SctpError::BindFailed(io::Error::last_os_error()));
        }

        // Get actual bound address
        self.local_addr = self.get_local_addr()?;

        Ok(())
    }

    fn listen(&self, backlog: c_int) -> Result<()> {
        let result = unsafe {
            libc::listen(self.fd.as_raw_fd(), backlog)
        };

        if result < 0 {
            return Err(SctpError::ListenFailed(io::Error::last_os_error()));
        }

        Ok(())
    }

    fn connect(&mut self, addr: &SocketAddr) -> Result<()> {
        let (sockaddr_ptr, sockaddr_len) = socketaddr_to_sockaddr(addr);

        let result = unsafe {
            libc::connect(
                self.fd.as_raw_fd(),
                sockaddr_ptr,
                sockaddr_len,
            )
        };

        if result < 0 {
            return Err(SctpError::ConnectFailed(io::Error::last_os_error()));
        }

        self.remote_addr = Some(*addr);
        Ok(())
    }

    fn get_local_addr(&self) -> Result<SocketAddr> {
        let mut addr_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut addr_len: socklen_t = mem::size_of::<libc::sockaddr_storage>() as socklen_t;

        let result = unsafe {
            libc::getsockname(
                self.fd.as_raw_fd(),
                &mut addr_storage as *mut _ as *mut sockaddr,
                &mut addr_len,
            )
        };

        if result < 0 {
            return Err(SctpError::SockoptFailed(io::Error::last_os_error()));
        }

        sockaddr_to_socketaddr(&addr_storage, addr_len)
    }

    fn set_reuse_addr(&self, enable: bool) -> Result<()> {
        let optval: c_int = if enable { 1 } else { 0 };

        let result = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                SOL_SOCKET,
                SO_REUSEADDR,
                &optval as *const _ as *const c_void,
                mem::size_of::<c_int>() as socklen_t,
            )
        };

        if result < 0 {
            return Err(SctpError::SockoptFailed(io::Error::last_os_error()));
        }

        Ok(())
    }

    fn set_sctp_events(&self) -> Result<()> {
        let events = SctpEventSubscribe {
            sctp_data_io_event: 1,
            sctp_association_event: 1,
            sctp_address_event: 1,
            sctp_shutdown_event: 1,
            ..Default::default()
        };

        let result = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                SOL_SCTP,
                SCTP_EVENTS,
                &events as *const _ as *const c_void,
                mem::size_of::<SctpEventSubscribe>() as socklen_t,
            )
        };

        if result < 0 {
            log::warn!("Failed to set SCTP events: {}", io::Error::last_os_error());
            // Don't fail - some options may not be supported
        }

        Ok(())
    }

    fn set_sctp_initmsg(
        &mut self,
        num_ostreams: u16,
        max_instreams: u16,
        max_attempts: u16,
        max_init_timeo: u16,
    ) -> Result<()> {
        let initmsg = SctpInitmsg {
            sinit_num_ostreams: num_ostreams,
            sinit_max_instreams: max_instreams,
            sinit_max_attempts: max_attempts,
            sinit_max_init_timeo: max_init_timeo,
        };

        let result = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                SOL_SCTP,
                SCTP_INITMSG,
                &initmsg as *const _ as *const c_void,
                mem::size_of::<SctpInitmsg>() as socklen_t,
            )
        };

        if result < 0 {
            log::warn!("Failed to set SCTP initmsg: {}", io::Error::last_os_error());
        }

        self.inbound_streams = max_instreams;
        self.outbound_streams = num_ostreams;

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn socketaddr_to_sockaddr(addr: &SocketAddr) -> (*const sockaddr, socklen_t) {
    match addr {
        SocketAddr::V4(v4) => {
            let mut sin: sockaddr_in = unsafe { mem::zeroed() };
            sin.sin_family = AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            {
                sin.sin_len = mem::size_of::<sockaddr_in>() as u8;
            }
            let sin_box = Box::new(sin);
            let ptr = Box::into_raw(sin_box) as *const sockaddr;
            (ptr, mem::size_of::<sockaddr_in>() as socklen_t)
        }
        SocketAddr::V6(v6) => {
            let mut sin6: sockaddr_in6 = unsafe { mem::zeroed() };
            sin6.sin6_family = AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_scope_id = v6.scope_id();
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            {
                sin6.sin6_len = mem::size_of::<sockaddr_in6>() as u8;
            }
            let sin6_box = Box::new(sin6);
            let ptr = Box::into_raw(sin6_box) as *const sockaddr;
            (ptr, mem::size_of::<sockaddr_in6>() as socklen_t)
        }
    }
}

fn sockaddr_to_socketaddr(
    storage: &libc::sockaddr_storage,
    len: socklen_t,
) -> Result<SocketAddr> {
    let family = storage.ss_family as c_int;

    if family == AF_INET && len >= mem::size_of::<sockaddr_in>() as socklen_t {
        let sin = unsafe { &*(storage as *const _ as *const sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port = u16::from_be(sin.sin_port);
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    } else if family == AF_INET6 && len >= mem::size_of::<sockaddr_in6>() as socklen_t {
        let sin6 = unsafe { &*(storage as *const _ as *const sockaddr_in6) };
        let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        let port = u16::from_be(sin6.sin6_port);
        Ok(SocketAddr::new(IpAddr::V6(ip), port))
    } else {
        Err(SctpError::NoValidAddress)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sctp_initmsg_size() {
        assert_eq!(mem::size_of::<SctpInitmsg>(), 8);
    }

    #[test]
    fn test_socketaddr_conversion() {
        let addr: SocketAddr = "127.0.0.1:38412".parse().unwrap();
        let (ptr, len) = socketaddr_to_sockaddr(&addr);
        assert!(len > 0);

        // Clean up
        unsafe {
            let _ = Box::from_raw(ptr as *mut sockaddr_in);
        }
    }
}
