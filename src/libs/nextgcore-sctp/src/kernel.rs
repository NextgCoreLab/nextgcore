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
    self, c_int, c_void, sockaddr, sockaddr_in, sockaddr_in6, socklen_t, AF_INET, AF_INET6,
    IPPROTO_SCTP, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
};

use super::{NextgcoreSctpInfo, Result, SctpError};

// ============================================================================
// libsctp (lksctp-tools) FFI
// ============================================================================
//
// `sctp_sendmsg`/`sctp_recvmsg` are the simple one-shot helpers from
// `<netinet/sctp.h>` (libsctp). They carry the PPID + stream as SCTP send
// info, which the plain `libc::send`/`recv` cannot. They are linked from
// `libsctp` (`-lsctp`), present only on Linux with `libsctp-dev`. The
// declarations type-check on any platform (`cargo check`); the symbols are
// resolved only when an actual binary/test is *linked* on Linux — which is
// exactly where the `kernel` feature is meant to run.
#[link(name = "sctp")]
extern "C" {
    fn sctp_sendmsg(
        sd: c_int,
        msg: *const c_void,
        len: libc::size_t,
        to: *const sockaddr,
        tolen: socklen_t,
        ppid: u32,
        flags: u32,
        stream_no: u16,
        timetolive: u32,
        context: u32,
    ) -> c_int;

    fn sctp_recvmsg(
        sd: c_int,
        msg: *mut c_void,
        len: libc::size_t,
        from: *mut sockaddr,
        fromlen: *mut socklen_t,
        sinfo: *mut libc::sctp_sndrcvinfo,
        msg_flags: *mut c_int,
    ) -> c_int;
}

// ============================================================================
// SCTP Constants
// ============================================================================

/// SCTP socket option level. `libc` defines `SOL_SCTP` for Android only, not
/// for Linux, so it stays local; it equals `IPPROTO_SCTP` by definition.
pub const SOL_SCTP: c_int = 132;

/// SCTP socket options, re-exported from `libc` rather than transcribed (#209
/// in nextgsim): one definition, the one `<linux/sctp.h>` is checked against.
pub use libc::{SCTP_EVENTS, SCTP_INITMSG, SCTP_NODELAY, SCTP_PEER_ADDR_PARAMS, SCTP_RTOINFO};

/// SCTP notification types (`enum sctp_sn_type`). Not in `libc`.
pub const SCTP_ASSOC_CHANGE: u16 = 1;
pub const SCTP_PEER_ADDR_CHANGE: u16 = 2;
pub const SCTP_SHUTDOWN_EVENT: u16 = 5;

/// SCTP association change states (`enum sctp_sac_state`). Not in `libc`.
pub const SCTP_COMM_UP: u16 = 0;
pub const SCTP_COMM_LOST: u16 = 1;
pub const SCTP_RESTART: u16 = 2;
pub const SCTP_SHUTDOWN_COMP: u16 = 3;
pub const SCTP_CANT_STR_ASSOC: u16 = 4;

// ============================================================================
// SCTP Structures (matching kernel ABI)
// ============================================================================
//
// `sctp_initmsg` and `sctp_sndrcvinfo` are used straight from `libc`: they were
// hand-transcribed here until 2026-10-18, and the transcription is what let
// `sinfo_assoc_id` sit as `u32` instead of the signed `sctp_assoc_t` until
// #429. The unused `SctpRtoinfo` copy, which carried the same unsigned
// `srto_assoc_id` defect, was deleted rather than fixed. Only
// `sctp_event_subscribe` remains local, because `libc` does not define it.

/// SCTP event subscription (`struct sctp_event_subscribe`, `<linux/sctp.h>`).
///
/// Every member is a `__u8` flag. Not in `libc`, so this is the one SCTP struct
/// still transcribed; `event_subscribe_layout_matches_the_kernel` pins it. The
/// kernel copies `min(optlen, sizeof(kernel struct))`, so this 14-member form
/// (through `sctp_send_failure_event_event`) is accepted by older
/// kernels too.
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

        let fd = unsafe { libc::socket(family, sock_type, IPPROTO_SCTP) };

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

    /// Create a listening server socket.
    ///
    /// Uses SOCK_STREAM (one-to-one): each peer association becomes its own
    /// accepted socket via [`accept`](Self::accept), mirroring Open5GS's
    /// default NGAP server model and the `KernelSctpServer` accept loop. (The
    /// one-to-many SOCK_SEQPACKET model would identify associations by
    /// `sctp_assoc_t` on a single fd and never call `accept`; we deliberately
    /// take the simpler per-association-fd model so each gNB maps to one fd.)
    pub fn server(addr: SocketAddr) -> Result<Self> {
        let mut sock = Self::new(&addr, SOCK_STREAM)?;
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

    /// Send data with PPID and stream number via `sctp_sendmsg`.
    ///
    /// The PPID travels on the wire in **network byte order**: lksctp
    /// transmits the value passed to `sctp_sendmsg` verbatim, so the caller
    /// byte-swaps it here (Open5GS `nextgcore_sctp_senddata` does the same with
    /// `htobe32`). Getting this wrong silently breaks NGAP demux on the peer —
    /// see the project's PPID-network-order note. NGAP uses PPID 60.
    pub fn send(&self, data: &[u8], ppid: u32, stream_no: u16) -> Result<usize> {
        let sent = unsafe {
            sctp_sendmsg(
                self.fd.as_raw_fd(),
                data.as_ptr() as *const c_void,
                data.len(),
                std::ptr::null(), // connected socket: destination is implicit
                0,
                ppid.to_be(), // network byte order on the wire
                0,            // flags
                stream_no,
                0, // timetolive (0 = no expiry)
                0, // context
            )
        };

        if sent < 0 {
            return Err(SctpError::SendFailed(io::Error::last_os_error()));
        }

        Ok(sent as usize)
    }

    /// The association's negotiated `(inbound, outbound)` stream counts, read with
    /// `getsockopt(SCTP_STATUS)` (RFC 6458 §8.2.1): `sstat_instrms` / `sstat_outstrms`,
    /// i.e. the configured counts lowered to what the peer offered in its INIT / INIT ACK.
    /// An outbound stream identifier must be below the outbound count (#813).
    pub fn negotiated_streams(&self) -> Result<(u16, u16)> {
        let mut status: SctpStatus = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<SctpStatus>() as socklen_t;
        let result = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                SOL_SCTP,
                libc::SCTP_STATUS,
                &mut status as *mut SctpStatus as *mut c_void,
                &mut len,
            )
        };
        if result < 0 {
            return Err(SctpError::SockoptFailed(io::Error::last_os_error()));
        }
        Ok((status.sstat_instrms, status.sstat_outstrms))
    }

    /// Receive a single SCTP message, returning the byte count, the decoded
    /// send/receive info (PPID restored to host order, stream number) and the
    /// raw `msg_flags`. `msg_flags & MSG_NOTIFICATION` marks an SCTP event
    /// notification (e.g. shutdown / association change) rather than user data.
    pub fn recv_msg(&self, buf: &mut [u8]) -> Result<(usize, NextgcoreSctpInfo, i32)> {
        let mut sinfo = libc::sctp_sndrcvinfo {
            sinfo_stream: 0,
            sinfo_ssn: 0,
            sinfo_flags: 0,
            sinfo_ppid: 0,
            sinfo_context: 0,
            sinfo_timetolive: 0,
            sinfo_tsn: 0,
            sinfo_cumtsn: 0,
            sinfo_assoc_id: 0,
        };
        let mut msg_flags: c_int = 0;

        let received = unsafe {
            sctp_recvmsg(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sinfo as *mut libc::sctp_sndrcvinfo,
                &mut msg_flags as *mut c_int,
            )
        };

        if received < 0 {
            return Err(SctpError::ReceiveFailed(io::Error::last_os_error()));
        }

        let info = NextgcoreSctpInfo {
            ppid: u32::from_be(sinfo.sinfo_ppid), // wire (network) -> host order
            stream_no: sinfo.sinfo_stream,
            inbound_streams: self.inbound_streams,
            outbound_streams: self.outbound_streams,
        };

        Ok((received as usize, info, msg_flags))
    }

    /// Receive data (compatibility shim that discards `msg_flags`).
    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, NextgcoreSctpInfo)> {
        let (n, info, _flags) = self.recv_msg(buf)?;
        Ok((n, info))
    }

    /// Put the socket in (non-)blocking mode. Required before registering the
    /// fd with tokio's `AsyncFd` in the async `KernelSctpServer`.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let fd = self.fd.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(SctpError::SockoptFailed(io::Error::last_os_error()));
        }
        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) } < 0 {
            return Err(SctpError::SockoptFailed(io::Error::last_os_error()));
        }
        Ok(())
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

        let result = unsafe { libc::bind(self.fd.as_raw_fd(), sockaddr_ptr, sockaddr_len) };

        if result < 0 {
            return Err(SctpError::BindFailed(io::Error::last_os_error()));
        }

        // Get actual bound address
        self.local_addr = self.get_local_addr()?;

        Ok(())
    }

    fn listen(&self, backlog: c_int) -> Result<()> {
        let result = unsafe { libc::listen(self.fd.as_raw_fd(), backlog) };

        if result < 0 {
            return Err(SctpError::ListenFailed(io::Error::last_os_error()));
        }

        Ok(())
    }

    fn connect(&mut self, addr: &SocketAddr) -> Result<()> {
        let (sockaddr_ptr, sockaddr_len) = socketaddr_to_sockaddr(addr);

        let result = unsafe { libc::connect(self.fd.as_raw_fd(), sockaddr_ptr, sockaddr_len) };

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
        let initmsg = libc::sctp_initmsg {
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
                mem::size_of::<libc::sctp_initmsg>() as socklen_t,
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

/// `struct sctp_status` (`<linux/sctp.h>`, RFC 6458 §8.2.1). libc does not define it.
/// The trailing `struct sctp_paddrinfo` (packed, aligned 4: an `sctp_assoc_t`, a
/// 128-octet `sockaddr_storage` and five 32-bit fields) is kept as opaque octets.
#[repr(C)]
struct SctpStatus {
    sstat_assoc_id: i32,
    sstat_state: i32,
    sstat_rwnd: u32,
    sstat_unackdata: u16,
    sstat_penddata: u16,
    sstat_instrms: u16,
    sstat_outstrms: u16,
    sstat_fragmentation_point: u32,
    sstat_primary: [u8; 152],
}

// The kernel rejects a shorter option buffer with EINVAL, so the layout is pinned.
const _: () = assert!(mem::size_of::<SctpStatus>() == 176);

impl AsRawFd for KernelSctpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
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

fn sockaddr_to_socketaddr(storage: &libc::sockaddr_storage, len: socklen_t) -> Result<SocketAddr> {
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

    /// #813 (review of #870, MINOR 5): `negotiated_streams` reads the kernel's
    /// `SCTP_STATUS` on a real loopback association. Both ends offer 10 / 10, so the
    /// accepted socket reports 10 outbound streams. Ignored by default: it needs the SCTP
    /// kernel module and libsctp; run with `--features kernel -- --ignored`.
    #[test]
    #[ignore = "needs the SCTP kernel module and libsctp"]
    fn negotiated_streams_reads_sctp_status_on_a_live_association() {
        let server = KernelSctpSocket::server("127.0.0.1:0".parse().unwrap()).expect("server");
        let _client = KernelSctpSocket::client(server.local_addr(), None).expect("client");
        let (accepted, _) = server.accept().expect("accept");
        assert_eq!(
            accepted.negotiated_streams().expect("SCTP_STATUS"),
            (10, 10)
        );
    }

    /// `SctpEventSubscribe` is the one SCTP struct `libc` lacks, so it is still
    /// transcribed and handed to `setsockopt` by size: a dropped, reordered or
    /// widened member shifts every flag after it and silently subscribes the
    /// wrong events. Pin the size, the alignment and the offsets of the three
    /// members `set_sctp_events` sets against `<linux/sctp.h>`.
    #[test]
    fn event_subscribe_layout_matches_the_kernel() {
        assert_eq!(mem::size_of::<SctpEventSubscribe>(), 14);
        assert_eq!(mem::align_of::<SctpEventSubscribe>(), 1);
        assert_eq!(mem::offset_of!(SctpEventSubscribe, sctp_data_io_event), 0);
        assert_eq!(
            mem::offset_of!(SctpEventSubscribe, sctp_association_event),
            1
        );
        assert_eq!(mem::offset_of!(SctpEventSubscribe, sctp_address_event), 2);
        assert_eq!(mem::offset_of!(SctpEventSubscribe, sctp_shutdown_event), 5);
        assert_eq!(
            mem::offset_of!(SctpEventSubscribe, sctp_send_failure_event_event),
            13
        );
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
