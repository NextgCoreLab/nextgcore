//! Socket operations
//!
//! Exact port of lib/core/ogs-socket.h and ogs-socket.c

use std::os::unix::io::RawFd;

use crate::errno::{OGS_ERROR, OGS_OK};
use crate::sockaddr::OgsSockaddr;

/// Socket type (file descriptor on Unix)
#[cfg(unix)]
pub type OgsSocket = RawFd;

/// Invalid socket constant
#[cfg(unix)]
pub const INVALID_SOCKET: OgsSocket = -1;

/// Socket structure (identical to ogs_sock_t)
pub struct OgsSock {
    pub family: i32,
    pub fd: OgsSocket,
    pub local_addr: Option<OgsSockaddr>,
    pub remote_addr: Option<OgsSockaddr>,
}

impl OgsSock {
    /// Create a new socket structure (identical to ogs_sock_create)
    pub fn create() -> Self {
        OgsSock {
            family: 0,
            fd: INVALID_SOCKET,
            local_addr: None,
            remote_addr: None,
        }
    }

    /// Check if socket is valid
    pub fn is_valid(&self) -> bool {
        self.fd != INVALID_SOCKET
    }
}

impl Drop for OgsSock {
    fn drop(&mut self) {
        if self.fd != INVALID_SOCKET {
            let _ = ogs_closesocket(self.fd);
            self.fd = INVALID_SOCKET;
        }
    }
}

/// Initialize socket subsystem (identical to ogs_socket_init)
pub fn ogs_socket_init() {
    // No-op on Unix
}

/// Finalize socket subsystem (identical to ogs_socket_final)
pub fn ogs_socket_final() {
    // No-op on Unix
}

/// Create a socket (identical to ogs_sock_socket)
pub fn ogs_sock_socket(family: i32, sock_type: i32, protocol: i32) -> Option<OgsSock> {
    let fd = unsafe { libc::socket(family, sock_type, protocol) };

    if fd < 0 {
        return None;
    }

    Some(OgsSock {
        family,
        fd,
        local_addr: None,
        remote_addr: None,
    })
}

/// Bind socket to address (identical to ogs_sock_bind)
pub fn ogs_sock_bind(sock: &mut OgsSock, addr: &OgsSockaddr) -> i32 {
    let (sockaddr, addrlen) = sockaddr_to_raw(addr);

    let rv = unsafe { libc::bind(sock.fd, sockaddr.as_ptr() as *const libc::sockaddr, addrlen) };

    if rv != 0 {
        return OGS_ERROR;
    }

    sock.local_addr = Some(addr.clone());
    OGS_OK
}

/// Connect socket to address (identical to ogs_sock_connect)
pub fn ogs_sock_connect(sock: &mut OgsSock, addr: &OgsSockaddr) -> i32 {
    let (sockaddr, addrlen) = sockaddr_to_raw(addr);

    let rv = unsafe { libc::connect(sock.fd, sockaddr.as_ptr() as *const libc::sockaddr, addrlen) };

    if rv != 0 {
        return OGS_ERROR;
    }

    sock.remote_addr = Some(addr.clone());
    OGS_OK
}

/// Listen on socket (identical to ogs_sock_listen)
pub fn ogs_sock_listen(sock: &OgsSock) -> i32 {
    let rv = unsafe { libc::listen(sock.fd, 5) };

    if rv < 0 {
        return OGS_ERROR;
    }

    OGS_OK
}

/// Accept connection on socket (identical to ogs_sock_accept)
pub fn ogs_sock_accept(sock: &OgsSock) -> Option<OgsSock> {
    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addrlen: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let new_fd = unsafe {
        libc::accept(
            sock.fd,
            &mut addr_storage as *mut _ as *mut libc::sockaddr,
            &mut addrlen,
        )
    };

    if new_fd < 0 {
        return None;
    }

    let remote_addr = raw_to_sockaddr(&addr_storage, addrlen);

    Some(OgsSock {
        family: sock.family,
        fd: new_fd,
        local_addr: None,
        remote_addr,
    })
}

/// Write to socket (identical to ogs_write)
pub fn ogs_write(fd: OgsSocket, buf: &[u8]) -> isize {
    unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) }
}

/// Read from socket (identical to ogs_read)
pub fn ogs_read(fd: OgsSocket, buf: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
}

/// Send data on socket (identical to ogs_send)
pub fn ogs_send(fd: OgsSocket, buf: &[u8], flags: i32) -> isize {
    unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), flags) }
}

/// Send data to address (identical to ogs_sendto)
pub fn ogs_sendto(fd: OgsSocket, buf: &[u8], flags: i32, to: &OgsSockaddr) -> isize {
    let (sockaddr, addrlen) = sockaddr_to_raw(to);

    unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            flags,
            sockaddr.as_ptr() as *const libc::sockaddr,
            addrlen,
        )
    }
}

/// Receive data from socket (identical to ogs_recv)
pub fn ogs_recv(fd: OgsSocket, buf: &mut [u8], flags: i32) -> isize {
    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), flags) }
}

/// Receive data with source address (identical to ogs_recvfrom)
pub fn ogs_recvfrom(fd: OgsSocket, buf: &mut [u8], flags: i32) -> (isize, Option<OgsSockaddr>) {
    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addrlen: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            flags,
            &mut addr_storage as *mut _ as *mut libc::sockaddr,
            &mut addrlen,
        )
    };

    let from = if n >= 0 {
        raw_to_sockaddr(&addr_storage, addrlen)
    } else {
        None
    };

    (n, from)
}

/// Close socket (identical to ogs_closesocket)
pub fn ogs_closesocket(fd: OgsSocket) -> i32 {
    let rv = unsafe { libc::close(fd) };

    if rv != 0 {
        return OGS_ERROR;
    }

    OGS_OK
}

/// Destroy socket (identical to ogs_sock_destroy)
pub fn ogs_sock_destroy(sock: OgsSock) {
    // Drop will handle closing the socket
    drop(sock);
}

/// Convert OgsSockaddr to raw sockaddr
fn sockaddr_to_raw(addr: &OgsSockaddr) -> ([u8; 128], libc::socklen_t) {
    let mut storage = [0u8; 128];

    match addr.addr {
        std::net::SocketAddr::V4(v4) => {
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
            let sin: libc::sockaddr_in = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd")))]
            let sin: libc::sockaddr_in = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let sin_bytes = unsafe {
                std::slice::from_raw_parts(
                    &sin as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                )
            };
            storage[..sin_bytes.len()].copy_from_slice(sin_bytes);
            (storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        std::net::SocketAddr::V6(v6) => {
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
            let sin6: libc::sockaddr_in6 = libc::sockaddr_in6 {
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd")))]
            let sin6: libc::sockaddr_in6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            let sin6_bytes = unsafe {
                std::slice::from_raw_parts(
                    &sin6 as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                )
            };
            storage[..sin6_bytes.len()].copy_from_slice(sin6_bytes);
            (storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

/// Convert raw sockaddr to OgsSockaddr
fn raw_to_sockaddr(storage: &libc::sockaddr_storage, _addrlen: libc::socklen_t) -> Option<OgsSockaddr> {
    let family = storage.ss_family as i32;

    match family {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(OgsSockaddr::from_ipv4(ip, port))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(OgsSockaddr::from_ipv6(ip, port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sock_create() {
        let sock = OgsSock::create();
        assert!(!sock.is_valid());
    }

    #[test]
    fn test_sock_socket() {
        let sock = ogs_sock_socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(sock.is_some());
        let sock = sock.unwrap();
        assert!(sock.is_valid());
    }

    #[test]
    fn test_sockaddr_conversion() {
        let addr = OgsSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let (raw, len) = sockaddr_to_raw(&addr);
        assert!(len > 0);

        let storage = unsafe { &*(raw.as_ptr() as *const libc::sockaddr_storage) };
        let recovered = raw_to_sockaddr(storage, len);
        assert!(recovered.is_some());
        let recovered = recovered.unwrap();
        assert_eq!(recovered.port(), 8080);
    }
}
