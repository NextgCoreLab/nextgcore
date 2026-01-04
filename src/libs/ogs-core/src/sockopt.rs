//! Socket options
//!
//! Exact port of lib/core/ogs-sockopt.h and ogs-sockopt.c

use crate::errno::{OGS_ERROR, OGS_OK};
use crate::socket::OgsSocket;

/// Default SCTP max number of output streams
pub const OGS_DEFAULT_SCTP_MAX_NUM_OF_OSTREAMS: u16 = 30;

/// SCTP options
#[derive(Debug, Clone)]
pub struct SctpOptions {
    pub spp_hbinterval: u32,
    pub spp_sackdelay: u32,
    pub srto_initial: u32,
    pub srto_min: u32,
    pub srto_max: u32,
    pub sinit_num_ostreams: u16,
    pub sinit_max_instreams: u16,
    pub sinit_max_attempts: u16,
    pub sinit_max_init_timeo: u16,
}

impl Default for SctpOptions {
    fn default() -> Self {
        SctpOptions {
            spp_hbinterval: 5000,      // 5 seconds
            spp_sackdelay: 200,        // 200 ms
            srto_initial: 3000,        // 3 seconds
            srto_min: 1000,            // 1 second
            srto_max: 5000,            // 5 seconds
            sinit_num_ostreams: OGS_DEFAULT_SCTP_MAX_NUM_OF_OSTREAMS,
            sinit_max_instreams: 65535,
            sinit_max_attempts: 4,
            sinit_max_init_timeo: 8000, // 8 seconds
        }
    }
}

/// Linger options
#[derive(Debug, Clone, Default)]
pub struct LingerOptions {
    pub l_onoff: bool,
    pub l_linger: i32,
}

/// Socket options structure (identical to ogs_sockopt_t)
#[derive(Debug, Clone)]
pub struct OgsSockopt {
    pub sctp: SctpOptions,
    pub sctp_nodelay: bool,
    pub tcp_nodelay: bool,
    pub so_linger: LingerOptions,
    pub so_bindtodevice: Option<String>,
}

impl Default for OgsSockopt {
    fn default() -> Self {
        OgsSockopt {
            sctp: SctpOptions::default(),
            sctp_nodelay: true,
            tcp_nodelay: true,
            so_linger: LingerOptions::default(),
            so_bindtodevice: None,
        }
    }
}

/// Initialize socket options (identical to ogs_sockopt_init)
pub fn ogs_sockopt_init() -> OgsSockopt {
    OgsSockopt::default()
}

/// Set socket to non-blocking mode (identical to ogs_nonblocking)
#[cfg(unix)]
pub fn ogs_nonblocking(fd: OgsSocket) -> i32 {
    use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};

    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return OGS_ERROR;
        }

        if (flags & O_NONBLOCK) == 0 {
            let rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            if rv != 0 {
                return OGS_ERROR;
            }
        }
    }

    OGS_OK
}

#[cfg(not(unix))]
pub fn ogs_nonblocking(_fd: OgsSocket) -> i32 {
    OGS_OK
}

/// Set close-on-exec flag (identical to ogs_closeonexec)
#[cfg(unix)]
pub fn ogs_closeonexec(fd: OgsSocket) -> i32 {
    use libc::{fcntl, F_GETFD, F_SETFD, FD_CLOEXEC};

    unsafe {
        let flags = fcntl(fd, F_GETFD);
        if flags < 0 {
            return OGS_ERROR;
        }

        if (flags & FD_CLOEXEC) == 0 {
            let rv = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
            if rv != 0 {
                return OGS_ERROR;
            }
        }
    }

    OGS_OK
}

#[cfg(not(unix))]
pub fn ogs_closeonexec(_fd: OgsSocket) -> i32 {
    OGS_OK
}

/// Set SO_REUSEADDR option (identical to ogs_listen_reusable)
#[cfg(unix)]
pub fn ogs_listen_reusable(fd: OgsSocket, on: bool) -> i32 {
    let optval: i32 = if on { 1 } else { 0 };

    let rv = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if rv != 0 {
        return OGS_ERROR;
    }

    OGS_OK
}

#[cfg(not(unix))]
pub fn ogs_listen_reusable(_fd: OgsSocket, _on: bool) -> i32 {
    OGS_OK
}

/// Set TCP_NODELAY option (identical to ogs_tcp_nodelay)
#[cfg(unix)]
pub fn ogs_tcp_nodelay(fd: OgsSocket, on: bool) -> i32 {
    let optval: i32 = if on { 1 } else { 0 };

    let rv = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if rv != 0 {
        return OGS_ERROR;
    }

    OGS_OK
}

#[cfg(not(unix))]
pub fn ogs_tcp_nodelay(_fd: OgsSocket, _on: bool) -> i32 {
    OGS_OK
}

/// Set SO_LINGER option (identical to ogs_so_linger)
#[cfg(unix)]
pub fn ogs_so_linger(fd: OgsSocket, l_linger: i32) -> i32 {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger,
    };

    let rv = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };

    if rv != 0 {
        return OGS_ERROR;
    }

    OGS_OK
}

#[cfg(not(unix))]
pub fn ogs_so_linger(_fd: OgsSocket, _l_linger: i32) -> i32 {
    OGS_OK
}

/// Bind socket to device (identical to ogs_bind_to_device)
#[cfg(target_os = "linux")]
pub fn ogs_bind_to_device(fd: OgsSocket, device: &str) -> i32 {
    use std::ffi::CString;

    let device_cstr = match CString::new(device) {
        Ok(s) => s,
        Err(_) => return OGS_ERROR,
    };

    let rv = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device_cstr.as_ptr() as *const libc::c_void,
            (device.len() + 1) as libc::socklen_t,
        )
    };

    if rv != 0 {
        return OGS_ERROR;
    }

    OGS_OK
}

#[cfg(not(target_os = "linux"))]
pub fn ogs_bind_to_device(_fd: OgsSocket, _device: &str) -> i32 {
    // SO_BINDTODEVICE is Linux-specific
    OGS_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockopt_init() {
        let opt = ogs_sockopt_init();
        assert!(opt.tcp_nodelay);
        assert!(opt.sctp_nodelay);
        assert_eq!(opt.sctp.spp_hbinterval, 5000);
    }

    #[test]
    #[cfg(unix)]
    fn test_nonblocking() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = ogs_nonblocking(fd);
        assert_eq!(rv, OGS_OK);

        unsafe { libc::close(fd) };
    }

    #[test]
    #[cfg(unix)]
    fn test_closeonexec() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = ogs_closeonexec(fd);
        assert_eq!(rv, OGS_OK);

        unsafe { libc::close(fd) };
    }

    #[test]
    #[cfg(unix)]
    fn test_listen_reusable() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = ogs_listen_reusable(fd, true);
        assert_eq!(rv, OGS_OK);

        unsafe { libc::close(fd) };
    }

    #[test]
    #[cfg(unix)]
    fn test_tcp_nodelay() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = ogs_tcp_nodelay(fd, true);
        assert_eq!(rv, OGS_OK);

        unsafe { libc::close(fd) };
    }
}
