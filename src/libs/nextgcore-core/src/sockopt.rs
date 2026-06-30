//! Socket options
//!
//! Exact port of lib/core/nextgcore-sockopt.h and nextgcore-sockopt.c

use crate::errno::{NEXTGCORE_ERROR, NEXTGCORE_OK};
use crate::socket::NextgcoreSocket;

/// Default SCTP max number of output streams
pub const NEXTGCORE_DEFAULT_SCTP_MAX_NUM_OF_OSTREAMS: u16 = 30;

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
            spp_hbinterval: 5000, // 5 seconds
            spp_sackdelay: 200,   // 200 ms
            srto_initial: 3000,   // 3 seconds
            srto_min: 1000,       // 1 second
            srto_max: 5000,       // 5 seconds
            sinit_num_ostreams: NEXTGCORE_DEFAULT_SCTP_MAX_NUM_OF_OSTREAMS,
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

/// Socket options structure (identical to nextgcore_sockopt_t)
#[derive(Debug, Clone)]
pub struct NextgcoreSockopt {
    pub sctp: SctpOptions,
    pub sctp_nodelay: bool,
    pub tcp_nodelay: bool,
    pub so_linger: LingerOptions,
    pub so_bindtodevice: Option<String>,
}

impl Default for NextgcoreSockopt {
    fn default() -> Self {
        NextgcoreSockopt {
            sctp: SctpOptions::default(),
            sctp_nodelay: true,
            tcp_nodelay: true,
            so_linger: LingerOptions::default(),
            so_bindtodevice: None,
        }
    }
}

/// Initialize socket options (identical to nextgcore_sockopt_init)
pub fn nextgcore_sockopt_init() -> NextgcoreSockopt {
    NextgcoreSockopt::default()
}

/// Set socket to non-blocking mode (identical to nextgcore_nonblocking)
#[cfg(unix)]
pub fn nextgcore_nonblocking(fd: NextgcoreSocket) -> i32 {
    use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};

    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return NEXTGCORE_ERROR;
        }

        if (flags & O_NONBLOCK) == 0 {
            let rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            if rv != 0 {
                return NEXTGCORE_ERROR;
            }
        }
    }

    NEXTGCORE_OK
}

#[cfg(not(unix))]
pub fn nextgcore_nonblocking(_fd: NextgcoreSocket) -> i32 {
    NEXTGCORE_OK
}

/// Set close-on-exec flag (identical to nextgcore_closeonexec)
#[cfg(unix)]
pub fn nextgcore_closeonexec(fd: NextgcoreSocket) -> i32 {
    use libc::{fcntl, FD_CLOEXEC, F_GETFD, F_SETFD};

    unsafe {
        let flags = fcntl(fd, F_GETFD);
        if flags < 0 {
            return NEXTGCORE_ERROR;
        }

        if (flags & FD_CLOEXEC) == 0 {
            let rv = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
            if rv != 0 {
                return NEXTGCORE_ERROR;
            }
        }
    }

    NEXTGCORE_OK
}

#[cfg(not(unix))]
pub fn nextgcore_closeonexec(_fd: NextgcoreSocket) -> i32 {
    NEXTGCORE_OK
}

/// Set SO_REUSEADDR option (identical to nextgcore_listen_reusable)
#[cfg(unix)]
pub fn nextgcore_listen_reusable(fd: NextgcoreSocket, on: bool) -> i32 {
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
        return NEXTGCORE_ERROR;
    }

    NEXTGCORE_OK
}

#[cfg(not(unix))]
pub fn nextgcore_listen_reusable(_fd: NextgcoreSocket, _on: bool) -> i32 {
    NEXTGCORE_OK
}

/// Set TCP_NODELAY option (identical to nextgcore_tcp_nodelay)
#[cfg(unix)]
pub fn nextgcore_tcp_nodelay(fd: NextgcoreSocket, on: bool) -> i32 {
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
        return NEXTGCORE_ERROR;
    }

    NEXTGCORE_OK
}

#[cfg(not(unix))]
pub fn nextgcore_tcp_nodelay(_fd: NextgcoreSocket, _on: bool) -> i32 {
    NEXTGCORE_OK
}

/// Set SO_LINGER option (identical to nextgcore_so_linger)
#[cfg(unix)]
pub fn nextgcore_so_linger(fd: NextgcoreSocket, l_linger: i32) -> i32 {
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
        return NEXTGCORE_ERROR;
    }

    NEXTGCORE_OK
}

#[cfg(not(unix))]
pub fn nextgcore_so_linger(_fd: NextgcoreSocket, _l_linger: i32) -> i32 {
    NEXTGCORE_OK
}

/// Bind socket to device (identical to nextgcore_bind_to_device)
#[cfg(target_os = "linux")]
pub fn nextgcore_bind_to_device(fd: NextgcoreSocket, device: &str) -> i32 {
    use std::ffi::CString;

    let device_cstr = match CString::new(device) {
        Ok(s) => s,
        Err(_) => return NEXTGCORE_ERROR,
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
        return NEXTGCORE_ERROR;
    }

    NEXTGCORE_OK
}

#[cfg(not(target_os = "linux"))]
pub fn nextgcore_bind_to_device(_fd: NextgcoreSocket, _device: &str) -> i32 {
    // SO_BINDTODEVICE is Linux-specific
    NEXTGCORE_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockopt_init() {
        let opt = nextgcore_sockopt_init();
        assert!(opt.tcp_nodelay);
        assert!(opt.sctp_nodelay);
        assert_eq!(opt.sctp.spp_hbinterval, 5000);
    }

    #[test]
    #[cfg(unix)]
    fn test_nonblocking() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = nextgcore_nonblocking(fd);
        assert_eq!(rv, NEXTGCORE_OK);

        unsafe { libc::close(fd) };
    }

    #[test]
    #[cfg(unix)]
    fn test_closeonexec() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = nextgcore_closeonexec(fd);
        assert_eq!(rv, NEXTGCORE_OK);

        unsafe { libc::close(fd) };
    }

    #[test]
    #[cfg(unix)]
    fn test_listen_reusable() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = nextgcore_listen_reusable(fd, true);
        assert_eq!(rv, NEXTGCORE_OK);

        unsafe { libc::close(fd) };
    }

    #[test]
    #[cfg(unix)]
    fn test_tcp_nodelay() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let rv = nextgcore_tcp_nodelay(fd, true);
        assert_eq!(rv, NEXTGCORE_OK);

        unsafe { libc::close(fd) };
    }
}
