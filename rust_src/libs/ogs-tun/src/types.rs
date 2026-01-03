//! TUN interface types and error definitions

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

/// TUN device handle
#[derive(Debug)]
pub struct TunDevice {
    /// File descriptor for the TUN device
    pub fd: i32,
    /// Interface name
    pub ifname: String,
    /// Whether this is a TAP device (layer 2) vs TUN (layer 3)
    pub is_tap: bool,
}

impl TunDevice {
    /// Create a new TUN device handle
    pub fn new(fd: i32, ifname: String, is_tap: bool) -> Self {
        Self { fd, ifname, is_tap }
    }

    /// Get the file descriptor
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Get the interface name
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Check if this is a TAP device
    pub fn is_tap(&self) -> bool {
        self.is_tap
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// IP subnet configuration for TUN interface
#[derive(Debug, Clone)]
pub struct IpSubnet {
    /// Address family (AF_INET or AF_INET6)
    pub family: i32,
    /// Subnet address (up to 4 u32 for IPv6)
    pub sub: [u32; 4],
    /// Subnet mask
    pub mask: [u32; 4],
}

impl IpSubnet {
    /// Create a new IPv4 subnet
    pub fn new_ipv4(addr: Ipv4Addr, prefix_len: u8) -> Self {
        let addr_u32 = u32::from(addr);
        let mask = if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        
        Self {
            family: libc::AF_INET,
            sub: [addr_u32.to_be(), 0, 0, 0],
            mask: [mask.to_be(), 0, 0, 0],
        }
    }

    /// Create a new IPv6 subnet
    pub fn new_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Self {
        let octets = addr.octets();
        let mut sub = [0u32; 4];
        let mut mask = [0u32; 4];

        // Convert octets to u32 array
        for i in 0..4 {
            sub[i] = u32::from_be_bytes([
                octets[i * 4],
                octets[i * 4 + 1],
                octets[i * 4 + 2],
                octets[i * 4 + 3],
            ]);
        }

        // Calculate mask
        let mut remaining = prefix_len as i32;
        for i in 0..4 {
            if remaining >= 32 {
                mask[i] = 0xFFFFFFFF;
                remaining -= 32;
            } else if remaining > 0 {
                mask[i] = !((1u32 << (32 - remaining)) - 1);
                remaining = 0;
            } else {
                mask[i] = 0;
            }
        }

        Self {
            family: libc::AF_INET6,
            sub,
            mask,
        }
    }

    /// Check if this is an IPv4 subnet
    pub fn is_ipv4(&self) -> bool {
        self.family == libc::AF_INET
    }

    /// Check if this is an IPv6 subnet
    pub fn is_ipv6(&self) -> bool {
        self.family == libc::AF_INET6
    }
}

/// TUN operation errors
#[derive(Debug)]
pub enum TunError {
    /// Device not found
    DeviceNotFound,
    /// Permission denied
    PermissionDenied,
    /// Device busy
    DeviceBusy,
    /// Invalid interface name
    InvalidIfname,
    /// I/O error
    IoError(String),
    /// System call error
    SyscallError(i32, String),
    /// Invalid packet
    InvalidPacket(String),
    /// Not supported on this platform
    NotSupported,
}

impl fmt::Display for TunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunError::DeviceNotFound => write!(f, "TUN device not found"),
            TunError::PermissionDenied => write!(f, "Permission denied"),
            TunError::DeviceBusy => write!(f, "Device busy"),
            TunError::InvalidIfname => write!(f, "Invalid interface name"),
            TunError::IoError(msg) => write!(f, "I/O error: {}", msg),
            TunError::SyscallError(errno, msg) => {
                write!(f, "System call error ({}): {}", errno, msg)
            }
            TunError::InvalidPacket(msg) => write!(f, "Invalid packet: {}", msg),
            TunError::NotSupported => write!(f, "Not supported on this platform"),
        }
    }
}

impl std::error::Error for TunError {}

impl From<io::Error> for TunError {
    fn from(err: io::Error) -> Self {
        TunError::IoError(err.to_string())
    }
}

/// Result type for TUN operations
pub type TunResult<T> = Result<T, TunError>;
