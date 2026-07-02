//! IPFW types and structures

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Maximum number of packet filter components
pub const MAX_NUM_OF_PACKET_FILTER_COMPONENT: usize = 16;

/// IPv4 address length in bytes
pub const IPV4_LEN: usize = 4;

/// IPv6 address length in bytes
pub const IPV6_LEN: usize = 16;

/// IPv4 bit length
pub const IPV4_BITLEN: usize = 32;

/// IPv6 bit length
pub const IPV6_BITLEN: usize = 128;

/// IP address with mask (supports both IPv4 and IPv6)
#[derive(Debug, Clone, Default)]
pub struct IpAddrMask {
    /// Address (up to 4 u32 for IPv6)
    pub addr: [u32; 4],
    /// Mask
    pub mask: [u32; 4],
}

impl IpAddrMask {
    /// Create from IPv4 address and prefix length
    pub fn from_ipv4(addr: Ipv4Addr, prefix_len: u8) -> Self {
        let addr_u32 = u32::from(addr);
        let mask = if prefix_len >= 32 {
            0xFFFFFFFF
        } else if prefix_len == 0 {
            0
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };

        Self {
            addr: [addr_u32, 0, 0, 0],
            mask: [mask, 0, 0, 0],
        }
    }

    /// Create from IPv6 address and prefix length
    pub fn from_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Self {
        let segments = addr.segments();
        let mut addr_arr = [0u32; 4];
        let mut mask_arr = [0u32; 4];

        // Convert segments to u32 array
        for i in 0..4 {
            addr_arr[i] = ((segments[i * 2] as u32) << 16) | (segments[i * 2 + 1] as u32);
        }

        // Calculate mask
        let mut remaining = prefix_len as i32;
        for i in 0..4 {
            if remaining >= 32 {
                mask_arr[i] = 0xFFFFFFFF;
                remaining -= 32;
            } else if remaining > 0 {
                mask_arr[i] = !((1u32 << (32 - remaining)) - 1);
                remaining = 0;
            }
        }

        Self {
            addr: addr_arr,
            mask: mask_arr,
        }
    }
}

/// Port range
#[derive(Debug, Clone, Default)]
pub struct PortRange {
    pub low: u16,
    pub high: u16,
}

impl PortRange {
    /// Create a single port
    pub fn single(port: u16) -> Self {
        Self {
            low: port,
            high: port,
        }
    }

    /// Create a port range
    pub fn range(low: u16, high: u16) -> Self {
        Self { low, high }
    }

    /// Check if this is a single port
    pub fn is_single(&self) -> bool {
        self.low == self.high
    }

    /// Check if this is empty (no port specified)
    pub fn is_empty(&self) -> bool {
        self.low == 0 && self.high == 0
    }
}

/// IP addresses for source and destination
#[derive(Debug, Clone, Default)]
pub struct IpAddresses {
    pub src: IpAddrMask,
    pub dst: IpAddrMask,
}

/// Port ranges for source and destination
#[derive(Debug, Clone, Default)]
pub struct PortRanges {
    pub src: PortRange,
    pub dst: PortRange,
}

/// IPFW rule structure
#[derive(Debug, Clone, Default)]
pub struct IpfwRule {
    /// Protocol number (0 = any, 6 = TCP, 17 = UDP, etc.)
    pub proto: u8,

    /// IPv4 source address present
    pub ipv4_src: bool,
    /// IPv4 destination address present
    pub ipv4_dst: bool,
    /// IPv6 source address present
    pub ipv6_src: bool,
    /// IPv6 destination address present
    pub ipv6_dst: bool,

    /// IP addresses
    pub ip: IpAddresses,
    /// Port ranges
    pub port: PortRanges,

    /// ToS/Traffic Class
    pub tos_traffic_class: u16,
    /// Security Parameter Index
    pub security_parameter_index: u32,
    /// Flow Label (24 bits)
    pub flow_label: u32,
    /// SDF Filter ID
    pub sdf_filter_id: u32,
}

impl IpfwRule {
    /// Create a new empty rule
    pub fn new() -> Self {
        Self::default()
    }

    /// Swap source and destination
    pub fn swap(&mut self) {
        std::mem::swap(&mut self.ipv4_src, &mut self.ipv4_dst);
        std::mem::swap(&mut self.ipv6_src, &mut self.ipv6_dst);
        std::mem::swap(&mut self.ip.src, &mut self.ip.dst);
        std::mem::swap(&mut self.port.src, &mut self.port.dst);
    }

    /// Copy and swap source/destination
    pub fn copy_and_swap(&self) -> Self {
        let mut dst = self.clone();
        dst.swap();
        dst
    }
}

/// IPFW error types
#[derive(Debug)]
pub enum IpfwError {
    /// Invalid flow description syntax
    InvalidSyntax(String),
    /// Missing required keyword
    MissingKeyword(String),
    /// Invalid IP address
    InvalidAddress(String),
    /// Invalid port
    InvalidPort(String),
    /// Invalid protocol
    InvalidProtocol(String),
}

impl fmt::Display for IpfwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpfwError::InvalidSyntax(msg) => write!(f, "Invalid syntax: {msg}"),
            IpfwError::MissingKeyword(kw) => write!(f, "Missing keyword: {kw}"),
            IpfwError::InvalidAddress(addr) => write!(f, "Invalid address: {addr}"),
            IpfwError::InvalidPort(port) => write!(f, "Invalid port: {port}"),
            IpfwError::InvalidProtocol(proto) => write!(f, "Invalid protocol: {proto}"),
        }
    }
}

impl std::error::Error for IpfwError {}

/// Result type for IPFW operations
pub type IpfwResult<T> = Result<T, IpfwError>;
