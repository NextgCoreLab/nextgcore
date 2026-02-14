//! Socket address utilities
//!
//! Exact port of lib/core/ogs-sockaddr.h and ogs-sockaddr.c

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::errno::{OGS_ERROR, OGS_OK};

/// Address string length constant
pub const OGS_ADDRSTRLEN: usize = 46; // INET6_ADDRSTRLEN

/// Socket address structure (identical to ogs_sockaddr_t)
#[derive(Clone)]
pub struct OgsSockaddr {
    /// Address family (AF_INET or AF_INET6)
    pub family: i32,
    /// Socket address
    pub addr: SocketAddr,
    /// Hostname (if resolved from DNS)
    pub hostname: Option<String>,
    /// Next address in linked list
    pub next: Option<Box<OgsSockaddr>>,
}

impl Default for OgsSockaddr {
    fn default() -> Self {
        OgsSockaddr {
            family: libc::AF_INET,
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            hostname: None,
            next: None,
        }
    }
}

impl fmt::Display for OgsSockaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr.ip())
    }
}

impl OgsSockaddr {
    /// Create a new socket address
    pub fn new(addr: SocketAddr) -> Self {
        let family = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        OgsSockaddr {
            family,
            addr,
            hostname: None,
            next: None,
        }
    }

    /// Create from IPv4 address and port
    pub fn from_ipv4(addr: Ipv4Addr, port: u16) -> Self {
        OgsSockaddr {
            family: libc::AF_INET,
            addr: SocketAddr::V4(SocketAddrV4::new(addr, port)),
            hostname: None,
            next: None,
        }
    }

    /// Create from IPv6 address and port
    pub fn from_ipv6(addr: Ipv6Addr, port: u16) -> Self {
        OgsSockaddr {
            family: libc::AF_INET6,
            addr: SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0)),
            hostname: None,
            next: None,
        }
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Set the port number
    pub fn set_port(&mut self, port: u16) {
        self.addr.set_port(port);
    }

    /// Get the IP address
    pub fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    /// Get socket address length
    pub fn len(&self) -> usize {
        match self.family {
            libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
            libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
            _ => 0,
        }
    }

    /// Check if address is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for OgsSockaddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OgsSockaddr")
            .field("family", &self.family)
            .field("addr", &self.addr)
            .field("hostname", &self.hostname)
            .field("has_next", &self.next.is_some())
            .finish()
    }
}

/// IP subnet structure (identical to ogs_ipsubnet_t)
#[derive(Debug, Clone, Default)]
pub struct OgsIpsubnet {
    pub family: i32,
    pub sub: [u32; 4],
    pub mask: [u32; 4],
}

/// Get address info (identical to ogs_getaddrinfo)
pub fn ogs_getaddrinfo(
    family: i32,
    hostname: Option<&str>,
    port: u16,
    _flags: i32,
) -> Result<OgsSockaddr, i32> {
    let mut sa_list: Option<OgsSockaddr> = None;
    let rv = ogs_addaddrinfo(&mut sa_list, family, hostname, port, _flags);
    if rv != OGS_OK {
        return Err(rv);
    }
    sa_list.ok_or(OGS_ERROR)
}

/// Add address info to list (identical to ogs_addaddrinfo)
pub fn ogs_addaddrinfo(
    sa_list: &mut Option<OgsSockaddr>,
    family: i32,
    hostname: Option<&str>,
    port: u16,
    _flags: i32,
) -> i32 {
    use std::net::ToSocketAddrs;

    let host = hostname.unwrap_or("");
    let addr_str = if host.is_empty() {
        format!("0.0.0.0:{port}")
    } else if host.contains(':') {
        // IPv6 address
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    // Try to resolve the address
    let addrs = match addr_str.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => {
            // Try DNS resolution
            let host_with_port = format!("{host}:{port}");
            match host_with_port.to_socket_addrs() {
                Ok(addrs) => addrs,
                Err(_) => return OGS_ERROR,
            }
        }
    };

    // Collect addresses into a vector first
    let mut new_addrs: Vec<OgsSockaddr> = Vec::new();

    for addr in addrs {
        // Filter by family if specified
        let addr_family = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };

        if family != libc::AF_UNSPEC && family != addr_family {
            continue;
        }

        let mut new_addr = OgsSockaddr::new(addr);
        new_addr.set_port(port);

        // Set hostname if it's not a numeric IP
        if let Some(h) = hostname {
            if h.parse::<IpAddr>().is_err() {
                new_addr.hostname = Some(h.to_string());
            }
        }

        new_addrs.push(new_addr);
    }

    if new_addrs.is_empty() {
        return OGS_ERROR;
    }

    // Build linked list from vector
    let mut new_head: Option<OgsSockaddr> = None;
    for addr in new_addrs.into_iter().rev() {
        let mut new_addr = addr;
        new_addr.next = new_head.map(Box::new);
        new_head = Some(new_addr);
    }

    // Append to existing list or set as head
    if sa_list.is_none() {
        *sa_list = new_head;
    } else {
        // Find tail of existing list
        let mut current = sa_list.as_mut().unwrap();
        while current.next.is_some() {
            current = current.next.as_mut().unwrap();
        }
        current.next = new_head.map(Box::new);
    }

    OGS_OK
}

/// Free address info list (identical to ogs_freeaddrinfo)
/// In Rust, this is handled automatically by Drop
pub fn ogs_freeaddrinfo(_sa_list: Option<OgsSockaddr>) {
    // Rust handles memory automatically
}

/// Copy address info (identical to ogs_copyaddrinfo)
pub fn ogs_copyaddrinfo(src: &OgsSockaddr) -> OgsSockaddr {
    let mut dst = src.clone();

    // Deep copy the linked list
    let mut current_src = &src.next;
    let mut current_dst = &mut dst.next;

    while let Some(ref src_next) = current_src {
        *current_dst = Some(Box::new((**src_next).clone()));
        current_src = &src_next.next;
        current_dst = &mut current_dst.as_mut().unwrap().next;
    }

    dst
}

/// Filter address info by family (identical to ogs_filteraddrinfo)
pub fn ogs_filteraddrinfo(sa_list: &mut Option<OgsSockaddr>, family: i32) {
    // Collect matching addresses into a vector
    let mut matching: Vec<OgsSockaddr> = Vec::new();

    let mut current = sa_list.take();
    while let Some(mut addr) = current {
        let next = addr.next.take().map(|b| *b);
        if addr.family == family {
            matching.push(addr);
        }
        current = next;
    }

    // Rebuild linked list
    let mut new_head: Option<OgsSockaddr> = None;
    for addr in matching.into_iter().rev() {
        let mut new_addr = addr;
        new_addr.next = new_head.map(Box::new);
        new_head = Some(new_addr);
    }

    *sa_list = new_head;
}

/// Sort address info by family (identical to ogs_sortaddrinfo)
pub fn ogs_sortaddrinfo(sa_list: &mut Option<OgsSockaddr>, family: i32) {
    let mut preferred: Vec<OgsSockaddr> = Vec::new();
    let mut others: Vec<OgsSockaddr> = Vec::new();

    // Collect all addresses
    let mut current = sa_list.take();
    while let Some(mut addr) = current {
        let next = addr.next.take().map(|b| *b);
        if addr.family == family {
            preferred.push(addr);
        } else {
            others.push(addr);
        }
        current = next;
    }

    // Rebuild the list with preferred family first
    preferred.append(&mut others);

    // Rebuild linked list
    let mut new_head: Option<OgsSockaddr> = None;
    for addr in preferred.into_iter().rev() {
        let mut new_addr = addr;
        new_addr.next = new_head.map(Box::new);
        new_head = Some(new_addr);
    }

    *sa_list = new_head;
}

/// Convert IP address to string (identical to ogs_inet_ntop)
pub fn ogs_inet_ntop(addr: &OgsSockaddr) -> String {
    addr.addr.ip().to_string()
}

/// Parse IP address from string (identical to ogs_inet_pton)
pub fn ogs_inet_pton(family: i32, src: &str) -> Result<OgsSockaddr, i32> {
    match family {
        libc::AF_INET => {
            if let Ok(addr) = src.parse::<Ipv4Addr>() {
                Ok(OgsSockaddr::from_ipv4(addr, 0))
            } else {
                Err(OGS_ERROR)
            }
        }
        libc::AF_INET6 => {
            if let Ok(addr) = src.parse::<Ipv6Addr>() {
                Ok(OgsSockaddr::from_ipv6(addr, 0))
            } else {
                Err(OGS_ERROR)
            }
        }
        _ => Err(OGS_ERROR),
    }
}

/// Get socket address length (identical to ogs_sockaddr_len)
pub fn ogs_sockaddr_len(addr: &OgsSockaddr) -> usize {
    addr.len()
}

/// Check if two addresses are equal (identical to ogs_sockaddr_is_equal)
pub fn ogs_sockaddr_is_equal(a: &OgsSockaddr, b: &OgsSockaddr) -> bool {
    a.addr == b.addr
}

/// Check if two addresses have equal IP (identical to ogs_sockaddr_is_equal_addr)
pub fn ogs_sockaddr_is_equal_addr(a: &OgsSockaddr, b: &OgsSockaddr) -> bool {
    a.addr.ip() == b.addr.ip()
}

/// Get hostname from address (identical to ogs_gethostname)
pub fn ogs_gethostname(addr: &OgsSockaddr) -> Option<&str> {
    addr.hostname.as_deref()
}

/// Get IP string (duplicate) (identical to ogs_ipstrdup)
pub fn ogs_ipstrdup(addr: &OgsSockaddr) -> String {
    ogs_inet_ntop(addr)
}

/// Parse IP subnet (identical to ogs_ipsubnet)
pub fn ogs_ipsubnet(ipstr: &str, mask_or_numbits: Option<&str>) -> Result<OgsIpsubnet, i32> {
    let mut ipsub = OgsIpsubnet::default();

    // Check if it looks like an IP address
    if !looks_like_ip(ipstr) {
        return Err(OGS_ERROR);
    }

    // Initialize mask to all 1s (single IP)
    ipsub.mask = [0xFFFFFFFF; 4];

    // Try to parse as IPv6
    if let Ok(addr) = ipstr.parse::<Ipv6Addr>() {
        let octets = addr.octets();
        ipsub.sub[0] = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
        ipsub.sub[1] = u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]);
        ipsub.sub[2] = u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]);
        ipsub.sub[3] = u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]);
        ipsub.family = libc::AF_INET6;

        // Check for IPv4-mapped IPv6
        if addr.to_ipv4_mapped().is_some() {
            return Err(OGS_ERROR);
        }
    } else if let Ok(addr) = ipstr.parse::<Ipv4Addr>() {
        ipsub.sub[0] = u32::from_be_bytes(addr.octets());
        ipsub.family = libc::AF_INET;
    } else {
        // Try legacy network syntax (e.g., "192.168.1.")
        parse_network(&mut ipsub, ipstr)?;
    }

    // Parse mask if provided
    if let Some(mask) = mask_or_numbits {
        let maxbits = if ipsub.family == libc::AF_INET6 { 128 } else { 32 };

        if let Ok(bits) = mask.parse::<u32>() {
            if bits > 0 && bits <= maxbits {
                // Fill in mask based on number of bits
                ipsub.mask = [0; 4];
                let mut remaining_bits = bits;
                let mut cur_entry = 0;

                while remaining_bits > 32 {
                    ipsub.mask[cur_entry] = 0xFFFFFFFF;
                    remaining_bits -= 32;
                    cur_entry += 1;
                }

                if remaining_bits > 0 {
                    ipsub.mask[cur_entry] = !((1u32 << (32 - remaining_bits)) - 1);
                }
            } else {
                return Err(OGS_ERROR);
            }
        } else if ipsub.family == libc::AF_INET {
            // Try to parse as IPv4 netmask
            if let Ok(mask_addr) = mask.parse::<Ipv4Addr>() {
                ipsub.mask[0] = u32::from_be_bytes(mask_addr.octets());
            } else {
                return Err(OGS_ERROR);
            }
        } else {
            return Err(OGS_ERROR);
        }
    }

    // Apply mask to subnet
    for i in 0..4 {
        ipsub.sub[i] &= ipsub.mask[i];
    }

    Ok(ipsub)
}

/// Check if string looks like an IP address
fn looks_like_ip(ipstr: &str) -> bool {
    if ipstr.is_empty() {
        return false;
    }

    // Contains colon = likely IPv6
    if ipstr.contains(':') {
        return true;
    }

    // Check for IPv4 pattern (digits and dots only)
    ipstr.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Parse legacy network syntax
fn parse_network(ipsub: &mut OgsIpsubnet, network: &str) -> Result<(), i32> {
    let parts: Vec<&str> = network.split('.').collect();

    if parts.is_empty() || parts.len() > 4 {
        return Err(OGS_ERROR);
    }

    ipsub.sub[0] = 0;
    ipsub.mask[0] = 0;
    let mut shift = 24i32;

    for part in parts {
        if part.is_empty() {
            continue;
        }

        if shift < 0 {
            return Err(OGS_ERROR);
        }

        let octet: u32 = part.parse().map_err(|_| OGS_ERROR)?;
        if octet > 255 {
            return Err(OGS_ERROR);
        }

        ipsub.sub[0] |= octet << shift;
        ipsub.mask[0] |= 0xFF << shift;
        shift -= 8;
    }

    ipsub.family = libc::AF_INET;
    Ok(())
}

/// Convert sockaddr list to string (identical to ogs_sockaddr_to_string_static)
pub fn ogs_sockaddr_to_string(sa_list: &OgsSockaddr) -> String {
    let mut result = String::new();
    let mut current = Some(sa_list);

    while let Some(addr) = current {
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(&format!("[{}]:{}", addr.addr.ip(), addr.addr.port()));
        current = addr.next.as_ref().map(|b| b.as_ref());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockaddr_new() {
        let addr = OgsSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        assert_eq!(addr.family, libc::AF_INET);
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_sockaddr_ipv6() {
        let addr = OgsSockaddr::from_ipv6(Ipv6Addr::LOCALHOST, 8080);
        assert_eq!(addr.family, libc::AF_INET6);
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_inet_ntop() {
        let addr = OgsSockaddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 0);
        assert_eq!(ogs_inet_ntop(&addr), "192.168.1.1");
    }

    #[test]
    fn test_inet_pton() {
        let addr = ogs_inet_pton(libc::AF_INET, "192.168.1.1").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        let addr = ogs_inet_pton(libc::AF_INET6, "::1").unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_sockaddr_is_equal() {
        let addr1 = OgsSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let addr2 = OgsSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let addr3 = OgsSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 9090);

        assert!(ogs_sockaddr_is_equal(&addr1, &addr2));
        assert!(!ogs_sockaddr_is_equal(&addr1, &addr3));
        assert!(ogs_sockaddr_is_equal_addr(&addr1, &addr3));
    }

    #[test]
    fn test_ipsubnet() {
        let ipsub = ogs_ipsubnet("192.168.1.0", Some("24")).unwrap();
        assert_eq!(ipsub.family, libc::AF_INET);

        let ipsub = ogs_ipsubnet("10.0.0.1", None).unwrap();
        assert_eq!(ipsub.family, libc::AF_INET);
    }
}
