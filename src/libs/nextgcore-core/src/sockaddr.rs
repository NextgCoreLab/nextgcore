//! Socket address utilities
//!
//! Exact port of lib/core/nextgcore-sockaddr.h and nextgcore-sockaddr.c

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::errno::{NEXTGCORE_ERROR, NEXTGCORE_OK};

/// Address string length constant
pub const NEXTGCORE_ADDRSTRLEN: usize = 46; // INET6_ADDRSTRLEN

/// Socket address structure (identical to nextgcore_sockaddr_t)
#[derive(Clone)]
pub struct NextgcoreSockaddr {
    /// Address family (AF_INET or AF_INET6)
    pub family: i32,
    /// Socket address
    pub addr: SocketAddr,
    /// Hostname (if resolved from DNS)
    pub hostname: Option<String>,
    /// Next address in linked list
    pub next: Option<Box<NextgcoreSockaddr>>,
}

impl Default for NextgcoreSockaddr {
    fn default() -> Self {
        NextgcoreSockaddr {
            family: libc::AF_INET,
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            hostname: None,
            next: None,
        }
    }
}

impl fmt::Display for NextgcoreSockaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr.ip())
    }
}

impl NextgcoreSockaddr {
    /// Create a new socket address
    pub fn new(addr: SocketAddr) -> Self {
        let family = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        NextgcoreSockaddr {
            family,
            addr,
            hostname: None,
            next: None,
        }
    }

    /// Create from IPv4 address and port
    pub fn from_ipv4(addr: Ipv4Addr, port: u16) -> Self {
        NextgcoreSockaddr {
            family: libc::AF_INET,
            addr: SocketAddr::V4(SocketAddrV4::new(addr, port)),
            hostname: None,
            next: None,
        }
    }

    /// Create from IPv6 address and port
    pub fn from_ipv6(addr: Ipv6Addr, port: u16) -> Self {
        NextgcoreSockaddr {
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

impl std::fmt::Debug for NextgcoreSockaddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NextgcoreSockaddr")
            .field("family", &self.family)
            .field("addr", &self.addr)
            .field("hostname", &self.hostname)
            .field("has_next", &self.next.is_some())
            .finish()
    }
}

/// IP subnet structure (identical to nextgcore_ipsubnet_t)
#[derive(Debug, Clone, Default)]
pub struct NextgcoreIpsubnet {
    pub family: i32,
    pub sub: [u32; 4],
    pub mask: [u32; 4],
}

/// Get address info (identical to nextgcore_getaddrinfo)
pub fn nextgcore_getaddrinfo(
    family: i32,
    hostname: Option<&str>,
    port: u16,
    _flags: i32,
) -> Result<NextgcoreSockaddr, i32> {
    let mut sa_list: Option<NextgcoreSockaddr> = None;
    let rv = nextgcore_addaddrinfo(&mut sa_list, family, hostname, port, _flags);
    if rv != NEXTGCORE_OK {
        return Err(rv);
    }
    sa_list.ok_or(NEXTGCORE_ERROR)
}

/// Add address info to list (identical to nextgcore_addaddrinfo)
pub fn nextgcore_addaddrinfo(
    sa_list: &mut Option<NextgcoreSockaddr>,
    family: i32,
    hostname: Option<&str>,
    port: u16,
    _flags: i32,
) -> i32 {
    use std::net::ToSocketAddrs;

    let host = hostname.unwrap_or("");
    // No host is loopback, never the wildcard (#1308): a caller that wants every
    // interface names `0.0.0.0` itself.
    let addr_str = if host.is_empty() {
        format!("{DEFAULT_LISTEN_HOST}:{port}")
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
                Err(_) => return NEXTGCORE_ERROR,
            }
        }
    };

    // Collect addresses into a vector first
    let mut new_addrs: Vec<NextgcoreSockaddr> = Vec::new();

    for addr in addrs {
        // Filter by family if specified
        let addr_family = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };

        if family != libc::AF_UNSPEC && family != addr_family {
            continue;
        }

        let mut new_addr = NextgcoreSockaddr::new(addr);
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
        return NEXTGCORE_ERROR;
    }

    // Build linked list from vector
    let mut new_head: Option<NextgcoreSockaddr> = None;
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
        let mut current = sa_list.as_mut().expect("sa_list was Some");
        while current.next.is_some() {
            current = current.next.as_mut().expect("next was Some");
        }
        current.next = new_head.map(Box::new);
    }

    NEXTGCORE_OK
}

/// Free address info list (identical to nextgcore_freeaddrinfo)
/// In Rust, this is handled automatically by Drop
pub fn nextgcore_freeaddrinfo(_sa_list: Option<NextgcoreSockaddr>) {
    // Rust handles memory automatically
}

/// Copy address info (identical to nextgcore_copyaddrinfo)
pub fn nextgcore_copyaddrinfo(src: &NextgcoreSockaddr) -> NextgcoreSockaddr {
    let mut dst = src.clone();

    // Deep copy the linked list
    let mut current_src = &src.next;
    let mut current_dst = &mut dst.next;

    while let Some(ref src_next) = current_src {
        *current_dst = Some(Box::new((**src_next).clone()));
        current_src = &src_next.next;
        current_dst = &mut current_dst.as_mut().expect("dst was set").next;
    }

    dst
}

/// Filter address info by family (identical to nextgcore_filteraddrinfo)
pub fn nextgcore_filteraddrinfo(sa_list: &mut Option<NextgcoreSockaddr>, family: i32) {
    // Collect matching addresses into a vector
    let mut matching: Vec<NextgcoreSockaddr> = Vec::new();

    let mut current = sa_list.take();
    while let Some(mut addr) = current {
        let next = addr.next.take().map(|b| *b);
        if addr.family == family {
            matching.push(addr);
        }
        current = next;
    }

    // Rebuild linked list
    let mut new_head: Option<NextgcoreSockaddr> = None;
    for addr in matching.into_iter().rev() {
        let mut new_addr = addr;
        new_addr.next = new_head.map(Box::new);
        new_head = Some(new_addr);
    }

    *sa_list = new_head;
}

/// Sort address info by family (identical to nextgcore_sortaddrinfo)
pub fn nextgcore_sortaddrinfo(sa_list: &mut Option<NextgcoreSockaddr>, family: i32) {
    let mut preferred: Vec<NextgcoreSockaddr> = Vec::new();
    let mut others: Vec<NextgcoreSockaddr> = Vec::new();

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
    let mut new_head: Option<NextgcoreSockaddr> = None;
    for addr in preferred.into_iter().rev() {
        let mut new_addr = addr;
        new_addr.next = new_head.map(Box::new);
        new_head = Some(new_addr);
    }

    *sa_list = new_head;
}

/// Convert IP address to string (identical to nextgcore_inet_ntop)
pub fn nextgcore_inet_ntop(addr: &NextgcoreSockaddr) -> String {
    addr.addr.ip().to_string()
}

/// Parse IP address from string (identical to nextgcore_inet_pton)
pub fn nextgcore_inet_pton(family: i32, src: &str) -> Result<NextgcoreSockaddr, i32> {
    match family {
        libc::AF_INET => {
            if let Ok(addr) = src.parse::<Ipv4Addr>() {
                Ok(NextgcoreSockaddr::from_ipv4(addr, 0))
            } else {
                Err(NEXTGCORE_ERROR)
            }
        }
        libc::AF_INET6 => {
            if let Ok(addr) = src.parse::<Ipv6Addr>() {
                Ok(NextgcoreSockaddr::from_ipv6(addr, 0))
            } else {
                Err(NEXTGCORE_ERROR)
            }
        }
        _ => Err(NEXTGCORE_ERROR),
    }
}

/// Get socket address length (identical to nextgcore_sockaddr_len)
pub fn nextgcore_sockaddr_len(addr: &NextgcoreSockaddr) -> usize {
    addr.len()
}

/// Check if two addresses are equal (identical to nextgcore_sockaddr_is_equal)
pub fn nextgcore_sockaddr_is_equal(a: &NextgcoreSockaddr, b: &NextgcoreSockaddr) -> bool {
    a.addr == b.addr
}

/// Check if two addresses have equal IP (identical to nextgcore_sockaddr_is_equal_addr)
pub fn nextgcore_sockaddr_is_equal_addr(a: &NextgcoreSockaddr, b: &NextgcoreSockaddr) -> bool {
    a.addr.ip() == b.addr.ip()
}

/// Get hostname from address (identical to nextgcore_gethostname)
pub fn nextgcore_gethostname(addr: &NextgcoreSockaddr) -> Option<&str> {
    addr.hostname.as_deref()
}

/// Get IP string (duplicate) (identical to nextgcore_ipstrdup)
pub fn nextgcore_ipstrdup(addr: &NextgcoreSockaddr) -> String {
    nextgcore_inet_ntop(addr)
}

/// Parse IP subnet (identical to nextgcore_ipsubnet)
pub fn nextgcore_ipsubnet(
    ipstr: &str,
    mask_or_numbits: Option<&str>,
) -> Result<NextgcoreIpsubnet, i32> {
    let mut ipsub = NextgcoreIpsubnet::default();

    // Check if it looks like an IP address
    if !looks_like_ip(ipstr) {
        return Err(NEXTGCORE_ERROR);
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
            return Err(NEXTGCORE_ERROR);
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
        let maxbits = if ipsub.family == libc::AF_INET6 {
            128
        } else {
            32
        };

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
                return Err(NEXTGCORE_ERROR);
            }
        } else if ipsub.family == libc::AF_INET {
            // Try to parse as IPv4 netmask
            if let Ok(mask_addr) = mask.parse::<Ipv4Addr>() {
                ipsub.mask[0] = u32::from_be_bytes(mask_addr.octets());
            } else {
                return Err(NEXTGCORE_ERROR);
            }
        } else {
            return Err(NEXTGCORE_ERROR);
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
fn parse_network(ipsub: &mut NextgcoreIpsubnet, network: &str) -> Result<(), i32> {
    let parts: Vec<&str> = network.split('.').collect();

    if parts.is_empty() || parts.len() > 4 {
        return Err(NEXTGCORE_ERROR);
    }

    ipsub.sub[0] = 0;
    ipsub.mask[0] = 0;
    let mut shift = 24i32;

    for part in parts {
        if part.is_empty() {
            continue;
        }

        if shift < 0 {
            return Err(NEXTGCORE_ERROR);
        }

        let octet: u32 = part.parse().map_err(|_| NEXTGCORE_ERROR)?;
        if octet > 255 {
            return Err(NEXTGCORE_ERROR);
        }

        ipsub.sub[0] |= octet << shift;
        ipsub.mask[0] |= 0xFF << shift;
        shift -= 8;
    }

    ipsub.family = libc::AF_INET;
    Ok(())
}

/// Convert sockaddr list to string (identical to nextgcore_sockaddr_to_string_static)
pub fn nextgcore_sockaddr_to_string(sa_list: &NextgcoreSockaddr) -> String {
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
        let addr = NextgcoreSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        assert_eq!(addr.family, libc::AF_INET);
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_sockaddr_ipv6() {
        let addr = NextgcoreSockaddr::from_ipv6(Ipv6Addr::LOCALHOST, 8080);
        assert_eq!(addr.family, libc::AF_INET6);
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_inet_ntop() {
        let addr = NextgcoreSockaddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 0);
        assert_eq!(nextgcore_inet_ntop(&addr), "192.168.1.1");
    }

    #[test]
    fn test_inet_pton() {
        let addr = nextgcore_inet_pton(libc::AF_INET, "192.168.1.1").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        let addr = nextgcore_inet_pton(libc::AF_INET6, "::1").unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_sockaddr_is_equal() {
        let addr1 = NextgcoreSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let addr2 = NextgcoreSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let addr3 = NextgcoreSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 9090);

        assert!(nextgcore_sockaddr_is_equal(&addr1, &addr2));
        assert!(!nextgcore_sockaddr_is_equal(&addr1, &addr3));
        assert!(nextgcore_sockaddr_is_equal_addr(&addr1, &addr3));
    }

    #[test]
    fn test_ipsubnet() {
        let ipsub = nextgcore_ipsubnet("192.168.1.0", Some("24")).unwrap();
        assert_eq!(ipsub.family, libc::AF_INET);

        let ipsub = nextgcore_ipsubnet("10.0.0.1", None).unwrap();
        assert_eq!(ipsub.family, libc::AF_INET);
    }
}

/// The host every nextgcore listener binds when its address is not configured
/// (#1308): loopback, so a daemon started with its defaults on a bare-metal host
/// is reachable from that host only. A deployment whose peers are on other hosts
/// names the address it listens on (a container or pod's own network, or a
/// private interface of the host).
pub const DEFAULT_LISTEN_HOST: &str = "127.0.0.1";

/// The first `<section>.<iface>.server[]` entry of the YAML config `text`:
/// its `address` and `port`, each `None` when absent (#1312). YAML that does not
/// parse is an error: a typo must not fall back silently to loopback (#1313
/// review).
pub fn yaml_listen_server(
    text: &str,
    section: &str,
    iface: &str,
) -> Result<(Option<String>, Option<u16>), ListenAddrError> {
    let doc = serde_yaml::from_str::<serde_yaml::Value>(text)
        .map_err(|e| ListenAddrError(format!("config does not parse as YAML: {e}")))?;
    let entry = &doc[section][iface]["server"][0];
    let address = entry["address"].as_str().map(str::to_string);
    let port = entry["port"].as_u64().and_then(|p| u16::try_from(p).ok());
    Ok((address, port))
}

/// A listener's host and port (#1312, as #1311): the command line, else the
/// config file's `<section>.<iface>.server[0]`, else [`DEFAULT_LISTEN_HOST`] and
/// `default_port` (#1308: no default is widened). Each field on its own.
///
/// A config file that does not exist is no config. One that cannot be read, or
/// does not parse, is an error for the caller to fail startup with.
pub fn resolve_listen(
    cli_host: Option<&str>,
    cli_port: Option<u16>,
    config_path: &str,
    section: &str,
    iface: &str,
    default_port: u16,
) -> Result<(String, u16), ListenAddrError> {
    let (yaml_host, yaml_port) = match std::fs::read_to_string(config_path) {
        Ok(text) => yaml_listen_server(&text, section, iface)
            .map_err(|e| ListenAddrError(format!("{config_path}: {}", e.0)))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(e) => return Err(ListenAddrError(format!("{config_path}: {e}"))),
    };
    let host = cli_host
        .map(str::to_string)
        .or(yaml_host)
        .unwrap_or_else(|| DEFAULT_LISTEN_HOST.to_string());
    Ok((host, cli_port.or(yaml_port).unwrap_or(default_port)))
}

/// The environment variable naming the SBI host an NF advertises: in its NRF
/// NFProfile and its callback URIs (#1312). `--sbi-advertise` wins over it.
pub const SBI_ADVERTISE_ENV: &str = "NEXTGCORE_SBI_ADVERTISE";

/// Whether `host` is an unspecified address (`0.0.0.0`, `::`): bindable, but no
/// peer can reach it, so it is never advertised.
pub fn is_wildcard_host(host: &str) -> bool {
    parse_listen_addr(host, 0).is_ok_and(|a| a.ip().is_unspecified())
}

/// An SBI listener and what it advertises (#1312).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbiEndpoint {
    /// The host the server binds.
    pub host: String,
    /// The port it binds, and advertises.
    pub port: u16,
    /// The host it registers with the NRF and puts in its callback URIs. `None`
    /// when the only candidate was a wildcard: nothing reachable to advertise.
    pub advertise: Option<String>,
}

impl SbiEndpoint {
    /// Resolve, field by field:
    /// - bind host and port: the command line, else the YAML `server[0]`, else
    ///   [`DEFAULT_LISTEN_HOST`] / `default_port` (#1308, #1311);
    /// - advertise: `--sbi-advertise`, else [`SBI_ADVERTISE_ENV`], else the YAML
    ///   `advertise`, else the bind host. A wildcard is skipped at every step.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        cli_host: Option<&str>,
        cli_port: Option<u16>,
        cli_advertise: Option<&str>,
        yaml_host: Option<&str>,
        yaml_port: Option<u16>,
        yaml_advertise: Option<&str>,
        default_port: u16,
    ) -> Self {
        let env = std::env::var(SBI_ADVERTISE_ENV).ok();
        Self::resolve_with_env(
            cli_host,
            cli_port,
            cli_advertise,
            env.as_deref(),
            yaml_host,
            yaml_port,
            yaml_advertise,
            default_port,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_with_env(
        cli_host: Option<&str>,
        cli_port: Option<u16>,
        cli_advertise: Option<&str>,
        env_advertise: Option<&str>,
        yaml_host: Option<&str>,
        yaml_port: Option<u16>,
        yaml_advertise: Option<&str>,
        default_port: u16,
    ) -> Self {
        let host = cli_host
            .or(yaml_host)
            .unwrap_or(DEFAULT_LISTEN_HOST)
            .to_string();
        let port = cli_port.or(yaml_port).unwrap_or(default_port);
        let advertise = [
            cli_advertise,
            env_advertise,
            yaml_advertise,
            Some(host.as_str()),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|h| !h.is_empty() && !is_wildcard_host(h))
        .map(str::to_string);
        Self {
            host,
            port,
            advertise,
        }
    }

    /// As [`resolve`](Self::resolve), with the YAML `<section>.sbi.server[0]` read
    /// from `config_path` (no file is no config; one that does not parse is an
    /// error, #1313 review).
    pub fn resolve_from_file(
        cli_host: Option<&str>,
        cli_port: Option<u16>,
        cli_advertise: Option<&str>,
        config_path: &str,
        section: &str,
        default_port: u16,
    ) -> Result<Self, ListenAddrError> {
        let entry = match std::fs::read_to_string(config_path) {
            Ok(text) => yaml_server_entry(&text, section, "sbi")
                .map_err(|e| ListenAddrError(format!("{config_path}: {}", e.0)))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => YamlServer::default(),
            Err(e) => return Err(ListenAddrError(format!("{config_path}: {e}"))),
        };
        Ok(Self::resolve(
            cli_host,
            cli_port,
            cli_advertise,
            entry.address.as_deref(),
            entry.port,
            entry.advertise.as_deref(),
            default_port,
        ))
    }

    /// The host to register with the NRF: the advertised one, or why there is none.
    pub fn registration_host(&self) -> Result<&str, String> {
        self.advertise.as_deref().ok_or_else(|| {
            format!(
                "not registering with the NRF: the SBI binds the wildcard {} and nothing \
                 reachable is configured to advertise; set --sbi-advertise, {SBI_ADVERTISE_ENV} \
                 or sbi.server[0].advertise",
                self.host
            )
        })
    }

    /// The advertised host, or the bind host when there is none (log text and
    /// URIs that are built either way; the NRF registration uses
    /// [`registration_host`](Self::registration_host)).
    pub fn advertise_or_bind(&self) -> &str {
        self.advertise.as_deref().unwrap_or(&self.host)
    }
}

/// A YAML `server[0]` entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct YamlServer {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub advertise: Option<String>,
}

/// The first `<section>.<iface>.server[]` entry of the YAML config `text`, with
/// its `advertise` (#1312). YAML that does not parse is an error.
pub fn yaml_server_entry(
    text: &str,
    section: &str,
    iface: &str,
) -> Result<YamlServer, ListenAddrError> {
    let doc = serde_yaml::from_str::<serde_yaml::Value>(text)
        .map_err(|e| ListenAddrError(format!("config does not parse as YAML: {e}")))?;
    let entry = &doc[section][iface]["server"][0];
    Ok(YamlServer {
        address: entry["address"].as_str().map(str::to_string),
        port: entry["port"].as_u64().and_then(|p| u16::try_from(p).ok()),
        advertise: entry["advertise"].as_str().map(str::to_string),
    })
}

#[cfg(test)]
mod tests_sbi_endpoint {
    use super::SbiEndpoint;

    fn r(
        cli: Option<&str>,
        adv: Option<&str>,
        env: Option<&str>,
        yaml: Option<&str>,
        yaml_adv: Option<&str>,
    ) -> SbiEndpoint {
        SbiEndpoint::resolve_with_env(cli, None, adv, env, yaml, Some(7788), yaml_adv, 7777)
    }

    #[test]
    fn bind_cli_then_yaml_then_loopback() {
        assert_eq!(r(None, None, None, None, None).host, "127.0.0.1");
        assert_eq!(r(None, None, None, Some("10.0.0.1"), None).host, "10.0.0.1");
        assert_eq!(
            r(Some("0.0.0.0"), None, None, Some("10.0.0.1"), None).host,
            "0.0.0.0"
        );
        assert_eq!(r(None, None, None, None, None).port, 7788);
    }

    #[test]
    fn advertise_flag_then_env_then_yaml_then_bind_never_a_wildcard() {
        let adv = |e: SbiEndpoint| e.advertise;
        assert_eq!(
            adv(r(Some("0.0.0.0"), Some("a"), Some("b"), None, Some("c"))),
            Some("a".into())
        );
        assert_eq!(
            adv(r(Some("0.0.0.0"), None, Some("b"), None, Some("c"))),
            Some("b".into())
        );
        assert_eq!(
            adv(r(Some("0.0.0.0"), None, None, None, Some("c"))),
            Some("c".into())
        );
        assert_eq!(
            adv(r(Some("10.0.0.5"), None, None, None, None)),
            Some("10.0.0.5".into())
        );
        assert_eq!(
            adv(r(Some("0.0.0.0"), None, None, None, None)),
            None,
            "a wildcard bind"
        );
        assert_eq!(
            adv(r(Some("::"), Some("0.0.0.0"), Some(""), None, Some("[::]"))),
            None
        );
        let e = r(Some("0.0.0.0"), None, None, None, None);
        assert!(e
            .registration_host()
            .unwrap_err()
            .contains("not registering"));
        assert_eq!(
            r(Some("10.0.0.5"), None, None, None, None).registration_host(),
            Ok("10.0.0.5")
        );
    }
    /// The YAML `advertise` is read from the file; a file that does not parse is an
    /// error, and no file is no config.
    #[test]
    fn resolve_from_file_reads_the_yaml_advertise() {
        let dir = std::env::temp_dir().join(format!("sbi-endpoint-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nf.yaml");
        std::fs::write(
            &path,
            "pcf:\n  sbi:\n    server:\n      - address: 0.0.0.0\n        port: 7900\n        advertise: pcf.example\n",
        )
        .unwrap();
        let p = path.to_str().unwrap();
        let e =
            SbiEndpoint::resolve_from_file(None, None, Some("10.9.9.9"), p, "pcf", 7777).unwrap();
        assert_eq!((e.host.as_str(), e.port), ("0.0.0.0", 7900));
        assert_eq!(
            e.registration_host(),
            Ok("10.9.9.9"),
            "the flag beats the YAML"
        );
        let e = SbiEndpoint::resolve_from_file(Some("127.0.0.1"), Some(1), None, p, "pcf", 7777)
            .unwrap();
        assert_eq!(
            (e.host.as_str(), e.port),
            ("127.0.0.1", 1),
            "the flags beat the YAML"
        );
        let e = SbiEndpoint::resolve_from_file(None, None, None, "/nonexistent.yaml", "pcf", 7777)
            .unwrap();
        assert_eq!((e.host.as_str(), e.port), ("127.0.0.1", 7777));
        std::fs::write(&path, "pcf:\n  sbi: [\n").unwrap();
        assert!(SbiEndpoint::resolve_from_file(None, None, None, p, "pcf", 7777).is_err());
    }
}

#[cfg(test)]
mod tests_resolve_listen {
    use super::{resolve_listen, yaml_listen_server};

    #[test]
    fn the_command_line_then_the_yaml_then_loopback() {
        let dir = std::env::temp_dir().join(format!("resolve-listen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nf.yaml");
        std::fs::write(
            &path,
            "lmf:\n  sbi:\n    server:\n      - address: fd00::16\n        port: 7900\n",
        )
        .unwrap();
        let p = path.to_str().unwrap();
        let r = |h, port, s| resolve_listen(h, port, p, s, "sbi", 7816).unwrap();
        assert_eq!(r(None, None, "lmf"), ("fd00::16".into(), 7900));
        assert_eq!(
            r(Some("0.0.0.0"), None, "lmf"),
            ("0.0.0.0".into(), 7900),
            "field by field"
        );
        assert_eq!(r(None, Some(1), "lmf").1, 1);
        assert_eq!(
            r(None, None, "nwdaf"),
            ("127.0.0.1".into(), 7816),
            "another section"
        );
        assert_eq!(
            resolve_listen(None, None, "/nonexistent.yaml", "lmf", "sbi", 7816).unwrap(),
            ("127.0.0.1".into(), 7816),
            "no file is no config"
        );
    }

    /// #1313 review: a config that does not parse fails, rather than falling back.
    #[test]
    fn a_config_that_does_not_parse_is_an_error() {
        assert!(yaml_listen_server("not: [yaml", "lmf", "sbi").is_err());
        let dir = std::env::temp_dir().join(format!("resolve-listen-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nf.yaml");
        std::fs::write(&path, "lmf:\n  sbi: [\n").unwrap();
        let err = resolve_listen(None, None, path.to_str().unwrap(), "lmf", "sbi", 7816)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nf.yaml"), "{err}");
        assert!(
            resolve_listen(
                Some("10.0.0.1"),
                Some(1),
                path.to_str().unwrap(),
                "lmf",
                "sbi",
                7816
            )
            .is_err(),
            "even with the flags given: the file is broken"
        );
    }
}

/// The startup warning for a listener bound to a loopback address (#1308), naming
/// `setting`, the option that opens it to peers on other hosts. `None` when `addr`
/// is not loopback.
pub fn loopback_listener_warning(
    listener: &str,
    addr: &SocketAddr,
    setting: &str,
) -> Option<String> {
    addr.ip().is_loopback().then(|| {
        format!(
            "{listener} listens on {addr}, a loopback address: peers on other hosts cannot \
             reach it. Set {setting} to an address of this host that those peers can reach \
             (a private network, never a public one) to accept them"
        )
    })
}

/// Log [`loopback_listener_warning`] at warn level, if there is one.
pub fn warn_if_loopback_listener(listener: &str, addr: &SocketAddr, setting: &str) {
    if let Some(warning) = loopback_listener_warning(listener, addr, setting) {
        log::warn!("{warning}");
    }
}

/// A listen address given as a host and a port, which is not an IP literal (#1298).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenAddrError(String);

impl std::fmt::Display for ListenAddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ListenAddrError {}

/// The socket address to listen on for a configured `host` and `port` (#1298).
///
/// `host` must be an IP literal: an IPv4 address, or an IPv6 address with or without
/// square brackets (`fd00::1` and `[fd00::1]` are the same). Anything else is an error
/// for the caller to fail on: no name is resolved, and there is no fallback to a
/// wildcard address, so a bad value never widens what a daemon listens on.
///
/// Before, every daemon built `format!("{host}:{port}")` and parsed that, which works
/// for IPv4 only: `fd00::1:7777` is not a socket address, so an IPv6 address failed
/// at startup.
pub fn parse_listen_addr(host: &str, port: u16) -> Result<std::net::SocketAddr, ListenAddrError> {
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    literal
        .parse::<std::net::IpAddr>()
        .map(|ip| std::net::SocketAddr::new(ip, port))
        .map_err(|_| {
            ListenAddrError(format!(
                "listen address '{host}' is not an IPv4 or IPv6 address (port {port})"
            ))
        })
}

#[cfg(test)]
mod tests_parse_listen_addr {
    use super::parse_listen_addr;

    #[test]
    fn ipv4_ipv6_and_a_bad_value() {
        assert_eq!(
            parse_listen_addr("127.0.0.1", 7777).unwrap().to_string(),
            "127.0.0.1:7777"
        );
        assert_eq!(
            parse_listen_addr("0.0.0.0", 7777).unwrap().to_string(),
            "0.0.0.0:7777",
            "a configured wildcard is kept as it is, not changed"
        );
        assert_eq!(
            parse_listen_addr("fd00::1", 7777).unwrap().to_string(),
            "[fd00::1]:7777"
        );
        assert_eq!(
            parse_listen_addr("[fd00::1]", 7777).unwrap().to_string(),
            "[fd00::1]:7777"
        );
        assert_eq!(
            parse_listen_addr("::1", 80).unwrap().to_string(),
            "[::1]:80"
        );
        for bad in [
            "amf.example.org",
            "",
            "300.1.1.1",
            "10.0.0.1:7777",
            "[fd00::1",
            "[10.0.0.1]x",
        ] {
            let e = parse_listen_addr(bad, 7777).unwrap_err();
            assert!(
                e.to_string().contains("is not an IPv4 or IPv6 address"),
                "{bad}: {e}"
            );
        }
    }
}

#[cfg(test)]
mod tests_default_listen_host {
    use super::*;

    /// #1308: the default listener host is loopback, not the wildcard.
    #[test]
    fn the_default_listen_host_is_loopback() {
        assert_eq!(DEFAULT_LISTEN_HOST, "127.0.0.1");
        let a = parse_listen_addr(DEFAULT_LISTEN_HOST, 7777).unwrap();
        assert!(a.ip().is_loopback(), "{a}");
    }

    /// #1308: a getaddrinfo with no host gives loopback, not 0.0.0.0.
    #[test]
    fn no_host_is_loopback() {
        let sa = nextgcore_getaddrinfo(libc::AF_INET, None, 7777, 0).unwrap();
        assert_eq!(sa.addr.to_string(), "127.0.0.1:7777");
    }

    /// #1308: the warning names the listener, the address and the setting, and is
    /// only given for a loopback bind.
    #[test]
    fn the_loopback_warning_names_the_setting() {
        let lo: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let w = loopback_listener_warning("SBI", &lo, "--sbi-addr").unwrap();
        assert!(w.starts_with("SBI listens on 127.0.0.1:7777"), "{w}");
        assert!(w.contains("Set --sbi-addr"), "{w}");
        let lo6: SocketAddr = "[::1]:38412".parse().unwrap();
        assert!(loopback_listener_warning("NGAP", &lo6, "--ngap-addr").is_some());
        for other in ["0.0.0.0:7777", "10.0.0.5:7777", "[fd00::1]:7777"] {
            let a: SocketAddr = other.parse().unwrap();
            assert_eq!(
                loopback_listener_warning("SBI", &a, "--sbi-addr"),
                None,
                "{other}"
            );
        }
    }
}
