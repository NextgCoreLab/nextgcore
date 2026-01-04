//! UPF Rule Matching
//!
//! Port of src/upf/rule-match.c - Rule matching for packet forwarding
//!
//! This module provides functions to find UPF sessions based on packet content,
//! specifically by extracting the destination IP address from IP headers.

use crate::context::{upf_self, UpfSess};

// ============================================================================
// IP Header Constants
// ============================================================================

/// IPv4 version number
pub const IP_VERSION_4: u8 = 4;
/// IPv6 version number
pub const IP_VERSION_6: u8 = 6;

/// Minimum IPv4 header length (20 bytes)
pub const IPV4_MIN_HEADER_LEN: usize = 20;
/// IPv6 header length (40 bytes)
pub const IPV6_HEADER_LEN: usize = 40;

// ============================================================================
// IPv4 Header Structure
// ============================================================================

/// IPv4 header structure (simplified)
/// Matches struct ip from netinet/ip.h
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    /// Version (4 bits) and IHL (4 bits)
    pub version_ihl: u8,
    /// Type of Service
    pub tos: u8,
    /// Total Length
    pub tot_len: u16,
    /// Identification
    pub id: u16,
    /// Fragment Offset (and flags)
    pub frag_off: u16,
    /// Time to Live
    pub ttl: u8,
    /// Protocol
    pub protocol: u8,
    /// Header Checksum
    pub check: u16,
    /// Source Address
    pub saddr: u32,
    /// Destination Address
    pub daddr: u32,
}

impl Ipv4Header {
    /// Get IP version from header
    #[inline]
    pub fn version(&self) -> u8 {
        (self.version_ihl >> 4) & 0x0F
    }

    /// Get header length in bytes
    #[inline]
    pub fn header_len(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    /// Get destination address in network byte order
    #[inline]
    pub fn dst_addr(&self) -> u32 {
        self.daddr
    }

    /// Get source address in network byte order
    #[inline]
    pub fn src_addr(&self) -> u32 {
        self.saddr
    }
}

// ============================================================================
// IPv6 Header Structure
// ============================================================================

/// IPv6 header structure
/// Matches struct ip6_hdr from netinet/ip6.h
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Header {
    /// Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    pub vtc_flow: u32,
    /// Payload Length
    pub payload_len: u16,
    /// Next Header
    pub next_header: u8,
    /// Hop Limit
    pub hop_limit: u8,
    /// Source Address (128 bits = 16 bytes)
    pub saddr: [u8; 16],
    /// Destination Address (128 bits = 16 bytes)
    pub daddr: [u8; 16],
}

impl Ipv6Header {
    /// Get IP version from header
    #[inline]
    pub fn version(&self) -> u8 {
        // Version is in the first 4 bits (big-endian)
        ((u32::from_be(self.vtc_flow) >> 28) & 0x0F) as u8
    }

    /// Get destination address as array of u32 (network byte order)
    #[inline]
    pub fn dst_addr(&self) -> [u32; 4] {
        [
            u32::from_be_bytes([self.daddr[0], self.daddr[1], self.daddr[2], self.daddr[3]]),
            u32::from_be_bytes([self.daddr[4], self.daddr[5], self.daddr[6], self.daddr[7]]),
            u32::from_be_bytes([self.daddr[8], self.daddr[9], self.daddr[10], self.daddr[11]]),
            u32::from_be_bytes([self.daddr[12], self.daddr[13], self.daddr[14], self.daddr[15]]),
        ]
    }

    /// Get source address as array of u32 (network byte order)
    #[inline]
    pub fn src_addr(&self) -> [u32; 4] {
        [
            u32::from_be_bytes([self.saddr[0], self.saddr[1], self.saddr[2], self.saddr[3]]),
            u32::from_be_bytes([self.saddr[4], self.saddr[5], self.saddr[6], self.saddr[7]]),
            u32::from_be_bytes([self.saddr[8], self.saddr[9], self.saddr[10], self.saddr[11]]),
            u32::from_be_bytes([self.saddr[12], self.saddr[13], self.saddr[14], self.saddr[15]]),
        ]
    }
}

// ============================================================================
// Rule Matching Functions
// ============================================================================

/// Find UPF session by UE IP address from packet buffer
///
/// This function extracts the destination IP address from the packet's IP header
/// and finds the corresponding UPF session.
///
/// Port of upf_sess_find_by_ue_ip_address() from src/upf/rule-match.c
///
/// # Arguments
/// * `data` - Packet data buffer containing IP packet
///
/// # Returns
/// * `Some(UpfSess)` - The session matching the destination IP address
/// * `None` - If no matching session found or packet is invalid
pub fn upf_sess_find_by_ue_ip_address(data: &[u8]) -> Option<UpfSess> {
    if data.is_empty() {
        log::error!("Empty packet buffer");
        return None;
    }

    // Get IP version from first byte
    let version = (data[0] >> 4) & 0x0F;

    match version {
        IP_VERSION_4 => {
            if data.len() < IPV4_MIN_HEADER_LEN {
                log::error!(
                    "Invalid IPv4 packet [Packet Length:{}, Min Required:{}]",
                    data.len(),
                    IPV4_MIN_HEADER_LEN
                );
                return None;
            }

            // Safety: We've verified the buffer is large enough
            let ip_hdr = unsafe { &*(data.as_ptr() as *const Ipv4Header) };
            
            // Verify version matches
            if ip_hdr.version() != IP_VERSION_4 {
                log::error!("IPv4 version mismatch in header");
                return None;
            }

            let dst_addr = ip_hdr.dst_addr();
            let sess = upf_self().sess_find_by_ipv4(dst_addr);

            if let Some(ref s) = sess {
                if let Some(ref ipv4) = s.ipv4 {
                    let addr_bytes = ipv4.addr[0].to_be_bytes();
                    log::trace!(
                        "PAA IPv4:{}.{}.{}.{}",
                        addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]
                    );
                }
            }

            sess
        }
        IP_VERSION_6 => {
            if data.len() < IPV6_HEADER_LEN {
                log::error!(
                    "Invalid IPv6 packet [Packet Length:{}, Min Required:{}]",
                    data.len(),
                    IPV6_HEADER_LEN
                );
                return None;
            }

            // Safety: We've verified the buffer is large enough
            let ip6_hdr = unsafe { &*(data.as_ptr() as *const Ipv6Header) };
            
            let dst_addr = ip6_hdr.dst_addr();
            let sess = upf_self().sess_find_by_ipv6(&dst_addr);

            if let Some(ref s) = sess {
                if let Some(ref ipv6) = s.ipv6 {
                    log::trace!(
                        "PAA IPv6:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                        (ipv6.addr[0] >> 16) & 0xFFFF,
                        ipv6.addr[0] & 0xFFFF,
                        (ipv6.addr[1] >> 16) & 0xFFFF,
                        ipv6.addr[1] & 0xFFFF,
                        (ipv6.addr[2] >> 16) & 0xFFFF,
                        ipv6.addr[2] & 0xFFFF,
                        (ipv6.addr[3] >> 16) & 0xFFFF,
                        ipv6.addr[3] & 0xFFFF
                    );
                }
            }

            sess
        }
        _ => {
            log::error!(
                "Invalid packet [IP version:{}, Packet Length:{}]",
                version,
                data.len()
            );
            // Log hex dump for debugging (first 64 bytes max)
            let dump_len = data.len().min(64);
            log::error!("Packet hex dump: {:02x?}", &data[..dump_len]);
            None
        }
    }
}

/// Find UPF session by source IP address from packet buffer
///
/// This function extracts the source IP address from the packet's IP header
/// and finds the corresponding UPF session. Useful for uplink packet matching.
///
/// # Arguments
/// * `data` - Packet data buffer containing IP packet
///
/// # Returns
/// * `Some(UpfSess)` - The session matching the source IP address
/// * `None` - If no matching session found or packet is invalid
pub fn upf_sess_find_by_ue_ip_address_src(data: &[u8]) -> Option<UpfSess> {
    if data.is_empty() {
        log::error!("Empty packet buffer");
        return None;
    }

    // Get IP version from first byte
    let version = (data[0] >> 4) & 0x0F;

    match version {
        IP_VERSION_4 => {
            if data.len() < IPV4_MIN_HEADER_LEN {
                log::error!(
                    "Invalid IPv4 packet [Packet Length:{}, Min Required:{}]",
                    data.len(),
                    IPV4_MIN_HEADER_LEN
                );
                return None;
            }

            let ip_hdr = unsafe { &*(data.as_ptr() as *const Ipv4Header) };
            let src_addr = ip_hdr.src_addr();
            upf_self().sess_find_by_ipv4(src_addr)
        }
        IP_VERSION_6 => {
            if data.len() < IPV6_HEADER_LEN {
                log::error!(
                    "Invalid IPv6 packet [Packet Length:{}, Min Required:{}]",
                    data.len(),
                    IPV6_HEADER_LEN
                );
                return None;
            }

            let ip6_hdr = unsafe { &*(data.as_ptr() as *const Ipv6Header) };
            let src_addr = ip6_hdr.src_addr();
            upf_self().sess_find_by_ipv6(&src_addr)
        }
        _ => {
            log::error!(
                "Invalid packet [IP version:{}, Packet Length:{}]",
                version,
                data.len()
            );
            None
        }
    }
}

/// Extract IP version from packet buffer
///
/// # Arguments
/// * `data` - Packet data buffer
///
/// # Returns
/// * `Some(4)` for IPv4, `Some(6)` for IPv6
/// * `None` if buffer is empty or version is invalid
pub fn get_ip_version(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }
    let version = (data[0] >> 4) & 0x0F;
    if version == IP_VERSION_4 || version == IP_VERSION_6 {
        Some(version)
    } else {
        None
    }
}

/// Extract destination IPv4 address from packet buffer
///
/// # Arguments
/// * `data` - Packet data buffer containing IPv4 packet
///
/// # Returns
/// * `Some(u32)` - Destination address in network byte order
/// * `None` - If packet is invalid
pub fn get_ipv4_dst_addr(data: &[u8]) -> Option<u32> {
    if data.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let version = (data[0] >> 4) & 0x0F;
    if version != IP_VERSION_4 {
        return None;
    }
    let ip_hdr = unsafe { &*(data.as_ptr() as *const Ipv4Header) };
    Some(ip_hdr.dst_addr())
}

/// Extract destination IPv6 address from packet buffer
///
/// # Arguments
/// * `data` - Packet data buffer containing IPv6 packet
///
/// # Returns
/// * `Some([u32; 4])` - Destination address as array of u32
/// * `None` - If packet is invalid
pub fn get_ipv6_dst_addr(data: &[u8]) -> Option<[u32; 4]> {
    if data.len() < IPV6_HEADER_LEN {
        return None;
    }
    let version = (data[0] >> 4) & 0x0F;
    if version != IP_VERSION_6 {
        return None;
    }
    let ip6_hdr = unsafe { &*(data.as_ptr() as *const Ipv6Header) };
    Some(ip6_hdr.dst_addr())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Create a minimal IPv4 packet for testing
    fn create_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; IPV4_MIN_HEADER_LEN];
        
        // Version (4) and IHL (5 = 20 bytes)
        packet[0] = 0x45;
        // TOS
        packet[1] = 0x00;
        // Total length (20 bytes header only)
        packet[2] = 0x00;
        packet[3] = 0x14;
        // ID
        packet[4] = 0x00;
        packet[5] = 0x00;
        // Flags and fragment offset
        packet[6] = 0x00;
        packet[7] = 0x00;
        // TTL
        packet[8] = 64;
        // Protocol (TCP = 6)
        packet[9] = 6;
        // Checksum (0 for test)
        packet[10] = 0x00;
        packet[11] = 0x00;
        // Source address
        let src_bytes = src.octets();
        packet[12] = src_bytes[0];
        packet[13] = src_bytes[1];
        packet[14] = src_bytes[2];
        packet[15] = src_bytes[3];
        // Destination address
        let dst_bytes = dst.octets();
        packet[16] = dst_bytes[0];
        packet[17] = dst_bytes[1];
        packet[18] = dst_bytes[2];
        packet[19] = dst_bytes[3];
        
        packet
    }

    /// Create a minimal IPv6 packet for testing
    fn create_ipv6_packet(src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
        let mut packet = vec![0u8; IPV6_HEADER_LEN];
        
        // Version (6), Traffic Class, Flow Label
        packet[0] = 0x60; // Version 6
        packet[1] = 0x00;
        packet[2] = 0x00;
        packet[3] = 0x00;
        // Payload length (0 for header only)
        packet[4] = 0x00;
        packet[5] = 0x00;
        // Next header (TCP = 6)
        packet[6] = 6;
        // Hop limit
        packet[7] = 64;
        // Source address
        packet[8..24].copy_from_slice(&src);
        // Destination address
        packet[24..40].copy_from_slice(&dst);
        
        packet
    }

    #[test]
    fn test_ipv4_header_parsing() {
        let packet = create_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 100),
        );
        
        let ip_hdr = unsafe { &*(packet.as_ptr() as *const Ipv4Header) };
        
        assert_eq!(ip_hdr.version(), 4);
        assert_eq!(ip_hdr.header_len(), 20);
        
        // Check destination address - stored in network byte order
        // The raw u32 value is what we get from the header
        let dst = ip_hdr.dst_addr();
        // Convert to native byte order to get the expected IP
        let dst_native = u32::from_be(dst);
        assert_eq!(dst_native, u32::from_be_bytes([192, 168, 1, 100]));
        
        // Check source address
        let src = ip_hdr.src_addr();
        let src_native = u32::from_be(src);
        assert_eq!(src_native, u32::from_be_bytes([10, 0, 0, 1]));
    }

    #[test]
    fn test_ipv6_header_parsing() {
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        
        let packet = create_ipv6_packet(src, dst);
        
        let ip6_hdr = unsafe { &*(packet.as_ptr() as *const Ipv6Header) };
        
        assert_eq!(ip6_hdr.version(), 6);
        
        // Check destination address
        let dst_addr = ip6_hdr.dst_addr();
        assert_eq!(dst_addr[0], 0x20010db8);
        assert_eq!(dst_addr[1], 0x00000000);
        assert_eq!(dst_addr[2], 0x00000000);
        assert_eq!(dst_addr[3], 0x00000002);
    }

    #[test]
    fn test_get_ip_version() {
        // IPv4 packet
        let ipv4_packet = create_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 100),
        );
        assert_eq!(get_ip_version(&ipv4_packet), Some(4));
        
        // IPv6 packet
        let ipv6_packet = create_ipv6_packet([0; 16], [0; 16]);
        assert_eq!(get_ip_version(&ipv6_packet), Some(6));
        
        // Empty packet
        assert_eq!(get_ip_version(&[]), None);
        
        // Invalid version
        let invalid = vec![0x30u8; 20]; // Version 3
        assert_eq!(get_ip_version(&invalid), None);
    }

    #[test]
    fn test_get_ipv4_dst_addr() {
        let packet = create_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 100),
        );
        
        let dst = get_ipv4_dst_addr(&packet).unwrap();
        // The address is in network byte order (big-endian)
        // Convert to native to verify
        let dst_native = u32::from_be(dst);
        assert_eq!(dst_native, u32::from_be_bytes([192, 168, 1, 100]));
        
        // Too short packet
        assert!(get_ipv4_dst_addr(&[0x45; 10]).is_none());
        
        // Wrong version
        let ipv6_packet = create_ipv6_packet([0; 16], [0; 16]);
        assert!(get_ipv4_dst_addr(&ipv6_packet).is_none());
    }

    #[test]
    fn test_get_ipv6_dst_addr() {
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let packet = create_ipv6_packet([0; 16], dst);
        
        let dst_addr = get_ipv6_dst_addr(&packet).unwrap();
        assert_eq!(dst_addr[0], 0x20010db8);
        assert_eq!(dst_addr[3], 0x00000002);
        
        // Too short packet
        assert!(get_ipv6_dst_addr(&[0x60; 20]).is_none());
        
        // Wrong version
        let ipv4_packet = create_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 100),
        );
        assert!(get_ipv6_dst_addr(&ipv4_packet).is_none());
    }

    #[test]
    fn test_invalid_packets() {
        // Empty packet
        assert!(upf_sess_find_by_ue_ip_address(&[]).is_none());
        
        // Too short IPv4 packet
        assert!(upf_sess_find_by_ue_ip_address(&[0x45; 10]).is_none());
        
        // Too short IPv6 packet
        assert!(upf_sess_find_by_ue_ip_address(&[0x60; 20]).is_none());
        
        // Invalid IP version
        let invalid = vec![0x30u8; 40]; // Version 3
        assert!(upf_sess_find_by_ue_ip_address(&invalid).is_none());
    }
}
