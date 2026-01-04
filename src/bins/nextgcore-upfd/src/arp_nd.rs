//! ARP and Neighbor Discovery (ND) Handling for UPF
//!
//! Port of src/upf/arp-nd.cpp - ARP and IPv6 Neighbor Discovery handling
//!
//! This module handles:
//! - ARP request detection and reply generation
//! - IPv6 Neighbor Solicitation detection and Neighbor Advertisement reply
//! - Proxy ARP/ND for TAP devices

use crate::gtp_path::{ETHER_ADDR_LEN, ETHER_HDR_LEN, ETHERTYPE_ARP, ETHERTYPE_IPV6};

// ============================================================================
// Constants
// ============================================================================

/// Maximum ND packet size for parsing
pub const MAX_ND_SIZE: usize = 128;

/// ARP hardware type: Ethernet
pub const ARP_HW_TYPE_ETHERNET: u16 = 1;

/// ARP protocol type: IPv4
pub const ARP_PROTO_TYPE_IPV4: u16 = 0x0800;

/// ARP operation: Request
pub const ARP_OP_REQUEST: u16 = 1;

/// ARP operation: Reply
pub const ARP_OP_REPLY: u16 = 2;

/// ARP packet length (for Ethernet/IPv4)
pub const ARP_PKT_LEN: usize = 28;

/// ICMPv6 type: Neighbor Solicitation
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;

/// ICMPv6 type: Neighbor Advertisement
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// ICMPv6 option type: Target Link-Layer Address
pub const ICMPV6_OPT_TARGET_LINK_ADDR: u8 = 2;

/// IPv6 header length
pub const IPV6_HEADER_LEN: usize = 40;

/// IPv6 next header: ICMPv6
pub const IPV6_NEXT_HEADER_ICMPV6: u8 = 58;


// ============================================================================
// ARP Packet Structure
// ============================================================================

/// ARP packet structure (for Ethernet/IPv4)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ArpPacket {
    /// Hardware type (1 = Ethernet)
    pub hw_type: u16,
    /// Protocol type (0x0800 = IPv4)
    pub proto_type: u16,
    /// Hardware address length (6 for Ethernet)
    pub hw_addr_len: u8,
    /// Protocol address length (4 for IPv4)
    pub proto_addr_len: u8,
    /// Operation (1 = request, 2 = reply)
    pub operation: u16,
    /// Sender hardware address
    pub sender_hw_addr: [u8; ETHER_ADDR_LEN],
    /// Sender protocol address (IPv4)
    pub sender_proto_addr: [u8; 4],
    /// Target hardware address
    pub target_hw_addr: [u8; ETHER_ADDR_LEN],
    /// Target protocol address (IPv4)
    pub target_proto_addr: [u8; 4],
}

impl ArpPacket {
    /// Get operation in host byte order
    #[inline]
    pub fn get_operation(&self) -> u16 {
        u16::from_be(self.operation)
    }

    /// Get target IPv4 address as u32
    #[inline]
    pub fn get_target_ip(&self) -> u32 {
        u32::from_be_bytes(self.target_proto_addr)
    }

    /// Get sender IPv4 address as u32
    #[inline]
    pub fn get_sender_ip(&self) -> u32 {
        u32::from_be_bytes(self.sender_proto_addr)
    }
}


// ============================================================================
// Ethernet Header Structure
// ============================================================================

/// Ethernet header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    /// Destination MAC address
    pub dst_addr: [u8; ETHER_ADDR_LEN],
    /// Source MAC address
    pub src_addr: [u8; ETHER_ADDR_LEN],
    /// Ethertype
    pub ether_type: u16,
}

impl EthernetHeader {
    /// Get ethertype in host byte order
    #[inline]
    pub fn get_ether_type(&self) -> u16 {
        u16::from_be(self.ether_type)
    }
}

// ============================================================================
// IPv6 Header Structure
// ============================================================================

/// IPv6 header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Header {
    /// Version, traffic class, flow label
    pub version_tc_flow: u32,
    /// Payload length
    pub payload_len: u16,
    /// Next header
    pub next_header: u8,
    /// Hop limit
    pub hop_limit: u8,
    /// Source address
    pub src_addr: [u8; 16],
    /// Destination address
    pub dst_addr: [u8; 16],
}


// ============================================================================
// ICMPv6 Neighbor Solicitation/Advertisement Structures
// ============================================================================

/// ICMPv6 header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Icmpv6Header {
    /// Type
    pub icmp_type: u8,
    /// Code
    pub code: u8,
    /// Checksum
    pub checksum: u16,
}

/// ICMPv6 Neighbor Solicitation message
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NeighborSolicitation {
    /// ICMPv6 header
    pub header: Icmpv6Header,
    /// Reserved (must be zero)
    pub reserved: u32,
    /// Target address
    pub target_addr: [u8; 16],
}

/// ICMPv6 Neighbor Advertisement message
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NeighborAdvertisement {
    /// ICMPv6 header
    pub header: Icmpv6Header,
    /// Flags (R, S, O) and reserved
    pub flags_reserved: u32,
    /// Target address
    pub target_addr: [u8; 16],
}

/// ICMPv6 option: Target Link-Layer Address
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NdOptTargetLinkAddr {
    /// Option type (2 = Target Link-Layer Address)
    pub opt_type: u8,
    /// Length in units of 8 octets
    pub length: u8,
    /// Link-layer address
    pub link_addr: [u8; ETHER_ADDR_LEN],
}


// ============================================================================
// ARP Functions
// ============================================================================

/// Check if packet is an ARP request
///
/// Port of is_arp_req() from arp-nd.cpp
/// Returns true if the packet is a broadcast ARP request
pub fn is_arp_req(data: &[u8]) -> bool {
    if data.len() < ETHER_HDR_LEN + ARP_PKT_LEN {
        return false;
    }

    // Check Ethernet type
    let eth_hdr = unsafe { &*(data.as_ptr() as *const EthernetHeader) };
    if eth_hdr.get_ether_type() != ETHERTYPE_ARP {
        return false;
    }

    // Check if destination is broadcast
    let is_broadcast = eth_hdr.dst_addr == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    if !is_broadcast {
        return false;
    }

    // Check ARP operation
    let arp = unsafe { &*(data[ETHER_HDR_LEN..].as_ptr() as *const ArpPacket) };
    arp.get_operation() == ARP_OP_REQUEST
}

/// Parse target IPv4 address from ARP request
///
/// Port of arp_parse_target_addr() from arp-nd.cpp
/// Returns the target IPv4 address as u32, or 0 if not an ARP packet
pub fn arp_parse_target_addr(data: &[u8]) -> u32 {
    if data.len() < ETHER_HDR_LEN + ARP_PKT_LEN {
        return 0;
    }

    let eth_hdr = unsafe { &*(data.as_ptr() as *const EthernetHeader) };
    if eth_hdr.get_ether_type() != ETHERTYPE_ARP {
        return 0;
    }

    let arp = unsafe { &*(data[ETHER_HDR_LEN..].as_ptr() as *const ArpPacket) };
    arp.get_target_ip()
}


/// Generate ARP reply from ARP request
///
/// Port of arp_reply() from arp-nd.cpp
/// Returns the number of bytes written to reply_data, or 0 on error
pub fn arp_reply(reply_data: &mut [u8], request_data: &[u8], mac: &[u8; ETHER_ADDR_LEN]) -> usize {
    if !is_arp_req(request_data) {
        return 0;
    }

    let reply_len = ETHER_HDR_LEN + ARP_PKT_LEN;
    if reply_data.len() < reply_len {
        return 0;
    }

    // Parse request
    let req_eth = unsafe { &*(request_data.as_ptr() as *const EthernetHeader) };
    let req_arp = unsafe { &*(request_data[ETHER_HDR_LEN..].as_ptr() as *const ArpPacket) };

    // Build Ethernet header for reply
    // Destination = original sender
    // Source = our MAC
    reply_data[0..ETHER_ADDR_LEN].copy_from_slice(&req_eth.src_addr);
    reply_data[ETHER_ADDR_LEN..ETHER_ADDR_LEN * 2].copy_from_slice(mac);
    reply_data[ETHER_ADDR_LEN * 2..ETHER_HDR_LEN].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    // Build ARP reply
    let arp_offset = ETHER_HDR_LEN;
    
    // Hardware type: Ethernet
    reply_data[arp_offset..arp_offset + 2].copy_from_slice(&ARP_HW_TYPE_ETHERNET.to_be_bytes());
    // Protocol type: IPv4
    reply_data[arp_offset + 2..arp_offset + 4].copy_from_slice(&ARP_PROTO_TYPE_IPV4.to_be_bytes());
    // Hardware address length
    reply_data[arp_offset + 4] = ETHER_ADDR_LEN as u8;
    // Protocol address length
    reply_data[arp_offset + 5] = 4;
    // Operation: Reply
    reply_data[arp_offset + 6..arp_offset + 8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    // Sender hardware address: our MAC
    reply_data[arp_offset + 8..arp_offset + 14].copy_from_slice(mac);
    // Sender protocol address: target IP from request
    reply_data[arp_offset + 14..arp_offset + 18].copy_from_slice(&req_arp.target_proto_addr);
    // Target hardware address: sender MAC from request
    reply_data[arp_offset + 18..arp_offset + 24].copy_from_slice(&req_arp.sender_hw_addr);
    // Target protocol address: sender IP from request
    reply_data[arp_offset + 24..arp_offset + 28].copy_from_slice(&req_arp.sender_proto_addr);

    reply_len
}


// ============================================================================
// Neighbor Discovery Functions
// ============================================================================

/// Check if packet is an IPv6 Neighbor Solicitation
///
/// Port of is_nd_req() from arp-nd.cpp
/// Returns true if the packet is a Neighbor Solicitation
pub fn is_nd_req(data: &[u8]) -> bool {
    // Check minimum size
    if data.len() < MAX_ND_SIZE {
        // Only parse if packet is small enough (safety check from C code)
    } else {
        return false;
    }

    if data.len() < ETHER_HDR_LEN + IPV6_HEADER_LEN + 8 {
        return false;
    }

    // Check Ethernet type
    let eth_hdr = unsafe { &*(data.as_ptr() as *const EthernetHeader) };
    if eth_hdr.get_ether_type() != ETHERTYPE_IPV6 {
        return false;
    }

    // Check IPv6 next header
    let ipv6_hdr = unsafe { &*(data[ETHER_HDR_LEN..].as_ptr() as *const Ipv6Header) };
    if ipv6_hdr.next_header != IPV6_NEXT_HEADER_ICMPV6 {
        return false;
    }

    // Check ICMPv6 type
    let icmpv6_offset = ETHER_HDR_LEN + IPV6_HEADER_LEN;
    if data.len() < icmpv6_offset + 1 {
        return false;
    }

    data[icmpv6_offset] == ICMPV6_NEIGHBOR_SOLICITATION
}


/// Calculate ICMPv6 checksum
///
/// ICMPv6 checksum includes a pseudo-header with source/dest addresses
fn calculate_icmpv6_checksum(
    src_addr: &[u8; 16],
    dst_addr: &[u8; 16],
    icmpv6_data: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src_addr[i], src_addr[i + 1]]) as u32;
    }

    // Pseudo-header: destination address
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst_addr[i], dst_addr[i + 1]]) as u32;
    }

    // Pseudo-header: upper-layer packet length
    let len = icmpv6_data.len() as u32;
    sum += (len >> 16) as u32;
    sum += (len & 0xFFFF) as u32;

    // Pseudo-header: next header (ICMPv6 = 58)
    sum += IPV6_NEXT_HEADER_ICMPV6 as u32;

    // ICMPv6 data (with checksum field zeroed)
    let mut i = 0;
    while i + 1 < icmpv6_data.len() {
        if i == 2 {
            // Skip checksum field
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([icmpv6_data[i], icmpv6_data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if icmpv6_data.len() % 2 == 1 {
        sum += (icmpv6_data[icmpv6_data.len() - 1] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}


/// Generate Neighbor Advertisement reply from Neighbor Solicitation
///
/// Port of nd_reply() from arp-nd.cpp
/// Returns the number of bytes written to reply_data, or 0 on error
pub fn nd_reply(reply_data: &mut [u8], request_data: &[u8], mac: &[u8; ETHER_ADDR_LEN]) -> usize {
    if !is_nd_req(request_data) {
        return 0;
    }

    // Parse request
    let req_eth = unsafe { &*(request_data.as_ptr() as *const EthernetHeader) };
    let req_ipv6 = unsafe { &*(request_data[ETHER_HDR_LEN..].as_ptr() as *const Ipv6Header) };
    let icmpv6_offset = ETHER_HDR_LEN + IPV6_HEADER_LEN;
    let req_ns = unsafe { &*(request_data[icmpv6_offset..].as_ptr() as *const NeighborSolicitation) };

    // Calculate reply size
    // Ethernet header + IPv6 header + NA header (24 bytes) + Target Link-Layer Address option (8 bytes)
    let na_len = std::mem::size_of::<NeighborAdvertisement>();
    let opt_len = std::mem::size_of::<NdOptTargetLinkAddr>();
    let icmpv6_len = na_len + opt_len;
    let reply_len = ETHER_HDR_LEN + IPV6_HEADER_LEN + icmpv6_len;

    if reply_data.len() < reply_len {
        return 0;
    }

    // Build Ethernet header
    // Destination = original source
    // Source = our MAC
    reply_data[0..ETHER_ADDR_LEN].copy_from_slice(&req_eth.src_addr);
    reply_data[ETHER_ADDR_LEN..ETHER_ADDR_LEN * 2].copy_from_slice(mac);
    reply_data[ETHER_ADDR_LEN * 2..ETHER_HDR_LEN].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

    // Build IPv6 header
    let ipv6_offset = ETHER_HDR_LEN;
    // Version (6), Traffic Class (0), Flow Label (0)
    reply_data[ipv6_offset..ipv6_offset + 4].copy_from_slice(&0x60000000u32.to_be_bytes());
    // Payload length
    reply_data[ipv6_offset + 4..ipv6_offset + 6].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
    // Next header: ICMPv6
    reply_data[ipv6_offset + 6] = IPV6_NEXT_HEADER_ICMPV6;
    // Hop limit: 255 (required for ND)
    reply_data[ipv6_offset + 7] = 255;
    // Source address: target address from solicitation
    reply_data[ipv6_offset + 8..ipv6_offset + 24].copy_from_slice(&req_ns.target_addr);
    // Destination address: source address from request
    reply_data[ipv6_offset + 24..ipv6_offset + 40].copy_from_slice(&req_ipv6.src_addr);

    // Build ICMPv6 Neighbor Advertisement
    let na_offset = ETHER_HDR_LEN + IPV6_HEADER_LEN;
    // Type: Neighbor Advertisement
    reply_data[na_offset] = ICMPV6_NEIGHBOR_ADVERTISEMENT;
    // Code: 0
    reply_data[na_offset + 1] = 0;
    // Checksum: placeholder (calculated later)
    reply_data[na_offset + 2..na_offset + 4].copy_from_slice(&[0, 0]);
    // Flags: Solicited (S=1), Override (O=1) = 0x60000000
    reply_data[na_offset + 4..na_offset + 8].copy_from_slice(&0x60000000u32.to_be_bytes());
    // Target address
    reply_data[na_offset + 8..na_offset + 24].copy_from_slice(&req_ns.target_addr);

    // Build Target Link-Layer Address option
    let opt_offset = na_offset + na_len;
    reply_data[opt_offset] = ICMPV6_OPT_TARGET_LINK_ADDR;
    reply_data[opt_offset + 1] = 1; // Length in units of 8 octets
    reply_data[opt_offset + 2..opt_offset + 8].copy_from_slice(mac);

    // Calculate and set checksum
    let src_addr: [u8; 16] = reply_data[ipv6_offset + 8..ipv6_offset + 24].try_into().unwrap();
    let dst_addr: [u8; 16] = reply_data[ipv6_offset + 24..ipv6_offset + 40].try_into().unwrap();
    let checksum = calculate_icmpv6_checksum(
        &src_addr,
        &dst_addr,
        &reply_data[na_offset..na_offset + icmpv6_len],
    );
    reply_data[na_offset + 2..na_offset + 4].copy_from_slice(&checksum.to_be_bytes());

    reply_len
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a valid ARP request packet
    fn create_arp_request(sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; ETHER_HDR_LEN + ARP_PKT_LEN];
        
        // Ethernet header
        // Destination: broadcast
        pkt[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Source: some MAC
        pkt[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Ethertype: ARP
        pkt[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        
        // ARP packet
        let arp_offset = ETHER_HDR_LEN;
        // Hardware type: Ethernet
        pkt[arp_offset..arp_offset + 2].copy_from_slice(&ARP_HW_TYPE_ETHERNET.to_be_bytes());
        // Protocol type: IPv4
        pkt[arp_offset + 2..arp_offset + 4].copy_from_slice(&ARP_PROTO_TYPE_IPV4.to_be_bytes());
        // Hardware address length
        pkt[arp_offset + 4] = 6;
        // Protocol address length
        pkt[arp_offset + 5] = 4;
        // Operation: Request
        pkt[arp_offset + 6..arp_offset + 8].copy_from_slice(&ARP_OP_REQUEST.to_be_bytes());
        // Sender hardware address
        pkt[arp_offset + 8..arp_offset + 14].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Sender protocol address
        pkt[arp_offset + 14..arp_offset + 18].copy_from_slice(&sender_ip);
        // Target hardware address (zeros for request)
        pkt[arp_offset + 18..arp_offset + 24].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Target protocol address
        pkt[arp_offset + 24..arp_offset + 28].copy_from_slice(&target_ip);
        
        pkt
    }

    #[test]
    fn test_is_arp_req_valid() {
        let pkt = create_arp_request([192, 168, 1, 1], [192, 168, 1, 100]);
        assert!(is_arp_req(&pkt));
    }

    #[test]
    fn test_is_arp_req_not_broadcast() {
        let mut pkt = create_arp_request([192, 168, 1, 1], [192, 168, 1, 100]);
        // Change destination to unicast
        pkt[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!is_arp_req(&pkt));
    }

    #[test]
    fn test_is_arp_req_reply() {
        let mut pkt = create_arp_request([192, 168, 1, 1], [192, 168, 1, 100]);
        // Change operation to reply
        let arp_offset = ETHER_HDR_LEN;
        pkt[arp_offset + 6..arp_offset + 8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
        assert!(!is_arp_req(&pkt));
    }

    #[test]
    fn test_is_arp_req_too_short() {
        let pkt = vec![0u8; 10];
        assert!(!is_arp_req(&pkt));
    }


    #[test]
    fn test_arp_parse_target_addr() {
        let pkt = create_arp_request([192, 168, 1, 1], [192, 168, 1, 100]);
        let target_ip = arp_parse_target_addr(&pkt);
        // 192.168.1.100 in network byte order
        assert_eq!(target_ip, u32::from_be_bytes([192, 168, 1, 100]));
    }

    #[test]
    fn test_arp_parse_target_addr_invalid() {
        let pkt = vec![0u8; 10];
        assert_eq!(arp_parse_target_addr(&pkt), 0);
    }

    #[test]
    fn test_arp_reply() {
        let request = create_arp_request([192, 168, 1, 1], [192, 168, 1, 100]);
        let our_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut reply = vec![0u8; ETHER_HDR_LEN + ARP_PKT_LEN];
        
        let len = arp_reply(&mut reply, &request, &our_mac);
        assert_eq!(len, ETHER_HDR_LEN + ARP_PKT_LEN);
        
        // Check Ethernet header
        // Destination should be original sender
        assert_eq!(&reply[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Source should be our MAC
        assert_eq!(&reply[6..12], &our_mac);
        // Ethertype should be ARP
        assert_eq!(&reply[12..14], &ETHERTYPE_ARP.to_be_bytes());
        
        // Check ARP reply
        let arp_offset = ETHER_HDR_LEN;
        // Operation should be reply
        assert_eq!(&reply[arp_offset + 6..arp_offset + 8], &ARP_OP_REPLY.to_be_bytes());
        // Sender hardware address should be our MAC
        assert_eq!(&reply[arp_offset + 8..arp_offset + 14], &our_mac);
        // Sender protocol address should be target IP from request
        assert_eq!(&reply[arp_offset + 14..arp_offset + 18], &[192, 168, 1, 100]);
        // Target hardware address should be sender MAC from request
        assert_eq!(&reply[arp_offset + 18..arp_offset + 24], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Target protocol address should be sender IP from request
        assert_eq!(&reply[arp_offset + 24..arp_offset + 28], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_arp_reply_invalid_request() {
        let request = vec![0u8; 10]; // Too short
        let our_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut reply = vec![0u8; ETHER_HDR_LEN + ARP_PKT_LEN];
        
        let len = arp_reply(&mut reply, &request, &our_mac);
        assert_eq!(len, 0);
    }


    /// Create a valid Neighbor Solicitation packet
    fn create_neighbor_solicitation(target_addr: [u8; 16]) -> Vec<u8> {
        let icmpv6_len = std::mem::size_of::<NeighborSolicitation>();
        let pkt_len = ETHER_HDR_LEN + IPV6_HEADER_LEN + icmpv6_len;
        let mut pkt = vec![0u8; pkt_len];
        
        // Ethernet header
        // Destination: solicited-node multicast
        pkt[0..6].copy_from_slice(&[0x33, 0x33, 0xFF, target_addr[13], target_addr[14], target_addr[15]]);
        // Source: some MAC
        pkt[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Ethertype: IPv6
        pkt[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        
        // IPv6 header
        let ipv6_offset = ETHER_HDR_LEN;
        // Version (6), Traffic Class (0), Flow Label (0)
        pkt[ipv6_offset..ipv6_offset + 4].copy_from_slice(&0x60000000u32.to_be_bytes());
        // Payload length
        pkt[ipv6_offset + 4..ipv6_offset + 6].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
        // Next header: ICMPv6
        pkt[ipv6_offset + 6] = IPV6_NEXT_HEADER_ICMPV6;
        // Hop limit
        pkt[ipv6_offset + 7] = 255;
        // Source address: link-local
        let src_addr: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55];
        pkt[ipv6_offset + 8..ipv6_offset + 24].copy_from_slice(&src_addr);
        // Destination address: solicited-node multicast
        let dst_addr: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, target_addr[13], target_addr[14], target_addr[15]];
        pkt[ipv6_offset + 24..ipv6_offset + 40].copy_from_slice(&dst_addr);
        
        // ICMPv6 Neighbor Solicitation
        let ns_offset = ETHER_HDR_LEN + IPV6_HEADER_LEN;
        // Type: Neighbor Solicitation
        pkt[ns_offset] = ICMPV6_NEIGHBOR_SOLICITATION;
        // Code: 0
        pkt[ns_offset + 1] = 0;
        // Checksum: placeholder
        pkt[ns_offset + 2..ns_offset + 4].copy_from_slice(&[0, 0]);
        // Reserved
        pkt[ns_offset + 4..ns_offset + 8].copy_from_slice(&[0, 0, 0, 0]);
        // Target address
        pkt[ns_offset + 8..ns_offset + 24].copy_from_slice(&target_addr);
        
        pkt
    }

    #[test]
    fn test_is_nd_req_valid() {
        let target_addr: [u8; 16] = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let pkt = create_neighbor_solicitation(target_addr);
        assert!(is_nd_req(&pkt));
    }

    #[test]
    fn test_is_nd_req_wrong_type() {
        let target_addr: [u8; 16] = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let mut pkt = create_neighbor_solicitation(target_addr);
        // Change ICMPv6 type to Neighbor Advertisement
        let ns_offset = ETHER_HDR_LEN + IPV6_HEADER_LEN;
        pkt[ns_offset] = ICMPV6_NEIGHBOR_ADVERTISEMENT;
        assert!(!is_nd_req(&pkt));
    }

    #[test]
    fn test_is_nd_req_too_short() {
        let pkt = vec![0u8; 10];
        assert!(!is_nd_req(&pkt));
    }

    #[test]
    fn test_is_nd_req_too_large() {
        // Packet larger than MAX_ND_SIZE should be rejected
        let pkt = vec![0u8; MAX_ND_SIZE + 10];
        assert!(!is_nd_req(&pkt));
    }


    #[test]
    fn test_nd_reply() {
        let target_addr: [u8; 16] = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let request = create_neighbor_solicitation(target_addr);
        let our_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        
        let na_len = std::mem::size_of::<NeighborAdvertisement>();
        let opt_len = std::mem::size_of::<NdOptTargetLinkAddr>();
        let reply_len = ETHER_HDR_LEN + IPV6_HEADER_LEN + na_len + opt_len;
        let mut reply = vec![0u8; reply_len];
        
        let len = nd_reply(&mut reply, &request, &our_mac);
        assert_eq!(len, reply_len);
        
        // Check Ethernet header
        // Destination should be original sender MAC
        assert_eq!(&reply[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Source should be our MAC
        assert_eq!(&reply[6..12], &our_mac);
        // Ethertype should be IPv6
        assert_eq!(&reply[12..14], &ETHERTYPE_IPV6.to_be_bytes());
        
        // Check IPv6 header
        let ipv6_offset = ETHER_HDR_LEN;
        // Next header should be ICMPv6
        assert_eq!(reply[ipv6_offset + 6], IPV6_NEXT_HEADER_ICMPV6);
        // Hop limit should be 255
        assert_eq!(reply[ipv6_offset + 7], 255);
        // Source address should be target address from solicitation
        assert_eq!(&reply[ipv6_offset + 8..ipv6_offset + 24], &target_addr);
        
        // Check ICMPv6 Neighbor Advertisement
        let na_offset = ETHER_HDR_LEN + IPV6_HEADER_LEN;
        // Type should be Neighbor Advertisement
        assert_eq!(reply[na_offset], ICMPV6_NEIGHBOR_ADVERTISEMENT);
        // Code should be 0
        assert_eq!(reply[na_offset + 1], 0);
        // Flags should have S and O set (0x60000000)
        assert_eq!(&reply[na_offset + 4..na_offset + 8], &0x60000000u32.to_be_bytes());
        // Target address should match
        assert_eq!(&reply[na_offset + 8..na_offset + 24], &target_addr);
        
        // Check Target Link-Layer Address option
        let opt_offset = na_offset + na_len;
        assert_eq!(reply[opt_offset], ICMPV6_OPT_TARGET_LINK_ADDR);
        assert_eq!(reply[opt_offset + 1], 1); // Length in units of 8 octets
        assert_eq!(&reply[opt_offset + 2..opt_offset + 8], &our_mac);
    }

    #[test]
    fn test_nd_reply_invalid_request() {
        let request = vec![0u8; 10]; // Too short
        let our_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut reply = vec![0u8; 200];
        
        let len = nd_reply(&mut reply, &request, &our_mac);
        assert_eq!(len, 0);
    }

    #[test]
    fn test_nd_reply_buffer_too_small() {
        let target_addr: [u8; 16] = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let request = create_neighbor_solicitation(target_addr);
        let our_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut reply = vec![0u8; 10]; // Too small
        
        let len = nd_reply(&mut reply, &request, &our_mac);
        assert_eq!(len, 0);
    }

    #[test]
    fn test_calculate_icmpv6_checksum() {
        // Simple test with known values
        let src_addr: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let dst_addr: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
        let icmpv6_data = [
            ICMPV6_NEIGHBOR_ADVERTISEMENT, // Type
            0, // Code
            0, 0, // Checksum (zeroed for calculation)
            0x60, 0, 0, 0, // Flags
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // Target
        ];
        
        let checksum = calculate_icmpv6_checksum(&src_addr, &dst_addr, &icmpv6_data);
        // Checksum should be non-zero
        assert_ne!(checksum, 0);
    }
}
