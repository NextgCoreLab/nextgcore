//! PFCP Types
//!
//! Types and constants for PFCP protocol as specified in 3GPP TS 29.244.

use crate::error::{PfcpError, PfcpResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// PFCP Version
pub const PFCP_VERSION: u8 = 1;

/// PFCP UDP port (8805)
pub const PFCP_UDP_PORT: u16 = 8805;

/// Maximum APN length
pub const MAX_APN_LEN: usize = 100;

/// Maximum network instance length
pub const MAX_NETWORK_INSTANCE_LEN: usize = 100;

/// IPv6 address length
pub const IPV6_LEN: usize = 16;

/// PFCP bitrate length (5 bytes uplink + 5 bytes downlink)
pub const PFCP_BITRATE_LEN: usize = 10;

/// PFCP Cause Values (TS 29.244 Section 8.2.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PfcpCause {
    RequestAccepted = 1,
    RequestRejected = 64,
    SessionContextNotFound = 65,
    MandatoryIeMissing = 66,
    ConditionalIeMissing = 67,
    InvalidLength = 68,
    MandatoryIeIncorrect = 69,
    InvalidForwardingPolicy = 70,
    InvalidFTeidAllocationOption = 71,
    NoEstablishedPfcpAssociation = 72,
    RuleCreationModificationFailure = 73,
    PfcpEntityInCongestion = 74,
    NoResourcesAvailable = 75,
    ServiceNotSupported = 76,
    SystemFailure = 77,
}

impl TryFrom<u8> for PfcpCause {
    type Error = PfcpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RequestAccepted),
            64 => Ok(Self::RequestRejected),
            65 => Ok(Self::SessionContextNotFound),
            66 => Ok(Self::MandatoryIeMissing),
            67 => Ok(Self::ConditionalIeMissing),
            68 => Ok(Self::InvalidLength),
            69 => Ok(Self::MandatoryIeIncorrect),
            70 => Ok(Self::InvalidForwardingPolicy),
            71 => Ok(Self::InvalidFTeidAllocationOption),
            72 => Ok(Self::NoEstablishedPfcpAssociation),
            73 => Ok(Self::RuleCreationModificationFailure),
            74 => Ok(Self::PfcpEntityInCongestion),
            75 => Ok(Self::NoResourcesAvailable),
            76 => Ok(Self::ServiceNotSupported),
            77 => Ok(Self::SystemFailure),
            _ => Err(PfcpError::InvalidCause(value)),
        }
    }
}

impl PfcpCause {
    /// Get the name of the cause
    pub fn name(&self) -> &'static str {
        match self {
            Self::RequestAccepted => "Request Accepted",
            Self::RequestRejected => "Request Rejected",
            Self::SessionContextNotFound => "Session Context Not Found",
            Self::MandatoryIeMissing => "Mandatory IE Missing",
            Self::ConditionalIeMissing => "Conditional IE Missing",
            Self::InvalidLength => "Invalid Length",
            Self::MandatoryIeIncorrect => "Mandatory IE Incorrect",
            Self::InvalidForwardingPolicy => "Invalid Forwarding Policy",
            Self::InvalidFTeidAllocationOption => "Invalid F-TEID Allocation Option",
            Self::NoEstablishedPfcpAssociation => "No Established PFCP Association",
            Self::RuleCreationModificationFailure => "Rule Creation/Modification Failure",
            Self::PfcpEntityInCongestion => "PFCP Entity in Congestion",
            Self::NoResourcesAvailable => "No Resources Available",
            Self::ServiceNotSupported => "Service Not Supported",
            Self::SystemFailure => "System Failure",
        }
    }

    /// Check if cause indicates success
    pub fn is_success(&self) -> bool {
        matches!(self, Self::RequestAccepted)
    }
}

/// Source Interface values (TS 29.244 Section 8.2.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SourceInterface {
    #[default]
    Access = 0,
    Core = 1,
    SgiLanN6Lan = 2,
    CpFunction = 3,
    FiveGVnInternal = 4,
}

impl TryFrom<u8> for SourceInterface {
    type Error = PfcpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Access),
            1 => Ok(Self::Core),
            2 => Ok(Self::SgiLanN6Lan),
            3 => Ok(Self::CpFunction),
            4 => Ok(Self::FiveGVnInternal),
            _ => Err(PfcpError::InvalidInterfaceType(value)),
        }
    }
}

/// Destination Interface values (TS 29.244 Section 8.2.24)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DestinationInterface {
    #[default]
    Access = 0,
    Core = 1,
    SgiLanN6Lan = 2,
    CpFunction = 3,
    LiFunction = 4,
    FiveGVnInternal = 5,
}

impl TryFrom<u8> for DestinationInterface {
    type Error = PfcpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Access),
            1 => Ok(Self::Core),
            2 => Ok(Self::SgiLanN6Lan),
            3 => Ok(Self::CpFunction),
            4 => Ok(Self::LiFunction),
            5 => Ok(Self::FiveGVnInternal),
            _ => Err(PfcpError::InvalidInterfaceType(value)),
        }
    }
}

/// Node ID Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeIdType {
    Ipv4 = 0,
    Ipv6 = 1,
    Fqdn = 2,
}

impl TryFrom<u8> for NodeIdType {
    type Error = PfcpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ipv4),
            1 => Ok(Self::Ipv6),
            2 => Ok(Self::Fqdn),
            _ => Err(PfcpError::InvalidNodeIdType(value)),
        }
    }
}

/// Node ID structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeId {
    pub node_id_type: NodeIdType,
    pub ipv4_addr: Option<[u8; 4]>,
    pub ipv6_addr: Option<[u8; 16]>,
    pub fqdn: Option<String>,
}

impl NodeId {
    /// Create IPv4 Node ID
    pub fn new_ipv4(addr: [u8; 4]) -> Self {
        Self {
            node_id_type: NodeIdType::Ipv4,
            ipv4_addr: Some(addr),
            ipv6_addr: None,
            fqdn: None,
        }
    }

    /// Create IPv6 Node ID
    pub fn new_ipv6(addr: [u8; 16]) -> Self {
        Self {
            node_id_type: NodeIdType::Ipv6,
            ipv4_addr: None,
            ipv6_addr: Some(addr),
            fqdn: None,
        }
    }

    /// Create FQDN Node ID
    pub fn new_fqdn(fqdn: String) -> Self {
        Self {
            node_id_type: NodeIdType::Fqdn,
            ipv4_addr: None,
            ipv6_addr: None,
            fqdn: Some(fqdn),
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.node_id_type as u8);
        match self.node_id_type {
            NodeIdType::Ipv4 => {
                if let Some(addr) = &self.ipv4_addr {
                    buf.put_slice(addr);
                }
            }
            NodeIdType::Ipv6 => {
                if let Some(addr) = &self.ipv6_addr {
                    buf.put_slice(addr);
                }
            }
            NodeIdType::Fqdn => {
                if let Some(fqdn) = &self.fqdn {
                    // Encode FQDN as RFC 1035 length-prefixed labels followed
                    // by the zero-length root label terminator (TS 29.244
                    // Section 8.2.38)
                    for label in fqdn.split('.').filter(|l| !l.is_empty()) {
                        buf.put_u8(label.len() as u8);
                        buf.put_slice(label.as_bytes());
                    }
                    buf.put_u8(0);
                }
            }
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 1 {
            return Err(PfcpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let node_id_type = NodeIdType::try_from(buf.get_u8() & 0x0F)?;

        match node_id_type {
            NodeIdType::Ipv4 => {
                if buf.remaining() < 4 {
                    return Err(PfcpError::BufferTooShort {
                        needed: 4,
                        available: buf.remaining(),
                    });
                }
                let mut addr = [0u8; 4];
                buf.copy_to_slice(&mut addr);
                Ok(Self::new_ipv4(addr))
            }
            NodeIdType::Ipv6 => {
                if buf.remaining() < 16 {
                    return Err(PfcpError::BufferTooShort {
                        needed: 16,
                        available: buf.remaining(),
                    });
                }
                let mut addr = [0u8; 16];
                buf.copy_to_slice(&mut addr);
                Ok(Self::new_ipv6(addr))
            }
            NodeIdType::Fqdn => {
                let mut fqdn = String::new();
                while buf.remaining() > 0 {
                    let len = buf.get_u8() as usize;
                    if len == 0 {
                        break;
                    }
                    if buf.remaining() < len {
                        return Err(PfcpError::BufferTooShort {
                            needed: len,
                            available: buf.remaining(),
                        });
                    }
                    if !fqdn.is_empty() {
                        fqdn.push('.');
                    }
                    let label = buf.copy_to_bytes(len);
                    fqdn.push_str(&String::from_utf8_lossy(&label));
                }
                Ok(Self::new_fqdn(fqdn))
            }
        }
    }
}

/// F-SEID (Fully Qualified SEID) structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FSeid {
    pub ipv4: bool,
    pub ipv6: bool,
    pub seid: u64,
    pub ipv4_addr: Option<[u8; 4]>,
    pub ipv6_addr: Option<[u8; 16]>,
}

impl FSeid {
    /// Create IPv4 F-SEID
    pub fn new_ipv4(seid: u64, addr: [u8; 4]) -> Self {
        Self {
            ipv4: true,
            ipv6: false,
            seid,
            ipv4_addr: Some(addr),
            ipv6_addr: None,
        }
    }

    /// Create IPv6 F-SEID
    pub fn new_ipv6(seid: u64, addr: [u8; 16]) -> Self {
        Self {
            ipv4: false,
            ipv6: true,
            seid,
            ipv4_addr: None,
            ipv6_addr: Some(addr),
        }
    }

    /// Encode to bytes
    ///
    /// TS 29.244 Section 8.2.37: octet 5 carries V4 in bit 2 (0x02) and V6 in
    /// bit 1 (0x01). Note this is the opposite bit order of F-TEID (8.2.3).
    pub fn encode(&self, buf: &mut BytesMut) {
        let flags = ((self.ipv4 as u8) << 1) | (self.ipv6 as u8);
        buf.put_u8(flags);
        buf.put_u64(self.seid);
        if let Some(addr) = &self.ipv4_addr {
            buf.put_slice(addr);
        }
        if let Some(addr) = &self.ipv6_addr {
            buf.put_slice(addr);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 9 {
            return Err(PfcpError::BufferTooShort {
                needed: 9,
                available: buf.remaining(),
            });
        }
        let flags = buf.get_u8();
        // TS 29.244 Section 8.2.37: V4 is bit 2, V6 is bit 1
        let ipv4 = (flags >> 1) & 0x01 != 0;
        let ipv6 = flags & 0x01 != 0;
        let seid = buf.get_u64();

        let ipv4_addr = if ipv4 {
            if buf.remaining() < 4 {
                return Err(PfcpError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 4];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        let ipv6_addr = if ipv6 {
            if buf.remaining() < 16 {
                return Err(PfcpError::BufferTooShort {
                    needed: 16,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 16];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        Ok(Self {
            ipv4,
            ipv6,
            seid,
            ipv4_addr,
            ipv6_addr,
        })
    }
}

/// F-TEID (Fully Qualified TEID) structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FTeid {
    pub ipv4: bool,
    pub ipv6: bool,
    pub ch: bool,   // CHOOSE bit
    pub chid: bool, // CHOOSE ID bit
    pub teid: u32,
    pub ipv4_addr: Option<[u8; 4]>,
    pub ipv6_addr: Option<[u8; 16]>,
    pub choose_id: Option<u8>,
}

impl FTeid {
    /// Create IPv4 F-TEID
    pub fn new_ipv4(teid: u32, addr: [u8; 4]) -> Self {
        Self {
            ipv4: true,
            ipv6: false,
            ch: false,
            chid: false,
            teid,
            ipv4_addr: Some(addr),
            ipv6_addr: None,
            choose_id: None,
        }
    }

    /// Create IPv6 F-TEID
    pub fn new_ipv6(teid: u32, addr: [u8; 16]) -> Self {
        Self {
            ipv4: false,
            ipv6: true,
            ch: false,
            chid: false,
            teid,
            ipv4_addr: None,
            ipv6_addr: Some(addr),
            choose_id: None,
        }
    }

    /// Create CHOOSE F-TEID (for allocation by UP function)
    pub fn new_choose(ipv4: bool, ipv6: bool, choose_id: Option<u8>) -> Self {
        Self {
            ipv4,
            ipv6,
            ch: true,
            chid: choose_id.is_some(),
            teid: 0,
            ipv4_addr: None,
            ipv6_addr: None,
            choose_id,
        }
    }

    /// Encode to bytes (TS 29.244 Section 8.2.3)
    ///
    /// When the CH (CHOOSE) flag is set, the TEID and address fields are
    /// omitted entirely; the CHOOSE ID field is present only when CHID is set.
    pub fn encode(&self, buf: &mut BytesMut) {
        let flags = ((self.chid as u8) << 3)
            | ((self.ch as u8) << 2)
            | ((self.ipv6 as u8) << 1)
            | (self.ipv4 as u8);
        buf.put_u8(flags);
        if !self.ch {
            buf.put_u32(self.teid);
            if let Some(addr) = &self.ipv4_addr {
                buf.put_slice(addr);
            }
            if let Some(addr) = &self.ipv6_addr {
                buf.put_slice(addr);
            }
        }
        if self.chid {
            buf.put_u8(self.choose_id.unwrap_or(0));
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 1 {
            return Err(PfcpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let flags = buf.get_u8();
        let ipv4 = flags & 0x01 != 0;
        let ipv6 = (flags >> 1) & 0x01 != 0;
        let ch = (flags >> 2) & 0x01 != 0;
        let chid = (flags >> 3) & 0x01 != 0;
        if chid && !ch {
            return Err(PfcpError::InvalidFormat(
                "F-TEID: CHID flag set without CH flag".to_string(),
            ));
        }
        let teid = if ch {
            // CH=1: the TEID field is not present on the wire
            0
        } else {
            if buf.remaining() < 4 {
                return Err(PfcpError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            buf.get_u32()
        };

        let ipv4_addr = if ipv4 && !ch {
            if buf.remaining() < 4 {
                return Err(PfcpError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 4];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        let ipv6_addr = if ipv6 && !ch {
            if buf.remaining() < 16 {
                return Err(PfcpError::BufferTooShort {
                    needed: 16,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 16];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        let choose_id = if chid {
            if buf.remaining() < 1 {
                return Err(PfcpError::BufferTooShort {
                    needed: 1,
                    available: buf.remaining(),
                });
            }
            Some(buf.get_u8())
        } else {
            None
        };

        Ok(Self {
            ipv4,
            ipv6,
            ch,
            chid,
            teid,
            ipv4_addr,
            ipv6_addr,
            choose_id,
        })
    }
}

/// UE IP Address structure
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UeIpAddress {
    pub ipv4: bool,
    pub ipv6: bool,
    pub sd: bool,    // Source/Destination flag
    pub ipv6d: bool, // IPv6 prefix delegation
    pub chv4: bool,  // CHOOSE IPv4
    pub chv6: bool,  // CHOOSE IPv6
    pub ipv4_addr: Option<[u8; 4]>,
    pub ipv6_addr: Option<[u8; 16]>,
    pub ipv6_prefix_delegation_bits: Option<u8>,
    pub ipv6_prefix_length: Option<u8>,
}

impl UeIpAddress {
    /// Create IPv4 UE IP Address
    pub fn new_ipv4(addr: [u8; 4], is_source: bool) -> Self {
        Self {
            ipv4: true,
            ipv6: false,
            sd: is_source,
            ipv6d: false,
            chv4: false,
            chv6: false,
            ipv4_addr: Some(addr),
            ipv6_addr: None,
            ipv6_prefix_delegation_bits: None,
            ipv6_prefix_length: None,
        }
    }

    /// Create IPv6 UE IP Address
    pub fn new_ipv6(addr: [u8; 16], is_source: bool) -> Self {
        Self {
            ipv4: false,
            ipv6: true,
            sd: is_source,
            ipv6d: false,
            chv4: false,
            chv6: false,
            ipv4_addr: None,
            ipv6_addr: Some(addr),
            ipv6_prefix_delegation_bits: None,
            ipv6_prefix_length: None,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let flags = ((self.chv6 as u8) << 5)
            | ((self.chv4 as u8) << 4)
            | ((self.ipv6d as u8) << 3)
            | ((self.sd as u8) << 2)
            | ((self.ipv6 as u8) << 1)
            | (self.ipv4 as u8);
        buf.put_u8(flags);
        if let Some(addr) = &self.ipv4_addr {
            buf.put_slice(addr);
        }
        if let Some(addr) = &self.ipv6_addr {
            buf.put_slice(addr);
        }
        if let Some(bits) = self.ipv6_prefix_delegation_bits {
            buf.put_u8(bits);
        }
        if let Some(len) = self.ipv6_prefix_length {
            buf.put_u8(len);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 1 {
            return Err(PfcpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let flags = buf.get_u8();
        let ipv4 = flags & 0x01 != 0;
        let ipv6 = (flags >> 1) & 0x01 != 0;
        let sd = (flags >> 2) & 0x01 != 0;
        let ipv6d = (flags >> 3) & 0x01 != 0;
        let chv4 = (flags >> 4) & 0x01 != 0;
        let chv6 = (flags >> 5) & 0x01 != 0;

        let ipv4_addr = if ipv4 && !chv4 {
            if buf.remaining() < 4 {
                return Err(PfcpError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 4];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        let ipv6_addr = if ipv6 && !chv6 {
            if buf.remaining() < 16 {
                return Err(PfcpError::BufferTooShort {
                    needed: 16,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 16];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        let ipv6_prefix_delegation_bits = if ipv6d && buf.remaining() > 0 {
            Some(buf.get_u8())
        } else {
            None
        };

        let ipv6_prefix_length = if ipv6 && buf.remaining() > 0 {
            Some(buf.get_u8())
        } else {
            None
        };

        Ok(Self {
            ipv4,
            ipv6,
            sd,
            ipv6d,
            chv4,
            chv6,
            ipv4_addr,
            ipv6_addr,
            ipv6_prefix_delegation_bits,
            ipv6_prefix_length,
        })
    }
}

/// Apply Action flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplyAction {
    pub drop: bool,
    pub forw: bool, // Forward
    pub buff: bool, // Buffer
    pub nocp: bool, // Notify CP function
    pub dupl: bool, // Duplicate
    pub ipma: bool, // IP Multicast Accept
    pub ipmd: bool, // IP Multicast Deny
    pub dfrt: bool, // Duplicate for Redundant Transmission
    pub edrt: bool, // Eliminate Duplicate for Redundant Transmission
    pub bdpn: bool, // Buffered Downlink Packet Notification
    pub ddpn: bool, // Discarded Downlink Packet Notification
}

impl ApplyAction {
    /// Create DROP action
    pub fn drop() -> Self {
        Self {
            drop: true,
            ..Default::default()
        }
    }

    /// Create FORWARD action
    pub fn forward() -> Self {
        Self {
            forw: true,
            ..Default::default()
        }
    }

    /// Create BUFFER action
    pub fn buffer() -> Self {
        Self {
            buff: true,
            ..Default::default()
        }
    }

    /// Encode the flags to a packed u16 (logical layout, NOT wire order):
    /// low byte = TS 29.244 §8.2.26 octet 5 (DROP..DFRT), high byte = octet 6
    /// (EDRT/BDPN/DDPN). Use [`encode_ie`](Self::encode_ie) to emit on the wire.
    pub fn encode(&self) -> u16 {
        ((self.ddpn as u16) << 10)
            | ((self.bdpn as u16) << 9)
            | ((self.edrt as u16) << 8)
            | ((self.dfrt as u16) << 7)
            | ((self.ipmd as u16) << 6)
            | ((self.ipma as u16) << 5)
            | ((self.dupl as u16) << 4)
            | ((self.nocp as u16) << 3)
            | ((self.buff as u16) << 2)
            | ((self.forw as u16) << 1)
            | (self.drop as u16)
    }

    /// Decode from bytes
    pub fn decode(value: u16) -> Self {
        Self {
            drop: value & 0x01 != 0,
            forw: (value >> 1) & 0x01 != 0,
            buff: (value >> 2) & 0x01 != 0,
            nocp: (value >> 3) & 0x01 != 0,
            dupl: (value >> 4) & 0x01 != 0,
            ipma: (value >> 5) & 0x01 != 0,
            ipmd: (value >> 6) & 0x01 != 0,
            dfrt: (value >> 7) & 0x01 != 0,
            edrt: (value >> 8) & 0x01 != 0,
            bdpn: (value >> 9) & 0x01 != 0,
            ddpn: (value >> 10) & 0x01 != 0,
        }
    }

    /// Encode as a complete Apply Action IE (type + length + payload) with the
    /// correct TS 29.244 §8.2.26 wire octet order: octet 5 (DROP..DFRT) is
    /// transmitted first, then octet 6 (EDRT/BDPN/DDPN).
    pub fn encode_ie(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_bytes_ie, IeType};
        let v = self.encode();
        encode_bytes_ie(buf, IeType::ApplyAction, &[(v & 0xFF) as u8, (v >> 8) as u8]);
    }

    /// Decode the Apply Action IE payload from its wire octets (octet 5 first,
    /// then octet 6), inverse of [`encode_ie`](Self::encode_ie).
    pub fn decode_ie(data: &[u8]) -> Self {
        let octet5 = data.first().copied().unwrap_or(0);
        let octet6 = data.get(1).copied().unwrap_or(0);
        Self::decode((octet5 as u16) | ((octet6 as u16) << 8))
    }
}

/// Outer Header Removal description
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum OuterHeaderRemovalDescription {
    #[default]
    GtpUUdpIpv4 = 0,
    GtpUUdpIpv6 = 1,
    UdpIpv4 = 2,
    UdpIpv6 = 3,
    Ipv4 = 4,
    Ipv6 = 5,
    GtpUUdpIp = 6,
    VlanSTag = 7,
    STagAndCTag = 8,
}

/// Outer Header Removal structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OuterHeaderRemoval {
    pub description: OuterHeaderRemovalDescription,
    pub pdu_session_container: bool,
}

impl OuterHeaderRemoval {
    pub fn new(description: OuterHeaderRemovalDescription) -> Self {
        Self {
            description,
            pdu_session_container: false,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.description as u8);
        if self.pdu_session_container {
            buf.put_u8(0x01);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 1 {
            return Err(PfcpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let desc = buf.get_u8();
        let pdu_session_container = if buf.remaining() > 0 {
            buf.get_u8() & 0x01 != 0
        } else {
            false
        };
        Ok(Self {
            description: match desc {
                0 => OuterHeaderRemovalDescription::GtpUUdpIpv4,
                1 => OuterHeaderRemovalDescription::GtpUUdpIpv6,
                2 => OuterHeaderRemovalDescription::UdpIpv4,
                3 => OuterHeaderRemovalDescription::UdpIpv6,
                4 => OuterHeaderRemovalDescription::Ipv4,
                5 => OuterHeaderRemovalDescription::Ipv6,
                6 => OuterHeaderRemovalDescription::GtpUUdpIp,
                7 => OuterHeaderRemovalDescription::VlanSTag,
                8 => OuterHeaderRemovalDescription::STagAndCTag,
                _ => OuterHeaderRemovalDescription::GtpUUdpIpv4,
            },
            pdu_session_container,
        })
    }
}

/// Outer Header Creation description
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OuterHeaderCreationDescription {
    pub gtpu_udp_ipv4: bool,
    pub gtpu_udp_ipv6: bool,
    pub udp_ipv4: bool,
    pub udp_ipv6: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub c_tag: bool,
    pub s_tag: bool,
    pub n19: bool,
    pub n6: bool,
}

/// Outer Header Creation structure
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OuterHeaderCreation {
    pub description: OuterHeaderCreationDescription,
    pub teid: Option<u32>,
    pub ipv4_addr: Option<[u8; 4]>,
    pub ipv6_addr: Option<[u8; 16]>,
    pub port_number: Option<u16>,
    pub c_tag: Option<[u8; 3]>,
    pub s_tag: Option<[u8; 3]>,
}

impl OuterHeaderCreation {
    /// Create GTP-U/UDP/IPv4 outer header
    pub fn new_gtpu_ipv4(teid: u32, addr: [u8; 4]) -> Self {
        Self {
            description: OuterHeaderCreationDescription {
                gtpu_udp_ipv4: true,
                ..Default::default()
            },
            teid: Some(teid),
            ipv4_addr: Some(addr),
            ..Default::default()
        }
    }

    /// Create GTP-U/UDP/IPv6 outer header
    pub fn new_gtpu_ipv6(teid: u32, addr: [u8; 16]) -> Self {
        Self {
            description: OuterHeaderCreationDescription {
                gtpu_udp_ipv6: true,
                ..Default::default()
            },
            teid: Some(teid),
            ipv6_addr: Some(addr),
            ..Default::default()
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let desc = ((self.description.n6 as u16) << 9)
            | ((self.description.n19 as u16) << 8)
            | ((self.description.s_tag as u16) << 7)
            | ((self.description.c_tag as u16) << 6)
            | ((self.description.ipv6 as u16) << 5)
            | ((self.description.ipv4 as u16) << 4)
            | ((self.description.udp_ipv6 as u16) << 3)
            | ((self.description.udp_ipv4 as u16) << 2)
            | ((self.description.gtpu_udp_ipv6 as u16) << 1)
            | (self.description.gtpu_udp_ipv4 as u16);
        buf.put_u16(desc);
        if let Some(teid) = self.teid {
            buf.put_u32(teid);
        }
        if let Some(addr) = &self.ipv4_addr {
            buf.put_slice(addr);
        }
        if let Some(addr) = &self.ipv6_addr {
            buf.put_slice(addr);
        }
        if let Some(port) = self.port_number {
            buf.put_u16(port);
        }
        if let Some(tag) = &self.c_tag {
            buf.put_slice(tag);
        }
        if let Some(tag) = &self.s_tag {
            buf.put_slice(tag);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 2 {
            return Err(PfcpError::BufferTooShort {
                needed: 2,
                available: buf.remaining(),
            });
        }
        let desc_val = buf.get_u16();
        let description = OuterHeaderCreationDescription {
            gtpu_udp_ipv4: desc_val & 0x01 != 0,
            gtpu_udp_ipv6: (desc_val >> 1) & 0x01 != 0,
            udp_ipv4: (desc_val >> 2) & 0x01 != 0,
            udp_ipv6: (desc_val >> 3) & 0x01 != 0,
            ipv4: (desc_val >> 4) & 0x01 != 0,
            ipv6: (desc_val >> 5) & 0x01 != 0,
            c_tag: (desc_val >> 6) & 0x01 != 0,
            s_tag: (desc_val >> 7) & 0x01 != 0,
            n19: (desc_val >> 8) & 0x01 != 0,
            n6: (desc_val >> 9) & 0x01 != 0,
        };

        let teid = if description.gtpu_udp_ipv4 || description.gtpu_udp_ipv6 {
            if buf.remaining() < 4 {
                return Err(PfcpError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            Some(buf.get_u32())
        } else {
            None
        };

        let ipv4_addr = if description.gtpu_udp_ipv4 || description.udp_ipv4 || description.ipv4 {
            if buf.remaining() < 4 {
                return Err(PfcpError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 4];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        let ipv6_addr = if description.gtpu_udp_ipv6 || description.udp_ipv6 || description.ipv6 {
            if buf.remaining() < 16 {
                return Err(PfcpError::BufferTooShort {
                    needed: 16,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 16];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        let port_number = if description.udp_ipv4 || description.udp_ipv6 {
            if buf.remaining() < 2 {
                return Err(PfcpError::BufferTooShort {
                    needed: 2,
                    available: buf.remaining(),
                });
            }
            Some(buf.get_u16())
        } else {
            None
        };

        let c_tag = if description.c_tag && buf.remaining() >= 3 {
            let mut tag = [0u8; 3];
            buf.copy_to_slice(&mut tag);
            Some(tag)
        } else {
            None
        };

        let s_tag = if description.s_tag && buf.remaining() >= 3 {
            let mut tag = [0u8; 3];
            buf.copy_to_slice(&mut tag);
            Some(tag)
        } else {
            None
        };

        Ok(Self {
            description,
            teid,
            ipv4_addr,
            ipv6_addr,
            port_number,
            c_tag,
            s_tag,
        })
    }
}

/// Gate Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GateStatus {
    pub ul_gate: bool, // true = open, false = closed
    pub dl_gate: bool, // true = open, false = closed
}

impl GateStatus {
    pub fn both_open() -> Self {
        Self {
            ul_gate: true,
            dl_gate: true,
        }
    }

    pub fn both_closed() -> Self {
        Self {
            ul_gate: false,
            dl_gate: false,
        }
    }

    pub fn encode(&self) -> u8 {
        let ul = if self.ul_gate { 0 } else { 1 };
        let dl = if self.dl_gate { 0 } else { 1 };
        (ul << 2) | dl
    }

    pub fn decode(value: u8) -> Self {
        Self {
            ul_gate: (value >> 2) & 0x03 == 0,
            dl_gate: value & 0x03 == 0,
        }
    }
}

/// Bitrate structure (MBR/GBR)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bitrate {
    pub uplink: u64,   // bits per second
    pub downlink: u64, // bits per second
}

impl Bitrate {
    pub fn new(uplink: u64, downlink: u64) -> Self {
        Self { uplink, downlink }
    }

    /// Encode to bytes (10 bytes: 5 for uplink, 5 for downlink in kbps)
    pub fn encode(&self, buf: &mut BytesMut) {
        // Convert bps to kbps, rounding up
        let ul_kbps = (self.uplink / 1000)
            + if !self.uplink.is_multiple_of(1000) {
                1
            } else {
                0
            };
        let dl_kbps = (self.downlink / 1000)
            + if !self.downlink.is_multiple_of(1000) {
                1
            } else {
                0
            };

        // Write as 5-byte big-endian values
        buf.put_u8((ul_kbps >> 32) as u8);
        buf.put_u32(ul_kbps as u32);
        buf.put_u8((dl_kbps >> 32) as u8);
        buf.put_u32(dl_kbps as u32);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < PFCP_BITRATE_LEN {
            return Err(PfcpError::BufferTooShort {
                needed: PFCP_BITRATE_LEN,
                available: buf.remaining(),
            });
        }
        let ul_high = buf.get_u8() as u64;
        let ul_low = buf.get_u32() as u64;
        let ul_kbps = (ul_high << 32) | ul_low;

        let dl_high = buf.get_u8() as u64;
        let dl_low = buf.get_u32() as u64;
        let dl_kbps = (dl_high << 32) | dl_low;

        Ok(Self {
            uplink: ul_kbps * 1000,
            downlink: dl_kbps * 1000,
        })
    }
}

/// Volume Threshold/Quota structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VolumeThreshold {
    pub tovol: bool, // Total Volume present
    pub ulvol: bool, // Uplink Volume present
    pub dlvol: bool, // Downlink Volume present
    pub total_volume: u64,
    pub uplink_volume: u64,
    pub downlink_volume: u64,
}

impl VolumeThreshold {
    pub fn new_total(volume: u64) -> Self {
        Self {
            tovol: true,
            total_volume: volume,
            ..Default::default()
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let flags = ((self.dlvol as u8) << 2) | ((self.ulvol as u8) << 1) | (self.tovol as u8);
        buf.put_u8(flags);
        if self.tovol {
            buf.put_u64(self.total_volume);
        }
        if self.ulvol {
            buf.put_u64(self.uplink_volume);
        }
        if self.dlvol {
            buf.put_u64(self.downlink_volume);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 1 {
            return Err(PfcpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let flags = buf.get_u8();
        let tovol = flags & 0x01 != 0;
        let ulvol = (flags >> 1) & 0x01 != 0;
        let dlvol = (flags >> 2) & 0x01 != 0;

        let total_volume = if tovol {
            if buf.remaining() < 8 {
                return Err(PfcpError::BufferTooShort {
                    needed: 8,
                    available: buf.remaining(),
                });
            }
            buf.get_u64()
        } else {
            0
        };

        let uplink_volume = if ulvol {
            if buf.remaining() < 8 {
                return Err(PfcpError::BufferTooShort {
                    needed: 8,
                    available: buf.remaining(),
                });
            }
            buf.get_u64()
        } else {
            0
        };

        let downlink_volume = if dlvol {
            if buf.remaining() < 8 {
                return Err(PfcpError::BufferTooShort {
                    needed: 8,
                    available: buf.remaining(),
                });
            }
            buf.get_u64()
        } else {
            0
        };

        Ok(Self {
            tovol,
            ulvol,
            dlvol,
            total_volume,
            uplink_volume,
            downlink_volume,
        })
    }
}

/// Volume Measurement structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VolumeMeasurement {
    pub tovol: bool,
    pub ulvol: bool,
    pub dlvol: bool,
    pub tonop: bool, // Total Number of Packets
    pub ulnop: bool, // Uplink Number of Packets
    pub dlnop: bool, // Downlink Number of Packets
    pub total_volume: u64,
    pub uplink_volume: u64,
    pub downlink_volume: u64,
    pub total_n_packets: u64,
    pub uplink_n_packets: u64,
    pub downlink_n_packets: u64,
}

impl VolumeMeasurement {
    pub fn encode(&self, buf: &mut BytesMut) {
        let flags = ((self.dlnop as u8) << 5)
            | ((self.ulnop as u8) << 4)
            | ((self.tonop as u8) << 3)
            | ((self.dlvol as u8) << 2)
            | ((self.ulvol as u8) << 1)
            | (self.tovol as u8);
        buf.put_u8(flags);
        if self.tovol {
            buf.put_u64(self.total_volume);
        }
        if self.ulvol {
            buf.put_u64(self.uplink_volume);
        }
        if self.dlvol {
            buf.put_u64(self.downlink_volume);
        }
        if self.tonop {
            buf.put_u64(self.total_n_packets);
        }
        if self.ulnop {
            buf.put_u64(self.uplink_n_packets);
        }
        if self.dlnop {
            buf.put_u64(self.downlink_n_packets);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 1 {
            return Err(PfcpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let flags = buf.get_u8();
        let mut result = Self {
            tovol: flags & 0x01 != 0,
            ulvol: (flags >> 1) & 0x01 != 0,
            dlvol: (flags >> 2) & 0x01 != 0,
            tonop: (flags >> 3) & 0x01 != 0,
            ulnop: (flags >> 4) & 0x01 != 0,
            dlnop: (flags >> 5) & 0x01 != 0,
            ..Default::default()
        };
        let get_field = |buf: &mut Bytes| -> PfcpResult<u64> {
            if buf.remaining() < 8 {
                return Err(PfcpError::BufferTooShort {
                    needed: 8,
                    available: buf.remaining(),
                });
            }
            Ok(buf.get_u64())
        };
        if result.tovol {
            result.total_volume = get_field(buf)?;
        }
        if result.ulvol {
            result.uplink_volume = get_field(buf)?;
        }
        if result.dlvol {
            result.downlink_volume = get_field(buf)?;
        }
        if result.tonop {
            result.total_n_packets = get_field(buf)?;
        }
        if result.ulnop {
            result.uplink_n_packets = get_field(buf)?;
        }
        if result.dlnop {
            result.downlink_n_packets = get_field(buf)?;
        }
        Ok(result)
    }
}

/// Reporting Triggers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReportingTriggers {
    pub perio: bool, // Periodic Reporting
    pub volth: bool, // Volume Threshold
    pub timth: bool, // Time Threshold
    pub quhti: bool, // Quota Holding Time
    pub start: bool, // Start of Traffic
    pub stopt: bool, // Stop of Traffic
    pub droth: bool, // Dropped DL Traffic Threshold
    pub liusa: bool, // Linked Usage Reporting
    pub volqu: bool, // Volume Quota
    pub timqu: bool, // Time Quota
    pub envcl: bool, // Envelope Closure
    pub macar: bool, // MAC Addresses Reporting
    pub eveth: bool, // Event Threshold
    pub evequ: bool, // Event Quota
    pub ipmjl: bool, // IP Multicast Join/Leave
    pub quvti: bool, // Quota Validity Time
    pub reemr: bool, // REport the End Marker Reception
    pub upint: bool, // User Plane Inactivity Timer
}

impl ReportingTriggers {
    /// Encode to the 3-octet bitmask of TS 29.244 Section 8.2.19 (Rel-16)
    ///
    /// Octet 5: LIUSA DROTH STOPT START QUHTI TIMTH VOLTH PERIO
    /// Octet 6: QUVTI IPMJL EVEQU EVETH MACAR ENVCL TIMQU VOLQU
    /// Octet 7: spare(6) UPINT REEMR
    pub fn encode(&self) -> [u8; 3] {
        let b0 = ((self.liusa as u8) << 7)
            | ((self.droth as u8) << 6)
            | ((self.stopt as u8) << 5)
            | ((self.start as u8) << 4)
            | ((self.quhti as u8) << 3)
            | ((self.timth as u8) << 2)
            | ((self.volth as u8) << 1)
            | (self.perio as u8);
        let b1 = ((self.quvti as u8) << 7)
            | ((self.ipmjl as u8) << 6)
            | ((self.evequ as u8) << 5)
            | ((self.eveth as u8) << 4)
            | ((self.macar as u8) << 3)
            | ((self.envcl as u8) << 2)
            | ((self.timqu as u8) << 1)
            | (self.volqu as u8);
        let b2 = ((self.upint as u8) << 1) | (self.reemr as u8);
        [b0, b1, b2]
    }

    /// Decode from the wire bitmask (2 octets for Rel-15 peers, 3 for Rel-16+)
    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.len() < 2 {
            return Err(PfcpError::BufferTooShort {
                needed: 2,
                available: data.len(),
            });
        }
        let b0 = data[0];
        let b1 = data[1];
        let b2 = if data.len() >= 3 { data[2] } else { 0 };
        Ok(Self {
            perio: b0 & 0x01 != 0,
            volth: (b0 >> 1) & 0x01 != 0,
            timth: (b0 >> 2) & 0x01 != 0,
            quhti: (b0 >> 3) & 0x01 != 0,
            start: (b0 >> 4) & 0x01 != 0,
            stopt: (b0 >> 5) & 0x01 != 0,
            droth: (b0 >> 6) & 0x01 != 0,
            liusa: (b0 >> 7) & 0x01 != 0,
            volqu: b1 & 0x01 != 0,
            timqu: (b1 >> 1) & 0x01 != 0,
            envcl: (b1 >> 2) & 0x01 != 0,
            macar: (b1 >> 3) & 0x01 != 0,
            eveth: (b1 >> 4) & 0x01 != 0,
            evequ: (b1 >> 5) & 0x01 != 0,
            ipmjl: (b1 >> 6) & 0x01 != 0,
            quvti: (b1 >> 7) & 0x01 != 0,
            reemr: b2 & 0x01 != 0,
            upint: (b2 >> 1) & 0x01 != 0,
        })
    }
}

/// Report Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReportType {
    pub dldr: bool, // Downlink Data Report
    pub usar: bool, // Usage Report
    pub erir: bool, // Error Indication Report
    pub upir: bool, // User Plane Inactivity Report
    pub tmir: bool, // TSC Management Information Report
    pub sesr: bool, // Session Report
    pub uisr: bool, // UE IP address usage Information Report
}

impl ReportType {
    pub fn encode(&self) -> u8 {
        ((self.uisr as u8) << 6)
            | ((self.sesr as u8) << 5)
            | ((self.tmir as u8) << 4)
            | ((self.upir as u8) << 3)
            | ((self.erir as u8) << 2)
            | ((self.usar as u8) << 1)
            | (self.dldr as u8)
    }

    pub fn decode(val: u8) -> Self {
        Self {
            dldr: val & 0x01 != 0,
            usar: (val >> 1) & 0x01 != 0,
            erir: (val >> 2) & 0x01 != 0,
            upir: (val >> 3) & 0x01 != 0,
            tmir: (val >> 4) & 0x01 != 0,
            sesr: (val >> 5) & 0x01 != 0,
            uisr: (val >> 6) & 0x01 != 0,
        }
    }
}

/// UP Function Features
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpFunctionFeatures {
    pub bucp: bool,     // Downlink Data Buffering in CP function
    pub ddnd: bool,     // Buffered Downlink Data Notification Delay
    pub dlbd: bool,     // DL Buffering Duration
    pub trst: bool,     // Traffic Steering
    pub ftup: bool,     // F-TEID allocation/release in the UP function
    pub pfdm: bool,     // PFD Management procedure
    pub heeu: bool,     // Header Enrichment of Uplink traffic
    pub treu: bool,     // Traffic Redirection Enforcement in the UP function
    pub empu: bool,     // Sending End Marker packets supported by UP function
    pub pdiu: bool,     // Support of PDI optimised signalling
    pub udbc: bool,     // Support of UL/DL Buffering Control
    pub quoac: bool,    // Support of Quota Action
    pub trace: bool,    // Support of Trace
    pub frrt: bool,     // Support of Framed Routing
    pub pfde: bool,     // Support of PFD for Ethernet
    pub epfar: bool,    // Support of Extended PDR for Ethernet
    pub dpdra: bool,    // Support of Deferred PDR Activation
    pub adpdp: bool,    // Support of Activation and Deactivation of Pre-defined PDRs
    pub ueip: bool,     // Support of UE IP address allocation
    pub sset: bool,     // Support of PFCP sessions successively controlled by different SMFs
    pub mnop: bool,     // Support of Measurement of Number of Packets
    pub mte: bool,      // Support of Measurement of Time
    pub bundl: bool,    // Support of PFCP Session Bundling
    pub gcom: bool,     // Support of 5G VN Group Communication
    pub mpas: bool,     // Support of Multiple PFCP Associations
    pub rttl: bool,     // Support of Redundant Transmission at Transport Layer
    pub vtime: bool,    // Support of quota validity time
    pub norp: bool,     // Support of Number of Reports
    pub iptv: bool,     // Support of IPTV
    pub ip6pl: bool,    // Support of IPv6 prefix length
    pub tscu: bool,     // Support of Time Sensitive Communication
    pub mptcp: bool,    // Support of MPTCP Proxy functionality
    pub atsss_ll: bool, // Support of ATSSS-LL steering functionality
    pub qfqm: bool,     // Support of per QoS flow per UE QoS monitoring
    pub gpqm: bool,     // Support of per GTP-U Path QoS monitoring
    pub mt_edt: bool,   // Support of MT-EDT
    pub ciot: bool,     // Support of CIoT
    pub ethar: bool,    // Support of Ethernet Address Reporting
    pub ddds: bool,     // Support of Downlink Data Delivery Status
    pub rds: bool,      // Support of Reliable Data Service
    pub rttwp: bool,    // Support of RTT measurement without PMF
    pub quasf: bool,    // Support of Quota Action to apply when SMF is restored
    pub nspoc: bool,    // Support of Notify Start of Pause of Charging
    pub l2tp: bool,     // Support of L2TP
    pub upber: bool,    // Support of UP function sending of Buffer Error Report
    pub resps: bool,    // Support of Restoration of PFCP Session association
    pub iprep: bool,    // Support of IP Address and Port number Replacement
    pub dnsts: bool,    // Support of DNS Server Address Reporting
    pub drqos: bool,    // Support of Direct Reporting of QoS monitoring events
    pub mbsn4: bool,    // Support of MBS N4
    pub psuprm: bool,   // Support of Per Slice UP Resource Management
    pub eppi: bool,     // Support of Enhanced PDI for Paging Policy Indication
}

impl UpFunctionFeatures {
    /// Number of feature octets emitted on the wire (octets 5-12 of the IE)
    pub const ENCODED_LEN: usize = 8;

    /// Minimum feature octets accepted from a peer (octets 5-10, Rel-16)
    pub const MIN_LEN: usize = 6;

    /// Encode the full 8-octet bitmask (TS 29.244 Section 8.2.25)
    ///
    /// Octet 5:  TREU HEEU PFDM FTUP TRST DLBD DDND BUCP
    /// Octet 6:  EPFAR PFDE FRRT TRACE QUOAC UDBC PDIU EMPU
    /// Octet 7:  GCOM BUNDL MTE MNOP SSET UEIP ADPDP DPDRA
    /// Octet 8:  MPTCP TSCU IP6PL IPTV NORP VTIME RTTL MPAS
    /// Octet 9:  RDS DDDS ETHAR CIOT MT-EDT GPQM QFQM ATSSS-LL
    /// Octet 10: DNSTS IPREP RESPS UPBER L2TP NSPOC QUASF RTTWP
    /// Octet 11: spare(4) EPPI PSUPRM MBSN4 DRQOS
    /// Octet 12: spare
    pub fn encode(&self, buf: &mut BytesMut) {
        let b0 = ((self.treu as u8) << 7)
            | ((self.heeu as u8) << 6)
            | ((self.pfdm as u8) << 5)
            | ((self.ftup as u8) << 4)
            | ((self.trst as u8) << 3)
            | ((self.dlbd as u8) << 2)
            | ((self.ddnd as u8) << 1)
            | (self.bucp as u8);
        let b1 = ((self.epfar as u8) << 7)
            | ((self.pfde as u8) << 6)
            | ((self.frrt as u8) << 5)
            | ((self.trace as u8) << 4)
            | ((self.quoac as u8) << 3)
            | ((self.udbc as u8) << 2)
            | ((self.pdiu as u8) << 1)
            | (self.empu as u8);
        let b2 = ((self.gcom as u8) << 7)
            | ((self.bundl as u8) << 6)
            | ((self.mte as u8) << 5)
            | ((self.mnop as u8) << 4)
            | ((self.sset as u8) << 3)
            | ((self.ueip as u8) << 2)
            | ((self.adpdp as u8) << 1)
            | (self.dpdra as u8);
        let b3 = ((self.mptcp as u8) << 7)
            | ((self.tscu as u8) << 6)
            | ((self.ip6pl as u8) << 5)
            | ((self.iptv as u8) << 4)
            | ((self.norp as u8) << 3)
            | ((self.vtime as u8) << 2)
            | ((self.rttl as u8) << 1)
            | (self.mpas as u8);
        let b4 = ((self.rds as u8) << 7)
            | ((self.ddds as u8) << 6)
            | ((self.ethar as u8) << 5)
            | ((self.ciot as u8) << 4)
            | ((self.mt_edt as u8) << 3)
            | ((self.gpqm as u8) << 2)
            | ((self.qfqm as u8) << 1)
            | (self.atsss_ll as u8);
        let b5 = ((self.dnsts as u8) << 7)
            | ((self.iprep as u8) << 6)
            | ((self.resps as u8) << 5)
            | ((self.upber as u8) << 4)
            | ((self.l2tp as u8) << 3)
            | ((self.nspoc as u8) << 2)
            | ((self.quasf as u8) << 1)
            | (self.rttwp as u8);
        let b6 = ((self.eppi as u8) << 3)
            | ((self.psuprm as u8) << 2)
            | ((self.mbsn4 as u8) << 1)
            | (self.drqos as u8);
        buf.put_slice(&[b0, b1, b2, b3, b4, b5, b6, 0]);
    }

    /// Decode from bytes
    ///
    /// Strict on length: at least the 6 octets of the Rel-16 bitmask are
    /// required; legacy 2/4-octet encodings are rejected. The Rel-17
    /// additional octets (11-12) are parsed when present.
    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < Self::MIN_LEN {
            return Err(PfcpError::BufferTooShort {
                needed: Self::MIN_LEN,
                available: buf.remaining(),
            });
        }
        let b0 = buf.get_u8();
        let b1 = buf.get_u8();
        let b2 = buf.get_u8();
        let b3 = buf.get_u8();
        let b4 = buf.get_u8();
        let b5 = buf.get_u8();
        let b6 = if buf.remaining() >= 1 {
            buf.get_u8()
        } else {
            0
        };

        Ok(Self {
            bucp: b0 & 0x01 != 0,
            ddnd: (b0 >> 1) & 0x01 != 0,
            dlbd: (b0 >> 2) & 0x01 != 0,
            trst: (b0 >> 3) & 0x01 != 0,
            ftup: (b0 >> 4) & 0x01 != 0,
            pfdm: (b0 >> 5) & 0x01 != 0,
            heeu: (b0 >> 6) & 0x01 != 0,
            treu: (b0 >> 7) & 0x01 != 0,
            empu: b1 & 0x01 != 0,
            pdiu: (b1 >> 1) & 0x01 != 0,
            udbc: (b1 >> 2) & 0x01 != 0,
            quoac: (b1 >> 3) & 0x01 != 0,
            trace: (b1 >> 4) & 0x01 != 0,
            frrt: (b1 >> 5) & 0x01 != 0,
            pfde: (b1 >> 6) & 0x01 != 0,
            epfar: (b1 >> 7) & 0x01 != 0,
            dpdra: b2 & 0x01 != 0,
            adpdp: (b2 >> 1) & 0x01 != 0,
            ueip: (b2 >> 2) & 0x01 != 0,
            sset: (b2 >> 3) & 0x01 != 0,
            mnop: (b2 >> 4) & 0x01 != 0,
            mte: (b2 >> 5) & 0x01 != 0,
            bundl: (b2 >> 6) & 0x01 != 0,
            gcom: (b2 >> 7) & 0x01 != 0,
            mpas: b3 & 0x01 != 0,
            rttl: (b3 >> 1) & 0x01 != 0,
            vtime: (b3 >> 2) & 0x01 != 0,
            norp: (b3 >> 3) & 0x01 != 0,
            iptv: (b3 >> 4) & 0x01 != 0,
            ip6pl: (b3 >> 5) & 0x01 != 0,
            tscu: (b3 >> 6) & 0x01 != 0,
            mptcp: (b3 >> 7) & 0x01 != 0,
            atsss_ll: b4 & 0x01 != 0,
            qfqm: (b4 >> 1) & 0x01 != 0,
            gpqm: (b4 >> 2) & 0x01 != 0,
            mt_edt: (b4 >> 3) & 0x01 != 0,
            ciot: (b4 >> 4) & 0x01 != 0,
            ethar: (b4 >> 5) & 0x01 != 0,
            ddds: (b4 >> 6) & 0x01 != 0,
            rds: (b4 >> 7) & 0x01 != 0,
            rttwp: b5 & 0x01 != 0,
            quasf: (b5 >> 1) & 0x01 != 0,
            nspoc: (b5 >> 2) & 0x01 != 0,
            l2tp: (b5 >> 3) & 0x01 != 0,
            upber: (b5 >> 4) & 0x01 != 0,
            resps: (b5 >> 5) & 0x01 != 0,
            iprep: (b5 >> 6) & 0x01 != 0,
            dnsts: (b5 >> 7) & 0x01 != 0,
            drqos: b6 & 0x01 != 0,
            mbsn4: (b6 >> 1) & 0x01 != 0,
            psuprm: (b6 >> 2) & 0x01 != 0,
            eppi: (b6 >> 3) & 0x01 != 0,
        })
    }
}

/// CP Function Features
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpFunctionFeatures {
    pub load: bool,  // Load Control
    pub ovrl: bool,  // Overload Control
    pub epfar: bool, // Extended PDR for Ethernet
    pub sset: bool,  // PFCP sessions successively controlled by different SMFs
    pub bundl: bool, // PFCP Session Bundling
    pub mpas: bool,  // Multiple PFCP Associations
    pub ardr: bool,  // Additional Redundant Transmission
    pub uiaur: bool, // UE IP Address Usage Reporting
    pub psucc: bool, // PFCP Session Update Continuation
}

impl CpFunctionFeatures {
    /// Encode the 2-octet bitmask (TS 29.244 Section 8.2.58)
    ///
    /// Octet 5: UIAUR ARDR MPAS BUNDL SSET EPFAR OVRL LOAD
    /// Octet 6: spare(7) PSUCC
    pub fn encode(&self, buf: &mut BytesMut) {
        let b0 = ((self.uiaur as u8) << 7)
            | ((self.ardr as u8) << 6)
            | ((self.mpas as u8) << 5)
            | ((self.bundl as u8) << 4)
            | ((self.sset as u8) << 3)
            | ((self.epfar as u8) << 2)
            | ((self.ovrl as u8) << 1)
            | (self.load as u8);
        let b1 = self.psucc as u8;
        buf.put_slice(&[b0, b1]);
    }

    /// Decode from bytes (octet 6 is absent on Rel-15 peers)
    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.is_empty() {
            return Err(PfcpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        let b0 = data[0];
        let b1 = if data.len() >= 2 { data[1] } else { 0 };
        Ok(Self {
            load: b0 & 0x01 != 0,
            ovrl: (b0 >> 1) & 0x01 != 0,
            epfar: (b0 >> 2) & 0x01 != 0,
            sset: (b0 >> 3) & 0x01 != 0,
            bundl: (b0 >> 4) & 0x01 != 0,
            mpas: (b0 >> 5) & 0x01 != 0,
            ardr: (b0 >> 6) & 0x01 != 0,
            uiaur: (b0 >> 7) & 0x01 != 0,
            psucc: b1 & 0x01 != 0,
        })
    }
}

/// Measurement Method flags (TS 29.244 Section 8.2.40)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeasurementMethod {
    pub durat: bool, // Duration
    pub volum: bool, // Volume
    pub event: bool, // Event
}

impl MeasurementMethod {
    pub fn encode(&self) -> u8 {
        ((self.event as u8) << 2) | ((self.volum as u8) << 1) | (self.durat as u8)
    }

    pub fn decode(val: u8) -> Self {
        Self {
            durat: val & 0x01 != 0,
            volum: (val >> 1) & 0x01 != 0,
            event: (val >> 2) & 0x01 != 0,
        }
    }
}

/// PDI (Packet Detection Information) - grouped IE within PDR
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdi {
    pub source_interface: SourceInterface,
    pub local_f_teid: Option<FTeid>,
    pub network_instance: Option<String>,
    pub ue_ip_address: Option<UeIpAddress>,
    pub sdf_filter: Option<Vec<u8>>,
    pub application_id: Option<Vec<u8>>,
}

impl Pdi {
    pub fn new(source_interface: SourceInterface) -> Self {
        Self {
            source_interface,
            local_f_teid: None,
            network_instance: None,
            ue_ip_address: None,
            sdf_filter: None,
            application_id: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_bytes_ie, encode_u8_ie, IeHeader, IeType};

        encode_u8_ie(buf, IeType::SourceInterface, self.source_interface as u8);

        if let Some(fteid) = &self.local_f_teid {
            let mut fteid_buf = BytesMut::new();
            fteid.encode(&mut fteid_buf);
            let header = IeHeader::new(IeType::FTeid as u16, fteid_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&fteid_buf);
        }

        if let Some(ni) = &self.network_instance {
            encode_bytes_ie(buf, IeType::NetworkInstance, ni.as_bytes());
        }

        if let Some(ue_ip) = &self.ue_ip_address {
            let mut ip_buf = BytesMut::new();
            ue_ip.encode(&mut ip_buf);
            let header = IeHeader::new(IeType::UeIpAddress as u16, ip_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&ip_buf);
        }

        if let Some(sdf) = &self.sdf_filter {
            encode_bytes_ie(buf, IeType::SdfFilter, sdf);
        }

        if let Some(app_id) = &self.application_id {
            encode_bytes_ie(buf, IeType::ApplicationId, app_id);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut source_interface = SourceInterface::Access;
        let mut local_f_teid = None;
        let mut network_instance = None;
        let mut ue_ip_address = None;
        let mut sdf_filter = None;
        let mut application_id = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::SourceInterface as u16 => {
                    if !ie.data.is_empty() {
                        source_interface = SourceInterface::try_from(ie.data[0] & 0x0F)?;
                    }
                }
                t if t == IeType::FTeid as u16 => {
                    let mut data = ie.data;
                    local_f_teid = Some(FTeid::decode(&mut data)?);
                }
                t if t == IeType::NetworkInstance as u16 => {
                    network_instance = Some(String::from_utf8_lossy(&ie.data).to_string());
                }
                t if t == IeType::UeIpAddress as u16 => {
                    let mut data = ie.data;
                    ue_ip_address = Some(UeIpAddress::decode(&mut data)?);
                }
                t if t == IeType::SdfFilter as u16 => {
                    sdf_filter = Some(ie.data.to_vec());
                }
                t if t == IeType::ApplicationId as u16 => {
                    application_id = Some(ie.data.to_vec());
                }
                _ => {}
            }
        }

        Ok(Self {
            source_interface,
            local_f_teid,
            network_instance,
            ue_ip_address,
            sdf_filter,
            application_id,
        })
    }
}

/// Create PDR (Packet Detection Rule) - grouped IE (TS 29.244 Section 7.5.2.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePdr {
    pub pdr_id: u16,
    pub precedence: u32,
    pub pdi: Pdi,
    pub outer_header_removal: Option<OuterHeaderRemoval>,
    pub far_id: Option<u32>,
    pub urr_ids: Vec<u32>,
    pub qer_id: Option<u32>,
}

impl CreatePdr {
    pub fn new(pdr_id: u16, precedence: u32, pdi: Pdi) -> Self {
        Self {
            pdr_id,
            precedence,
            pdi,
            outer_header_removal: None,
            far_id: None,
            urr_ids: Vec::new(),
            qer_id: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u16_ie, encode_u32_ie, IeHeader, IeType};

        encode_u16_ie(buf, IeType::PdrId, self.pdr_id);
        encode_u32_ie(buf, IeType::Precedence, self.precedence);

        // PDI is a grouped IE
        let mut pdi_buf = BytesMut::new();
        self.pdi.encode(&mut pdi_buf);
        let header = IeHeader::new(IeType::Pdi as u16, pdi_buf.len() as u16);
        header.encode(buf);
        buf.put_slice(&pdi_buf);

        if let Some(ohr) = &self.outer_header_removal {
            let mut ohr_buf = BytesMut::new();
            ohr.encode(&mut ohr_buf);
            let header = IeHeader::new(IeType::OuterHeaderRemoval as u16, ohr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&ohr_buf);
        }

        if let Some(far_id) = self.far_id {
            encode_u32_ie(buf, IeType::FarId, far_id);
        }

        for urr_id in &self.urr_ids {
            encode_u32_ie(buf, IeType::UrrId, *urr_id);
        }

        if let Some(qer_id) = self.qer_id {
            encode_u32_ie(buf, IeType::QerId, qer_id);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut pdr_id = 0u16;
        let mut precedence = 0u32;
        let mut pdi = None;
        let mut outer_header_removal = None;
        let mut far_id = None;
        let mut urr_ids = Vec::new();
        let mut qer_id = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::PdrId as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        pdr_id = data.get_u16();
                    }
                }
                t if t == IeType::Precedence as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        precedence = data.get_u32();
                    }
                }
                t if t == IeType::Pdi as u16 => {
                    let mut data = ie.data;
                    pdi = Some(Pdi::decode(&mut data)?);
                }
                t if t == IeType::OuterHeaderRemoval as u16 => {
                    let mut data = ie.data;
                    outer_header_removal = Some(OuterHeaderRemoval::decode(&mut data)?);
                }
                t if t == IeType::FarId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        far_id = Some(data.get_u32());
                    }
                }
                t if t == IeType::UrrId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        urr_ids.push(data.get_u32());
                    }
                }
                t if t == IeType::QerId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        qer_id = Some(data.get_u32());
                    }
                }
                _ => {}
            }
        }

        let pdi = pdi.ok_or_else(|| PfcpError::MissingMandatoryIe("PDI".to_string()))?;

        Ok(Self {
            pdr_id,
            precedence,
            pdi,
            outer_header_removal,
            far_id,
            urr_ids,
            qer_id,
        })
    }
}

/// Forwarding Parameters - grouped IE within FAR (TS 29.244 Section 7.5.2.3-3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingParameters {
    pub destination_interface: DestinationInterface,
    pub network_instance: Option<String>,
    pub outer_header_creation: Option<OuterHeaderCreation>,
}

impl ForwardingParameters {
    pub fn new(destination_interface: DestinationInterface) -> Self {
        Self {
            destination_interface,
            network_instance: None,
            outer_header_creation: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_bytes_ie, encode_u8_ie, IeHeader, IeType};

        encode_u8_ie(
            buf,
            IeType::DestinationInterface,
            self.destination_interface as u8,
        );

        if let Some(ni) = &self.network_instance {
            encode_bytes_ie(buf, IeType::NetworkInstance, ni.as_bytes());
        }

        if let Some(ohc) = &self.outer_header_creation {
            let mut ohc_buf = BytesMut::new();
            ohc.encode(&mut ohc_buf);
            let header = IeHeader::new(IeType::OuterHeaderCreation as u16, ohc_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&ohc_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut destination_interface = DestinationInterface::Access;
        let mut network_instance = None;
        let mut outer_header_creation = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::DestinationInterface as u16 => {
                    if !ie.data.is_empty() {
                        destination_interface = DestinationInterface::try_from(ie.data[0] & 0x0F)?;
                    }
                }
                t if t == IeType::NetworkInstance as u16 => {
                    network_instance = Some(String::from_utf8_lossy(&ie.data).to_string());
                }
                t if t == IeType::OuterHeaderCreation as u16 => {
                    let mut data = ie.data;
                    outer_header_creation = Some(OuterHeaderCreation::decode(&mut data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            destination_interface,
            network_instance,
            outer_header_creation,
        })
    }
}

/// Create FAR (Forwarding Action Rule) - grouped IE (TS 29.244 Section 7.5.2.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFar {
    pub far_id: u32,
    pub apply_action: ApplyAction,
    pub forwarding_parameters: Option<ForwardingParameters>,
    pub bar_id: Option<u8>,
}

impl CreateFar {
    pub fn new(far_id: u32, apply_action: ApplyAction) -> Self {
        Self {
            far_id,
            apply_action,
            forwarding_parameters: None,
            bar_id: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u32_ie, encode_u8_ie, IeHeader, IeType};

        encode_u32_ie(buf, IeType::FarId, self.far_id);
        self.apply_action.encode_ie(buf);

        if let Some(fp) = &self.forwarding_parameters {
            let mut fp_buf = BytesMut::new();
            fp.encode(&mut fp_buf);
            let header = IeHeader::new(IeType::ForwardingParameters as u16, fp_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&fp_buf);
        }

        if let Some(bar_id) = self.bar_id {
            encode_u8_ie(buf, IeType::BarId, bar_id);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut far_id = 0u32;
        let mut apply_action = ApplyAction::default();
        let mut forwarding_parameters = None;
        let mut bar_id = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::FarId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        far_id = data.get_u32();
                    }
                }
                t if t == IeType::ApplyAction as u16 => {
                    if ie.data.len() >= 2 {
                        apply_action = ApplyAction::decode_ie(&ie.data[..]);
                    }
                }
                t if t == IeType::ForwardingParameters as u16 => {
                    let mut data = ie.data;
                    forwarding_parameters = Some(ForwardingParameters::decode(&mut data)?);
                }
                t if t == IeType::BarId as u16 => {
                    if !ie.data.is_empty() {
                        bar_id = Some(ie.data[0]);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            far_id,
            apply_action,
            forwarding_parameters,
            bar_id,
        })
    }
}

/// Create QER (QoS Enforcement Rule) - grouped IE (TS 29.244 Section 7.5.2.5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateQer {
    pub qer_id: u32,
    pub gate_status: GateStatus,
    pub maximum_bitrate: Option<Bitrate>,
    pub guaranteed_bitrate: Option<Bitrate>,
    pub qfi: Option<u8>,
}

impl CreateQer {
    pub fn new(qer_id: u32, gate_status: GateStatus) -> Self {
        Self {
            qer_id,
            gate_status,
            maximum_bitrate: None,
            guaranteed_bitrate: None,
            qfi: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u32_ie, encode_u8_ie, IeHeader, IeType};

        encode_u32_ie(buf, IeType::QerId, self.qer_id);
        encode_u8_ie(buf, IeType::GateStatus, self.gate_status.encode());

        if let Some(mbr) = &self.maximum_bitrate {
            let mut mbr_buf = BytesMut::new();
            mbr.encode(&mut mbr_buf);
            let header = IeHeader::new(IeType::Mbr as u16, mbr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&mbr_buf);
        }

        if let Some(gbr) = &self.guaranteed_bitrate {
            let mut gbr_buf = BytesMut::new();
            gbr.encode(&mut gbr_buf);
            let header = IeHeader::new(IeType::Gbr as u16, gbr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&gbr_buf);
        }

        if let Some(qfi) = self.qfi {
            encode_u8_ie(buf, IeType::Qfi, qfi);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut qer_id = 0u32;
        let mut gate_status = GateStatus::default();
        let mut maximum_bitrate = None;
        let mut guaranteed_bitrate = None;
        let mut qfi = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::QerId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        qer_id = data.get_u32();
                    }
                }
                t if t == IeType::GateStatus as u16 => {
                    if !ie.data.is_empty() {
                        gate_status = GateStatus::decode(ie.data[0]);
                    }
                }
                t if t == IeType::Mbr as u16 => {
                    let mut data = ie.data;
                    maximum_bitrate = Some(Bitrate::decode(&mut data)?);
                }
                t if t == IeType::Gbr as u16 => {
                    let mut data = ie.data;
                    guaranteed_bitrate = Some(Bitrate::decode(&mut data)?);
                }
                t if t == IeType::Qfi as u16 => {
                    if !ie.data.is_empty() {
                        qfi = Some(ie.data[0]);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            qer_id,
            gate_status,
            maximum_bitrate,
            guaranteed_bitrate,
            qfi,
        })
    }
}

/// Create URR (Usage Reporting Rule) - grouped IE (TS 29.244 Section 7.5.2.4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUrr {
    pub urr_id: u32,
    pub measurement_method: MeasurementMethod,
    pub reporting_triggers: ReportingTriggers,
    pub measurement_period: Option<u32>,
    pub volume_threshold: Option<VolumeThreshold>,
    pub time_threshold: Option<u32>,
}

impl CreateUrr {
    pub fn new(
        urr_id: u32,
        measurement_method: MeasurementMethod,
        reporting_triggers: ReportingTriggers,
    ) -> Self {
        Self {
            urr_id,
            measurement_method,
            reporting_triggers,
            measurement_period: None,
            volume_threshold: None,
            time_threshold: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u32_ie, encode_u8_ie, IeHeader, IeType};

        encode_u32_ie(buf, IeType::UrrId, self.urr_id);
        encode_u8_ie(
            buf,
            IeType::MeasurementMethod,
            self.measurement_method.encode(),
        );

        // Reporting Triggers is a 3-octet bitmask (TS 29.244 Section 8.2.19)
        let rt = self.reporting_triggers.encode();
        let header = IeHeader::new(IeType::ReportingTriggers as u16, rt.len() as u16);
        header.encode(buf);
        buf.put_slice(&rt);

        if let Some(period) = self.measurement_period {
            encode_u32_ie(buf, IeType::MeasurementPeriod, period);
        }

        if let Some(vt) = &self.volume_threshold {
            let mut vt_buf = BytesMut::new();
            vt.encode(&mut vt_buf);
            let header = IeHeader::new(IeType::VolumeThreshold as u16, vt_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&vt_buf);
        }

        if let Some(tt) = self.time_threshold {
            encode_u32_ie(buf, IeType::TimeThreshold, tt);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut urr_id = 0u32;
        let mut measurement_method = MeasurementMethod::default();
        let mut reporting_triggers = ReportingTriggers::default();
        let mut measurement_period = None;
        let mut volume_threshold = None;
        let mut time_threshold = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::UrrId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        urr_id = data.get_u32();
                    }
                }
                t if t == IeType::MeasurementMethod as u16 => {
                    if !ie.data.is_empty() {
                        measurement_method = MeasurementMethod::decode(ie.data[0]);
                    }
                }
                t if t == IeType::ReportingTriggers as u16 => {
                    reporting_triggers = ReportingTriggers::decode(&ie.data)?;
                }
                t if t == IeType::MeasurementPeriod as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        measurement_period = Some(data.get_u32());
                    }
                }
                t if t == IeType::VolumeThreshold as u16 => {
                    let mut data = ie.data;
                    volume_threshold = Some(VolumeThreshold::decode(&mut data)?);
                }
                t if t == IeType::TimeThreshold as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        time_threshold = Some(data.get_u32());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            urr_id,
            measurement_method,
            reporting_triggers,
            measurement_period,
            volume_threshold,
            time_threshold,
        })
    }
}

/// Create BAR (Buffering Action Rule) - grouped IE (TS 29.244 Section 7.5.2.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateBar {
    pub bar_id: u8,
    pub downlink_data_notification_delay: Option<u8>,
    pub suggested_buffering_packets_count: Option<u8>,
}

impl CreateBar {
    pub fn new(bar_id: u8) -> Self {
        Self {
            bar_id,
            downlink_data_notification_delay: None,
            suggested_buffering_packets_count: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u8_ie, IeType};

        encode_u8_ie(buf, IeType::BarId, self.bar_id);

        if let Some(delay) = self.downlink_data_notification_delay {
            encode_u8_ie(buf, IeType::DownlinkDataNotificationDelay, delay);
        }

        if let Some(count) = self.suggested_buffering_packets_count {
            encode_u8_ie(buf, IeType::SuggestedBufferingPacketsCount, count);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut bar_id = 0u8;
        let mut downlink_data_notification_delay = None;
        let mut suggested_buffering_packets_count = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::BarId as u16 => {
                    if !ie.data.is_empty() {
                        bar_id = ie.data[0];
                    }
                }
                t if t == IeType::DownlinkDataNotificationDelay as u16 => {
                    if !ie.data.is_empty() {
                        downlink_data_notification_delay = Some(ie.data[0]);
                    }
                }
                t if t == IeType::SuggestedBufferingPacketsCount as u16 => {
                    if !ie.data.is_empty() {
                        suggested_buffering_packets_count = Some(ie.data[0]);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            bar_id,
            downlink_data_notification_delay,
            suggested_buffering_packets_count,
        })
    }
}

/// Update PDR - grouped IE for Session Modification (TS 29.244 Section 7.5.4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePdr {
    pub pdr_id: u16,
    pub precedence: Option<u32>,
    pub pdi: Option<Pdi>,
    pub outer_header_removal: Option<OuterHeaderRemoval>,
    pub far_id: Option<u32>,
    pub urr_ids: Vec<u32>,
    pub qer_id: Option<u32>,
}

impl UpdatePdr {
    pub fn new(pdr_id: u16) -> Self {
        Self {
            pdr_id,
            precedence: None,
            pdi: None,
            outer_header_removal: None,
            far_id: None,
            urr_ids: Vec::new(),
            qer_id: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u16_ie, encode_u32_ie, IeHeader, IeType};

        encode_u16_ie(buf, IeType::PdrId, self.pdr_id);

        if let Some(prec) = self.precedence {
            encode_u32_ie(buf, IeType::Precedence, prec);
        }

        if let Some(pdi) = &self.pdi {
            let mut pdi_buf = BytesMut::new();
            pdi.encode(&mut pdi_buf);
            let header = IeHeader::new(IeType::Pdi as u16, pdi_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&pdi_buf);
        }

        if let Some(ohr) = &self.outer_header_removal {
            let mut ohr_buf = BytesMut::new();
            ohr.encode(&mut ohr_buf);
            let header = IeHeader::new(IeType::OuterHeaderRemoval as u16, ohr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&ohr_buf);
        }

        if let Some(far_id) = self.far_id {
            encode_u32_ie(buf, IeType::FarId, far_id);
        }

        for urr_id in &self.urr_ids {
            encode_u32_ie(buf, IeType::UrrId, *urr_id);
        }

        if let Some(qer_id) = self.qer_id {
            encode_u32_ie(buf, IeType::QerId, qer_id);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut pdr_id = 0u16;
        let mut precedence = None;
        let mut pdi = None;
        let mut outer_header_removal = None;
        let mut far_id = None;
        let mut urr_ids = Vec::new();
        let mut qer_id = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::PdrId as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        pdr_id = data.get_u16();
                    }
                }
                t if t == IeType::Precedence as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        precedence = Some(data.get_u32());
                    }
                }
                t if t == IeType::Pdi as u16 => {
                    let mut data = ie.data;
                    pdi = Some(Pdi::decode(&mut data)?);
                }
                t if t == IeType::OuterHeaderRemoval as u16 => {
                    let mut data = ie.data;
                    outer_header_removal = Some(OuterHeaderRemoval::decode(&mut data)?);
                }
                t if t == IeType::FarId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        far_id = Some(data.get_u32());
                    }
                }
                t if t == IeType::UrrId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        urr_ids.push(data.get_u32());
                    }
                }
                t if t == IeType::QerId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        qer_id = Some(data.get_u32());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            pdr_id,
            precedence,
            pdi,
            outer_header_removal,
            far_id,
            urr_ids,
            qer_id,
        })
    }
}

/// Update FAR - grouped IE for Session Modification (TS 29.244 Section 7.5.4.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFar {
    pub far_id: u32,
    pub apply_action: Option<ApplyAction>,
    pub forwarding_parameters: Option<ForwardingParameters>,
    pub bar_id: Option<u8>,
}

impl UpdateFar {
    pub fn new(far_id: u32) -> Self {
        Self {
            far_id,
            apply_action: None,
            forwarding_parameters: None,
            bar_id: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u32_ie, encode_u8_ie, IeHeader, IeType};

        encode_u32_ie(buf, IeType::FarId, self.far_id);

        if let Some(aa) = &self.apply_action {
            aa.encode_ie(buf);
        }

        if let Some(fp) = &self.forwarding_parameters {
            let mut fp_buf = BytesMut::new();
            fp.encode(&mut fp_buf);
            let header = IeHeader::new(
                IeType::UpdateForwardingParameters as u16,
                fp_buf.len() as u16,
            );
            header.encode(buf);
            buf.put_slice(&fp_buf);
        }

        if let Some(bar_id) = self.bar_id {
            encode_u8_ie(buf, IeType::BarId, bar_id);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut far_id = 0u32;
        let mut apply_action = None;
        let mut forwarding_parameters = None;
        let mut bar_id = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::FarId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        far_id = data.get_u32();
                    }
                }
                t if t == IeType::ApplyAction as u16 => {
                    if ie.data.len() >= 2 {
                        apply_action = Some(ApplyAction::decode_ie(&ie.data[..]));
                    }
                }
                t if t == IeType::UpdateForwardingParameters as u16 => {
                    let mut data = ie.data;
                    forwarding_parameters = Some(ForwardingParameters::decode(&mut data)?);
                }
                t if t == IeType::BarId as u16 => {
                    if !ie.data.is_empty() {
                        bar_id = Some(ie.data[0]);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            far_id,
            apply_action,
            forwarding_parameters,
            bar_id,
        })
    }
}

/// Remove PDR - grouped IE for Session Modification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovePdr {
    pub pdr_id: u16,
}

impl RemovePdr {
    pub fn new(pdr_id: u16) -> Self {
        Self { pdr_id }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u16_ie, IeType};
        encode_u16_ie(buf, IeType::PdrId, self.pdr_id);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};
        let mut pdr_id = 0u16;
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::PdrId as u16 && ie.data.len() >= 2 {
                let mut data = ie.data;
                pdr_id = data.get_u16();
            }
        }
        Ok(Self { pdr_id })
    }
}

/// Remove FAR - grouped IE for Session Modification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveFar {
    pub far_id: u32,
}

impl RemoveFar {
    pub fn new(far_id: u32) -> Self {
        Self { far_id }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u32_ie, IeType};
        encode_u32_ie(buf, IeType::FarId, self.far_id);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};
        let mut far_id = 0u32;
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::FarId as u16 && ie.data.len() >= 4 {
                let mut data = ie.data;
                far_id = data.get_u32();
            }
        }
        Ok(Self { far_id })
    }
}

/// Usage Report (Session Report) - grouped IE in Session Report Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReportSrr {
    pub urr_id: u32,
    pub ur_seqn: Option<u32>,
    pub usage_report_trigger: Option<u32>,
    pub volume_measurement: Option<VolumeMeasurement>,
    pub duration_measurement: Option<u32>,
    pub start_time: Option<u32>,
    pub end_time: Option<u32>,
}

impl UsageReportSrr {
    pub fn new(urr_id: u32) -> Self {
        Self {
            urr_id,
            ur_seqn: None,
            usage_report_trigger: None,
            volume_measurement: None,
            duration_measurement: None,
            start_time: None,
            end_time: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u32_ie, IeHeader, IeType};

        encode_u32_ie(buf, IeType::UrrId, self.urr_id);

        if let Some(seqn) = self.ur_seqn {
            encode_u32_ie(buf, IeType::UrSeqn, seqn);
        }

        if let Some(trigger) = self.usage_report_trigger {
            let header = IeHeader::new(IeType::UsageReportTrigger as u16, 3);
            header.encode(buf);
            buf.put_u8((trigger >> 16) as u8);
            buf.put_u8((trigger >> 8) as u8);
            buf.put_u8(trigger as u8);
        }

        if let Some(vm) = &self.volume_measurement {
            let mut vm_buf = BytesMut::new();
            vm.encode(&mut vm_buf);
            let header = IeHeader::new(IeType::VolumeMeasurement as u16, vm_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&vm_buf);
        }

        if let Some(dm) = self.duration_measurement {
            encode_u32_ie(buf, IeType::DurationMeasurement, dm);
        }

        if let Some(st) = self.start_time {
            encode_u32_ie(buf, IeType::StartTime, st);
        }

        if let Some(et) = self.end_time {
            encode_u32_ie(buf, IeType::EndTime, et);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};

        let mut urr_id = 0u32;
        let mut ur_seqn = None;
        let mut usage_report_trigger = None;
        let mut volume_measurement = None;
        let mut duration_measurement = None;
        let mut start_time = None;
        let mut end_time = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::UrrId as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        urr_id = data.get_u32();
                    }
                }
                t if t == IeType::UrSeqn as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        ur_seqn = Some(data.get_u32());
                    }
                }
                t if t == IeType::UsageReportTrigger as u16 => {
                    let data = &ie.data;
                    // Usage Report Trigger is at least 2 octets (3 from Rel-16).
                    // A zero-length payload must be rejected rather than indexing
                    // data[0] and panicking on attacker-controlled input.
                    let val = match data.len() {
                        0 => {
                            return Err(PfcpError::BufferTooShort {
                                needed: 1,
                                available: 0,
                            });
                        }
                        1 => data[0] as u32,
                        2 => ((data[0] as u32) << 8) | (data[1] as u32),
                        _ => ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32),
                    };
                    usage_report_trigger = Some(val);
                }
                t if t == IeType::VolumeMeasurement as u16 => {
                    let mut data = ie.data;
                    volume_measurement = Some(VolumeMeasurement::decode(&mut data)?);
                }
                t if t == IeType::DurationMeasurement as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        duration_measurement = Some(data.get_u32());
                    }
                }
                t if t == IeType::StartTime as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        start_time = Some(data.get_u32());
                    }
                }
                t if t == IeType::EndTime as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        end_time = Some(data.get_u32());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            urr_id,
            ur_seqn,
            usage_report_trigger,
            volume_measurement,
            duration_measurement,
            start_time,
            end_time,
        })
    }
}

/// Downlink Data Report - grouped IE in Session Report Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownlinkDataReport {
    pub pdr_id: u16,
}

impl DownlinkDataReport {
    pub fn new(pdr_id: u16) -> Self {
        Self { pdr_id }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        use crate::ie::{encode_u16_ie, IeType};
        encode_u16_ie(buf, IeType::PdrId, self.pdr_id);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        use crate::ie::{IeHeader, IeType, RawIe};
        let mut pdr_id = 0u16;
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::PdrId as u16 && ie.data.len() >= 2 {
                let mut data = ie.data;
                pdr_id = data.get_u16();
            }
        }
        Ok(Self { pdr_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_fteid(fteid: &FTeid) -> (Bytes, FTeid) {
        let mut buf = BytesMut::new();
        fteid.encode(&mut buf);
        let encoded = buf.freeze();
        let mut bytes = encoded.clone();
        let decoded = FTeid::decode(&mut bytes).unwrap();
        (encoded, decoded)
    }

    #[test]
    fn test_fseid_v4_flag_is_bit2_per_ts29244() {
        // TS 29.244 Section 8.2.37: octet 5 bit 2 = V4, bit 1 = V6
        // (opposite of the F-TEID flag order in Section 8.2.3).
        let fseid = FSeid::new_ipv4(0x0102030405060708, [10, 0, 0, 1]);
        let mut buf = BytesMut::new();
        fseid.encode(&mut buf);
        assert_eq!(buf[0], 0x02, "V4 flag must be bit 2 (0x02)");
        assert_eq!(&buf[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&buf[9..13], &[10, 0, 0, 1]);

        let fseid6 = FSeid::new_ipv6(1, [0xAB; 16]);
        let mut buf6 = BytesMut::new();
        fseid6.encode(&mut buf6);
        assert_eq!(buf6[0], 0x01, "V6 flag must be bit 1 (0x01)");
    }

    #[test]
    fn test_fseid_round_trip() {
        for fseid in [
            FSeid::new_ipv4(0xCAFEBABE, [192, 168, 0, 1]),
            FSeid::new_ipv6(0x42, [0x20; 16]),
        ] {
            let mut buf = BytesMut::new();
            fseid.encode(&mut buf);
            let mut bytes = buf.freeze();
            let decoded = FSeid::decode(&mut bytes).unwrap();
            assert_eq!(decoded, fseid);
        }
    }

    #[test]
    fn test_fteid_ch0_ipv4_round_trip() {
        let fteid = FTeid::new_ipv4(0x12345678, [10, 0, 0, 1]);
        let (encoded, decoded) = round_trip_fteid(&fteid);
        // flags + TEID + IPv4 address
        assert_eq!(encoded.len(), 9);
        assert_eq!(decoded, fteid);
    }

    #[test]
    fn test_fteid_ch0_ipv6_round_trip() {
        let fteid = FTeid::new_ipv6(0xDEADBEEF, [0xFE; 16]);
        let (encoded, decoded) = round_trip_fteid(&fteid);
        // flags + TEID + IPv6 address
        assert_eq!(encoded.len(), 21);
        assert_eq!(decoded, fteid);
    }

    #[test]
    fn test_fteid_ch1_omits_teid() {
        let fteid = FTeid::new_choose(true, false, None);
        let (encoded, decoded) = round_trip_fteid(&fteid);
        // CH=1: only the flags octet is present on the wire
        assert_eq!(encoded.as_ref(), &[0x05]);
        assert_eq!(decoded, fteid);
    }

    #[test]
    fn test_fteid_ch1_chid_round_trip() {
        let fteid = FTeid::new_choose(true, true, Some(7));
        let (encoded, decoded) = round_trip_fteid(&fteid);
        // CH=1 + CHID: flags octet followed only by the CHOOSE ID
        assert_eq!(encoded.as_ref(), &[0x0F, 0x07]);
        assert_eq!(decoded, fteid);
    }

    #[test]
    fn test_fteid_chid_without_ch_rejected() {
        // CHID flag set without CH is invalid per TS 29.244 Section 8.2.3
        let mut bytes = Bytes::from_static(&[0x09, 0x00, 0x00, 0x00, 0x01, 0x07]);
        assert!(FTeid::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_fteid_ch0_truncated_teid_rejected() {
        let mut bytes = Bytes::from_static(&[0x01, 0x00, 0x00]);
        assert!(FTeid::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_reporting_triggers_all_bits_round_trip() {
        let rt = ReportingTriggers {
            perio: true,
            volth: true,
            timth: true,
            quhti: true,
            start: true,
            stopt: true,
            droth: true,
            liusa: true,
            volqu: true,
            timqu: true,
            envcl: true,
            macar: true,
            eveth: true,
            evequ: true,
            ipmjl: true,
            quvti: true,
            reemr: true,
            upint: true,
        };
        let encoded = rt.encode();
        // 3 octets, spare bits of octet 7 zero
        assert_eq!(encoded, [0xFF, 0xFF, 0x03]);
        assert_eq!(ReportingTriggers::decode(&encoded).unwrap(), rt);
    }

    #[test]
    fn test_reporting_triggers_octet_order() {
        // PERIO is bit 1 of the FIRST wire octet (TS 29.244 Section 8.2.19)
        let rt = ReportingTriggers {
            perio: true,
            ..Default::default()
        };
        assert_eq!(rt.encode(), [0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_reporting_triggers_rel15_two_octets() {
        let rt = ReportingTriggers::decode(&[0x03, 0x01]).unwrap();
        assert!(rt.perio && rt.volth && rt.volqu);
        assert!(!rt.reemr && !rt.upint);
    }

    #[test]
    fn test_reporting_triggers_short_rejected() {
        assert!(ReportingTriggers::decode(&[0x01]).is_err());
    }

    #[test]
    fn test_up_function_features_all_bits_round_trip() {
        let features = UpFunctionFeatures {
            bucp: true,
            ddnd: true,
            dlbd: true,
            trst: true,
            ftup: true,
            pfdm: true,
            heeu: true,
            treu: true,
            empu: true,
            pdiu: true,
            udbc: true,
            quoac: true,
            trace: true,
            frrt: true,
            pfde: true,
            epfar: true,
            dpdra: true,
            adpdp: true,
            ueip: true,
            sset: true,
            mnop: true,
            mte: true,
            bundl: true,
            gcom: true,
            mpas: true,
            rttl: true,
            vtime: true,
            norp: true,
            iptv: true,
            ip6pl: true,
            tscu: true,
            mptcp: true,
            atsss_ll: true,
            qfqm: true,
            gpqm: true,
            mt_edt: true,
            ciot: true,
            ethar: true,
            ddds: true,
            rds: true,
            rttwp: true,
            quasf: true,
            nspoc: true,
            l2tp: true,
            upber: true,
            resps: true,
            iprep: true,
            dnsts: true,
            drqos: true,
            mbsn4: true,
            psuprm: true,
            eppi: true,
        };
        let mut buf = BytesMut::new();
        features.encode(&mut buf);
        let encoded = buf.freeze();
        assert_eq!(encoded.len(), UpFunctionFeatures::ENCODED_LEN);
        assert_eq!(
            encoded.as_ref(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00]
        );
        let mut bytes = encoded;
        assert_eq!(UpFunctionFeatures::decode(&mut bytes).unwrap(), features);
    }

    #[test]
    fn test_up_function_features_wire_bit_positions() {
        let features = UpFunctionFeatures {
            ftup: true,
            empu: true,
            mnop: true,
            mpas: true,
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        features.encode(&mut buf);
        // FTUP = octet 5 bit 5, EMPU = octet 6 bit 1,
        // MNOP = octet 7 bit 5, MPAS = octet 8 bit 1
        assert_eq!(
            buf.as_ref(),
            &[0x10, 0x01, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_strict_peer_rejects_four_byte_up_function_features() {
        // The legacy truncated 4-octet encoding must be rejected
        let mut bytes = Bytes::from_static(&[0x22, 0x01, 0x10, 0x00]);
        assert!(UpFunctionFeatures::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_up_function_features_six_octets_accepted() {
        // Rel-16 peers send 6 feature octets (no additional octets 11-12)
        let mut bytes = Bytes::from_static(&[0x10, 0x01, 0x00, 0x00, 0x00, 0x00]);
        let features = UpFunctionFeatures::decode(&mut bytes).unwrap();
        assert!(features.ftup && features.empu);
        assert!(!features.drqos);
    }

    #[test]
    fn test_cp_function_features_all_bits_round_trip() {
        let features = CpFunctionFeatures {
            load: true,
            ovrl: true,
            epfar: true,
            sset: true,
            bundl: true,
            mpas: true,
            ardr: true,
            uiaur: true,
            psucc: true,
        };
        let mut buf = BytesMut::new();
        features.encode(&mut buf);
        assert_eq!(buf.as_ref(), &[0xFF, 0x01]);
        assert_eq!(CpFunctionFeatures::decode(&buf).unwrap(), features);
    }

    #[test]
    fn test_cp_function_features_rel15_single_octet() {
        let features = CpFunctionFeatures::decode(&[0x03]).unwrap();
        assert!(features.load && features.ovrl);
        assert!(!features.psucc);
    }

    #[test]
    fn test_node_id_fqdn_round_trip() {
        let node_id = NodeId::new_fqdn("smf.example.com".to_string());
        let mut buf = BytesMut::new();
        node_id.encode(&mut buf);
        // Type octet + RFC 1035 labels + zero-length root label terminator
        assert_eq!(
            buf.as_ref(),
            &[
                0x02, 3, b's', b'm', b'f', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c',
                b'o', b'm', 0,
            ]
        );
        let mut bytes = buf.freeze();
        assert_eq!(NodeId::decode(&mut bytes).unwrap(), node_id);
    }

    #[test]
    fn test_node_id_ipv4_round_trip() {
        let node_id = NodeId::new_ipv4([192, 168, 1, 1]);
        let mut buf = BytesMut::new();
        node_id.encode(&mut buf);
        let mut bytes = buf.freeze();
        assert_eq!(NodeId::decode(&mut bytes).unwrap(), node_id);
    }

    #[test]
    fn test_volume_measurement_round_trip() {
        let vm = VolumeMeasurement {
            tovol: true,
            ulvol: true,
            dlvol: true,
            tonop: true,
            ulnop: true,
            dlnop: true,
            total_volume: 1000,
            uplink_volume: 400,
            downlink_volume: 600,
            total_n_packets: 100,
            uplink_n_packets: 40,
            downlink_n_packets: 60,
        };
        let mut buf = BytesMut::new();
        vm.encode(&mut buf);
        // flags + 6 x u64
        assert_eq!(buf.len(), 49);
        let mut bytes = buf.freeze();
        assert_eq!(VolumeMeasurement::decode(&mut bytes).unwrap(), vm);
    }

    #[test]
    fn test_volume_measurement_truncated_rejected() {
        // TOVOL flag set but only 2 of the 8 volume octets present
        let mut bytes = Bytes::from_static(&[0x01, 0x00, 0x01]);
        assert!(VolumeMeasurement::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_usage_report_srr_zero_length_trigger_rejected() {
        // UsageReportSrr containing a UsageReportTrigger IE (type 63) with a
        // zero-length payload. Previously the `match data.len()` arm indexed
        // data[0] and panicked; it must now return a graceful Err.
        // IE = type(2) + length(2) + data(len). Type 63 = 0x003F, length 0.
        let mut bytes = Bytes::from_static(&[0x00, 0x3F, 0x00, 0x00]);
        let res = UsageReportSrr::decode(&mut bytes);
        assert!(
            res.is_err(),
            "zero-length UsageReportTrigger must error, got {res:?}"
        );
    }

    #[test]
    fn test_usage_report_srr_valid_trigger_decodes() {
        // Success path preserved: a 2-octet UsageReportTrigger payload decodes.
        // IE type 63, length 2, value 0x0102.
        let mut bytes = Bytes::from_static(&[0x00, 0x3F, 0x00, 0x02, 0x01, 0x02]);
        let decoded = UsageReportSrr::decode(&mut bytes).expect("valid trigger decodes");
        assert_eq!(decoded.usage_report_trigger, Some(0x0102));
    }

    #[test]
    fn test_apply_action_ie_wire_octet_order() {
        // TS 29.244 §8.2.26: octet 5 (DROP..DFRT) first, octet 6 (EDRT/BDPN/DDPN) second.
        let mut buf = BytesMut::new();
        ApplyAction::forward().encode_ie(&mut buf);
        // payload is the last two octets of the IE.
        assert_eq!(&buf[buf.len() - 2..], &[0x02, 0x00], "FORW -> octet5=0x02");

        let mut buf = BytesMut::new();
        ApplyAction::drop().encode_ie(&mut buf);
        assert_eq!(&buf[buf.len() - 2..], &[0x01, 0x00], "DROP -> octet5=0x01");

        // An octet-6 flag (DDPN) must land in the second payload octet.
        let mut aa = ApplyAction::default();
        aa.ddpn = true;
        let mut buf = BytesMut::new();
        aa.encode_ie(&mut buf);
        assert_eq!(&buf[buf.len() - 2..], &[0x00, 0x04], "DDPN -> octet6 bit3");

        // Round-trip via the payload octets.
        let payload = &buf[buf.len() - 2..];
        assert!(ApplyAction::decode_ie(payload).ddpn);
        assert!(ApplyAction::decode_ie(&[0x02, 0x00]).forw);
    }
}
