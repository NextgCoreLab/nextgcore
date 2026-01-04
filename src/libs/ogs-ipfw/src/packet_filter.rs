//! Packet filter content generation from IPFW rules

use crate::rule::contigmask;
use crate::types::*;

/// Packet filter component type identifiers
pub mod filter_type {
    pub const MATCH_ALL: u8 = 1;
    pub const PROTOCOL_IDENTIFIER_NEXT_HEADER_TYPE: u8 = 48;
    pub const IPV4_REMOTE_ADDRESS_TYPE: u8 = 16;
    pub const IPV4_LOCAL_ADDRESS_TYPE: u8 = 17;
    pub const IPV6_REMOTE_ADDRESS_TYPE: u8 = 32;
    pub const IPV6_REMOTE_ADDRESS_PREFIX_LENGTH_TYPE: u8 = 33;
    pub const IPV6_LOCAL_ADDRESS_TYPE: u8 = 34;
    pub const IPV6_LOCAL_ADDRESS_PREFIX_LENGTH_TYPE: u8 = 35;
    pub const SINGLE_LOCAL_PORT_TYPE: u8 = 64;
    pub const LOCAL_PORT_RANGE_TYPE: u8 = 65;
    pub const SINGLE_REMOTE_PORT_TYPE: u8 = 80;
    pub const REMOTE_PORT_RANGE_TYPE: u8 = 81;
    pub const SECURITY_PARAMETER_INDEX_TYPE: u8 = 96;
    pub const TOS_TRAFFIC_CLASS_TYPE: u8 = 112;
    pub const FLOW_LABEL_TYPE: u8 = 128;
}

/// Flow direction
pub mod flow_direction {
    pub const UNSPECIFIED: u8 = 0;
    pub const DOWNLINK_ONLY: u8 = 1;
    pub const UPLINK_ONLY: u8 = 2;
    pub const BIDIRECTIONAL: u8 = 3;
}

/// Packet filter component
#[derive(Debug, Clone)]
pub enum PfComponent {
    /// Protocol identifier
    Protocol(u8),
    /// IPv4 address with mask
    Ipv4Address {
        addr: u32,
        mask: u32,
        is_local: bool,
    },
    /// IPv6 address with prefix length
    Ipv6AddressPrefix {
        addr: [u32; 4],
        prefix_len: u8,
        is_local: bool,
    },
    /// IPv6 address with mask
    Ipv6AddressMask {
        addr: [u32; 4],
        mask: [u32; 4],
        is_local: bool,
    },
    /// Single port
    SinglePort { port: u16, is_local: bool },
    /// Port range
    PortRange {
        low: u16,
        high: u16,
        is_local: bool,
    },
    /// Security Parameter Index
    SecurityParameterIndex(u32),
    /// ToS/Traffic Class
    TosTrafficClass(u16),
    /// Flow Label
    FlowLabel(u32),
}

impl PfComponent {
    /// Get the type identifier for this component
    pub fn type_id(&self) -> u8 {
        match self {
            PfComponent::Protocol(_) => filter_type::PROTOCOL_IDENTIFIER_NEXT_HEADER_TYPE,
            PfComponent::Ipv4Address { is_local, .. } => {
                if *is_local {
                    filter_type::IPV4_LOCAL_ADDRESS_TYPE
                } else {
                    filter_type::IPV4_REMOTE_ADDRESS_TYPE
                }
            }
            PfComponent::Ipv6AddressPrefix { is_local, .. } => {
                if *is_local {
                    filter_type::IPV6_LOCAL_ADDRESS_PREFIX_LENGTH_TYPE
                } else {
                    filter_type::IPV6_REMOTE_ADDRESS_PREFIX_LENGTH_TYPE
                }
            }
            PfComponent::Ipv6AddressMask { is_local, .. } => {
                if *is_local {
                    filter_type::IPV6_LOCAL_ADDRESS_TYPE
                } else {
                    filter_type::IPV6_REMOTE_ADDRESS_TYPE
                }
            }
            PfComponent::SinglePort { is_local, .. } => {
                if *is_local {
                    filter_type::SINGLE_LOCAL_PORT_TYPE
                } else {
                    filter_type::SINGLE_REMOTE_PORT_TYPE
                }
            }
            PfComponent::PortRange { is_local, .. } => {
                if *is_local {
                    filter_type::LOCAL_PORT_RANGE_TYPE
                } else {
                    filter_type::REMOTE_PORT_RANGE_TYPE
                }
            }
            PfComponent::SecurityParameterIndex(_) => filter_type::SECURITY_PARAMETER_INDEX_TYPE,
            PfComponent::TosTrafficClass(_) => filter_type::TOS_TRAFFIC_CLASS_TYPE,
            PfComponent::FlowLabel(_) => filter_type::FLOW_LABEL_TYPE,
        }
    }

    /// Get the encoded length of this component
    pub fn encoded_len(&self) -> usize {
        match self {
            PfComponent::Protocol(_) => 2,
            PfComponent::Ipv4Address { .. } => 9,
            PfComponent::Ipv6AddressPrefix { .. } => 18,
            PfComponent::Ipv6AddressMask { .. } => 33,
            PfComponent::SinglePort { .. } => 3,
            PfComponent::PortRange { .. } => 5,
            PfComponent::SecurityParameterIndex(_) => 5,
            PfComponent::TosTrafficClass(_) => 3,
            PfComponent::FlowLabel(_) => 4,
        }
    }
}

/// Packet filter content
#[derive(Debug, Clone, Default)]
pub struct PfContent {
    /// Total encoded length
    pub length: usize,
    /// Components
    pub components: Vec<PfComponent>,
}

impl PfContent {
    /// Create a new empty packet filter content
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a component
    pub fn add_component(&mut self, component: PfComponent) {
        self.length += component.encoded_len();
        self.components.push(component);
    }

    /// Get the number of components
    pub fn num_components(&self) -> usize {
        self.components.len()
    }
}

/// Generate packet filter content from an IPFW rule
/// 
/// # Arguments
/// * `direction` - Flow direction (DOWNLINK_ONLY, UPLINK_ONLY, BIDIRECTIONAL)
/// * `rule` - The IPFW rule
/// * `no_ipv4v6_local_addr` - If true, don't include local address in packet filter
pub fn pf_content_from_ipfw_rule(
    direction: u8,
    rule: &IpfwRule,
    no_ipv4v6_local_addr: bool,
) -> PfContent {
    let mut content = PfContent::new();

    // Protocol
    if rule.proto != 0 {
        content.add_component(PfComponent::Protocol(rule.proto));
    }

    // IPv4 source address
    if rule.ipv4_src {
        let is_local = match direction {
            flow_direction::DOWNLINK_ONLY | flow_direction::BIDIRECTIONAL => false, // remote
            flow_direction::UPLINK_ONLY => true,                                     // local
            _ => false,
        };

        if !is_local || !no_ipv4v6_local_addr {
            content.add_component(PfComponent::Ipv4Address {
                addr: rule.ip.src.addr[0],
                mask: rule.ip.src.mask[0],
                is_local,
            });
        }
    }

    // IPv4 destination address
    if rule.ipv4_dst {
        let is_local = match direction {
            flow_direction::DOWNLINK_ONLY | flow_direction::BIDIRECTIONAL => true, // local
            flow_direction::UPLINK_ONLY => false,                                   // remote
            _ => false,
        };

        if !is_local || !no_ipv4v6_local_addr {
            content.add_component(PfComponent::Ipv4Address {
                addr: rule.ip.dst.addr[0],
                mask: rule.ip.dst.mask[0],
                is_local,
            });
        }
    }

    // IPv6 source address
    if rule.ipv6_src {
        let is_local = match direction {
            flow_direction::DOWNLINK_ONLY | flow_direction::BIDIRECTIONAL => false,
            flow_direction::UPLINK_ONLY => true,
            _ => false,
        };

        if !is_local || !no_ipv4v6_local_addr {
            if no_ipv4v6_local_addr {
                // Use mask format for remote address
                content.add_component(PfComponent::Ipv6AddressMask {
                    addr: rule.ip.src.addr,
                    mask: rule.ip.src.mask,
                    is_local,
                });
            } else {
                // Use prefix length format
                let mask_bytes: Vec<u8> = rule
                    .ip
                    .src
                    .mask
                    .iter()
                    .flat_map(|&m| m.to_be_bytes())
                    .collect();
                let prefix_len = contigmask(&mask_bytes, 128) as u8;
                content.add_component(PfComponent::Ipv6AddressPrefix {
                    addr: rule.ip.src.addr,
                    prefix_len,
                    is_local,
                });
            }
        }
    }

    // IPv6 destination address
    if rule.ipv6_dst {
        let is_local = match direction {
            flow_direction::DOWNLINK_ONLY | flow_direction::BIDIRECTIONAL => true,
            flow_direction::UPLINK_ONLY => false,
            _ => false,
        };

        if !is_local || !no_ipv4v6_local_addr {
            if no_ipv4v6_local_addr && !is_local {
                content.add_component(PfComponent::Ipv6AddressMask {
                    addr: rule.ip.dst.addr,
                    mask: rule.ip.dst.mask,
                    is_local,
                });
            } else {
                let mask_bytes: Vec<u8> = rule
                    .ip
                    .dst
                    .mask
                    .iter()
                    .flat_map(|&m| m.to_be_bytes())
                    .collect();
                let prefix_len = contigmask(&mask_bytes, 128) as u8;
                content.add_component(PfComponent::Ipv6AddressPrefix {
                    addr: rule.ip.dst.addr,
                    prefix_len,
                    is_local,
                });
            }
        }
    }

    // Source port
    if rule.port.src.low != 0 {
        let is_local = match direction {
            flow_direction::DOWNLINK_ONLY | flow_direction::BIDIRECTIONAL => false,
            flow_direction::UPLINK_ONLY => true,
            _ => false,
        };

        if rule.port.src.is_single() {
            content.add_component(PfComponent::SinglePort {
                port: rule.port.src.low,
                is_local,
            });
        } else {
            content.add_component(PfComponent::PortRange {
                low: rule.port.src.low,
                high: rule.port.src.high,
                is_local,
            });
        }
    }

    // Destination port
    if rule.port.dst.low != 0 {
        let is_local = match direction {
            flow_direction::DOWNLINK_ONLY | flow_direction::BIDIRECTIONAL => true,
            flow_direction::UPLINK_ONLY => false,
            _ => false,
        };

        if rule.port.dst.is_single() {
            content.add_component(PfComponent::SinglePort {
                port: rule.port.dst.low,
                is_local,
            });
        } else {
            content.add_component(PfComponent::PortRange {
                low: rule.port.dst.low,
                high: rule.port.dst.high,
                is_local,
            });
        }
    }

    content
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pf_content_new() {
        let content = PfContent::new();
        assert_eq!(content.length, 0);
        assert_eq!(content.num_components(), 0);
    }

    #[test]
    fn test_pf_component_type_id() {
        assert_eq!(
            PfComponent::Protocol(17).type_id(),
            filter_type::PROTOCOL_IDENTIFIER_NEXT_HEADER_TYPE
        );
        assert_eq!(
            PfComponent::Ipv4Address {
                addr: 0,
                mask: 0,
                is_local: false
            }
            .type_id(),
            filter_type::IPV4_REMOTE_ADDRESS_TYPE
        );
        assert_eq!(
            PfComponent::Ipv4Address {
                addr: 0,
                mask: 0,
                is_local: true
            }
            .type_id(),
            filter_type::IPV4_LOCAL_ADDRESS_TYPE
        );
    }

    #[test]
    fn test_pf_content_from_rule() {
        let mut rule = IpfwRule::new();
        rule.proto = 17; // UDP
        rule.ipv4_src = true;
        rule.ip.src.addr[0] = 0x0a000001; // 10.0.0.1
        rule.ip.src.mask[0] = 0xffffffff;
        rule.port.dst.low = 80;
        rule.port.dst.high = 80;

        let content = pf_content_from_ipfw_rule(flow_direction::DOWNLINK_ONLY, &rule, false);

        assert!(content.num_components() >= 2); // At least protocol and address
    }
}
