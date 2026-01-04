//! IPFW rule compilation and encoding

use crate::types::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Compile a flow description string into an IPFW rule
/// 
/// Flow description format:
/// `permit out <proto> from <src_addr> [<src_port>] to <dst_addr> [<dst_port>]`
/// 
/// Examples:
/// - `permit out ip from any to any`
/// - `permit out 17 from 10.0.0.1 to 192.168.1.1 80`
/// - `permit out ip from 2001:db8::1/64 to any`
pub fn compile_rule(flow_description: &str) -> IpfwResult<IpfwRule> {
    let mut rule = IpfwRule::new();
    let tokens: Vec<&str> = flow_description.split_whitespace().collect();

    if tokens.is_empty() {
        return Err(IpfwError::InvalidSyntax("Empty flow description".to_string()));
    }

    // Check for "permit" keyword
    if tokens.get(0) != Some(&"permit") {
        return Err(IpfwError::MissingKeyword("permit".to_string()));
    }

    // Check for "out" keyword
    if tokens.get(1) != Some(&"out") {
        return Err(IpfwError::MissingKeyword("out".to_string()));
    }

    // Parse protocol
    let proto_idx = 2;
    if let Some(&proto_str) = tokens.get(proto_idx) {
        rule.proto = parse_protocol(proto_str)?;
    } else {
        return Err(IpfwError::InvalidSyntax("Missing protocol".to_string()));
    }

    // Find "from" keyword
    let from_idx = tokens.iter().position(|&t| t == "from");
    if from_idx.is_none() {
        return Err(IpfwError::MissingKeyword("from".to_string()));
    }
    let from_idx = from_idx.unwrap();

    // Find "to" keyword
    let to_idx = tokens.iter().position(|&t| t == "to");
    if to_idx.is_none() {
        return Err(IpfwError::MissingKeyword("to".to_string()));
    }
    let to_idx = to_idx.unwrap();

    // Parse source address and port
    let src_tokens: Vec<&str> = tokens[from_idx + 1..to_idx].to_vec();
    parse_address_port(&src_tokens, &mut rule, true)?;

    // Parse destination address and port
    let dst_tokens: Vec<&str> = tokens[to_idx + 1..].to_vec();
    parse_address_port(&dst_tokens, &mut rule, false)?;

    Ok(rule)
}

/// Parse protocol string
fn parse_protocol(proto: &str) -> IpfwResult<u8> {
    match proto.to_lowercase().as_str() {
        "ip" => Ok(0),
        "icmp" => Ok(1),
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmpv6" | "ipv6-icmp" => Ok(58),
        _ => {
            // Try to parse as number
            proto
                .parse::<u8>()
                .map_err(|_| IpfwError::InvalidProtocol(proto.to_string()))
        }
    }
}

/// Parse address and optional port
fn parse_address_port(tokens: &[&str], rule: &mut IpfwRule, is_src: bool) -> IpfwResult<()> {
    if tokens.is_empty() {
        return Err(IpfwError::InvalidSyntax("Missing address".to_string()));
    }

    let addr_str = tokens[0];

    // Handle "any" or "assigned"
    if addr_str == "any" || addr_str == "assigned" {
        // No address specified
    } else {
        // Parse address (with optional prefix)
        parse_address(addr_str, rule, is_src)?;
    }

    // Parse optional port
    if tokens.len() > 1 {
        parse_port(tokens[1], rule, is_src)?;
    }

    Ok(())
}

/// Parse IP address (IPv4 or IPv6, with optional prefix)
fn parse_address(addr_str: &str, rule: &mut IpfwRule, is_src: bool) -> IpfwResult<()> {
    // Check for prefix notation
    let (addr_part, prefix_len) = if let Some(idx) = addr_str.find('/') {
        let prefix: u8 = addr_str[idx + 1..]
            .parse()
            .map_err(|_| IpfwError::InvalidAddress(addr_str.to_string()))?;
        (&addr_str[..idx], Some(prefix))
    } else {
        (addr_str, None)
    };

    // Try IPv4 first
    if let Ok(ipv4) = Ipv4Addr::from_str(addr_part) {
        let prefix = prefix_len.unwrap_or(32);
        let addr_mask = IpAddrMask::from_ipv4(ipv4, prefix);

        if is_src {
            rule.ipv4_src = true;
            rule.ip.src = addr_mask;
        } else {
            rule.ipv4_dst = true;
            rule.ip.dst = addr_mask;
        }
        return Ok(());
    }

    // Try IPv6
    if let Ok(ipv6) = Ipv6Addr::from_str(addr_part) {
        let prefix = prefix_len.unwrap_or(128);
        let addr_mask = IpAddrMask::from_ipv6(ipv6, prefix);

        if is_src {
            rule.ipv6_src = true;
            rule.ip.src = addr_mask;
        } else {
            rule.ipv6_dst = true;
            rule.ip.dst = addr_mask;
        }
        return Ok(());
    }

    Err(IpfwError::InvalidAddress(addr_str.to_string()))
}

/// Parse port or port range
fn parse_port(port_str: &str, rule: &mut IpfwRule, is_src: bool) -> IpfwResult<()> {
    let port_range = if let Some(idx) = port_str.find('-') {
        // Port range
        let low: u16 = port_str[..idx]
            .parse()
            .map_err(|_| IpfwError::InvalidPort(port_str.to_string()))?;
        let high: u16 = port_str[idx + 1..]
            .parse()
            .map_err(|_| IpfwError::InvalidPort(port_str.to_string()))?;
        PortRange::range(low, high)
    } else {
        // Single port
        let port: u16 = port_str
            .parse()
            .map_err(|_| IpfwError::InvalidPort(port_str.to_string()))?;
        PortRange::single(port)
    };

    if is_src {
        rule.port.src = port_range;
    } else {
        rule.port.dst = port_range;
    }

    Ok(())
}

/// Encode an IPFW rule into a flow description string
pub fn encode_flow_description(rule: &IpfwRule) -> IpfwResult<String> {
    let mut parts = vec!["permit out".to_string()];

    // Protocol
    if rule.proto == 0 {
        parts.push("ip".to_string());
    } else {
        parts.push(rule.proto.to_string());
    }

    // Source
    parts.push("from".to_string());
    parts.push(encode_address_port(rule, true));

    // Destination
    parts.push("to".to_string());
    parts.push(encode_address_port(rule, false));

    Ok(parts.join(" "))
}

/// Encode address and port for flow description
fn encode_address_port(rule: &IpfwRule, is_src: bool) -> String {
    let mut result = String::new();

    let (has_ipv4, has_ipv6, addr_mask, port_range) = if is_src {
        (rule.ipv4_src, rule.ipv6_src, &rule.ip.src, &rule.port.src)
    } else {
        (rule.ipv4_dst, rule.ipv6_dst, &rule.ip.dst, &rule.port.dst)
    };

    // Address
    if has_ipv4 {
        let addr = Ipv4Addr::from(addr_mask.addr[0]);
        let prefix = count_prefix_bits(&addr_mask.mask, IPV4_BITLEN);

        if prefix == 0 {
            result.push_str(if is_src { "any" } else { "assigned" });
        } else if prefix == 32 {
            result.push_str(&addr.to_string());
        } else {
            result.push_str(&format!("{}/{}", addr, prefix));
        }
    } else if has_ipv6 {
        let mut octets = [0u8; 16];
        for i in 0..4 {
            let bytes = addr_mask.addr[i].to_be_bytes();
            octets[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        let addr = Ipv6Addr::from(octets);
        let prefix = count_prefix_bits(&addr_mask.mask, IPV6_BITLEN);

        if prefix == 0 {
            result.push_str(if is_src { "any" } else { "assigned" });
        } else if prefix == 128 {
            result.push_str(&addr.to_string());
        } else {
            result.push_str(&format!("{}/{}", addr, prefix));
        }
    } else {
        result.push_str(if is_src { "any" } else { "assigned" });
    }

    // Port
    if !port_range.is_empty() {
        if port_range.is_single() {
            result.push_str(&format!(" {}", port_range.low));
        } else {
            result.push_str(&format!(" {}-{}", port_range.low, port_range.high));
        }
    }

    result
}

/// Count contiguous prefix bits in a mask
fn count_prefix_bits(mask: &[u32; 4], max_bits: usize) -> u32 {
    let mut count = 0u32;
    let num_words = (max_bits + 31) / 32;

    for i in 0..num_words {
        let word = u32::from_be(mask[i]);
        if word == 0xFFFFFFFF {
            count += 32;
        } else if word == 0 {
            break;
        } else {
            // Count leading ones
            count += word.leading_ones();
            break;
        }
    }

    count.min(max_bits as u32)
}

/// Calculate contiguous mask bits (same as C contigmask function)
pub fn contigmask(mask: &[u8], len: usize) -> i32 {
    let mut count = 0i32;
    let mut found_zero = false;

    for i in 0..len {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);

        if byte_idx >= mask.len() {
            break;
        }

        let bit = (mask[byte_idx] >> bit_idx) & 1;

        if bit == 1 {
            if found_zero {
                // Non-contiguous mask
                return -1;
            }
            count += 1;
        } else {
            found_zero = true;
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_protocol() {
        assert_eq!(parse_protocol("ip").unwrap(), 0);
        assert_eq!(parse_protocol("tcp").unwrap(), 6);
        assert_eq!(parse_protocol("udp").unwrap(), 17);
        assert_eq!(parse_protocol("17").unwrap(), 17);
    }

    #[test]
    fn test_contigmask() {
        // /24 mask
        let mask = [0xFF, 0xFF, 0xFF, 0x00];
        assert_eq!(contigmask(&mask, 32), 24);

        // /32 mask
        let mask = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(contigmask(&mask, 32), 32);

        // /0 mask
        let mask = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(contigmask(&mask, 32), 0);
    }

    #[test]
    fn test_count_prefix_bits() {
        let mask = [0xFFFFFF00u32.to_be(), 0, 0, 0];
        assert_eq!(count_prefix_bits(&mask, 32), 24);
    }
}
