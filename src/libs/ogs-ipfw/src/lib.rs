//! NextGCore IP Firewall Library
//!
//! This crate provides IP firewall rule parsing and encoding for flow descriptions
//! used in 3GPP networks (GTP, PFCP, etc.).

mod types;
mod rule;
mod packet_filter;

pub use types::*;
pub use rule::*;
pub use packet_filter::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipfw_rule_default() {
        let rule = IpfwRule::default();
        assert_eq!(rule.proto, 0);
        assert!(!rule.ipv4_src);
        assert!(!rule.ipv4_dst);
        assert!(!rule.ipv6_src);
        assert!(!rule.ipv6_dst);
    }

    #[test]
    fn test_compile_simple_rule() {
        let flow = "permit out ip from any to any";
        let result = compile_rule(flow);
        assert!(result.is_ok());
        let rule = result.unwrap();
        assert_eq!(rule.proto, 0); // ip = any protocol
    }

    #[test]
    fn test_compile_rule_with_proto() {
        let flow = "permit out 17 from any to any";
        let result = compile_rule(flow);
        assert!(result.is_ok());
        let rule = result.unwrap();
        assert_eq!(rule.proto, 17); // UDP
    }

    #[test]
    fn test_compile_rule_with_ipv4() {
        let flow = "permit out ip from 10.0.0.1 to 192.168.1.1";
        let result = compile_rule(flow);
        assert!(result.is_ok());
        let rule = result.unwrap();
        assert!(rule.ipv4_src);
        assert!(rule.ipv4_dst);
    }

    #[test]
    fn test_encode_flow_description() {
        let mut rule = IpfwRule::default();
        rule.proto = 17; // UDP
        
        let desc = encode_flow_description(&rule);
        assert!(desc.is_ok());
        let desc = desc.unwrap();
        assert!(desc.contains("permit out"));
        assert!(desc.contains("17"));
    }

    #[test]
    fn test_rule_swap() {
        let mut rule = IpfwRule::default();
        rule.ipv4_src = true;
        rule.ipv4_dst = false;
        rule.ip.src.addr[0] = 0x0a000001; // 10.0.0.1
        rule.ip.dst.addr[0] = 0xc0a80101; // 192.168.1.1
        rule.port.src.low = 1000;
        rule.port.src.high = 1000;
        rule.port.dst.low = 80;
        rule.port.dst.high = 80;

        rule.swap();

        assert!(!rule.ipv4_src);
        assert!(rule.ipv4_dst);
        assert_eq!(rule.ip.src.addr[0], 0xc0a80101);
        assert_eq!(rule.ip.dst.addr[0], 0x0a000001);
        assert_eq!(rule.port.src.low, 80);
        assert_eq!(rule.port.dst.low, 1000);
    }
}
