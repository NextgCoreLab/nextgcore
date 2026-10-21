//! #619: the EPS Traffic Flow Template, as the PGW-C sends it and reads it on S5/S8.
//!
//! TS 24.008 §10.5.6.12 codes the TFT. The same coding is used by:
//! - the Bearer TFT IE in a Create Bearer Request (TS 29.274 §8.19);
//! - the Traffic Aggregate Description IE in a Bearer Resource Command (TS 29.274 §8.20,
//!   which TS 24.301 §9.9.4.15 codes "as the TFT").
//!
//! Inside the SMF a packet filter is a TS 29.212 flow description in the **downlink**
//! orientation: `permit out <proto> from <remote> [<port>] to assigned [<port>]`. The
//! remote end is the "from" side, and the UE is the "to" side whatever the filter's
//! direction. The PGW-U compiles the downlink filters as SDF filters, so one
//! orientation serves both the TFT the UE receives and the PDR that carries the bearer's
//! downlink traffic.

use crate::context::FlowDirection;

/// TFT operation codes (TS 24.008 Table 10.5.162).
pub mod op {
    pub const CREATE_NEW_TFT: u8 = 1;
    pub const DELETE_EXISTING_TFT: u8 = 2;
    pub const ADD_PACKET_FILTERS: u8 = 3;
    pub const REPLACE_PACKET_FILTERS: u8 = 4;
    pub const DELETE_PACKET_FILTERS: u8 = 5;
    pub const NO_TFT_OPERATION: u8 = 6;
}

/// Packet filter component type identifiers (TS 24.008 §10.5.6.12).
mod component {
    pub const IPV4_REMOTE: u8 = 0x10;
    pub const IPV4_LOCAL: u8 = 0x11;
    pub const IPV6_REMOTE: u8 = 0x20;
    pub const IPV6_REMOTE_PREFIX: u8 = 0x21;
    pub const IPV6_LOCAL_PREFIX: u8 = 0x23;
    pub const PROTOCOL: u8 = 0x30;
    pub const SINGLE_LOCAL_PORT: u8 = 0x40;
    pub const LOCAL_PORT_RANGE: u8 = 0x41;
    pub const SINGLE_REMOTE_PORT: u8 = 0x50;
    pub const REMOTE_PORT_RANGE: u8 = 0x51;
}

/// One packet filter of a TFT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFilter {
    pub direction: FlowDirection,
    /// The packet filter identifier (4 bits).
    pub identifier: u8,
    /// Evaluation precedence: lower values are evaluated first.
    pub precedence: u8,
    /// The filter as a flow description, in the downlink orientation (see module docs).
    pub flow_description: String,
}

/// A decoded TFT or Traffic Aggregate Description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tft {
    pub operation: u8,
    pub filters: Vec<PacketFilter>,
}

fn direction_bits(d: FlowDirection) -> u8 {
    match d {
        FlowDirection::DownlinkOnly => 0b01,
        FlowDirection::UplinkOnly => 0b10,
        FlowDirection::Bidirectional => 0b11,
    }
}

fn direction_from_bits(bits: u8) -> FlowDirection {
    match bits & 0x03 {
        0b01 => FlowDirection::DownlinkOnly,
        0b10 => FlowDirection::UplinkOnly,
        // 0b00 is "pre-Release 7 TFT filter", which applies in both directions.
        _ => FlowDirection::Bidirectional,
    }
}

/// The packet filter contents of one flow description.
///
/// The "from" side becomes the remote components and the "to" side the local ones. An
/// address on the "to" side is the UE's, which TS 24.008 lets the network omit. It is
/// kept when the description names one, because dropping it would widen the filter.
fn encode_contents(flow_description: &str) -> Result<Vec<u8>, String> {
    let rule = nextgcore_ipfw::compile_rule(flow_description)
        .map_err(|e| format!("flow description {flow_description:?}: {e}"))?;
    let mut out = Vec::new();
    if rule.ipv4_src {
        out.push(component::IPV4_REMOTE);
        out.extend_from_slice(&rule.ip.src.addr[0].to_be_bytes());
        out.extend_from_slice(&rule.ip.src.mask[0].to_be_bytes());
    }
    if rule.ipv4_dst {
        out.push(component::IPV4_LOCAL);
        out.extend_from_slice(&rule.ip.dst.addr[0].to_be_bytes());
        out.extend_from_slice(&rule.ip.dst.mask[0].to_be_bytes());
    }
    if rule.ipv6_src {
        out.push(component::IPV6_REMOTE_PREFIX);
        for w in rule.ip.src.addr {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out.push(prefix_len(&rule.ip.src.mask));
    }
    if rule.ipv6_dst {
        out.push(component::IPV6_LOCAL_PREFIX);
        for w in rule.ip.dst.addr {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out.push(prefix_len(&rule.ip.dst.mask));
    }
    if rule.proto != 0 {
        out.push(component::PROTOCOL);
        out.push(rule.proto);
    }
    for (range, single, ranged) in [
        (
            rule.port.dst,
            component::SINGLE_LOCAL_PORT,
            component::LOCAL_PORT_RANGE,
        ),
        (
            rule.port.src,
            component::SINGLE_REMOTE_PORT,
            component::REMOTE_PORT_RANGE,
        ),
    ] {
        if range.low == 0 && range.high == 0 {
            continue;
        }
        if range.low == range.high {
            out.push(single);
            out.extend_from_slice(&range.low.to_be_bytes());
        } else {
            out.push(ranged);
            out.extend_from_slice(&range.low.to_be_bytes());
            out.extend_from_slice(&range.high.to_be_bytes());
        }
    }
    if out.is_empty() {
        // A filter with no component matches everything. TS 24.008 has no "match all"
        // component, so it cannot be coded in an EPS TFT, and a dedicated bearer that
        // took every packet would starve the default bearer.
        return Err(format!(
            "flow description {flow_description:?} matches all traffic, which a dedicated \
             bearer's TFT cannot carry"
        ));
    }
    Ok(out)
}

fn prefix_len(mask: &[u32; 4]) -> u8 {
    mask.iter().map(|w| w.count_ones()).sum::<u32>() as u8
}

/// Encode a TFT (TS 24.008 §10.5.6.12) with no parameters list.
pub fn encode(operation: u8, filters: &[PacketFilter]) -> Result<Vec<u8>, String> {
    if filters.len() > 15 {
        return Err(format!(
            "{} packet filters; a TFT holds at most 15",
            filters.len()
        ));
    }
    let mut out = vec![((operation & 0x07) << 5) | (filters.len() as u8)];
    for f in filters {
        let contents = encode_contents(&f.flow_description)?;
        out.push((direction_bits(f.direction) << 4) | (f.identifier & 0x0f));
        out.push(f.precedence);
        out.push(contents.len() as u8);
        out.extend_from_slice(&contents);
    }
    Ok(out)
}

/// Decode a TFT or Traffic Aggregate Description.
///
/// A packet filter with a component this SMF cannot express as a flow description
/// (security parameter index, type of service, flow label) is an error, not skipped:
/// dropping a component would widen the filter beyond what the UE asked for.
pub fn decode(value: &[u8]) -> Result<Tft, String> {
    let first = *value.first().ok_or("empty TFT")?;
    let operation = first >> 5;
    let e_bit = first & 0x10 != 0;
    let count = usize::from(first & 0x0f);
    let mut filters = Vec::with_capacity(count);
    let mut off = 1usize;
    // Delete Packet Filters carries identifiers only (one octet each).
    if operation == op::DELETE_PACKET_FILTERS {
        for _ in 0..count {
            let id = *value
                .get(off)
                .ok_or("truncated packet filter identifier list")?;
            filters.push(PacketFilter {
                direction: FlowDirection::Bidirectional,
                identifier: id & 0x0f,
                precedence: 0,
                flow_description: String::new(),
            });
            off += 1;
        }
        return Ok(Tft { operation, filters });
    }
    if operation == op::DELETE_EXISTING_TFT || operation == op::NO_TFT_OPERATION {
        return Ok(Tft { operation, filters });
    }
    for n in 0..count {
        let hdr = value
            .get(off..off + 3)
            .ok_or(format!("packet filter {n} truncated"))?;
        let len = usize::from(hdr[2]);
        let contents = value
            .get(off + 3..off + 3 + len)
            .ok_or(format!("packet filter {n} contents truncated"))?;
        filters.push(PacketFilter {
            direction: direction_from_bits(hdr[0] >> 4),
            identifier: hdr[0] & 0x0f,
            precedence: hdr[1],
            flow_description: decode_contents(contents)?,
        });
        off += 3 + len;
    }
    // A parameters list may follow when E is set. Nothing in it changes the filters.
    let _ = e_bit;
    Ok(Tft { operation, filters })
}

fn ipv4_with_mask(addr: &[u8], mask: &[u8]) -> String {
    let a = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let bits: u32 = mask.iter().map(|b| b.count_ones()).sum();
    if bits == 32 {
        a.to_string()
    } else {
        format!("{a}/{bits}")
    }
}

fn ipv6_with_prefix(addr: &[u8], prefix: u8) -> String {
    let mut o = [0u8; 16];
    o.copy_from_slice(&addr[..16]);
    let a = std::net::Ipv6Addr::from(o);
    if prefix >= 128 {
        a.to_string()
    } else {
        format!("{a}/{prefix}")
    }
}

fn decode_contents(c: &[u8]) -> Result<String, String> {
    let mut proto: Option<u8> = None;
    let mut remote: Option<String> = None;
    let mut local: Option<String> = None;
    let mut remote_port: Option<String> = None;
    let mut local_port: Option<String> = None;
    let mut i = 0usize;
    let take = |i: usize, n: usize| -> Result<&[u8], String> {
        c.get(i..i + n)
            .ok_or_else(|| format!("packet filter component at {i} truncated"))
    };
    while i < c.len() {
        let t = c[i];
        i += 1;
        match t {
            component::IPV4_REMOTE | component::IPV4_LOCAL => {
                let v = take(i, 8)?;
                let s = ipv4_with_mask(&v[..4], &v[4..]);
                if t == component::IPV4_REMOTE {
                    remote = Some(s);
                } else {
                    local = Some(s);
                }
                i += 8;
            }
            component::IPV6_REMOTE => {
                let v = take(i, 32)?;
                let bits: u32 = v[16..].iter().map(|b| b.count_ones()).sum();
                remote = Some(ipv6_with_prefix(&v[..16], bits as u8));
                i += 32;
            }
            component::IPV6_REMOTE_PREFIX | component::IPV6_LOCAL_PREFIX => {
                let v = take(i, 17)?;
                let s = ipv6_with_prefix(&v[..16], v[16]);
                if t == component::IPV6_REMOTE_PREFIX {
                    remote = Some(s);
                } else {
                    local = Some(s);
                }
                i += 17;
            }
            component::PROTOCOL => {
                proto = Some(take(i, 1)?[0]);
                i += 1;
            }
            component::SINGLE_LOCAL_PORT | component::SINGLE_REMOTE_PORT => {
                let v = take(i, 2)?;
                let p = u16::from_be_bytes([v[0], v[1]]).to_string();
                if t == component::SINGLE_LOCAL_PORT {
                    local_port = Some(p);
                } else {
                    remote_port = Some(p);
                }
                i += 2;
            }
            component::LOCAL_PORT_RANGE | component::REMOTE_PORT_RANGE => {
                let v = take(i, 4)?;
                let p = format!(
                    "{}-{}",
                    u16::from_be_bytes([v[0], v[1]]),
                    u16::from_be_bytes([v[2], v[3]])
                );
                if t == component::LOCAL_PORT_RANGE {
                    local_port = Some(p);
                } else {
                    remote_port = Some(p);
                }
                i += 4;
            }
            other => {
                return Err(format!(
                    "packet filter component type {other:#04x} cannot be expressed as a flow \
                     description"
                ))
            }
        }
    }
    let mut s = format!(
        "permit out {} from {}",
        proto.map_or("ip".to_string(), |p| p.to_string()),
        remote.unwrap_or_else(|| "any".to_string())
    );
    if let Some(p) = remote_port {
        s.push(' ');
        s.push_str(&p);
    }
    s.push_str(" to ");
    s.push_str(&local.unwrap_or_else(|| "assigned".to_string()));
    if let Some(p) = local_port {
        s.push(' ');
        s.push_str(&p);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pf(direction: FlowDirection, id: u8, desc: &str) -> PacketFilter {
        PacketFilter {
            direction,
            identifier: id,
            precedence: 10 + id,
            flow_description: desc.to_string(),
        }
    }

    /// The octets TS 24.008 §10.5.6.12 gives, worked by hand: create new TFT, one
    /// downlink filter, UDP from 198.51.100.7 port 5004.
    #[test]
    fn a_downlink_filter_encodes_to_the_24_008_octets() {
        let tft = encode(
            op::CREATE_NEW_TFT,
            &[pf(
                FlowDirection::DownlinkOnly,
                1,
                "permit out 17 from 198.51.100.7 5004 to assigned",
            )],
        )
        .unwrap();
        assert_eq!(
            tft,
            vec![
                0x21, // create new TFT, E=0, one filter
                0x11, // downlink only, identifier 1
                11,   // precedence
                14,   // contents length: 9 + 2 + 3
                0x10, 198, 51, 100, 7, 255, 255, 255, 255, // IPv4 remote address
                0x30, 17, // protocol UDP
                0x50, 0x13, 0x8c, // single remote port 5004
            ]
        );
    }

    #[test]
    fn filters_round_trip_through_the_wire_coding() {
        let filters = vec![
            pf(
                FlowDirection::DownlinkOnly,
                1,
                "permit out 17 from 198.51.100.0/24 5004 to assigned",
            ),
            pf(
                FlowDirection::UplinkOnly,
                2,
                "permit out 6 from 203.0.113.9 80-90 to assigned 4000",
            ),
            pf(
                FlowDirection::Bidirectional,
                3,
                "permit out ip from 2001:db8::/32 to assigned",
            ),
        ];
        let tft = decode(&encode(op::ADD_PACKET_FILTERS, &filters).unwrap()).unwrap();
        assert_eq!(tft.operation, op::ADD_PACKET_FILTERS);
        assert_eq!(tft.filters, filters);
    }

    #[test]
    fn a_match_all_filter_is_refused() {
        assert!(encode(
            op::CREATE_NEW_TFT,
            &[pf(
                FlowDirection::DownlinkOnly,
                1,
                "permit out ip from any to assigned"
            )]
        )
        .is_err());
    }

    #[test]
    fn a_component_with_no_flow_description_is_an_error_not_a_wider_filter() {
        // One filter whose only component is a security parameter index (type 0x60).
        let tad = [0x21, 0x31, 1, 5, 0x60, 0, 0, 0, 1];
        assert!(decode(&tad).is_err());
    }

    #[test]
    fn a_truncated_tft_is_an_error() {
        assert!(decode(&[0x21, 0x11, 1, 9, 0x10, 1, 2]).is_err());
        assert!(decode(&[]).is_err());
    }
}
