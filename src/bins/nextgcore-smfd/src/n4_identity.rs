//! The SMF's N4 identity: the PFCP Node ID it signals and the IPv4 address it puts
//! in every CP F-SEID (#797).
//!
//! Before #797 both came from `SMF_PFCP_ADDR`, which is also the N4 bind address.
//! The k8s manifests and the Helm chart bind `0.0.0.0`, so every SMF there
//! advertised Node ID `0.0.0.0` and a CP F-SEID of `0.0.0.0`, and the EKS EPC
//! profile bound the pod IP, so its Node ID changed on every restart.
//!
//! TS 29.244 §5.8.1: "a CP function or a UP function shall be identified by a unique
//! Node ID", which "may be set to an FQDN or to an IP address". An unspecified
//! address identifies nothing. A per-pod address is a different CP function after
//! every restart, which defeats the §6.2.6.2.2 "same Node ID" re-association
//! handling: the UP function cannot tell the restarted SMF from a new one.
//!
//! The two values are therefore separate:
//! - `SMF_PFCP_NODE_ID` names the CP function. An IPv4 literal or an FQDN (for
//!   example the SMF's Service name), stable across restarts. When unset, the bind
//!   address is used if it is a specified address, and otherwise the F-SEID address.
//! - `SMF_PFCP_ADVERTISE_ADDR` is the routable IPv4 address the UPF can reach this
//!   SMF at, carried in the CP F-SEID (§8.2.37). §5.8.1 lets it differ from the
//!   Node ID ("The PFCP entities shall accept any new IP address allocated as part
//!   of F-SEID other than the one(s) communicated in the Node Id"). When unset, the
//!   bind address is used if it is specified; otherwise an IPv4 Node ID; otherwise
//!   the local address the kernel routes toward the first UPF.
//!
//! When no routable F-SEID address can be found the SMF refuses to start: an
//! F-SEID of `0.0.0.0` is not an address any UPF can send to.

use std::net::Ipv4Addr;

use nextgcore_pfcp::types::NodeId;

/// The resolved N4 identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N4Identity {
    /// The PFCP Node ID (TS 29.244 §8.2.38).
    pub node_id: NodeId,
    /// The IPv4 address of every CP F-SEID (TS 29.244 §8.2.37).
    pub f_seid_ipv4: [u8; 4],
    /// Whether the Node ID was configured explicitly (or is the specified bind
    /// address) rather than derived from the F-SEID address. A derived Node ID is
    /// only as stable as that address, which the operator should know.
    pub node_id_explicit: bool,
}

/// The raw configuration the identity is resolved from. Each field is the trimmed
/// value of its environment variable, `None` when unset or empty.
#[derive(Debug, Default, Clone)]
pub struct N4IdentityConfig<'a> {
    /// `SMF_PFCP_ADDR`, the N4 bind address.
    pub bind_addr: Option<&'a str>,
    /// `SMF_PFCP_NODE_ID`.
    pub node_id: Option<&'a str>,
    /// `SMF_PFCP_ADVERTISE_ADDR`.
    pub advertise_addr: Option<&'a str>,
}

/// Resolve the N4 identity. `discover` is asked for the local address that routes
/// toward the UPF only when nothing configured supplies a routable F-SEID address.
pub fn resolve_n4_identity(
    cfg: &N4IdentityConfig<'_>,
    discover: impl FnOnce() -> Option<Ipv4Addr>,
) -> Result<N4Identity, String> {
    let bind = match cfg.bind_addr {
        None => None,
        Some(s) => Some(s.parse::<Ipv4Addr>().map_err(|_| {
            format!("SMF_PFCP_ADDR '{s}' is not an IPv4 address (the N4 socket is IPv4)")
        })?),
    };
    let specified_bind = bind.filter(|a| !a.is_unspecified());

    let advertise = match cfg.advertise_addr {
        None => None,
        Some(s) => {
            let a = s
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("SMF_PFCP_ADVERTISE_ADDR '{s}' is not an IPv4 address"))?;
            if !is_routable(a) {
                return Err(format!(
                    "SMF_PFCP_ADVERTISE_ADDR '{s}' is not an address a UPF can send to"
                ));
            }
            Some(a)
        }
    };

    let explicit_node_id = match cfg.node_id {
        None => None,
        Some(s) => Some(parse_node_id(s)?),
    };
    let node_id_ipv4 = explicit_node_id
        .as_ref()
        .and_then(|n| n.ipv4_addr.map(Ipv4Addr::from));

    let f_seid = match advertise.or(specified_bind).or(node_id_ipv4) {
        Some(a) => a,
        None => discover().filter(|a| is_routable(*a)).ok_or_else(|| {
            "no routable N4 address for the CP F-SEID: SMF_PFCP_ADDR is the unspecified \
             address and neither SMF_PFCP_ADVERTISE_ADDR nor an IPv4 SMF_PFCP_NODE_ID is \
             set, and no local route to the UPF was found. Set SMF_PFCP_ADVERTISE_ADDR to \
             the address the UPF reaches this SMF at (on k8s, the pod IP)"
                .to_string()
        })?,
    };

    let (node_id, node_id_explicit) = match explicit_node_id {
        Some(n) => (n, true),
        None => match specified_bind {
            Some(a) => (NodeId::new_ipv4(a.octets()), true),
            None => (NodeId::new_ipv4(f_seid.octets()), false),
        },
    };

    Ok(N4Identity {
        node_id,
        f_seid_ipv4: f_seid.octets(),
        node_id_explicit,
    })
}

/// A Node ID for the log: the address or the FQDN.
pub fn display_node_id(node_id: &NodeId) -> String {
    if let Some(fqdn) = &node_id.fqdn {
        return fqdn.clone();
    }
    if let Some(a) = node_id.ipv4_addr {
        return Ipv4Addr::from(a).to_string();
    }
    if let Some(a) = node_id.ipv6_addr {
        return std::net::Ipv6Addr::from(a).to_string();
    }
    "<empty>".to_string()
}

/// An address a UPF can send to: neither unspecified nor broadcast nor multicast.
fn is_routable(a: Ipv4Addr) -> bool {
    !(a.is_unspecified() || a.is_broadcast() || a.is_multicast())
}

/// Parse `SMF_PFCP_NODE_ID`: an IPv4 literal or an FQDN.
fn parse_node_id(s: &str) -> Result<NodeId, String> {
    if let Ok(a) = s.parse::<Ipv4Addr>() {
        if !is_routable(a) {
            return Err(format!(
                "SMF_PFCP_NODE_ID '{s}' does not identify a node (TS 29.244 §5.8.1)"
            ));
        }
        return Ok(NodeId::new_ipv4(a.octets()));
    }
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(format!(
            "SMF_PFCP_NODE_ID '{s}' is an IPv6 address; this SMF's N4 is IPv4, so use \
             an IPv4 address or an FQDN"
        ));
    }
    validate_fqdn(s).map_err(|why| format!("SMF_PFCP_NODE_ID '{s}' is not an FQDN: {why}"))?;
    // A trailing root dot is accepted and dropped: the IE excludes the root label.
    Ok(NodeId::new_fqdn(
        s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase(),
    ))
}

/// RFC 1035 §2.3.1 / §2.3.4 host-name syntax: letters, digits and hyphens, labels of
/// 1 to 63 octets that neither start nor end with a hyphen, at most 255 octets
/// encoded. At least two labels, because a single label is not fully qualified.
fn validate_fqdn(s: &str) -> Result<(), &'static str> {
    let name = s.strip_suffix('.').unwrap_or(s);
    if name.is_empty() {
        return Err("empty");
    }
    // Encoded length: one length octet per label plus the label octets.
    if name.len() + 1 > 255 {
        return Err("longer than 255 octets");
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err("a single label is not fully qualified");
    }
    for label in labels {
        if label.is_empty() {
            return Err("empty label");
        }
        if label.len() > 63 {
            return Err("label longer than 63 octets");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("label starts or ends with a hyphen");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("only letters, digits and hyphens are allowed");
        }
    }
    Ok(())
}

/// The local IPv4 address the kernel would use to reach `peer`. No packet is sent:
/// connecting a UDP socket only selects a route.
pub fn local_ipv4_toward(peer: std::net::SocketAddr) -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect(peer).ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(a) if !a.is_unspecified() => Some(a),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg<'a>(
        bind: Option<&'a str>,
        node: Option<&'a str>,
        adv: Option<&'a str>,
    ) -> N4IdentityConfig<'a> {
        N4IdentityConfig {
            bind_addr: bind,
            node_id: node,
            advertise_addr: adv,
        }
    }

    fn never() -> Option<Ipv4Addr> {
        panic!("discovery must not run when the configuration supplies an address")
    }

    /// The k8s manifests and the Helm chart: bind 0.0.0.0, Node ID the Service FQDN,
    /// F-SEID the pod IP. Before #797 both were 0.0.0.0.
    #[test]
    fn a_wildcard_bind_with_a_service_fqdn_signals_the_fqdn_and_the_pod_ip() {
        let id = resolve_n4_identity(
            &cfg(
                Some("0.0.0.0"),
                Some("smf.nextg-system.svc.cluster.local"),
                Some("10.1.2.3"),
            ),
            never,
        )
        .unwrap();
        assert_eq!(
            id.node_id,
            NodeId::new_fqdn("smf.nextg-system.svc.cluster.local".into())
        );
        assert_eq!(id.f_seid_ipv4, [10, 1, 2, 3]);
        assert!(id.node_id_explicit);
    }

    /// docker compose: a fixed bind address is both the Node ID and the F-SEID
    /// address, unchanged from before #797.
    #[test]
    fn a_specified_bind_address_is_the_node_id_and_the_f_seid_address() {
        let id = resolve_n4_identity(&cfg(Some("172.23.0.4"), None, None), never).unwrap();
        assert_eq!(id.node_id, NodeId::new_ipv4([172, 23, 0, 4]));
        assert_eq!(id.f_seid_ipv4, [172, 23, 0, 4]);
        assert!(id.node_id_explicit);
    }

    /// A wildcard bind with nothing else configured never signals 0.0.0.0: it uses
    /// the address that routes to the UPF, and says the Node ID is derived.
    #[test]
    fn a_wildcard_bind_alone_uses_the_routed_address_never_the_wildcard() {
        let id = resolve_n4_identity(&cfg(Some("0.0.0.0"), None, None), || {
            Some(Ipv4Addr::new(192, 168, 7, 9))
        })
        .unwrap();
        assert_eq!(id.node_id, NodeId::new_ipv4([192, 168, 7, 9]));
        assert_eq!(id.f_seid_ipv4, [192, 168, 7, 9]);
        assert!(!id.node_id_explicit);

        // No bind address at all. main.rs always passes one (SMF_PFCP_ADDR, else the
        // loopback default of #1308); this is the function's own contract.
        let id = resolve_n4_identity(&cfg(None, None, None), || Some(Ipv4Addr::LOCALHOST)).unwrap();
        assert_eq!(id.node_id, NodeId::new_ipv4([127, 0, 0, 1]));
    }

    #[test]
    fn no_routable_address_refuses_to_start() {
        let err = resolve_n4_identity(&cfg(Some("0.0.0.0"), None, None), || None).unwrap_err();
        assert!(err.contains("SMF_PFCP_ADVERTISE_ADDR"), "{err}");
        // A discovered wildcard is no better.
        assert!(
            resolve_n4_identity(&cfg(Some("0.0.0.0"), None, None), || Some(
                Ipv4Addr::UNSPECIFIED
            ))
            .is_err()
        );
        // An FQDN Node ID still needs an F-SEID address.
        assert!(
            resolve_n4_identity(&cfg(Some("0.0.0.0"), Some("smf.example.org"), None), || {
                None
            })
            .is_err()
        );
    }

    /// The EKS EPC profile: bind the pod IP, Node ID the Service FQDN, so the Node ID
    /// survives the restart and the F-SEID follows the pod.
    #[test]
    fn an_fqdn_node_id_overrides_a_specified_bind_address() {
        let id = resolve_n4_identity(
            &cfg(Some("10.0.0.7"), Some("pgwc.epc.svc.cluster.local"), None),
            never,
        )
        .unwrap();
        assert_eq!(
            id.node_id,
            NodeId::new_fqdn("pgwc.epc.svc.cluster.local".into())
        );
        assert_eq!(id.f_seid_ipv4, [10, 0, 0, 7]);
    }

    #[test]
    fn an_ipv4_node_id_supplies_the_f_seid_address_when_nothing_else_does() {
        let id = resolve_n4_identity(&cfg(Some("0.0.0.0"), Some("10.9.9.9"), None), never).unwrap();
        assert_eq!(id.node_id, NodeId::new_ipv4([10, 9, 9, 9]));
        assert_eq!(id.f_seid_ipv4, [10, 9, 9, 9]);
    }

    #[test]
    fn the_advertise_address_wins_for_the_f_seid() {
        let id =
            resolve_n4_identity(&cfg(Some("10.0.0.7"), None, Some("10.0.0.8")), never).unwrap();
        assert_eq!(id.node_id, NodeId::new_ipv4([10, 0, 0, 7]));
        assert_eq!(id.f_seid_ipv4, [10, 0, 0, 8]);
    }

    #[test]
    fn invalid_values_are_rejected_with_the_variable_named() {
        for (c, var) in [
            (cfg(Some("bogus"), None, None), "SMF_PFCP_ADDR"),
            (
                cfg(None, Some("0.0.0.0"), Some("10.0.0.1")),
                "SMF_PFCP_NODE_ID",
            ),
            (cfg(None, Some("::1"), Some("10.0.0.1")), "SMF_PFCP_NODE_ID"),
            (cfg(None, Some("smf"), Some("10.0.0.1")), "SMF_PFCP_NODE_ID"),
            (
                cfg(None, Some("smf..example"), Some("10.0.0.1")),
                "SMF_PFCP_NODE_ID",
            ),
            (
                cfg(None, Some("-smf.example"), Some("10.0.0.1")),
                "SMF_PFCP_NODE_ID",
            ),
            (
                cfg(None, Some("smf_1.example"), Some("10.0.0.1")),
                "SMF_PFCP_NODE_ID",
            ),
            (cfg(None, None, Some("0.0.0.0")), "SMF_PFCP_ADVERTISE_ADDR"),
            (
                cfg(None, None, Some("224.0.0.1")),
                "SMF_PFCP_ADVERTISE_ADDR",
            ),
            (
                cfg(None, None, Some("smf.example")),
                "SMF_PFCP_ADVERTISE_ADDR",
            ),
        ] {
            let err = resolve_n4_identity(&c, || Some(Ipv4Addr::LOCALHOST)).unwrap_err();
            assert!(err.starts_with(var), "{c:?}: {err}");
        }
        let long_label = format!("{}.example", "a".repeat(64));
        assert!(
            resolve_n4_identity(&cfg(None, Some(&long_label), Some("10.0.0.1")), || None).is_err()
        );
        let long_name = format!("{}example", "abcdefgh.".repeat(29));
        assert!(long_name.len() > 254);
        assert!(
            resolve_n4_identity(&cfg(None, Some(&long_name), Some("10.0.0.1")), || None).is_err()
        );
    }

    #[test]
    fn an_fqdn_with_a_root_dot_or_capitals_is_normalised() {
        let id = resolve_n4_identity(
            &cfg(None, Some("SMF.Example.org."), Some("10.0.0.1")),
            never,
        )
        .unwrap();
        assert_eq!(id.node_id, NodeId::new_fqdn("smf.example.org".into()));
    }

    #[test]
    fn the_routed_address_toward_loopback_is_loopback() {
        assert_eq!(
            local_ipv4_toward("127.0.0.1:8805".parse().unwrap()),
            Some(Ipv4Addr::LOCALHOST)
        );
    }
}
