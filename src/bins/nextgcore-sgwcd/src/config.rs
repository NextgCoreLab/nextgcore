//! Configuration file parsing (issue #387).
//!
//! ## Why this module exists
//!
//! `SgwcApp::init` took the `--config` path as `_config_path` and discarded it, and
//! the crate had no serde dependency at all — so every field of the shipped
//! `docker/rust/configs/epc/sgwc.yaml` was inert. The damaging one was
//! `sgwc.pfcp.client.sgwu`, which names the SGW-U this SGW-C provisions user planes
//! on: with nothing reading it, `pfcp_path::configured_sgwu_addr` fell back to
//! `127.0.0.1`, the Association Setup Request went to the SGW-C's OWN Sxa socket,
//! and the CI `EPC bring-up` stage failed with `sgwu_pfcp_associations never
//! reached 1`. TS 29.244 §6.2.6.2.1 has the CP function *retrieve an IP address of
//! the UP function* before it can establish a first PFCP session there; there was
//! nowhere for that address to come from.
//!
//! ## Shape, and why it is this shape
//!
//! Modelled on `nextgcore-mmed`'s `config.rs` (#157), which is the closest analogue
//! in the tree: same problem (a shipped YAML file read by nothing), same document
//! layout (`<nf>.<interface>.server` / `.client.<peer>` lists of
//! `{address, port}`), and it already parses `mme.gtpc.client.sgwc` — the S11 peer
//! list — into exactly the shape `pfcp.client.sgwu` needs. Following it rather than
//! `smfd`'s typed-struct loader because `smfd` reads its PFCP peer from the
//! environment (`UPF_PFCP_ADDR`) and not from YAML at all, so it is precedent for
//! the wrong half of this problem.
//!
//! Every field is optional: a partial file configures what it names and leaves the
//! rest at its default, and a missing or malformed file logs a warning and changes
//! nothing rather than taking an EPC control plane down over a scratch file.
//!
//! ## What is deliberately not read here
//!
//! `sgwc.gtpc.server` is declared in the same file and is also unread — see
//! [`GtpcYaml`] for why folding it in here would trade a loud misconfiguration for
//! a silent one.

use std::net::{Ipv4Addr, SocketAddr};

use serde::Deserialize;

use crate::context::SgwcContext;
use crate::pfcp_path::PFCP_PORT;

// ============================================================================
// YAML shape
// ============================================================================

/// One `{address, port}` entry, the shape every list in these config files uses.
#[derive(Debug, Default, Deserialize)]
struct AddrEntry {
    address: Option<String>,
    port: Option<u16>,
}

/// `sgwc.pfcp.client`: the peers this SGW-C dials on Sxa.
#[derive(Debug, Default, Deserialize)]
struct PfcpClientYaml {
    sgwu: Option<Vec<AddrEntry>>,
}

/// `sgwc.pfcp`: the Sxa interface (#387).
///
/// `server` is the address this SGW-C presents on Sxa and `client.sgwu` the UP
/// function it associates with. Both were declared and unread until #387.
#[derive(Debug, Default, Deserialize)]
struct PfcpYaml {
    server: Option<Vec<AddrEntry>>,
    client: Option<PfcpClientYaml>,
}

/// `sgwc.gtpc.server`: present in the shipped config and deliberately NOT applied.
///
/// It is declared here so this loader accepts the file as written rather than
/// rejecting an unknown key, and so the omission is recorded at the site instead of
/// looking like an oversight.
///
/// Reading it is a separate change with its own hazard: `gtp_path::gtp_open` derives
/// `ctx.set_gtpu_address` from the S11 advertised address when `SGWC_GTPU_ADVERTISE`
/// is unset, and the SGW's user-plane endpoints live on the **SGW-U** (172.24.0.6),
/// not on the SGW-C (172.24.0.3). So applying `gtpc.server` here would silently
/// start advertising 172.24.0.3 in S1-U/S5-U F-TEIDs, replacing today's loud "No
/// GTP-U address configured" with a wrong address that fails invisibly, because
/// GTP-U is unacknowledged. That decision needs the SGW-U's address too, which this
/// file does not carry, so it is filed rather than guessed.
#[derive(Debug, Default, Deserialize)]
struct GtpcYaml {
    #[allow(dead_code)]
    server: Option<Vec<AddrEntry>>,
}

#[derive(Debug, Default, Deserialize)]
struct SgwcSection {
    gtpc: Option<GtpcYaml>,
    pfcp: Option<PfcpYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct SgwcYaml {
    sgwc: Option<SgwcSection>,
}

// ============================================================================
// Resolved configuration
// ============================================================================

/// What this loader resolved, flat and free of YAML shape.
///
/// Returned rather than written straight into the global context so the parse can be
/// asserted on its own, without a test having to take the process-state guard to read
/// the answer back out of ambient state.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SgwcConfig {
    /// The address this SGW-C advertises as its PFCP Node ID, from
    /// `sgwc.pfcp.server[0].address`.
    ///
    /// TS 29.244 §5.8.1 makes the Node ID the identity of a PFCP association, and
    /// §6.2.6.2.2 has the UP function *store the Node ID of the CP function as the
    /// identifier of the PFCP association* — so a CP function that advertises
    /// `127.0.0.1` asks a remote UP function to key the association on an address
    /// that means nothing off-host.
    pub pfcp_node_ip: Option<Ipv4Addr>,
    /// The SGW-U peers from `sgwc.pfcp.client.sgwu`, in file order.
    ///
    /// A list because the file declares one and because TS 29.244 §5.8.1 permits a CP
    /// function to hold associations with several UP functions. Only the first is
    /// used — see [`SgwcConfig::sgwu_peer`].
    pub sgwu_peers: Vec<SocketAddr>,
}

impl SgwcConfig {
    /// The one SGW-U this SGW-C associates with and sends every session message to.
    ///
    /// **Only the first entry is used, and that is a stated ceiling rather than an
    /// accident.** TS 29.244 §5.8.1 allows "A CP function may have PFCP Associations
    /// set up with multiple UP functions", but choosing *which* UP function serves a
    /// given session is a selection function this SGW-C does not have: `pfcp_path`
    /// carries one destination per queued request and nothing maps a session to a
    /// peer (contrast `smfd`, which has `select_upf` and a client pool). Associating
    /// with every configured peer would therefore set up associations no session can
    /// ever be placed on — advertising a capability that is not there. So the extra
    /// entries are named in a warning at load time and otherwise unused, the same
    /// shape `mmed` uses for a multi-entry `mme.gtpc.client.sgwc`.
    pub fn sgwu_peer(&self) -> Option<SocketAddr> {
        self.sgwu_peers.first().copied()
    }
}

// ============================================================================
// Loading
// ============================================================================

/// Parse `path` into an [`SgwcConfig`].
///
/// A missing file, unparsable YAML or no `sgwc:` section yields
/// `SgwcConfig::default()` and a warning that NAMES the file, because the previous
/// silence is what let a fully populated config go unread.
pub fn load_config(path: &str) -> SgwcConfig {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) => {
            log::warn!("Could not read config file '{path}': {e}. Using defaults.");
            return SgwcConfig::default();
        }
    };

    let yaml: SgwcYaml = match serde_yaml::from_str(&content) {
        Ok(yaml) => yaml,
        Err(e) => {
            log::warn!("Failed to parse YAML config '{path}': {e}. Using defaults.");
            return SgwcConfig::default();
        }
    };

    let Some(sgwc) = yaml.sgwc else {
        log::warn!("Config '{path}' has no 'sgwc' section. Using defaults.");
        return SgwcConfig::default();
    };

    let config = resolve(sgwc);
    log::info!("Configuration loaded from {path}");
    config
}

fn resolve(sgwc: SgwcSection) -> SgwcConfig {
    let mut config = SgwcConfig::default();

    // `gtpc` is accepted and not applied; see `GtpcYaml`.
    let _ = sgwc.gtpc;

    let Some(pfcp) = sgwc.pfcp else {
        return config;
    };

    // The Node ID. IPv4 only, because `SxaNode::open` takes an `Ipv4Addr` and
    // `NodeId::new_ipv4` is what the Association Setup Request carries; a v6 or FQDN
    // entry (both legal per TS 29.244 §8.2.38) is skipped with a note rather than
    // treated as a fatal config error, so the daemon still starts and says why.
    let servers = pfcp.server.unwrap_or_default();
    if servers.len() > 1 {
        log::warn!(
            "{} sgwc.pfcp.server addresses configured; the first is advertised as the PFCP \
             Node ID, because TS 29.244 §5.8.1 gives a CP function ONE Node ID ('When set to \
             an IP address, it indicates that the CP/UP function only exposes one IP address \
             for the PFCP Association signalling')",
            servers.len()
        );
    }
    if let Some(address) = servers.into_iter().next().and_then(|s| s.address) {
        match address.parse::<Ipv4Addr>() {
            Ok(ip) => config.pfcp_node_ip = Some(ip),
            Err(_) => log::warn!(
                "sgwc.pfcp.server address '{address}' is not an IPv4 address; the PFCP Node ID \
                 is left at its default"
            ),
        }
    }

    // The SGW-U peers.
    for peer in pfcp
        .client
        .and_then(|client| client.sgwu)
        .unwrap_or_default()
    {
        let Some(address) = peer.address else {
            continue;
        };
        // A bare address means the fixed PFCP port (TS 29.244 §4.2.2).
        let port = peer.port.unwrap_or(PFCP_PORT);
        match parse_socket_addr(&address, port) {
            Some(addr) => config.sgwu_peers.push(addr),
            None => log::warn!("Ignoring unparsable SGW-U address '{address}'"),
        }
    }
    if config.sgwu_peers.len() > 1 {
        log::warn!(
            "{} SGW-U peers configured; only {} is associated with and used for every session, \
             because this SGW-C has no UP function selection: an Sxa request carries one \
             destination and no session is bound to a peer",
            config.sgwu_peers.len(),
            config.sgwu_peers[0]
        );
    }

    config
}

/// `<host>` or `<host>:<port>` to a socket address, defaulting the port.
///
/// Same helper and same shape as `mmed`'s, so the two loaders accept the same
/// spellings of an address.
fn parse_socket_addr(address: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Some(addr);
    }
    address
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

/// Publish a resolved configuration into the global context, where the Sxa send paths
/// read it.
///
/// Separate from [`load_config`] so the parse is testable without ambient state, and
/// called once from `SgwcApp::init` BEFORE `pfcp_open` — the Node ID is baked into the
/// node at open time.
pub fn apply(ctx: &SgwcContext, config: &SgwcConfig) {
    match config.pfcp_node_ip {
        Some(ip) => log::info!("PFCP/Sxa Node ID: {ip}"),
        None => log::warn!(
            "No sgwc.pfcp.server address configured: the PFCP Node ID falls back to loopback, \
             which a remote SGW-U cannot use as the association identifier it stores \
             (TS 29.244 §6.2.6.2.2). Set sgwc.pfcp.server[0].address or SGWC_PFCP_NODE_IP."
        ),
    }
    ctx.set_pfcp_node_ip(config.pfcp_node_ip);

    match config.sgwu_peer() {
        Some(peer) => log::info!("Sxa SGW-U peer: {peer}"),
        None => log::warn!(
            "No sgwc.pfcp.client.sgwu address configured: the SGW-C would associate with its \
             own loopback and every session request would fail (TS 29.244 §6.2.6.2.1 requires \
             the CP function to retrieve an IP address OF THE UP FUNCTION). Set \
             sgwc.pfcp.client.sgwu[0].address or SGWC_SGWU_ADDR."
        ),
    }
    ctx.set_sgwu_peers(config.sgwu_peers.clone());
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration the Docker EPC actually ships, read from the tree so config
    /// drift breaks this test instead of going unnoticed — the same anchoring
    /// `mmed::config`'s tests use.
    const SHIPPED_CONFIG: &str = "../../../docker/rust/configs/epc/sgwc.yaml";

    fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// The headline fix: the shipped file's `pfcp.client.sgwu` resolves to the SGW-U's
    /// container address, and `pfcp.server` to the SGW-C's own.
    ///
    /// Asserted as EQUALITY against the values only reachable by reading the file —
    /// `172.24.0.6:8805` and `172.24.0.3` appear nowhere in any default. Before #387
    /// `sgwu_peers` was unreachable (nothing parsed the section) and the resolved peer
    /// was `127.0.0.1:8805`.
    #[test]
    fn the_shipped_config_resolves_the_sgwu_peer_and_the_node_id() {
        let config = load_config(SHIPPED_CONFIG);
        assert_eq!(
            config.sgwu_peer(),
            Some(SocketAddr::from(([172, 24, 0, 6], 8805))),
            "sgwc.pfcp.client.sgwu[0] must be the SGW-U container, on TS 29.244 §4.2.2's port"
        );
        assert_eq!(
            config.pfcp_node_ip,
            Some(Ipv4Addr::new(172, 24, 0, 3)),
            "sgwc.pfcp.server[0] is what the Association Setup Request advertises as Node ID"
        );
    }

    /// An explicit `ip:port` and an explicit `port:` key both work, so a deployment can
    /// put an SGW-U on a non-standard port without editing the daemon.
    #[test]
    fn an_explicit_port_overrides_the_fixed_pfcp_port() {
        let path = write_temp(
            "nextgcore-sgwcd-port.yaml",
            r#"
sgwc:
  pfcp:
    client:
      sgwu:
        - address: 10.0.0.6
          port: 9805
"#,
        );
        let config = load_config(path.to_str().unwrap());
        assert_eq!(
            config.sgwu_peer(),
            Some(SocketAddr::from(([10, 0, 0, 6], 9805)))
        );

        let path = write_temp(
            "nextgcore-sgwcd-inline-port.yaml",
            r#"
sgwc:
  pfcp:
    client:
      sgwu:
        - address: 10.0.0.6:9806
"#,
        );
        let config = load_config(path.to_str().unwrap());
        assert_eq!(
            config.sgwu_peer(),
            Some(SocketAddr::from(([10, 0, 0, 6], 9806)))
        );
    }

    /// Several `client.sgwu` entries are all parsed, and the FIRST is the one used.
    ///
    /// Pinned because "only the first" is a documented ceiling (no UP function
    /// selection exists here), not an implementation detail: if a later change starts
    /// associating with all of them this assertion should be revisited deliberately.
    #[test]
    fn several_sgwu_entries_are_kept_and_the_first_is_the_one_used() {
        let path = write_temp(
            "nextgcore-sgwcd-multi.yaml",
            r#"
sgwc:
  pfcp:
    client:
      sgwu:
        - address: 10.0.0.6
        - address: 10.0.0.7
"#,
        );
        let config = load_config(path.to_str().unwrap());
        assert_eq!(
            config.sgwu_peers,
            vec![
                SocketAddr::from(([10, 0, 0, 6], PFCP_PORT)),
                SocketAddr::from(([10, 0, 0, 7], PFCP_PORT)),
            ],
            "every entry is parsed, so the warning can name how many were ignored"
        );
        assert_eq!(
            config.sgwu_peer(),
            Some(SocketAddr::from(([10, 0, 0, 6], PFCP_PORT)))
        );
    }

    /// A missing, malformed or `sgwc:`-less file resolves nothing and is not fatal.
    #[test]
    fn missing_and_malformed_files_resolve_nothing() {
        assert_eq!(
            load_config("/nonexistent/nextgcore/sgwc.yaml"),
            SgwcConfig::default()
        );

        let path = write_temp("nextgcore-sgwcd-bad.yaml", "sgwc: [this is not a mapping\n");
        assert_eq!(
            load_config(path.to_str().unwrap()),
            SgwcConfig::default(),
            "unparsable YAML changes nothing"
        );

        let path = write_temp("nextgcore-sgwcd-empty.yaml", "logger:\n  level: info\n");
        assert_eq!(
            load_config(path.to_str().unwrap()),
            SgwcConfig::default(),
            "a file that parses but names no sgwc section changes nothing"
        );
    }

    /// An unusable entry is skipped rather than poisoning the ones around it, and an
    /// `sgwc.gtpc` section is accepted without being applied (it is in the shipped
    /// file, so refusing it would refuse the real config).
    #[test]
    fn unusable_entries_are_skipped_and_gtpc_is_accepted_unapplied() {
        let path = write_temp(
            "nextgcore-sgwcd-skip.yaml",
            r#"
sgwc:
  gtpc:
    server:
      - address: 172.24.0.3
  pfcp:
    server:
      - address: not-an-address
    client:
      sgwu:
        - port: 8805
        - address: bogus
        - address: 10.0.0.9
"#,
        );
        let config = load_config(path.to_str().unwrap());
        assert_eq!(
            config.pfcp_node_ip, None,
            "an unparsable server address leaves the Node ID unset, and says so"
        );
        assert_eq!(
            config.sgwu_peers,
            vec![SocketAddr::from(([10, 0, 0, 9], PFCP_PORT))],
            "the entry with no address and the unparsable one are skipped; the good one survives"
        );
    }
}
