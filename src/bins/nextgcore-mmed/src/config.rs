//! Configuration file parsing (issue #157).
//!
//! ## Why this module exists
//!
//! `MmeApp::init` took the `--config` path as `_config_path` and discarded it,
//! and the crate had no serde dependency at all. Every field of the shipped
//! `mme.yaml` was inert — most damagingly `mme.gummei`, because
//! `handle_s1_setup_request` answers **S1 Setup Failure** when
//! `served_gummei` is empty, which in production it always was. The daemon bound
//! S1-MME and then refused every eNB association, so nothing downstream of S1
//! Setup could run.
//!
//! ## Shape
//!
//! The serde types mirror `docker/rust/configs/epc/mme.yaml` exactly. Every
//! field is optional: a partial file configures what it names and leaves the rest
//! at its default, and a missing or malformed file logs a warning and changes
//! nothing (the behaviour amfd's loader already has).
//!
//! ## What is deliberately not read here
//!
//! `mme.freeDiameter` names a file in freeDiameter's own `.conf` format, which
//! nothing in this tree parses — so the path is *recorded* in `diam_conf_path`
//! for diagnosis and the Diameter identity still comes from built-in defaults.
//! That is why mmed has no HSS address and its S6a peer stays unconnected; see
//! the filed follow-up. `mme.gtpc` clients wait on S11 (#51).

use serde::Deserialize;

use crate::context::{EpsTai0List, MmeContext, NetworkName, PlmnId, ServedGummei, ServedTai};

// ============================================================================
// YAML shape
// ============================================================================

#[derive(Debug, Default, Deserialize)]
struct PlmnIdYaml {
    mcc: Option<serde_yaml::Value>,
    mnc: Option<serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct GummeiYaml {
    plmn_id: Option<PlmnIdYaml>,
    mme_gid: Option<u16>,
    mme_code: Option<u8>,
}

#[derive(Debug, Default, Deserialize)]
struct TaiYaml {
    plmn_id: Option<PlmnIdYaml>,
    tac: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
struct SecurityYaml {
    integrity_order: Option<Vec<String>>,
    ciphering_order: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct NetworkNameYaml {
    full: Option<String>,
    short: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ServerYaml {
    address: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
struct S1apYaml {
    server: Option<Vec<ServerYaml>>,
}

/// A single `<timer>: { value: <seconds> }` entry under `mme.time`, matching the
/// nesting the 5GC configs use for `amf.time`.
#[derive(Debug, Default, Deserialize)]
struct TimerValueYaml {
    value: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct TimeYaml {
    t3402: Option<TimerValueYaml>,
    t3412: Option<TimerValueYaml>,
    t3423: Option<TimerValueYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct MmeSection {
    #[serde(rename = "freeDiameter")]
    free_diameter: Option<String>,
    s1ap: Option<S1apYaml>,
    gummei: Option<Vec<GummeiYaml>>,
    tai: Option<Vec<TaiYaml>>,
    security: Option<SecurityYaml>,
    network_name: Option<NetworkNameYaml>,
    mme_name: Option<String>,
    time: Option<TimeYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct MmeYaml {
    mme: Option<MmeSection>,
}

// ============================================================================
// Loading
// ============================================================================

/// Apply `path` to `ctx`.
///
/// Returns `false` when nothing was applied — a missing file, unparsable YAML, or
/// no `mme:` section — which is a warning rather than a failure so a mis-typed
/// config cannot take the daemon down. The warning names the file, because the
/// previous silence is what let this go unnoticed.
pub fn load_config(ctx: &mut MmeContext, path: &str) -> bool {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) => {
            log::warn!("Could not read config file '{path}': {e}. Using defaults.");
            return false;
        }
    };

    let yaml: MmeYaml = match serde_yaml::from_str(&content) {
        Ok(yaml) => yaml,
        Err(e) => {
            log::warn!("Failed to parse YAML config '{path}': {e}. Using defaults.");
            return false;
        }
    };

    let Some(mme) = yaml.mme else {
        log::warn!("Config '{path}' has no 'mme' section. Using defaults.");
        return false;
    };

    apply(ctx, mme);
    log::info!("Configuration loaded from {path}");
    true
}

fn apply(ctx: &mut MmeContext, mme: MmeSection) {
    if let Some(name) = mme.mme_name {
        log::info!("MME name: {name}");
        ctx.mme_name = Some(name);
    }

    if let Some(network_name) = mme.network_name {
        if let Some(full) = network_name.full {
            ctx.full_name = NetworkName {
                name: full,
                ..Default::default()
            };
        }
        if let Some(short) = network_name.short {
            ctx.short_name = NetworkName {
                name: short,
                ..Default::default()
            };
        }
    }

    // The Diameter identity, realm, listener and HSS peer live in this file's
    // own format. It is mounted into the container and is what an operator
    // edits, so it is read rather than merely recorded.
    if let Some(free_diameter) = mme.free_diameter {
        apply_fd_conf(ctx, &free_diameter);
        ctx.diam_conf_path = Some(free_diameter);
    }

    // S1AP bind addresses. `S1apServer::bind` takes one address, so the first
    // entry is what gets bound; the rest are recorded and named in a warning
    // rather than dropped silently.
    if let Some(s1ap) = mme.s1ap {
        for server in s1ap.server.unwrap_or_default() {
            let Some(address) = server.address else {
                continue;
            };
            let port = server.port.unwrap_or(ctx.s1ap_port);
            match parse_socket_addr(&address, port) {
                Some(addr) => {
                    log::info!("S1AP server address: {addr}");
                    ctx.s1ap_list.push(addr);
                }
                None => log::warn!("Ignoring unparsable S1AP server address '{address}'"),
            }
        }
        if ctx.s1ap_list.len() > 1 {
            log::warn!(
                "{} S1AP server addresses configured; only the first is bound",
                ctx.s1ap_list.len()
            );
        }
    }

    // Served GUMMEI. Without at least one of these the MME rejects every S1
    // Setup (TS 36.413 §8.7.3.4), which is the headline defect in #157.
    for entry in mme.gummei.unwrap_or_default() {
        let Some(plmn_id) = entry.plmn_id.and_then(resolve_plmn_id) else {
            log::warn!("Ignoring GUMMEI entry with no usable plmn_id");
            continue;
        };
        let mme_gid = entry.mme_gid.unwrap_or(0);
        let mme_code = entry.mme_code.unwrap_or(0);
        log::info!(
            "Configured GUMMEI: PLMN {}, MME group {mme_gid}, MME code {mme_code}",
            plmn_id.to_bcd()
        );
        ctx.served_gummei.push(ServedGummei {
            num_of_plmn_id: 1,
            plmn_id: vec![plmn_id],
            num_of_mme_gid: 1,
            mme_gid: vec![mme_gid],
            num_of_mme_code: 1,
            mme_code: vec![mme_code],
        });
        ctx.num_of_served_gummei += 1;
    }

    // Served TAI, as a TAI0 list (one PLMN, a list of TACs) which is what
    // `find_served_tai` matches against.
    for entry in mme.tai.unwrap_or_default() {
        let Some(plmn_id) = entry.plmn_id.and_then(resolve_plmn_id) else {
            log::warn!("Ignoring TAI entry with no usable plmn_id");
            continue;
        };
        let tac = entry.tac.unwrap_or(0);
        log::info!("Configured TAI: PLMN {}, TAC {tac}", plmn_id.to_bcd());
        ctx.served_tai.push(ServedTai {
            list0: EpsTai0List {
                type_: 0,
                num: 1,
                plmn_id,
                tac: vec![tac],
            },
            ..Default::default()
        });
        ctx.num_of_served_tai += 1;
    }

    // Algorithm order. REPLACES the built-in defaults rather than appending to
    // them: `MmeContext::new` seeds both vectors (issue #44), so pushing would
    // leave the defaults ahead of the configured entries and the configuration
    // would be silently ineffective.
    if let Some(security) = mme.security {
        if let Some(order) = security.integrity_order {
            ctx.integrity_order = order.iter().map(|name| parse_eia(name)).collect();
            log::info!("NAS integrity order: {:?}", ctx.integrity_order);
        }
        if let Some(order) = security.ciphering_order {
            ctx.ciphering_order = order.iter().map(|name| parse_eea(name)).collect();
            log::info!("NAS ciphering order: {:?}", ctx.ciphering_order);
        }
    }

    if let Some(time) = mme.time {
        if let Some(value) = time.t3402.and_then(|t| t.value) {
            ctx.time.t3402 = value;
        }
        if let Some(value) = time.t3412.and_then(|t| t.value) {
            ctx.time.t3412 = value;
        }
        if let Some(value) = time.t3423.and_then(|t| t.value) {
            ctx.time.t3423 = value;
        }
    }
}

/// Read the freeDiameter `.conf` at `path` into the S6a fields of the context.
///
/// The MME is the S6a *client*, so the peer that matters is the one it dials:
/// `ConnectPeer = "hss.localdomain" { ConnectTo = "172.24.0.8"; }` becomes
/// `hss_peer`, which is the address `mme_fd_connect` needs and which mmed
/// previously had no way to learn.
fn apply_fd_conf(ctx: &mut MmeContext, path: &str) {
    let conf = match nextgcore_diameter::fd_conf::FreeDiameterConf::load(path) {
        Ok(conf) => conf,
        Err(e) => {
            log::warn!("Could not read freeDiameter config '{path}': {e}");
            return;
        }
    };

    if !conf.ignored.is_empty() {
        log::info!(
            "{path}: directives not interpreted: {}",
            conf.ignored
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if let Some(identity) = conf.identity.clone() {
        log::info!("Diameter identity: {identity}");
        ctx.diam_identity = Some(identity);
    }
    ctx.diam_realm = conf.realm.clone();
    ctx.diam_addr = conf.listen_address().map(str::to_string);

    // Port is optional in the shipped files; RFC 6733 §2.1 puts unsecured
    // Diameter on 3868.
    let default_port = conf.port.unwrap_or(DIAMETER_PORT);
    match conf.first_connect_peer() {
        Some((identity, address, port)) => {
            let port = port.unwrap_or(default_port);
            match parse_socket_addr(address, port) {
                Some(addr) => {
                    log::info!("S6a peer: {identity} at {addr}");
                    ctx.hss_peer = Some((identity.to_string(), addr));
                }
                None => log::warn!(
                    "{path}: peer '{identity}' has unusable ConnectTo address '{address}'"
                ),
            }
        }
        None => log::warn!(
            "{path}: no ConnectPeer with a ConnectTo address, so no S6a peer can be dialled"
        ),
    }
}

/// Default unsecured Diameter port (RFC 6733 §2.1).
const DIAMETER_PORT: u16 = 3868;

/// Build a `PlmnId` from the YAML `plmn_id` block.
///
/// MCC and MNC are accepted as either numbers or strings, because YAML reads an
/// unquoted `mnc: 70` as an integer while a quoted `mnc: "070"` is a string —
/// and the leading zero matters: MNC 070 is three digits, MNC 70 is two.
fn resolve_plmn_id(plmn: PlmnIdYaml) -> Option<PlmnId> {
    let mcc = scalar_digits(plmn.mcc.as_ref()?)?;
    let mnc = scalar_digits(plmn.mnc.as_ref()?)?;
    Some(PlmnId::new(&mcc, &mnc))
}

/// Render a YAML scalar as its digit string, preserving a quoted form verbatim.
fn scalar_digits(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// `<host>` or `<host>:<port>` to a socket address, defaulting the port.
fn parse_socket_addr(address: &str, port: u16) -> Option<std::net::SocketAddr> {
    if let Ok(addr) = address.parse::<std::net::SocketAddr>() {
        return Some(addr);
    }
    address
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| std::net::SocketAddr::new(ip, port))
}

/// EPS integrity algorithm name to identity (TS 33.401 Annex B).
fn parse_eia(name: &str) -> u8 {
    match name.to_uppercase().as_str() {
        "EIA1" | "128-EIA1" => 1,
        "EIA2" | "128-EIA2" => 2,
        "EIA3" | "128-EIA3" => 3,
        // EIA0 and anything unrecognised map to null integrity, which
        // `nas_security::select_nas_algorithms` refuses to select.
        _ => 0,
    }
}

/// EPS ciphering algorithm name to identity (TS 33.401 Annex B).
fn parse_eea(name: &str) -> u8 {
    match name.to_uppercase().as_str() {
        "EEA1" | "128-EEA1" => 1,
        "EEA2" | "128-EEA2" => 2,
        "EEA3" | "128-EEA3" => 3,
        _ => 0,
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration the Docker EPC actually ships, read from the tree so
    /// config drift breaks this test instead of going unnoticed.
    const SHIPPED_CONFIG: &str = "../../../docker/rust/configs/epc/mme.yaml";

    fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_shipped_config_populates_the_context() {
        let mut ctx = MmeContext::new();
        assert!(
            load_config(&mut ctx, SHIPPED_CONFIG),
            "the shipped config must parse"
        );

        assert_eq!(ctx.mme_name.as_deref(), Some("nextgcore-mme0"));
        assert_eq!(ctx.full_name.name, "NextGCore");
        assert_eq!(ctx.short_name.name, "Next");
        assert_eq!(
            ctx.diam_conf_path.as_deref(),
            Some("/etc/freeDiameter/mme.conf")
        );
        // The .conf lives at an absolute path that only exists inside the
        // container, so the shipped config cannot populate the identity here;
        // `test_freediameter_conf_supplies_the_identity_and_peer` covers that
        // mapping against the file as shipped in the tree.
        assert_eq!(ctx.diam_identity, None);
        assert_eq!(ctx.hss_peer, None);

        // The headline fix: a served GUMMEI, without which S1 Setup always fails.
        assert_eq!(ctx.num_of_served_gummei, 1);
        let gummei = &ctx.served_gummei[0];
        assert_eq!(gummei.plmn_id[0].to_bcd(), "99970");
        assert_eq!(gummei.mme_gid[0], 2);
        assert_eq!(gummei.mme_code[0], 1);

        assert_eq!(ctx.num_of_served_tai, 1);
        assert_eq!(ctx.served_tai[0].list0.plmn_id.to_bcd(), "99970");
        assert_eq!(ctx.served_tai[0].list0.tac, vec![1]);

        // The S1AP bind address comes from the file.
        assert_eq!(
            ctx.s1ap_list,
            vec![std::net::SocketAddr::from(([172, 24, 0, 5], 36412))]
        );

        // [EIA2, EIA1, EIA0] / [EEA0, EEA1, EEA2] as declared.
        assert_eq!(ctx.integrity_order, vec![2, 1, 0]);
        assert_eq!(ctx.ciphering_order, vec![0, 1, 2]);
    }

    #[test]
    fn test_configured_algorithm_order_replaces_the_defaults() {
        let mut ctx = MmeContext::new();
        assert_eq!(
            ctx.integrity_order,
            crate::context::DEFAULT_INTEGRITY_ORDER.to_vec(),
            "the defaults are seeded by MmeContext::new"
        );

        let path = write_temp(
            "nextgcore-mmed-order.yaml",
            "mme:\n  security:\n    integrity_order: [EIA1, EIA2]\n    ciphering_order: [EEA2]\n",
        );
        assert!(load_config(&mut ctx, path.to_str().unwrap()));

        // Appending instead of replacing would leave [2, 1, 0, 1, 2] here, and
        // the default EIA2 would still win the selection.
        assert_eq!(ctx.integrity_order, vec![1, 2]);
        assert_eq!(ctx.ciphering_order, vec![2]);
    }

    #[test]
    fn test_missing_and_malformed_files_leave_defaults() {
        let mut ctx = MmeContext::new();
        assert!(!load_config(&mut ctx, "/nonexistent/nextgcore/mme.yaml"));
        assert!(ctx.served_gummei.is_empty());
        assert_eq!(
            ctx.integrity_order,
            crate::context::DEFAULT_INTEGRITY_ORDER.to_vec()
        );

        let path = write_temp("nextgcore-mmed-bad.yaml", "mme: [this is not a mapping\n");
        assert!(!load_config(&mut ctx, path.to_str().unwrap()));
        assert!(ctx.served_gummei.is_empty());

        // A file that parses but configures nothing is also reported.
        let path = write_temp("nextgcore-mmed-empty.yaml", "logger:\n  level: info\n");
        assert!(!load_config(&mut ctx, path.to_str().unwrap()));
        assert!(ctx.served_gummei.is_empty());
    }

    #[test]
    fn test_partial_config_leaves_the_rest_alone() {
        let mut ctx = MmeContext::new();
        let path = write_temp(
            "nextgcore-mmed-partial.yaml",
            "mme:\n  mme_name: only-a-name\n",
        );
        assert!(load_config(&mut ctx, path.to_str().unwrap()));

        assert_eq!(ctx.mme_name.as_deref(), Some("only-a-name"));
        assert!(ctx.served_gummei.is_empty());
        assert_eq!(ctx.s1ap_port, 36412, "untouched defaults survive");
        assert_eq!(
            ctx.integrity_order,
            crate::context::DEFAULT_INTEGRITY_ORDER.to_vec()
        );
    }

    #[test]
    fn test_plmn_id_accepts_numeric_and_quoted_mnc() {
        // Unquoted YAML numbers lose a leading zero, so an operator writing a
        // three-digit MNC has to quote it; both forms must work.
        let mut numeric = MmeContext::new();
        let path = write_temp(
            "nextgcore-mmed-plmn-num.yaml",
            "mme:\n  gummei:\n    - plmn_id:\n        mcc: 001\n        mnc: 01\n",
        );
        assert!(load_config(&mut numeric, path.to_str().unwrap()));
        assert_eq!(numeric.served_gummei[0].plmn_id[0].to_bcd(), "00101");

        let mut quoted = MmeContext::new();
        let path = write_temp(
            "nextgcore-mmed-plmn-str.yaml",
            "mme:\n  gummei:\n    - plmn_id:\n        mcc: \"001\"\n        mnc: \"010\"\n",
        );
        assert!(load_config(&mut quoted, path.to_str().unwrap()));
        assert_eq!(quoted.served_gummei[0].plmn_id[0].to_bcd(), "001010");
    }

    #[test]
    fn test_unusable_entries_are_skipped_not_fatal() {
        let mut ctx = MmeContext::new();
        let path = write_temp(
            "nextgcore-mmed-partial-entries.yaml",
            "mme:\n  gummei:\n    - mme_gid: 7\n    - plmn_id:\n        mcc: 999\n        mnc: 70\n      \
             mme_gid: 2\n  s1ap:\n    server:\n      - address: not-an-address\n      - address: 10.0.0.1\n",
        );
        assert!(load_config(&mut ctx, path.to_str().unwrap()));

        // The GUMMEI with no PLMN is dropped; the usable one survives.
        assert_eq!(ctx.num_of_served_gummei, 1);
        assert_eq!(ctx.served_gummei[0].mme_gid[0], 2);
        // An unparsable address is skipped, not fatal.
        assert_eq!(
            ctx.s1ap_list,
            vec![std::net::SocketAddr::from(([10, 0, 0, 1], 36412))]
        );
    }

    #[test]
    fn test_freediameter_conf_supplies_the_identity_and_peer() {
        // Point `freeDiameter:` at the file as it ships in the tree, standing in
        // for the container path the compose deployment mounts it to.
        let path = write_temp(
            "nextgcore-mmed-fd.yaml",
            "mme:\n  freeDiameter: ../../../docker/rust/configs/epc/freeDiameter/mme.conf\n",
        );
        let mut ctx = MmeContext::new();
        assert!(load_config(&mut ctx, path.to_str().unwrap()));

        assert_eq!(ctx.diam_identity.as_deref(), Some("mme.localdomain"));
        assert_eq!(ctx.diam_realm.as_deref(), Some("localdomain"));
        assert_eq!(ctx.diam_addr.as_deref(), Some("172.24.0.5"));
        // The HSS address mmed previously had no way to learn, defaulted to the
        // RFC 6733 port because the shipped file leaves `Port` commented out.
        assert_eq!(
            ctx.hss_peer,
            Some((
                "hss.localdomain".to_string(),
                std::net::SocketAddr::from(([172, 24, 0, 8], 3868))
            ))
        );
    }

    #[test]
    fn test_unreadable_freediameter_conf_is_recorded_but_not_fatal() {
        let path = write_temp(
            "nextgcore-mmed-fd-missing.yaml",
            "mme:\n  mme_name: still-configured\n  freeDiameter: /nonexistent/mme.conf\n",
        );
        let mut ctx = MmeContext::new();
        assert!(load_config(&mut ctx, path.to_str().unwrap()));

        // The rest of the file still applies, and the path is recorded so the
        // deployment can be diagnosed.
        assert_eq!(ctx.mme_name.as_deref(), Some("still-configured"));
        assert_eq!(ctx.diam_conf_path.as_deref(), Some("/nonexistent/mme.conf"));
        assert_eq!(ctx.diam_identity, None);
        assert_eq!(ctx.hss_peer, None);
    }

    #[test]
    fn test_peer_without_connect_to_yields_no_s6a_peer() {
        let conf = write_temp(
            "nextgcore-mmed-noconnect.conf",
            "Identity = \"mme.localdomain\";\nConnectPeer = \"hss.localdomain\";\n",
        );
        let path = write_temp(
            "nextgcore-mmed-noconnect.yaml",
            &format!("mme:\n  freeDiameter: {}\n", conf.to_str().unwrap()),
        );
        let mut ctx = MmeContext::new();
        assert!(load_config(&mut ctx, path.to_str().unwrap()));

        assert_eq!(ctx.diam_identity.as_deref(), Some("mme.localdomain"));
        assert_eq!(
            ctx.hss_peer, None,
            "a peer with no address is not something to dial"
        );
    }

    #[test]
    fn test_algorithm_name_parsing() {
        assert_eq!(parse_eia("EIA2"), 2);
        assert_eq!(parse_eia("128-EIA1"), 1);
        assert_eq!(parse_eia("eia3"), 3);
        assert_eq!(parse_eia("EIA0"), 0);
        assert_eq!(parse_eia("nonsense"), 0);
        assert_eq!(parse_eea("EEA2"), 2);
        assert_eq!(parse_eea("128-EEA3"), 3);
        assert_eq!(parse_eea("EEA0"), 0);
    }

    #[test]
    fn test_socket_addr_parsing() {
        assert_eq!(
            parse_socket_addr("10.0.0.1", 36412),
            Some(std::net::SocketAddr::from(([10, 0, 0, 1], 36412)))
        );
        assert_eq!(
            parse_socket_addr("10.0.0.1:1234", 36412),
            Some(std::net::SocketAddr::from(([10, 0, 0, 1], 1234))),
            "an explicit port in the address wins"
        );
        assert!(parse_socket_addr("example.invalid", 36412).is_none());
    }
}
