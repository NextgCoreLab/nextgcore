//! freeDiameter `.conf` parsing.
//!
//! ## Why this module exists
//!
//! The shipped EPC deployment mounts `configs/epc/freeDiameter` into the mmed,
//! hssd and pcrfd containers, and each daemon's YAML names its file
//! (`mme.freeDiameter: /etc/freeDiameter/mme.conf`). Those files hold the real
//! Diameter identity, realm, listen address and peer for the deployment — and
//! **nothing read them**. Each daemon fell back to a built-in default identity
//! (`hss.epc.mnc001.mcc001.3gppnetwork.org` and friends), and mmed had no HSS
//! address at all, which is why its S6a peer could never be connected.
//!
//! There is also no freeDiameter binary anywhere in the tree — no package
//! install, no `.fdx` extension, nothing that could consume these files instead.
//! So the files are not a foreign library's configuration that happens to sit
//! nearby: they are this deployment's Diameter configuration, and reading them is
//! what makes them true.
//!
//! ## Scope
//!
//! Only the directives the shipped files actually use, plus the handful that
//! naturally accompany them:
//!
//! ```text
//! Identity = "mme.localdomain";
//! Realm = "localdomain";
//! Port = 3868;            SecPort = 5868;
//! ListenOn = "172.24.0.5";
//! No_IPv6;  No_IP;  No_TCP;  No_SCTP;  Prefer_TCP;  NoRelay;
//! ConnectPeer = "hss.localdomain" { ConnectTo = "172.24.0.8"; No_TLS; };
//! ```
//!
//! Anything else — `LoadExtension`, `TLS_Cred`, `AppServThreads`, … — is collected
//! into [`FreeDiameterConf::ignored`] so a caller can log what it skipped rather
//! than dropping it silently. This is deliberately not a complete freeDiameter
//! grammar: an unknown directive is reported, never guessed at.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

/// A peer declared by `ConnectPeer`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FreeDiameterPeer {
    /// The peer's Diameter identity (the quoted name after `ConnectPeer =`)
    pub identity: String,
    /// `ConnectTo` address, when given
    pub connect_to: Option<String>,
    /// A `Port` inside the peer's block
    pub port: Option<u16>,
    /// `No_TLS` inside the peer's block
    pub no_tls: bool,
}

/// The subset of a freeDiameter configuration this crate understands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FreeDiameterConf {
    /// `Identity` — the local Diameter identity (an FQDN)
    pub identity: Option<String>,
    /// `Realm` — the local Diameter realm
    pub realm: Option<String>,
    /// `ListenOn` addresses, in declaration order
    pub listen_on: Vec<String>,
    /// `Port` — the local TCP/SCTP port
    pub port: Option<u16>,
    /// `SecPort` — the local TLS port
    pub sec_port: Option<u16>,
    /// `No_IP` / `No_IPv6` / `No_TCP` / `No_SCTP` / `Prefer_TCP` / `NoRelay`
    pub flags: FreeDiameterFlags,
    /// `ConnectPeer` entries, in declaration order
    pub peers: Vec<FreeDiameterPeer>,
    /// Directives this parser does not interpret, deduplicated by keyword
    pub ignored: BTreeSet<String>,
    /// Recognised directives whose value does not parse (`Port = "abc"`,
    /// `Port = 70000`, `ListenOn = ""`), each as `Keyword = value` in
    /// declaration order (#1536 review). They set nothing, so an earlier valid
    /// value of the same directive stands; a caller logs them rather than
    /// letting a typo fall back to a default silently.
    pub malformed: Vec<String>,
}

/// The valueless directives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FreeDiameterFlags {
    /// `No_IP`
    pub no_ip: bool,
    /// `No_IPv6`
    pub no_ipv6: bool,
    /// `No_TCP`
    pub no_tcp: bool,
    /// `No_SCTP`
    pub no_sctp: bool,
    /// `Prefer_TCP`
    pub prefer_tcp: bool,
    /// `NoRelay` — the peer does not relay, i.e. do not advertise the relay
    /// application (0xffffff)
    pub no_relay: bool,
}

impl FreeDiameterConf {
    /// Read and parse `path`.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse(&text))
    }

    /// Parse configuration text. Never fails: unrecognised or malformed
    /// directives are recorded in [`Self::ignored`] rather than rejected, so a
    /// caller keeps whatever the file did state clearly.
    pub fn parse(text: &str) -> Self {
        let mut conf = Self::default();
        for statement in statements(text) {
            conf.apply(&statement);
        }
        conf
    }

    /// The first `ListenOn` address, which is the one a single-socket server
    /// binds.
    pub fn listen_address(&self) -> Option<&str> {
        self.listen_on.first().map(String::as_str)
    }

    /// The first peer that names a `ConnectTo` address, as
    /// `(identity, address, port)`.
    ///
    /// The shipped files declare exactly one peer each, which is the HSS for
    /// mmed and the MME for hssd.
    pub fn first_connect_peer(&self) -> Option<(&str, &str, Option<u16>)> {
        self.peers.iter().find_map(|peer| {
            peer.connect_to
                .as_deref()
                .map(|addr| (peer.identity.as_str(), addr, peer.port))
        })
    }

    fn apply(&mut self, statement: &str) {
        let (keyword, value) = split_statement(statement);

        let malformed = |this: &mut Self| {
            this.malformed
                .push(format!("{keyword} = {}", value.unwrap_or_default()));
        };
        match keyword.to_ascii_lowercase().as_str() {
            "identity" => match value.and_then(unquote) {
                Some(v) => self.identity = Some(v),
                None => malformed(self),
            },
            "realm" => match value.and_then(unquote) {
                Some(v) => self.realm = Some(v),
                None => malformed(self),
            },
            "listenon" => match value.and_then(unquote) {
                Some(address) => self.listen_on.push(address),
                None => malformed(self),
            },
            "port" => match value.and_then(parse_port) {
                Some(p) => self.port = Some(p),
                None => malformed(self),
            },
            "secport" => match value.and_then(parse_port) {
                Some(p) => self.sec_port = Some(p),
                None => malformed(self),
            },
            "no_ip" => self.flags.no_ip = true,
            "no_ipv6" => self.flags.no_ipv6 = true,
            "no_tcp" => self.flags.no_tcp = true,
            "no_sctp" => self.flags.no_sctp = true,
            "prefer_tcp" => self.flags.prefer_tcp = true,
            "norelay" => self.flags.no_relay = true,
            // parse_connect_peer records its own malformed parts, the identity
            // included, so only a ConnectPeer with no value at all is noted here.
            "connectpeer" => match value {
                Some(v) => {
                    if let Some(peer) = parse_connect_peer(v, &mut self.malformed) {
                        self.peers.push(peer);
                    }
                }
                None => malformed(self),
            },
            other if !other.is_empty() => {
                self.ignored.insert(keyword.to_string());
            }
            _ => {}
        }
    }
}

/// Split configuration text into `;`-terminated statements, keeping a
/// `ConnectPeer` block with its directive.
///
/// Comments run from `#` to end of line. The shipped files put no `#` inside a
/// quoted value, and freeDiameter itself treats `#` as a comment anywhere, so
/// stripping before tokenising matches the reference behaviour.
fn statements(text: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;

    for line in text.lines() {
        let line = match line.find('#') {
            Some(idx) => &line[..idx],
            None => line,
        };

        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    current.push(ch);
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                    current.push(ch);
                }
                // A `;` inside a ConnectPeer block separates that block's own
                // directives, so only a top-level one ends a statement.
                ';' if depth == 0 => {
                    push_statement(&mut statements, &mut current);
                }
                _ => current.push(ch),
            }
        }
        // Statements may span lines, so only a newline's worth of whitespace is
        // added rather than terminating here.
        current.push(' ');
    }
    push_statement(&mut statements, &mut current);
    statements
}

fn push_statement(statements: &mut Vec<String>, current: &mut String) {
    let statement = current.trim().to_string();
    current.clear();
    if !statement.is_empty() {
        statements.push(statement);
    }
}

/// Split `Key = value` (or a bare `Key`) into its keyword and optional value.
fn split_statement(statement: &str) -> (&str, Option<&str>) {
    match statement.find('=') {
        Some(idx) => (
            statement[..idx].trim(),
            Some(statement[idx + 1..].trim()).filter(|value| !value.is_empty()),
        ),
        None => (statement.trim(), None),
    }
}

fn unquote(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(trimmed);
    (!unquoted.is_empty()).then(|| unquoted.to_string())
}

/// A port 1-65535. Port 0 is not one a peer can connect to (#1536 review), so it
/// does not parse either.
fn parse_port(value: &str) -> Option<u16> {
    unquote(value)?.parse().ok().filter(|p| *p != 0)
}

/// Parse `"peer.identity" { ConnectTo = "addr"; No_TLS; }`.
///
/// An identity, `ConnectTo` or `Port` that does not parse is noted in `malformed`
/// (#1536 review). A peer with a bad identity is not returned, but its block is
/// still read, so its other bad entries are noted too.
fn parse_connect_peer(value: &str, malformed: &mut Vec<String>) -> Option<FreeDiameterPeer> {
    let (identity_part, block) = match value.find('{') {
        Some(idx) => (&value[..idx], value[idx + 1..].trim_end_matches(['}', ' '])),
        None => (value, ""),
    };

    let identity = unquote(identity_part);
    if identity.is_none() {
        malformed.push(format!("ConnectPeer = {}", identity_part.trim()));
    }
    // The peer as written: `"name"` when the identity parsed, else the raw text.
    let label = match &identity {
        Some(id) => format!("\"{id}\""),
        None => identity_part.trim().to_string(),
    };
    let mut peer = FreeDiameterPeer {
        identity: identity.clone().unwrap_or_default(),
        ..Default::default()
    };

    for inner in block.split(';') {
        let (keyword, inner_value) = split_statement(inner);
        let mut bad = || {
            malformed.push(format!(
                "ConnectPeer {label} {keyword} = {}",
                inner_value.unwrap_or_default()
            ))
        };
        match keyword.to_ascii_lowercase().as_str() {
            "connectto" => match inner_value.and_then(unquote) {
                Some(addr) => peer.connect_to = Some(addr),
                None => bad(),
            },
            "port" => match inner_value.and_then(parse_port) {
                Some(p) => peer.port = Some(p),
                None => bad(),
            },
            "no_tls" => peer.no_tls = true,
            _ => {}
        }
    }

    identity.map(|_| peer)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// #1536 review: a recognised directive whose value does not parse is
    /// recorded in `malformed`, sets nothing, and leaves an earlier valid value
    /// in place; the valid directives around it still apply.
    #[test]
    fn a_recognised_directive_with_a_bad_value_is_recorded_as_malformed() {
        let conf = FreeDiameterConf::parse(
            r#"
Identity = "pcrf.localdomain";
Port = 3868;
Port = "abc";
SecPort = 70000;
ListenOn = "";
Realm = "localdomain";
ConnectPeer = "smf.localdomain" { ConnectTo = "172.24.0.4"; Port = x; };
ConnectPeer = "hss.localdomain" { ConnectTo = ""; Port = 0; };
ConnectPeer = "" { ConnectTo = ""; };
Port = 0;
"#,
        );
        assert_eq!(
            conf.malformed,
            vec![
                "Port = \"abc\"".to_string(),
                "SecPort = 70000".to_string(),
                "ListenOn = \"\"".to_string(),
                "ConnectPeer \"smf.localdomain\" Port = x".to_string(),
                "ConnectPeer \"hss.localdomain\" ConnectTo = \"\"".to_string(),
                "ConnectPeer \"hss.localdomain\" Port = 0".to_string(),
                "ConnectPeer = \"\"".to_string(),
                "ConnectPeer \"\" ConnectTo = \"\"".to_string(),
                "Port = 0".to_string(),
            ]
        );
        assert_eq!(conf.port, Some(3868), "the earlier valid Port stands");
        assert_eq!(conf.sec_port, None);
        assert!(conf.listen_on.is_empty());
        assert_eq!(conf.identity.as_deref(), Some("pcrf.localdomain"));
        assert_eq!(conf.realm.as_deref(), Some("localdomain"));
        assert_eq!(conf.peers.len(), 2, "the peer with no identity is not kept");
        assert_eq!(conf.peers[0].port, None);
        assert_eq!(conf.peers[1].identity, "hss.localdomain");
        assert_eq!(
            conf.peers[1].connect_to, None,
            "a bad ConnectTo sets nothing"
        );
        assert_eq!(
            conf.port,
            Some(3868),
            "Port = 0 does not replace a valid Port"
        );
        assert!(conf.ignored.is_empty());
    }

    /// The MME file the Docker EPC ships, verbatim.
    const SHIPPED_MME_CONF: &str = r#"
# freeDiameter configuration for MME
Identity = "mme.localdomain";
Realm = "localdomain";

# LoadExtension = "/usr/lib/freeDiameter/dbg_msg_dumps.fdx" : "0x8888";
No_IPv6;
ListenOn = "172.24.0.5";
NoRelay;

ConnectPeer = "hss.localdomain" { ConnectTo = "172.24.0.8"; No_TLS; };
"#;

    #[test]
    fn test_parses_the_shipped_mme_conf() {
        let conf = FreeDiameterConf::parse(SHIPPED_MME_CONF);

        assert_eq!(conf.identity.as_deref(), Some("mme.localdomain"));
        assert_eq!(conf.realm.as_deref(), Some("localdomain"));
        assert_eq!(conf.listen_address(), Some("172.24.0.5"));
        assert!(conf.flags.no_ipv6);
        assert!(conf.flags.no_relay);
        assert_eq!(
            conf.port, None,
            "the shipped file leaves Port commented out"
        );

        assert_eq!(
            conf.first_connect_peer(),
            Some(("hss.localdomain", "172.24.0.8", None))
        );
        assert!(conf.peers[0].no_tls);

        // The commented LoadExtension must not be reported as an unknown
        // directive, because it is a comment.
        assert!(
            conf.ignored.is_empty(),
            "nothing outside comments is unrecognised here: {:?}",
            conf.ignored
        );
    }

    #[test]
    fn test_unknown_directives_are_reported_not_guessed() {
        let conf = FreeDiameterConf::parse(
            r#"
            Identity = "mme.localdomain";
            LoadExtension = "/usr/lib/freeDiameter/dict_dcca_3gpp.fdx";
            TLS_Cred = "/cert.pem", "/key.pem";
            AppServThreads = 4;
            "#,
        );

        assert_eq!(conf.identity.as_deref(), Some("mme.localdomain"));
        assert_eq!(
            conf.ignored.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["AppServThreads", "LoadExtension", "TLS_Cred"],
            "a caller can log exactly what was skipped"
        );
    }

    #[test]
    fn test_ports_flags_and_multiple_listen_addresses() {
        let conf = FreeDiameterConf::parse(
            r#"
            Port = 3868;
            SecPort = 5868;
            No_IP;
            No_SCTP;
            Prefer_TCP;
            ListenOn = "10.0.0.1";
            ListenOn = "10.0.0.2";
            "#,
        );

        assert_eq!(conf.port, Some(3868));
        assert_eq!(conf.sec_port, Some(5868));
        assert!(conf.flags.no_ip);
        assert!(conf.flags.no_sctp);
        assert!(conf.flags.prefer_tcp);
        assert!(!conf.flags.no_tcp);
        assert_eq!(conf.listen_on, vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(conf.listen_address(), Some("10.0.0.1"));
    }

    #[test]
    fn test_connect_peer_variants() {
        let conf = FreeDiameterConf::parse(
            r#"
            ConnectPeer = "no-address.localdomain";
            ConnectPeer = "with-port.localdomain" { ConnectTo = "10.0.0.9"; Port = 3869; };
            ConnectPeer = "hss.localdomain" { ConnectTo = "10.0.0.8"; No_TLS; };
            "#,
        );

        assert_eq!(conf.peers.len(), 3);
        assert_eq!(conf.peers[0].connect_to, None);
        assert_eq!(conf.peers[1].port, Some(3869));
        // A peer with no ConnectTo is not a connection target, so the first
        // usable one is chosen rather than the first declared.
        assert_eq!(
            conf.first_connect_peer(),
            Some(("with-port.localdomain", "10.0.0.9", Some(3869)))
        );
    }

    #[test]
    fn test_multi_line_connect_peer_block() {
        // freeDiameter allows the block to span lines, and the shipped files may
        // be reformatted at any time.
        let conf = FreeDiameterConf::parse(
            r#"
            ConnectPeer = "hss.localdomain" {
                ConnectTo = "172.24.0.8";
                No_TLS;
            };
            "#,
        );

        assert_eq!(
            conf.first_connect_peer(),
            Some(("hss.localdomain", "172.24.0.8", None))
        );
        assert!(conf.peers[0].no_tls);
    }

    #[test]
    fn test_comments_and_empty_input() {
        let conf = FreeDiameterConf::parse(
            "# Identity = \"commented.out\";\n\n   \n# ConnectPeer = \"nope\" { };\n",
        );
        assert_eq!(conf, FreeDiameterConf::default());

        assert_eq!(FreeDiameterConf::parse(""), FreeDiameterConf::default());
    }

    #[test]
    fn test_trailing_statement_without_semicolon() {
        // A file whose last line lost its `;` still yields what it stated.
        let conf = FreeDiameterConf::parse("Identity = \"mme.localdomain\"");
        assert_eq!(conf.identity.as_deref(), Some("mme.localdomain"));
    }

    #[test]
    fn test_case_insensitive_keywords_and_unquoted_values() {
        let conf = FreeDiameterConf::parse("identity = mme.localdomain;\nNORELAY;\nport = 3869;\n");
        assert_eq!(conf.identity.as_deref(), Some("mme.localdomain"));
        assert!(conf.flags.no_relay);
        assert_eq!(conf.port, Some(3869));
    }

    #[test]
    fn test_load_reports_a_missing_file() {
        assert!(FreeDiameterConf::load("/nonexistent/freeDiameter/mme.conf").is_err());
    }
}
