//! The SGW-U's configuration file (#482).
//!
//! Before this nothing read it: `docker-compose-epc.yml` starts the daemon with
//! `-c /etc/nextgcore/sgwu.yaml`, and `main` never looked at its arguments, so
//! `sgwu.pfcp.server` and `sgwu.gtpu.server` had no effect. The PFCP Node ID then
//! defaulted to loopback — the association identifier a remote SGW-C is required to
//! store (TS 29.244 §6.2.6.2.2) — and the GTP-U address came only from the
//! environment.
//!
//! Precedence everywhere is the environment variable first (the test escape hatch and
//! the multi-homed-host override), then this file, then the built-in default.

use serde::Deserialize;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

#[derive(Debug, Default, Deserialize)]
struct AddrEntry {
    address: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ServerList {
    server: Option<Vec<AddrEntry>>,
}

#[derive(Debug, Default, Deserialize)]
struct PfcpSection {
    server: Option<Vec<AddrEntry>>,
    /// The SGW-C addresses (IPs, CIDR prefixes or host names) allowed to associate.
    allowed_peers: Option<Vec<String>>,
    /// The most sessions one SGW-C may hold (#968).
    max_sessions_per_peer: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct SgwuSection {
    pfcp: Option<PfcpSection>,
    gtpu: Option<ServerList>,
}

#[derive(Debug, Default, Deserialize)]
struct LoggerSection {
    level: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SgwuYaml {
    logger: Option<LoggerSection>,
    sgwu: Option<SgwuSection>,
}

/// What the file resolved to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SgwuConfig {
    /// `sgwu.pfcp.server[0].address`: the PFCP Node ID this SGW-U advertises.
    pub pfcp_ip: Option<Ipv4Addr>,
    /// `sgwu.gtpu.server[0].address`: the S1-U/S5-U address put in F-TEIDs.
    pub gtpu_ip: Option<Ipv4Addr>,
    /// `logger.level`: the default log filter when `RUST_LOG` is unset (#500).
    pub log_level: Option<String>,
    /// `sgwu.pfcp.allowed_peers`: the SGW-C addresses (IPs, CIDR prefixes or host
    /// names) an Association Setup is accepted from (security, #968), as written. Parsed by
    /// `pfcp_open`, which refuses to start on a bad entry.
    pub pfcp_allowed_peers: Vec<String>,
    /// `sgwu.pfcp.max_sessions_per_peer`: the per-SGW-C session cap (#968).
    pub pfcp_max_sessions_per_peer: Option<usize>,
}

static CONFIG: OnceLock<SgwuConfig> = OnceLock::new();

/// The configuration loaded at startup, or the default if none was.
pub fn config() -> SgwuConfig {
    CONFIG.get().cloned().unwrap_or_default()
}

/// Publish the configuration for `pfcp_open` / `gtp_open`. First call wins.
pub fn install(config: SgwuConfig) {
    let _ = CONFIG.set(config);
}

/// The value of `-c <path>` / `--config <path>` / `--config=<path>`, if given.
pub fn config_path_from_args<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "-c" || arg == "--config" {
            return args.next();
        }
        if let Some(path) = arg.strip_prefix("--config=") {
            return Some(path.to_string());
        }
    }
    None
}

/// The value of `-l <level>` / `--log-level <level>` / `--log-level=<level>`.
pub fn log_level_from_args<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "-l" || arg == "--log-level" {
            return args.next();
        }
        if let Some(level) = arg.strip_prefix("--log-level=") {
            return Some(level.to_string());
        }
    }
    None
}

/// The default log filter (#500): `--log-level`, then the file's `logger.level`,
/// then `info` -- the level every other NF starts at. `RUST_LOG`, when set, still
/// overrides it (`env_logger`'s `default_filter_or`). Read silently, because it
/// runs before the logger exists; [`load`] reports any problem with the file.
///
/// The shared resolution every NF uses (#691 follow-up).
pub fn default_log_level(cli: Option<String>, path: Option<&str>) -> String {
    nextgcore_core::log::nf_log_level(cli.as_deref(), path)
}

/// Parse `path`. A missing or unparsable file yields the default and a warning
/// that names it.
pub fn load(path: &str) -> SgwuConfig {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Could not read config file '{path}': {e}. Using defaults.");
            return SgwuConfig::default();
        }
    };
    match parse(&content) {
        Ok(config) => {
            log::info!("Configuration loaded from {path}");
            config
        }
        Err(e) => {
            log::warn!("Failed to parse YAML config '{path}': {e}. Using defaults.");
            SgwuConfig::default()
        }
    }
}

fn parse(content: &str) -> Result<SgwuConfig, serde_yaml::Error> {
    let yaml: SgwuYaml = serde_yaml::from_str(content)?;
    let first_ipv4 = |list: Option<ServerList>, key: &str| -> Option<Ipv4Addr> {
        let address = list?.server?.into_iter().next()?.address?;
        match address.parse::<Ipv4Addr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                log::warn!("sgwu.{key}.server address '{address}' is not an IPv4 address; ignored");
                None
            }
        }
    };
    let section = yaml.sgwu.unwrap_or_default();
    let pfcp = section.pfcp.unwrap_or_default();
    Ok(SgwuConfig {
        pfcp_ip: first_ipv4(
            Some(ServerList {
                server: pfcp.server,
            }),
            "pfcp",
        ),
        gtpu_ip: first_ipv4(section.gtpu, "gtpu"),
        log_level: yaml.logger.and_then(|l| l.level),
        pfcp_allowed_peers: pfcp.allowed_peers.unwrap_or_default(),
        pfcp_max_sessions_per_peer: pfcp.max_sessions_per_peer,
    })
}

/// `env` first, then the file's value, then `default`.
pub fn resolve_ipv4(
    env: Option<String>,
    file: Option<Ipv4Addr>,
    default: Ipv4Addr,
) -> Result<Ipv4Addr, String> {
    match env {
        Some(v) => v
            .parse()
            .map_err(|e| format!("'{v}' is not an IPv4 address: {e}")),
        None => Ok(file.unwrap_or(default)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped docker/rust/configs/epc/sgwu.yaml shape.
    #[test]
    fn the_shipped_shape_is_read() {
        let config = parse(
            "logger:\n  level: info\nsgwu:\n  pfcp:\n    server:\n      - address: 172.24.0.6\n  \
             gtpu:\n    server:\n      - address: 172.24.0.6\n",
        )
        .unwrap();
        assert_eq!(config.pfcp_ip, Some(Ipv4Addr::new(172, 24, 0, 6)));
        assert_eq!(config.gtpu_ip, Some(Ipv4Addr::new(172, 24, 0, 6)));
        assert_eq!(config.log_level.as_deref(), Some("info"));
        assert!(config.pfcp_allowed_peers.is_empty());
    }

    /// #968: `sgwu.pfcp.allowed_peers` is read as written.
    #[test]
    fn the_pfcp_allowed_peers_are_read() {
        let config = parse(
            "sgwu:\n  pfcp:\n    server:\n      - address: 172.24.0.6\n    allowed_peers:\n      \
             - 172.24.0.5\n      - 10.0.0.0/8\n    max_sessions_per_peer: 300\n",
        )
        .unwrap();
        assert_eq!(config.pfcp_ip, Some(Ipv4Addr::new(172, 24, 0, 6)));
        assert_eq!(config.pfcp_allowed_peers, vec!["172.24.0.5", "10.0.0.0/8"]);
        assert_eq!(config.pfcp_max_sessions_per_peer, Some(300));
    }

    /// #500: with no RUST_LOG, sgwud starts at `--log-level`, else the file's
    /// `logger.level`, else info -- never env_logger's error-only default.
    #[test]
    fn the_default_log_level_is_cli_then_file_then_info() {
        let dir = std::env::temp_dir().join(format!("sgwud-500-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let debug = dir.join("debug.yaml");
        std::fs::write(&debug, "logger:\n  level: debug\n").unwrap();
        let bare = dir.join("bare.yaml");
        std::fs::write(&bare, "sgwu: {}\n").unwrap();
        let debug = debug.to_str().unwrap();

        assert_eq!(default_log_level(None, None), "info");
        assert_eq!(
            default_log_level(None, Some(bare.to_str().unwrap())),
            "info"
        );
        assert_eq!(
            default_log_level(None, Some("/nonexistent/sgwu.yaml")),
            "info"
        );
        assert_eq!(default_log_level(None, Some(debug)), "debug");
        assert_eq!(
            default_log_level(Some("trace".into()), Some(debug)),
            "trace"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_level_is_taken_from_the_arguments() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            log_level_from_args(args(&["sgwud", "-l", "warn"])).as_deref(),
            Some("warn")
        );
        assert_eq!(
            log_level_from_args(args(&["sgwud", "-c", "x", "--log-level=debug"])).as_deref(),
            Some("debug")
        );
        assert_eq!(log_level_from_args(args(&["sgwud", "-c", "x"])), None);
    }

    #[test]
    fn missing_sections_and_bad_addresses_are_none() {
        assert_eq!(parse("logger: {}\n").unwrap(), SgwuConfig::default());
        let config = parse("sgwu:\n  pfcp:\n    server:\n      - address: sgwu.local\n").unwrap();
        assert_eq!(config.pfcp_ip, None);
    }

    #[test]
    fn config_path_is_taken_from_the_arguments() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            config_path_from_args(args(&["sgwud", "-c", "/etc/nextgcore/sgwu.yaml"])).as_deref(),
            Some("/etc/nextgcore/sgwu.yaml")
        );
        assert_eq!(
            config_path_from_args(args(&["sgwud", "--config=/x.yaml"])).as_deref(),
            Some("/x.yaml")
        );
        assert_eq!(config_path_from_args(args(&["sgwud"])), None);
    }

    #[test]
    fn environment_beats_file_beats_default() {
        let file_ip = Ipv4Addr::new(172, 24, 0, 6);
        let file = Some(file_ip);
        assert_eq!(
            resolve_ipv4(Some("10.0.0.9".into()), file, Ipv4Addr::LOCALHOST).unwrap(),
            Ipv4Addr::new(10, 0, 0, 9)
        );
        assert_eq!(
            resolve_ipv4(None, file, Ipv4Addr::LOCALHOST).unwrap(),
            file_ip
        );
        assert_eq!(
            resolve_ipv4(None, None, Ipv4Addr::LOCALHOST).unwrap(),
            Ipv4Addr::LOCALHOST
        );
        assert!(resolve_ipv4(Some("bogus".into()), file, Ipv4Addr::LOCALHOST).is_err());
    }
}
