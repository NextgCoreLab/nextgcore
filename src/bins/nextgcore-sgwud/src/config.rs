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
struct SgwuSection {
    pfcp: Option<ServerList>,
    gtpu: Option<ServerList>,
}

#[derive(Debug, Default, Deserialize)]
struct SgwuYaml {
    sgwu: Option<SgwuSection>,
}

/// What the file resolved to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SgwuConfig {
    /// `sgwu.pfcp.server[0].address`: the PFCP Node ID this SGW-U advertises.
    pub pfcp_ip: Option<Ipv4Addr>,
    /// `sgwu.gtpu.server[0].address`: the S1-U/S5-U address put in F-TEIDs.
    pub gtpu_ip: Option<Ipv4Addr>,
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
    Ok(SgwuConfig {
        pfcp_ip: first_ipv4(section.pfcp, "pfcp"),
        gtpu_ip: first_ipv4(section.gtpu, "gtpu"),
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
