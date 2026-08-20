//! SCP YAML configuration parsing (scpd-#102, TS 29.500 §6.10.1).
//!
//! Before this module the SCP read `scp.yaml` only to log its byte count, so
//! every setting in the file was silently discarded. Here the file is
//! deserialised into [`ScpYaml`] and its values feed the runtime config with
//! CLI > env > file > built-in-default precedence (see [`resolve`]).
//!
//! The schema deliberately covers only keys the SCP can act on:
//! - `scp.sbi.server[0].address` / `.port` — the SBI listen/advertised endpoint
//! - `scp.sbi.client.nrf[0].uri` — the NRF for Model D delegated discovery
//! - `scp.sbi.tls.enabled` / `.cert` / `.key` — SBI TLS
//! - `scp.fqdn` — the SCP identity used for `Via` / loop detection
//! - `scp.nf_instance_id` — the SCP's `nfInstanceId` for delegated OAuth2
//! - `scp.connect_timeout` / `scp.request_timeout` — upstream timeouts (seconds)
//! - `scp.max_cache_entries` / `scp.cache_ttl` — proxy cache bounds
//!
//! Declaring only actionable keys is deliberate: parsing a key nothing reads
//! is the very defect (#58, #102) being fixed.

use serde::Deserialize;

/// A single `scp.sbi.client.nrf[]` entry.
#[derive(Debug, Default, Deserialize)]
pub struct NrfClientYaml {
    pub uri: String,
}

/// The `scp.sbi.client` block.
#[derive(Debug, Default, Deserialize)]
pub struct SbiClientYaml {
    pub nrf: Option<Vec<NrfClientYaml>>,
}

/// A single `scp.sbi.server[]` entry (the SCP binds/advertises the first).
#[derive(Debug, Default, Deserialize)]
pub struct SbiServerYaml {
    pub address: Option<String>,
    pub port: Option<u16>,
}

/// The `scp.sbi.tls` block (G36: SBI TLS).
#[derive(Debug, Default, Deserialize)]
pub struct SbiTlsYaml {
    pub enabled: Option<bool>,
    pub cert: Option<String>,
    pub key: Option<String>,
}

/// The `scp.sbi` block.
#[derive(Debug, Default, Deserialize)]
pub struct SbiYaml {
    pub server: Option<Vec<SbiServerYaml>>,
    pub client: Option<SbiClientYaml>,
    pub tls: Option<SbiTlsYaml>,
}

/// The `scp` block. New optional keys (`fqdn`, `nf_instance_id`, the timeouts,
/// the cache bounds) are absent from the shipped config and documented there
/// commented-out; leaving them unset preserves today's built-in defaults.
#[derive(Debug, Default, Deserialize)]
pub struct ScpSection {
    pub sbi: Option<SbiYaml>,
    /// SCP identity/FQDN for `Via` / `Server` / `SCP-<fqdn>` loop detection.
    pub fqdn: Option<String>,
    /// The SCP's own `nfInstanceId` for delegated OAuth2 token requests.
    pub nf_instance_id: Option<String>,
    /// Upstream connect timeout, in whole seconds.
    pub connect_timeout: Option<u64>,
    /// Upstream request timeout, in whole seconds.
    pub request_timeout: Option<u64>,
    /// Hard ceiling on entries in each proxy cache.
    pub max_cache_entries: Option<usize>,
    /// Cache entry lifetime, in whole seconds.
    pub cache_ttl: Option<u64>,
}

/// The top-level document: `scp: { ... }`.
#[derive(Debug, Default, Deserialize)]
pub struct ScpYaml {
    pub scp: Option<ScpSection>,
}

impl ScpYaml {
    /// Borrow the `scp` section, or a shared empty one when the key is absent,
    /// so callers can read fields without repeated `Option` matching.
    pub fn section(&self) -> &ScpSection {
        static EMPTY: ScpSection = ScpSection {
            sbi: None,
            fqdn: None,
            nf_instance_id: None,
            connect_timeout: None,
            request_timeout: None,
            max_cache_entries: None,
            cache_ttl: None,
        };
        self.scp.as_ref().unwrap_or(&EMPTY)
    }

    /// The first configured SBI server address, if any.
    pub fn sbi_address(&self) -> Option<String> {
        self.section()
            .sbi
            .as_ref()?
            .server
            .as_ref()?
            .first()?
            .address
            .clone()
    }

    /// The first configured SBI server port, if any.
    pub fn sbi_port(&self) -> Option<u16> {
        self.section().sbi.as_ref()?.server.as_ref()?.first()?.port
    }

    /// The first configured NRF URI, if any.
    pub fn nrf_uri(&self) -> Option<String> {
        Some(
            self.section()
                .sbi
                .as_ref()?
                .client
                .as_ref()?
                .nrf
                .as_ref()?
                .first()?
                .uri
                .clone(),
        )
    }
}

/// Parse the SCP YAML document.
pub fn parse(content: &str) -> Result<ScpYaml, serde_yaml::Error> {
    serde_yaml::from_str(content)
}

/// Resolve one setting by precedence: CLI flag > env var > config file >
/// built-in default. Each source is an `Option`; the first `Some` wins.
///
/// This is the crux of #102's precedence requirement. Any CLI flag that
/// carries this value MUST be an `Option` (no clap `default_value`) — a
/// `default_value` makes the flag always look explicitly set, so `cli` would
/// never be `None` and the file could never take effect (the precedence-
/// inversion trap; see LEARNINGS).
pub fn resolve<T>(cli: Option<T>, env: Option<T>, file: Option<T>, default: T) -> T {
    cli.or(env).or(file).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
scp:
  sbi:
    server:
      - address: 172.22.0.50
        port: 7778
    client:
      nrf:
        - uri: http://172.22.0.10:7777
    tls:
      enabled: false
  fqdn: scp1.5gc.example.org
  nf_instance_id: scp-inst-1
  connect_timeout: 5
  request_timeout: 20
  max_cache_entries: 256
  cache_ttl: 120
"#;

    #[test]
    fn parses_all_actionable_keys() {
        let cfg = parse(SAMPLE).expect("valid yaml");
        assert_eq!(cfg.sbi_address().as_deref(), Some("172.22.0.50"));
        assert_eq!(cfg.sbi_port(), Some(7778));
        assert_eq!(cfg.nrf_uri().as_deref(), Some("http://172.22.0.10:7777"));
        let s = cfg.section();
        assert_eq!(s.fqdn.as_deref(), Some("scp1.5gc.example.org"));
        assert_eq!(s.nf_instance_id.as_deref(), Some("scp-inst-1"));
        assert_eq!(s.connect_timeout, Some(5));
        assert_eq!(s.request_timeout, Some(20));
        assert_eq!(s.max_cache_entries, Some(256));
        assert_eq!(s.cache_ttl, Some(120));
        assert_eq!(
            s.sbi.as_ref().unwrap().tls.as_ref().unwrap().enabled,
            Some(false)
        );
    }

    #[test]
    fn absent_scp_block_yields_empty_section() {
        let cfg = parse("logger:\n  level: info\n").expect("valid yaml");
        assert!(cfg.sbi_address().is_none());
        assert!(cfg.nrf_uri().is_none());
        assert!(cfg.section().fqdn.is_none());
        assert!(cfg.section().connect_timeout.is_none());
    }

    #[test]
    fn shipped_config_shape_parses() {
        // Mirrors the shape of docker/rust/configs/scp.yaml: an sbi block with
        // no scp-level fqdn/timeout keys. Must parse and leave the new keys unset
        // so today's defaults survive.
        let shipped = r#"
logger:
  level: info
scp:
  sbi:
    server:
      - address: 172.22.0.50
        port: 7777
    client:
      nrf:
        - uri: http://172.22.0.10:7777
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/scp.crt
"#;
        let cfg = parse(shipped).expect("shipped shape parses");
        assert_eq!(cfg.sbi_port(), Some(7777));
        assert!(cfg.section().fqdn.is_none());
        assert!(cfg.section().connect_timeout.is_none());
    }

    #[test]
    fn malformed_yaml_is_an_error() {
        assert!(parse("scp:\n  sbi:\n    server: [ this is : not valid").is_err());
    }

    /// Parse the REAL shipped docker/rust/configs/scp.yaml (not a fixture copy)
    /// so a future edit to it cannot silently break the SCP's startup parse.
    /// Its `logger` / `global` / `tls.ca` / `tls.min_version` keys are outside
    /// this schema and must be tolerated (serde ignores unknown fields).
    #[test]
    fn shipped_scp_yaml_parses() {
        let shipped = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../docker/rust/configs/scp.yaml"
        ));
        let cfg = parse(shipped).expect("shipped scp.yaml must parse");
        assert_eq!(cfg.sbi_address().as_deref(), Some("172.22.0.50"));
        assert_eq!(cfg.sbi_port(), Some(7777));
        assert_eq!(cfg.nrf_uri().as_deref(), Some("http://172.22.0.10:7777"));
        // The optional scp-level keys are documented commented-out, so the
        // built-in defaults still apply.
        assert!(cfg.section().fqdn.is_none());
        assert!(cfg.section().connect_timeout.is_none());
        assert!(cfg.section().max_cache_entries.is_none());
    }

    #[test]
    fn resolve_precedence_cli_over_env_over_file_over_default() {
        // CLI wins over everything.
        assert_eq!(
            resolve(Some("cli"), Some("env"), Some("file"), "default"),
            "cli"
        );
        // env wins when no CLI.
        assert_eq!(resolve(None, Some("env"), Some("file"), "default"), "env");
        // file wins when no CLI/env.
        assert_eq!(resolve(None, None, Some("file"), "default"), "file");
        // default is the floor.
        assert_eq!(resolve::<&str>(None, None, None, "default"), "default");
    }
}
