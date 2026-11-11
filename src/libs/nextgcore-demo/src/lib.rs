//! The demo toggle convention (nextgsim#458, nextgcore#1394), shared so that no
//! demo hand-rolls it.
//!
//! # Schema
//!
//! One block at the root of a network function's YAML config, identical to the
//! nextgsim `nextgsim-demo` crate (nextgsim#461):
//!
//! ```yaml
//! demo:
//!   enabled: false        # process-wide kill switch; false overrides every demo below
//!   <key>:                # a demo key this binary registered, e.g. d441a-congestion-loop
//!     enabled: false
//!     mode: <mode>        # one of the modes the binary registered for <key>
//! ```
//!
//! - The block is optional. Absent, `demo: ~` and `demo: {}` all mean "no demo".
//! - `demo.enabled` defaults to `false`; so does each `<key>.enabled`.
//! - `<key>.mode` is **required** when `<key>.enabled` is true: there is no
//!   default mode, because a silent fallback is what the convention forbids.
//! - A key or mode the binary did not register, or a misspelt field, fails
//!   startup with a [`DemoConfigError`]. This holds even when the kill switch is
//!   off, so a typo cannot hide behind `enabled: false`.
//! - Keys and modes are lowercase letters, digits and `-`.
//!
//! # Gates
//!
//! A demo is active only when its binary was built with that demo's cargo
//! feature (the binary registers the [`DemoSpec`] under it), **and** both
//! `demo.enabled` and `demo.<key>.enabled` are true. With no demo active the
//! process is unchanged: no banner, no metric series, no demo log lines.
//!
//! # Visibility
//!
//! - [`install`] logs `WARN DEMO MODE ACTIVE: <key>=<mode>,...` once at startup.
//! - [`render_installed_metrics`] writes `nextg_demo_enabled{demo,mode} 1` per
//!   active demo, and nothing at all when none is active. `nextgcore-metrics`
//!   calls it from `nf::render_common`, so the NFs that render their `/metrics`
//!   through that (amfd, ausfd, bsfd, nrfd, nssfd, pcfd, smfd, udmd, udrd, upfd
//!   at the time of writing) carry it with no extra code. An NF that renders
//!   its own body (eesd, nwdafd, ...) must call [`render_installed_metrics`]
//!   itself when it is wired for a demo.
//! - [`demo_log!`] prefixes a demo's log lines with `[demo:<key>]`.
//!
//! # Wiring an NF for a demo
//!
//! 1. Under the demo's cargo feature, register its [`DemoSpec`] in the NF's
//!    [`DemoRegistry`] (a default build registers nothing).
//! 2. At startup, call [`init_from_root`] on the parsed config root and fail
//!    startup on its error.
//! 3. Read [`active_mode`] at each decision, and log with [`demo_log!`].
//! 4. If the NF does not render `/metrics` through `nextgcore-metrics`'
//!    `nf::render_common`, append [`render_installed_metrics`] to its body.
//!
//! # Switching
//!
//! nextgcore NFs switch demos and modes by config plus restart only. This crate
//! has no runtime setter and opens no listener; the installed state is a
//! write-once [`OnceLock`]. Runtime switching (`nr-cli <node> demo <key> set`)
//! is a nextgsim-only feature.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

use serde_yaml::Value;

#[doc(hidden)]
pub use log;

/// The name of the config block at the root of an NF config.
pub const DEMO_BLOCK: &str = "demo";

/// The metric family exported while a demo is active.
pub const METRIC_NAME: &str = "nextg_demo_enabled";

/// One demo a binary knows about: its key, its modes, and the demos it needs
/// active alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemoSpec {
    /// The demo's key, as written under `demo:` (e.g. `d441a-congestion-loop`).
    pub key: &'static str,
    /// The modes (arms, variants) the demo accepts.
    pub modes: &'static [&'static str],
    /// Keys of demos that must also be active when this one is.
    pub requires: &'static [&'static str],
}

/// The demos one binary registered. A binary registers a demo only under that
/// demo's cargo feature, so a default build has an empty registry and rejects
/// every `demo.<key>` block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemoRegistry {
    specs: Vec<DemoSpec>,
}

impl DemoRegistry {
    /// A registry of `specs`.
    ///
    /// # Panics
    /// On a malformed key or mode, a duplicate key, an empty mode list, or a
    /// `requires` naming an unregistered key. These are programming errors in the
    /// binary's own table, not configuration errors.
    pub fn new(specs: &[DemoSpec]) -> Self {
        let mut seen = std::collections::BTreeSet::new();
        for s in specs {
            assert!(is_name(s.key), "demo key {:?} is not [a-z0-9-]+", s.key);
            assert!(seen.insert(s.key), "demo key {:?} registered twice", s.key);
            assert!(!s.modes.is_empty(), "demo {:?} registers no mode", s.key);
            for m in s.modes {
                assert!(
                    is_name(m),
                    "demo {:?} mode {:?} is not [a-z0-9-]+",
                    s.key,
                    m
                );
            }
        }
        for s in specs {
            for r in s.requires {
                assert!(
                    specs.iter().any(|o| o.key == *r),
                    "demo {:?} requires unregistered demo {:?}",
                    s.key,
                    r
                );
            }
        }
        Self {
            specs: specs.to_vec(),
        }
    }

    /// The spec registered for `key`.
    pub fn get(&self, key: &str) -> Option<&DemoSpec> {
        self.specs.iter().find(|s| s.key == key)
    }

    /// Every registered key, in registration order.
    pub fn keys(&self) -> Vec<&'static str> {
        self.specs.iter().map(|s| s.key).collect()
    }
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Why a `demo:` block was refused. Every variant fails startup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DemoConfigError {
    /// `demo.<key>` names a demo this binary did not register (not built with
    /// its feature, or misspelt).
    #[error("demo config: unknown demo key {key:?} (this binary knows {known:?})")]
    UnknownKey {
        key: String,
        known: Vec<&'static str>,
    },
    /// `demo.<key>.mode` is not one of the modes registered for the key.
    #[error("demo config: unknown mode {mode:?} for demo {demo:?} (known modes {known:?})")]
    UnknownMode {
        demo: String,
        mode: String,
        known: Vec<&'static str>,
    },
    /// An active demo needs another demo that is not active.
    #[error("demo config: demo {demo:?} requires demo {requires:?} to be enabled too")]
    MissingDependency { demo: String, requires: String },
    /// The block is not the schema's shape: a wrong type, a misspelt field, or
    /// an enabled demo without a mode.
    #[error("demo config: {detail}")]
    Malformed { detail: String },
    /// [`init_from_root`] ran a second time in this process: a programming
    /// error, not a config error (the state is write-once).
    #[error("demo config: demo state is already installed for this process")]
    AlreadyInstalled,
}

fn malformed(detail: impl Into<String>) -> DemoConfigError {
    DemoConfigError::Malformed {
        detail: detail.into(),
    }
}

/// One `demo.<key>` entry as written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemoEntry {
    pub enabled: bool,
    pub mode: Option<String>,
}

/// The `demo:` block as written, before it is checked against a registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemoConfig {
    /// The process-wide kill switch.
    pub enabled: bool,
    /// The per-demo entries, by key.
    pub demos: BTreeMap<String, DemoEntry>,
}

fn as_bool(v: &Value, path: &str) -> Result<bool, DemoConfigError> {
    match v {
        Value::Bool(b) => Ok(*b),
        Value::Null => Ok(false),
        other => Err(malformed(format!(
            "{path} must be a boolean, got {other:?}"
        ))),
    }
}

impl DemoConfig {
    /// Read the `demo:` block from the root of an NF's YAML config. A root with
    /// no `demo` key (or a non-mapping root) yields the empty, disabled config.
    pub fn from_root(root: &Value) -> Result<Self, DemoConfigError> {
        match root.get(DEMO_BLOCK) {
            None => Ok(Self::default()),
            Some(block) => Self::from_block(block),
        }
    }

    /// Read a `demo:` block's value.
    pub fn from_block(block: &Value) -> Result<Self, DemoConfigError> {
        let map = match block {
            Value::Null => return Ok(Self::default()),
            Value::Mapping(m) => m,
            other => return Err(malformed(format!("demo must be a mapping, got {other:?}"))),
        };
        let mut cfg = Self::default();
        for (k, v) in map {
            let Some(k) = k.as_str() else {
                return Err(malformed(format!("demo has a non-string key {k:?}")));
            };
            if k == "enabled" {
                cfg.enabled = as_bool(v, "demo.enabled")?;
                continue;
            }
            cfg.demos
                .insert(k.to_string(), DemoEntry::from_value(k, v)?);
        }
        Ok(cfg)
    }

    /// Check the block against the binary's registry and return what is active.
    ///
    /// Keys, modes and field names are checked whether or not the kill switch is
    /// on. The kill switch then decides: off, nothing is active. On, every entry
    /// with `enabled: true` is, and each one's `requires` must be active too.
    pub fn validate(&self, registry: &DemoRegistry) -> Result<ActiveDemos, DemoConfigError> {
        let mut active = Vec::new();
        for (key, entry) in &self.demos {
            let Some(spec) = registry.get(key) else {
                return Err(DemoConfigError::UnknownKey {
                    key: key.clone(),
                    known: registry.keys(),
                });
            };
            if let Some(mode) = &entry.mode {
                if !spec.modes.contains(&mode.as_str()) {
                    return Err(DemoConfigError::UnknownMode {
                        demo: key.clone(),
                        mode: mode.clone(),
                        known: spec.modes.to_vec(),
                    });
                }
            }
            if entry.enabled {
                let Some(mode) = &entry.mode else {
                    return Err(malformed(format!(
                        "demo.{key}.mode is required when demo.{key}.enabled is true \
                         (known modes {:?})",
                        spec.modes
                    )));
                };
                if self.enabled {
                    active.push((spec.key, mode.clone()));
                }
            }
        }
        for (key, _) in &active {
            let spec = registry.get(key).expect("active keys are registered");
            for req in spec.requires {
                if !active.iter().any(|(k, _)| k == req) {
                    return Err(DemoConfigError::MissingDependency {
                        demo: key.to_string(),
                        requires: req.to_string(),
                    });
                }
            }
        }
        Ok(ActiveDemos { entries: active })
    }
}

impl DemoEntry {
    fn from_value(key: &str, v: &Value) -> Result<Self, DemoConfigError> {
        let map = match v {
            Value::Null => return Ok(Self::default()),
            Value::Mapping(m) => m,
            other => {
                return Err(malformed(format!(
                    "demo.{key} must be a mapping, got {other:?}"
                )))
            }
        };
        let mut e = Self::default();
        for (f, fv) in map {
            match f.as_str() {
                Some("enabled") => e.enabled = as_bool(fv, &format!("demo.{key}.enabled"))?,
                Some("mode") => match fv {
                    Value::String(s) => e.mode = Some(s.clone()),
                    Value::Null => e.mode = None,
                    other => {
                        return Err(malformed(format!(
                            "demo.{key}.mode must be a string, got {other:?}"
                        )))
                    }
                },
                _ => {
                    let name = f
                        .as_str()
                        .map_or_else(|| format!("{f:?}"), |n| format!("{n:?}"));
                    return Err(malformed(format!(
                        "demo.{key} has unknown field {name} (expected enabled, mode)"
                    )));
                }
            }
        }
        Ok(e)
    }
}

/// The demos active in this process, sorted by key. Empty unless both gates
/// and the kill switch are on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveDemos {
    entries: Vec<(&'static str, String)>,
}

impl ActiveDemos {
    /// No demo active.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The active `(key, mode)` pairs, sorted by key.
    pub fn entries(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.entries.iter().map(|(k, m)| (*k, m.as_str()))
    }

    /// The mode of `key`, if that demo is active.
    pub fn mode(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, m)| m.as_str())
    }

    /// Whether `key` is active.
    pub fn is_active(&self, key: &str) -> bool {
        self.mode(key).is_some()
    }

    /// `DEMO MODE ACTIVE: <key>=<mode>,...`, or `None` when no demo is active.
    pub fn banner(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let list: Vec<String> = self.entries().map(|(k, m)| format!("{k}={m}")).collect();
        Some(format!("DEMO MODE ACTIVE: {}", list.join(",")))
    }

    /// Append the `nextg_demo_enabled` family: one `{demo,mode} 1` series per
    /// active demo, and nothing at all (not even the HELP/TYPE header) when none
    /// is active.
    pub fn render_metrics(&self, out: &mut String) {
        if self.is_empty() {
            return;
        }
        let _ = writeln!(
            out,
            "# HELP {METRIC_NAME} 1 for each demo active in this process (nextgsim#458)"
        );
        let _ = writeln!(out, "# TYPE {METRIC_NAME} gauge");
        // Keys and modes are [a-z0-9-]+ (checked at registration), so they need
        // no label escaping.
        for (k, m) in self.entries() {
            let _ = writeln!(out, "{METRIC_NAME}{{demo=\"{k}\",mode=\"{m}\"}} 1");
        }
    }
}

/// The process's demo state, set once at startup. Write-once by design: NFs
/// switch demos by config plus restart, never at runtime.
static INSTALLED: OnceLock<ActiveDemos> = OnceLock::new();

/// [`install`] was called twice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("demo state is already installed for this process")]
pub struct AlreadyInstalled;

/// Install the process's active demos and, if any is active, log the
/// `WARN DEMO MODE ACTIVE` banner. Call once, at startup.
pub fn install(active: ActiveDemos) -> Result<&'static ActiveDemos, AlreadyInstalled> {
    let mut fresh = false;
    let installed = INSTALLED.get_or_init(|| {
        fresh = true;
        active
    });
    if !fresh {
        return Err(AlreadyInstalled);
    }
    if let Some(banner) = installed.banner() {
        log::warn!("{banner}");
    }
    Ok(installed)
}

/// Parse, check and install the `demo:` block of an NF config root in one step:
/// what an NF's startup calls. An error must fail startup.
pub fn init_from_root(
    root: &Value,
    registry: &DemoRegistry,
) -> Result<&'static ActiveDemos, DemoConfigError> {
    let active = DemoConfig::from_root(root)?.validate(registry)?;
    install(active).map_err(|AlreadyInstalled| DemoConfigError::AlreadyInstalled)
}

/// The installed state, or `None` before [`install`].
pub fn installed() -> Option<&'static ActiveDemos> {
    INSTALLED.get()
}

/// The mode of `key` in the installed state, if that demo is active.
pub fn active_mode(key: &str) -> Option<&'static str> {
    installed().and_then(|a| a.mode(key))
}

/// Append the installed state's `nextg_demo_enabled` family to a `/metrics`
/// body. Writes nothing before [`install`] or when no demo is active.
pub fn render_installed_metrics(out: &mut String) {
    if let Some(a) = installed() {
        a.render_metrics(out);
    }
}

/// `[demo:<key>]`, the prefix of every demo log line.
pub fn prefix(key: &str) -> String {
    format!("[demo:{key}]")
}

/// Log a demo line at `level` with the `[demo:<key>]` prefix:
///
/// ```
/// nextgcore_demo::demo_log!(info, "d441a-congestion-loop", "lowered the cap to {}", 3);
/// // => INFO [demo:d441a-congestion-loop] lowered the cap to 3
/// ```
#[macro_export]
macro_rules! demo_log {
    ($level:ident, $key:expr, $($arg:tt)+) => {
        $crate::log::$level!("[demo:{}] {}", $key, format_args!($($arg)+))
    };
}

#[cfg(test)]
mod tests;
