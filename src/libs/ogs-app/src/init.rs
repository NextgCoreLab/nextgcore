//! Application Initialization
//!
//! This module provides application initialization and termination functionality,
//! ported from lib/app/ogs-init.c and lib/app/ogs-init.h.

use crate::config::ConfigError;
use crate::context::{ogs_app, OgsLogTs};
use crate::yaml::{OgsYamlDocument, YamlError};
use std::env;
use thiserror::Error;

/// Initialization errors
#[derive(Error, Debug)]
pub enum InitError {
    #[error("Configuration error: {0}")]
    ConfigError(#[from] ConfigError),
    #[error("YAML error: {0}")]
    YamlError(#[from] YamlError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Initialization failed: {0}")]
    InitFailed(String),
    #[error("Already initialized")]
    AlreadyInitialized,
    #[error("Not initialized")]
    NotInitialized,
}

/// Command line options
#[derive(Debug, Default)]
pub struct CommandLineOptions {
    pub config_file: Option<String>,
    pub log_file: Option<String>,
    pub log_level: Option<String>,
    pub domain_mask: Option<String>,
    pub config_section_id: Option<i32>,
}

impl CommandLineOptions {
    /// Parse command line arguments
    /// Mirrors the getopt parsing in ogs_app_initialize()
    pub fn parse(args: &[String]) -> Self {
        let mut opts = CommandLineOptions::default();
        let mut i = 0;

        while i < args.len() {
            match args[i].as_str() {
                "-c" => {
                    if i + 1 < args.len() {
                        opts.config_file = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                "-l" => {
                    if i + 1 < args.len() {
                        opts.log_file = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                "-e" => {
                    if i + 1 < args.len() {
                        opts.log_level = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                "-m" => {
                    if i + 1 < args.len() {
                        opts.domain_mask = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                "-k" => {
                    if i + 1 < args.len() {
                        opts.config_section_id = args[i + 1].parse().ok();
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }

        opts
    }
}

/// Application initializer
pub struct OgsAppInitializer {
    document: Option<OgsYamlDocument>,
}

impl OgsAppInitializer {
    /// Create a new initializer
    pub fn new() -> Self {
        OgsAppInitializer { document: None }
    }

    /// Initialize the application
    /// Mirrors ogs_app_initialize()
    pub fn initialize(
        &mut self,
        version: &str,
        default_config: &str,
        args: &[String],
    ) -> Result<(), InitError> {
        // Stage 1: Parse command line options
        let opts = CommandLineOptions::parse(args);

        // Initialize context
        ogs_app()
            .init()
            .map_err(|e| InitError::InitFailed(e.to_string()))?;

        ogs_app().set_version(version);

        // Stage 2: Load configuration file
        let config_file = opts
            .config_file
            .unwrap_or_else(|| default_config.to_string());
        ogs_app().set_file(&config_file);

        self.read_config(&config_file)?;
        self.parse_config()?;

        // Stage 3: Setup logger
        if let Some(log_file) = opts.log_file {
            ogs_app().context_mut().logger.file = Some(log_file);
        }

        if let Some(domain_mask) = opts.domain_mask {
            ogs_app().context_mut().logger.domain = Some(domain_mask);
        }

        if let Some(log_level) = opts.log_level {
            ogs_app().context_mut().logger.level = Some(log_level);
        }

        // Stage 4: Setup database URI from environment
        if let Ok(db_uri) = env::var("DB_URI") {
            ogs_app().set_db_uri(&db_uri);
        }

        // Stage 5: Setup config section ID
        if let Some(id) = opts.config_section_id {
            ogs_app().set_config_section_id(id);
        }

        Ok(())
    }

    /// Terminate the application
    /// Mirrors ogs_app_terminate()
    pub fn terminate(&self) -> Result<(), InitError> {
        ogs_app()
            .final_()
            .map_err(|e| InitError::InitFailed(e.to_string()))?;
        Ok(())
    }

    /// Read configuration file
    /// Mirrors read_config()
    fn read_config(&mut self, file: &str) -> Result<(), InitError> {
        self.document = Some(OgsYamlDocument::from_file(file)?);
        Ok(())
    }

    /// Parse configuration
    /// Mirrors parse_config()
    fn parse_config(&mut self) -> Result<(), InitError> {
        let document = self
            .document
            .as_ref()
            .ok_or_else(|| InitError::InitFailed("No document loaded".to_string()))?;

        // Prepare context
        self.context_prepare()?;

        let mut iter = document.iter();

        while iter.next() {
            let root_key = match iter.key() {
                Some(k) => k.to_string(),
                None => continue,
            };

            match root_key.as_str() {
                "db_uri" => {
                    if let Some(child) = iter.recurse() {
                        if let Some(uri) = child.value() {
                            ogs_app().set_db_uri(uri);
                        }
                    }
                }
                "logger" => {
                    self.parse_logger(&mut iter)?;
                }
                "global" => {
                    let mut global = ogs_app().global_conf_mut();
                    global.parse(&mut iter)?;
                    drop(global);
                    ogs_app().recalculate_pool_size();
                }
                _ => {
                    // Count NF configuration sections
                    ogs_app().global_conf_mut().count_nf_conf_section(&root_key);
                }
            }
        }

        self.context_validation()?;

        Ok(())
    }

    /// Prepare context with defaults
    /// Mirrors context_prepare()
    fn context_prepare(&self) -> Result<(), InitError> {
        // Set USRSCTP default port
        ogs_app().context_mut().usrsctp.udp_port = 9899;

        // Prepare global configuration
        ogs_app().global_conf_mut().prepare();

        // Recalculate pool sizes
        ogs_app().recalculate_pool_size();

        Ok(())
    }

    /// Validate context
    /// Mirrors context_validation()
    fn context_validation(&self) -> Result<(), InitError> {
        // Currently no validation needed
        Ok(())
    }

    /// Parse logger configuration
    fn parse_logger(&self, root_iter: &mut crate::yaml::OgsYamlIter) -> Result<(), InitError> {
        if let Some(mut logger_iter) = root_iter.recurse() {
            while logger_iter.next() {
                let logger_key = match logger_iter.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                match logger_key.as_str() {
                    "file" => {
                        // Check if it's the legacy format (direct value) or new format (nested)
                        if logger_iter.has_value() {
                            // Legacy format: logger.file: /path/to/file
                            if let Some(child) = logger_iter.recurse() {
                                if let Some(file) = child.value() {
                                    ogs_app().context_mut().logger.file = Some(file.to_string());
                                }
                            }
                        } else {
                            // New format: logger.file.path
                            if let Some(mut file_iter) = logger_iter.recurse() {
                                while file_iter.next() {
                                    let file_key = match file_iter.key() {
                                        Some(k) => k.to_string(),
                                        None => continue,
                                    };

                                    match file_key.as_str() {
                                        "path" => {
                                            if let Some(child) = file_iter.recurse() {
                                                if let Some(path) = child.value() {
                                                    ogs_app().context_mut().logger.file =
                                                        Some(path.to_string());
                                                }
                                            }
                                        }
                                        "timestamp" => {
                                            if let Some(child) = file_iter.recurse() {
                                                let ts = if child.bool_value() {
                                                    OgsLogTs::Enabled
                                                } else {
                                                    OgsLogTs::Disabled
                                                };
                                                ogs_app().context_mut().logger.timestamp = ts;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    "default" => {
                        if let Some(mut default_iter) = logger_iter.recurse() {
                            while default_iter.next() {
                                let default_key = match default_iter.key() {
                                    Some(k) => k.to_string(),
                                    None => continue,
                                };

                                if default_key == "timestamp" {
                                    if let Some(child) = default_iter.recurse() {
                                        let ts = if child.bool_value() {
                                            OgsLogTs::Enabled
                                        } else {
                                            OgsLogTs::Disabled
                                        };
                                        ogs_app().context_mut().logger_default.timestamp = ts;
                                    }
                                }
                            }
                        }
                    }
                    "level" => {
                        if let Some(child) = logger_iter.recurse() {
                            if let Some(level) = child.value() {
                                ogs_app().context_mut().logger.level = Some(level.to_string());
                            }
                        }
                    }
                    "domain" => {
                        if let Some(child) = logger_iter.recurse() {
                            if let Some(domain) = child.value() {
                                ogs_app().context_mut().logger.domain = Some(domain.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Get the parsed YAML document
    pub fn document(&self) -> Option<&OgsYamlDocument> {
        self.document.as_ref()
    }
}

impl Default for OgsAppInitializer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to initialize the application
/// Mirrors ogs_app_initialize()
pub fn ogs_app_initialize(
    version: &str,
    default_config: &str,
    args: &[String],
) -> Result<OgsAppInitializer, InitError> {
    let mut initializer = OgsAppInitializer::new();
    initializer.initialize(version, default_config, args)?;
    Ok(initializer)
}

/// Convenience function to terminate the application
/// Mirrors ogs_app_terminate()
pub fn ogs_app_terminate() -> Result<(), InitError> {
    let initializer = OgsAppInitializer::new();
    initializer.terminate()
}

/// Read and parse configuration file
/// Mirrors ogs_app_config_read()
pub fn ogs_app_config_read(file: &str) -> Result<OgsYamlDocument, InitError> {
    Ok(OgsYamlDocument::from_file(file)?)
}

// ── NF lifecycle helpers ──────────────────────────────────────────────────────

/// Common NF startup initialisation.
///
/// Consolidates the three lines that appear verbatim in every NF `main`:
/// 1. `env_logger` initialisation (respects `RUST_LOG`; falls back to `log_level`).
/// 2. OpenTelemetry / OTLP tracing setup (no-op when the collector is absent).
/// 3. `ctrlc` / SIGTERM signal handler that sets `shutdown` to `true`.
///
/// # Arguments
/// * `service_name` — value of `env!("CARGO_PKG_NAME")` from the calling binary.
/// * `log_level`    — default log level string (e.g. `"info"`).
/// * `shutdown`     — shared `AtomicBool`; the signal handler stores `true` here.
///
/// # Errors
/// Returns `InitError` if the signal handler cannot be registered.
///
/// # Example
/// ```no_run
/// use std::sync::{Arc, atomic::AtomicBool};
/// use ogs_app::init::nf_common_init;
///
/// let shutdown = Arc::new(AtomicBool::new(false));
/// nf_common_init("my-nf", "info", shutdown.clone()).expect("init failed");
/// ```
pub fn nf_common_init(
    service_name: &str,
    log_level: &str,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), InitError> {
    // 1. Logging — honour RUST_LOG env var; fall back to the supplied level.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    // 2. OpenTelemetry — best-effort; failures are logged but not fatal.
    let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://jaeger:4317".to_string());
    let _ = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(service_name).with_endpoint(otel_endpoint),
    );

    // 3. Signal handler — graceful shutdown on Ctrl-C / SIGTERM.
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .map_err(|e| InitError::InitFailed(format!("Failed to set signal handler: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_line_parse() {
        let args = vec![
            "-c".to_string(),
            "/etc/nextgcore/amf.yaml".to_string(),
            "-l".to_string(),
            "/var/log/nextgcore/amf.log".to_string(),
            "-e".to_string(),
            "debug".to_string(),
            "-m".to_string(),
            "amf".to_string(),
            "-k".to_string(),
            "1".to_string(),
        ];

        let opts = CommandLineOptions::parse(&args);

        assert_eq!(
            opts.config_file,
            Some("/etc/nextgcore/amf.yaml".to_string())
        );
        assert_eq!(
            opts.log_file,
            Some("/var/log/nextgcore/amf.log".to_string())
        );
        assert_eq!(opts.log_level, Some("debug".to_string()));
        assert_eq!(opts.domain_mask, Some("amf".to_string()));
        assert_eq!(opts.config_section_id, Some(1));
    }

    #[test]
    fn test_command_line_parse_empty() {
        let args: Vec<String> = vec![];
        let opts = CommandLineOptions::parse(&args);

        assert!(opts.config_file.is_none());
        assert!(opts.log_file.is_none());
        assert!(opts.log_level.is_none());
    }

    #[test]
    fn test_initializer_new() {
        let init = OgsAppInitializer::new();
        assert!(init.document.is_none());
    }
}
