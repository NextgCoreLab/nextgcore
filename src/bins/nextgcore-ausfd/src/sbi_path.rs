//! AUSF SBI Path Functions
//!
//! Port of src/ausf/sbi-path.c - SBI server and client path functions.
//!
//! NOTE (ausfd-10): the live SBI server is the HTTP/2 `nextgcore_sbi::server::SbiServer`
//! started in `app`, and live Nudm client requests are issued directly from
//! `app` (`send_udm_generate_auth_data` / `send_udm_auth_result`). The C
//! port's inert `ausf_sbi_discover_and_send_*` shims were only reachable from
//! the deleted per-UE FSM (#654).

use std::sync::atomic::{AtomicBool, Ordering};

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    /// Server address
    pub addr: String,
    /// Server port
    pub port: u16,
    /// TLS enabled
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert: Option<String>,
    /// TLS key path
    pub tls_key: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 7777,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// SBI server state
static SBI_RUNNING: AtomicBool = AtomicBool::new(false);

/// Open SBI server
///
/// Port of ausf_sbi_open()
pub fn ausf_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    let config = config.unwrap_or_default();

    log::info!("Opening AUSF SBI server on {}:{}", config.addr, config.port);

    // Initialize SELF NF instance
    // In C: nf_instance = nextgcore_sbi_self()->nf_instance;
    // nextgcore_sbi_nf_fsm_init(nf_instance);

    // Build NF instance information
    // In C: nextgcore_sbi_nf_instance_build_default(nf_instance);
    // nextgcore_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_SCP);
    // nextgcore_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_AMF);

    // Build NF service information (nausf-auth)
    // In C: service = nextgcore_sbi_nf_service_build_default(nf_instance, NEXTGCORE_SBI_SERVICE_NAME_NAUSF_AUTH);
    // nextgcore_sbi_nf_service_add_version(service, NEXTGCORE_SBI_API_V1, NEXTGCORE_SBI_API_V1_0_0, NULL);
    // nextgcore_sbi_nf_service_add_allowed_nf_type(service, OpenAPI_nf_type_AMF);

    // Initialize NRF NF Instance
    // In C: nf_instance = nextgcore_sbi_self()->nrf_instance;
    // if (nf_instance) nextgcore_sbi_nf_fsm_init(nf_instance);

    // Setup Subscription-Data
    // In C: nextgcore_sbi_subscription_spec_add(OpenAPI_nf_type_SEPP, NULL);
    // nextgcore_sbi_subscription_spec_add(OpenAPI_nf_type_NULL, NEXTGCORE_SBI_SERVICE_NAME_NUDM_UEAU);

    // Start SBI server
    // In C: nextgcore_sbi_server_start_all(nextgcore_sbi_server_handler)

    SBI_RUNNING.store(true, Ordering::SeqCst);

    log::info!("AUSF SBI server opened successfully");
    Ok(())
}

/// Close SBI server
///
/// Port of ausf_sbi_close()
pub fn ausf_sbi_close() {
    log::info!("Closing AUSF SBI server");

    // Stop all clients and servers
    // In C: nextgcore_sbi_client_stop_all();
    // nextgcore_sbi_server_stop_all();

    SBI_RUNNING.store(false, Ordering::SeqCst);

    log::info!("AUSF SBI server closed");
}

/// Check if SBI server is running
pub fn ausf_sbi_is_running() -> bool {
    SBI_RUNNING.load(Ordering::SeqCst)
}

/// SBI server handle (placeholder)
pub struct SbiServer {
    config: SbiServerConfig,
}

impl SbiServer {
    /// Create a new SBI server
    pub fn new(config: SbiServerConfig) -> Self {
        Self { config }
    }

    /// Get server URI
    pub fn uri(&self) -> String {
        let scheme = if self.config.tls_enabled {
            "https"
        } else {
            "http"
        };
        format!(
            "{}://{}",
            scheme,
            nextgcore_sbi::uri_encode::uri_authority(&self.config.addr, self.config.port)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbi_server_config_default() {
        let config = SbiServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 7777);
        assert!(!config.tls_enabled);
    }

    #[test]
    fn test_sbi_open_close() {
        assert!(!ausf_sbi_is_running());

        ausf_sbi_open(None).unwrap();
        assert!(ausf_sbi_is_running());

        ausf_sbi_close();
        assert!(!ausf_sbi_is_running());
    }

    #[test]
    fn test_sbi_server_uri() {
        let config = SbiServerConfig {
            addr: "192.168.1.1".to_string(),
            port: 8080,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        };
        let server = SbiServer::new(config);
        assert_eq!(server.uri(), "http://192.168.1.1:8080");
    }

    #[test]
    fn test_sbi_server_uri_tls() {
        let config = SbiServerConfig {
            addr: "192.168.1.1".to_string(),
            port: 8443,
            tls_enabled: true,
            tls_cert: Some("/path/to/cert".to_string()),
            tls_key: Some("/path/to/key".to_string()),
        };
        let server = SbiServer::new(config);
        assert_eq!(server.uri(), "https://192.168.1.1:8443");
    }
}
