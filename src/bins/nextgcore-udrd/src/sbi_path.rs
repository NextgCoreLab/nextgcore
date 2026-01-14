//! UDR SBI Path Functions
//!
//! Port of src/udr/sbi-path.c - SBI server and client path functions

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
            addr: "0.0.0.0".to_string(),
            port: 7777,  // Standard SBI port
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
/// Port of udr_sbi_open()
pub fn udr_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    let config = config.unwrap_or_default();

    log::info!("Opening UDR SBI server on {}:{}", config.addr, config.port);

    // Initialize SELF NF instance
    // In C: nf_instance = ogs_sbi_self()->nf_instance;
    // ogs_assert(nf_instance);
    // ogs_sbi_nf_fsm_init(nf_instance);

    // Build NF instance information. It will be transmitted to NRF.
    // In C: ogs_sbi_nf_instance_build_default(nf_instance);
    // ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_SCP);
    // ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_PCF);
    // ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_UDM);

    // Build NF service information. It will be transmitted to NRF.
    // In C: if (ogs_sbi_nf_service_is_available(OGS_SBI_SERVICE_NAME_NUDR_DR)) {
    //     service = ogs_sbi_nf_service_build_default(
    //                 nf_instance, OGS_SBI_SERVICE_NAME_NUDR_DR);
    //     ogs_assert(service);
    //     ogs_sbi_nf_service_add_version(
    //                 service, OGS_SBI_API_V1, OGS_SBI_API_V1_0_0, NULL);
    //     ogs_sbi_nf_service_add_allowed_nf_type(service, OpenAPI_nf_type_PCF);
    //     ogs_sbi_nf_service_add_allowed_nf_type(service, OpenAPI_nf_type_UDM);
    // }

    // Initialize NRF NF Instance
    // In C: nf_instance = ogs_sbi_self()->nrf_instance;
    // if (nf_instance)
    //     ogs_sbi_nf_fsm_init(nf_instance);

    // Setup Subscription-Data
    // In C: ogs_sbi_subscription_spec_add(OpenAPI_nf_type_SEPP, NULL);

    // Start SBI server
    // In C: if (ogs_sbi_server_start_all(ogs_sbi_server_handler) != OGS_OK)
    //     return OGS_ERROR;

    SBI_RUNNING.store(true, Ordering::SeqCst);

    log::info!("UDR SBI server opened successfully");
    Ok(())
}

/// Close SBI server
///
/// Port of udr_sbi_close()
pub fn udr_sbi_close() {
    log::info!("Closing UDR SBI server");

    // Stop all clients and servers
    // In C: ogs_sbi_client_stop_all();
    // ogs_sbi_server_stop_all();

    SBI_RUNNING.store(false, Ordering::SeqCst);

    log::info!("UDR SBI server closed");
}

/// Check if SBI server is running
pub fn udr_sbi_is_running() -> bool {
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
        format!("{}://{}:{}", scheme, self.config.addr, self.config.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbi_server_config_default() {
        let config = SbiServerConfig::default();
        assert_eq!(config.addr, "0.0.0.0");
        assert_eq!(config.port, 7777);
        assert!(!config.tls_enabled);
    }

    #[test]
    fn test_sbi_open_close() {
        assert!(!udr_sbi_is_running());

        udr_sbi_open(None).unwrap();
        assert!(udr_sbi_is_running());

        udr_sbi_close();
        assert!(!udr_sbi_is_running());
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
