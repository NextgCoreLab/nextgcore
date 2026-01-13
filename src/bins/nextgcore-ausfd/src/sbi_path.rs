//! AUSF SBI Path Functions
//!
//! Port of src/ausf/sbi-path.c - SBI server and client path functions

use crate::nudm_build::{self, ResynchronizationInfo};
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
    // In C: nf_instance = ogs_sbi_self()->nf_instance;
    // ogs_sbi_nf_fsm_init(nf_instance);

    // Build NF instance information
    // In C: ogs_sbi_nf_instance_build_default(nf_instance);
    // ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_SCP);
    // ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_AMF);

    // Build NF service information (nausf-auth)
    // In C: service = ogs_sbi_nf_service_build_default(nf_instance, OGS_SBI_SERVICE_NAME_NAUSF_AUTH);
    // ogs_sbi_nf_service_add_version(service, OGS_SBI_API_V1, OGS_SBI_API_V1_0_0, NULL);
    // ogs_sbi_nf_service_add_allowed_nf_type(service, OpenAPI_nf_type_AMF);

    // Initialize NRF NF Instance
    // In C: nf_instance = ogs_sbi_self()->nrf_instance;
    // if (nf_instance) ogs_sbi_nf_fsm_init(nf_instance);

    // Setup Subscription-Data
    // In C: ogs_sbi_subscription_spec_add(OpenAPI_nf_type_SEPP, NULL);
    // ogs_sbi_subscription_spec_add(OpenAPI_nf_type_NULL, OGS_SBI_SERVICE_NAME_NUDM_UEAU);

    // Start SBI server
    // In C: ogs_sbi_server_start_all(ogs_sbi_server_handler)

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
    // In C: ogs_sbi_client_stop_all();
    // ogs_sbi_server_stop_all();

    SBI_RUNNING.store(false, Ordering::SeqCst);

    log::info!("AUSF SBI server closed");
}

/// Check if SBI server is running
pub fn ausf_sbi_is_running() -> bool {
    SBI_RUNNING.load(Ordering::SeqCst)
}

/// Send SBI request to NF instance
///
/// Port of ausf_sbi_send_request()
pub fn ausf_sbi_send_request(nf_instance_id: &str, xact_id: u64) -> bool {
    log::debug!(
        "Sending SBI request to NF instance [{}] xact [{}]",
        nf_instance_id,
        xact_id
    );

    // In C: ogs_sbi_send_request_to_nf_instance(nf_instance, xact)
    // This would send the request through the SBI client

    true
}

/// Discover and send NUDM UEAU get request
///
/// Port of ausf_sbi_discover_and_send() with ausf_nudm_ueau_build_get
pub fn ausf_sbi_discover_and_send_nudm_ueau_get(
    ausf_ue_id: u64,
    stream_id: u64,
    resync_info: Option<&ResynchronizationInfo>,
) -> Result<(), String> {
    log::debug!(
        "Discover and send NUDM UEAU get for UE [{}] stream [{}]",
        ausf_ue_id,
        stream_id
    );

    // Build the request
    let request = nudm_build::ausf_nudm_ueau_build_get(ausf_ue_id, resync_info)
        .ok_or("Failed to build NUDM UEAU get request")?;

    // In C code:
    // 1. Create SBI xact with ausf_ue->id, service_type, discovery_option, build function
    // 2. Set xact->assoc_stream_id = stream_id
    // 3. Call ogs_sbi_discover_and_send(xact)

    // For now, log the request details
    log::debug!(
        "NUDM UEAU request: {} /{}/{}",
        request.method,
        request.service_name,
        request.resource_components.join("/")
    );

    Ok(())
}

/// Discover and send NUDM UEAU result confirmation request
///
/// Port of ausf_sbi_discover_and_send() with ausf_nudm_ueau_build_result_confirmation_inform
pub fn ausf_sbi_discover_and_send_nudm_ueau_result_confirmation(
    ausf_ue_id: u64,
    stream_id: u64,
) -> Result<(), String> {
    log::debug!(
        "Discover and send NUDM UEAU result confirmation for UE [{}] stream [{}]",
        ausf_ue_id,
        stream_id
    );

    // Build the request
    let request = nudm_build::ausf_nudm_ueau_build_result_confirmation_inform(ausf_ue_id)
        .ok_or("Failed to build NUDM UEAU result confirmation request")?;

    log::debug!(
        "NUDM UEAU request: {} /{}/{}",
        request.method,
        request.service_name,
        request.resource_components.join("/")
    );

    Ok(())
}

/// Discover and send NUDM UEAU auth removal request
///
/// Port of ausf_sbi_discover_and_send() with ausf_nudm_ueau_build_auth_removal_ind
pub fn ausf_sbi_discover_and_send_nudm_ueau_auth_removal(
    ausf_ue_id: u64,
    stream_id: u64,
) -> Result<(), String> {
    log::debug!(
        "Discover and send NUDM UEAU auth removal for UE [{}] stream [{}]",
        ausf_ue_id,
        stream_id
    );

    // Build the request
    let request = nudm_build::ausf_nudm_ueau_build_auth_removal_ind(ausf_ue_id)
        .ok_or("Failed to build NUDM UEAU auth removal request")?;

    log::debug!(
        "NUDM UEAU request: {} /{}/{}",
        request.method,
        request.service_name,
        request.resource_components.join("/")
    );

    Ok(())
}

/// SBI transaction for tracking requests
#[derive(Debug, Clone)]
pub struct SbiXact {
    /// Transaction ID
    pub id: u64,
    /// Associated SBI object ID (e.g., ausf_ue_id)
    pub sbi_object_id: u64,
    /// Associated stream ID for response
    pub assoc_stream_id: u64,
    /// Service type
    pub service_type: String,
}

impl SbiXact {
    /// Create a new SBI transaction
    pub fn new(id: u64, sbi_object_id: u64, service_type: &str) -> Self {
        Self {
            id,
            sbi_object_id,
            assoc_stream_id: 0,
            service_type: service_type.to_string(),
        }
    }
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

    #[test]
    fn test_sbi_xact() {
        let xact = SbiXact::new(1, 100, "nudm-ueau");
        assert_eq!(xact.id, 1);
        assert_eq!(xact.sbi_object_id, 100);
        assert_eq!(xact.service_type, "nudm-ueau");
    }
}
