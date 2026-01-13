//! NSSF SBI Path Functions
//!
//! Port of src/nssf/sbi-path.c - SBI server/client path functions

use std::sync::atomic::{AtomicBool, Ordering};

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    pub addr: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_cert: Option<String>,
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
static SBI_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Open SBI server
/// Port of nssf_sbi_open
pub fn nssf_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    let config = config.unwrap_or_default();

    log::info!(
        "Opening NSSF SBI server on {}:{}",
        config.addr,
        config.port
    );

    // Note: Initialize SELF NF instance
    // In C: ogs_sbi_nf_instance_build_default(nf_instance)
    // - Add allowed NF types: SCP, AMF, NSSF
    // - Build NF service for nnssf-nsselection (v2)

    // Note: Initialize NRF NF Instance if configured
    // In C: ogs_sbi_nf_fsm_init(nf_instance)

    // Note: Setup subscription data
    // In C: ogs_sbi_subscription_spec_add(OpenAPI_nf_type_SEPP, NULL)

    // Note: Start SBI server - handled by main.rs HTTP server startup

    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    log::info!("NSSF SBI server opened successfully");
    Ok(())
}

/// Close SBI server
/// Port of nssf_sbi_close
pub fn nssf_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    log::info!("Closing NSSF SBI server");

    // Note: Stop SBI client - handled by HTTP client shutdown
    // In C: ogs_sbi_client_stop_all()

    // Note: Stop SBI server - handled by main.rs HTTP server shutdown
    // In C: ogs_sbi_server_stop_all()

    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::info!("NSSF SBI server closed");
}

/// Check if SBI server is running
pub fn nssf_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}


/// SBI request builder function type
pub type PathSbiRequestBuilder = fn(home_id: u64, data: &dyn std::any::Any) -> Option<PathSbiRequest>;

/// Simplified SBI request for path operations
#[derive(Debug, Clone)]
pub struct PathSbiRequest {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// SBI transaction for tracking requests
#[derive(Debug)]
pub struct SbiXact {
    pub id: u64,
    pub home_id: u64,
    pub stream_id: u64,
    pub service_type: String,
}

/// Send SBI request to NF instance
/// Port of nssf_sbi_send_request
pub fn nssf_sbi_send_request(nf_instance_id: &str, request: PathSbiRequest) -> Result<u64, String> {
    log::debug!(
        "Sending SBI request to NF instance [{}]: {} {}",
        nf_instance_id,
        request.method,
        request.uri
    );

    // Note: SBI request sending requires HTTP client integration
    // In C: ogs_sbi_send_request_to_nf_instance(nf_instance, xact)

    // Return transaction ID (placeholder)
    Ok(1)
}

/// Discover NF and send request
/// Port of nssf_sbi_discover_and_send
pub fn nssf_sbi_discover_and_send(
    service_type: &str,
    home_id: u64,
    stream_id: u64,
    _request: PathSbiRequest,
) -> Result<u64, String> {
    log::debug!(
        "Discover and send: service_type={}, home_id={}, stream_id={}",
        service_type,
        home_id,
        stream_id
    );

    // Note: SBI transaction tracking and NF discovery require NRF integration
    // In C: ogs_sbi_xact_add(...) creates a transaction
    // In C: ogs_sbi_discover_and_send(xact) discovers and sends to target NF

    // Return transaction ID (placeholder)
    Ok(1)
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
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        let result = nssf_sbi_open(None);
        assert!(result.is_ok());
        assert!(nssf_sbi_is_running());

        nssf_sbi_close();
        assert!(!nssf_sbi_is_running());
    }

    #[test]
    fn test_sbi_open_already_running() {
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        let _ = nssf_sbi_open(None);
        let result = nssf_sbi_open(None);
        assert!(result.is_err());

        nssf_sbi_close();
    }

    #[test]
    fn test_sbi_request() {
        let request = PathSbiRequest {
            method: "GET".to_string(),
            uri: "/nnssf-nsselection/v2/network-slice-information".to_string(),
            headers: vec![],
            body: None,
        };
        assert_eq!(request.method, "GET");
    }
}
