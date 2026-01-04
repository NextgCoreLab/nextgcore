//! BSF SBI Path Functions
//!
//! Port of src/bsf/sbi-path.c - SBI server/client path functions

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
            port: 7779,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// SBI server state
static SBI_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Open SBI server
/// Port of bsf_sbi_open
pub fn bsf_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    let config = config.unwrap_or_default();

    log::info!(
        "Opening BSF SBI server on {}:{}",
        config.addr,
        config.port
    );

    // TODO: Initialize SELF NF instance
    // In C: ogs_sbi_nf_instance_build_default(nf_instance)
    // - Add allowed NF types: SCP, PCF, AF
    // - Build NF service for nbsf-management (v1)

    // TODO: Initialize NRF NF Instance if configured
    // In C: ogs_sbi_nf_fsm_init(nf_instance)

    // TODO: Setup subscription data
    // In C: ogs_sbi_subscription_spec_add(OpenAPI_nf_type_SEPP, NULL)

    // TODO: Start SBI server
    // In C: ogs_sbi_server_start_all(ogs_sbi_server_handler)

    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    log::info!("BSF SBI server opened successfully");
    Ok(())
}

/// Close SBI server
/// Port of bsf_sbi_close
pub fn bsf_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    log::info!("Closing BSF SBI server");

    // TODO: Stop SBI client
    // In C: ogs_sbi_client_stop_all()

    // TODO: Stop SBI server
    // In C: ogs_sbi_server_stop_all()

    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::info!("BSF SBI server closed");
}

/// Check if SBI server is running
pub fn bsf_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}


/// SBI request builder function type
pub type SbiRequestBuilder = fn(sess_id: u64, data: &dyn std::any::Any) -> Option<SbiRequest>;

/// Simplified SBI request
#[derive(Debug, Clone)]
pub struct SbiRequest {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// SBI transaction for tracking requests
#[derive(Debug)]
pub struct SbiXact {
    pub id: u64,
    pub sess_id: u64,
    pub stream_id: u64,
    pub service_type: String,
}

/// Send SBI request to NF instance
/// Port of bsf_sbi_send_request
pub fn bsf_sbi_send_request(nf_instance_id: &str, request: SbiRequest) -> Result<u64, String> {
    log::debug!(
        "Sending SBI request to NF instance [{}]: {} {}",
        nf_instance_id,
        request.method,
        request.uri
    );

    // TODO: Implement actual SBI request sending
    // In C: ogs_sbi_send_request_to_nf_instance(nf_instance, xact)

    // Return transaction ID (placeholder)
    Ok(1)
}

/// Discover NF and send request
/// Port of bsf_sbi_discover_and_send
pub fn bsf_sbi_discover_and_send(
    service_type: &str,
    sess_id: u64,
    stream_id: u64,
    _request: SbiRequest,
) -> Result<u64, String> {
    log::debug!(
        "Discover and send: service_type={}, sess_id={}, stream_id={}",
        service_type,
        sess_id,
        stream_id
    );

    // TODO: Create SBI transaction
    // In C: ogs_sbi_xact_add(...)

    // TODO: Discover NF instance
    // In C: ogs_sbi_discover_and_send(xact)

    // Return transaction ID (placeholder)
    Ok(1)
}

/// Send SBI response
/// Port of bsf_sbi_send_response
pub fn bsf_sbi_send_response(stream_id: u64, status: u16) -> Result<(), String> {
    log::debug!("Sending SBI response: stream_id={}, status={}", stream_id, status);

    // TODO: Build and send response
    // In C: ogs_sbi_build_response(&sendmsg, status)
    // In C: ogs_sbi_server_send_response(stream, response)

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbi_server_config_default() {
        let config = SbiServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 7779);
        assert!(!config.tls_enabled);
    }

    #[test]
    fn test_sbi_open_close() {
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        let result = bsf_sbi_open(None);
        assert!(result.is_ok());
        assert!(bsf_sbi_is_running());

        bsf_sbi_close();
        assert!(!bsf_sbi_is_running());
    }

    #[test]
    fn test_sbi_open_already_running() {
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        let _ = bsf_sbi_open(None);
        let result = bsf_sbi_open(None);
        assert!(result.is_err());

        bsf_sbi_close();
    }

    #[test]
    fn test_sbi_request() {
        let request = SbiRequest {
            method: "POST".to_string(),
            uri: "/nbsf-management/v1/pcf-bindings".to_string(),
            headers: vec![],
            body: None,
        };
        assert_eq!(request.method, "POST");
    }

    #[test]
    fn test_sbi_send_response() {
        let result = bsf_sbi_send_response(1, 200);
        assert!(result.is_ok());
    }
}
