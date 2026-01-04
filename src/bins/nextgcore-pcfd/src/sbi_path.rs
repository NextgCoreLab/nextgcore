//! PCF SBI Path Management
//!
//! Port of src/pcf/sbi-path.c - SBI server and client path handling

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
/// Port of pcf_sbi_open() from sbi-path.c
pub fn pcf_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    let config = config.unwrap_or_default();

    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    log::info!(
        "Opening PCF SBI server on {}:{}",
        config.addr,
        config.port
    );

    // In C implementation:
    // 1. Initialize SELF NF instance
    // 2. Build NF instance information for NRF
    // 3. Add allowed NF types (SCP, AMF, SMF, AF)
    // 4. Build NF service information:
    //    - npcf-am-policy-control (allowed: AMF)
    //    - npcf-smpolicycontrol (allowed: SMF)
    //    - npcf-policyauthorization (allowed: AF, PCF)
    // 5. Initialize NRF NF instance
    // 6. Setup subscription data for SEPP, NBSF, NUDR
    // 7. Start all SBI servers

    // Validate that smpolicycontrol and policyauthorization are enabled together
    // (or both disabled) - this is a PCF-specific requirement
    // In C: if one is enabled and other disabled, return OGS_ERROR

    // TODO: Implement actual HTTP/2 server using hyper
    // For now, just mark as running

    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    log::debug!("PCF SBI server opened successfully");
    Ok(())
}

/// Close SBI server
/// Port of pcf_sbi_close() from sbi-path.c
pub fn pcf_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        log::warn!("SBI server not running");
        return;
    }

    log::info!("Closing PCF SBI server");

    // In C implementation:
    // 1. Stop all SBI clients
    // 2. Stop all SBI servers

    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::debug!("PCF SBI server closed");
}

/// Check if SBI server is running
pub fn pcf_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}

/// Send AM policy control notify to AMF
/// Port of pcf_sbi_send_am_policy_control_notify() from sbi-path.c
pub fn pcf_sbi_send_am_policy_control_notify(pcf_ue_am_id: u64) -> bool {
    log::debug!(
        "[ue_am_id={}] Sending AM policy control notify",
        pcf_ue_am_id
    );

    // In C implementation:
    // 1. Get pcf_ue_am from ID
    // 2. Get client from pcf_ue_am->namf
    // 3. Build request using pcf_namf_callback_build_am_policy_control()
    // 4. Send request to client with client_notify_cb callback

    // TODO: Implement actual notification sending
    true
}

/// Send SM policy control create response
/// Port of pcf_sbi_send_smpolicycontrol_create_response() from sbi-path.c
pub fn pcf_sbi_send_smpolicycontrol_create_response(
    sess_id: u64,
    stream_id: u64,
) -> bool {
    log::debug!(
        "[sess_id={}, stream_id={}] Sending SM policy control create response",
        sess_id,
        stream_id
    );

    // In C implementation:
    // 1. Get session and UE SM from IDs
    // 2. Get session data from database
    // 3. Build SmPolicyDecision with:
    //    - Session rules (auth_sess_ambr, auth_def_qos)
    //    - PCC rules
    //    - QoS decisions
    //    - Policy control request triggers
    //    - Supported features
    // 4. Build response with location header
    // 5. Send response to stream

    // TODO: Implement actual response building and sending
    true
}

/// Send SM policy control update notify to SMF
/// Port of pcf_sbi_send_smpolicycontrol_update_notify() from sbi-path.c
pub fn pcf_sbi_send_smpolicycontrol_update_notify(sess_id: u64) -> bool {
    log::debug!(
        "[sess_id={}] Sending SM policy control update notify",
        sess_id
    );

    // In C implementation:
    // 1. Get session from ID
    // 2. Get client from sess->nsmf
    // 3. Build request using pcf_nsmf_callback_build_smpolicycontrol_update()
    // 4. Send request to client with client_notify_cb callback

    // TODO: Implement actual notification sending
    true
}

/// Send SM policy control delete notify to SMF
/// Port of pcf_sbi_send_smpolicycontrol_delete_notify() from sbi-path.c
pub fn pcf_sbi_send_smpolicycontrol_delete_notify(
    sess_id: u64,
    app_session_id: u64,
) -> bool {
    log::debug!(
        "[sess_id={}, app_id={}] Sending SM policy control delete notify",
        sess_id,
        app_session_id
    );

    // In C implementation:
    // 1. Get session from ID
    // 2. Get client from sess->nsmf
    // 3. Build request using pcf_nsmf_callback_build_smpolicycontrol_update()
    // 4. Send request to client with client_delete_notify_cb callback
    //    (which removes app_session after callback)

    // TODO: Implement actual notification sending
    true
}

/// Send policy authorization terminate notify to AF
/// Port of pcf_sbi_send_policyauthorization_terminate_notify() from sbi-path.c
pub fn pcf_sbi_send_policyauthorization_terminate_notify(app_id: u64) -> bool {
    log::debug!(
        "[app_id={}] Sending policy authorization terminate notify",
        app_id
    );

    // In C implementation:
    // 1. Get app session from ID
    // 2. Get client from app->naf
    // 3. Build request using pcf_naf_callback_build_policyauthorization_terminate()
    // 4. Send request to client with client_notify_cb callback

    // TODO: Implement actual notification sending
    true
}

/// Discover and send request to UDR for UE AM
/// Port of pcf_ue_am_sbi_discover_and_send() from sbi-path.c
pub fn pcf_ue_am_sbi_discover_and_send(
    pcf_ue_am_id: u64,
    stream_id: u64,
    service_type: &str,
) -> Result<(), String> {
    log::debug!(
        "[ue_am_id={}, stream_id={}] Discover and send to {}",
        pcf_ue_am_id,
        stream_id,
        service_type
    );

    // In C implementation:
    // 1. Create SBI transaction
    // 2. Set associated stream ID
    // 3. Call ogs_sbi_discover_and_send()

    // TODO: Implement actual discovery and sending
    Ok(())
}

/// Discover and send request for session
/// Port of pcf_sess_sbi_discover_and_send() from sbi-path.c
pub fn pcf_sess_sbi_discover_and_send(
    sess_id: u64,
    stream_id: u64,
    service_type: &str,
) -> Result<(), String> {
    log::debug!(
        "[sess_id={}, stream_id={}] Discover and send to {}",
        sess_id,
        stream_id,
        service_type
    );

    // In C implementation:
    // 1. Create SBI transaction
    // 2. Set associated stream ID
    // 3. Call ogs_sbi_discover_and_send()

    // TODO: Implement actual discovery and sending
    Ok(())
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

        assert!(!pcf_sbi_is_running());

        let result = pcf_sbi_open(None);
        assert!(result.is_ok());
        assert!(pcf_sbi_is_running());

        // Try to open again - should fail
        let result = pcf_sbi_open(None);
        assert!(result.is_err());

        pcf_sbi_close();
        assert!(!pcf_sbi_is_running());
    }

    #[test]
    fn test_sbi_open_with_config() {
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        let config = SbiServerConfig {
            addr: "0.0.0.0".to_string(),
            port: 8080,
            tls_enabled: true,
            tls_cert: Some("/path/to/cert.pem".to_string()),
            tls_key: Some("/path/to/key.pem".to_string()),
        };

        let result = pcf_sbi_open(Some(config));
        assert!(result.is_ok());

        pcf_sbi_close();
    }
}
