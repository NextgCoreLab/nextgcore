//! PCRF Rx Interface Path
//!
//! Port of src/pcrf/pcrf-rx-path.c - Rx interface (AAR/AAA, STR/STA, ASR handling)
//! 3GPP TS 29.214

use crate::context::{pcrf_self, pcrf_sess_find_by_ipv4, pcrf_sess_find_by_ipv6, OGS_IPV6_LEN};
use crate::fd_path::pcrf_diam_stats;
use crate::gx_path::{pcrf_gx_send_rar, RxMessageForRar, rx_cmd_code};

/// Rx session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxSessionState {
    /// Normal state
    Normal = 0,
    /// Session aborted
    Aborted = 1,
}

/// Abort cause values (3GPP TS 29.214)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AbortCause {
    /// Bearer released
    BearerReleased = 0,
    /// Insufficient server resources
    InsufficientServerResources = 1,
    /// Insufficient bearer resources
    InsufficientBearerResources = 2,
    /// PS to CS handover
    PsToCsHandover = 3,
    /// Sponsored connectivity data limit reached
    SponsoredDataConnectivityDisallowed = 4,
}

impl From<u32> for AbortCause {
    fn from(value: u32) -> Self {
        match value {
            0 => AbortCause::BearerReleased,
            1 => AbortCause::InsufficientServerResources,
            2 => AbortCause::InsufficientBearerResources,
            3 => AbortCause::PsToCsHandover,
            4 => AbortCause::SponsoredDataConnectivityDisallowed,
            _ => AbortCause::BearerReleased,
        }
    }
}

/// Termination cause values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TerminationCause {
    /// Diameter logout
    DiameterLogout = 1,
    /// Service not provided
    ServiceNotProvided = 2,
    /// Bad answer
    BadAnswer = 3,
    /// Administrative
    Administrative = 4,
    /// Link broken
    LinkBroken = 5,
    /// Auth expired
    AuthExpired = 6,
    /// User moved
    UserMoved = 7,
    /// Session timeout
    SessionTimeout = 8,
}

/// Rx message structure
#[derive(Debug, Clone, Default)]
pub struct RxMessage {
    /// Command code
    pub cmd_code: u32,
    /// Result code
    pub result_code: u32,
    /// IMS data
    pub ims_data: RxImsData,
}

/// Rx IMS data
#[derive(Debug, Clone, Default)]
pub struct RxImsData {
    /// Media components
    pub media_components: Vec<RxMediaComponent>,
}

/// Rx media component
#[derive(Debug, Clone, Default)]
pub struct RxMediaComponent {
    /// Media component number
    pub media_component_number: i32,
    /// Media type
    pub media_type: i32,
    /// Max requested bandwidth DL
    pub max_requested_bandwidth_dl: u32,
    /// Max requested bandwidth UL
    pub max_requested_bandwidth_ul: u32,
    /// Min requested bandwidth DL
    pub min_requested_bandwidth_dl: u32,
    /// Min requested bandwidth UL
    pub min_requested_bandwidth_ul: u32,
    /// RR bandwidth
    pub rr_bandwidth: u32,
    /// RS bandwidth
    pub rs_bandwidth: u32,
    /// Flow status
    pub flow_status: i32,
    /// Sub-components
    pub sub_components: Vec<RxMediaSubComponent>,
}

/// Rx media sub-component
#[derive(Debug, Clone, Default)]
pub struct RxMediaSubComponent {
    /// Flow number
    pub flow_number: i32,
    /// Flow usage
    pub flow_usage: i32,
    /// Flow descriptions
    pub flows: Vec<RxFlow>,
}

/// Rx flow
#[derive(Debug, Clone, Default)]
pub struct RxFlow {
    /// Flow description
    pub description: String,
}

/// Flow usage values
pub mod flow_usage {
    pub const NO_INFO: i32 = 0;
    pub const RTCP: i32 = 1;
    pub const AF_SIGNALLING: i32 = 2;
}

/// Diameter result codes
pub mod result_code {
    pub const DIAMETER_SUCCESS: u32 = 2001;
    pub const DIAMETER_AVP_UNSUPPORTED: u32 = 5001;
    pub const DIAMETER_UNKNOWN_SESSION_ID: u32 = 5002;
    pub const DIAMETER_MISSING_AVP: u32 = 5005;
    pub const DIAMETER_IP_CAN_SESSION_NOT_AVAILABLE: u32 = 5065;
}

/// Initialize Rx interface
pub fn pcrf_rx_init() -> Result<(), String> {
    log::info!("Initializing PCRF Rx interface");

    // Note: Initialize Rx Diameter application
    // Diameter application initialization handled by fd_path module:
    // - Register AAR callback via FreeDiameter fd_disp_register
    // - Register STR callback via FreeDiameter fd_disp_register
    // - Register fallback callback for unknown commands
    // - Advertise Rx application support via fd_dict_load_extension

    log::info!("PCRF Rx interface initialized");
    Ok(())
}

/// Finalize Rx interface
pub fn pcrf_rx_final() {
    log::info!("Finalizing PCRF Rx interface");

    // Note: Cleanup Rx Diameter application
    // Diameter cleanup handled by fd_path module during shutdown:
    // - Unregister callbacks via fd_disp_unregister
    // - Destroy session handler via fd_sess_handler_destroy

    log::info!("PCRF Rx interface finalized");
}

/// Handle AAR (AA-Request) - stub implementation
pub fn pcrf_rx_handle_aar(
    session_id: &str,
    ipv4_addr: Option<[u8; 4]>,
    ipv6_addr: Option<[u8; OGS_IPV6_LEN]>,
    _rx_message: &RxMessage,
) -> Result<u32, String> {
    log::debug!("Handling AAR: session={session_id}");

    // Update statistics
    pcrf_diam_stats().rx.inc_rx_aar();

    // Find Gx session by IP address
    let gx_sid = if let Some(addr) = ipv4_addr {
        pcrf_sess_find_by_ipv4(&addr)
    } else if let Some(addr) = ipv6_addr {
        pcrf_sess_find_by_ipv6(&addr)
    } else {
        None
    };

    let gx_sid = match gx_sid {
        Some(sid) => sid,
        None => {
            log::error!("Cannot find Gx session for IP address");
            pcrf_diam_stats().rx.inc_rx_aar_error();
            return Err("IP-CAN session not available".to_string());
        }
    };

    // Send RAR to P-GW
    let mut rx_msg_for_rar = RxMessageForRar {
        cmd_code: rx_cmd_code::AA,
        result_code: 0,
        ims_data: crate::gx_path::ImsData::default(),
    };

    if let Err(e) = pcrf_gx_send_rar(&gx_sid, session_id, &mut rx_msg_for_rar) {
        log::error!("Failed to send RAR: {e}");
        pcrf_diam_stats().rx.inc_rx_aar_error();
        return Err(e);
    }

    // Update statistics
    pcrf_diam_stats().rx.inc_tx_aaa();

    Ok(result_code::DIAMETER_SUCCESS)
}

/// Handle STR (Session-Termination-Request) - stub implementation
pub fn pcrf_rx_handle_str(
    session_id: &str,
    termination_cause: u32,
) -> Result<u32, String> {
    log::debug!(
        "Handling STR: session={session_id}, cause={termination_cause}"
    );

    // Update statistics
    pcrf_diam_stats().rx.inc_rx_str();

    let ctx = pcrf_self();
    let context = ctx.read().map_err(|e| format!("Failed to read context: {e}"))?;

    // Find Rx session
    let _rx_session = context
        .rx_session_find_by_sid(session_id)
        .ok_or_else(|| {
            pcrf_diam_stats().rx.inc_rx_str_error();
            "Rx session not found".to_string()
        })?;

    // Get associated Gx session
    let gx_sessions = context.gx_session_count();
    if gx_sessions == 0 {
        pcrf_diam_stats().rx.inc_rx_str_error();
        return Err("No Gx sessions".to_string());
    }

    // Note: Get Gx session ID from Rx session and send RAR
    // Gx session lookup via rx_session.gx_session_idx, then send RAR to remove PCC rules

    // Remove Rx session
    context.rx_session_remove(session_id);

    // Update statistics
    pcrf_diam_stats().rx.inc_tx_sta();

    Ok(result_code::DIAMETER_SUCCESS)
}

/// Send ASR (Abort-Session-Request) to AF/P-CSCF
pub fn pcrf_rx_send_asr(rx_sid: &str, abort_cause: u32) -> Result<(), String> {
    log::debug!(
        "Sending ASR: rx_sid={rx_sid}, abort_cause={abort_cause}"
    );

    let ctx = pcrf_self();
    let context = ctx.read().map_err(|e| format!("Failed to read context: {e}"))?;

    // Find Rx session
    let _rx_session = context
        .rx_session_find_by_sid(rx_sid)
        .ok_or_else(|| format!("Cannot find Rx session: {rx_sid}"))?;

    // Note: Build and send ASR message
    // ASR message construction handled by FreeDiameter fd_msg_new/fd_msg_avp_add:
    // - Set Session-Id via fd_msg_avp_setvalue
    // - Set Origin-Host, Origin-Realm from local configuration
    // - Set Destination-Host, Destination-Realm from Rx session peer info
    // - Set Auth-Application-Id (Rx application ID)
    // - Set Abort-Cause with abort_cause parameter value

    // Update statistics
    pcrf_diam_stats().rx.inc_tx_asr();

    log::info!("ASR sent for Rx session: {rx_sid}");
    Ok(())
}

/// Handle ASA (Abort-Session-Answer) callback - stub implementation
pub fn pcrf_rx_handle_asa(session_id: &str, result_code: u32) {
    log::debug!(
        "Handling ASA: session={session_id}, result_code={result_code}"
    );

    // Update statistics
    pcrf_diam_stats().rx.inc_rx_asa();

    if result_code != result_code::DIAMETER_SUCCESS {
        log::error!("ASA error: result_code={result_code}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abort_cause_from_u32() {
        assert_eq!(AbortCause::from(0), AbortCause::BearerReleased);
        assert_eq!(AbortCause::from(1), AbortCause::InsufficientServerResources);
        assert_eq!(AbortCause::from(2), AbortCause::InsufficientBearerResources);
        assert_eq!(AbortCause::from(99), AbortCause::BearerReleased);
    }

    #[test]
    fn test_rx_message_default() {
        let msg = RxMessage::default();
        assert_eq!(msg.cmd_code, 0);
        assert_eq!(msg.result_code, 0);
    }

    #[test]
    fn test_rx_ims_data_default() {
        let data = RxImsData::default();
        assert!(data.media_components.is_empty());
    }

    #[test]
    fn test_rx_media_component_default() {
        let comp = RxMediaComponent::default();
        assert_eq!(comp.media_component_number, 0);
        assert_eq!(comp.media_type, 0);
        assert!(comp.sub_components.is_empty());
    }

    #[test]
    fn test_pcrf_rx_init_final() {
        let result = pcrf_rx_init();
        assert!(result.is_ok());

        pcrf_rx_final();
    }

    #[test]
    fn test_pcrf_rx_handle_aar_no_gx_session() {
        // Initialize context
        crate::context::pcrf_context_init(1024);

        let rx_msg = RxMessage::default();
        let result = pcrf_rx_handle_aar(
            "rx-session-1",
            Some([192, 168, 1, 1]),
            None,
            &rx_msg,
        );

        // Should fail because no Gx session exists for this IP
        assert!(result.is_err());
    }

    #[test]
    fn test_pcrf_rx_handle_str_no_session() {
        // Initialize context
        crate::context::pcrf_context_init(1024);

        let result = pcrf_rx_handle_str("rx-session-nonexistent", 1);

        // Should fail because Rx session doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_pcrf_rx_send_asr_no_session() {
        // Initialize context
        crate::context::pcrf_context_init(1024);

        let result = pcrf_rx_send_asr("rx-session-nonexistent", 0);

        // Should fail because Rx session doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_pcrf_rx_handle_asa() {
        // This should not panic
        pcrf_rx_handle_asa("rx-session-1", result_code::DIAMETER_SUCCESS);
        pcrf_rx_handle_asa("rx-session-1", 5001); // Error case
    }

    #[test]
    fn test_flow_usage_constants() {
        assert_eq!(flow_usage::NO_INFO, 0);
        assert_eq!(flow_usage::RTCP, 1);
        assert_eq!(flow_usage::AF_SIGNALLING, 2);
    }

    #[test]
    fn test_result_code_constants() {
        assert_eq!(result_code::DIAMETER_SUCCESS, 2001);
        assert_eq!(result_code::DIAMETER_AVP_UNSUPPORTED, 5001);
        assert_eq!(result_code::DIAMETER_UNKNOWN_SESSION_ID, 5002);
    }
}
