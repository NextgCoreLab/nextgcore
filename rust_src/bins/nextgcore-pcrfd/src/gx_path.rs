//! PCRF Gx Interface Path
//!
//! Port of src/pcrf/pcrf-gx-path.c - Gx interface (CCR/CCA handling, RAR sending)
//! 3GPP TS 29.212 section 4

use crate::context::{pcrf_self, pcrf_sess_set_ipv4, pcrf_sess_set_ipv6, OGS_IPV6_LEN};
use crate::fd_path::pcrf_diam_stats;

/// CC-Request-Type values (3GPP TS 29.212)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CcRequestType {
    /// Initial request
    Initial = 1,
    /// Update request
    Update = 2,
    /// Termination request
    Termination = 3,
    /// Event request
    Event = 4,
}

impl From<u32> for CcRequestType {
    fn from(value: u32) -> Self {
        match value {
            1 => CcRequestType::Initial,
            2 => CcRequestType::Update,
            3 => CcRequestType::Termination,
            4 => CcRequestType::Event,
            _ => CcRequestType::Initial,
        }
    }
}

/// Gx message structure
#[derive(Debug, Clone, Default)]
pub struct GxMessage {
    /// CC-Request-Type
    pub cc_request_type: u32,
    /// CC-Request-Number
    pub cc_request_number: u32,
    /// Result code
    pub result_code: u32,
    /// Session data
    pub session_data: GxSessionData,
}

/// Gx session data
#[derive(Debug, Clone, Default)]
pub struct GxSessionData {
    /// AMBR downlink (bps)
    pub ambr_downlink: u64,
    /// AMBR uplink (bps)
    pub ambr_uplink: u64,
    /// QoS class identifier
    pub qos_index: u8,
    /// ARP priority level
    pub arp_priority_level: u8,
    /// ARP pre-emption capability
    pub arp_pre_emption_capability: bool,
    /// ARP pre-emption vulnerability
    pub arp_pre_emption_vulnerability: bool,
    /// PCC rules
    pub pcc_rules: Vec<PccRuleData>,
}

/// PCC rule data
#[derive(Debug, Clone, Default)]
pub struct PccRuleData {
    /// Rule name
    pub name: String,
    /// QoS index
    pub qos_index: u8,
    /// Flow status
    pub flow_status: i32,
    /// Precedence
    pub precedence: u32,
    /// MBR downlink
    pub mbr_downlink: u64,
    /// MBR uplink
    pub mbr_uplink: u64,
    /// GBR downlink
    pub gbr_downlink: u64,
    /// GBR uplink
    pub gbr_uplink: u64,
    /// Flow descriptions
    pub flows: Vec<FlowData>,
}

/// Flow data
#[derive(Debug, Clone, Default)]
pub struct FlowData {
    /// Flow direction
    pub direction: i32,
    /// Flow description
    pub description: String,
}

/// Rx message for RAR (from Rx interface)
#[derive(Debug, Clone, Default)]
pub struct RxMessageForRar {
    /// Command code
    pub cmd_code: u32,
    /// Result code
    pub result_code: u32,
    /// IMS data
    pub ims_data: ImsData,
}

/// IMS data from Rx interface
#[derive(Debug, Clone, Default)]
pub struct ImsData {
    /// Media components
    pub media_components: Vec<MediaComponent>,
}

/// Media component
#[derive(Debug, Clone, Default)]
pub struct MediaComponent {
    /// Media component number
    pub media_component_number: i32,
    /// Media type
    pub media_type: i32,
    /// Max requested bandwidth DL
    pub max_requested_bandwidth_dl: u32,
    /// Max requested bandwidth UL
    pub max_requested_bandwidth_ul: u32,
    /// Flow status
    pub flow_status: i32,
    /// Sub-components
    pub sub_components: Vec<MediaSubComponent>,
}

/// Media sub-component
#[derive(Debug, Clone, Default)]
pub struct MediaSubComponent {
    /// Flow number
    pub flow_number: i32,
    /// Flow usage
    pub flow_usage: i32,
    /// Flow descriptions
    pub flows: Vec<String>,
}

/// Media type values
pub mod media_type {
    pub const AUDIO: i32 = 0;
    pub const VIDEO: i32 = 1;
    pub const DATA: i32 = 2;
    pub const APPLICATION: i32 = 3;
    pub const CONTROL: i32 = 4;
    pub const TEXT: i32 = 5;
    pub const MESSAGE: i32 = 6;
    pub const OTHER: i32 = 0xFFFFFFFF_u32 as i32;
}

/// Rx command codes
pub mod rx_cmd_code {
    pub const AA: u32 = 265;
    pub const SESSION_TERMINATION: u32 = 275;
}

/// Initialize Gx interface
pub fn pcrf_gx_init() -> Result<(), String> {
    log::info!("Initializing PCRF Gx interface");

    // TODO: Initialize Gx Diameter application
    // - Register CCR callback
    // - Register fallback callback
    // - Advertise Gx application support

    log::info!("PCRF Gx interface initialized");
    Ok(())
}

/// Finalize Gx interface
pub fn pcrf_gx_final() {
    log::info!("Finalizing PCRF Gx interface");

    // TODO: Cleanup Gx Diameter application
    // - Unregister callbacks
    // - Destroy session handler

    log::info!("PCRF Gx interface finalized");
}

/// Handle CCR (Credit-Control-Request) - stub implementation
pub fn pcrf_gx_handle_ccr(
    session_id: &str,
    cc_request_type: CcRequestType,
    cc_request_number: u32,
    imsi: &str,
    apn: &str,
    ipv4_addr: Option<[u8; 4]>,
    ipv6_addr: Option<[u8; OGS_IPV6_LEN]>,
) -> Result<GxMessage, String> {
    log::debug!(
        "Handling CCR: session={}, type={:?}, number={}, imsi={}, apn={}",
        session_id,
        cc_request_type,
        cc_request_number,
        imsi,
        apn
    );

    // Update statistics
    pcrf_diam_stats().gx.inc_rx_ccr();

    let ctx = pcrf_self();
    let context = ctx.read().map_err(|e| format!("Failed to read context: {}", e))?;

    match cc_request_type {
        CcRequestType::Initial => {
            // Create new Gx session
            if let Some(_idx) = context.gx_session_add(session_id) {
                // Update session with subscriber info
                context.gx_session_update(session_id, |session| {
                    session.set_imsi(imsi);
                    session.set_apn(apn);
                    if let Some(addr) = ipv4_addr {
                        session.set_ipv4(std::net::Ipv4Addr::from(addr));
                    }
                    if let Some(addr) = ipv6_addr {
                        session.set_ipv6(addr);
                    }
                });

                // Set IP mappings
                if let Some(addr) = ipv4_addr {
                    pcrf_sess_set_ipv4(&addr, Some(session_id));
                }
                if let Some(addr) = ipv6_addr {
                    pcrf_sess_set_ipv6(&addr, Some(session_id));
                }
            }
        }
        CcRequestType::Update => {
            // Update existing session
            if context.gx_session_find_by_sid(session_id).is_none() {
                pcrf_diam_stats().gx.inc_rx_ccr_error();
                return Err("Unknown session ID".to_string());
            }
        }
        CcRequestType::Termination => {
            // Remove session
            if let Some(session) = context.gx_session_find_by_sid(session_id) {
                // Clear IP mappings
                if let Some(addr) = session.ipv4_addr {
                    let bytes: [u8; 4] = addr.octets();
                    pcrf_sess_set_ipv4(&bytes, None);
                }
                if let Some(addr) = session.ipv6_addr {
                    pcrf_sess_set_ipv6(&addr, None);
                }
            }
            context.gx_session_remove(session_id);
        }
        CcRequestType::Event => {
            // Handle event request
            log::debug!("Event request received");
        }
    }

    // Update statistics
    pcrf_diam_stats().gx.inc_tx_cca();

    Ok(GxMessage {
        cc_request_type: cc_request_type as u32,
        cc_request_number,
        result_code: 2001, // DIAMETER_SUCCESS
        session_data: GxSessionData::default(),
    })
}

/// Send RAR (Re-Auth-Request) to P-GW
pub fn pcrf_gx_send_rar(
    gx_sid: &str,
    rx_sid: &str,
    rx_message: &mut RxMessageForRar,
) -> Result<(), String> {
    log::debug!(
        "Sending RAR: gx_sid={}, rx_sid={}, cmd_code={}",
        gx_sid,
        rx_sid,
        rx_message.cmd_code
    );

    let ctx = pcrf_self();
    let context = ctx.read().map_err(|e| format!("Failed to read context: {}", e))?;

    // Find Gx session
    let gx_session = context
        .gx_session_find_by_sid(gx_sid)
        .ok_or_else(|| "Gx session not found".to_string())?;

    // Validate session has required data
    if gx_session.peer_host.is_none() {
        pcrf_diam_stats().gx.inc_tx_rar_error();
        return Err("No peer host in session".to_string());
    }

    match rx_message.cmd_code {
        rx_cmd_code::AA => {
            // Handle AA-Request from Rx - install PCC rules
            log::debug!("Processing AA-Request for RAR");

            // Get Gx session index
            let gx_idx = context
                .gx_session_get_idx(gx_sid)
                .ok_or_else(|| "Gx session index not found".to_string())?;

            // Add Rx session if not exists
            if context.rx_session_find_by_sid(rx_sid).is_none() {
                context.rx_session_add(rx_sid, gx_idx);
            }

            // TODO: Build and send RAR with Charging-Rule-Install
        }
        rx_cmd_code::SESSION_TERMINATION => {
            // Handle STR from Rx - remove PCC rules
            log::debug!("Processing STR for RAR");

            // Remove Rx session
            context.rx_session_remove(rx_sid);

            // TODO: Build and send RAR with Charging-Rule-Remove
        }
        _ => {
            log::warn!("Unknown Rx command code: {}", rx_message.cmd_code);
        }
    }

    // Update statistics
    pcrf_diam_stats().gx.inc_tx_rar();

    // Set success result
    rx_message.result_code = 2001; // DIAMETER_SUCCESS

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cc_request_type_from_u32() {
        assert_eq!(CcRequestType::from(1), CcRequestType::Initial);
        assert_eq!(CcRequestType::from(2), CcRequestType::Update);
        assert_eq!(CcRequestType::from(3), CcRequestType::Termination);
        assert_eq!(CcRequestType::from(4), CcRequestType::Event);
        assert_eq!(CcRequestType::from(99), CcRequestType::Initial);
    }

    #[test]
    fn test_gx_message_default() {
        let msg = GxMessage::default();
        assert_eq!(msg.cc_request_type, 0);
        assert_eq!(msg.cc_request_number, 0);
        assert_eq!(msg.result_code, 0);
    }

    #[test]
    fn test_gx_session_data_default() {
        let data = GxSessionData::default();
        assert_eq!(data.ambr_downlink, 0);
        assert_eq!(data.ambr_uplink, 0);
        assert_eq!(data.qos_index, 0);
    }

    #[test]
    fn test_pcc_rule_data_default() {
        let rule = PccRuleData::default();
        assert!(rule.name.is_empty());
        assert_eq!(rule.qos_index, 0);
        assert!(rule.flows.is_empty());
    }

    #[test]
    fn test_rx_message_for_rar_default() {
        let msg = RxMessageForRar::default();
        assert_eq!(msg.cmd_code, 0);
        assert_eq!(msg.result_code, 0);
    }

    #[test]
    fn test_pcrf_gx_init_final() {
        let result = pcrf_gx_init();
        assert!(result.is_ok());

        pcrf_gx_final();
    }

    #[test]
    fn test_pcrf_gx_handle_ccr_initial() {
        // Initialize context
        crate::context::pcrf_context_init(1024);

        let result = pcrf_gx_handle_ccr(
            "gx-session-1",
            CcRequestType::Initial,
            0,
            "123456789012345",
            "internet",
            Some([192, 168, 1, 1]),
            None,
        );

        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.cc_request_type, CcRequestType::Initial as u32);
        assert_eq!(msg.result_code, 2001);
    }

    #[test]
    fn test_pcrf_gx_handle_ccr_termination() {
        // Initialize context
        crate::context::pcrf_context_init(1024);

        // First create a session
        let _ = pcrf_gx_handle_ccr(
            "gx-session-term",
            CcRequestType::Initial,
            0,
            "123456789012345",
            "internet",
            None,
            None,
        );

        // Then terminate it
        let result = pcrf_gx_handle_ccr(
            "gx-session-term",
            CcRequestType::Termination,
            1,
            "123456789012345",
            "internet",
            None,
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_pcrf_gx_send_rar() {
        // Initialize context
        crate::context::pcrf_context_init(1024);

        // Create a Gx session first
        let ctx = pcrf_self();
        if let Ok(context) = ctx.read() {
            context.gx_session_add("gx-session-rar");
            context.gx_session_update("gx-session-rar", |session| {
                session.set_peer_host("pgw.example.com");
            });
        }

        let mut rx_msg = RxMessageForRar {
            cmd_code: rx_cmd_code::AA,
            result_code: 0,
            ims_data: ImsData::default(),
        };

        let result = pcrf_gx_send_rar("gx-session-rar", "rx-session-1", &mut rx_msg);
        assert!(result.is_ok());
        assert_eq!(rx_msg.result_code, 2001);
    }
}
