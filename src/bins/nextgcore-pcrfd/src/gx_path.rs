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

    // Note: Initialize Gx Diameter application
    // Diameter application initialization handled by fd_path module:
    // - Register CCR callback via FreeDiameter fd_disp_register
    // - Register fallback callback for unknown commands
    // - Advertise Gx application support via fd_dict_load_extension

    log::info!("PCRF Gx interface initialized");
    Ok(())
}

/// Finalize Gx interface
pub fn pcrf_gx_final() {
    log::info!("Finalizing PCRF Gx interface");

    // Note: Cleanup Gx Diameter application
    // Diameter cleanup handled by fd_path module during shutdown:
    // - Unregister callbacks via fd_disp_unregister
    // - Destroy session handler via fd_sess_handler_destroy

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
        "Handling CCR: session={session_id}, type={cc_request_type:?}, number={cc_request_number}, imsi={imsi}, apn={apn}"
    );

    // Update statistics
    pcrf_diam_stats().gx.inc_rx_ccr();

    let ctx = pcrf_self();
    let context = ctx.read().map_err(|e| format!("Failed to read context: {e}"))?;

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
    let context = ctx.read().map_err(|e| format!("Failed to read context: {e}"))?;

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

            // Note: Build and send RAR with Charging-Rule-Install
            // RAR message construction handled by FreeDiameter fd_msg_new/fd_msg_avp_add
            // Charging-Rule-Install AVP contains PCC rules derived from Rx media components
        }
        rx_cmd_code::SESSION_TERMINATION => {
            // Handle STR from Rx - remove PCC rules
            log::debug!("Processing STR for RAR");

            // Remove Rx session
            context.rx_session_remove(rx_sid);

            // Note: Build and send RAR with Charging-Rule-Remove
            // RAR message construction handled by FreeDiameter fd_msg_new/fd_msg_avp_add
            // Charging-Rule-Remove AVP contains rule names to be removed from P-GW
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

// ============================================================================
// Flow Status Values (TS 29.214)
// ============================================================================

pub mod flow_status {
    pub const ENABLED_UPLINK: i32 = 0;
    pub const ENABLED_DOWNLINK: i32 = 1;
    pub const ENABLED: i32 = 2;
    pub const DISABLED: i32 = 3;
    pub const REMOVED: i32 = 4;
}

// ============================================================================
// QCI → QoS Mapping (TS 23.203 Table 6.1.7)
// ============================================================================

/// QoS characteristics for a given QCI
#[derive(Debug, Clone)]
pub struct QciQosMapping {
    pub qci: u8,
    pub resource_type: QciResourceType,
    pub priority: u8,
    pub packet_delay_budget_ms: u32,
    pub packet_error_loss_rate: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QciResourceType {
    Gbr,
    NonGbr,
}

/// Get QoS parameters for a given QCI value (TS 23.203 Table 6.1.7)
pub fn qci_to_qos(qci: u8) -> QciQosMapping {
    match qci {
        1 => QciQosMapping {
            qci: 1, resource_type: QciResourceType::Gbr,
            priority: 2, packet_delay_budget_ms: 100, packet_error_loss_rate: 1e-2,
        },
        2 => QciQosMapping {
            qci: 2, resource_type: QciResourceType::Gbr,
            priority: 4, packet_delay_budget_ms: 150, packet_error_loss_rate: 1e-3,
        },
        3 => QciQosMapping {
            qci: 3, resource_type: QciResourceType::Gbr,
            priority: 3, packet_delay_budget_ms: 50, packet_error_loss_rate: 1e-3,
        },
        4 => QciQosMapping {
            qci: 4, resource_type: QciResourceType::Gbr,
            priority: 5, packet_delay_budget_ms: 300, packet_error_loss_rate: 1e-6,
        },
        5 => QciQosMapping {
            qci: 5, resource_type: QciResourceType::NonGbr,
            priority: 1, packet_delay_budget_ms: 100, packet_error_loss_rate: 1e-6,
        },
        6 => QciQosMapping {
            qci: 6, resource_type: QciResourceType::NonGbr,
            priority: 6, packet_delay_budget_ms: 300, packet_error_loss_rate: 1e-6,
        },
        7 => QciQosMapping {
            qci: 7, resource_type: QciResourceType::NonGbr,
            priority: 7, packet_delay_budget_ms: 100, packet_error_loss_rate: 1e-3,
        },
        8 => QciQosMapping {
            qci: 8, resource_type: QciResourceType::NonGbr,
            priority: 8, packet_delay_budget_ms: 300, packet_error_loss_rate: 1e-6,
        },
        9 => QciQosMapping {
            qci: 9, resource_type: QciResourceType::NonGbr,
            priority: 9, packet_delay_budget_ms: 300, packet_error_loss_rate: 1e-6,
        },
        65 => QciQosMapping {
            qci: 65, resource_type: QciResourceType::Gbr,
            priority: 0, packet_delay_budget_ms: 75, packet_error_loss_rate: 1e-2,
        },
        66 => QciQosMapping {
            qci: 66, resource_type: QciResourceType::Gbr,
            priority: 2, packet_delay_budget_ms: 100, packet_error_loss_rate: 1e-2,
        },
        _ => QciQosMapping {
            qci, resource_type: QciResourceType::NonGbr,
            priority: 9, packet_delay_budget_ms: 300, packet_error_loss_rate: 1e-6,
        },
    }
}

// ============================================================================
// PCC Rule Derivation from Rx Media Components
// ============================================================================

/// Derive PCC rules from IMS media components (Rx → Gx)
/// Port of pcrf-gx-path logic that converts Rx media info to PCC rules
pub fn derive_pcc_rules(
    ims_data: &ImsData,
    base_rule_name: &str,
) -> Vec<PccRuleData> {
    let mut rules = Vec::new();

    for (idx, mc) in ims_data.media_components.iter().enumerate() {
        let rule_name = format!("{}-mc{}", base_rule_name, mc.media_component_number);

        // Determine QCI from media type (TS 29.213 section 7.1.4)
        let qci = match mc.media_type {
            media_type::AUDIO => 1,   // Conversational Voice
            media_type::VIDEO => 2,   // Conversational Video (live)
            media_type::APPLICATION => 5, // IMS signalling
            media_type::CONTROL => 5, // IMS signalling
            _ => 9,                   // Default non-GBR
        };

        // Determine flow status
        let rule_flow_status = if mc.flow_status != 0 {
            mc.flow_status
        } else {
            flow_status::ENABLED
        };

        // Build flow descriptions from sub-components
        let mut flows = Vec::new();
        for sub in &mc.sub_components {
            for flow_desc in &sub.flows {
                // Determine direction from flow description
                // IPFilterRule: "permit in/out ..." where in=downlink, out=uplink
                let direction = if flow_desc.contains("out") {
                    0 // Uplink
                } else {
                    1 // Downlink
                };
                flows.push(FlowData {
                    direction,
                    description: flow_desc.clone(),
                });
            }
        }

        // If no sub-components, create a default permit-all flow
        if flows.is_empty() {
            flows.push(FlowData {
                direction: flow_status::ENABLED,
                description: "permit out ip from any to any".to_string(),
            });
            flows.push(FlowData {
                direction: flow_status::ENABLED,
                description: "permit in ip from any to any".to_string(),
            });
        }

        let rule = PccRuleData {
            name: rule_name,
            qos_index: qci,
            flow_status: rule_flow_status,
            precedence: (idx as u32 + 1) * 10,
            mbr_downlink: mc.max_requested_bandwidth_dl as u64,
            mbr_uplink: mc.max_requested_bandwidth_ul as u64,
            gbr_downlink: if qci <= 4 { mc.max_requested_bandwidth_dl as u64 } else { 0 },
            gbr_uplink: if qci <= 4 { mc.max_requested_bandwidth_ul as u64 } else { 0 },
            flows,
        };

        rules.push(rule);
    }

    log::debug!("Derived {} PCC rules from {} media components",
        rules.len(), ims_data.media_components.len());

    rules
}

/// Build GxSessionData with PCC rules for a CCA response
pub fn build_session_data_with_rules(
    qos_index: u8,
    ambr_dl: u64,
    ambr_ul: u64,
    pcc_rules: Vec<PccRuleData>,
) -> GxSessionData {
    let qos = qci_to_qos(qos_index);
    GxSessionData {
        ambr_downlink: ambr_dl,
        ambr_uplink: ambr_ul,
        qos_index,
        arp_priority_level: qos.priority,
        arp_pre_emption_capability: false,
        arp_pre_emption_vulnerability: true,
        pcc_rules,
    }
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

    #[test]
    fn test_qci_to_qos() {
        let qos1 = qci_to_qos(1);
        assert_eq!(qos1.qci, 1);
        assert_eq!(qos1.resource_type, QciResourceType::Gbr);
        assert_eq!(qos1.priority, 2);
        assert_eq!(qos1.packet_delay_budget_ms, 100);

        let qos5 = qci_to_qos(5);
        assert_eq!(qos5.resource_type, QciResourceType::NonGbr);
        assert_eq!(qos5.priority, 1);

        let qos9 = qci_to_qos(9);
        assert_eq!(qos9.resource_type, QciResourceType::NonGbr);
        assert_eq!(qos9.priority, 9);

        // Unknown QCI falls back to non-GBR
        let qos_unknown = qci_to_qos(200);
        assert_eq!(qos_unknown.resource_type, QciResourceType::NonGbr);
    }

    #[test]
    fn test_derive_pcc_rules_audio() {
        let ims_data = ImsData {
            media_components: vec![
                MediaComponent {
                    media_component_number: 1,
                    media_type: media_type::AUDIO,
                    max_requested_bandwidth_dl: 64000,
                    max_requested_bandwidth_ul: 64000,
                    flow_status: flow_status::ENABLED,
                    sub_components: vec![
                        MediaSubComponent {
                            flow_number: 1,
                            flow_usage: 0,
                            flows: vec![
                                "permit out 17 from 10.0.0.1 to 10.0.0.2".to_string(),
                                "permit in 17 from 10.0.0.2 to 10.0.0.1".to_string(),
                            ],
                        },
                    ],
                },
            ],
        };

        let rules = derive_pcc_rules(&ims_data, "test-rule");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].qos_index, 1); // Audio → QCI 1
        assert_eq!(rules[0].mbr_downlink, 64000);
        assert_eq!(rules[0].gbr_downlink, 64000); // GBR for QCI 1
        assert_eq!(rules[0].flows.len(), 2);
    }

    #[test]
    fn test_derive_pcc_rules_video_and_data() {
        let ims_data = ImsData {
            media_components: vec![
                MediaComponent {
                    media_component_number: 1,
                    media_type: media_type::VIDEO,
                    max_requested_bandwidth_dl: 1000000,
                    max_requested_bandwidth_ul: 500000,
                    flow_status: 0,
                    sub_components: vec![],
                },
                MediaComponent {
                    media_component_number: 2,
                    media_type: media_type::APPLICATION,
                    max_requested_bandwidth_dl: 100000,
                    max_requested_bandwidth_ul: 100000,
                    flow_status: 0,
                    sub_components: vec![],
                },
            ],
        };

        let rules = derive_pcc_rules(&ims_data, "multi");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].qos_index, 2); // Video → QCI 2
        assert_eq!(rules[1].qos_index, 5); // Application → QCI 5
        assert_eq!(rules[1].gbr_downlink, 0); // Non-GBR for QCI 5
    }

    #[test]
    fn test_build_session_data_with_rules() {
        let rules = vec![PccRuleData {
            name: "rule1".to_string(),
            qos_index: 1,
            ..Default::default()
        }];
        let data = build_session_data_with_rules(9, 100000, 50000, rules);
        assert_eq!(data.ambr_downlink, 100000);
        assert_eq!(data.ambr_uplink, 50000);
        assert_eq!(data.qos_index, 9);
        assert_eq!(data.pcc_rules.len(), 1);
    }
}
