//! GSM (5G Session Management) Message Handling
//!
//! Port of src/smf/gsm-handler.c - GSM message handling functions for 5G NAS

use crate::context::{
    SmfSess, SmfBearer, SmfPf, FlowDirection, IpfwRule,
    MaxIntegrityProtectedDataRate,
};
use crate::gsm_build::GsmCause;
use std::net::Ipv4Addr;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of QoS rules in NAS
pub const OGS_NAS_MAX_NUM_OF_QOS_RULE: usize = 8;

/// Maximum number of packet filters per QoS rule
pub const OGS_MAX_NUM_OF_FLOW_IN_NAS: usize = 16;

/// Maximum number of QoS flow descriptions
pub const OGS_NAS_MAX_NUM_OF_QOS_FLOW_DESCRIPTION: usize = 8;

/// Integrity protection maximum data rate values
pub mod integrity_protection_rate {
    pub const NULL: u8 = 0;
    pub const RATE_64KBPS: u8 = 1;
    pub const FULL: u8 = 0xff;
}

/// QoS rule operation codes
pub mod qos_rule_code {
    pub const CREATE_NEW_QOS_RULE: u8 = 1;
    pub const DELETE_EXISTING_QOS_RULE: u8 = 2;
    pub const MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS: u8 = 3;
    pub const MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS: u8 = 4;
    pub const MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS: u8 = 5;
    pub const MODIFY_EXISTING_QOS_RULE_WITHOUT_MODIFYING_PACKET_FILTERS: u8 = 6;
}

/// QoS flow parameter identifiers
pub mod qos_flow_param_id {
    pub const FIVE_QI: u8 = 0x01;
    pub const GFBR_UPLINK: u8 = 0x02;
    pub const GFBR_DOWNLINK: u8 = 0x03;
    pub const MFBR_UPLINK: u8 = 0x04;
    pub const MFBR_DOWNLINK: u8 = 0x05;
}

/// Packet filter component types
pub mod pf_component_type {
    pub const MATCH_ALL: u8 = 0x01;
    pub const IPV4_REMOTE_ADDRESS: u8 = 0x10;
    pub const IPV4_LOCAL_ADDRESS: u8 = 0x11;
    pub const IPV6_REMOTE_ADDRESS: u8 = 0x21;
    pub const IPV6_REMOTE_ADDRESS_PREFIX: u8 = 0x22;
    pub const IPV6_LOCAL_ADDRESS: u8 = 0x23;
    pub const IPV6_LOCAL_ADDRESS_PREFIX: u8 = 0x24;
    pub const PROTOCOL_IDENTIFIER: u8 = 0x30;
    pub const SINGLE_LOCAL_PORT: u8 = 0x40;
    pub const LOCAL_PORT_RANGE: u8 = 0x41;
    pub const SINGLE_REMOTE_PORT: u8 = 0x50;
    pub const REMOTE_PORT_RANGE: u8 = 0x51;
}

/// PFCP modification flags
pub mod pfcp_flags {
    pub const MODIFY_REMOVE: u64 = 1 << 0;
    pub const MODIFY_TFT_NEW: u64 = 1 << 1;
    pub const MODIFY_TFT_ADD: u64 = 1 << 2;
    pub const MODIFY_TFT_REPLACE: u64 = 1 << 3;
    pub const MODIFY_TFT_DELETE: u64 = 1 << 4;
    pub const MODIFY_QOS_MODIFY: u64 = 1 << 5;
    pub const MODIFY_UE_REQUESTED: u64 = 1 << 6;
}

// ============================================================================
// Parsed NAS Structures
// ============================================================================

/// Parsed QoS rule packet filter component
#[derive(Debug, Clone, Default)]
pub struct QosRuleComponent {
    pub component_type: u8,
    pub proto: u8,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub ipv4_mask: Option<Ipv4Addr>,
    pub ipv6_addr: Option<[u8; 16]>,
    pub ipv6_mask: Option<[u8; 16]>,
    pub ipv6_prefix_len: u8,
    pub port_low: u16,
    pub port_high: u16,
}

/// Parsed QoS rule packet filter
#[derive(Debug, Clone, Default)]
pub struct QosRulePacketFilter {
    pub direction: u8,
    pub identifier: u8,
    pub components: Vec<QosRuleComponent>,
}

/// Parsed QoS rule
#[derive(Debug, Clone, Default)]
pub struct ParsedQosRule {
    pub identifier: u8,
    pub code: u8,
    pub dqr: bool,
    pub precedence: u8,
    pub qfi: u8,
    pub packet_filters: Vec<QosRulePacketFilter>,
}

/// Parsed QoS flow description parameter
#[derive(Debug, Clone, Default)]
pub struct QosFlowParam {
    pub identifier: u8,
    pub five_qi: u8,
    pub bitrate: u64,
}

/// Parsed QoS flow description
#[derive(Debug, Clone, Default)]
pub struct ParsedQosFlowDescription {
    pub identifier: u8,
    pub code: u8,
    pub e_bit: bool,
    pub params: Vec<QosFlowParam>,
}

/// PDU session establishment request
#[derive(Debug, Clone, Default)]
pub struct PduSessionEstablishmentRequest {
    /// Integrity protection maximum data rate - downlink
    pub integrity_protection_mbr_dl: u8,
    /// Integrity protection maximum data rate - uplink
    pub integrity_protection_mbr_ul: u8,
    /// UE requested PDU session type
    pub ue_session_type: Option<u8>,
    /// UE requested SSC mode
    pub ue_ssc_mode: Option<u8>,
    /// Extended protocol configuration options
    pub epco: Option<Vec<u8>>,
    /// Presence mask
    pub presencemask: u64,
}

/// PDU session modification request
#[derive(Debug, Clone, Default)]
pub struct PduSessionModificationRequest {
    /// 5GSM cause (if present)
    pub gsm_cause: Option<u8>,
    /// Requested QoS rules
    pub qos_rules: Vec<ParsedQosRule>,
    /// Requested QoS flow descriptions
    pub qos_flow_descriptions: Vec<ParsedQosFlowDescription>,
    /// Presence mask
    pub presencemask: u64,
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Handle PDU session establishment request
pub fn handle_pdu_session_establishment_request(
    sess: &mut SmfSess,
    request: &PduSessionEstablishmentRequest,
) -> Result<(), GsmCause> {
    // Process integrity protection maximum data rate
    sess.integrity_protection_mbr_dl = match request.integrity_protection_mbr_dl {
        integrity_protection_rate::RATE_64KBPS => MaxIntegrityProtectedDataRate::Bitrate64kbps,
        integrity_protection_rate::FULL => MaxIntegrityProtectedDataRate::MaxUeRate,
        _ => MaxIntegrityProtectedDataRate::Bitrate64kbps,
    };
    
    sess.integrity_protection_mbr_ul = match request.integrity_protection_mbr_ul {
        integrity_protection_rate::RATE_64KBPS => MaxIntegrityProtectedDataRate::Bitrate64kbps,
        integrity_protection_rate::FULL => MaxIntegrityProtectedDataRate::MaxUeRate,
        _ => MaxIntegrityProtectedDataRate::Bitrate64kbps,
    };

    // Store UE requested session type
    if let Some(session_type) = request.ue_session_type {
        sess.ue_session_type = session_type;
    }

    // Store UE requested SSC mode
    if let Some(ssc_mode) = request.ue_ssc_mode {
        sess.ue_ssc_mode = ssc_mode;
    }

    log::info!("[PSI:{}] PDU session establishment request processed", sess.psi);

    Ok(())
}

/// Handle PDU session modification request - QoS rules
/// Returns the list of bearer IDs to modify and PFCP flags
pub fn handle_pdu_session_modification_qos_rules(
    sess: &SmfSess,
    qos_rules: &[ParsedQosRule],
    bearers: &mut [SmfBearer],
    pfcp_flags: &mut u64,
) -> Result<Vec<u64>, GsmCause> {
    if qos_rules.is_empty() {
        log::error!("[PSI:{}] Invalid modification request - no QoS rules", sess.psi);
        return Err(GsmCause::InvalidMandatoryInformation);
    }

    let mut modified_bearer_ids = Vec::new();

    for rule in qos_rules {
        // Find QoS flow by QFI (rule identifier)
        let qos_flow = match bearers.iter_mut().find(|b| b.qfi == rule.identifier) {
            Some(flow) => flow,
            None => {
                log::error!("[PSI:{}] No QoS flow for QFI {}", sess.psi, rule.identifier);
                continue;
            }
        };

        match rule.code {
            qos_rule_code::DELETE_EXISTING_QOS_RULE => {
                // Remove all packet filters (clear pf_ids)
                qos_flow.pf_ids.clear();
                *pfcp_flags |= pfcp_flags::MODIFY_REMOVE;
                if !modified_bearer_ids.contains(&qos_flow.id) {
                    modified_bearer_ids.push(qos_flow.id);
                }
            }
            qos_rule_code::CREATE_NEW_QOS_RULE |
            qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS |
            qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS => {
                // For create or replace, remove existing filters first
                if rule.code == qos_rule_code::CREATE_NEW_QOS_RULE ||
                   rule.code == qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS {
                    qos_flow.pf_ids.clear();
                }

                // Note: In actual implementation, packet filters would be added to global context
                // and their IDs added to qos_flow.pf_ids
                // For now, we just validate the packet filters
                for pf in &rule.packet_filters {
                    let _new_pf = create_packet_filter_from_rule(qos_flow, pf)?;
                    // In real implementation: add to context and push ID to pf_ids
                }

                // Set appropriate PFCP flag
                match rule.code {
                    qos_rule_code::CREATE_NEW_QOS_RULE => {
                        *pfcp_flags |= pfcp_flags::MODIFY_TFT_NEW;
                    }
                    qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS => {
                        *pfcp_flags |= pfcp_flags::MODIFY_TFT_ADD;
                    }
                    qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS => {
                        *pfcp_flags |= pfcp_flags::MODIFY_TFT_REPLACE;
                    }
                    _ => {}
                }

                if !modified_bearer_ids.contains(&qos_flow.id) {
                    modified_bearer_ids.push(qos_flow.id);
                }
            }
            qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS => {
                // Delete specific packet filters
                for pf in &rule.packet_filters {
                    qos_flow.pf_to_delete.push(pf.identifier);
                }

                if !qos_flow.pf_ids.is_empty() {
                    *pfcp_flags |= pfcp_flags::MODIFY_TFT_DELETE;
                } else {
                    *pfcp_flags |= pfcp_flags::MODIFY_REMOVE;
                }

                if !modified_bearer_ids.contains(&qos_flow.id) {
                    modified_bearer_ids.push(qos_flow.id);
                }
            }
            _ => {
                log::warn!("[PSI:{}] Unknown QoS rule code: {}", sess.psi, rule.code);
            }
        }

        // Update TFT if needed
        if *pfcp_flags & (pfcp_flags::MODIFY_TFT_NEW | pfcp_flags::MODIFY_TFT_ADD |
                         pfcp_flags::MODIFY_TFT_REPLACE | pfcp_flags::MODIFY_TFT_DELETE) != 0 {
            log::debug!("[QFI:{}] TFT updated", qos_flow.qfi);
        }
    }

    Ok(modified_bearer_ids)
}

/// Handle PDU session modification request - QoS flow descriptions
/// Returns the list of bearer IDs to modify
pub fn handle_pdu_session_modification_qos_flow_descriptions(
    sess: &SmfSess,
    descriptions: &[ParsedQosFlowDescription],
    bearers: &mut [SmfBearer],
    pfcp_flags: &mut u64,
) -> Result<Vec<u64>, GsmCause> {
    if descriptions.is_empty() {
        log::error!("[PSI:{}] Invalid modification request - no QoS flow descriptions", sess.psi);
        return Err(GsmCause::InvalidMandatoryInformation);
    }

    let mut modified_bearer_ids = Vec::new();

    for desc in descriptions {
        // Find QoS flow by QFI
        let qos_flow = match bearers.iter_mut().find(|b| b.qfi == desc.identifier) {
            Some(flow) => flow,
            None => {
                log::error!("[PSI:{}] No QoS flow for QFI {}", sess.psi, desc.identifier);
                continue;
            }
        };

        // Process parameters
        for param in &desc.params {
            match param.identifier {
                qos_flow_param_id::FIVE_QI => {
                    // 5QI is informational, don't modify
                }
                qos_flow_param_id::GFBR_UPLINK => {
                    qos_flow.qos.gbr_uplink = param.bitrate;
                }
                qos_flow_param_id::GFBR_DOWNLINK => {
                    qos_flow.qos.gbr_downlink = param.bitrate;
                }
                qos_flow_param_id::MFBR_UPLINK => {
                    qos_flow.qos.mbr_uplink = param.bitrate;
                }
                qos_flow_param_id::MFBR_DOWNLINK => {
                    qos_flow.qos.mbr_downlink = param.bitrate;
                }
                _ => {
                    log::warn!("[PSI:{}] Unknown QoS flow parameter: {}", 
                        sess.psi, param.identifier);
                }
            }
        }

        *pfcp_flags |= pfcp_flags::MODIFY_QOS_MODIFY;
        if !modified_bearer_ids.contains(&qos_flow.id) {
            modified_bearer_ids.push(qos_flow.id);
        }

        // Update QoS if needed
        if *pfcp_flags & pfcp_flags::MODIFY_QOS_MODIFY != 0 {
            log::debug!("[QFI:{}] QoS updated - GBR UL:{} DL:{}, MBR UL:{} DL:{}",
                qos_flow.qfi,
                qos_flow.qos.gbr_uplink,
                qos_flow.qos.gbr_downlink,
                qos_flow.qos.mbr_uplink,
                qos_flow.qos.mbr_downlink);
        }
    }

    Ok(modified_bearer_ids)
}

/// Handle PDU session modification request
/// Returns PFCP flags and updates sess.qos_flow_to_modify_list
pub fn handle_pdu_session_modification_request(
    sess: &mut SmfSess,
    request: &PduSessionModificationRequest,
    bearers: &mut [SmfBearer],
) -> Result<u64, GsmCause> {
    let mut pfcp_flags: u64 = 0;

    // Clear modification list
    sess.qos_flow_to_modify_list.clear();

    // Handle QoS rules if present
    if !request.qos_rules.is_empty() {
        let modified = handle_pdu_session_modification_qos_rules(
            sess, &request.qos_rules, bearers, &mut pfcp_flags)?;
        for id in modified {
            if !sess.qos_flow_to_modify_list.contains(&id) {
                sess.qos_flow_to_modify_list.push(id);
            }
        }
    }

    // Handle QoS flow descriptions if present
    if !request.qos_flow_descriptions.is_empty() {
        let modified = handle_pdu_session_modification_qos_flow_descriptions(
            sess, &request.qos_flow_descriptions, bearers, &mut pfcp_flags)?;
        for id in modified {
            if !sess.qos_flow_to_modify_list.contains(&id) {
                sess.qos_flow_to_modify_list.push(id);
            }
        }
    }

    // Validate modification list
    if sess.qos_flow_to_modify_list.len() != 1 {
        log::error!("[PSI:{}] Invalid modification request - modify count: {}",
            sess.psi, sess.qos_flow_to_modify_list.len());
        return Err(GsmCause::InvalidMandatoryInformation);
    }

    // Validate PFCP flags
    if pfcp_flags & pfcp_flags::MODIFY_REMOVE != 0 {
        if pfcp_flags & (pfcp_flags::MODIFY_TFT_NEW | pfcp_flags::MODIFY_TFT_ADD |
                        pfcp_flags::MODIFY_TFT_REPLACE | pfcp_flags::MODIFY_TFT_DELETE |
                        pfcp_flags::MODIFY_QOS_MODIFY) != 0 {
            log::error!("[PSI:{}] Invalid PFCP flags combination: 0x{:x}", sess.psi, pfcp_flags);
            return Err(GsmCause::InvalidMandatoryInformation);
        }
    }

    pfcp_flags |= pfcp_flags::MODIFY_UE_REQUESTED;

    log::info!("[PSI:{}] PDU session modification request processed, flags=0x{:x}",
        sess.psi, pfcp_flags);

    Ok(pfcp_flags)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create packet filter from parsed QoS rule
fn create_packet_filter_from_rule(
    qos_flow: &SmfBearer,
    pf: &QosRulePacketFilter,
) -> Result<SmfPf, GsmCause> {
    let mut ipfw_rule = IpfwRule::default();

    // Process components
    for component in &pf.components {
        match component.component_type {
            pf_component_type::MATCH_ALL => {
                // Match all - no specific rule
            }
            pf_component_type::PROTOCOL_IDENTIFIER => {
                ipfw_rule.proto = component.proto;
            }
            pf_component_type::IPV4_REMOTE_ADDRESS => {
                if let Some(addr) = component.ipv4_addr {
                    ipfw_rule.dst_addr = Some(addr);
                }
                if let Some(mask) = component.ipv4_mask {
                    ipfw_rule.dst_mask = Some(mask);
                }
            }
            pf_component_type::IPV4_LOCAL_ADDRESS => {
                if let Some(addr) = component.ipv4_addr {
                    ipfw_rule.src_addr = Some(addr);
                }
                if let Some(mask) = component.ipv4_mask {
                    ipfw_rule.src_mask = Some(mask);
                }
            }
            pf_component_type::SINGLE_LOCAL_PORT => {
                ipfw_rule.src_port_low = component.port_low;
                ipfw_rule.src_port_high = component.port_low;
            }
            pf_component_type::SINGLE_REMOTE_PORT => {
                ipfw_rule.dst_port_low = component.port_low;
                ipfw_rule.dst_port_high = component.port_low;
            }
            pf_component_type::LOCAL_PORT_RANGE => {
                ipfw_rule.src_port_low = component.port_low;
                ipfw_rule.src_port_high = component.port_high;
            }
            pf_component_type::REMOTE_PORT_RANGE => {
                ipfw_rule.dst_port_low = component.port_low;
                ipfw_rule.dst_port_high = component.port_high;
            }
            _ => {
                log::error!("Unknown packet filter component type: {}", component.component_type);
                return Err(GsmCause::SemanticErrorsInPacketFilters);
            }
        }
    }

    // Determine direction
    let direction = match pf.direction {
        0x01 => FlowDirection::DownlinkOnly,
        0x02 => FlowDirection::UplinkOnly,
        0x03 => FlowDirection::Bidirectional,
        _ => FlowDirection::Bidirectional,
    };

    // Swap addresses for downlink direction
    // (TFT uses UE perspective, IPFW uses network perspective)
    if direction == FlowDirection::DownlinkOnly {
        std::mem::swap(&mut ipfw_rule.src_addr, &mut ipfw_rule.dst_addr);
        std::mem::swap(&mut ipfw_rule.src_mask, &mut ipfw_rule.dst_mask);
    }

    Ok(SmfPf {
        id: 0, // Will be assigned
        bearer_id: qos_flow.id,
        identifier: pf.identifier,
        direction,
        precedence: 0,
        sdf_filter_id: 0,
        ipfw_rule,
        flow_description: None,
    })
}

/// Parse NAS bitrate to u64
pub fn nas_bitrate_to_u64(unit: u8, value: u16) -> u64 {
    let multiplier: u64 = match unit {
        0 => 1000,        // 1 kbps
        1 => 4000,        // 4 kbps
        2 => 16000,       // 16 kbps
        3 => 64000,       // 64 kbps
        4 => 256000,      // 256 kbps
        5 => 1000000,     // 1 Mbps
        6 => 4000000,     // 4 Mbps
        7 => 16000000,    // 16 Mbps
        8 => 64000000,    // 64 Mbps
        9 => 256000000,   // 256 Mbps
        10 => 1000000000, // 1 Gbps
        11 => 4000000000, // 4 Gbps
        _ => 1000,
    };
    
    (value as u64) * multiplier
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{SmfSess, SmfBearer, Qos, PduSessionType, SNssai, SessionAmbr};
    use std::net::Ipv4Addr;

    fn create_test_sess() -> SmfSess {
        SmfSess {
            id: 1,
            smf_ue_id: 1,
            psi: 5,
            pti: 1,
            session_type: PduSessionType::Ipv4,
            session_name: Some("internet".to_string()),
            s_nssai: SNssai { sst: 1, sd: Some(0x010203) },
            session_ambr: SessionAmbr {
                downlink: 100_000_000,
                uplink: 50_000_000,
            },
            ipv4_addr: Some(Ipv4Addr::new(10, 45, 0, 1)),
            bearer_ids: vec![1],
            ..Default::default()
        }
    }

    fn create_test_bearer() -> SmfBearer {
        SmfBearer {
            id: 1,
            sess_id: 1,
            qfi: 1,
            qos: Qos {
                index: 9,
                arp_priority_level: 8,
                arp_preempt_cap: false,
                arp_preempt_vuln: false,
                gbr_uplink: 0,
                gbr_downlink: 0,
                mbr_uplink: 0,
                mbr_downlink: 0,
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_handle_pdu_session_establishment_request() {
        let mut sess = create_test_sess();
        
        let request = PduSessionEstablishmentRequest {
            integrity_protection_mbr_dl: integrity_protection_rate::FULL,
            integrity_protection_mbr_ul: integrity_protection_rate::RATE_64KBPS,
            ue_session_type: Some(1), // IPv4
            ue_ssc_mode: Some(1),
            epco: Some(vec![0x01, 0x02, 0x03]),
            presencemask: 0,
        };

        let result = handle_pdu_session_establishment_request(&mut sess, &request);
        
        assert!(result.is_ok());
        assert_eq!(sess.integrity_protection_mbr_dl, MaxIntegrityProtectedDataRate::MaxUeRate);
        assert_eq!(sess.integrity_protection_mbr_ul, MaxIntegrityProtectedDataRate::Bitrate64kbps);
        assert_eq!(sess.ue_session_type, 1);
        assert_eq!(sess.ue_ssc_mode, 1);
    }

    #[test]
    fn test_handle_pdu_session_modification_qos_rules_delete() {
        let sess = create_test_sess();
        let mut bearer = create_test_bearer();
        bearer.pf_ids.push(1); // Add a packet filter ID
        let mut bearers = vec![bearer];
        
        let qos_rules = vec![ParsedQosRule {
            identifier: 1, // QFI
            code: qos_rule_code::DELETE_EXISTING_QOS_RULE,
            ..Default::default()
        }];

        let mut pfcp_flags = 0u64;
        let result = handle_pdu_session_modification_qos_rules(&sess, &qos_rules, &mut bearers, &mut pfcp_flags);
        
        assert!(result.is_ok());
        assert!(pfcp_flags & pfcp_flags::MODIFY_REMOVE != 0);
        assert!(bearers[0].pf_ids.is_empty());
    }

    #[test]
    fn test_handle_pdu_session_modification_qos_rules_create() {
        let sess = create_test_sess();
        let mut bearers = vec![create_test_bearer()];
        
        let qos_rules = vec![ParsedQosRule {
            identifier: 1,
            code: qos_rule_code::CREATE_NEW_QOS_RULE,
            packet_filters: vec![QosRulePacketFilter {
                direction: 0x03, // Bidirectional
                identifier: 1,
                components: vec![QosRuleComponent {
                    component_type: pf_component_type::PROTOCOL_IDENTIFIER,
                    proto: 17, // UDP
                    ..Default::default()
                }],
            }],
            ..Default::default()
        }];

        let mut pfcp_flags = 0u64;
        let result = handle_pdu_session_modification_qos_rules(&sess, &qos_rules, &mut bearers, &mut pfcp_flags);
        
        assert!(result.is_ok());
        assert!(pfcp_flags & pfcp_flags::MODIFY_TFT_NEW != 0);
    }

    #[test]
    fn test_handle_pdu_session_modification_qos_flow_descriptions() {
        let sess = create_test_sess();
        let mut bearers = vec![create_test_bearer()];
        
        let descriptions = vec![ParsedQosFlowDescription {
            identifier: 1,
            code: 3, // Modify
            e_bit: true,
            params: vec![
                QosFlowParam {
                    identifier: qos_flow_param_id::GFBR_UPLINK,
                    bitrate: 10_000_000,
                    ..Default::default()
                },
                QosFlowParam {
                    identifier: qos_flow_param_id::GFBR_DOWNLINK,
                    bitrate: 20_000_000,
                    ..Default::default()
                },
            ],
        }];

        let mut pfcp_flags = 0u64;
        let result = handle_pdu_session_modification_qos_flow_descriptions(
            &sess, &descriptions, &mut bearers, &mut pfcp_flags);
        
        assert!(result.is_ok());
        assert!(pfcp_flags & pfcp_flags::MODIFY_QOS_MODIFY != 0);
        assert_eq!(bearers[0].qos.gbr_uplink, 10_000_000);
        assert_eq!(bearers[0].qos.gbr_downlink, 20_000_000);
    }

    #[test]
    fn test_handle_pdu_session_modification_request() {
        let mut sess = create_test_sess();
        let mut bearers = vec![create_test_bearer()];
        
        let request = PduSessionModificationRequest {
            qos_rules: vec![ParsedQosRule {
                identifier: 1,
                code: qos_rule_code::CREATE_NEW_QOS_RULE,
                packet_filters: vec![QosRulePacketFilter {
                    direction: 0x03,
                    identifier: 1,
                    components: vec![QosRuleComponent {
                        component_type: pf_component_type::MATCH_ALL,
                        ..Default::default()
                    }],
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = handle_pdu_session_modification_request(&mut sess, &request, &mut bearers);
        
        assert!(result.is_ok());
        let flags = result.unwrap();
        assert!(flags & pfcp_flags::MODIFY_TFT_NEW != 0);
        assert!(flags & pfcp_flags::MODIFY_UE_REQUESTED != 0);
    }

    #[test]
    fn test_handle_pdu_session_modification_request_empty_rules() {
        let mut sess = create_test_sess();
        let mut bearers = vec![create_test_bearer()];
        
        let request = PduSessionModificationRequest {
            qos_rules: vec![],
            qos_flow_descriptions: vec![],
            ..Default::default()
        };

        let result = handle_pdu_session_modification_request(&mut sess, &request, &mut bearers);
        
        // Should fail because no modifications
        assert!(result.is_err());
    }

    #[test]
    fn test_nas_bitrate_to_u64() {
        assert_eq!(nas_bitrate_to_u64(0, 1000), 1_000_000); // 1000 kbps = 1 Mbps
        assert_eq!(nas_bitrate_to_u64(5, 100), 100_000_000); // 100 Mbps
        assert_eq!(nas_bitrate_to_u64(10, 1), 1_000_000_000); // 1 Gbps
    }

    #[test]
    fn test_create_packet_filter_from_rule_match_all() {
        let bearer = create_test_bearer();
        let pf = QosRulePacketFilter {
            direction: 0x03,
            identifier: 1,
            components: vec![QosRuleComponent {
                component_type: pf_component_type::MATCH_ALL,
                ..Default::default()
            }],
        };

        let result = create_packet_filter_from_rule(&bearer, &pf);
        
        assert!(result.is_ok());
        let smf_pf = result.unwrap();
        assert_eq!(smf_pf.identifier, 1);
        assert_eq!(smf_pf.direction, FlowDirection::Bidirectional);
    }

    #[test]
    fn test_create_packet_filter_from_rule_with_ports() {
        let bearer = create_test_bearer();
        let pf = QosRulePacketFilter {
            direction: 0x02, // Uplink
            identifier: 2,
            components: vec![
                QosRuleComponent {
                    component_type: pf_component_type::PROTOCOL_IDENTIFIER,
                    proto: 17, // UDP
                    ..Default::default()
                },
                QosRuleComponent {
                    component_type: pf_component_type::SINGLE_REMOTE_PORT,
                    port_low: 5060,
                    ..Default::default()
                },
            ],
        };

        let result = create_packet_filter_from_rule(&bearer, &pf);
        
        assert!(result.is_ok());
        let smf_pf = result.unwrap();
        assert_eq!(smf_pf.ipfw_rule.proto, 17);
        assert_eq!(smf_pf.ipfw_rule.dst_port_low, 5060);
        assert_eq!(smf_pf.direction, FlowDirection::UplinkOnly);
    }

    #[test]
    fn test_create_packet_filter_from_rule_with_ipv4() {
        let bearer = create_test_bearer();
        let pf = QosRulePacketFilter {
            direction: 0x01, // Downlink
            identifier: 3,
            components: vec![QosRuleComponent {
                component_type: pf_component_type::IPV4_REMOTE_ADDRESS,
                ipv4_addr: Some(Ipv4Addr::new(192, 168, 1, 0)),
                ipv4_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
                ..Default::default()
            }],
        };

        let result = create_packet_filter_from_rule(&bearer, &pf);
        
        assert!(result.is_ok());
        let smf_pf = result.unwrap();
        assert_eq!(smf_pf.direction, FlowDirection::DownlinkOnly);
        // For downlink, addresses are swapped
        assert!(smf_pf.ipfw_rule.src_addr.is_some());
    }

    #[test]
    fn test_integrity_protection_rate_constants() {
        assert_eq!(integrity_protection_rate::NULL, 0);
        assert_eq!(integrity_protection_rate::RATE_64KBPS, 1);
        assert_eq!(integrity_protection_rate::FULL, 0xff);
    }

    #[test]
    fn test_qos_rule_code_constants() {
        assert_eq!(qos_rule_code::CREATE_NEW_QOS_RULE, 1);
        assert_eq!(qos_rule_code::DELETE_EXISTING_QOS_RULE, 2);
        assert_eq!(qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS, 3);
        assert_eq!(qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS, 4);
        assert_eq!(qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS, 5);
        assert_eq!(qos_rule_code::MODIFY_EXISTING_QOS_RULE_WITHOUT_MODIFYING_PACKET_FILTERS, 6);
    }

    #[test]
    fn test_pfcp_flags_constants() {
        assert_eq!(pfcp_flags::MODIFY_REMOVE, 1);
        assert_eq!(pfcp_flags::MODIFY_TFT_NEW, 2);
        assert_eq!(pfcp_flags::MODIFY_TFT_ADD, 4);
        assert_eq!(pfcp_flags::MODIFY_TFT_REPLACE, 8);
        assert_eq!(pfcp_flags::MODIFY_TFT_DELETE, 16);
        assert_eq!(pfcp_flags::MODIFY_QOS_MODIFY, 32);
        assert_eq!(pfcp_flags::MODIFY_UE_REQUESTED, 64);
    }
}
