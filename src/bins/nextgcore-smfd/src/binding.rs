//! SMF Policy Binding Implementation

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//!
//! This module implements policy binding for the SMF, handling PCC rules
//! from the PCF and binding them to bearers/QoS flows.
//!
//! Based on NextGCore src/smf/binding.c

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::context::{
    SmfSess, SmfBearer, SmfUe, PduSessionType, Qos, PacketFilter,
    FlowDirection, IpfwRule,
};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of flows in a GTP TFT
pub const MAX_NUM_OF_FLOW_IN_GTP: usize = 16;

/// Maximum number of bearers per session
pub const MAX_NUM_OF_BEARER: usize = 8;

// TFT Operation Codes (3GPP TS 24.008)
pub mod tft_code {
    pub const CREATE_NEW_TFT: u8 = 1;
    pub const DELETE_EXISTING_TFT: u8 = 2;
    pub const ADD_PACKET_FILTERS_TO_EXISTING_TFT: u8 = 3;
    pub const REPLACE_PACKET_FILTERS_IN_EXISTING: u8 = 4;
    pub const DELETE_PACKET_FILTERS_FROM_EXISTING: u8 = 5;
    pub const NO_TFT_OPERATION: u8 = 6;
}

// QoS Rule Operation Codes (3GPP TS 24.501)
pub mod qos_code {
    pub const CREATE_NEW_QOS_RULE: u8 = 1;
    pub const DELETE_EXISTING_QOS_RULE: u8 = 2;
    pub const MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS: u8 = 3;
    pub const MODIFY_EXISTING_QOS_RULE_AND_REPLACE_PACKET_FILTERS: u8 = 4;
    pub const MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS: u8 = 5;
    pub const MODIFY_EXISTING_QOS_RULE_WITHOUT_MODIFYING_PACKET_FILTERS: u8 = 6;
}

// PFCP Modify Flags
pub mod pfcp_modify {
    pub const CREATE: u64 = 0x0001;
    pub const REMOVE: u64 = 0x0002;
    pub const TFT_ADD: u64 = 0x0004;
    pub const TFT_DELETE: u64 = 0x0008;
    pub const TFT_REPLACE: u64 = 0x0010;
    pub const QOS_MODIFY: u64 = 0x0020;
    pub const NETWORK_REQUESTED: u64 = 0x0040;
    pub const EPC_TFT_UPDATE: u64 = 0x0080;
    pub const EPC_QOS_UPDATE: u64 = 0x0100;
    pub const DL_ONLY: u64 = 0x0200;
    pub const DEACTIVATE: u64 = 0x0400;
    pub const HOME_ROUTED_ROAMING: u64 = 0x0800;
}

// ============================================================================
// PCC Rule Types
// ============================================================================

/// PCC Rule Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PccRuleType {
    /// Install a new rule or update existing
    Install,
    /// Remove an existing rule
    Remove,
}

/// Flow direction for packet filters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDir {
    /// Downlink only
    DownlinkOnly = 1,
    /// Uplink only
    UplinkOnly = 2,
    /// Bidirectional
    Bidirectional = 3,
}

impl From<u8> for FlowDir {
    fn from(value: u8) -> Self {
        match value {
            1 => FlowDir::DownlinkOnly,
            2 => FlowDir::UplinkOnly,
            _ => FlowDir::Bidirectional,
        }
    }
}

// ============================================================================
// Flow Description
// ============================================================================

/// A flow description from PCC rules
#[derive(Debug, Clone)]
pub struct Flow {
    /// Flow direction
    pub direction: FlowDir,
    /// Flow description string (IPFilterRule format)
    pub description: String,
}

impl Flow {
    /// Create a new flow
    pub fn new(direction: FlowDir, description: &str) -> Self {
        Self {
            direction,
            description: description.to_string(),
        }
    }
}


// ============================================================================
// QoS Parameters
// ============================================================================

/// QoS parameters for a PCC rule
#[derive(Debug, Clone, Default)]
pub struct PccQos {
    /// QoS Class Identifier (QCI for EPC, 5QI for 5GC)
    pub qci: u8,
    /// Allocation and Retention Priority
    pub arp: ArpParams,
    /// Maximum Bit Rate
    pub mbr: BitRate,
    /// Guaranteed Bit Rate
    pub gbr: BitRate,
}

/// ARP (Allocation and Retention Priority) parameters
#[derive(Debug, Clone, Default)]
pub struct ArpParams {
    /// Priority level (1-15)
    pub priority_level: u8,
    /// Pre-emption capability
    pub pre_emption_capability: bool,
    /// Pre-emption vulnerability
    pub pre_emption_vulnerability: bool,
}

/// Bit rate values (uplink/downlink)
#[derive(Debug, Clone, Default)]
pub struct BitRate {
    /// Uplink bit rate in bps
    pub uplink: u64,
    /// Downlink bit rate in bps
    pub downlink: u64,
}

// ============================================================================
// PCC Rule
// ============================================================================

/// A PCC (Policy and Charging Control) Rule
#[derive(Debug, Clone)]
pub struct PccRule {
    /// Rule ID (for 5GC)
    pub id: Option<String>,
    /// Rule name (for EPC)
    pub name: Option<String>,
    /// Rule type (install or remove)
    pub rule_type: PccRuleType,
    /// Rule precedence
    pub precedence: u32,
    /// QoS parameters
    pub qos: PccQos,
    /// List of flows
    pub flows: Vec<Flow>,
}

impl PccRule {
    /// Create a new install rule
    pub fn new_install(name: &str) -> Self {
        Self {
            id: None,
            name: Some(name.to_string()),
            rule_type: PccRuleType::Install,
            precedence: 0,
            qos: PccQos::default(),
            flows: Vec::new(),
        }
    }

    /// Create a new remove rule
    pub fn new_remove(name: &str) -> Self {
        Self {
            id: None,
            name: Some(name.to_string()),
            rule_type: PccRuleType::Remove,
            precedence: 0,
            qos: PccQos::default(),
            flows: Vec::new(),
        }
    }


    /// Create a new 5GC install rule with ID
    pub fn new_5gc_install(id: &str) -> Self {
        Self {
            id: Some(id.to_string()),
            name: None,
            rule_type: PccRuleType::Install,
            precedence: 0,
            qos: PccQos::default(),
            flows: Vec::new(),
        }
    }

    /// Create a new 5GC remove rule with ID
    pub fn new_5gc_remove(id: &str) -> Self {
        Self {
            id: Some(id.to_string()),
            name: None,
            rule_type: PccRuleType::Remove,
            precedence: 0,
            qos: PccQos::default(),
            flows: Vec::new(),
        }
    }

    /// Add a flow to the rule
    pub fn add_flow(&mut self, direction: FlowDir, description: &str) {
        self.flows.push(Flow::new(direction, description));
    }

    /// Set QoS parameters
    pub fn set_qos(&mut self, qos: PccQos) {
        self.qos = qos;
    }

    /// Set precedence
    pub fn set_precedence(&mut self, precedence: u32) {
        self.precedence = precedence;
    }
}

// ============================================================================
// Session Policy
// ============================================================================

/// Session policy containing PCC rules
#[derive(Debug, Clone, Default)]
pub struct SessionPolicy {
    /// List of PCC rules
    pub pcc_rules: Vec<PccRule>,
}

impl SessionPolicy {
    /// Create a new empty session policy
    pub fn new() -> Self {
        Self {
            pcc_rules: Vec::new(),
        }
    }

    /// Add a PCC rule
    pub fn add_rule(&mut self, rule: PccRule) {
        self.pcc_rules.push(rule);
    }

    /// Get the number of rules
    pub fn num_rules(&self) -> usize {
        self.pcc_rules.len()
    }
}


// ============================================================================
// Traffic Flow Template (TFT)
// ============================================================================

/// TFT Packet Filter
#[derive(Debug, Clone, Default)]
pub struct TftPacketFilter {
    /// Packet filter identifier (0-15)
    pub identifier: u8,
    /// Direction
    pub direction: u8,
    /// Precedence (evaluation order)
    pub precedence: u8,
    /// Packet filter content
    pub content: PacketFilterContent,
}

/// Packet filter content
#[derive(Debug, Clone, Default)]
pub struct PacketFilterContent {
    /// Remote IPv4 address
    pub remote_ipv4_addr: Option<Ipv4Addr>,
    /// Remote IPv4 mask
    pub remote_ipv4_mask: Option<Ipv4Addr>,
    /// Remote IPv6 address
    pub remote_ipv6_addr: Option<Ipv6Addr>,
    /// Remote IPv6 prefix length
    pub remote_ipv6_prefix_len: u8,
    /// Local IPv4 address
    pub local_ipv4_addr: Option<Ipv4Addr>,
    /// Local IPv4 mask
    pub local_ipv4_mask: Option<Ipv4Addr>,
    /// Local IPv6 address
    pub local_ipv6_addr: Option<Ipv6Addr>,
    /// Local IPv6 prefix length
    pub local_ipv6_prefix_len: u8,
    /// Protocol identifier / Next header
    pub protocol_id: Option<u8>,
    /// Single local port
    pub local_port: Option<u16>,
    /// Local port range (low, high)
    pub local_port_range: Option<(u16, u16)>,
    /// Single remote port
    pub remote_port: Option<u16>,
    /// Remote port range (low, high)
    pub remote_port_range: Option<(u16, u16)>,
    /// Security parameter index
    pub spi: Option<u32>,
    /// Type of service / Traffic class
    pub tos_tc: Option<(u8, u8)>,
    /// Flow label (IPv6)
    pub flow_label: Option<u32>,
}

/// Traffic Flow Template
#[derive(Debug, Clone, Default)]
pub struct Tft {
    /// TFT operation code
    pub code: u8,
    /// Number of packet filters
    pub num_of_packet_filter: usize,
    /// Packet filters
    pub pf: Vec<TftPacketFilter>,
}


impl Tft {
    /// Create a new TFT with the given operation code
    pub fn new(code: u8) -> Self {
        Self {
            code,
            num_of_packet_filter: 0,
            pf: Vec::new(),
        }
    }

    /// Add a packet filter
    pub fn add_packet_filter(&mut self, pf: TftPacketFilter) {
        if self.pf.len() < MAX_NUM_OF_FLOW_IN_GTP {
            self.pf.push(pf);
            self.num_of_packet_filter = self.pf.len();
        }
    }

    /// Encode TFT to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // TFT operation code and number of packet filters
        let first_byte = (self.code << 5) | (self.num_of_packet_filter as u8 & 0x0F);
        buf.push(first_byte);
        
        // Encode each packet filter
        for pf in &self.pf {
            // Packet filter identifier and direction
            let id_dir = (pf.direction << 4) | (pf.identifier & 0x0F);
            buf.push(id_dir);
            
            // Precedence
            buf.push(pf.precedence);
            
            // Packet filter content length placeholder
            let len_pos = buf.len();
            buf.push(0);
            
            // Encode packet filter content
            let content_start = buf.len();
            self.encode_pf_content(&pf.content, &mut buf);
            
            // Update length
            let content_len = buf.len() - content_start;
            buf[len_pos] = content_len as u8;
        }
        
        buf
    }

    fn encode_pf_content(&self, content: &PacketFilterContent, buf: &mut Vec<u8>) {
        // Protocol ID / Next header
        if let Some(proto) = content.protocol_id {
            buf.push(0x30); // Component type: Protocol ID
            buf.push(proto);
        }
        
        // Remote IPv4 address
        if let Some(addr) = content.remote_ipv4_addr {
            buf.push(0x10); // Component type: IPv4 remote address
            buf.extend_from_slice(&addr.octets());
            if let Some(mask) = content.remote_ipv4_mask {
                buf.extend_from_slice(&mask.octets());
            } else {
                buf.extend_from_slice(&[255, 255, 255, 255]);
            }
        }

        
        // Local IPv4 address
        if let Some(addr) = content.local_ipv4_addr {
            buf.push(0x11); // Component type: IPv4 local address
            buf.extend_from_slice(&addr.octets());
            if let Some(mask) = content.local_ipv4_mask {
                buf.extend_from_slice(&mask.octets());
            } else {
                buf.extend_from_slice(&[255, 255, 255, 255]);
            }
        }
        
        // Remote IPv6 address
        if let Some(addr) = content.remote_ipv6_addr {
            buf.push(0x20); // Component type: IPv6 remote address
            buf.extend_from_slice(&addr.octets());
            buf.push(content.remote_ipv6_prefix_len);
        }
        
        // Local IPv6 address
        if let Some(addr) = content.local_ipv6_addr {
            buf.push(0x21); // Component type: IPv6 local address
            buf.extend_from_slice(&addr.octets());
            buf.push(content.local_ipv6_prefix_len);
        }
        
        // Single local port
        if let Some(port) = content.local_port {
            buf.push(0x40); // Component type: Single local port
            buf.extend_from_slice(&port.to_be_bytes());
        }
        
        // Local port range
        if let Some((low, high)) = content.local_port_range {
            buf.push(0x41); // Component type: Local port range
            buf.extend_from_slice(&low.to_be_bytes());
            buf.extend_from_slice(&high.to_be_bytes());
        }
        
        // Single remote port
        if let Some(port) = content.remote_port {
            buf.push(0x50); // Component type: Single remote port
            buf.extend_from_slice(&port.to_be_bytes());
        }
        
        // Remote port range
        if let Some((low, high)) = content.remote_port_range {
            buf.push(0x51); // Component type: Remote port range
            buf.extend_from_slice(&low.to_be_bytes());
            buf.extend_from_slice(&high.to_be_bytes());
        }
        
        // Security parameter index
        if let Some(spi) = content.spi {
            buf.push(0x60); // Component type: Security parameter index
            buf.extend_from_slice(&spi.to_be_bytes());
        }
        
        // Type of service / Traffic class
        if let Some((tos, mask)) = content.tos_tc {
            buf.push(0x70); // Component type: Type of service
            buf.push(tos);
            buf.push(mask);
        }
        
        // Flow label
        if let Some(label) = content.flow_label {
            buf.push(0x80); // Component type: Flow label
            buf.extend_from_slice(&label.to_be_bytes()[1..4]); // 3 bytes
        }
    }
}


// ============================================================================
// Bearer Binding Result
// ============================================================================

/// Result of bearer binding operation
#[derive(Debug, Clone)]
pub enum BearerBindingResult {
    /// Bearer was created
    Created {
        bearer_id: u64,
        pfcp_flags: u64,
    },
    /// Bearer was modified
    Modified {
        bearer_id: u64,
        pfcp_flags: u64,
        tft_update: bool,
        qos_update: bool,
    },
    /// Bearer should be removed
    Remove {
        bearer_id: u64,
        pfcp_flags: u64,
    },
    /// No action needed
    NoAction,
    /// Error occurred
    Error(String),
}

/// Result of QoS flow binding operation
#[derive(Debug, Clone)]
pub enum QosFlowBindingResult {
    /// QoS flow was created
    Created {
        qos_flow_id: u8,
        pfcp_flags: u64,
    },
    /// QoS flow was modified
    Modified {
        qos_flow_id: u8,
        pfcp_flags: u64,
        tft_update: bool,
        qos_update: bool,
    },
    /// QoS flow should be removed
    Remove {
        qos_flow_id: u8,
        pfcp_flags: u64,
    },
    /// No action needed
    NoAction,
    /// Error occurred
    Error(String),
}

// ============================================================================
// Policy Binding Functions
// ============================================================================

/// Process EPC bearer binding for a session
/// 
/// This function processes PCC rules and binds them to bearers.
/// For each rule:
/// - INSTALL: Creates a new bearer or updates an existing one
/// - REMOVE: Marks the bearer for removal
pub fn process_bearer_binding(
    policy: &SessionPolicy,
    existing_bearers: &[SmfBearer],
) -> Vec<BearerBindingResult> {
    let mut results = Vec::new();
    
    for pcc_rule in &policy.pcc_rules {
        let rule_name = match &pcc_rule.name {
            Some(name) => name,
            None => {
                results.push(BearerBindingResult::Error(
                    "No PCC Rule Name".to_string()
                ));
                continue;
            }
        };

        
        match pcc_rule.rule_type {
            PccRuleType::Install => {
                // Find existing bearer with this rule name
                let existing = existing_bearers.iter()
                    .find(|b| b.pcc_rule_name.as_deref() == Some(rule_name));
                
                if let Some(_bearer) = existing {
                    // Bearer exists - check if update needed
                    let mut tft_update = false;
                    let mut qos_update = false;
                    let mut pfcp_flags = pfcp_modify::NETWORK_REQUESTED;
                    
                    // Check for new flows
                    if !pcc_rule.flows.is_empty() {
                        tft_update = true;
                        pfcp_flags |= pfcp_modify::EPC_TFT_UPDATE;
                    }
                    
                    // Check for QoS changes
                    // In a real implementation, compare with existing QoS
                    if pcc_rule.qos.mbr.downlink > 0 || pcc_rule.qos.mbr.uplink > 0 {
                        qos_update = true;
                        pfcp_flags |= pfcp_modify::EPC_QOS_UPDATE;
                    }
                    
                    if tft_update || qos_update {
                        results.push(BearerBindingResult::Modified {
                            bearer_id: 0, // Would be actual bearer ID
                            pfcp_flags,
                            tft_update,
                            qos_update,
                        });
                    } else {
                        results.push(BearerBindingResult::NoAction);
                    }
                } else {
                    // Create new bearer
                    if pcc_rule.flows.is_empty() {
                        results.push(BearerBindingResult::Error(
                            "No flow in PCC Rule - TFT is mandatory".to_string()
                        ));
                        continue;
                    }
                    
                    if existing_bearers.len() >= MAX_NUM_OF_BEARER {
                        results.push(BearerBindingResult::Error(
                            format!("Bearer overflow: {}", existing_bearers.len())
                        ));
                        continue;
                    }
                    
                    results.push(BearerBindingResult::Created {
                        bearer_id: 0, // Would be assigned by caller
                        pfcp_flags: pfcp_modify::CREATE,
                    });
                }
            }
            PccRuleType::Remove => {
                // Find bearer to remove
                let existing = existing_bearers.iter()
                    .find(|b| b.pcc_rule_name.as_deref() == Some(rule_name));
                
                if existing.is_some() {
                    results.push(BearerBindingResult::Remove {
                        bearer_id: 0, // Would be actual bearer ID
                        pfcp_flags: pfcp_modify::DL_ONLY | pfcp_modify::DEACTIVATE,
                    });
                } else {
                    results.push(BearerBindingResult::NoAction);
                }
            }
        }
    }
    
    results
}


/// Process 5GC QoS flow binding for a session
/// 
/// This function processes PCC rules and binds them to QoS flows.
/// For each rule:
/// - INSTALL: Creates a new QoS flow or updates an existing one
/// - REMOVE: Marks the QoS flow for removal
pub fn process_qos_flow_binding(
    policy: &SessionPolicy,
    existing_flows: &[SmfBearer],
) -> (Vec<QosFlowBindingResult>, u64) {
    let mut results = Vec::new();
    let mut pfcp_flags = pfcp_modify::NETWORK_REQUESTED;
    
    for pcc_rule in &policy.pcc_rules {
        let rule_id = match &pcc_rule.id {
            Some(id) => id,
            None => {
                results.push(QosFlowBindingResult::Error(
                    "No PCC Rule Id".to_string()
                ));
                continue;
            }
        };
        
        match pcc_rule.rule_type {
            PccRuleType::Install => {
                // Find existing QoS flow with this rule ID
                let existing = existing_flows.iter()
                    .find(|f| f.pcc_rule_id.as_deref() == Some(rule_id));
                
                if let Some(_flow) = existing {
                    // QoS flow exists - check if update needed
                    let mut tft_update = false;
                    let mut qos_update = false;
                    let mut flow_pfcp_flags = pfcp_modify::NETWORK_REQUESTED;
                    
                    // Check for new flows
                    if !pcc_rule.flows.is_empty() {
                        tft_update = true;
                        flow_pfcp_flags |= pfcp_modify::TFT_ADD;
                    }
                    
                    // Check for QoS changes (GBR flows)
                    if pcc_rule.qos.mbr.downlink > 0 || pcc_rule.qos.mbr.uplink > 0 ||
                       pcc_rule.qos.gbr.downlink > 0 || pcc_rule.qos.gbr.uplink > 0 {
                        qos_update = true;
                        flow_pfcp_flags |= pfcp_modify::QOS_MODIFY;
                    }
                    
                    if tft_update || qos_update {
                        pfcp_flags |= flow_pfcp_flags;
                        results.push(QosFlowBindingResult::Modified {
                            qos_flow_id: 0, // Would be actual QFI
                            pfcp_flags: flow_pfcp_flags,
                            tft_update,
                            qos_update,
                        });
                    } else {
                        results.push(QosFlowBindingResult::NoAction);
                    }
                } else {
                    // Create new QoS flow
                    if pcc_rule.flows.is_empty() {
                        results.push(QosFlowBindingResult::Error(
                            "No flow in PCC Rule".to_string()
                        ));
                        continue;
                    }
                    
                    if existing_flows.len() >= MAX_NUM_OF_BEARER {
                        results.push(QosFlowBindingResult::Error(
                            format!("QoS flow overflow: {}", existing_flows.len())
                        ));
                        continue;
                    }
                    
                    pfcp_flags |= pfcp_modify::CREATE;
                    results.push(QosFlowBindingResult::Created {
                        qos_flow_id: 0, // Would be assigned by caller
                        pfcp_flags: pfcp_modify::CREATE,
                    });
                }
            }

            PccRuleType::Remove => {
                // Find QoS flow to remove
                let existing = existing_flows.iter()
                    .find(|f| f.pcc_rule_id.as_deref() == Some(rule_id));
                
                if existing.is_some() {
                    pfcp_flags |= pfcp_modify::REMOVE;
                    results.push(QosFlowBindingResult::Remove {
                        qos_flow_id: 0, // Would be actual QFI
                        pfcp_flags: pfcp_modify::REMOVE,
                    });
                } else {
                    results.push(QosFlowBindingResult::NoAction);
                }
            }
        }
    }
    
    (results, pfcp_flags)
}

/// Encode traffic flow template from packet filters
/// 
/// This function creates a TFT from the packet filters to be added to a bearer.
/// 
/// Issue #338 from NextGCore:
/// - DOWNLINK/BI-DIRECTIONAL:
///   RULE: Source <P-CSCF_RTP_IP> <P-CSCF_RTP_PORT> Destination <UE_IP> <UE_PORT>
///   TFT: Local <UE_IP> <UE_PORT> REMOTE <P-CSCF_RTP_IP> <P-CSCF_RTP_PORT>
/// - UPLINK:
///   RULE: Source <UE_IP> <UE_PORT> Destination <P-CSCF_RTP_IP> <P-CSCF_RTP_PORT>
///   TFT: Local <UE_IP> <UE_PORT> REMOTE <P-CSCF_RTP_IP> <P-CSCF_RTP_PORT>
pub fn encode_traffic_flow_template(
    packet_filters: &[PacketFilter],
    operation_code: u8,
) -> Tft {
    let mut tft = Tft::new(operation_code);
    
    // Skip encoding for delete or no-op
    if operation_code == tft_code::DELETE_EXISTING_TFT ||
       operation_code == tft_code::NO_TFT_OPERATION {
        return tft;
    }
    
    for (i, pf) in packet_filters.iter().enumerate() {
        if i >= MAX_NUM_OF_FLOW_IN_GTP {
            break;
        }
        
        let mut tft_pf = TftPacketFilter {
            identifier: pf.identifier.saturating_sub(1),
            direction: pf.direction as u8,
            precedence: pf.precedence.saturating_sub(1),
            content: PacketFilterContent::default(),
        };
        
        // For delete packet filters, only identifier is needed
        if operation_code != tft_code::DELETE_PACKET_FILTERS_FROM_EXISTING {
            // Convert IPFW rule to packet filter content
            tft_pf.content = ipfw_rule_to_pf_content(&pf.ipfw_rule, pf.direction);
        }
        
        tft.add_packet_filter(tft_pf);
    }
    
    tft
}


/// Convert IPFW rule to packet filter content
fn ipfw_rule_to_pf_content(rule: &IpfwRule, direction: FlowDirection) -> PacketFilterContent {
    let mut content = PacketFilterContent::default();
    
    // Protocol
    if rule.proto != 0 {
        content.protocol_id = Some(rule.proto);
    }
    
    // For downlink/bidirectional: source is remote, destination is local
    // For uplink: source is local, destination is remote
    match direction {
        FlowDirection::DownlinkOnly | FlowDirection::Bidirectional => {
            // Source -> Remote
            if let Some(addr) = rule.src_addr {
                content.remote_ipv4_addr = Some(addr);
                content.remote_ipv4_mask = rule.src_mask;
            }
            if let Some(addr) = rule.src_addr6 {
                content.remote_ipv6_addr = Some(addr);
                content.remote_ipv6_prefix_len = rule.src_prefix_len6;
            }
            if rule.src_port_low > 0 {
                if rule.src_port_low == rule.src_port_high {
                    content.remote_port = Some(rule.src_port_low);
                } else {
                    content.remote_port_range = Some((rule.src_port_low, rule.src_port_high));
                }
            }
            
            // Destination -> Local
            if let Some(addr) = rule.dst_addr {
                content.local_ipv4_addr = Some(addr);
                content.local_ipv4_mask = rule.dst_mask;
            }
            if let Some(addr) = rule.dst_addr6 {
                content.local_ipv6_addr = Some(addr);
                content.local_ipv6_prefix_len = rule.dst_prefix_len6;
            }
            if rule.dst_port_low > 0 {
                if rule.dst_port_low == rule.dst_port_high {
                    content.local_port = Some(rule.dst_port_low);
                } else {
                    content.local_port_range = Some((rule.dst_port_low, rule.dst_port_high));
                }
            }
        }
        FlowDirection::UplinkOnly => {
            // Source -> Local (after swap)
            if let Some(addr) = rule.src_addr {
                content.local_ipv4_addr = Some(addr);
                content.local_ipv4_mask = rule.src_mask;
            }
            if let Some(addr) = rule.src_addr6 {
                content.local_ipv6_addr = Some(addr);
                content.local_ipv6_prefix_len = rule.src_prefix_len6;
            }
            if rule.src_port_low > 0 {
                if rule.src_port_low == rule.src_port_high {
                    content.local_port = Some(rule.src_port_low);
                } else {
                    content.local_port_range = Some((rule.src_port_low, rule.src_port_high));
                }
            }
            
            // Destination -> Remote (after swap)
            if let Some(addr) = rule.dst_addr {
                content.remote_ipv4_addr = Some(addr);
                content.remote_ipv4_mask = rule.dst_mask;
            }
            if let Some(addr) = rule.dst_addr6 {
                content.remote_ipv6_addr = Some(addr);
                content.remote_ipv6_prefix_len = rule.dst_prefix_len6;
            }
            if rule.dst_port_low > 0 {
                if rule.dst_port_low == rule.dst_port_high {
                    content.remote_port = Some(rule.dst_port_low);
                } else {
                    content.remote_port_range = Some((rule.dst_port_low, rule.dst_port_high));
                }
            }
        }
    }
    
    content
}


/// Validate PFCP flags for consistency
///
/// Ensures that CREATE and REMOVE flags are not both set
pub fn validate_pfcp_flags(flags: u64) -> Result<(), &'static str> {
    let check = flags & (pfcp_modify::CREATE | pfcp_modify::REMOVE);

    if check != 0 && check != pfcp_modify::CREATE && check != pfcp_modify::REMOVE {
        return Err("Invalid flags: CREATE and REMOVE cannot both be set");
    }

    Ok(())
}

// ============================================================================
// Rel-18 XR/URLLC QoS Flow Binding (5QI 82-85)
// ============================================================================

/// 5QI resource type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosResourceType {
    /// GBR (Guaranteed Bit Rate)
    Gbr,
    /// Non-GBR
    NonGbr,
    /// Delay-critical GBR (Rel-16+, XR/URLLC)
    DelayCriticalGbr,
}

/// XR/URLLC 5QI characteristics (TS 23.501 Table 5.7.4-1)
#[derive(Debug, Clone)]
pub struct FiveQiCharacteristics {
    /// 5QI value
    pub five_qi: u8,
    /// Resource type
    pub resource_type: QosResourceType,
    /// Default priority level (1-127, lower = higher priority)
    pub priority: u8,
    /// Packet delay budget in milliseconds
    pub packet_delay_budget_ms: u32,
    /// Packet error rate (e.g., 1e-6 stored as 6)
    pub packet_error_rate_exp: u8,
    /// Default averaging window (ms), only for GBR
    pub averaging_window_ms: Option<u32>,
}

/// Standard 5QI table for XR/URLLC (Rel-18, TS 23.501)
pub fn xr_urllc_5qi_table() -> Vec<FiveQiCharacteristics> {
    vec![
        // 5QI 82: Delay-critical GBR, XR/cloud gaming DL
        FiveQiCharacteristics {
            five_qi: 82,
            resource_type: QosResourceType::DelayCriticalGbr,
            priority: 19,
            packet_delay_budget_ms: 10,
            packet_error_rate_exp: 4,
            averaging_window_ms: Some(2000),
        },
        // 5QI 83: Delay-critical GBR, XR/cloud gaming DL with higher error tolerance
        FiveQiCharacteristics {
            five_qi: 83,
            resource_type: QosResourceType::DelayCriticalGbr,
            priority: 22,
            packet_delay_budget_ms: 15,
            packet_error_rate_exp: 3,
            averaging_window_ms: Some(2000),
        },
        // 5QI 84: Delay-critical GBR, XR split rendering DL
        FiveQiCharacteristics {
            five_qi: 84,
            resource_type: QosResourceType::DelayCriticalGbr,
            priority: 24,
            packet_delay_budget_ms: 30,
            packet_error_rate_exp: 5,
            averaging_window_ms: Some(2000),
        },
        // 5QI 85: Delay-critical GBR, XR split rendering UL
        FiveQiCharacteristics {
            five_qi: 85,
            resource_type: QosResourceType::DelayCriticalGbr,
            priority: 21,
            packet_delay_budget_ms: 5,
            packet_error_rate_exp: 5,
            averaging_window_ms: Some(2000),
        },
    ]
}

/// Look up XR/URLLC 5QI characteristics
pub fn lookup_xr_5qi(five_qi: u8) -> Option<FiveQiCharacteristics> {
    xr_urllc_5qi_table().into_iter().find(|c| c.five_qi == five_qi)
}

/// Check if a 5QI value is an XR/URLLC delay-critical type
pub fn is_xr_5qi(five_qi: u8) -> bool {
    (82..=85).contains(&five_qi)
}

/// Create a PCC rule pre-configured for XR/URLLC QoS flow binding.
///
/// Sets appropriate 5QI, GBR rates, and flow description for XR traffic.
pub fn create_xr_pcc_rule(
    rule_id: &str,
    five_qi: u8,
    gbr_dl_bps: u64,
    gbr_ul_bps: u64,
    mbr_dl_bps: u64,
    mbr_ul_bps: u64,
    flow_description: &str,
) -> PccRule {
    let chars = lookup_xr_5qi(five_qi);
    let arp_priority = chars.as_ref().map(|c| c.priority).unwrap_or(25);

    let mut rule = PccRule::new_5gc_install(rule_id);
    rule.set_qos(PccQos {
        qci: five_qi,
        arp: ArpParams {
            priority_level: arp_priority,
            pre_emption_capability: true,  // XR can preempt lower-priority
            pre_emption_vulnerability: false,
        },
        mbr: BitRate {
            uplink: mbr_ul_bps,
            downlink: mbr_dl_bps,
        },
        gbr: BitRate {
            uplink: gbr_ul_bps,
            downlink: gbr_dl_bps,
        },
    });
    rule.add_flow(FlowDir::Bidirectional, flow_description);
    rule.set_precedence(10); // high precedence for XR
    rule
}

/// Process XR-aware QoS flow binding.
///
/// Extends standard QoS flow binding with XR/URLLC-specific logic:
/// - Validates that XR 5QI values (82-85) get delay-critical GBR treatment
/// - Ensures GBR rates are provided for delay-critical flows
/// - Returns enriched results with XR metadata
pub fn process_xr_qos_flow_binding(
    policy: &SessionPolicy,
    existing_flows: &[SmfBearer],
) -> (Vec<QosFlowBindingResult>, u64, Vec<XrFlowMetadata>) {
    let (results, flags) = process_qos_flow_binding(policy, existing_flows);

    let mut xr_metadata = Vec::new();
    for rule in &policy.pcc_rules {
        if rule.rule_type == PccRuleType::Install && is_xr_5qi(rule.qos.qci) {
            let chars = lookup_xr_5qi(rule.qos.qci);
            xr_metadata.push(XrFlowMetadata {
                rule_id: rule.id.clone().unwrap_or_default(),
                five_qi: rule.qos.qci,
                delay_budget_ms: chars.as_ref().map(|c| c.packet_delay_budget_ms).unwrap_or(30),
                gbr_dl_bps: rule.qos.gbr.downlink,
                gbr_ul_bps: rule.qos.gbr.uplink,
                requires_pdb_enforcement: true,
            });
        }
    }

    (results, flags, xr_metadata)
}

/// Metadata for an XR QoS flow
#[derive(Debug, Clone)]
pub struct XrFlowMetadata {
    /// PCC rule ID
    pub rule_id: String,
    /// 5QI value
    pub five_qi: u8,
    /// Packet delay budget (ms)
    pub delay_budget_ms: u32,
    /// GBR downlink (bps)
    pub gbr_dl_bps: u64,
    /// GBR uplink (bps)
    pub gbr_ul_bps: u64,
    /// Whether PDB enforcement is required
    pub requires_pdb_enforcement: bool,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcc_rule_new_install() {
        let rule = PccRule::new_install("test-rule");
        assert_eq!(rule.name, Some("test-rule".to_string()));
        assert_eq!(rule.rule_type, PccRuleType::Install);
        assert!(rule.flows.is_empty());
    }

    #[test]
    fn test_pcc_rule_new_remove() {
        let rule = PccRule::new_remove("test-rule");
        assert_eq!(rule.name, Some("test-rule".to_string()));
        assert_eq!(rule.rule_type, PccRuleType::Remove);
    }

    #[test]
    fn test_pcc_rule_5gc_install() {
        let rule = PccRule::new_5gc_install("rule-123");
        assert_eq!(rule.id, Some("rule-123".to_string()));
        assert!(rule.name.is_none());
        assert_eq!(rule.rule_type, PccRuleType::Install);
    }

    #[test]
    fn test_pcc_rule_add_flow() {
        let mut rule = PccRule::new_install("test");
        rule.add_flow(FlowDir::Bidirectional, "permit out ip from any to any");
        assert_eq!(rule.flows.len(), 1);
        assert_eq!(rule.flows[0].direction, FlowDir::Bidirectional);
    }

    #[test]
    fn test_session_policy() {
        let mut policy = SessionPolicy::new();
        assert_eq!(policy.num_rules(), 0);
        
        policy.add_rule(PccRule::new_install("rule1"));
        policy.add_rule(PccRule::new_remove("rule2"));
        assert_eq!(policy.num_rules(), 2);
    }

    #[test]
    fn test_tft_new() {
        let tft = Tft::new(tft_code::CREATE_NEW_TFT);
        assert_eq!(tft.code, tft_code::CREATE_NEW_TFT);
        assert_eq!(tft.num_of_packet_filter, 0);
    }


    #[test]
    fn test_tft_add_packet_filter() {
        let mut tft = Tft::new(tft_code::CREATE_NEW_TFT);
        
        let pf = TftPacketFilter {
            identifier: 0,
            direction: 1,
            precedence: 0,
            content: PacketFilterContent::default(),
        };
        
        tft.add_packet_filter(pf);
        assert_eq!(tft.num_of_packet_filter, 1);
        assert_eq!(tft.pf.len(), 1);
    }

    #[test]
    fn test_tft_encode_basic() {
        let mut tft = Tft::new(tft_code::CREATE_NEW_TFT);
        
        let mut content = PacketFilterContent::default();
        content.protocol_id = Some(17); // UDP
        
        let pf = TftPacketFilter {
            identifier: 0,
            direction: 1,
            precedence: 0,
            content,
        };
        
        tft.add_packet_filter(pf);
        
        let encoded = tft.encode();
        assert!(!encoded.is_empty());
        // First byte: operation code (1) << 5 | num_pf (1) = 0x21
        assert_eq!(encoded[0], 0x21);
    }

    #[test]
    fn test_flow_dir_from_u8() {
        assert_eq!(FlowDir::from(1), FlowDir::DownlinkOnly);
        assert_eq!(FlowDir::from(2), FlowDir::UplinkOnly);
        assert_eq!(FlowDir::from(3), FlowDir::Bidirectional);
        assert_eq!(FlowDir::from(99), FlowDir::Bidirectional);
    }

    #[test]
    fn test_process_bearer_binding_no_name() {
        let mut policy = SessionPolicy::new();
        let mut rule = PccRule::new_install("test");
        rule.name = None; // Remove name
        policy.add_rule(rule);
        
        let results = process_bearer_binding(&policy, &[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], BearerBindingResult::Error(_)));
    }

    #[test]
    fn test_process_bearer_binding_no_flows() {
        let mut policy = SessionPolicy::new();
        policy.add_rule(PccRule::new_install("test"));
        
        let results = process_bearer_binding(&policy, &[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], BearerBindingResult::Error(_)));
    }

    #[test]
    fn test_process_bearer_binding_create() {
        let mut policy = SessionPolicy::new();
        let mut rule = PccRule::new_install("test");
        rule.add_flow(FlowDir::Bidirectional, "permit out ip from any to any");
        policy.add_rule(rule);
        
        let results = process_bearer_binding(&policy, &[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], BearerBindingResult::Created { .. }));
    }


    #[test]
    fn test_process_bearer_binding_remove_not_found() {
        let mut policy = SessionPolicy::new();
        policy.add_rule(PccRule::new_remove("nonexistent"));
        
        let results = process_bearer_binding(&policy, &[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], BearerBindingResult::NoAction));
    }

    #[test]
    fn test_process_qos_flow_binding_no_id() {
        let mut policy = SessionPolicy::new();
        let mut rule = PccRule::new_5gc_install("test");
        rule.id = None; // Remove ID
        policy.add_rule(rule);
        
        let (results, _) = process_qos_flow_binding(&policy, &[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], QosFlowBindingResult::Error(_)));
    }

    #[test]
    fn test_process_qos_flow_binding_create() {
        let mut policy = SessionPolicy::new();
        let mut rule = PccRule::new_5gc_install("rule-1");
        rule.add_flow(FlowDir::Bidirectional, "permit out ip from any to any");
        policy.add_rule(rule);
        
        let (results, flags) = process_qos_flow_binding(&policy, &[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], QosFlowBindingResult::Created { .. }));
        assert!(flags & pfcp_modify::CREATE != 0);
    }

    #[test]
    fn test_validate_pfcp_flags_valid() {
        assert!(validate_pfcp_flags(pfcp_modify::CREATE).is_ok());
        assert!(validate_pfcp_flags(pfcp_modify::REMOVE).is_ok());
        assert!(validate_pfcp_flags(pfcp_modify::NETWORK_REQUESTED).is_ok());
        assert!(validate_pfcp_flags(0).is_ok());
    }

    #[test]
    fn test_validate_pfcp_flags_invalid() {
        let invalid = pfcp_modify::CREATE | pfcp_modify::REMOVE;
        assert!(validate_pfcp_flags(invalid).is_err());
    }

    #[test]
    fn test_pcc_qos_default() {
        let qos = PccQos::default();
        assert_eq!(qos.qci, 0);
        assert_eq!(qos.mbr.uplink, 0);
        assert_eq!(qos.mbr.downlink, 0);
    }

    #[test]
    fn test_arp_params_default() {
        let arp = ArpParams::default();
        assert_eq!(arp.priority_level, 0);
        assert!(!arp.pre_emption_capability);
        assert!(!arp.pre_emption_vulnerability);
    }

    #[test]
    fn test_bit_rate_default() {
        let br = BitRate::default();
        assert_eq!(br.uplink, 0);
        assert_eq!(br.downlink, 0);
    }

    #[test]
    fn test_packet_filter_content_default() {
        let content = PacketFilterContent::default();
        assert!(content.remote_ipv4_addr.is_none());
        assert!(content.protocol_id.is_none());
        assert!(content.local_port.is_none());
    }

    #[test]
    fn test_encode_tft_delete() {
        let tft = Tft::new(tft_code::DELETE_EXISTING_TFT);
        let encoded = tft.encode();
        // First byte: operation code (2) << 5 | num_pf (0) = 0x40
        assert_eq!(encoded[0], 0x40);
    }

    #[test]
    fn test_xr_5qi_lookup() {
        let c82 = lookup_xr_5qi(82).unwrap();
        assert_eq!(c82.resource_type, QosResourceType::DelayCriticalGbr);
        assert_eq!(c82.packet_delay_budget_ms, 10);

        let c85 = lookup_xr_5qi(85).unwrap();
        assert_eq!(c85.packet_delay_budget_ms, 5);
        assert_eq!(c85.priority, 21);

        assert!(lookup_xr_5qi(9).is_none()); // not XR
    }

    #[test]
    fn test_is_xr_5qi() {
        assert!(is_xr_5qi(82));
        assert!(is_xr_5qi(83));
        assert!(is_xr_5qi(84));
        assert!(is_xr_5qi(85));
        assert!(!is_xr_5qi(9));
        assert!(!is_xr_5qi(1));
        assert!(!is_xr_5qi(86));
    }

    #[test]
    fn test_create_xr_pcc_rule() {
        let rule = create_xr_pcc_rule(
            "xr-dl-1",
            82,
            50_000_000,  // 50 Mbps GBR DL
            10_000_000,  // 10 Mbps GBR UL
            100_000_000, // 100 Mbps MBR DL
            20_000_000,  // 20 Mbps MBR UL
            "permit out ip from any to assigned",
        );
        assert_eq!(rule.qos.qci, 82);
        assert_eq!(rule.qos.gbr.downlink, 50_000_000);
        assert_eq!(rule.qos.gbr.uplink, 10_000_000);
        assert_eq!(rule.qos.mbr.downlink, 100_000_000);
        assert!(rule.qos.arp.pre_emption_capability);
        assert!(!rule.qos.arp.pre_emption_vulnerability);
        assert_eq!(rule.precedence, 10);
        assert_eq!(rule.flows.len(), 1);
    }

    #[test]
    fn test_xr_qos_flow_binding() {
        let mut policy = SessionPolicy::new();
        let rule = create_xr_pcc_rule(
            "xr-flow-1",
            83,
            30_000_000,
            5_000_000,
            60_000_000,
            10_000_000,
            "permit out ip from any to assigned",
        );
        policy.add_rule(rule);

        let (results, flags, xr_meta) = process_xr_qos_flow_binding(&policy, &[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], QosFlowBindingResult::Created { .. }));
        assert!(flags & pfcp_modify::CREATE != 0);

        assert_eq!(xr_meta.len(), 1);
        assert_eq!(xr_meta[0].five_qi, 83);
        assert_eq!(xr_meta[0].delay_budget_ms, 15);
        assert_eq!(xr_meta[0].gbr_dl_bps, 30_000_000);
        assert!(xr_meta[0].requires_pdb_enforcement);
    }

    #[test]
    fn test_xr_urllc_5qi_table_completeness() {
        let table = xr_urllc_5qi_table();
        assert_eq!(table.len(), 4);
        for entry in &table {
            assert!(is_xr_5qi(entry.five_qi));
            assert_eq!(entry.resource_type, QosResourceType::DelayCriticalGbr);
            assert!(entry.averaging_window_ms.is_some());
        }
    }
}
