//! GSM (5G Session Management) Message Building

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//!
//! Port of src/smf/gsm-build.c - GSM message building functions for 5G NAS

use crate::context::{FlowDirection, SmfBearer, SmfPf, SmfSess};
use bytes::{BufMut, BytesMut};

// ============================================================================
// Constants
// ============================================================================

/// Extended protocol discriminator for 5GSM
pub const NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM: u8 = 0x2e;

/// 5GSM message types
pub mod message_type {
    pub const PDU_SESSION_ESTABLISHMENT_REQUEST: u8 = 0xc1;
    pub const PDU_SESSION_ESTABLISHMENT_ACCEPT: u8 = 0xc2;
    pub const PDU_SESSION_ESTABLISHMENT_REJECT: u8 = 0xc3;
    pub const PDU_SESSION_AUTHENTICATION_COMMAND: u8 = 0xc5;
    pub const PDU_SESSION_AUTHENTICATION_COMPLETE: u8 = 0xc6;
    pub const PDU_SESSION_AUTHENTICATION_RESULT: u8 = 0xc7;
    pub const PDU_SESSION_MODIFICATION_REQUEST: u8 = 0xc9;
    pub const PDU_SESSION_MODIFICATION_REJECT: u8 = 0xca;
    pub const PDU_SESSION_MODIFICATION_COMMAND: u8 = 0xcb;
    pub const PDU_SESSION_MODIFICATION_COMPLETE: u8 = 0xcc;
    pub const PDU_SESSION_MODIFICATION_COMMAND_REJECT: u8 = 0xcd;
    pub const PDU_SESSION_RELEASE_REQUEST: u8 = 0xd1;
    pub const PDU_SESSION_RELEASE_REJECT: u8 = 0xd2;
    pub const PDU_SESSION_RELEASE_COMMAND: u8 = 0xd3;
    pub const PDU_SESSION_RELEASE_COMPLETE: u8 = 0xd4;
    pub const GSM_STATUS: u8 = 0xd6;
}

/// QoS rule operation codes
pub mod qos_rule_code {
    pub const CREATE_NEW_QOS_RULE: u8 = 1;
    pub const DELETE_EXISTING_QOS_RULE: u8 = 2;
    pub const MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS: u8 = 3;
    pub const MODIFY_EXISTING_QOS_RULE_AND_REPLACE_PACKET_FILTERS: u8 = 4;
    pub const MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS: u8 = 5;
    pub const MODIFY_EXISTING_QOS_RULE_WITHOUT_MODIFYING_PACKET_FILTERS: u8 = 6;
}

/// QoS flow description operation codes
pub mod qos_flow_description_code {
    pub const CREATE_NEW_QOS_FLOW_DESCRIPTION: u8 = 1;
    pub const DELETE_NEW_QOS_FLOW_DESCRIPTION: u8 = 2;
    pub const MODIFY_NEW_QOS_FLOW_DESCRIPTION: u8 = 3;
}

/// QoS flow parameter identifiers
pub mod qos_flow_param_id {
    pub const FIVE_QI: u8 = 0x01;
    pub const GFBR_UPLINK: u8 = 0x02;
    pub const GFBR_DOWNLINK: u8 = 0x03;
    pub const MFBR_UPLINK: u8 = 0x04;
    pub const MFBR_DOWNLINK: u8 = 0x05;
    pub const AVERAGING_WINDOW: u8 = 0x06;
    pub const EPS_BEARER_IDENTITY: u8 = 0x07;
}

/// Packet filter direction
pub mod pf_direction {
    pub const DOWNLINK_ONLY: u8 = 0x01;
    pub const UPLINK_ONLY: u8 = 0x02;
    pub const BIDIRECTIONAL: u8 = 0x03;
}

/// Packet filter component types
pub mod pf_component_type {
    pub const MATCH_ALL: u8 = 0x01;
    pub const IPV4_REMOTE_ADDRESS: u8 = 0x10;
    pub const IPV4_LOCAL_ADDRESS: u8 = 0x11;
    pub const IPV6_REMOTE_ADDRESS: u8 = 0x21;
    pub const IPV6_LOCAL_ADDRESS: u8 = 0x23;
    pub const PROTOCOL_IDENTIFIER: u8 = 0x30;
    pub const SINGLE_LOCAL_PORT: u8 = 0x40;
    pub const LOCAL_PORT_RANGE: u8 = 0x41;
    pub const SINGLE_REMOTE_PORT: u8 = 0x50;
    pub const REMOTE_PORT_RANGE: u8 = 0x51;
    pub const SECURITY_PARAMETER_INDEX: u8 = 0x60;
    pub const TYPE_OF_SERVICE: u8 = 0x70;
    pub const FLOW_LABEL: u8 = 0x80;
    pub const DESTINATION_MAC_ADDRESS: u8 = 0x81;
    pub const SOURCE_MAC_ADDRESS: u8 = 0x82;
    pub const EIGHT02_1Q_C_TAG_VID: u8 = 0x83;
    pub const EIGHT02_1Q_S_TAG_VID: u8 = 0x84;
    pub const EIGHT02_1Q_C_TAG_PCP_DEI: u8 = 0x85;
    pub const EIGHT02_1Q_S_TAG_PCP_DEI: u8 = 0x86;
    pub const ETHERTYPE: u8 = 0x87;
}

/// PDU session types
pub mod pdu_session_type {
    pub const IPV4: u8 = 1;
    pub const IPV6: u8 = 2;
    pub const IPV4V6: u8 = 3;
    pub const UNSTRUCTURED: u8 = 4;
    pub const ETHERNET: u8 = 5;
}

/// 5GSM cause codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GsmCause {
    OperatorDeterminedBarring = 8,
    InsufficientResources = 26,
    MissingOrUnknownDnn = 27,
    UnknownPduSessionType = 28,
    UserAuthenticationOrAuthorizationFailed = 29,
    RequestRejectedUnspecified = 31,
    ServiceOptionNotSupported = 32,
    RequestedServiceOptionNotSubscribed = 33,
    PtiAlreadyInUse = 35,
    RegularDeactivation = 36,
    NetworkFailure = 38,
    ReactivationRequested = 39,
    InvalidPduSessionIdentity = 43,
    SemanticErrorsInPacketFilters = 44,
    SyntacticalErrorsInPacketFilters = 45,
    OutOfLadn = 46,
    PtiMismatch = 47,
    PduSessionTypeIpv4OnlyAllowed = 50,
    PduSessionTypeIpv6OnlyAllowed = 51,
    PduSessionDoesNotExist = 54,
    PduSessionTypeIpv4v6OnlyAllowed = 57,
    PduSessionTypeUnstructuredOnlyAllowed = 58,
    UnsupportedFiveQiValue = 59,
    PduSessionTypeEthernetOnlyAllowed = 61,
    InsufficientResourcesForSpecificSliceAndDnn = 67,
    NotSupportedSscMode = 68,
    InsufficientResourcesForSpecificSlice = 69,
    MissingOrUnknownDnnInASlice = 70,
    InvalidPtiValue = 81,
    MaximumDataRatePerUeForUserPlaneIntegrityProtectionIsTooLow = 82,
    SemanticErrorInTheQosOperation = 83,
    SyntacticalErrorInTheQosOperation = 84,
    InvalidMappedEpsBearerIdentity = 85,
    SemanticallyIncorrectMessage = 95,
    InvalidMandatoryInformation = 96,
    MessageTypeNonExistentOrNotImplemented = 97,
    MessageTypeNotCompatibleWithTheProtocolState = 98,
    InformationElementNonExistentOrNotImplemented = 99,
    ConditionalIeError = 100,
    MessageNotCompatibleWithTheProtocolState = 101,
    ProtocolErrorUnspecified = 111,
}

impl From<u8> for GsmCause {
    fn from(value: u8) -> Self {
        match value {
            8 => GsmCause::OperatorDeterminedBarring,
            26 => GsmCause::InsufficientResources,
            27 => GsmCause::MissingOrUnknownDnn,
            28 => GsmCause::UnknownPduSessionType,
            29 => GsmCause::UserAuthenticationOrAuthorizationFailed,
            31 => GsmCause::RequestRejectedUnspecified,
            32 => GsmCause::ServiceOptionNotSupported,
            33 => GsmCause::RequestedServiceOptionNotSubscribed,
            35 => GsmCause::PtiAlreadyInUse,
            36 => GsmCause::RegularDeactivation,
            38 => GsmCause::NetworkFailure,
            39 => GsmCause::ReactivationRequested,
            43 => GsmCause::InvalidPduSessionIdentity,
            44 => GsmCause::SemanticErrorsInPacketFilters,
            45 => GsmCause::SyntacticalErrorsInPacketFilters,
            46 => GsmCause::OutOfLadn,
            47 => GsmCause::PtiMismatch,
            50 => GsmCause::PduSessionTypeIpv4OnlyAllowed,
            51 => GsmCause::PduSessionTypeIpv6OnlyAllowed,
            54 => GsmCause::PduSessionDoesNotExist,
            57 => GsmCause::PduSessionTypeIpv4v6OnlyAllowed,
            58 => GsmCause::PduSessionTypeUnstructuredOnlyAllowed,
            59 => GsmCause::UnsupportedFiveQiValue,
            61 => GsmCause::PduSessionTypeEthernetOnlyAllowed,
            67 => GsmCause::InsufficientResourcesForSpecificSliceAndDnn,
            68 => GsmCause::NotSupportedSscMode,
            69 => GsmCause::InsufficientResourcesForSpecificSlice,
            70 => GsmCause::MissingOrUnknownDnnInASlice,
            81 => GsmCause::InvalidPtiValue,
            82 => GsmCause::MaximumDataRatePerUeForUserPlaneIntegrityProtectionIsTooLow,
            83 => GsmCause::SemanticErrorInTheQosOperation,
            84 => GsmCause::SyntacticalErrorInTheQosOperation,
            85 => GsmCause::InvalidMappedEpsBearerIdentity,
            95 => GsmCause::SemanticallyIncorrectMessage,
            96 => GsmCause::InvalidMandatoryInformation,
            97 => GsmCause::MessageTypeNonExistentOrNotImplemented,
            98 => GsmCause::MessageTypeNotCompatibleWithTheProtocolState,
            99 => GsmCause::InformationElementNonExistentOrNotImplemented,
            100 => GsmCause::ConditionalIeError,
            101 => GsmCause::MessageNotCompatibleWithTheProtocolState,
            _ => GsmCause::ProtocolErrorUnspecified,
        }
    }
}

// ============================================================================
// QoS Rule Structure
// ============================================================================

/// Packet filter content component
#[derive(Debug, Clone, Default)]
pub struct PacketFilterComponent {
    pub component_type: u8,
    pub data: Vec<u8>,
}

/// Packet filter content
#[derive(Debug, Clone, Default)]
pub struct PacketFilterContent {
    pub components: Vec<PacketFilterComponent>,
}

/// Packet filter in QoS rule
#[derive(Debug, Clone, Default)]
pub struct QosRulePacketFilter {
    pub direction: u8,
    pub identifier: u8,
    pub content: PacketFilterContent,
}

/// QoS rule structure
#[derive(Debug, Clone, Default)]
pub struct QosRule {
    pub identifier: u8,
    pub code: u8,
    pub dqr_bit: bool,
    pub packet_filters: Vec<QosRulePacketFilter>,
    pub precedence: u8,
    pub segregation: bool,
    pub qfi: u8,
}

/// QoS flow description parameter
#[derive(Debug, Clone, Default)]
pub struct QosFlowParam {
    pub identifier: u8,
    pub data: Vec<u8>,
}

/// QoS flow description
#[derive(Debug, Clone, Default)]
pub struct QosFlowDescription {
    pub identifier: u8,
    pub code: u8,
    pub e_bit: bool,
    pub params: Vec<QosFlowParam>,
}

// ============================================================================
// NAS Message Builder
// ============================================================================

/// NAS message builder for 5GSM messages
#[derive(Debug)]
pub struct GsmMessageBuilder {
    buffer: BytesMut,
}

impl GsmMessageBuilder {
    /// Create a new GSM message builder
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(1024),
        }
    }

    /// Create a new GSM message builder with header
    pub fn with_header(psi: u8, pti: u8, message_type: u8) -> Self {
        let mut builder = Self::new();
        builder
            .buffer
            .put_u8(NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM);
        builder.buffer.put_u8(psi);
        builder.buffer.put_u8(pti);
        builder.buffer.put_u8(message_type);
        builder
    }

    /// Write a single byte
    pub fn write_u8(&mut self, value: u8) -> &mut Self {
        self.buffer.put_u8(value);
        self
    }

    /// Write two bytes (big endian)
    pub fn write_u16(&mut self, value: u16) -> &mut Self {
        self.buffer.put_u16(value);
        self
    }

    /// Write four bytes (big endian)
    pub fn write_u32(&mut self, value: u32) -> &mut Self {
        self.buffer.put_u32(value);
        self
    }

    /// Write bytes
    pub fn write_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.put_slice(data);
        self
    }

    /// Write length-value pair (1-byte length)
    pub fn write_lv(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.put_u8(data.len() as u8);
        self.buffer.put_slice(data);
        self
    }

    /// Write length-value pair (2-byte length)
    pub fn write_lv_e(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.put_u16(data.len() as u16);
        self.buffer.put_slice(data);
        self
    }

    /// Write type-length-value triplet (1-byte length)
    pub fn write_tlv(&mut self, iei: u8, data: &[u8]) -> &mut Self {
        self.buffer.put_u8(iei);
        self.buffer.put_u8(data.len() as u8);
        self.buffer.put_slice(data);
        self
    }

    /// Write type-length-value triplet (2-byte length)
    pub fn write_tlv_e(&mut self, iei: u8, data: &[u8]) -> &mut Self {
        self.buffer.put_u8(iei);
        self.buffer.put_u16(data.len() as u16);
        self.buffer.put_slice(data);
        self
    }

    /// Build the message and return the buffer
    pub fn build(self) -> Vec<u8> {
        self.buffer.to_vec()
    }

    /// Get current buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for GsmMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// QoS Rule Encoding
// ============================================================================

/// Encode QoS rules to bytes
pub fn encode_qos_rules(rules: &[QosRule]) -> Vec<u8> {
    let mut buffer = BytesMut::with_capacity(256);

    for rule in rules {
        let rule_bytes = encode_single_qos_rule(rule);
        buffer.put_slice(&rule_bytes);
    }

    buffer.to_vec()
}

/// Encode a single QoS rule
fn encode_single_qos_rule(rule: &QosRule) -> Vec<u8> {
    let mut buffer = BytesMut::with_capacity(64);

    // QoS rule identifier
    buffer.put_u8(rule.identifier);

    // Length placeholder - will be filled later
    let length_pos = buffer.len();
    buffer.put_u16(0);

    // Rule operation code (3 bits) + DQR (1 bit) + number of packet filters (4 bits)
    let num_pf = rule.packet_filters.len().min(15) as u8;
    let first_byte =
        ((rule.code & 0x07) << 5) | (if rule.dqr_bit { 0x10 } else { 0 }) | (num_pf & 0x0f);
    buffer.put_u8(first_byte);

    // Packet filters
    for pf in &rule.packet_filters {
        // Direction (2 bits) + identifier (4 bits)
        let pf_header = ((pf.direction & 0x03) << 4) | (pf.identifier & 0x0f);
        buffer.put_u8(pf_header);

        // Packet filter content
        let content_bytes = encode_packet_filter_content(&pf.content);
        buffer.put_u8(content_bytes.len() as u8);
        buffer.put_slice(&content_bytes);
    }

    // QoS rule precedence (if not delete operation)
    if rule.code != qos_rule_code::DELETE_EXISTING_QOS_RULE
        && rule.code != qos_rule_code::MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS
        && rule.code != qos_rule_code::MODIFY_EXISTING_QOS_RULE_WITHOUT_MODIFYING_PACKET_FILTERS
    {
        buffer.put_u8(rule.precedence);

        // QoS flow identifier (segregation bit + QFI)
        let qfi_byte = (if rule.segregation { 0x40 } else { 0 }) | (rule.qfi & 0x3f);
        buffer.put_u8(qfi_byte);
    }

    // Update length field
    let total_len = buffer.len() - length_pos - 2;
    let mut result = buffer.to_vec();
    result[length_pos] = ((total_len >> 8) & 0xff) as u8;
    result[length_pos + 1] = (total_len & 0xff) as u8;

    result
}

/// Encode packet filter content
fn encode_packet_filter_content(content: &PacketFilterContent) -> Vec<u8> {
    let mut buffer = BytesMut::with_capacity(32);

    for component in &content.components {
        buffer.put_u8(component.component_type);
        buffer.put_slice(&component.data);
    }

    buffer.to_vec()
}

/// Encode QoS flow descriptions to bytes
pub fn encode_qos_flow_descriptions(descriptions: &[QosFlowDescription]) -> Vec<u8> {
    let mut buffer = BytesMut::with_capacity(256);

    for desc in descriptions {
        let desc_bytes = encode_single_qos_flow_description(desc);
        buffer.put_slice(&desc_bytes);
    }

    buffer.to_vec()
}

/// Encode a single QoS flow description
fn encode_single_qos_flow_description(desc: &QosFlowDescription) -> Vec<u8> {
    let mut buffer = BytesMut::with_capacity(32);

    // QFI
    buffer.put_u8(desc.identifier);

    // Operation code (3 bits) + spare (1 bit) + E bit (1 bit) + num params (3 bits)
    let num_params = desc.params.len().min(7) as u8;
    let second_byte =
        ((desc.code & 0x07) << 5) | (if desc.e_bit { 0x08 } else { 0 }) | (num_params & 0x07);
    buffer.put_u8(second_byte);

    // Parameters
    if desc.e_bit {
        for param in &desc.params {
            buffer.put_u8(param.identifier);
            buffer.put_u8(param.data.len() as u8);
            buffer.put_slice(&param.data);
        }
    }

    buffer.to_vec()
}

// ============================================================================
// Default QoS Rule/Flow Encoding
// ============================================================================

/// Encode default QoS rule for a QoS flow
pub fn encode_default_qos_rule(qos_flow: &SmfBearer) -> QosRule {
    let mut rule = QosRule {
        identifier: qos_flow.qfi,
        code: qos_rule_code::CREATE_NEW_QOS_RULE,
        dqr_bit: true,
        precedence: 255, // Lowest precedence
        segregation: false,
        qfi: qos_flow.qfi,
        ..Default::default()
    };

    // Add match-all packet filter
    let pf = QosRulePacketFilter {
        direction: pf_direction::BIDIRECTIONAL,
        identifier: 1,
        content: PacketFilterContent {
            components: vec![PacketFilterComponent {
                component_type: pf_component_type::MATCH_ALL,
                data: vec![],
            }],
        },
    };
    rule.packet_filters.push(pf);

    rule
}

/// Encode default QoS flow description
pub fn encode_default_qos_flow_description(qos_flow: &SmfBearer) -> QosFlowDescription {
    let mut desc = QosFlowDescription {
        identifier: qos_flow.qfi,
        code: qos_flow_description_code::CREATE_NEW_QOS_FLOW_DESCRIPTION,
        e_bit: true,
        ..Default::default()
    };

    // Add 5QI parameter
    desc.params.push(QosFlowParam {
        identifier: qos_flow_param_id::FIVE_QI,
        data: vec![qos_flow.qos.index],
    });

    desc
}

/// Encode QoS rule with packet filters from bearer
pub fn encode_qos_rule(qos_flow: &SmfBearer, code: u8, pfs: &[SmfPf]) -> QosRule {
    let mut rule = QosRule {
        identifier: qos_flow.qfi,
        code,
        dqr_bit: false,
        precedence: 128, // Default precedence
        segregation: false,
        qfi: qos_flow.qfi,
        ..Default::default()
    };

    // Add packet filters based on operation code
    if code != qos_rule_code::DELETE_EXISTING_QOS_RULE
        && code != qos_rule_code::MODIFY_EXISTING_QOS_RULE_WITHOUT_MODIFYING_PACKET_FILTERS
    {
        for pf in pfs {
            let direction = match pf.direction {
                FlowDirection::DownlinkOnly => pf_direction::DOWNLINK_ONLY,
                FlowDirection::UplinkOnly => pf_direction::UPLINK_ONLY,
                FlowDirection::Bidirectional => pf_direction::BIDIRECTIONAL,
            };

            let qos_pf = QosRulePacketFilter {
                direction,
                identifier: pf.identifier,
                content: encode_ipfw_rule_to_content(&pf.ipfw_rule),
            };
            rule.packet_filters.push(qos_pf);
        }
    }

    rule
}

/// Encode IPFW rule to packet filter content
fn encode_ipfw_rule_to_content(ipfw: &crate::context::IpfwRule) -> PacketFilterContent {
    let mut content = PacketFilterContent::default();

    // Protocol
    if ipfw.proto != 0 {
        content.components.push(PacketFilterComponent {
            component_type: pf_component_type::PROTOCOL_IDENTIFIER,
            data: vec![ipfw.proto],
        });
    }

    // Source address
    if let Some(addr) = ipfw.src_addr {
        let mut data = addr.octets().to_vec();
        if let Some(mask) = ipfw.src_mask {
            data.extend_from_slice(&mask.octets());
        } else {
            data.extend_from_slice(&[255, 255, 255, 255]);
        }
        content.components.push(PacketFilterComponent {
            component_type: pf_component_type::IPV4_REMOTE_ADDRESS,
            data,
        });
    }

    // Destination address
    if let Some(addr) = ipfw.dst_addr {
        let mut data = addr.octets().to_vec();
        if let Some(mask) = ipfw.dst_mask {
            data.extend_from_slice(&mask.octets());
        } else {
            data.extend_from_slice(&[255, 255, 255, 255]);
        }
        content.components.push(PacketFilterComponent {
            component_type: pf_component_type::IPV4_LOCAL_ADDRESS,
            data,
        });
    }

    // Source port range
    if ipfw.src_port_low != 0 || ipfw.src_port_high != 0 {
        if ipfw.src_port_low == ipfw.src_port_high {
            content.components.push(PacketFilterComponent {
                component_type: pf_component_type::SINGLE_REMOTE_PORT,
                data: ipfw.src_port_low.to_be_bytes().to_vec(),
            });
        } else {
            let mut data = ipfw.src_port_low.to_be_bytes().to_vec();
            data.extend_from_slice(&ipfw.src_port_high.to_be_bytes());
            content.components.push(PacketFilterComponent {
                component_type: pf_component_type::REMOTE_PORT_RANGE,
                data,
            });
        }
    }

    // Destination port range
    if ipfw.dst_port_low != 0 || ipfw.dst_port_high != 0 {
        if ipfw.dst_port_low == ipfw.dst_port_high {
            content.components.push(PacketFilterComponent {
                component_type: pf_component_type::SINGLE_LOCAL_PORT,
                data: ipfw.dst_port_low.to_be_bytes().to_vec(),
            });
        } else {
            let mut data = ipfw.dst_port_low.to_be_bytes().to_vec();
            data.extend_from_slice(&ipfw.dst_port_high.to_be_bytes());
            content.components.push(PacketFilterComponent {
                component_type: pf_component_type::LOCAL_PORT_RANGE,
                data,
            });
        }
    }

    // If no components, add match-all
    if content.components.is_empty() {
        content.components.push(PacketFilterComponent {
            component_type: pf_component_type::MATCH_ALL,
            data: vec![],
        });
    }

    content
}

/// Encode QoS flow description with full parameters
pub fn encode_qos_flow_description(qos_flow: &SmfBearer, code: u8) -> QosFlowDescription {
    let mut desc = QosFlowDescription {
        identifier: qos_flow.qfi,
        code,
        e_bit: code != qos_flow_description_code::DELETE_NEW_QOS_FLOW_DESCRIPTION,
        ..Default::default()
    };

    if code != qos_flow_description_code::DELETE_NEW_QOS_FLOW_DESCRIPTION {
        // 5QI
        desc.params.push(QosFlowParam {
            identifier: qos_flow_param_id::FIVE_QI,
            data: vec![qos_flow.qos.index],
        });

        // GBR uplink
        if qos_flow.qos.gbr_uplink > 0 {
            desc.params.push(QosFlowParam {
                identifier: qos_flow_param_id::GFBR_UPLINK,
                data: encode_bitrate(qos_flow.qos.gbr_uplink),
            });
        }

        // GBR downlink
        if qos_flow.qos.gbr_downlink > 0 {
            desc.params.push(QosFlowParam {
                identifier: qos_flow_param_id::GFBR_DOWNLINK,
                data: encode_bitrate(qos_flow.qos.gbr_downlink),
            });
        }

        // MBR uplink
        if qos_flow.qos.mbr_uplink > 0 {
            desc.params.push(QosFlowParam {
                identifier: qos_flow_param_id::MFBR_UPLINK,
                data: encode_bitrate(qos_flow.qos.mbr_uplink),
            });
        }

        // MBR downlink
        if qos_flow.qos.mbr_downlink > 0 {
            desc.params.push(QosFlowParam {
                identifier: qos_flow_param_id::MFBR_DOWNLINK,
                data: encode_bitrate(qos_flow.qos.mbr_downlink),
            });
        }
    }

    desc
}

/// Encode bitrate to NAS format (unit + value)
fn encode_bitrate(bitrate: u64) -> Vec<u8> {
    // NAS bitrate encoding: 1 byte unit + 2 bytes value
    // Unit: 0=1kbps, 1=4kbps, 2=16kbps, 3=64kbps, 4=256kbps, 5=1Mbps, 6=4Mbps, 7=16Mbps, etc.
    let (unit, value) = if bitrate == 0 {
        (0u8, 0u16)
    } else if bitrate <= 65535 * 1000 {
        (0, (bitrate / 1000) as u16)
    } else if bitrate <= 65535 * 4000 {
        (1, (bitrate / 4000) as u16)
    } else if bitrate <= 65535 * 16000 {
        (2, (bitrate / 16000) as u16)
    } else if bitrate <= 65535 * 64000 {
        (3, (bitrate / 64000) as u16)
    } else if bitrate <= 65535 * 256000 {
        (4, (bitrate / 256000) as u16)
    } else if bitrate <= 65535 * 1000000 {
        (5, (bitrate / 1000000) as u16)
    } else if bitrate <= 65535 * 4000000 {
        (6, (bitrate / 4000000) as u16)
    } else if bitrate <= 65535 * 16000000 {
        (7, (bitrate / 16000000) as u16)
    } else {
        (7, 65535)
    };

    let mut data = vec![unit];
    data.extend_from_slice(&value.to_be_bytes());
    data
}

// ============================================================================
// GSM Message Building Functions
// ============================================================================

// ---------------------------------------------------------------------------
// Mapped EPS bearer contexts, IEI 0x75 (TS 24.501 §9.11.4.8), issue #117
// ---------------------------------------------------------------------------

/// IEI of the Mapped EPS bearer contexts IE (TS 24.501 §9.11.4.8).
pub const IEI_MAPPED_EPS_BEARER_CONTEXTS: u8 = 0x75;

/// Operation code "Create new EPS bearer" (bits 8..7 of octet 7 = `01`).
const MAPPED_EPS_OP_CREATE: u8 = 0b01 << 6;

/// E bit (bit 5 of octet 7): the parameters list is included.
const MAPPED_EPS_E_PARAMS_INCLUDED: u8 = 1 << 4;

/// EPS parameter identifier 01H — Mapped EPS QoS parameters, whose contents are
/// coded per TS 24.301 §9.9.4.3 (QCI first, bit rates optional).
const EPS_PARAM_MAPPED_EPS_QOS: u8 = 0x01;

/// Map a 5QI onto the EPS QCI that means the same thing, or `None`.
///
/// TS 23.501 Table 5.7.4-1 gives the standardised 5QI values 1..=9 the same
/// numeric QCI, which is what makes 5GS↔EPS QoS mapping possible at all for them.
/// For any other 5QI — non-standardised, or one of the higher standardised values
/// with no EPS equivalent — there is **no defined QCI**, and this returns `None`
/// so the caller omits the QoS parameter rather than inventing one. An EPS bearer
/// context with an empty parameters list is legal (the IE's 7-octet minimum is
/// exactly that case); a bearer carrying a QCI the operator never configured is
/// not, and an MME would enforce it.
pub fn qci_for_5qi(five_qi: u8) -> Option<u8> {
    (1..=9).contains(&five_qi).then_some(five_qi)
}

/// Encode the Mapped EPS bearer contexts IE **contents** for one EPS bearer.
///
/// Layout, per figures 9.11.4.8.1–9.11.4.8.3:
///
/// ```text
/// octet 4      EPS bearer identity in bits 8..5, bits 4..1 spare (zero)
/// octets 5..6  length of the mapped EPS bearer context (octet 7 onward)
/// octet 7      operation code (8..7) | spare (6) | E bit (5) | #params (4..1)
/// octets 8..u  EPS parameters list: id, length, contents — repeated
/// ```
///
/// Returns the contents only; the caller writes the IEI and the two-octet outer
/// length (`write_tlv_e` does both).
///
/// `five_qi` is mapped through [`qci_for_5qi`]; when it has no EPS equivalent the
/// parameters list is empty and the E bit is clear, which the spec permits and
/// which is honest about what this SMF knows.
pub fn encode_mapped_eps_bearer_context(ebi: u8, five_qi: u8) -> Vec<u8> {
    let mut params: Vec<u8> = Vec::new();
    let mut param_count = 0u8;
    if let Some(qci) = qci_for_5qi(five_qi) {
        // TS 24.301 §9.9.4.3: the 3-octet form of the EPS QoS IE is IEI, length
        // and QCI, so as an EPS *parameter* the contents are the QCI alone. The
        // optional bit-rate octets are omitted deliberately: octet 4 cannot be
        // included without octets 5..7, and this SMF has no per-bearer MBR/GBR to
        // put in them (the session AMBR travels in its own IE).
        params.push(EPS_PARAM_MAPPED_EPS_QOS);
        params.push(1);
        params.push(qci);
        param_count = 1;
    }

    let mut octet7 = MAPPED_EPS_OP_CREATE | (param_count & 0x0f);
    if param_count > 0 {
        octet7 |= MAPPED_EPS_E_PARAMS_INCLUDED;
    }

    // The context length covers octet 7 onward, which is why the whole IE has a
    // 7-octet minimum: IEI + 2 outer length + EBI + 2 context length + octet 7.
    let context_len = (1 + params.len()) as u16;

    let mut out = Vec::with_capacity(3 + 1 + params.len());
    out.push((ebi & 0x0f) << 4);
    out.extend_from_slice(&context_len.to_be_bytes());
    out.push(octet7);
    out.extend_from_slice(&params);
    out
}

/// Emit the Mapped EPS bearer contexts IE onto `builder` when `ebi` is set.
///
/// A single helper so the three N1 builders here and the live accept builder in
/// `policy.rs` cannot disagree about the encoding — the shape of bug where two
/// copies of one IE drift and only the unused copy is tested.
pub fn write_mapped_eps_bearer_contexts(
    builder: &mut GsmMessageBuilder,
    ebi: Option<u8>,
    five_qi: u8,
) {
    if let Some(ebi) = ebi {
        let contents = encode_mapped_eps_bearer_context(ebi, five_qi);
        builder.write_tlv_e(IEI_MAPPED_EPS_BEARER_CONTEXTS, &contents);
    }
}

/// Build PDU Session Establishment Accept message
pub fn build_pdu_session_establishment_accept(
    sess: &SmfSess,
    qos_flow: &SmfBearer,
) -> Option<Vec<u8>> {
    let mut builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_ESTABLISHMENT_ACCEPT,
    );

    // Selected PDU session type (mandatory)
    // SSC mode (3 bits) + PDU session type (3 bits)
    let session_type = match sess.session_type {
        crate::context::PduSessionType::Ipv4 => pdu_session_type::IPV4,
        crate::context::PduSessionType::Ipv6 => pdu_session_type::IPV6,
        crate::context::PduSessionType::Ipv4v6 => pdu_session_type::IPV4V6,
        crate::context::PduSessionType::Unstructured => pdu_session_type::UNSTRUCTURED,
        crate::context::PduSessionType::Ethernet => pdu_session_type::ETHERNET,
    };
    builder.write_u8(session_type);

    // Authorized QoS rules (mandatory)
    let default_rule = encode_default_qos_rule(qos_flow);
    let qos_rules_bytes = encode_qos_rules(&[default_rule]);
    builder.write_lv_e(&qos_rules_bytes);

    // Session AMBR (mandatory)
    let ambr_bytes = encode_session_ambr(sess.session_ambr.downlink, sess.session_ambr.uplink);
    builder.write_lv(&ambr_bytes);

    // PDU address (optional, IEI = 0x29)
    if let Some(addr) = sess.ipv4_addr {
        let mut pdu_addr = vec![pdu_session_type::IPV4];
        pdu_addr.extend_from_slice(&addr.octets());
        builder.write_tlv(0x29, &pdu_addr);
    } else if let Some((_, addr)) = sess.ipv6_prefix {
        let mut pdu_addr = vec![pdu_session_type::IPV6];
        pdu_addr.extend_from_slice(&addr.octets()[8..16]); // Interface identifier
        builder.write_tlv(0x29, &pdu_addr);
    }

    // S-NSSAI (optional, IEI = 0x22)
    let snssai_bytes = encode_snssai(&sess.s_nssai);
    builder.write_tlv(0x22, &snssai_bytes);

    // Authorized QoS flow descriptions (optional, IEI = 0x79)
    let default_desc = encode_default_qos_flow_description(qos_flow);
    let qos_desc_bytes = encode_qos_flow_descriptions(&[default_desc]);
    builder.write_tlv_e(0x79, &qos_desc_bytes);

    // Mapped EPS bearer contexts (optional, IEI = 0x75), #117. Emitted only when
    // the AMF assigned this flow an EBI: without one there is no EPS bearer to
    // describe, and an IE naming EBI 0 would tell the UE to build a bearer on the
    // identity TS 24.301 §9.3.2 reserves for "none".
    write_mapped_eps_bearer_contexts(&mut builder, qos_flow.assigned_ebi(), qos_flow.qos.index);

    // DNN (optional, IEI = 0x25). Labelled-name form, same encoder the live
    // accept path uses — a single label with dots inline is malformed for any
    // multi-label DNN (TS 24.501 §9.11.2.1B).
    if let Some(ref dnn) = sess.session_name {
        builder.write_tlv(0x25, &crate::policy::encode_dnn_labels(dnn));
    }

    Some(builder.build())
}

/// Build PDU Session Establishment Reject message
pub fn build_pdu_session_establishment_reject(sess: &SmfSess, cause: GsmCause) -> Vec<u8> {
    let mut builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_ESTABLISHMENT_REJECT,
    );

    // 5GSM cause (mandatory)
    builder.write_u8(cause as u8);

    builder.build()
}

/// Build PDU Session Modification Command message
pub fn build_pdu_session_modification_command(
    sess: &SmfSess,
    qos_flows: &[SmfBearer],
    qos_rule_code: u8,
    qos_flow_desc_code: u8,
) -> Option<Vec<u8>> {
    let mut builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_MODIFICATION_COMMAND,
    );

    // Authorized QoS rules (optional, IEI = 0x7A)
    if qos_rule_code != 0 {
        let rules: Vec<QosRule> = qos_flows
            .iter()
            .map(|qf| encode_qos_rule(qf, qos_rule_code, &[]))
            .collect();
        let qos_rules_bytes = encode_qos_rules(&rules);
        builder.write_tlv_e(0x7A, &qos_rules_bytes);
    }

    // Authorized QoS flow descriptions (optional, IEI = 0x79)
    if qos_flow_desc_code != 0 {
        let descs: Vec<QosFlowDescription> = qos_flows
            .iter()
            .map(|qf| encode_qos_flow_description(qf, qos_flow_desc_code))
            .collect();
        let qos_desc_bytes = encode_qos_flow_descriptions(&descs);
        builder.write_tlv_e(0x79, &qos_desc_bytes);
    }

    // Mapped EPS bearer contexts (optional, IEI = 0x75), #117. TS 24.501
    // §8.3.2.7 lets the Modification Command carry it, so a flow that GAINED an
    // EBI mid-session is conveyed here rather than only at establishment. One
    // context per flow holding an EBI; flows without one contribute nothing, and
    // when no flow has one the IE is omitted entirely rather than emitted empty.
    let mapped: Vec<u8> = qos_flows
        .iter()
        .filter_map(|f| {
            f.assigned_ebi()
                .map(|ebi| encode_mapped_eps_bearer_context(ebi, f.qos.index))
        })
        .flatten()
        .collect();
    if !mapped.is_empty() {
        builder.write_tlv_e(IEI_MAPPED_EPS_BEARER_CONTEXTS, &mapped);
    }

    Some(builder.build())
}

/// Build PDU Session Modification Reject message
pub fn build_pdu_session_modification_reject(sess: &SmfSess, cause: GsmCause) -> Vec<u8> {
    let mut builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_MODIFICATION_REJECT,
    );

    // 5GSM cause (mandatory)
    builder.write_u8(cause as u8);

    builder.build()
}

/// Build PDU Session Release Command message
pub fn build_pdu_session_release_command(sess: &SmfSess, cause: GsmCause) -> Vec<u8> {
    let mut builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_RELEASE_COMMAND,
    );

    // 5GSM cause (mandatory)
    builder.write_u8(cause as u8);

    builder.build()
}

/// Build PDU Session Release Reject message
pub fn build_pdu_session_release_reject(sess: &SmfSess, cause: GsmCause) -> Vec<u8> {
    let mut builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_RELEASE_REJECT,
    );

    // 5GSM cause (mandatory)
    builder.write_u8(cause as u8);

    builder.build()
}

/// Build PDU Session Modification Complete message
pub fn build_pdu_session_modification_complete(sess: &SmfSess) -> Vec<u8> {
    let builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_MODIFICATION_COMPLETE,
    );

    builder.build()
}

/// Build PDU Session Release Complete message
pub fn build_pdu_session_release_complete(sess: &SmfSess) -> Vec<u8> {
    let builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_RELEASE_COMPLETE,
    );

    builder.build()
}

/// Build PDU Session Establishment Accept with extended options
/// This version supports IPv4v6 dual-stack and additional optional IEs
pub fn build_pdu_session_establishment_accept_extended(
    sess: &SmfSess,
    qos_flow: &SmfBearer,
    dns_servers: &[std::net::Ipv4Addr],
    mtu: Option<u16>,
) -> Option<Vec<u8>> {
    let mut builder = GsmMessageBuilder::with_header(
        sess.psi,
        sess.pti,
        message_type::PDU_SESSION_ESTABLISHMENT_ACCEPT,
    );

    // Selected PDU session type (mandatory)
    let session_type = match sess.session_type {
        crate::context::PduSessionType::Ipv4 => pdu_session_type::IPV4,
        crate::context::PduSessionType::Ipv6 => pdu_session_type::IPV6,
        crate::context::PduSessionType::Ipv4v6 => pdu_session_type::IPV4V6,
        crate::context::PduSessionType::Unstructured => pdu_session_type::UNSTRUCTURED,
        crate::context::PduSessionType::Ethernet => pdu_session_type::ETHERNET,
    };
    builder.write_u8(session_type);

    // Authorized QoS rules (mandatory)
    let default_rule = encode_default_qos_rule(qos_flow);
    let qos_rules_bytes = encode_qos_rules(&[default_rule]);
    builder.write_lv_e(&qos_rules_bytes);

    // Session AMBR (mandatory)
    let ambr_bytes = encode_session_ambr(sess.session_ambr.downlink, sess.session_ambr.uplink);
    builder.write_lv(&ambr_bytes);

    // PDU address (optional, IEI = 0x29)
    match sess.session_type {
        crate::context::PduSessionType::Ipv4 => {
            if let Some(addr) = sess.ipv4_addr {
                let mut pdu_addr = vec![pdu_session_type::IPV4];
                pdu_addr.extend_from_slice(&addr.octets());
                builder.write_tlv(0x29, &pdu_addr);
            }
        }
        crate::context::PduSessionType::Ipv6 => {
            if let Some((_, addr)) = sess.ipv6_prefix {
                let mut pdu_addr = vec![pdu_session_type::IPV6];
                pdu_addr.extend_from_slice(&addr.octets()[8..16]);
                builder.write_tlv(0x29, &pdu_addr);
            }
        }
        crate::context::PduSessionType::Ipv4v6 => {
            let mut pdu_addr = vec![pdu_session_type::IPV4V6];
            // IPv6 interface identifier (8 bytes)
            if let Some((_, addr6)) = sess.ipv6_prefix {
                pdu_addr.extend_from_slice(&addr6.octets()[8..16]);
            } else {
                pdu_addr.extend_from_slice(&[0u8; 8]);
            }
            // IPv4 address (4 bytes)
            if let Some(addr4) = sess.ipv4_addr {
                pdu_addr.extend_from_slice(&addr4.octets());
            } else {
                pdu_addr.extend_from_slice(&[0u8; 4]);
            }
            builder.write_tlv(0x29, &pdu_addr);
        }
        _ => {}
    }

    // S-NSSAI (optional, IEI = 0x22)
    let snssai_bytes = encode_snssai(&sess.s_nssai);
    builder.write_tlv(0x22, &snssai_bytes);

    // Authorized QoS flow descriptions (optional, IEI = 0x79)
    let default_desc = encode_default_qos_flow_description(qos_flow);
    let qos_desc_bytes = encode_qos_flow_descriptions(&[default_desc]);
    builder.write_tlv_e(0x79, &qos_desc_bytes);

    // Mapped EPS bearer contexts (optional, IEI = 0x75), #117. Emitted only when
    // the AMF assigned this flow an EBI: without one there is no EPS bearer to
    // describe, and an IE naming EBI 0 would tell the UE to build a bearer on the
    // identity TS 24.301 §9.3.2 reserves for "none".
    write_mapped_eps_bearer_contexts(&mut builder, qos_flow.assigned_ebi(), qos_flow.qos.index);

    // Extended protocol configuration options (optional, IEI = 0x7B)
    // Build ePCO with DNS servers and MTU
    if !dns_servers.is_empty() || mtu.is_some() {
        let epco = build_epco(dns_servers, mtu);
        if !epco.is_empty() {
            builder.write_tlv_e(0x7B, &epco);
        }
    }

    // DNN (optional, IEI = 0x25). Labelled-name form, same encoder the live
    // accept path uses — a single label with dots inline is malformed for any
    // multi-label DNN (TS 24.501 §9.11.2.1B).
    if let Some(ref dnn) = sess.session_name {
        builder.write_tlv(0x25, &crate::policy::encode_dnn_labels(dnn));
    }

    Some(builder.build())
}

/// Build Extended Protocol Configuration Options (ePCO) for establishment accept
pub(crate) fn build_epco(dns_servers: &[std::net::Ipv4Addr], mtu: Option<u16>) -> Vec<u8> {
    let mut buffer = BytesMut::with_capacity(64);

    // Configuration protocol byte (0x80 = PPP with extensions)
    buffer.put_u8(0x80);

    // DNS Server IPv4 Address (Protocol ID = 0x000D)
    for dns in dns_servers {
        buffer.put_u16(0x000D); // Container ID: DNS Server IPv4
        buffer.put_u8(4); // Length
        buffer.put_slice(&dns.octets());
    }

    // IPv4 Link MTU (Protocol ID = 0x0010)
    if let Some(mtu_val) = mtu {
        if mtu_val > 0 {
            buffer.put_u16(0x0010); // Container ID: IPv4 Link MTU
            buffer.put_u8(2); // Length
            buffer.put_u16(mtu_val);
        }
    }

    buffer.to_vec()
}

/// Build 5GSM Status message
pub fn build_gsm_status(sess: &SmfSess, cause: GsmCause) -> Vec<u8> {
    let mut builder = GsmMessageBuilder::with_header(sess.psi, sess.pti, message_type::GSM_STATUS);

    // 5GSM cause (mandatory)
    builder.write_u8(cause as u8);

    builder.build()
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode session AMBR to NAS format
fn encode_session_ambr(downlink: u64, uplink: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(6);

    // Length
    data.push(6);

    // Downlink (unit + value)
    let dl_bytes = encode_ambr_value(downlink);
    data.extend_from_slice(&dl_bytes);

    // Uplink (unit + value)
    let ul_bytes = encode_ambr_value(uplink);
    data.extend_from_slice(&ul_bytes);

    data
}

/// Encode AMBR value (unit + 2-byte value)
fn encode_ambr_value(bitrate: u64) -> Vec<u8> {
    // AMBR encoding: 1 byte unit + 2 bytes value
    let (unit, value) = if bitrate == 0 {
        (0u8, 0u16)
    } else if bitrate <= 65535 * 1000 {
        (1, (bitrate / 1000) as u16) // 1 kbps
    } else if bitrate <= 65535 * 4000 {
        (2, (bitrate / 4000) as u16) // 4 kbps
    } else if bitrate <= 65535 * 16000 {
        (3, (bitrate / 16000) as u16) // 16 kbps
    } else if bitrate <= 65535 * 64000 {
        (4, (bitrate / 64000) as u16) // 64 kbps
    } else if bitrate <= 65535 * 256000 {
        (5, (bitrate / 256000) as u16) // 256 kbps
    } else if bitrate <= 65535 * 1000000 {
        (6, (bitrate / 1000000) as u16) // 1 Mbps
    } else if bitrate <= 65535 * 4000000 {
        (7, (bitrate / 4000000) as u16) // 4 Mbps
    } else if bitrate <= 65535 * 16000000 {
        (8, (bitrate / 16000000) as u16) // 16 Mbps
    } else if bitrate <= 65535 * 64000000 {
        (9, (bitrate / 64000000) as u16) // 64 Mbps
    } else if bitrate <= 65535 * 256000000 {
        (10, (bitrate / 256000000) as u16) // 256 Mbps
    } else if bitrate <= 65535 * 1000000000 {
        (11, (bitrate / 1000000000) as u16) // 1 Gbps
    } else {
        (11, 65535)
    };

    let mut data = vec![unit];
    data.extend_from_slice(&value.to_be_bytes());
    data
}

/// Encode S-NSSAI to NAS format
fn encode_snssai(snssai: &crate::context::SNssai) -> Vec<u8> {
    let mut data = Vec::with_capacity(5);

    // SST (mandatory)
    data.push(snssai.sst);

    // SD (optional)
    if let Some(sd) = snssai.sd {
        data.push(((sd >> 16) & 0xff) as u8);
        data.push(((sd >> 8) & 0xff) as u8);
        data.push((sd & 0xff) as u8);
    }

    data
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{
        FlowDirection, IpfwRule, PduSessionType, Qos, SNssai, SessionAmbr, SmfBearer, SmfPf,
        SmfSess,
    };
    use std::net::Ipv4Addr;

    fn create_test_sess() -> SmfSess {
        SmfSess {
            id: 1,
            smf_ue_id: 1,
            psi: 5,
            pti: 1,
            session_type: PduSessionType::Ipv4,
            session_name: Some("internet".to_string()),
            s_nssai: SNssai {
                sst: 1,
                sd: Some(0x010203),
            },
            session_ambr: SessionAmbr {
                downlink: 100_000_000, // 100 Mbps
                uplink: 50_000_000,    // 50 Mbps
            },
            ipv4_addr: Some(Ipv4Addr::new(10, 45, 0, 1)),
            ipv6_prefix: None,
            ..Default::default()
        }
    }

    fn create_test_bearer() -> SmfBearer {
        SmfBearer {
            id: 1,
            sess_id: 1,
            qfi: 1,
            qos: Qos {
                index: 9, // 5QI
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
    fn test_gsm_cause_from_u8() {
        assert_eq!(GsmCause::from(26), GsmCause::InsufficientResources);
        assert_eq!(GsmCause::from(27), GsmCause::MissingOrUnknownDnn);
        assert_eq!(GsmCause::from(36), GsmCause::RegularDeactivation);
        assert_eq!(GsmCause::from(255), GsmCause::ProtocolErrorUnspecified);
    }

    #[test]
    fn test_gsm_message_builder_basic() {
        let mut builder = GsmMessageBuilder::new();
        builder.write_u8(0x2e);
        builder.write_u16(0x1234);
        builder.write_u32(0xdeadbeef);

        let result = builder.build();
        assert_eq!(result.len(), 7);
        assert_eq!(result[0], 0x2e);
        assert_eq!(result[1], 0x12);
        assert_eq!(result[2], 0x34);
    }

    #[test]
    fn test_gsm_message_builder_with_header() {
        let builder =
            GsmMessageBuilder::with_header(5, 1, message_type::PDU_SESSION_ESTABLISHMENT_ACCEPT);
        let result = builder.build();

        assert_eq!(result.len(), 4);
        assert_eq!(
            result[0],
            NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM
        );
        assert_eq!(result[1], 5); // PSI
        assert_eq!(result[2], 1); // PTI
        assert_eq!(result[3], message_type::PDU_SESSION_ESTABLISHMENT_ACCEPT);
    }

    #[test]
    fn test_gsm_message_builder_lv() {
        let mut builder = GsmMessageBuilder::new();
        builder.write_lv(&[0x01, 0x02, 0x03]);

        let result = builder.build();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], 3); // Length
        assert_eq!(result[1], 0x01);
        assert_eq!(result[2], 0x02);
        assert_eq!(result[3], 0x03);
    }

    #[test]
    fn test_gsm_message_builder_tlv() {
        let mut builder = GsmMessageBuilder::new();
        builder.write_tlv(0x29, &[0x01, 0x0a, 0x2d, 0x00, 0x01]);

        let result = builder.build();
        assert_eq!(result.len(), 7);
        assert_eq!(result[0], 0x29); // IEI
        assert_eq!(result[1], 5); // Length
    }

    #[test]
    fn test_encode_default_qos_rule() {
        let bearer = create_test_bearer();
        let rule = encode_default_qos_rule(&bearer);

        assert_eq!(rule.identifier, 1);
        assert_eq!(rule.code, qos_rule_code::CREATE_NEW_QOS_RULE);
        assert!(rule.dqr_bit);
        assert_eq!(rule.qfi, 1);
        assert_eq!(rule.precedence, 255);
        assert_eq!(rule.packet_filters.len(), 1);
        assert_eq!(
            rule.packet_filters[0].direction,
            pf_direction::BIDIRECTIONAL
        );
    }

    #[test]
    fn test_encode_default_qos_flow_description() {
        let bearer = create_test_bearer();
        let desc = encode_default_qos_flow_description(&bearer);

        assert_eq!(desc.identifier, 1);
        assert_eq!(
            desc.code,
            qos_flow_description_code::CREATE_NEW_QOS_FLOW_DESCRIPTION
        );
        assert!(desc.e_bit);
        assert_eq!(desc.params.len(), 1);
        assert_eq!(desc.params[0].identifier, qos_flow_param_id::FIVE_QI);
        assert_eq!(desc.params[0].data, vec![9]);
    }

    #[test]
    fn test_encode_qos_rules() {
        let bearer = create_test_bearer();
        let rule = encode_default_qos_rule(&bearer);
        let encoded = encode_qos_rules(&[rule]);

        // Should have: identifier (1) + length (2) + content
        assert!(encoded.len() >= 3);
        assert_eq!(encoded[0], 1); // QoS rule identifier
    }

    #[test]
    fn test_encode_qos_flow_descriptions() {
        let bearer = create_test_bearer();
        let desc = encode_default_qos_flow_description(&bearer);
        let encoded = encode_qos_flow_descriptions(&[desc]);

        // Should have: QFI (1) + operation code byte (1) + params
        assert!(encoded.len() >= 2);
        assert_eq!(encoded[0], 1); // QFI
    }

    #[test]
    fn test_encode_bitrate() {
        // Test 0 bitrate
        let result = encode_bitrate(0);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], 0); // Unit

        // Test 1 Mbps
        let result = encode_bitrate(1_000_000);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], 0); // Unit 0 = 1kbps

        // Test 100 Mbps
        let result = encode_bitrate(100_000_000);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_encode_session_ambr() {
        let ambr = encode_session_ambr(100_000_000, 50_000_000);

        // Length (1) + DL unit (1) + DL value (2) + UL unit (1) + UL value (2) = 7
        assert_eq!(ambr.len(), 7);
        assert_eq!(ambr[0], 6); // Length field
    }

    #[test]
    fn test_encode_snssai() {
        let snssai = SNssai {
            sst: 1,
            sd: Some(0x010203),
        };
        let encoded = encode_snssai(&snssai);

        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0], 1); // SST
        assert_eq!(encoded[1], 0x01); // SD byte 1
        assert_eq!(encoded[2], 0x02); // SD byte 2
        assert_eq!(encoded[3], 0x03); // SD byte 3
    }

    #[test]
    fn test_encode_snssai_no_sd() {
        let snssai = SNssai { sst: 1, sd: None };
        let encoded = encode_snssai(&snssai);

        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], 1); // SST only
    }

    #[test]
    fn test_build_pdu_session_establishment_accept() {
        let sess = create_test_sess();
        let bearer = create_test_bearer();

        let result = build_pdu_session_establishment_accept(&sess, &bearer);
        assert!(result.is_some());

        let msg = result.unwrap();
        assert!(msg.len() > 4);
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM);
        assert_eq!(msg[1], 5); // PSI
        assert_eq!(msg[2], 1); // PTI
        assert_eq!(msg[3], message_type::PDU_SESSION_ESTABLISHMENT_ACCEPT);
        assert_eq!(msg[4], pdu_session_type::IPV4);
    }

    #[test]
    fn test_build_pdu_session_establishment_reject() {
        let sess = create_test_sess();

        let msg = build_pdu_session_establishment_reject(&sess, GsmCause::InsufficientResources);

        assert_eq!(msg.len(), 5);
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM);
        assert_eq!(msg[1], 5); // PSI
        assert_eq!(msg[2], 1); // PTI
        assert_eq!(msg[3], message_type::PDU_SESSION_ESTABLISHMENT_REJECT);
        assert_eq!(msg[4], GsmCause::InsufficientResources as u8);
    }

    #[test]
    fn test_build_pdu_session_modification_command() {
        let sess = create_test_sess();
        let bearer = create_test_bearer();

        let result = build_pdu_session_modification_command(
            &sess,
            &[bearer],
            qos_rule_code::MODIFY_EXISTING_QOS_RULE_WITHOUT_MODIFYING_PACKET_FILTERS,
            qos_flow_description_code::MODIFY_NEW_QOS_FLOW_DESCRIPTION,
        );

        assert!(result.is_some());
        let msg = result.unwrap();
        assert!(msg.len() > 4);
        assert_eq!(msg[3], message_type::PDU_SESSION_MODIFICATION_COMMAND);
    }

    #[test]
    fn test_build_pdu_session_modification_reject() {
        let sess = create_test_sess();

        let msg =
            build_pdu_session_modification_reject(&sess, GsmCause::SemanticErrorInTheQosOperation);

        assert_eq!(msg.len(), 5);
        assert_eq!(msg[3], message_type::PDU_SESSION_MODIFICATION_REJECT);
        assert_eq!(msg[4], GsmCause::SemanticErrorInTheQosOperation as u8);
    }

    #[test]
    fn test_build_pdu_session_release_command() {
        let sess = create_test_sess();

        let msg = build_pdu_session_release_command(&sess, GsmCause::RegularDeactivation);

        assert_eq!(msg.len(), 5);
        assert_eq!(msg[3], message_type::PDU_SESSION_RELEASE_COMMAND);
        assert_eq!(msg[4], GsmCause::RegularDeactivation as u8);
    }

    #[test]
    fn test_build_pdu_session_release_reject() {
        let sess = create_test_sess();

        let msg = build_pdu_session_release_reject(&sess, GsmCause::PduSessionDoesNotExist);

        assert_eq!(msg.len(), 5);
        assert_eq!(msg[3], message_type::PDU_SESSION_RELEASE_REJECT);
        assert_eq!(msg[4], GsmCause::PduSessionDoesNotExist as u8);
    }

    #[test]
    fn test_build_gsm_status() {
        let sess = create_test_sess();

        let msg = build_gsm_status(&sess, GsmCause::ProtocolErrorUnspecified);

        assert_eq!(msg.len(), 5);
        assert_eq!(msg[3], message_type::GSM_STATUS);
        assert_eq!(msg[4], GsmCause::ProtocolErrorUnspecified as u8);
    }

    #[test]
    fn test_encode_qos_rule_with_packet_filters() {
        let bearer = create_test_bearer();
        let pf = SmfPf {
            id: 1,
            bearer_id: 1,
            identifier: 1,
            direction: FlowDirection::Bidirectional,
            precedence: 100,
            ipfw_rule: IpfwRule {
                proto: 17, // UDP
                src_addr: Some(Ipv4Addr::new(192, 168, 1, 0)),
                src_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
                dst_addr: None,
                dst_mask: None,
                src_addr6: None,
                src_prefix_len6: 0,
                dst_addr6: None,
                dst_prefix_len6: 0,
                src_port_low: 5000,
                src_port_high: 5000,
                dst_port_low: 0,
                dst_port_high: 0,
            },
            ..Default::default()
        };

        let rule = encode_qos_rule(&bearer, qos_rule_code::CREATE_NEW_QOS_RULE, &[pf]);

        assert_eq!(rule.identifier, 1);
        assert_eq!(rule.code, qos_rule_code::CREATE_NEW_QOS_RULE);
        assert_eq!(rule.packet_filters.len(), 1);
    }

    #[test]
    fn test_encode_qos_flow_description_with_gbr() {
        let mut bearer = create_test_bearer();
        bearer.qos.gbr_uplink = 10_000_000; // 10 Mbps
        bearer.qos.gbr_downlink = 20_000_000; // 20 Mbps
        bearer.qos.mbr_uplink = 50_000_000; // 50 Mbps
        bearer.qos.mbr_downlink = 100_000_000; // 100 Mbps

        let desc = encode_qos_flow_description(
            &bearer,
            qos_flow_description_code::CREATE_NEW_QOS_FLOW_DESCRIPTION,
        );

        assert_eq!(desc.identifier, 1);
        assert!(desc.e_bit);
        // Should have 5QI + 4 bitrate params
        assert_eq!(desc.params.len(), 5);
    }

    #[test]
    fn test_encode_qos_flow_description_delete() {
        let bearer = create_test_bearer();

        let desc = encode_qos_flow_description(
            &bearer,
            qos_flow_description_code::DELETE_NEW_QOS_FLOW_DESCRIPTION,
        );

        assert_eq!(desc.identifier, 1);
        assert!(!desc.e_bit);
        assert!(desc.params.is_empty());
    }

    #[test]
    fn test_packet_filter_content_encoding() {
        let content = PacketFilterContent {
            components: vec![
                PacketFilterComponent {
                    component_type: pf_component_type::PROTOCOL_IDENTIFIER,
                    data: vec![17], // UDP
                },
                PacketFilterComponent {
                    component_type: pf_component_type::SINGLE_REMOTE_PORT,
                    data: vec![0x13, 0x88], // Port 5000
                },
            ],
        };

        let encoded = encode_packet_filter_content(&content);

        // Protocol (1 type + 1 data) + Port (1 type + 2 data) = 5
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], pf_component_type::PROTOCOL_IDENTIFIER);
        assert_eq!(encoded[1], 17);
        assert_eq!(encoded[2], pf_component_type::SINGLE_REMOTE_PORT);
    }

    #[test]
    fn test_message_type_constants() {
        assert_eq!(message_type::PDU_SESSION_ESTABLISHMENT_REQUEST, 0xc1);
        assert_eq!(message_type::PDU_SESSION_ESTABLISHMENT_ACCEPT, 0xc2);
        assert_eq!(message_type::PDU_SESSION_ESTABLISHMENT_REJECT, 0xc3);
        assert_eq!(message_type::PDU_SESSION_MODIFICATION_REQUEST, 0xc9);
        assert_eq!(message_type::PDU_SESSION_MODIFICATION_COMMAND, 0xcb);
        assert_eq!(message_type::PDU_SESSION_RELEASE_COMMAND, 0xd3);
        assert_eq!(message_type::GSM_STATUS, 0xd6);
    }

    #[test]
    fn test_pdu_session_type_constants() {
        assert_eq!(pdu_session_type::IPV4, 1);
        assert_eq!(pdu_session_type::IPV6, 2);
        assert_eq!(pdu_session_type::IPV4V6, 3);
        assert_eq!(pdu_session_type::UNSTRUCTURED, 4);
        assert_eq!(pdu_session_type::ETHERNET, 5);
    }

    #[test]
    fn test_build_pdu_session_modification_complete() {
        let sess = create_test_sess();
        let msg = build_pdu_session_modification_complete(&sess);

        assert_eq!(msg.len(), 4);
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM);
        assert_eq!(msg[3], message_type::PDU_SESSION_MODIFICATION_COMPLETE);
    }

    #[test]
    fn test_build_pdu_session_release_complete() {
        let sess = create_test_sess();
        let msg = build_pdu_session_release_complete(&sess);

        assert_eq!(msg.len(), 4);
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM);
        assert_eq!(msg[3], message_type::PDU_SESSION_RELEASE_COMPLETE);
    }

    #[test]
    fn test_build_pdu_session_establishment_accept_extended() {
        let sess = create_test_sess();
        let bearer = create_test_bearer();
        let dns = vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];

        let result =
            build_pdu_session_establishment_accept_extended(&sess, &bearer, &dns, Some(1400));
        assert!(result.is_some());

        let msg = result.unwrap();
        assert!(msg.len() > 4);
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM);
        assert_eq!(msg[3], message_type::PDU_SESSION_ESTABLISHMENT_ACCEPT);
        assert_eq!(msg[4], pdu_session_type::IPV4);
    }

    #[test]
    fn test_build_pdu_session_establishment_accept_extended_no_extras() {
        let sess = create_test_sess();
        let bearer = create_test_bearer();

        let result = build_pdu_session_establishment_accept_extended(&sess, &bearer, &[], None);
        assert!(result.is_some());
    }

    #[test]
    fn test_gsm_message_builder_is_empty() {
        let builder = GsmMessageBuilder::new();
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
    }

    #[test]
    fn test_gsm_message_builder_default() {
        let builder = GsmMessageBuilder::default();
        assert!(builder.is_empty());
    }
    // ---- #117: Mapped EPS bearer contexts, IEI 0x75 --------------------------

    /// Find and fully decode the Mapped EPS bearer contexts IE in a built N1
    /// message, returning `(offset, contexts)` where each context is
    /// `(ebi, octet7, params)`.
    ///
    /// A scan-and-VALIDATE rather than a walk: the Establishment Accept begins with
    /// mandatory V/LV fields that are not TLVs, so a length-driven walk from the
    /// 5GSM header does not work without a full message parser. And a scan alone
    /// would be a false guard — 0x75 is an ordinary byte that can appear inside
    /// another IE's contents. So every candidate offset is parsed as
    /// TS 24.501 §9.11.4.8 and accepted only if the whole structure is
    /// self-consistent: the outer length fits the buffer, each context's own length
    /// fits the outer contents, and the parameters consume their context exactly.
    #[allow(clippy::type_complexity)]
    fn decode_mapped_eps_at(msg: &[u8]) -> Option<(usize, Vec<(u8, u8, Vec<(u8, Vec<u8>)>)>)> {
        for at in 0..msg.len() {
            if msg[at] != IEI_MAPPED_EPS_BEARER_CONTEXTS || at + 3 > msg.len() {
                continue;
            }
            let len = u16::from_be_bytes([msg[at + 1], msg[at + 2]]) as usize;
            if len < 4 || at + 3 + len > msg.len() {
                continue;
            }
            let body = &msg[at + 3..at + 3 + len];
            let mut contexts = Vec::new();
            let mut b = 0usize;
            let mut consistent = true;
            while b < body.len() {
                if b + 4 > body.len() || body[b] & 0x0f != 0 {
                    // Bits 4..1 of octet 4 are spare and shall be zero.
                    consistent = false;
                    break;
                }
                let ebi = body[b] >> 4;
                let ctx_len = u16::from_be_bytes([body[b + 1], body[b + 2]]) as usize;
                if ctx_len == 0 || b + 3 + ctx_len > body.len() {
                    consistent = false;
                    break;
                }
                let octet7 = body[b + 3];
                let params_bytes = &body[b + 4..b + 3 + ctx_len];
                let mut params = Vec::new();
                let mut p = 0usize;
                while p < params_bytes.len() {
                    if p + 2 > params_bytes.len() {
                        consistent = false;
                        break;
                    }
                    let id = params_bytes[p];
                    let plen = params_bytes[p + 1] as usize;
                    if p + 2 + plen > params_bytes.len() {
                        consistent = false;
                        break;
                    }
                    params.push((id, params_bytes[p + 2..p + 2 + plen].to_vec()));
                    p += 2 + plen;
                }
                if !consistent {
                    break;
                }
                if (octet7 & 0x0f) as usize != params.len() {
                    // The number-of-parameters field must match what is there.
                    consistent = false;
                    break;
                }
                contexts.push((ebi, octet7, params));
                b += 3 + ctx_len;
            }
            if consistent && b == body.len() && !contexts.is_empty() {
                return Some((at, contexts));
            }
        }
        None
    }

    /// The first (and, for the accept builders, only) mapped EPS bearer context.
    fn decode_mapped_eps(msg: &[u8]) -> Option<(u8, u8, Vec<(u8, Vec<u8>)>)> {
        decode_mapped_eps_at(msg).map(|(_, mut c)| c.remove(0))
    }

    fn bearer_with_ebi(ebi: u8, five_qi: u8) -> SmfBearer {
        let mut b = create_test_bearer();
        b.ebi = ebi;
        b.qos.index = five_qi;
        b
    }

    /// #117 criterion 3: the IE is emitted and decodes to the expected EBI and
    /// parameters, and it is ABSENT when no EBI was assigned.
    ///
    /// The absent half is criterion 5: a deployment with interworking off must
    /// produce the same N1 bytes it did before, and an IE emitted with EBI 0 would
    /// tell the UE to build a bearer on the identity TS 24.301 §9.3.2 reserves for
    /// "none assigned".
    #[test]
    fn establishment_accept_carries_mapped_eps_bearer_contexts_only_when_an_ebi_exists() {
        let sess = create_test_sess();

        let msg = build_pdu_session_establishment_accept(&sess, &bearer_with_ebi(7, 9))
            .expect("accept builds");
        let (ebi, octet7, params) =
            decode_mapped_eps(&msg).expect("IEI 0x75 must be present when an EBI is held");
        assert_eq!(ebi, 7, "the EBI occupies bits 8..5 of octet 4");
        assert_eq!(
            octet7 >> 6,
            0b01,
            "operation code must be 'Create new EPS bearer'"
        );
        assert_eq!(
            octet7 & 0x20,
            0,
            "bit 6 of octet 7 is spare and must be zero"
        );
        assert_eq!(
            octet7 & 0x10,
            0x10,
            "the E bit must say the parameters list is included"
        );
        assert_eq!(octet7 & 0x0f, 1, "one EPS parameter");
        assert_eq!(
            params,
            vec![(0x01u8, vec![9u8])],
            "01H is Mapped EPS QoS parameters; its contents are the QCI (TS 24.301 §9.9.4.3)"
        );

        // No EBI: the IE must not appear at all.
        let msg = build_pdu_session_establishment_accept(&sess, &bearer_with_ebi(0, 9))
            .expect("accept builds");
        assert!(
            decode_mapped_eps(&msg).is_none(),
            "EBI 0 means 'none assigned' and must not produce an IE"
        );
        // ...nor for a RESERVED identity.
        let msg = build_pdu_session_establishment_accept(&sess, &bearer_with_ebi(4, 9))
            .expect("accept builds");
        assert!(
            decode_mapped_eps(&msg).is_none(),
            "EBIs 1..=4 are reserved by TS 24.301 §9.3.2"
        );
    }

    /// The extended accept builder emits it too — the two accept builders are
    /// separate functions and a fix applied to one is invisible in the other.
    #[test]
    fn the_extended_establishment_accept_also_carries_the_ie() {
        let sess = create_test_sess();
        let msg = build_pdu_session_establishment_accept_extended(
            &sess,
            &bearer_with_ebi(9, 5),
            &[std::net::Ipv4Addr::new(8, 8, 8, 8)],
            Some(1400),
        )
        .expect("extended accept builds");
        let (ebi, _, params) = decode_mapped_eps(&msg).expect("IEI 0x75 present");
        assert_eq!(ebi, 9);
        assert_eq!(params, vec![(0x01u8, vec![5u8])]);
    }

    /// TS 24.501 §8.3.2.7: the Modification Command may carry the IE, so a flow
    /// that gains an EBI mid-session is conveyed without a new establishment. One
    /// context per flow holding an EBI, and none for flows without one.
    #[test]
    fn the_modification_command_carries_one_context_per_flow_holding_an_ebi() {
        let sess = create_test_sess();
        let flows = vec![
            bearer_with_ebi(5, 9),
            bearer_with_ebi(0, 9), // no EBI: contributes nothing
            bearer_with_ebi(6, 8),
        ];
        let msg = build_pdu_session_modification_command(
            &sess,
            &flows,
            qos_rule_code::CREATE_NEW_QOS_RULE,
            qos_flow_description_code::CREATE_NEW_QOS_FLOW_DESCRIPTION,
        )
        .expect("modification command builds");

        // Two contexts back to back inside one IE: decode the first, then check the
        // IE is long enough to hold the second.
        let (ebi, _, params) = decode_mapped_eps(&msg).expect("IEI 0x75 present");
        assert_eq!(ebi, 5, "the first flow holding an EBI comes first");
        assert_eq!(params, vec![(0x01u8, vec![9u8])]);
        let (_, contexts) = decode_mapped_eps_at(&msg).expect("IEI 0x75 present");
        assert_eq!(
            contexts.len(),
            2,
            "two contexts, and NOT three: the flow without an EBI contributes nothing"
        );
        assert_eq!(
            contexts.iter().map(|c| c.0).collect::<Vec<_>>(),
            vec![5, 6],
            "in flow order, skipping the one with no EBI"
        );
        assert_eq!(contexts[1].2, vec![(0x01u8, vec![8u8])]);

        // No flow holds an EBI: the IE is omitted rather than emitted empty.
        let msg = build_pdu_session_modification_command(
            &sess,
            &[bearer_with_ebi(0, 9)],
            qos_rule_code::CREATE_NEW_QOS_RULE,
            qos_flow_description_code::CREATE_NEW_QOS_FLOW_DESCRIPTION,
        )
        .expect("builds");
        assert!(decode_mapped_eps(&msg).is_none());
    }

    /// A 5QI with no EPS equivalent yields a bearer context with an EMPTY
    /// parameters list, not an invented QCI.
    ///
    /// TS 23.501 Table 5.7.4-1 gives 5QIs 1..=9 the same numeric QCI; there is no
    /// defined QCI for 5QI 82 (a delay-critical XR value). An MME would *enforce*
    /// whatever QCI it was handed, so guessing one is worse than omitting the
    /// parameter — and the 7-octet minimum length of the IE is exactly this case.
    #[test]
    fn a_five_qi_with_no_eps_equivalent_omits_the_qos_parameter_rather_than_inventing_a_qci() {
        assert_eq!(qci_for_5qi(9), Some(9));
        assert_eq!(qci_for_5qi(1), Some(1));
        assert_eq!(qci_for_5qi(82), None);
        assert_eq!(qci_for_5qi(0), None);

        let contents = encode_mapped_eps_bearer_context(5, 82);
        assert_eq!(
            contents.len(),
            4,
            "EBI + 2-octet length + octet 7, and no parameters"
        );
        assert_eq!(contents[3] & 0x0f, 0, "no EPS parameters");
        assert_eq!(
            contents[3] & 0x10,
            0,
            "the E bit must be clear when the parameters list is empty"
        );

        let sess = create_test_sess();
        let msg =
            build_pdu_session_establishment_accept(&sess, &bearer_with_ebi(5, 82)).expect("builds");
        let (ebi, _, params) = decode_mapped_eps(&msg).expect("the IE is still emitted");
        assert_eq!(ebi, 5, "the bearer identity is still conveyed");
        assert!(params.is_empty());
    }
}
