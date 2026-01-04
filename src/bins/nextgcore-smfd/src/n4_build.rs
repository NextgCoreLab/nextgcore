//! SMF N4 (PFCP) Message Building
//!
//! Port of src/smf/n4-build.c - PFCP message building for SMF

use bytes::{BufMut, BytesMut};

// ============================================================================
// PFCP Message Types
// ============================================================================

/// PFCP message types
pub mod pfcp_type {
    pub const HEARTBEAT_REQUEST: u8 = 1;
    pub const HEARTBEAT_RESPONSE: u8 = 2;
    pub const PFD_MANAGEMENT_REQUEST: u8 = 3;
    pub const PFD_MANAGEMENT_RESPONSE: u8 = 4;
    pub const ASSOCIATION_SETUP_REQUEST: u8 = 5;
    pub const ASSOCIATION_SETUP_RESPONSE: u8 = 6;
    pub const ASSOCIATION_UPDATE_REQUEST: u8 = 7;
    pub const ASSOCIATION_UPDATE_RESPONSE: u8 = 8;
    pub const ASSOCIATION_RELEASE_REQUEST: u8 = 9;
    pub const ASSOCIATION_RELEASE_RESPONSE: u8 = 10;
    pub const VERSION_NOT_SUPPORTED_RESPONSE: u8 = 11;
    pub const NODE_REPORT_REQUEST: u8 = 12;
    pub const NODE_REPORT_RESPONSE: u8 = 13;
    pub const SESSION_SET_DELETION_REQUEST: u8 = 14;
    pub const SESSION_SET_DELETION_RESPONSE: u8 = 15;
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_ESTABLISHMENT_RESPONSE: u8 = 51;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_MODIFICATION_RESPONSE: u8 = 53;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_DELETION_RESPONSE: u8 = 55;
    pub const SESSION_REPORT_REQUEST: u8 = 56;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

// ============================================================================
// PFCP Cause Values
// ============================================================================

/// PFCP cause values (3GPP TS 29.244)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PfcpCause {
    RequestAccepted = 1,
    RequestRejected = 64,
    SessionContextNotFound = 65,
    MandatoryIeMissing = 66,
    ConditionalIeMissing = 67,
    InvalidLength = 68,
    MandatoryIeIncorrect = 69,
    InvalidForwardingPolicy = 70,
    InvalidFTeidAllocationOption = 71,
    NoEstablishedPfcpAssociation = 72,
    RuleCreationModificationFailure = 73,
    PfcpEntityInCongestion = 74,
    NoResourcesAvailable = 75,
    ServiceNotSupported = 76,
    SystemFailure = 77,
    AllDynamicAddressAreOccupied = 78,
}


impl From<u8> for PfcpCause {
    fn from(value: u8) -> Self {
        match value {
            1 => PfcpCause::RequestAccepted,
            64 => PfcpCause::RequestRejected,
            65 => PfcpCause::SessionContextNotFound,
            66 => PfcpCause::MandatoryIeMissing,
            67 => PfcpCause::ConditionalIeMissing,
            68 => PfcpCause::InvalidLength,
            69 => PfcpCause::MandatoryIeIncorrect,
            70 => PfcpCause::InvalidForwardingPolicy,
            71 => PfcpCause::InvalidFTeidAllocationOption,
            72 => PfcpCause::NoEstablishedPfcpAssociation,
            73 => PfcpCause::RuleCreationModificationFailure,
            74 => PfcpCause::PfcpEntityInCongestion,
            75 => PfcpCause::NoResourcesAvailable,
            76 => PfcpCause::ServiceNotSupported,
            77 => PfcpCause::SystemFailure,
            78 => PfcpCause::AllDynamicAddressAreOccupied,
            _ => PfcpCause::SystemFailure,
        }
    }
}

impl Default for PfcpCause {
    fn default() -> Self {
        PfcpCause::RequestAccepted
    }
}

// ============================================================================
// PFCP IE Types
// ============================================================================

/// PFCP IE types (3GPP TS 29.244)
pub mod pfcp_ie {
    pub const CREATE_PDR: u16 = 1;
    pub const PDI: u16 = 2;
    pub const CREATE_FAR: u16 = 3;
    pub const FORWARDING_PARAMETERS: u16 = 4;
    pub const DUPLICATING_PARAMETERS: u16 = 5;
    pub const CREATE_URR: u16 = 6;
    pub const CREATE_QER: u16 = 7;
    pub const CREATED_PDR: u16 = 8;
    pub const UPDATE_PDR: u16 = 9;
    pub const UPDATE_FAR: u16 = 10;
    pub const UPDATE_FORWARDING_PARAMETERS: u16 = 11;
    pub const UPDATE_BAR_RESPONSE: u16 = 12;
    pub const UPDATE_URR: u16 = 13;
    pub const UPDATE_QER: u16 = 14;
    pub const REMOVE_PDR: u16 = 15;
    pub const REMOVE_FAR: u16 = 16;
    pub const REMOVE_URR: u16 = 17;
    pub const REMOVE_QER: u16 = 18;
    pub const CAUSE: u16 = 19;
    pub const SOURCE_INTERFACE: u16 = 20;
    pub const F_TEID: u16 = 21;
    pub const NETWORK_INSTANCE: u16 = 22;
    pub const SDF_FILTER: u16 = 23;
    pub const APPLICATION_ID: u16 = 24;
    pub const GATE_STATUS: u16 = 25;
    pub const MBR: u16 = 26;
    pub const GBR: u16 = 27;
    pub const QER_CORRELATION_ID: u16 = 28;
    pub const PRECEDENCE: u16 = 29;
    pub const TRANSPORT_LEVEL_MARKING: u16 = 30;
    pub const VOLUME_THRESHOLD: u16 = 31;
    pub const TIME_THRESHOLD: u16 = 32;
    pub const MONITORING_TIME: u16 = 33;
    pub const SUBSEQUENT_VOLUME_THRESHOLD: u16 = 34;
    pub const SUBSEQUENT_TIME_THRESHOLD: u16 = 35;
    pub const INACTIVITY_DETECTION_TIME: u16 = 36;
    pub const REPORTING_TRIGGERS: u16 = 37;
    pub const REDIRECT_INFORMATION: u16 = 38;
    pub const REPORT_TYPE: u16 = 39;
    pub const OFFENDING_IE: u16 = 40;
    pub const FORWARDING_POLICY: u16 = 41;
    pub const DESTINATION_INTERFACE: u16 = 42;
    pub const UP_FUNCTION_FEATURES: u16 = 43;
    pub const APPLY_ACTION: u16 = 44;
    pub const DOWNLINK_DATA_SERVICE_INFORMATION: u16 = 45;
    pub const DOWNLINK_DATA_NOTIFICATION_DELAY: u16 = 46;
    pub const DL_BUFFERING_DURATION: u16 = 47;
    pub const DL_BUFFERING_SUGGESTED_PACKET_COUNT: u16 = 48;
    pub const PFCPSMREQ_FLAGS: u16 = 49;
    pub const PFCPSRRSP_FLAGS: u16 = 50;
    pub const LOAD_CONTROL_INFORMATION: u16 = 51;
    pub const SEQUENCE_NUMBER: u16 = 52;
    pub const METRIC: u16 = 53;
    pub const OVERLOAD_CONTROL_INFORMATION: u16 = 54;
    pub const TIMER: u16 = 55;
    pub const PDR_ID: u16 = 56;
    pub const F_SEID: u16 = 57;
    pub const APPLICATION_IDS_PFDS: u16 = 58;
    pub const PFD_CONTEXT: u16 = 59;
    pub const NODE_ID: u16 = 60;
    pub const PFD_CONTENTS: u16 = 61;
    pub const MEASUREMENT_METHOD: u16 = 62;
    pub const USAGE_REPORT_TRIGGER: u16 = 63;
    pub const MEASUREMENT_PERIOD: u16 = 64;
    pub const FQ_CSID: u16 = 65;
    pub const VOLUME_MEASUREMENT: u16 = 66;
    pub const DURATION_MEASUREMENT: u16 = 67;
    pub const APPLICATION_DETECTION_INFORMATION: u16 = 68;
    pub const TIME_OF_FIRST_PACKET: u16 = 69;
    pub const TIME_OF_LAST_PACKET: u16 = 70;
    pub const QUOTA_HOLDING_TIME: u16 = 71;
    pub const DROPPED_DL_TRAFFIC_THRESHOLD: u16 = 72;
    pub const VOLUME_QUOTA: u16 = 73;
    pub const TIME_QUOTA: u16 = 74;
    pub const START_TIME: u16 = 75;
    pub const END_TIME: u16 = 76;
    pub const QUERY_URR: u16 = 77;
    pub const USAGE_REPORT_SMR: u16 = 78;
    pub const USAGE_REPORT_SDR: u16 = 79;
    pub const USAGE_REPORT_SRR: u16 = 80;
    pub const URR_ID: u16 = 81;
    pub const LINKED_URR_ID: u16 = 82;
    pub const DOWNLINK_DATA_REPORT: u16 = 83;
    pub const OUTER_HEADER_CREATION: u16 = 84;
    pub const CREATE_BAR: u16 = 85;
    pub const UPDATE_BAR_REQUEST: u16 = 86;
    pub const REMOVE_BAR: u16 = 87;
    pub const BAR_ID: u16 = 88;
    pub const CP_FUNCTION_FEATURES: u16 = 89;
    pub const USAGE_INFORMATION: u16 = 90;
    pub const APPLICATION_INSTANCE_ID: u16 = 91;
    pub const FLOW_INFORMATION: u16 = 92;
    pub const UE_IP_ADDRESS: u16 = 93;
    pub const PACKET_RATE: u16 = 94;
    pub const OUTER_HEADER_REMOVAL: u16 = 95;
    pub const RECOVERY_TIME_STAMP: u16 = 96;
    pub const DL_FLOW_LEVEL_MARKING: u16 = 97;
    pub const HEADER_ENRICHMENT: u16 = 98;
    pub const ERROR_INDICATION_REPORT: u16 = 99;
    pub const MEASUREMENT_INFORMATION: u16 = 100;
    pub const NODE_REPORT_TYPE: u16 = 101;
    pub const USER_PLANE_PATH_FAILURE_REPORT: u16 = 102;
    pub const REMOTE_GTP_U_PEER: u16 = 103;
    pub const UR_SEQN: u16 = 104;
    pub const UPDATE_DUPLICATING_PARAMETERS: u16 = 105;
    pub const ACTIVATE_PREDEFINED_RULES: u16 = 106;
    pub const DEACTIVATE_PREDEFINED_RULES: u16 = 107;
    pub const FAR_ID: u16 = 108;
    pub const QER_ID: u16 = 109;
    pub const OCI_FLAGS: u16 = 110;
    pub const PFCP_ASSOCIATION_RELEASE_REQUEST: u16 = 111;
    pub const GRACEFUL_RELEASE_PERIOD: u16 = 112;
    pub const PDN_TYPE: u16 = 113;
    pub const FAILED_RULE_ID: u16 = 114;
    pub const TIME_QUOTA_MECHANISM: u16 = 115;
    pub const USER_PLANE_IP_RESOURCE_INFORMATION: u16 = 116;
    pub const USER_PLANE_INACTIVITY_TIMER: u16 = 117;
    pub const AGGREGATED_URRS: u16 = 118;
    pub const MULTIPLIER: u16 = 119;
    pub const AGGREGATED_URR_ID: u16 = 120;
    pub const SUBSEQUENT_VOLUME_QUOTA: u16 = 121;
    pub const SUBSEQUENT_TIME_QUOTA: u16 = 122;
    pub const RQI: u16 = 123;
    pub const QFI: u16 = 124;
    pub const QUERY_URR_REFERENCE: u16 = 125;
    pub const ADDITIONAL_USAGE_REPORTS_INFORMATION: u16 = 126;
    pub const CREATE_TRAFFIC_ENDPOINT: u16 = 127;
    pub const CREATED_TRAFFIC_ENDPOINT: u16 = 128;
    pub const UPDATE_TRAFFIC_ENDPOINT: u16 = 129;
    pub const REMOVE_TRAFFIC_ENDPOINT: u16 = 130;
    pub const TRAFFIC_ENDPOINT_ID: u16 = 131;
    pub const ETHERNET_PACKET_FILTER: u16 = 132;
    pub const MAC_ADDRESS: u16 = 133;
    pub const C_TAG: u16 = 134;
    pub const S_TAG: u16 = 135;
    pub const ETHERTYPE: u16 = 136;
    pub const PROXYING: u16 = 137;
    pub const ETHERNET_FILTER_ID: u16 = 138;
    pub const ETHERNET_FILTER_PROPERTIES: u16 = 139;
    pub const SUGGESTED_BUFFERING_PACKETS_COUNT: u16 = 140;
    pub const USER_ID: u16 = 141;
    pub const ETHERNET_PDU_SESSION_INFORMATION: u16 = 142;
    pub const ETHERNET_TRAFFIC_INFORMATION: u16 = 143;
    pub const MAC_ADDRESSES_DETECTED: u16 = 144;
    pub const MAC_ADDRESSES_REMOVED: u16 = 145;
    pub const ETHERNET_INACTIVITY_TIMER: u16 = 146;
    pub const ADDITIONAL_MONITORING_TIME: u16 = 147;
    pub const EVENT_QUOTA: u16 = 148;
    pub const EVENT_THRESHOLD: u16 = 149;
    pub const SUBSEQUENT_EVENT_QUOTA: u16 = 150;
    pub const SUBSEQUENT_EVENT_THRESHOLD: u16 = 151;
    pub const TRACE_INFORMATION: u16 = 152;
    pub const FRAMED_ROUTE: u16 = 153;
    pub const FRAMED_ROUTING: u16 = 154;
    pub const FRAMED_IPV6_ROUTE: u16 = 155;
    pub const EVENT_TIME_STAMP: u16 = 156;
    pub const AVERAGING_WINDOW: u16 = 157;
    pub const PAGING_POLICY_INDICATOR: u16 = 158;
    pub const APN_DNN: u16 = 159;
    pub const TGPP_INTERFACE_TYPE: u16 = 160;
    pub const PFCPSRREQ_FLAGS: u16 = 161;
    pub const PFCPAUREQ_FLAGS: u16 = 162;
    pub const ACTIVATION_TIME: u16 = 163;
    pub const DEACTIVATION_TIME: u16 = 164;
    pub const CREATE_MAR: u16 = 165;
    pub const ACCESS_FORWARDING_ACTION_INFORMATION_1: u16 = 166;
    pub const ACCESS_FORWARDING_ACTION_INFORMATION_2: u16 = 167;
    pub const REMOVE_MAR: u16 = 168;
    pub const UPDATE_MAR: u16 = 169;
    pub const MAR_ID: u16 = 170;
    pub const STEERING_FUNCTIONALITY: u16 = 171;
    pub const STEERING_MODE: u16 = 172;
    pub const WEIGHT: u16 = 173;
    pub const PRIORITY: u16 = 174;
    pub const UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_1: u16 = 175;
    pub const UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_2: u16 = 176;
    pub const UE_IP_ADDRESS_POOL_IDENTITY: u16 = 177;
    pub const ALTERNATIVE_SMF_IP_ADDRESS: u16 = 178;
    pub const PACKET_REPLICATION_AND_DETECTION_CARRY_ON_INFORMATION: u16 = 179;
    pub const SMF_SET_ID: u16 = 180;
    pub const QUOTA_VALIDITY_TIME: u16 = 181;
    pub const NUMBER_OF_REPORTS: u16 = 182;
    pub const PFCP_SESSION_RETENTION_INFORMATION: u16 = 183;
    pub const PFCPASRSP_FLAGS: u16 = 184;
    pub const CP_PFCP_ENTITY_IP_ADDRESS: u16 = 185;
    pub const PFCPSEREQ_FLAGS: u16 = 186;
    pub const USER_PLANE_PATH_RECOVERY_REPORT: u16 = 187;
    pub const IP_MULTICAST_ADDRESSING_INFO: u16 = 188;
    pub const JOIN_IP_MULTICAST_INFORMATION: u16 = 189;
    pub const LEAVE_IP_MULTICAST_INFORMATION: u16 = 190;
    pub const CREATED_BRIDGE_INFO_FOR_TSC: u16 = 191;
    pub const TSC_MANAGEMENT_INFORMATION: u16 = 192;
    pub const TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST: u16 = 193;
    pub const TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_RESPONSE: u16 = 194;
    pub const TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_REPORT_REQUEST: u16 = 195;
    pub const CLOCK_DRIFT_CONTROL_INFORMATION: u16 = 196;
    pub const CLOCK_DRIFT_REPORT: u16 = 197;
    pub const REQUESTED_CLOCK_DRIFT_INFORMATION: u16 = 198;
    pub const TIME_DOMAIN_NUMBER: u16 = 199;
    pub const TIME_OFFSET_THRESHOLD: u16 = 200;
    pub const CUMULATIVE_RATE_RATIO_THRESHOLD: u16 = 201;
    pub const TIME_OFFSET_MEASUREMENT: u16 = 202;
    pub const CUMULATIVE_RATE_RATIO_MEASUREMENT: u16 = 203;
    pub const REMOVE_SRR: u16 = 204;
    pub const CREATE_SRR: u16 = 205;
    pub const UPDATE_SRR: u16 = 206;
    pub const SESSION_REPORT: u16 = 207;
    pub const SRR_ID: u16 = 208;
    pub const ACCESS_AVAILABILITY_CONTROL_INFORMATION: u16 = 209;
    pub const REQUESTED_ACCESS_AVAILABILITY_INFORMATION: u16 = 210;
    pub const ACCESS_AVAILABILITY_REPORT: u16 = 211;
    pub const ACCESS_AVAILABILITY_INFORMATION: u16 = 212;
    pub const PROVIDE_ATSSS_CONTROL_INFORMATION: u16 = 213;
    pub const ATSSS_CONTROL_PARAMETERS: u16 = 214;
    pub const MPTCP_CONTROL_INFORMATION: u16 = 215;
    pub const ATSSS_LL_CONTROL_INFORMATION: u16 = 216;
    pub const PMF_CONTROL_INFORMATION: u16 = 217;
    pub const MPTCP_PARAMETERS: u16 = 218;
    pub const ATSSS_LL_PARAMETERS: u16 = 219;
    pub const PMF_PARAMETERS: u16 = 220;
    pub const MPTCP_ADDRESS_INFORMATION: u16 = 221;
    pub const UE_LINK_SPECIFIC_IP_ADDRESS: u16 = 222;
    pub const PMF_ADDRESS_INFORMATION: u16 = 223;
    pub const ATSSS_LL_INFORMATION: u16 = 224;
    pub const DATA_NETWORK_ACCESS_IDENTIFIER: u16 = 225;
    pub const UE_IP_ADDRESS_POOL_INFORMATION: u16 = 226;
    pub const AVERAGE_PACKET_DELAY: u16 = 227;
    pub const MINIMUM_PACKET_DELAY: u16 = 228;
    pub const MAXIMUM_PACKET_DELAY: u16 = 229;
    pub const QOS_REPORT_TRIGGER: u16 = 230;
    pub const GTP_U_PATH_QOS_CONTROL_INFORMATION: u16 = 231;
    pub const GTP_U_PATH_QOS_REPORT: u16 = 232;
    pub const QOS_INFORMATION_IN_GTP_U_PATH_QOS_REPORT: u16 = 233;
    pub const GTP_U_PATH_INTERFACE_TYPE: u16 = 234;
    pub const QOS_MONITORING_PER_QOS_FLOW_CONTROL_INFORMATION: u16 = 235;
    pub const REQUESTED_QOS_MONITORING: u16 = 236;
    pub const REPORTING_FREQUENCY: u16 = 237;
    pub const PACKET_DELAY_THRESHOLDS: u16 = 238;
    pub const MINIMUM_WAIT_TIME: u16 = 239;
    pub const QOS_MONITORING_REPORT: u16 = 240;
    pub const QOS_MONITORING_MEASUREMENT: u16 = 241;
    pub const MT_EDT_CONTROL_INFORMATION: u16 = 242;
    pub const DL_DATA_PACKETS_SIZE: u16 = 243;
    pub const QER_CONTROL_INDICATIONS: u16 = 244;
    pub const PACKET_RATE_STATUS_REPORT: u16 = 245;
    pub const NF_INSTANCE_ID: u16 = 246;
    pub const ETHERNET_CONTEXT_INFORMATION: u16 = 247;
    pub const REDUNDANT_TRANSMISSION_PARAMETERS: u16 = 248;
    pub const UPDATED_PDR: u16 = 249;
    pub const S_NSSAI: u16 = 250;
    pub const IP_VERSION: u16 = 251;
    pub const PFCPASREQ_FLAGS: u16 = 252;
    pub const DATA_STATUS: u16 = 253;
    pub const PROVIDE_RDS_CONFIGURATION_INFORMATION: u16 = 254;
    pub const RDS_CONFIGURATION_INFORMATION: u16 = 255;
}


// ============================================================================
// PFCP Modify Flags
// ============================================================================

/// PFCP modify flags for session modification requests
pub mod modify_flags {
    pub const CREATE: u64 = 1 << 0;
    pub const REMOVE: u64 = 1 << 1;
    pub const ACTIVATE: u64 = 1 << 2;
    pub const DEACTIVATE: u64 = 1 << 3;
    pub const DL_ONLY: u64 = 1 << 4;
    pub const UL_ONLY: u64 = 1 << 5;
    pub const INDIRECT: u64 = 1 << 6;
    pub const END_MARKER: u64 = 1 << 7;
    pub const TFT_NEW: u64 = 1 << 8;
    pub const TFT_ADD: u64 = 1 << 9;
    pub const TFT_REPLACE: u64 = 1 << 10;
    pub const TFT_DELETE: u64 = 1 << 11;
    pub const EPC_TFT_UPDATE: u64 = 1 << 12;
    pub const OUTER_HEADER_REMOVAL: u64 = 1 << 13;
    pub const QOS_MODIFY: u64 = 1 << 14;
    pub const EPC_QOS_UPDATE: u64 = 1 << 15;
    pub const URR_MEAS_METHOD: u64 = 1 << 16;
    pub const URR_REPORT_TRIGGER: u64 = 1 << 17;
    pub const URR_VOLUME_THRESH: u64 = 1 << 18;
    pub const URR_VOLUME_QUOTA: u64 = 1 << 19;
    pub const URR_TIME_THRESH: u64 = 1 << 20;
    pub const URR_TIME_QUOTA: u64 = 1 << 21;
    pub const URR_QUOTA_VALIDITY_TIME: u64 = 1 << 22;
    pub const SESSION: u64 = 1 << 23;
    pub const ERROR_INDICATION: u64 = 1 << 24;
    pub const HOME_ROUTED_ROAMING: u64 = 1 << 25;
    pub const XN_HANDOVER: u64 = 1 << 26;
    pub const N2_HANDOVER: u64 = 1 << 27;
    pub const FROM_ACTIVATING: u64 = 1 << 28;
    pub const RESTORATION_INDICATION: u64 = 1 << 29;
}

// ============================================================================
// PFCP Delete Triggers
// ============================================================================

/// PFCP delete triggers
pub mod delete_trigger {
    pub const LOCAL_INITIATED: i32 = 1;
    pub const UE_REQUESTED: i32 = 2;
    pub const AMF_UPDATE_SM_CONTEXT: i32 = 3;
    pub const AMF_RELEASE_SM_CONTEXT: i32 = 4;
    pub const PCF_INITIATED: i32 = 5;
}

// ============================================================================
// PFCP Interface Types
// ============================================================================

/// PFCP source/destination interface types
pub mod interface {
    pub const ACCESS: u8 = 0;
    pub const CORE: u8 = 1;
    pub const SGI_LAN_N6_LAN: u8 = 2;
    pub const CP_FUNCTION: u8 = 3;
    pub const LI_FUNCTION: u8 = 4;
    pub const N6_LAN: u8 = 5;
}

// ============================================================================
// PFCP Apply Action Flags
// ============================================================================

/// PFCP apply action flags
pub mod apply_action {
    pub const DROP: u16 = 1 << 0;
    pub const FORW: u16 = 1 << 1;
    pub const BUFF: u16 = 1 << 2;
    pub const NOCP: u16 = 1 << 3;
    pub const DUPL: u16 = 1 << 4;
    pub const IPMA: u16 = 1 << 5;
    pub const IPMD: u16 = 1 << 6;
    pub const DFRT: u16 = 1 << 7;
    pub const EDRT: u16 = 1 << 8;
    pub const BDPN: u16 = 1 << 9;
    pub const DDPN: u16 = 1 << 10;
}

// ============================================================================
// PFCP Message Builder
// ============================================================================

/// PFCP message builder
#[derive(Debug, Clone, Default)]
pub struct PfcpMessageBuilder {
    buffer: BytesMut,
}

impl PfcpMessageBuilder {
    /// Create a new PFCP message builder
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Create with specific capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Get the current length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Build and return the message bytes
    pub fn build(self) -> Vec<u8> {
        self.buffer.to_vec()
    }

    /// Add a TLV IE (Type-Length-Value)
    pub fn add_tlv(&mut self, ie_type: u16, value: &[u8]) -> &mut Self {
        self.buffer.put_u16(ie_type);
        self.buffer.put_u16(value.len() as u16);
        self.buffer.put_slice(value);
        self
    }

    /// Add a u8 IE
    pub fn add_u8(&mut self, ie_type: u16, value: u8) -> &mut Self {
        self.add_tlv(ie_type, &[value])
    }

    /// Add a u16 IE
    pub fn add_u16(&mut self, ie_type: u16, value: u16) -> &mut Self {
        self.add_tlv(ie_type, &value.to_be_bytes())
    }

    /// Add a u32 IE
    pub fn add_u32(&mut self, ie_type: u16, value: u32) -> &mut Self {
        self.add_tlv(ie_type, &value.to_be_bytes())
    }

    /// Add a u64 IE
    pub fn add_u64(&mut self, ie_type: u16, value: u64) -> &mut Self {
        self.add_tlv(ie_type, &value.to_be_bytes())
    }

    /// Add Node ID IE
    pub fn add_node_id(&mut self, node_id: &[u8]) -> &mut Self {
        self.add_tlv(pfcp_ie::NODE_ID, node_id)
    }

    /// Add F-SEID IE
    pub fn add_f_seid(&mut self, seid: u64, ipv4: Option<[u8; 4]>, ipv6: Option<[u8; 16]>) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        
        if ipv6.is_some() {
            flags |= 0x01; // V6 flag
        }
        if ipv4.is_some() {
            flags |= 0x02; // V4 flag
        }
        
        value.put_u8(flags);
        value.put_u64(seid);
        
        if let Some(addr) = ipv4 {
            value.put_slice(&addr);
        }
        if let Some(addr) = ipv6 {
            value.put_slice(&addr);
        }
        
        self.add_tlv(pfcp_ie::F_SEID, &value)
    }

    /// Add PDR ID IE
    pub fn add_pdr_id(&mut self, pdr_id: u16) -> &mut Self {
        self.add_u16(pfcp_ie::PDR_ID, pdr_id)
    }

    /// Add FAR ID IE
    pub fn add_far_id(&mut self, far_id: u32) -> &mut Self {
        self.add_u32(pfcp_ie::FAR_ID, far_id)
    }

    /// Add URR ID IE
    pub fn add_urr_id(&mut self, urr_id: u32) -> &mut Self {
        self.add_u32(pfcp_ie::URR_ID, urr_id)
    }

    /// Add QER ID IE
    pub fn add_qer_id(&mut self, qer_id: u32) -> &mut Self {
        self.add_u32(pfcp_ie::QER_ID, qer_id)
    }

    /// Add BAR ID IE
    pub fn add_bar_id(&mut self, bar_id: u8) -> &mut Self {
        self.add_u8(pfcp_ie::BAR_ID, bar_id)
    }

    /// Add Cause IE
    pub fn add_cause(&mut self, cause: PfcpCause) -> &mut Self {
        self.add_u8(pfcp_ie::CAUSE, cause as u8)
    }

    /// Add Cause IE from raw u8 value
    pub fn add_cause_raw(&mut self, cause: u8) -> &mut Self {
        self.add_u8(pfcp_ie::CAUSE, cause)
    }

    /// Add Precedence IE
    pub fn add_precedence(&mut self, precedence: u32) -> &mut Self {
        self.add_u32(pfcp_ie::PRECEDENCE, precedence)
    }

    /// Add Source Interface IE
    pub fn add_source_interface(&mut self, interface: u8) -> &mut Self {
        self.add_u8(pfcp_ie::SOURCE_INTERFACE, interface)
    }

    /// Add Destination Interface IE
    pub fn add_destination_interface(&mut self, interface: u8) -> &mut Self {
        self.add_u8(pfcp_ie::DESTINATION_INTERFACE, interface)
    }

    /// Add Apply Action IE
    pub fn add_apply_action(&mut self, action: u16) -> &mut Self {
        self.add_u16(pfcp_ie::APPLY_ACTION, action)
    }

    /// Add PDN Type IE
    pub fn add_pdn_type(&mut self, pdn_type: u8) -> &mut Self {
        self.add_u8(pfcp_ie::PDN_TYPE, pdn_type)
    }

    /// Add QFI IE
    pub fn add_qfi(&mut self, qfi: u8) -> &mut Self {
        self.add_u8(pfcp_ie::QFI, qfi)
    }

    /// Add APN/DNN IE
    pub fn add_apn_dnn(&mut self, apn: &str) -> &mut Self {
        // Build FQDN format
        let mut fqdn = Vec::new();
        for label in apn.split('.') {
            fqdn.push(label.len() as u8);
            fqdn.extend_from_slice(label.as_bytes());
        }
        self.add_tlv(pfcp_ie::APN_DNN, &fqdn)
    }

    /// Add S-NSSAI IE
    pub fn add_s_nssai(&mut self, sst: u8, sd: Option<u32>) -> &mut Self {
        let mut value = BytesMut::new();
        value.put_u8(sst);
        if let Some(sd_val) = sd {
            // SD is 3 bytes
            value.put_u8((sd_val >> 16) as u8);
            value.put_u8((sd_val >> 8) as u8);
            value.put_u8(sd_val as u8);
        }
        self.add_tlv(pfcp_ie::S_NSSAI, &value)
    }

    /// Add User ID IE
    pub fn add_user_id(&mut self, imsi: Option<&[u8]>, imeisv: Option<&[u8]>, msisdn: Option<&[u8]>) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        
        if imsi.is_some() {
            flags |= 0x01; // IMSIF
        }
        if imeisv.is_some() {
            flags |= 0x02; // IMEIF
        }
        if msisdn.is_some() {
            flags |= 0x04; // MSISDNF
        }
        
        value.put_u8(flags);
        
        if let Some(id) = imsi {
            value.put_u8(id.len() as u8);
            value.put_slice(id);
        }
        if let Some(id) = imeisv {
            value.put_u8(id.len() as u8);
            value.put_slice(id);
        }
        if let Some(id) = msisdn {
            value.put_u8(id.len() as u8);
            value.put_slice(id);
        }
        
        self.add_tlv(pfcp_ie::USER_ID, &value)
    }

    /// Add PFCPSEREQ Flags IE (Session Establishment Request Flags)
    pub fn add_pfcpsereq_flags(&mut self, restoration_indication: bool) -> &mut Self {
        let mut flags: u8 = 0;
        if restoration_indication {
            flags |= 0x01;
        }
        self.add_u8(pfcp_ie::PFCPSEREQ_FLAGS, flags)
    }

    /// Add Outer Header Removal IE
    pub fn add_outer_header_removal(&mut self, description: u8) -> &mut Self {
        self.add_u8(pfcp_ie::OUTER_HEADER_REMOVAL, description)
    }

    /// Add F-TEID IE
    pub fn add_f_teid(&mut self, teid: u32, ipv4: Option<[u8; 4]>, ipv6: Option<[u8; 16]>, choose_id: Option<u8>) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        
        if ipv6.is_some() {
            flags |= 0x01; // V6 flag
        }
        if ipv4.is_some() {
            flags |= 0x02; // V4 flag
        }
        if choose_id.is_some() {
            flags |= 0x04; // CH flag (CHOOSE)
        }
        
        value.put_u8(flags);
        value.put_u32(teid);
        
        if let Some(addr) = ipv4 {
            value.put_slice(&addr);
        }
        if let Some(addr) = ipv6 {
            value.put_slice(&addr);
        }
        if let Some(id) = choose_id {
            value.put_u8(id);
        }
        
        self.add_tlv(pfcp_ie::F_TEID, &value)
    }

    /// Add UE IP Address IE
    pub fn add_ue_ip_address(&mut self, ipv4: Option<[u8; 4]>, ipv6: Option<[u8; 16]>, source: bool, destination: bool) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        
        if ipv6.is_some() {
            flags |= 0x01; // V6 flag
        }
        if ipv4.is_some() {
            flags |= 0x02; // V4 flag
        }
        if source {
            flags |= 0x04; // S/D flag = 0 for source
        }
        if destination {
            flags |= 0x04; // S/D flag = 1 for destination
        }
        
        value.put_u8(flags);
        
        if let Some(addr) = ipv4 {
            value.put_slice(&addr);
        }
        if let Some(addr) = ipv6 {
            value.put_slice(&addr);
        }
        
        self.add_tlv(pfcp_ie::UE_IP_ADDRESS, &value)
    }

    /// Add Outer Header Creation IE
    pub fn add_outer_header_creation(&mut self, description: u16, teid: u32, ipv4: Option<[u8; 4]>, ipv6: Option<[u8; 16]>) -> &mut Self {
        let mut value = BytesMut::new();
        value.put_u16(description);
        value.put_u32(teid);
        
        if let Some(addr) = ipv4 {
            value.put_slice(&addr);
        }
        if let Some(addr) = ipv6 {
            value.put_slice(&addr);
        }
        
        self.add_tlv(pfcp_ie::OUTER_HEADER_CREATION, &value)
    }

    /// Add MBR (Maximum Bit Rate) IE
    pub fn add_mbr(&mut self, uplink: u64, downlink: u64) -> &mut Self {
        let mut value = BytesMut::new();
        // MBR is encoded as 5 bytes each for UL and DL
        value.put_slice(&uplink.to_be_bytes()[3..8]); // 5 bytes
        value.put_slice(&downlink.to_be_bytes()[3..8]); // 5 bytes
        self.add_tlv(pfcp_ie::MBR, &value)
    }

    /// Add GBR (Guaranteed Bit Rate) IE
    pub fn add_gbr(&mut self, uplink: u64, downlink: u64) -> &mut Self {
        let mut value = BytesMut::new();
        // GBR is encoded as 5 bytes each for UL and DL
        value.put_slice(&uplink.to_be_bytes()[3..8]); // 5 bytes
        value.put_slice(&downlink.to_be_bytes()[3..8]); // 5 bytes
        self.add_tlv(pfcp_ie::GBR, &value)
    }

    /// Add Gate Status IE
    pub fn add_gate_status(&mut self, dl_gate: u8, ul_gate: u8) -> &mut Self {
        let value = (dl_gate & 0x03) | ((ul_gate & 0x03) << 2);
        self.add_u8(pfcp_ie::GATE_STATUS, value)
    }

    /// Add Measurement Method IE
    pub fn add_measurement_method(&mut self, duration: bool, volume: bool, event: bool) -> &mut Self {
        let mut flags: u8 = 0;
        if duration {
            flags |= 0x01;
        }
        if volume {
            flags |= 0x02;
        }
        if event {
            flags |= 0x04;
        }
        self.add_u8(pfcp_ie::MEASUREMENT_METHOD, flags)
    }

    /// Add Reporting Triggers IE
    pub fn add_reporting_triggers(&mut self, triggers: u32) -> &mut Self {
        // Reporting triggers is a 3-byte field
        let mut value = BytesMut::new();
        value.put_u8((triggers >> 16) as u8);
        value.put_u8((triggers >> 8) as u8);
        value.put_u8(triggers as u8);
        self.add_tlv(pfcp_ie::REPORTING_TRIGGERS, &value)
    }

    /// Add Volume Threshold IE
    pub fn add_volume_threshold(&mut self, total: Option<u64>, uplink: Option<u64>, downlink: Option<u64>) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        
        if total.is_some() {
            flags |= 0x01;
        }
        if uplink.is_some() {
            flags |= 0x02;
        }
        if downlink.is_some() {
            flags |= 0x04;
        }
        
        value.put_u8(flags);
        
        if let Some(v) = total {
            value.put_u64(v);
        }
        if let Some(v) = uplink {
            value.put_u64(v);
        }
        if let Some(v) = downlink {
            value.put_u64(v);
        }
        
        self.add_tlv(pfcp_ie::VOLUME_THRESHOLD, &value)
    }

    /// Add Volume Quota IE
    pub fn add_volume_quota(&mut self, total: Option<u64>, uplink: Option<u64>, downlink: Option<u64>) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        
        if total.is_some() {
            flags |= 0x01;
        }
        if uplink.is_some() {
            flags |= 0x02;
        }
        if downlink.is_some() {
            flags |= 0x04;
        }
        
        value.put_u8(flags);
        
        if let Some(v) = total {
            value.put_u64(v);
        }
        if let Some(v) = uplink {
            value.put_u64(v);
        }
        if let Some(v) = downlink {
            value.put_u64(v);
        }
        
        self.add_tlv(pfcp_ie::VOLUME_QUOTA, &value)
    }

    /// Add Time Threshold IE
    pub fn add_time_threshold(&mut self, seconds: u32) -> &mut Self {
        self.add_u32(pfcp_ie::TIME_THRESHOLD, seconds)
    }

    /// Add Time Quota IE
    pub fn add_time_quota(&mut self, seconds: u32) -> &mut Self {
        self.add_u32(pfcp_ie::TIME_QUOTA, seconds)
    }

    /// Add Quota Validity Time IE
    pub fn add_quota_validity_time(&mut self, seconds: u32) -> &mut Self {
        self.add_u32(pfcp_ie::QUOTA_VALIDITY_TIME, seconds)
    }

    /// Add SDF Filter IE
    pub fn add_sdf_filter(&mut self, flow_description: Option<&str>, tos_traffic_class: Option<u16>, 
                          security_param_index: Option<u32>, flow_label: Option<u32>, sdf_filter_id: Option<u32>) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        
        if flow_description.is_some() {
            flags |= 0x01; // FD
        }
        if tos_traffic_class.is_some() {
            flags |= 0x02; // TTC
        }
        if security_param_index.is_some() {
            flags |= 0x04; // SPI
        }
        if flow_label.is_some() {
            flags |= 0x08; // FL
        }
        if sdf_filter_id.is_some() {
            flags |= 0x10; // BID
        }
        
        value.put_u8(flags);
        value.put_u8(0); // Spare
        
        if let Some(fd) = flow_description {
            let fd_bytes = fd.as_bytes();
            value.put_u16(fd_bytes.len() as u16);
            value.put_slice(fd_bytes);
        }
        if let Some(ttc) = tos_traffic_class {
            value.put_u16(ttc);
        }
        if let Some(spi) = security_param_index {
            value.put_u32(spi);
        }
        if let Some(fl) = flow_label {
            // Flow label is 3 bytes
            value.put_u8((fl >> 16) as u8);
            value.put_u8((fl >> 8) as u8);
            value.put_u8(fl as u8);
        }
        if let Some(bid) = sdf_filter_id {
            value.put_u32(bid);
        }
        
        self.add_tlv(pfcp_ie::SDF_FILTER, &value)
    }
}


// ============================================================================
// Session Establishment Request Builder
// ============================================================================

/// Build PFCP Session Establishment Request
/// Port of smf_n4_build_session_establishment_request
pub fn build_session_establishment_request(
    smf_n4_seid: u64,
    node_id: &[u8],
    local_addr_v4: Option<[u8; 4]>,
    local_addr_v6: Option<[u8; 16]>,
    pdn_type: Option<u8>,
    apn_dnn: Option<&str>,
    s_nssai: Option<(u8, Option<u32>)>,
    user_id: Option<(&[u8], Option<&[u8]>, Option<&[u8]>)>,
    restoration_indication: bool,
) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // Node ID
    builder.add_node_id(node_id);
    
    // F-SEID
    builder.add_f_seid(smf_n4_seid, local_addr_v4, local_addr_v6);
    
    // PDN Type
    if let Some(pdn) = pdn_type {
        builder.add_pdn_type(pdn);
    }
    
    // User ID
    if let Some((imsi, imeisv, msisdn)) = user_id {
        builder.add_user_id(Some(imsi), imeisv, msisdn);
    }
    
    // APN/DNN
    if let Some(apn) = apn_dnn {
        builder.add_apn_dnn(apn);
    }
    
    // S-NSSAI (5GC only)
    if let Some((sst, sd)) = s_nssai {
        builder.add_s_nssai(sst, sd);
    }
    
    // Restoration Indication
    if restoration_indication {
        builder.add_pfcpsereq_flags(true);
    }
    
    builder.build()
}

/// Build PFCP Session Deletion Request
/// Port of smf_n4_build_session_deletion_request
pub fn build_session_deletion_request() -> Vec<u8> {
    // Session deletion request has no IEs in the body
    Vec::new()
}

// ============================================================================
// PDR Builder
// ============================================================================

/// PDR (Packet Detection Rule) parameters
#[derive(Debug, Clone, Default)]
pub struct PdrParams {
    pub pdr_id: u16,
    pub precedence: u32,
    pub source_interface: u8,
    pub far_id: Option<u32>,
    pub urr_ids: Vec<u32>,
    pub qer_id: Option<u32>,
    pub outer_header_removal: Option<u8>,
    pub f_teid: Option<(u32, Option<[u8; 4]>, Option<[u8; 16]>)>,
    pub ue_ip_address: Option<(Option<[u8; 4]>, Option<[u8; 16]>, bool)>,
    pub sdf_filters: Vec<String>,
    pub qfi: Option<u8>,
    pub network_instance: Option<String>,
}

/// Build Create PDR IE
pub fn build_create_pdr(params: &PdrParams) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // PDR ID
    builder.add_pdr_id(params.pdr_id);
    
    // Precedence
    builder.add_precedence(params.precedence);
    
    // PDI (Packet Detection Information) - grouped IE
    let mut pdi_builder = PfcpMessageBuilder::new();
    
    // Source Interface
    pdi_builder.add_source_interface(params.source_interface);
    
    // F-TEID
    if let Some((teid, ipv4, ipv6)) = params.f_teid {
        pdi_builder.add_f_teid(teid, ipv4, ipv6, None);
    }
    
    // UE IP Address
    if let Some((ipv4, ipv6, source)) = params.ue_ip_address {
        pdi_builder.add_ue_ip_address(ipv4, ipv6, source, !source);
    }
    
    // SDF Filters
    for sdf in &params.sdf_filters {
        pdi_builder.add_sdf_filter(Some(sdf), None, None, None, None);
    }
    
    // QFI
    if let Some(qfi) = params.qfi {
        pdi_builder.add_qfi(qfi);
    }
    
    // Network Instance
    if let Some(ref ni) = params.network_instance {
        pdi_builder.add_tlv(pfcp_ie::NETWORK_INSTANCE, ni.as_bytes());
    }
    
    // Add PDI to Create PDR
    builder.add_tlv(pfcp_ie::PDI, &pdi_builder.build());
    
    // Outer Header Removal
    if let Some(ohr) = params.outer_header_removal {
        builder.add_outer_header_removal(ohr);
    }
    
    // FAR ID
    if let Some(far_id) = params.far_id {
        builder.add_far_id(far_id);
    }
    
    // URR IDs
    for urr_id in &params.urr_ids {
        builder.add_urr_id(*urr_id);
    }
    
    // QER ID
    if let Some(qer_id) = params.qer_id {
        builder.add_qer_id(qer_id);
    }
    
    builder.build()
}

/// Build Update PDR IE
pub fn build_update_pdr(pdr_id: u16, outer_header_removal: Option<u8>) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // PDR ID
    builder.add_pdr_id(pdr_id);
    
    // Outer Header Removal
    if let Some(ohr) = outer_header_removal {
        builder.add_outer_header_removal(ohr);
    }
    
    builder.build()
}

/// Build Remove PDR IE
pub fn build_remove_pdr(pdr_id: u16) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    builder.add_pdr_id(pdr_id);
    builder.build()
}

// ============================================================================
// FAR Builder
// ============================================================================

/// FAR (Forwarding Action Rule) parameters
#[derive(Debug, Clone, Default)]
pub struct FarParams {
    pub far_id: u32,
    pub apply_action: u16,
    pub destination_interface: Option<u8>,
    pub outer_header_creation: Option<(u16, u32, Option<[u8; 4]>, Option<[u8; 16]>)>,
    pub network_instance: Option<String>,
}

/// Build Create FAR IE
pub fn build_create_far(params: &FarParams) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // FAR ID
    builder.add_far_id(params.far_id);
    
    // Apply Action
    builder.add_apply_action(params.apply_action);
    
    // Forwarding Parameters (grouped IE) - only if FORW action
    if params.apply_action & apply_action::FORW != 0 {
        let mut fp_builder = PfcpMessageBuilder::new();
        
        // Destination Interface
        if let Some(dst_if) = params.destination_interface {
            fp_builder.add_destination_interface(dst_if);
        }
        
        // Network Instance
        if let Some(ref ni) = params.network_instance {
            fp_builder.add_tlv(pfcp_ie::NETWORK_INSTANCE, ni.as_bytes());
        }
        
        // Outer Header Creation
        if let Some((desc, teid, ipv4, ipv6)) = params.outer_header_creation {
            fp_builder.add_outer_header_creation(desc, teid, ipv4, ipv6);
        }
        
        builder.add_tlv(pfcp_ie::FORWARDING_PARAMETERS, &fp_builder.build());
    }
    
    builder.build()
}

/// Build Update FAR IE for activation
pub fn build_update_far_activate(far_id: u32, destination_interface: u8, 
                                  outer_header_creation: Option<(u16, u32, Option<[u8; 4]>, Option<[u8; 16]>)>,
                                  send_end_marker: bool) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // FAR ID
    builder.add_far_id(far_id);
    
    // Apply Action - FORW
    builder.add_apply_action(apply_action::FORW);
    
    // Update Forwarding Parameters (grouped IE)
    let mut ufp_builder = PfcpMessageBuilder::new();
    
    // Destination Interface
    ufp_builder.add_destination_interface(destination_interface);
    
    // Outer Header Creation
    if let Some((desc, teid, ipv4, ipv6)) = outer_header_creation {
        ufp_builder.add_outer_header_creation(desc, teid, ipv4, ipv6);
    }
    
    // PFCPSMREQ Flags (send end marker)
    if send_end_marker {
        ufp_builder.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, 0x01);
    }
    
    builder.add_tlv(pfcp_ie::UPDATE_FORWARDING_PARAMETERS, &ufp_builder.build());
    
    builder.build()
}

/// Build Update FAR IE for deactivation
pub fn build_update_far_deactivate(far_id: u32) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // FAR ID
    builder.add_far_id(far_id);
    
    // Apply Action - BUFF | NOCP
    builder.add_apply_action(apply_action::BUFF | apply_action::NOCP);
    
    builder.build()
}

/// Build Remove FAR IE
pub fn build_remove_far(far_id: u32) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    builder.add_far_id(far_id);
    builder.build()
}

// ============================================================================
// URR Builder
// ============================================================================

/// URR (Usage Reporting Rule) parameters
#[derive(Debug, Clone, Default)]
pub struct UrrParams {
    pub urr_id: u32,
    pub measurement_method: (bool, bool, bool), // (duration, volume, event)
    pub reporting_triggers: u32,
    pub volume_threshold: Option<(Option<u64>, Option<u64>, Option<u64>)>,
    pub volume_quota: Option<(Option<u64>, Option<u64>, Option<u64>)>,
    pub time_threshold: Option<u32>,
    pub time_quota: Option<u32>,
    pub quota_validity_time: Option<u32>,
}

/// Build Create URR IE
pub fn build_create_urr(params: &UrrParams) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // URR ID
    builder.add_urr_id(params.urr_id);
    
    // Measurement Method
    let (duration, volume, event) = params.measurement_method;
    builder.add_measurement_method(duration, volume, event);
    
    // Reporting Triggers
    builder.add_reporting_triggers(params.reporting_triggers);
    
    // Volume Threshold
    if let Some((total, uplink, downlink)) = params.volume_threshold {
        builder.add_volume_threshold(total, uplink, downlink);
    }
    
    // Volume Quota
    if let Some((total, uplink, downlink)) = params.volume_quota {
        builder.add_volume_quota(total, uplink, downlink);
    }
    
    // Time Threshold
    if let Some(seconds) = params.time_threshold {
        builder.add_time_threshold(seconds);
    }
    
    // Time Quota
    if let Some(seconds) = params.time_quota {
        builder.add_time_quota(seconds);
    }
    
    // Quota Validity Time
    if let Some(seconds) = params.quota_validity_time {
        builder.add_quota_validity_time(seconds);
    }
    
    builder.build()
}

/// Build Update URR IE
pub fn build_update_urr(params: &UrrParams, modify_flags: u64) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // URR ID
    builder.add_urr_id(params.urr_id);
    
    // Measurement Method
    if modify_flags & modify_flags::URR_MEAS_METHOD != 0 {
        let (duration, volume, event) = params.measurement_method;
        builder.add_measurement_method(duration, volume, event);
    }
    
    // Reporting Triggers
    if modify_flags & modify_flags::URR_REPORT_TRIGGER != 0 {
        builder.add_reporting_triggers(params.reporting_triggers);
    }
    
    // Volume Threshold
    if modify_flags & modify_flags::URR_VOLUME_THRESH != 0 {
        if let Some((total, uplink, downlink)) = params.volume_threshold {
            builder.add_volume_threshold(total, uplink, downlink);
        }
    }
    
    // Volume Quota
    if modify_flags & modify_flags::URR_VOLUME_QUOTA != 0 {
        if let Some((total, uplink, downlink)) = params.volume_quota {
            builder.add_volume_quota(total, uplink, downlink);
        }
    }
    
    // Time Threshold
    if modify_flags & modify_flags::URR_TIME_THRESH != 0 {
        if let Some(seconds) = params.time_threshold {
            builder.add_time_threshold(seconds);
        }
    }
    
    // Time Quota
    if modify_flags & modify_flags::URR_TIME_QUOTA != 0 {
        if let Some(seconds) = params.time_quota {
            builder.add_time_quota(seconds);
        }
    }
    
    // Quota Validity Time
    if modify_flags & modify_flags::URR_QUOTA_VALIDITY_TIME != 0 {
        if let Some(seconds) = params.quota_validity_time {
            builder.add_quota_validity_time(seconds);
        }
    }
    
    builder.build()
}

/// Build Remove URR IE
pub fn build_remove_urr(urr_id: u32) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    builder.add_urr_id(urr_id);
    builder.build()
}

// ============================================================================
// QER Builder
// ============================================================================

/// QER (QoS Enforcement Rule) parameters
#[derive(Debug, Clone, Default)]
pub struct QerParams {
    pub qer_id: u32,
    pub gate_status: (u8, u8), // (dl_gate, ul_gate)
    pub mbr: Option<(u64, u64)>, // (uplink, downlink)
    pub gbr: Option<(u64, u64)>, // (uplink, downlink)
    pub qfi: Option<u8>,
}

/// Build Create QER IE
pub fn build_create_qer(params: &QerParams) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // QER ID
    builder.add_qer_id(params.qer_id);
    
    // Gate Status
    let (dl_gate, ul_gate) = params.gate_status;
    builder.add_gate_status(dl_gate, ul_gate);
    
    // MBR
    if let Some((uplink, downlink)) = params.mbr {
        builder.add_mbr(uplink, downlink);
    }
    
    // GBR
    if let Some((uplink, downlink)) = params.gbr {
        builder.add_gbr(uplink, downlink);
    }
    
    // QFI
    if let Some(qfi) = params.qfi {
        builder.add_qfi(qfi);
    }
    
    builder.build()
}

/// Build Update QER IE
pub fn build_update_qer(params: &QerParams) -> Vec<u8> {
    // Same as create for now
    build_create_qer(params)
}

/// Build Remove QER IE
pub fn build_remove_qer(qer_id: u32) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    builder.add_qer_id(qer_id);
    builder.build()
}

// ============================================================================
// BAR Builder
// ============================================================================

/// BAR (Buffering Action Rule) parameters
#[derive(Debug, Clone, Default)]
pub struct BarParams {
    pub bar_id: u8,
    pub downlink_data_notification_delay: Option<u8>,
    pub suggested_buffering_packets_count: Option<u8>,
}

/// Build Create BAR IE
pub fn build_create_bar(params: &BarParams) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // BAR ID
    builder.add_bar_id(params.bar_id);
    
    // Downlink Data Notification Delay
    if let Some(delay) = params.downlink_data_notification_delay {
        builder.add_u8(pfcp_ie::DOWNLINK_DATA_NOTIFICATION_DELAY, delay);
    }
    
    // Suggested Buffering Packets Count
    if let Some(count) = params.suggested_buffering_packets_count {
        builder.add_u8(pfcp_ie::SUGGESTED_BUFFERING_PACKETS_COUNT, count);
    }
    
    builder.build()
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pfcp_cause_from_u8() {
        assert_eq!(PfcpCause::from(1), PfcpCause::RequestAccepted);
        assert_eq!(PfcpCause::from(64), PfcpCause::RequestRejected);
        assert_eq!(PfcpCause::from(65), PfcpCause::SessionContextNotFound);
        assert_eq!(PfcpCause::from(77), PfcpCause::SystemFailure);
        assert_eq!(PfcpCause::from(255), PfcpCause::SystemFailure); // Unknown
    }

    #[test]
    fn test_pfcp_cause_default() {
        assert_eq!(PfcpCause::default(), PfcpCause::RequestAccepted);
    }

    #[test]
    fn test_pfcp_message_builder_new() {
        let builder = PfcpMessageBuilder::new();
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
    }

    #[test]
    fn test_pfcp_message_builder_add_u8() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_u8(pfcp_ie::CAUSE, 1);
        let data = builder.build();
        
        // Type (2 bytes) + Length (2 bytes) + Value (1 byte)
        assert_eq!(data.len(), 5);
        assert_eq!(data[0], 0); // Type high byte
        assert_eq!(data[1], pfcp_ie::CAUSE as u8); // Type low byte
        assert_eq!(data[2], 0); // Length high byte
        assert_eq!(data[3], 1); // Length low byte
        assert_eq!(data[4], 1); // Value
    }

    #[test]
    fn test_pfcp_message_builder_add_u16() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_u16(pfcp_ie::PDR_ID, 0x1234);
        let data = builder.build();
        
        assert_eq!(data.len(), 6);
        assert_eq!(data[4], 0x12);
        assert_eq!(data[5], 0x34);
    }

    #[test]
    fn test_pfcp_message_builder_add_u32() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_u32(pfcp_ie::FAR_ID, 0x12345678);
        let data = builder.build();
        
        assert_eq!(data.len(), 8);
        assert_eq!(data[4], 0x12);
        assert_eq!(data[5], 0x34);
        assert_eq!(data[6], 0x56);
        assert_eq!(data[7], 0x78);
    }

    #[test]
    fn test_pfcp_message_builder_add_f_seid() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_f_seid(0x123456789ABCDEF0, Some([192, 168, 1, 1]), None);
        let data = builder.build();
        
        // Type (2) + Length (2) + Flags (1) + SEID (8) + IPv4 (4) = 17
        assert_eq!(data.len(), 17);
        assert_eq!(data[4], 0x02); // V4 flag
    }

    #[test]
    fn test_pfcp_message_builder_add_apn_dnn() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_apn_dnn("internet");
        let data = builder.build();
        
        // Type (2) + Length (2) + FQDN (1 + 8) = 13
        assert_eq!(data.len(), 13);
        assert_eq!(data[4], 8); // Label length
        assert_eq!(&data[5..13], b"internet");
    }

    #[test]
    fn test_pfcp_message_builder_add_s_nssai() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_s_nssai(1, Some(0x010203));
        let data = builder.build();
        
        // Type (2) + Length (2) + SST (1) + SD (3) = 8
        assert_eq!(data.len(), 8);
        assert_eq!(data[4], 1); // SST
        assert_eq!(data[5], 0x01); // SD high
        assert_eq!(data[6], 0x02); // SD mid
        assert_eq!(data[7], 0x03); // SD low
    }

    #[test]
    fn test_pfcp_message_builder_add_s_nssai_no_sd() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_s_nssai(1, None);
        let data = builder.build();
        
        // Type (2) + Length (2) + SST (1) = 5
        assert_eq!(data.len(), 5);
        assert_eq!(data[4], 1); // SST
    }

    #[test]
    fn test_build_session_establishment_request() {
        let data = build_session_establishment_request(
            0x123456789ABCDEF0,
            &[0x00, 192, 168, 1, 1], // Node ID (IPv4)
            Some([192, 168, 1, 1]),
            None,
            Some(1), // IPv4
            Some("internet"),
            Some((1, Some(0x010203))),
            None,
            false,
        );
        
        assert!(!data.is_empty());
    }

    #[test]
    fn test_build_session_deletion_request() {
        let data = build_session_deletion_request();
        assert!(data.is_empty());
    }

    #[test]
    fn test_build_create_pdr() {
        let params = PdrParams {
            pdr_id: 1,
            precedence: 100,
            source_interface: interface::ACCESS,
            far_id: Some(1),
            qfi: Some(9),
            ..Default::default()
        };
        
        let data = build_create_pdr(&params);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_build_remove_pdr() {
        let data = build_remove_pdr(1);
        
        // Type (2) + Length (2) + PDR ID (2) = 6
        assert_eq!(data.len(), 6);
    }

    #[test]
    fn test_build_create_far() {
        let params = FarParams {
            far_id: 1,
            apply_action: apply_action::FORW,
            destination_interface: Some(interface::CORE),
            ..Default::default()
        };
        
        let data = build_create_far(&params);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_build_update_far_activate() {
        let data = build_update_far_activate(
            1,
            interface::ACCESS,
            Some((0x0100, 0x12345678, Some([10, 0, 0, 1]), None)),
            true,
        );
        
        assert!(!data.is_empty());
    }

    #[test]
    fn test_build_update_far_deactivate() {
        let data = build_update_far_deactivate(1);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_build_remove_far() {
        let data = build_remove_far(1);
        
        // Type (2) + Length (2) + FAR ID (4) = 8
        assert_eq!(data.len(), 8);
    }

    #[test]
    fn test_build_create_urr() {
        let params = UrrParams {
            urr_id: 1,
            measurement_method: (true, true, false),
            reporting_triggers: 0x010000,
            volume_threshold: Some((Some(1000000), None, None)),
            time_threshold: Some(3600),
            ..Default::default()
        };
        
        let data = build_create_urr(&params);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_build_remove_urr() {
        let data = build_remove_urr(1);
        
        // Type (2) + Length (2) + URR ID (4) = 8
        assert_eq!(data.len(), 8);
    }

    #[test]
    fn test_build_create_qer() {
        let params = QerParams {
            qer_id: 1,
            gate_status: (0, 0), // Open
            mbr: Some((100000000, 100000000)),
            qfi: Some(9),
            ..Default::default()
        };
        
        let data = build_create_qer(&params);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_build_remove_qer() {
        let data = build_remove_qer(1);
        
        // Type (2) + Length (2) + QER ID (4) = 8
        assert_eq!(data.len(), 8);
    }

    #[test]
    fn test_build_create_bar() {
        let params = BarParams {
            bar_id: 1,
            downlink_data_notification_delay: Some(50),
            suggested_buffering_packets_count: Some(10),
        };
        
        let data = build_create_bar(&params);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_modify_flags_constants() {
        assert_eq!(modify_flags::CREATE, 1);
        assert_eq!(modify_flags::REMOVE, 2);
        assert_eq!(modify_flags::ACTIVATE, 4);
        assert_eq!(modify_flags::DEACTIVATE, 8);
    }

    #[test]
    fn test_delete_trigger_constants() {
        assert_eq!(delete_trigger::LOCAL_INITIATED, 1);
        assert_eq!(delete_trigger::UE_REQUESTED, 2);
        assert_eq!(delete_trigger::AMF_UPDATE_SM_CONTEXT, 3);
        assert_eq!(delete_trigger::AMF_RELEASE_SM_CONTEXT, 4);
        assert_eq!(delete_trigger::PCF_INITIATED, 5);
    }

    #[test]
    fn test_interface_constants() {
        assert_eq!(interface::ACCESS, 0);
        assert_eq!(interface::CORE, 1);
        assert_eq!(interface::CP_FUNCTION, 3);
    }

    #[test]
    fn test_apply_action_constants() {
        assert_eq!(apply_action::DROP, 1);
        assert_eq!(apply_action::FORW, 2);
        assert_eq!(apply_action::BUFF, 4);
        assert_eq!(apply_action::NOCP, 8);
    }

    #[test]
    fn test_pfcp_message_builder_clear() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_u8(pfcp_ie::CAUSE, 1);
        assert!(!builder.is_empty());
        
        builder.clear();
        assert!(builder.is_empty());
    }

    #[test]
    fn test_pfcp_message_builder_chaining() {
        let mut builder = PfcpMessageBuilder::new();
        builder
            .add_u8(pfcp_ie::CAUSE, 1)
            .add_u16(pfcp_ie::PDR_ID, 1)
            .add_u32(pfcp_ie::FAR_ID, 1);
        
        // 5 + 6 + 8 = 19 bytes
        assert_eq!(builder.len(), 19);
    }

    #[test]
    fn test_build_update_pdr() {
        let data = build_update_pdr(1, Some(0));
        assert!(!data.is_empty());
    }

    #[test]
    fn test_build_update_urr() {
        let params = UrrParams {
            urr_id: 1,
            volume_quota: Some((Some(500000), None, None)),
            ..Default::default()
        };
        
        let data = build_update_urr(&params, modify_flags::URR_VOLUME_QUOTA);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_pfcp_message_builder_add_user_id() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_user_id(Some(&[0x00, 0x10, 0x10]), None, None);
        let data = builder.build();
        
        assert!(!data.is_empty());
        // Flags should have IMSIF set
        assert_eq!(data[4] & 0x01, 0x01);
    }

    #[test]
    fn test_pfcp_message_builder_add_sdf_filter() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_sdf_filter(Some("permit out ip from any to any"), None, None, None, None);
        let data = builder.build();
        
        assert!(!data.is_empty());
    }
}
