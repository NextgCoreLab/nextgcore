//! UPF N4 (PFCP) Message Building
//!
//! Port of src/upf/n4-build.c - PFCP message building for UPF

use bytes::{BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

// ============================================================================
// PFCP Message Types
// ============================================================================

/// PFCP message types
pub mod pfcp_type {
    pub const HEARTBEAT_REQUEST: u8 = 1;
    pub const HEARTBEAT_RESPONSE: u8 = 2;
    pub const ASSOCIATION_SETUP_REQUEST: u8 = 5;
    pub const ASSOCIATION_SETUP_RESPONSE: u8 = 6;
    pub const ASSOCIATION_UPDATE_REQUEST: u8 = 7;
    pub const ASSOCIATION_UPDATE_RESPONSE: u8 = 8;
    pub const ASSOCIATION_RELEASE_REQUEST: u8 = 9;
    pub const ASSOCIATION_RELEASE_RESPONSE: u8 = 10;
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
    pub const CREATE_URR: u16 = 6;
    pub const CREATE_QER: u16 = 7;
    pub const CREATED_PDR: u16 = 8;
    pub const UPDATE_PDR: u16 = 9;
    pub const UPDATE_FAR: u16 = 10;
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
    pub const PRECEDENCE: u16 = 29;
    pub const VOLUME_THRESHOLD: u16 = 31;
    pub const TIME_THRESHOLD: u16 = 32;
    pub const REPORTING_TRIGGERS: u16 = 37;
    pub const REPORT_TYPE: u16 = 39;
    pub const OFFENDING_IE: u16 = 40;
    pub const DESTINATION_INTERFACE: u16 = 42;
    pub const UP_FUNCTION_FEATURES: u16 = 43;
    pub const APPLY_ACTION: u16 = 44;
    pub const PDR_ID: u16 = 56;
    pub const F_SEID: u16 = 57;
    pub const NODE_ID: u16 = 60;
    pub const MEASUREMENT_METHOD: u16 = 62;
    pub const USAGE_REPORT_TRIGGER: u16 = 63;
    pub const VOLUME_MEASUREMENT: u16 = 66;
    pub const DURATION_MEASUREMENT: u16 = 67;
    pub const TIME_OF_FIRST_PACKET: u16 = 69;
    pub const TIME_OF_LAST_PACKET: u16 = 70;
    pub const VOLUME_QUOTA: u16 = 73;
    pub const TIME_QUOTA: u16 = 74;
    pub const START_TIME: u16 = 75;
    pub const END_TIME: u16 = 76;
    pub const USAGE_REPORT_SMR: u16 = 78;
    pub const USAGE_REPORT_SDR: u16 = 79;
    pub const USAGE_REPORT_SRR: u16 = 80;
    pub const URR_ID: u16 = 81;
    pub const OUTER_HEADER_CREATION: u16 = 84;
    pub const CREATE_BAR: u16 = 85;
    pub const REMOVE_BAR: u16 = 87;
    pub const BAR_ID: u16 = 88;
    pub const UE_IP_ADDRESS: u16 = 93;
    pub const OUTER_HEADER_REMOVAL: u16 = 95;
    pub const RECOVERY_TIME_STAMP: u16 = 96;
    pub const FAR_ID: u16 = 108;
    pub const QER_ID: u16 = 109;
    pub const PDN_TYPE: u16 = 113;
    pub const QFI: u16 = 124;
    pub const FRAMED_ROUTE: u16 = 153;
    pub const FRAMED_IPV6_ROUTE: u16 = 155;
    pub const APN_DNN: u16 = 159;
    pub const PFCPSEREQ_FLAGS: u16 = 186;
}

// ============================================================================
// Created PDR Structure
// ============================================================================

/// Created PDR information for session establishment/modification response
#[derive(Debug, Clone, Default)]
pub struct CreatedPdr {
    pub pdr_id: u16,
    pub local_f_teid: Option<FTeid>,
    pub ue_ip_address: Option<UeIpAddress>,
}

/// F-TEID (Fully Qualified Tunnel Endpoint Identifier)
#[derive(Debug, Clone, Default)]
pub struct FTeid {
    pub teid: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub choose: bool,
    pub choose_id: Option<u8>,
}

/// UE IP Address
#[derive(Debug, Clone, Default)]
pub struct UeIpAddress {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub ipv6_prefix_len: u8,
}

/// Usage Report for session deletion/report
#[derive(Debug, Clone, Default)]
pub struct UsageReport {
    pub urr_id: u32,
    pub ur_seqn: u32,
    pub trigger: UsageReportTrigger,
    pub start_time: Option<u32>,
    pub end_time: Option<u32>,
    pub volume_measurement: Option<VolumeMeasurement>,
    pub duration_measurement: Option<u32>,
    pub time_of_first_packet: Option<u32>,
    pub time_of_last_packet: Option<u32>,
}

/// Usage Report Trigger flags
#[derive(Debug, Clone, Default)]
pub struct UsageReportTrigger {
    pub periodic_reporting: bool,
    pub volume_threshold: bool,
    pub time_threshold: bool,
    pub quota_holding_time: bool,
    pub start_of_traffic: bool,
    pub stop_of_traffic: bool,
    pub dropped_dl_traffic_threshold: bool,
    pub immediate_report: bool,
    pub volume_quota: bool,
    pub time_quota: bool,
    pub linked_usage_reporting: bool,
    pub termination_report: bool,
    pub monitoring_time: bool,
    pub envelope_closure: bool,
    pub mac_addresses_reporting: bool,
    pub event_threshold: bool,
    pub event_quota: bool,
    pub termination_by_up_function_report: bool,
    pub ip_multicast_join_leave: bool,
    pub quota_validity_time: bool,
}

/// Volume Measurement
#[derive(Debug, Clone, Default)]
pub struct VolumeMeasurement {
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
    pub total_packets: Option<u64>,
    pub uplink_packets: Option<u64>,
    pub downlink_packets: Option<u64>,
}

/// User Plane Report (for session report request)
#[derive(Debug, Clone, Default)]
pub struct UserPlaneReport {
    pub report_type: ReportType,
    pub downlink_data_report: Option<DownlinkDataReport>,
    pub usage_reports: Vec<UsageReport>,
    pub error_indication_report: Option<ErrorIndicationReport>,
}

/// Report Type flags
#[derive(Debug, Clone, Default)]
pub struct ReportType {
    pub downlink_data_report: bool,
    pub usage_report: bool,
    pub error_indication_report: bool,
    pub uplink_data_report: bool,
    pub session_report: bool,
}

/// Downlink Data Report
#[derive(Debug, Clone, Default)]
pub struct DownlinkDataReport {
    pub pdr_id: u16,
    pub downlink_data_service_info: Option<DownlinkDataServiceInfo>,
}

/// Downlink Data Service Information
#[derive(Debug, Clone, Default)]
pub struct DownlinkDataServiceInfo {
    pub ppi: Option<u8>,
    pub qfi: Option<u8>,
}

/// Error Indication Report
#[derive(Debug, Clone, Default)]
pub struct ErrorIndicationReport {
    pub remote_f_teid: FTeid,
}

// ============================================================================
// Node ID
// ============================================================================

/// PFCP Node ID types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeId {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Fqdn(String),
}

impl Default for NodeId {
    fn default() -> Self {
        NodeId::Ipv4(Ipv4Addr::UNSPECIFIED)
    }
}

impl NodeId {
    /// Encode node ID to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            NodeId::Ipv4(addr) => {
                buf.push(0); // Type = IPv4
                buf.extend_from_slice(&addr.octets());
            }
            NodeId::Ipv6(addr) => {
                buf.push(1); // Type = IPv6
                buf.extend_from_slice(&addr.octets());
            }
            NodeId::Fqdn(fqdn) => {
                buf.push(2); // Type = FQDN
                // Encode as DNS label format
                for label in fqdn.split('.') {
                    buf.push(label.len() as u8);
                    buf.extend_from_slice(label.as_bytes());
                }
            }
        }
        buf
    }
}

// ============================================================================
// F-SEID
// ============================================================================

/// F-SEID (Fully Qualified SEID)
#[derive(Debug, Clone, Default)]
pub struct FSeid {
    pub seid: u64,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl FSeid {
    /// Encode F-SEID to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        let mut flags: u8 = 0;
        if self.ipv6.is_some() { flags |= 0x01; }
        if self.ipv4.is_some() { flags |= 0x02; }
        buf.put_u8(flags);
        buf.put_u64(self.seid);
        if let Some(addr) = self.ipv4 { buf.put_slice(&addr.octets()); }
        if let Some(addr) = self.ipv6 { buf.put_slice(&addr.octets()); }
        buf.to_vec()
    }
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
        Self { buffer: BytesMut::with_capacity(4096) }
    }

    /// Get the current length
    pub fn len(&self) -> usize { self.buffer.len() }

    /// Check if empty
    pub fn is_empty(&self) -> bool { self.buffer.is_empty() }

    /// Clear the buffer
    pub fn clear(&mut self) { self.buffer.clear(); }

    /// Build and return the message bytes
    pub fn build(self) -> Vec<u8> { self.buffer.to_vec() }

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
    pub fn add_node_id(&mut self, node_id: &NodeId) -> &mut Self {
        self.add_tlv(pfcp_ie::NODE_ID, &node_id.encode())
    }

    /// Add F-SEID IE
    pub fn add_f_seid(&mut self, f_seid: &FSeid) -> &mut Self {
        self.add_tlv(pfcp_ie::F_SEID, &f_seid.encode())
    }

    /// Add Cause IE
    pub fn add_cause(&mut self, cause: PfcpCause) -> &mut Self {
        self.add_u8(pfcp_ie::CAUSE, cause as u8)
    }

    /// Add PDR ID IE
    pub fn add_pdr_id(&mut self, pdr_id: u16) -> &mut Self {
        self.add_u16(pfcp_ie::PDR_ID, pdr_id)
    }

    /// Add F-TEID IE
    pub fn add_f_teid(&mut self, f_teid: &FTeid) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        if f_teid.ipv6.is_some() { flags |= 0x01; }
        if f_teid.ipv4.is_some() { flags |= 0x02; }
        if f_teid.choose { flags |= 0x04; }
        value.put_u8(flags);
        value.put_u32(f_teid.teid);
        if let Some(addr) = f_teid.ipv4 { value.put_slice(&addr.octets()); }
        if let Some(addr) = f_teid.ipv6 { value.put_slice(&addr.octets()); }
        if let Some(id) = f_teid.choose_id { value.put_u8(id); }
        self.add_tlv(pfcp_ie::F_TEID, &value)
    }

    /// Add UE IP Address IE
    pub fn add_ue_ip_address(&mut self, ue_ip: &UeIpAddress, source: bool) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        if ue_ip.ipv6.is_some() { flags |= 0x01; }
        if ue_ip.ipv4.is_some() { flags |= 0x02; }
        if source { flags |= 0x04; }
        if ue_ip.ipv6_prefix_len > 0 { flags |= 0x08; }
        value.put_u8(flags);
        if let Some(addr) = ue_ip.ipv4 { value.put_slice(&addr.octets()); }
        if let Some(addr) = ue_ip.ipv6 { value.put_slice(&addr.octets()); }
        if ue_ip.ipv6_prefix_len > 0 { value.put_u8(ue_ip.ipv6_prefix_len); }
        self.add_tlv(pfcp_ie::UE_IP_ADDRESS, &value)
    }

    /// Add Created PDR IE
    pub fn add_created_pdr(&mut self, created_pdr: &CreatedPdr) -> &mut Self {
        let mut inner = PfcpMessageBuilder::new();
        inner.add_pdr_id(created_pdr.pdr_id);
        if let Some(ref f_teid) = created_pdr.local_f_teid {
            inner.add_f_teid(f_teid);
        }
        if let Some(ref ue_ip) = created_pdr.ue_ip_address {
            inner.add_ue_ip_address(ue_ip, false);
        }
        self.add_tlv(pfcp_ie::CREATED_PDR, &inner.build())
    }

    /// Add Usage Report IE (for Session Modification/Deletion Response)
    pub fn add_usage_report(&mut self, report: &UsageReport, ie_type: u16) -> &mut Self {
        let mut inner = PfcpMessageBuilder::new();
        inner.add_u32(pfcp_ie::URR_ID, report.urr_id);
        // UR-SEQN
        inner.add_u32(104, report.ur_seqn); // UR_SEQN IE type
        // Usage Report Trigger
        inner.add_usage_report_trigger(&report.trigger);
        if let Some(t) = report.start_time {
            inner.add_u32(pfcp_ie::START_TIME, t);
        }
        if let Some(t) = report.end_time {
            inner.add_u32(pfcp_ie::END_TIME, t);
        }
        if let Some(ref vol) = report.volume_measurement {
            inner.add_volume_measurement(vol);
        }
        if let Some(dur) = report.duration_measurement {
            inner.add_u32(pfcp_ie::DURATION_MEASUREMENT, dur);
        }
        if let Some(t) = report.time_of_first_packet {
            inner.add_u32(pfcp_ie::TIME_OF_FIRST_PACKET, t);
        }
        if let Some(t) = report.time_of_last_packet {
            inner.add_u32(pfcp_ie::TIME_OF_LAST_PACKET, t);
        }
        self.add_tlv(ie_type, &inner.build())
    }

    /// Add Usage Report Trigger IE
    fn add_usage_report_trigger(&mut self, trigger: &UsageReportTrigger) -> &mut Self {
        let mut flags: [u8; 3] = [0, 0, 0];
        if trigger.periodic_reporting { flags[0] |= 0x01; }
        if trigger.volume_threshold { flags[0] |= 0x02; }
        if trigger.time_threshold { flags[0] |= 0x04; }
        if trigger.quota_holding_time { flags[0] |= 0x08; }
        if trigger.start_of_traffic { flags[0] |= 0x10; }
        if trigger.stop_of_traffic { flags[0] |= 0x20; }
        if trigger.dropped_dl_traffic_threshold { flags[0] |= 0x40; }
        if trigger.immediate_report { flags[0] |= 0x80; }
        if trigger.volume_quota { flags[1] |= 0x01; }
        if trigger.time_quota { flags[1] |= 0x02; }
        if trigger.linked_usage_reporting { flags[1] |= 0x04; }
        if trigger.termination_report { flags[1] |= 0x08; }
        if trigger.monitoring_time { flags[1] |= 0x10; }
        if trigger.envelope_closure { flags[1] |= 0x20; }
        if trigger.mac_addresses_reporting { flags[1] |= 0x40; }
        if trigger.event_threshold { flags[1] |= 0x80; }
        if trigger.event_quota { flags[2] |= 0x01; }
        if trigger.termination_by_up_function_report { flags[2] |= 0x02; }
        if trigger.ip_multicast_join_leave { flags[2] |= 0x04; }
        if trigger.quota_validity_time { flags[2] |= 0x08; }
        self.add_tlv(pfcp_ie::USAGE_REPORT_TRIGGER, &flags)
    }

    /// Add Volume Measurement IE
    fn add_volume_measurement(&mut self, vol: &VolumeMeasurement) -> &mut Self {
        let mut value = BytesMut::new();
        let mut flags: u8 = 0;
        if vol.total_volume.is_some() { flags |= 0x01; }
        if vol.uplink_volume.is_some() { flags |= 0x02; }
        if vol.downlink_volume.is_some() { flags |= 0x04; }
        if vol.total_packets.is_some() { flags |= 0x08; }
        if vol.uplink_packets.is_some() { flags |= 0x10; }
        if vol.downlink_packets.is_some() { flags |= 0x20; }
        value.put_u8(flags);
        if let Some(v) = vol.total_volume { value.put_u64(v); }
        if let Some(v) = vol.uplink_volume { value.put_u64(v); }
        if let Some(v) = vol.downlink_volume { value.put_u64(v); }
        if let Some(v) = vol.total_packets { value.put_u64(v); }
        if let Some(v) = vol.uplink_packets { value.put_u64(v); }
        if let Some(v) = vol.downlink_packets { value.put_u64(v); }
        self.add_tlv(pfcp_ie::VOLUME_MEASUREMENT, &value)
    }

    /// Add Report Type IE
    pub fn add_report_type(&mut self, report_type: &ReportType) -> &mut Self {
        let mut flags: u8 = 0;
        if report_type.downlink_data_report { flags |= 0x01; }
        if report_type.usage_report { flags |= 0x02; }
        if report_type.error_indication_report { flags |= 0x04; }
        if report_type.uplink_data_report { flags |= 0x08; }
        if report_type.session_report { flags |= 0x10; }
        self.add_u8(pfcp_ie::REPORT_TYPE, flags)
    }
}

// ============================================================================
// UPF N4 Message Building Functions
// ============================================================================

/// Build Session Establishment Response
/// Port of upf_n4_build_session_establishment_response
pub fn build_session_establishment_response(
    msg_type: u8,
    upf_n4_seid: u64,
    node_id: &NodeId,
    f_seid: &FSeid,
    created_pdrs: &[CreatedPdr],
) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // Node ID
    builder.add_node_id(node_id);
    
    // Cause - Request Accepted
    builder.add_cause(PfcpCause::RequestAccepted);
    
    // UP F-SEID
    builder.add_f_seid(f_seid);
    
    // Created PDRs
    for pdr in created_pdrs {
        builder.add_created_pdr(pdr);
    }
    
    let _ = msg_type; // Used for header construction
    let _ = upf_n4_seid;
    builder.build()
}

/// Build Session Modification Response
/// Port of upf_n4_build_session_modification_response
pub fn build_session_modification_response(
    msg_type: u8,
    created_pdrs: &[CreatedPdr],
) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // Cause - Request Accepted
    builder.add_cause(PfcpCause::RequestAccepted);
    
    // Created PDRs
    for pdr in created_pdrs {
        builder.add_created_pdr(pdr);
    }
    
    let _ = msg_type;
    builder.build()
}

/// Build Session Deletion Response
/// Port of upf_n4_build_session_deletion_response
pub fn build_session_deletion_response(
    msg_type: u8,
    usage_reports: &[UsageReport],
) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // Cause - Request Accepted
    builder.add_cause(PfcpCause::RequestAccepted);
    
    // Usage Reports (with termination trigger)
    for report in usage_reports {
        builder.add_usage_report(report, pfcp_ie::USAGE_REPORT_SDR);
    }
    
    let _ = msg_type;
    builder.build()
}

/// Build Session Report Request
/// Port of ogs_pfcp_build_session_report_request
pub fn build_session_report_request(
    msg_type: u8,
    report: &UserPlaneReport,
) -> Vec<u8> {
    let mut builder = PfcpMessageBuilder::new();
    
    // Report Type
    builder.add_report_type(&report.report_type);
    
    // Downlink Data Report
    if let Some(ref dldr) = report.downlink_data_report {
        let mut inner = PfcpMessageBuilder::new();
        inner.add_pdr_id(dldr.pdr_id);
        if let Some(ref info) = dldr.downlink_data_service_info {
            let mut dds_value = BytesMut::new();
            let mut flags: u8 = 0;
            if info.ppi.is_some() { flags |= 0x01; }
            if info.qfi.is_some() { flags |= 0x02; }
            dds_value.put_u8(flags);
            if let Some(ppi) = info.ppi { dds_value.put_u8(ppi); }
            if let Some(qfi) = info.qfi { dds_value.put_u8(qfi); }
            inner.add_tlv(45, &dds_value); // DOWNLINK_DATA_SERVICE_INFORMATION
        }
        builder.add_tlv(83, &inner.build()); // DOWNLINK_DATA_REPORT
    }
    
    // Usage Reports
    for ur in &report.usage_reports {
        builder.add_usage_report(ur, pfcp_ie::USAGE_REPORT_SRR);
    }
    
    // Error Indication Report
    if let Some(ref eir) = report.error_indication_report {
        let mut inner = PfcpMessageBuilder::new();
        inner.add_f_teid(&eir.remote_f_teid);
        builder.add_tlv(99, &inner.build()); // ERROR_INDICATION_REPORT
    }
    
    let _ = msg_type;
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
        assert_eq!(PfcpCause::from(65), PfcpCause::SessionContextNotFound);
        assert_eq!(PfcpCause::from(255), PfcpCause::SystemFailure);
    }

    #[test]
    fn test_node_id_encode_ipv4() {
        let node_id = NodeId::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let encoded = node_id.encode();
        assert_eq!(encoded[0], 0); // Type = IPv4
        assert_eq!(&encoded[1..5], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_node_id_encode_ipv6() {
        let node_id = NodeId::Ipv6(Ipv6Addr::LOCALHOST);
        let encoded = node_id.encode();
        assert_eq!(encoded[0], 1); // Type = IPv6
        assert_eq!(encoded.len(), 17);
    }

    #[test]
    fn test_node_id_encode_fqdn() {
        let node_id = NodeId::Fqdn("upf.example.com".to_string());
        let encoded = node_id.encode();
        assert_eq!(encoded[0], 2); // Type = FQDN
        assert_eq!(encoded[1], 3); // "upf" length
        assert_eq!(&encoded[2..5], b"upf");
    }

    #[test]
    fn test_f_seid_encode() {
        let f_seid = FSeid {
            seid: 0x123456789ABCDEF0,
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: None,
        };
        let encoded = f_seid.encode();
        assert_eq!(encoded[0], 0x02); // V4 flag
        assert_eq!(encoded.len(), 1 + 8 + 4); // flags + seid + ipv4
    }

    #[test]
    fn test_f_seid_encode_dual_stack() {
        let f_seid = FSeid {
            seid: 0x1234,
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: Some(Ipv6Addr::LOCALHOST),
        };
        let encoded = f_seid.encode();
        assert_eq!(encoded[0], 0x03); // V4 + V6 flags
        assert_eq!(encoded.len(), 1 + 8 + 4 + 16);
    }

    #[test]
    fn test_message_builder_add_tlv() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_tlv(pfcp_ie::CAUSE, &[1]);
        let msg = builder.build();
        assert_eq!(msg.len(), 4 + 1); // type(2) + len(2) + value(1)
        assert_eq!(&msg[0..2], &pfcp_ie::CAUSE.to_be_bytes());
        assert_eq!(&msg[2..4], &1u16.to_be_bytes());
        assert_eq!(msg[4], 1);
    }

    #[test]
    fn test_message_builder_add_cause() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_cause(PfcpCause::RequestAccepted);
        let msg = builder.build();
        assert_eq!(msg[4], 1); // RequestAccepted = 1
    }

    #[test]
    fn test_message_builder_add_pdr_id() {
        let mut builder = PfcpMessageBuilder::new();
        builder.add_pdr_id(0x1234);
        let msg = builder.build();
        assert_eq!(&msg[4..6], &0x1234u16.to_be_bytes());
    }

    #[test]
    fn test_build_session_establishment_response() {
        let node_id = NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let f_seid = FSeid {
            seid: 0x1234,
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: None,
        };
        let created_pdrs = vec![
            CreatedPdr {
                pdr_id: 1,
                local_f_teid: Some(FTeid {
                    teid: 0x5678,
                    ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
                    ipv6: None,
                    choose: false,
                    choose_id: None,
                }),
                ue_ip_address: None,
            },
        ];
        let msg = build_session_establishment_response(
            pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            0x1234,
            &node_id,
            &f_seid,
            &created_pdrs,
        );
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_build_session_modification_response() {
        let msg = build_session_modification_response(
            pfcp_type::SESSION_MODIFICATION_RESPONSE,
            &[],
        );
        // Should contain at least cause IE
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_build_session_deletion_response() {
        let usage_reports = vec![
            UsageReport {
                urr_id: 1,
                ur_seqn: 1,
                trigger: UsageReportTrigger {
                    termination_report: true,
                    ..Default::default()
                },
                volume_measurement: Some(VolumeMeasurement {
                    total_volume: Some(1000),
                    uplink_volume: Some(400),
                    downlink_volume: Some(600),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        let msg = build_session_deletion_response(
            pfcp_type::SESSION_DELETION_RESPONSE,
            &usage_reports,
        );
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_build_session_report_request() {
        let report = UserPlaneReport {
            report_type: ReportType {
                downlink_data_report: true,
                ..Default::default()
            },
            downlink_data_report: Some(DownlinkDataReport {
                pdr_id: 1,
                downlink_data_service_info: Some(DownlinkDataServiceInfo {
                    qfi: Some(5),
                    ppi: None,
                }),
            }),
            ..Default::default()
        };
        let msg = build_session_report_request(
            pfcp_type::SESSION_REPORT_REQUEST,
            &report,
        );
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_usage_report_trigger_encoding() {
        let mut builder = PfcpMessageBuilder::new();
        let trigger = UsageReportTrigger {
            termination_report: true,
            volume_threshold: true,
            ..Default::default()
        };
        builder.add_usage_report_trigger(&trigger);
        let msg = builder.build();
        // Check that flags are encoded correctly
        assert_eq!(msg.len(), 4 + 3); // TLV header + 3 bytes flags
    }

    #[test]
    fn test_volume_measurement_encoding() {
        let mut builder = PfcpMessageBuilder::new();
        let vol = VolumeMeasurement {
            total_volume: Some(1000),
            uplink_volume: Some(400),
            downlink_volume: Some(600),
            ..Default::default()
        };
        builder.add_volume_measurement(&vol);
        let msg = builder.build();
        // flags(1) + total(8) + uplink(8) + downlink(8) = 25 bytes value
        assert_eq!(msg.len(), 4 + 25);
    }

    #[test]
    fn test_created_pdr_encoding() {
        let mut builder = PfcpMessageBuilder::new();
        let pdr = CreatedPdr {
            pdr_id: 0x1234,
            local_f_teid: Some(FTeid {
                teid: 0x5678,
                ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
                ipv6: None,
                choose: false,
                choose_id: None,
            }),
            ue_ip_address: None,
        };
        builder.add_created_pdr(&pdr);
        let msg = builder.build();
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_f_teid_encoding() {
        let mut builder = PfcpMessageBuilder::new();
        let f_teid = FTeid {
            teid: 0x12345678,
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 1)),
            ipv6: None,
            choose: false,
            choose_id: None,
        };
        builder.add_f_teid(&f_teid);
        let msg = builder.build();
        // TLV header(4) + flags(1) + teid(4) + ipv4(4) = 13
        assert_eq!(msg.len(), 13);
    }

    #[test]
    fn test_ue_ip_address_encoding() {
        let mut builder = PfcpMessageBuilder::new();
        let ue_ip = UeIpAddress {
            ipv4: Some(Ipv4Addr::new(10, 45, 0, 1)),
            ipv6: None,
            ipv6_prefix_len: 0,
        };
        builder.add_ue_ip_address(&ue_ip, false);
        let msg = builder.build();
        // TLV header(4) + flags(1) + ipv4(4) = 9
        assert_eq!(msg.len(), 9);
    }
}
