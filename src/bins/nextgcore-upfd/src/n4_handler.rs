//! UPF N4 (PFCP) Message Handling
//!
//! Port of src/upf/n4-handler.c - PFCP message handling for UPF

use crate::n4_build::{PfcpCause, UsageReport, UsageReportTrigger, VolumeMeasurement};
use std::collections::HashMap;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of PDRs
pub const MAX_NUM_OF_PDR: usize = 16;
/// Maximum number of FARs
pub const MAX_NUM_OF_FAR: usize = 16;
/// Maximum number of URRs
pub const MAX_NUM_OF_URR: usize = 16;
/// Maximum number of QERs
pub const MAX_NUM_OF_QER: usize = 16;
/// Maximum DNN length
pub const MAX_DNN_LEN: usize = 100;

// ============================================================================
// PFCP Session Request Flags
// ============================================================================

/// PFCP Session Establishment Request Flags
#[derive(Debug, Clone, Default)]
pub struct PfcpSereqFlags {
    pub restoration_indication: bool,
}

// ============================================================================
// PDR (Packet Detection Rule)
// ============================================================================

/// PDR structure for handling
#[derive(Debug, Clone, Default)]
pub struct Pdr {
    pub pdr_id: u16,
    pub precedence: u32,
    pub outer_header_removal: Option<u8>,
    pub far_id: Option<u32>,
    pub urr_ids: Vec<u32>,
    pub qer_id: Option<u32>,
    pub pdi: Pdi,
    pub f_teid_len: usize,
    pub f_teid: FTeidInfo,
    pub ue_ip_addr_len: usize,
    pub ue_ip_addr: UeIpAddrInfo,
    pub ipv4_framed_routes: Vec<String>,
    pub ipv6_framed_routes: Vec<String>,
}

/// PDI (Packet Detection Information)
#[derive(Debug, Clone, Default)]
pub struct Pdi {
    pub source_interface: u8,
    pub network_instance: Option<String>,
    pub local_f_teid: Option<FTeidInfo>,
    pub ue_ip_address: Option<UeIpAddrInfo>,
    pub sdf_filters: Vec<SdfFilter>,
    pub qfi: Option<u8>,
}

/// F-TEID Information
#[derive(Debug, Clone, Default)]
pub struct FTeidInfo {
    pub teid: u32,
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<[u8; 16]>,
    pub ch: bool,      // CHOOSE flag
    pub chid: bool,    // CHOOSE ID flag
    pub choose_id: u8,
}

/// UE IP Address Information
#[derive(Debug, Clone, Default)]
pub struct UeIpAddrInfo {
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<[u8; 16]>,
    pub ipv6_prefix_len: u8,
    pub source: bool,
    pub destination: bool,
}

/// SDF Filter
#[derive(Debug, Clone, Default)]
pub struct SdfFilter {
    pub flow_description: Option<String>,
    pub tos_traffic_class: Option<u16>,
    pub security_parameter_index: Option<u32>,
    pub flow_label: Option<u32>,
    pub sdf_filter_id: Option<u32>,
}

// ============================================================================
// FAR (Forwarding Action Rule)
// ============================================================================

/// FAR structure
#[derive(Debug, Clone, Default)]
pub struct Far {
    pub far_id: u32,
    pub apply_action: u16,
    pub forwarding_parameters: Option<ForwardingParameters>,
    pub bar_id: Option<u8>,
    pub smreq_flags: SmreqFlags,
}

/// Forwarding Parameters
#[derive(Debug, Clone, Default)]
pub struct ForwardingParameters {
    pub destination_interface: u8,
    pub network_instance: Option<String>,
    pub outer_header_creation: Option<OuterHeaderCreation>,
}

/// Outer Header Creation
#[derive(Debug, Clone, Default)]
pub struct OuterHeaderCreation {
    pub description: u16,
    pub teid: u32,
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<[u8; 16]>,
    pub port: Option<u16>,
}

/// Session Modification Request Flags
#[derive(Debug, Clone, Default)]
pub struct SmreqFlags {
    pub drobu: bool,
    pub sndem: bool,
    pub qaurr: bool,
    pub send_end_marker_packets: bool,
}

// ============================================================================
// URR (Usage Reporting Rule)
// ============================================================================

/// URR structure
#[derive(Debug, Clone, Default)]
pub struct Urr {
    pub urr_id: u32,
    pub measurement_method: MeasurementMethod,
    pub reporting_triggers: ReportingTriggers,
    pub measurement_period: Option<u32>,
    pub volume_threshold: Option<VolumeThreshold>,
    pub volume_quota: Option<VolumeQuota>,
    pub time_threshold: Option<u32>,
    pub time_quota: Option<u32>,
    pub quota_holding_time: Option<u32>,
    pub quota_validity_time: Option<u32>,
    pub meas_info: MeasurementInfo,
}

/// Measurement Method flags
#[derive(Debug, Clone, Default)]
pub struct MeasurementMethod {
    pub durat: bool,  // Duration
    pub volum: bool,  // Volume
    pub event: bool,  // Event
}

/// Reporting Triggers
#[derive(Debug, Clone, Default)]
pub struct ReportingTriggers {
    pub perio: bool,  // Periodic Reporting
    pub volth: bool,  // Volume Threshold
    pub timth: bool,  // Time Threshold
    pub quhti: bool,  // Quota Holding Time
    pub start: bool,  // Start of Traffic
    pub stopt: bool,  // Stop of Traffic
    pub droth: bool,  // Dropped DL Traffic Threshold
    pub immer: bool,  // Immediate Report
    pub volqu: bool,  // Volume Quota
    pub timqu: bool,  // Time Quota
    pub liusa: bool,  // Linked Usage Reporting
    pub termr: bool,  // Termination Report
    pub monit: bool,  // Monitoring Time
    pub envcl: bool,  // Envelope Closure
    pub macar: bool,  // MAC Addresses Reporting
    pub eveth: bool,  // Event Threshold
    pub evequ: bool,  // Event Quota
    pub tebur: bool,  // Termination by UP function Report
    pub ipmjl: bool,  // IP Multicast Join/Leave
    pub quvti: bool,  // Quota Validity Time
}

/// Volume Threshold
#[derive(Debug, Clone, Default)]
pub struct VolumeThreshold {
    pub total: Option<u64>,
    pub uplink: Option<u64>,
    pub downlink: Option<u64>,
}

/// Volume Quota
#[derive(Debug, Clone, Default)]
pub struct VolumeQuota {
    pub total: Option<u64>,
    pub uplink: Option<u64>,
    pub downlink: Option<u64>,
}

/// Measurement Information
#[derive(Debug, Clone, Default)]
pub struct MeasurementInfo {
    pub mbqe: bool,  // Measurement Before QoS Enforcement
    pub inam: bool,  // Inactive Measurement
    pub radi: bool,  // Reduced Application Detection Information
    pub istm: bool,  // Immediate Start Time Metering
    pub mnop: bool,  // Measurement of Number of Packets
}

// ============================================================================
// QER (QoS Enforcement Rule)
// ============================================================================

/// QER structure
#[derive(Debug, Clone, Default)]
pub struct Qer {
    pub qer_id: u32,
    pub qer_correlation_id: Option<u32>,
    pub gate_status: GateStatus,
    pub mbr: Option<Mbr>,
    pub gbr: Option<Gbr>,
    pub qfi: Option<u8>,
    pub rqi: Option<u8>,
    pub ppi: Option<u8>,
}

/// Gate Status
#[derive(Debug, Clone, Default)]
pub struct GateStatus {
    pub ul_gate: u8,  // 0=OPEN, 1=CLOSED
    pub dl_gate: u8,
}

/// Maximum Bit Rate
#[derive(Debug, Clone, Default)]
pub struct Mbr {
    pub uplink: u64,
    pub downlink: u64,
}

/// Guaranteed Bit Rate
#[derive(Debug, Clone, Default)]
pub struct Gbr {
    pub uplink: u64,
    pub downlink: u64,
}

// ============================================================================
// BAR (Buffering Action Rule)
// ============================================================================

/// BAR structure
#[derive(Debug, Clone, Default)]
pub struct Bar {
    pub bar_id: u8,
    pub downlink_data_notification_delay: Option<u8>,
    pub suggested_buffering_packets_count: Option<u8>,
}

// ============================================================================
// Handler Result
// ============================================================================

/// Result of handling a PFCP message
#[derive(Debug, Clone)]
pub struct HandlerResult {
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
}

impl Default for HandlerResult {
    fn default() -> Self {
        Self {
            cause: PfcpCause::RequestAccepted,
            offending_ie: None,
        }
    }
}

impl HandlerResult {
    pub fn success() -> Self {
        Self::default()
    }

    pub fn error(cause: PfcpCause, offending_ie: Option<u16>) -> Self {
        Self { cause, offending_ie }
    }

    pub fn is_success(&self) -> bool {
        self.cause == PfcpCause::RequestAccepted
    }
}

// ============================================================================
// Session Context (simplified for handler)
// ============================================================================

/// Simplified session context for N4 handling
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub upf_n4_seid: u64,
    pub smf_n4_seid: u64,
    pub apn_dnn: Option<String>,
    pub pdn_type: Option<u8>,
    pub pdrs: HashMap<u16, Pdr>,
    pub fars: HashMap<u32, Far>,
    pub urrs: HashMap<u32, Urr>,
    pub qers: HashMap<u32, Qer>,
    pub bar: Option<Bar>,
}

// ============================================================================
// URR Accounting
// ============================================================================

/// URR accounting data
#[derive(Debug, Clone, Default)]
pub struct UrrAccounting {
    pub total_octets: u64,
    pub uplink_octets: u64,
    pub downlink_octets: u64,
    pub total_packets: u64,
    pub uplink_packets: u64,
    pub downlink_packets: u64,
    pub start_time: Option<u32>,
    pub last_time: Option<u32>,
    pub time_of_first_packet: Option<u32>,
    pub time_of_last_packet: Option<u32>,
}

impl UrrAccounting {
    /// Take a snapshot and reset counters
    pub fn snapshot(&mut self) -> UrrAccountingSnapshot {
        let snapshot = UrrAccountingSnapshot {
            total_octets: self.total_octets,
            uplink_octets: self.uplink_octets,
            downlink_octets: self.downlink_octets,
            total_packets: self.total_packets,
            uplink_packets: self.uplink_packets,
            downlink_packets: self.downlink_packets,
            start_time: self.start_time,
            end_time: self.last_time,
            time_of_first_packet: self.time_of_first_packet,
            time_of_last_packet: self.time_of_last_packet,
        };
        // Reset counters
        self.total_octets = 0;
        self.uplink_octets = 0;
        self.downlink_octets = 0;
        self.total_packets = 0;
        self.uplink_packets = 0;
        self.downlink_packets = 0;
        self.start_time = self.last_time;
        self.time_of_first_packet = None;
        self.time_of_last_packet = None;
        snapshot
    }
}

/// Snapshot of URR accounting for usage report
#[derive(Debug, Clone, Default)]
pub struct UrrAccountingSnapshot {
    pub total_octets: u64,
    pub uplink_octets: u64,
    pub downlink_octets: u64,
    pub total_packets: u64,
    pub uplink_packets: u64,
    pub downlink_packets: u64,
    pub start_time: Option<u32>,
    pub end_time: Option<u32>,
    pub time_of_first_packet: Option<u32>,
    pub time_of_last_packet: Option<u32>,
}

impl UrrAccountingSnapshot {
    /// Convert to UsageReport
    pub fn to_usage_report(&self, urr_id: u32, ur_seqn: u32, termination: bool) -> UsageReport {
        UsageReport {
            urr_id,
            ur_seqn,
            trigger: UsageReportTrigger {
                termination_report: termination,
                ..Default::default()
            },
            start_time: self.start_time,
            end_time: self.end_time,
            volume_measurement: Some(VolumeMeasurement {
                total_volume: Some(self.total_octets),
                uplink_volume: Some(self.uplink_octets),
                downlink_volume: Some(self.downlink_octets),
                total_packets: Some(self.total_packets),
                uplink_packets: Some(self.uplink_packets),
                downlink_packets: Some(self.downlink_packets),
            }),
            duration_measurement: match (self.start_time, self.end_time) {
                (Some(s), Some(e)) if e > s => Some(e - s),
                _ => None,
            },
            time_of_first_packet: self.time_of_first_packet,
            time_of_last_packet: self.time_of_last_packet,
        }
    }
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Handle Create URR
/// Port of upf_n4_handle_create_urr
pub fn handle_create_urr(
    sess: &mut SessionContext,
    urr: Urr,
) -> HandlerResult {
    if sess.urrs.len() >= MAX_NUM_OF_URR {
        return HandlerResult::error(PfcpCause::NoResourcesAvailable, None);
    }
    
    let urr_id = urr.urr_id;
    sess.urrs.insert(urr_id, urr);
    
    HandlerResult::success()
}

/// Handle Session Establishment Request
/// Port of upf_n4_handle_session_establishment_request
pub fn handle_session_establishment_request(
    sess: &mut SessionContext,
    sereq_flags: &PfcpSereqFlags,
    pdrs: Vec<Pdr>,
    fars: Vec<Far>,
    urrs: Vec<Urr>,
    qers: Vec<Qer>,
    bar: Option<Bar>,
    apn_dnn: Option<String>,
    pdn_type: Option<u8>,
) -> (HandlerResult, Vec<u16>) {
    let mut created_pdr_ids = Vec::new();
    
    // Process PDRs
    for pdr in pdrs {
        if sess.pdrs.len() >= MAX_NUM_OF_PDR {
            return (HandlerResult::error(PfcpCause::NoResourcesAvailable, None), created_pdr_ids);
        }
        let pdr_id = pdr.pdr_id;
        sess.pdrs.insert(pdr_id, pdr);
        created_pdr_ids.push(pdr_id);
    }
    
    // Process FARs
    for far in fars {
        if sess.fars.len() >= MAX_NUM_OF_FAR {
            return (HandlerResult::error(PfcpCause::NoResourcesAvailable, None), created_pdr_ids);
        }
        sess.fars.insert(far.far_id, far);
    }
    
    // Process URRs
    for urr in urrs {
        let result = handle_create_urr(sess, urr);
        if !result.is_success() {
            return (result, created_pdr_ids);
        }
    }
    
    // Process QERs
    for qer in qers {
        if sess.qers.len() >= MAX_NUM_OF_QER {
            return (HandlerResult::error(PfcpCause::NoResourcesAvailable, None), created_pdr_ids);
        }
        sess.qers.insert(qer.qer_id, qer);
    }
    
    // Process BAR
    sess.bar = bar;
    
    // Set APN/DNN
    sess.apn_dnn = apn_dnn;
    sess.pdn_type = pdn_type;
    
    // Handle restoration indication
    if sereq_flags.restoration_indication {
        // TEID restoration logic would go here
        log::debug!("Restoration indication set");
    }
    
    (HandlerResult::success(), created_pdr_ids)
}

/// Handle Session Modification Request
/// Port of upf_n4_handle_session_modification_request
pub fn handle_session_modification_request(
    sess: &mut SessionContext,
    create_pdrs: Vec<Pdr>,
    update_pdrs: Vec<Pdr>,
    remove_pdr_ids: Vec<u16>,
    create_fars: Vec<Far>,
    update_fars: Vec<Far>,
    remove_far_ids: Vec<u32>,
    create_urrs: Vec<Urr>,
    update_urrs: Vec<Urr>,
    remove_urr_ids: Vec<u32>,
    create_qers: Vec<Qer>,
    update_qers: Vec<Qer>,
    remove_qer_ids: Vec<u32>,
    create_bar: Option<Bar>,
    remove_bar: bool,
) -> (HandlerResult, Vec<u16>) {
    let mut created_pdr_ids = Vec::new();
    
    // Create PDRs
    for pdr in create_pdrs {
        if sess.pdrs.len() >= MAX_NUM_OF_PDR {
            return (HandlerResult::error(PfcpCause::NoResourcesAvailable, None), created_pdr_ids);
        }
        let pdr_id = pdr.pdr_id;
        sess.pdrs.insert(pdr_id, pdr);
        created_pdr_ids.push(pdr_id);
    }
    
    // Update PDRs
    for pdr in update_pdrs {
        sess.pdrs.insert(pdr.pdr_id, pdr);
    }
    
    // Remove PDRs
    for pdr_id in remove_pdr_ids {
        sess.pdrs.remove(&pdr_id);
    }
    
    // Create FARs
    for far in create_fars {
        if sess.fars.len() >= MAX_NUM_OF_FAR {
            return (HandlerResult::error(PfcpCause::NoResourcesAvailable, None), created_pdr_ids);
        }
        sess.fars.insert(far.far_id, far);
    }
    
    // Update FARs
    for far in update_fars {
        sess.fars.insert(far.far_id, far);
    }
    
    // Remove FARs
    for far_id in remove_far_ids {
        sess.fars.remove(&far_id);
    }
    
    // Create URRs
    for urr in create_urrs {
        let result = handle_create_urr(sess, urr);
        if !result.is_success() {
            return (result, created_pdr_ids);
        }
    }
    
    // Update URRs
    for urr in update_urrs {
        sess.urrs.insert(urr.urr_id, urr);
    }
    
    // Remove URRs
    for urr_id in remove_urr_ids {
        sess.urrs.remove(&urr_id);
    }
    
    // Create QERs
    for qer in create_qers {
        if sess.qers.len() >= MAX_NUM_OF_QER {
            return (HandlerResult::error(PfcpCause::NoResourcesAvailable, None), created_pdr_ids);
        }
        sess.qers.insert(qer.qer_id, qer);
    }
    
    // Update QERs
    for qer in update_qers {
        sess.qers.insert(qer.qer_id, qer);
    }
    
    // Remove QERs
    for qer_id in remove_qer_ids {
        sess.qers.remove(&qer_id);
    }
    
    // Create/Remove BAR
    if let Some(bar) = create_bar {
        sess.bar = Some(bar);
    }
    if remove_bar {
        sess.bar = None;
    }
    
    (HandlerResult::success(), created_pdr_ids)
}

/// Handle Session Deletion Request
/// Port of upf_n4_handle_session_deletion_request
pub fn handle_session_deletion_request(
    sess: &SessionContext,
    urr_accounting: &mut HashMap<u32, UrrAccounting>,
) -> (HandlerResult, Vec<UsageReport>) {
    let mut usage_reports = Vec::new();
    let mut ur_seqn = 1u32;
    
    // Generate usage reports for all URRs
    for urr_id in sess.urrs.keys() {
        if let Some(acc) = urr_accounting.get_mut(urr_id) {
            let snapshot = acc.snapshot();
            let report = snapshot.to_usage_report(*urr_id, ur_seqn, true);
            usage_reports.push(report);
            ur_seqn += 1;
        }
    }
    
    (HandlerResult::success(), usage_reports)
}

/// Handle Session Report Response
/// Port of upf_n4_handle_session_report_response
pub fn handle_session_report_response(
    cause: PfcpCause,
) -> HandlerResult {
    if cause != PfcpCause::RequestAccepted {
        log::error!("PFCP Cause[{cause:?}] : Not Accepted");
        return HandlerResult::error(cause, None);
    }
    
    HandlerResult::success()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_result_success() {
        let result = HandlerResult::success();
        assert!(result.is_success());
        assert_eq!(result.cause, PfcpCause::RequestAccepted);
    }

    #[test]
    fn test_handler_result_error() {
        let result = HandlerResult::error(PfcpCause::SessionContextNotFound, Some(57));
        assert!(!result.is_success());
        assert_eq!(result.cause, PfcpCause::SessionContextNotFound);
        assert_eq!(result.offending_ie, Some(57));
    }

    #[test]
    fn test_session_context_default() {
        let sess = SessionContext::default();
        assert_eq!(sess.upf_n4_seid, 0);
        assert!(sess.pdrs.is_empty());
        assert!(sess.fars.is_empty());
    }

    #[test]
    fn test_handle_create_urr() {
        let mut sess = SessionContext::default();
        let urr = Urr {
            urr_id: 1,
            measurement_method: MeasurementMethod {
                volum: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = handle_create_urr(&mut sess, urr);
        assert!(result.is_success());
        assert_eq!(sess.urrs.len(), 1);
    }

    #[test]
    fn test_handle_session_establishment_request() {
        let mut sess = SessionContext::default();
        let sereq_flags = PfcpSereqFlags::default();
        let pdrs = vec![
            Pdr { pdr_id: 1, precedence: 100, ..Default::default() },
            Pdr { pdr_id: 2, precedence: 200, ..Default::default() },
        ];
        let fars = vec![
            Far { far_id: 1, apply_action: 0x02, ..Default::default() },
        ];
        let urrs = vec![
            Urr { urr_id: 1, ..Default::default() },
        ];
        let qers = vec![
            Qer { qer_id: 1, ..Default::default() },
        ];
        
        let (result, created_pdr_ids) = handle_session_establishment_request(
            &mut sess,
            &sereq_flags,
            pdrs,
            fars,
            urrs,
            qers,
            None,
            Some("internet".to_string()),
            Some(1),
        );
        
        assert!(result.is_success());
        assert_eq!(created_pdr_ids.len(), 2);
        assert_eq!(sess.pdrs.len(), 2);
        assert_eq!(sess.fars.len(), 1);
        assert_eq!(sess.urrs.len(), 1);
        assert_eq!(sess.qers.len(), 1);
        assert_eq!(sess.apn_dnn, Some("internet".to_string()));
    }

    #[test]
    fn test_handle_session_modification_request() {
        let mut sess = SessionContext::default();
        sess.pdrs.insert(1, Pdr { pdr_id: 1, ..Default::default() });
        sess.fars.insert(1, Far { far_id: 1, ..Default::default() });
        
        let (result, created_pdr_ids) = handle_session_modification_request(
            &mut sess,
            vec![Pdr { pdr_id: 2, ..Default::default() }],  // create
            vec![],  // update
            vec![1], // remove
            vec![Far { far_id: 2, ..Default::default() }],  // create
            vec![],  // update
            vec![1], // remove
            vec![],  // create urrs
            vec![],  // update urrs
            vec![],  // remove urrs
            vec![],  // create qers
            vec![],  // update qers
            vec![],  // remove qers
            None,    // create bar
            false,   // remove bar
        );
        
        assert!(result.is_success());
        assert_eq!(created_pdr_ids.len(), 1);
        assert_eq!(sess.pdrs.len(), 1);
        assert!(sess.pdrs.contains_key(&2));
        assert!(!sess.pdrs.contains_key(&1));
        assert_eq!(sess.fars.len(), 1);
        assert!(sess.fars.contains_key(&2));
    }

    #[test]
    fn test_handle_session_deletion_request() {
        let mut sess = SessionContext::default();
        sess.urrs.insert(1, Urr { urr_id: 1, ..Default::default() });
        sess.urrs.insert(2, Urr { urr_id: 2, ..Default::default() });
        
        let mut urr_accounting = HashMap::new();
        urr_accounting.insert(1, UrrAccounting {
            total_octets: 1000,
            uplink_octets: 400,
            downlink_octets: 600,
            ..Default::default()
        });
        urr_accounting.insert(2, UrrAccounting {
            total_octets: 2000,
            uplink_octets: 800,
            downlink_octets: 1200,
            ..Default::default()
        });
        
        let (result, usage_reports) = handle_session_deletion_request(&sess, &mut urr_accounting);
        
        assert!(result.is_success());
        assert_eq!(usage_reports.len(), 2);
    }

    #[test]
    fn test_urr_accounting_snapshot() {
        let mut acc = UrrAccounting {
            total_octets: 1000,
            uplink_octets: 400,
            downlink_octets: 600,
            total_packets: 100,
            uplink_packets: 40,
            downlink_packets: 60,
            start_time: Some(1000),
            last_time: Some(2000),
            time_of_first_packet: Some(1001),
            time_of_last_packet: Some(1999),
        };
        
        let snapshot = acc.snapshot();
        
        assert_eq!(snapshot.total_octets, 1000);
        assert_eq!(snapshot.uplink_octets, 400);
        assert_eq!(snapshot.downlink_octets, 600);
        assert_eq!(snapshot.start_time, Some(1000));
        assert_eq!(snapshot.end_time, Some(2000));
        
        // Verify counters are reset
        assert_eq!(acc.total_octets, 0);
        assert_eq!(acc.uplink_octets, 0);
        assert_eq!(acc.start_time, Some(2000)); // Reset to last_time
    }

    #[test]
    fn test_snapshot_to_usage_report() {
        let snapshot = UrrAccountingSnapshot {
            total_octets: 1000,
            uplink_octets: 400,
            downlink_octets: 600,
            total_packets: 100,
            uplink_packets: 40,
            downlink_packets: 60,
            start_time: Some(1000),
            end_time: Some(2000),
            time_of_first_packet: Some(1001),
            time_of_last_packet: Some(1999),
        };
        
        let report = snapshot.to_usage_report(1, 1, true);
        
        assert_eq!(report.urr_id, 1);
        assert_eq!(report.ur_seqn, 1);
        assert!(report.trigger.termination_report);
        assert_eq!(report.duration_measurement, Some(1000));
        
        let vol = report.volume_measurement.unwrap();
        assert_eq!(vol.total_volume, Some(1000));
        assert_eq!(vol.uplink_volume, Some(400));
        assert_eq!(vol.downlink_volume, Some(600));
    }

    #[test]
    fn test_handle_session_report_response_success() {
        let result = handle_session_report_response(PfcpCause::RequestAccepted);
        assert!(result.is_success());
    }

    #[test]
    fn test_handle_session_report_response_failure() {
        let result = handle_session_report_response(PfcpCause::SessionContextNotFound);
        assert!(!result.is_success());
    }
}
