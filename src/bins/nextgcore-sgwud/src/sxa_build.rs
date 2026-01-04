//! SGWU SXA Message Builder
//!
//! Port of src/sgwu/sxa-build.c - Build PFCP response messages for SXA interface

use crate::context::SgwuSess;

// ============================================================================
// PFCP Message Types
// ============================================================================

pub mod pfcp_type {
    pub const SESSION_ESTABLISHMENT_RESPONSE: u8 = 51;
    pub const SESSION_MODIFICATION_RESPONSE: u8 = 53;
    pub const SESSION_DELETION_RESPONSE: u8 = 55;
    pub const SESSION_REPORT_REQUEST: u8 = 56;
}

// ============================================================================
// PFCP Cause Values
// ============================================================================

pub mod pfcp_cause {
    pub const REQUEST_ACCEPTED: u8 = 1;
    pub const REQUEST_REJECTED: u8 = 64;
    pub const SESSION_CONTEXT_NOT_FOUND: u8 = 65;
    pub const MANDATORY_IE_MISSING: u8 = 66;
    pub const CONDITIONAL_IE_MISSING: u8 = 67;
    pub const INVALID_LENGTH: u8 = 68;
    pub const MANDATORY_IE_INCORRECT: u8 = 69;
    pub const INVALID_FORWARDING_POLICY: u8 = 70;
    pub const INVALID_F_TEID_ALLOCATION_OPTION: u8 = 71;
    pub const NO_ESTABLISHED_PFCP_ASSOCIATION: u8 = 72;
    pub const RULE_CREATION_MODIFICATION_FAILURE: u8 = 73;
    pub const PFCP_ENTITY_IN_CONGESTION: u8 = 74;
    pub const NO_RESOURCES_AVAILABLE: u8 = 75;
    pub const SERVICE_NOT_SUPPORTED: u8 = 76;
    pub const SYSTEM_FAILURE: u8 = 77;
}

// ============================================================================
// PFCP IE Types
// ============================================================================

pub mod pfcp_ie {
    pub const NODE_ID: u16 = 60;
    pub const CAUSE: u16 = 19;
    pub const F_SEID: u16 = 57;
    pub const CREATED_PDR: u16 = 8;
    pub const PDR_ID: u16 = 56;
    pub const F_TEID: u16 = 21;
    pub const REPORT_TYPE: u16 = 39;
    pub const DOWNLINK_DATA_REPORT: u16 = 83;
    pub const ERROR_INDICATION_REPORT: u16 = 99;
}

// ============================================================================
// Created PDR Information
// ============================================================================

/// Created PDR information for responses
#[derive(Debug, Clone, Default)]
pub struct CreatedPdr {
    /// PDR ID
    pub pdr_id: u16,
    /// Local F-TEID (if allocated)
    pub local_f_teid: Option<LocalFTeid>,
}

/// Local F-TEID information
#[derive(Debug, Clone, Default)]
pub struct LocalFTeid {
    /// TEID value
    pub teid: u32,
    /// IPv4 address
    pub ipv4: Option<std::net::Ipv4Addr>,
    /// IPv6 address
    pub ipv6: Option<std::net::Ipv6Addr>,
}

// ============================================================================
// Message Builder Result
// ============================================================================

/// Built PFCP message
#[derive(Debug, Clone)]
pub struct PfcpMessage {
    pub msg_type: u8,
    pub seid: u64,
    pub data: Vec<u8>,
}

impl PfcpMessage {
    pub fn new(msg_type: u8, seid: u64) -> Self {
        Self {
            msg_type,
            seid,
            data: Vec::new(),
        }
    }
}

// ============================================================================
// SXA Message Builders (SGWU -> SGWC Responses)
// ============================================================================

/// Build Session Establishment Response
/// Port of sgwu_sxa_build_session_establishment_response
pub fn build_session_establishment_response(
    sess: &SgwuSess,
    created_pdrs: &[CreatedPdr],
) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(
        pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
        sess.sgwc_sxa_f_seid.seid,
    );

    let mut data = Vec::new();

    // Node ID IE (local node identifier)
    // In actual implementation, this would be populated from local PFCP config
    build_node_id_ie(&mut data);

    // Cause IE - Request Accepted
    build_cause_ie(&mut data, pfcp_cause::REQUEST_ACCEPTED);

    // UP F-SEID IE (SGWU's F-SEID)
    build_f_seid_ie(&mut data, sess.sgwu_sxa_seid);

    // Created PDR IEs
    for created_pdr in created_pdrs {
        build_created_pdr_ie(&mut data, created_pdr);
    }

    msg.data = data;
    log::debug!(
        "Built Session Establishment Response: cp_seid=0x{:x}, up_seid=0x{:x}, created_pdrs={}",
        sess.sgwc_sxa_f_seid.seid,
        sess.sgwu_sxa_seid,
        created_pdrs.len()
    );

    Some(msg)
}

/// Build Session Modification Response
/// Port of sgwu_sxa_build_session_modification_response
pub fn build_session_modification_response(
    sess: &SgwuSess,
    created_pdrs: &[CreatedPdr],
) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(
        pfcp_type::SESSION_MODIFICATION_RESPONSE,
        sess.sgwc_sxa_f_seid.seid,
    );

    let mut data = Vec::new();

    // Cause IE - Request Accepted
    build_cause_ie(&mut data, pfcp_cause::REQUEST_ACCEPTED);

    // Created PDR IEs (for newly created PDRs during modification)
    for created_pdr in created_pdrs {
        build_created_pdr_ie(&mut data, created_pdr);
    }

    msg.data = data;
    log::debug!(
        "Built Session Modification Response: cp_seid=0x{:x}, created_pdrs={}",
        sess.sgwc_sxa_f_seid.seid,
        created_pdrs.len()
    );

    Some(msg)
}

/// Build Session Deletion Response
/// Port of sgwu_sxa_build_session_deletion_response
pub fn build_session_deletion_response(sess: &SgwuSess) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(
        pfcp_type::SESSION_DELETION_RESPONSE,
        sess.sgwc_sxa_f_seid.seid,
    );

    let mut data = Vec::new();

    // Cause IE - Request Accepted
    build_cause_ie(&mut data, pfcp_cause::REQUEST_ACCEPTED);

    msg.data = data;
    log::debug!(
        "Built Session Deletion Response: cp_seid=0x{:x}",
        sess.sgwc_sxa_f_seid.seid
    );

    Some(msg)
}

/// Build Session Report Request (for downlink data notification, error indication)
/// Port of ogs_pfcp_build_session_report_request
pub fn build_session_report_request(
    sess: &SgwuSess,
    report: &UserPlaneReport,
) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(
        pfcp_type::SESSION_REPORT_REQUEST,
        sess.sgwc_sxa_f_seid.seid,
    );

    let mut data = Vec::new();

    // Report Type IE
    build_report_type_ie(&mut data, report);

    // Downlink Data Report (if applicable)
    if report.downlink_data_report {
        build_downlink_data_report_ie(&mut data, report);
    }

    // Error Indication Report (if applicable)
    if report.error_indication_report {
        build_error_indication_report_ie(&mut data, report);
    }

    msg.data = data;
    log::debug!(
        "Built Session Report Request: cp_seid=0x{:x}, report_type=0x{:x}",
        sess.sgwc_sxa_f_seid.seid,
        report.report_type()
    );

    Some(msg)
}

// ============================================================================
// User Plane Report
// ============================================================================

/// User plane report information
#[derive(Debug, Clone, Default)]
pub struct UserPlaneReport {
    /// Downlink Data Report flag
    pub downlink_data_report: bool,
    /// Error Indication Report flag
    pub error_indication_report: bool,
    /// Usage Report flag
    pub usage_report: bool,
    /// User Plane Inactivity Report flag
    pub upir: bool,
    /// PDR ID for downlink data report
    pub pdr_id: Option<u16>,
    /// QFI for 5GC
    pub qfi: Option<u8>,
    /// Remote F-TEID for error indication
    pub remote_f_teid: Option<LocalFTeid>,
}

impl UserPlaneReport {
    /// Get report type value
    pub fn report_type(&self) -> u8 {
        let mut rt = 0u8;
        if self.downlink_data_report {
            rt |= 0x01; // DLDR
        }
        if self.usage_report {
            rt |= 0x02; // USAR
        }
        if self.error_indication_report {
            rt |= 0x04; // ERIR
        }
        if self.upir {
            rt |= 0x08; // UPIR
        }
        rt
    }
}

// ============================================================================
// Helper Functions for Building IEs
// ============================================================================

/// Build Node ID IE
fn build_node_id_ie(data: &mut Vec<u8>) {
    // IE Type (2 bytes)
    data.extend_from_slice(&pfcp_ie::NODE_ID.to_be_bytes());
    // IE Length placeholder (2 bytes) - will be filled with actual length
    let len_pos = data.len();
    data.extend_from_slice(&0u16.to_be_bytes());
    
    // Node ID Type: 0 = IPv4, 1 = IPv6, 2 = FQDN
    data.push(0); // IPv4 type
    // IPv4 address (placeholder - would be actual local address)
    data.extend_from_slice(&[127, 0, 0, 1]);
    
    // Update length
    let ie_len = (data.len() - len_pos - 2) as u16;
    data[len_pos..len_pos + 2].copy_from_slice(&ie_len.to_be_bytes());
}

/// Build Cause IE
fn build_cause_ie(data: &mut Vec<u8>, cause: u8) {
    // IE Type (2 bytes)
    data.extend_from_slice(&pfcp_ie::CAUSE.to_be_bytes());
    // IE Length (2 bytes)
    data.extend_from_slice(&1u16.to_be_bytes());
    // Cause value
    data.push(cause);
}

/// Build F-SEID IE
fn build_f_seid_ie(data: &mut Vec<u8>, seid: u64) {
    // IE Type (2 bytes)
    data.extend_from_slice(&pfcp_ie::F_SEID.to_be_bytes());
    // IE Length placeholder
    let len_pos = data.len();
    data.extend_from_slice(&0u16.to_be_bytes());
    
    // Flags: bit 0 = V4, bit 1 = V6
    data.push(0x02); // V4 flag set
    // SEID (8 bytes)
    data.extend_from_slice(&seid.to_be_bytes());
    // IPv4 address (placeholder)
    data.extend_from_slice(&[127, 0, 0, 1]);
    
    // Update length
    let ie_len = (data.len() - len_pos - 2) as u16;
    data[len_pos..len_pos + 2].copy_from_slice(&ie_len.to_be_bytes());
}

/// Build Created PDR IE
fn build_created_pdr_ie(data: &mut Vec<u8>, created_pdr: &CreatedPdr) {
    // IE Type (2 bytes)
    data.extend_from_slice(&pfcp_ie::CREATED_PDR.to_be_bytes());
    // IE Length placeholder
    let len_pos = data.len();
    data.extend_from_slice(&0u16.to_be_bytes());
    
    // PDR ID (nested IE)
    data.extend_from_slice(&pfcp_ie::PDR_ID.to_be_bytes());
    data.extend_from_slice(&2u16.to_be_bytes());
    data.extend_from_slice(&created_pdr.pdr_id.to_be_bytes());
    
    // Local F-TEID (if present)
    if let Some(ref f_teid) = created_pdr.local_f_teid {
        build_f_teid_ie(data, f_teid);
    }
    
    // Update length
    let ie_len = (data.len() - len_pos - 2) as u16;
    data[len_pos..len_pos + 2].copy_from_slice(&ie_len.to_be_bytes());
}

/// Build F-TEID IE
fn build_f_teid_ie(data: &mut Vec<u8>, f_teid: &LocalFTeid) {
    // IE Type (2 bytes)
    data.extend_from_slice(&pfcp_ie::F_TEID.to_be_bytes());
    // IE Length placeholder
    let len_pos = data.len();
    data.extend_from_slice(&0u16.to_be_bytes());
    
    // Flags
    let mut flags = 0u8;
    if f_teid.ipv4.is_some() {
        flags |= 0x01; // V4
    }
    if f_teid.ipv6.is_some() {
        flags |= 0x02; // V6
    }
    data.push(flags);
    
    // TEID (4 bytes)
    data.extend_from_slice(&f_teid.teid.to_be_bytes());
    
    // IPv4 address
    if let Some(ipv4) = f_teid.ipv4 {
        data.extend_from_slice(&ipv4.octets());
    }
    
    // IPv6 address
    if let Some(ipv6) = f_teid.ipv6 {
        data.extend_from_slice(&ipv6.octets());
    }
    
    // Update length
    let ie_len = (data.len() - len_pos - 2) as u16;
    data[len_pos..len_pos + 2].copy_from_slice(&ie_len.to_be_bytes());
}

/// Build Report Type IE
fn build_report_type_ie(data: &mut Vec<u8>, report: &UserPlaneReport) {
    // IE Type (2 bytes)
    data.extend_from_slice(&pfcp_ie::REPORT_TYPE.to_be_bytes());
    // IE Length (2 bytes)
    data.extend_from_slice(&1u16.to_be_bytes());
    // Report Type value
    data.push(report.report_type());
}

/// Build Downlink Data Report IE
fn build_downlink_data_report_ie(data: &mut Vec<u8>, report: &UserPlaneReport) {
    // IE Type (2 bytes)
    data.extend_from_slice(&pfcp_ie::DOWNLINK_DATA_REPORT.to_be_bytes());
    // IE Length placeholder
    let len_pos = data.len();
    data.extend_from_slice(&0u16.to_be_bytes());
    
    // PDR ID (if present)
    if let Some(pdr_id) = report.pdr_id {
        data.extend_from_slice(&pfcp_ie::PDR_ID.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&pdr_id.to_be_bytes());
    }
    
    // Update length
    let ie_len = (data.len() - len_pos - 2) as u16;
    data[len_pos..len_pos + 2].copy_from_slice(&ie_len.to_be_bytes());
}

/// Build Error Indication Report IE
fn build_error_indication_report_ie(data: &mut Vec<u8>, report: &UserPlaneReport) {
    // IE Type (2 bytes)
    data.extend_from_slice(&pfcp_ie::ERROR_INDICATION_REPORT.to_be_bytes());
    // IE Length placeholder
    let len_pos = data.len();
    data.extend_from_slice(&0u16.to_be_bytes());
    
    // Remote F-TEID (if present)
    if let Some(ref f_teid) = report.remote_f_teid {
        build_f_teid_ie(data, f_teid);
    }
    
    // Update length
    let ie_len = (data.len() - len_pos - 2) as u16;
    data[len_pos..len_pos + 2].copy_from_slice(&ie_len.to_be_bytes());
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::FSeid;
    use std::net::Ipv4Addr;

    #[test]
    fn test_pfcp_message_new() {
        let msg = PfcpMessage::new(pfcp_type::SESSION_ESTABLISHMENT_RESPONSE, 0x1234);
        assert_eq!(msg.msg_type, pfcp_type::SESSION_ESTABLISHMENT_RESPONSE);
        assert_eq!(msg.seid, 0x1234);
        assert!(msg.data.is_empty());
    }

    #[test]
    fn test_build_session_establishment_response() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };

        let created_pdrs = vec![
            CreatedPdr {
                pdr_id: 1,
                local_f_teid: Some(LocalFTeid {
                    teid: 0x12345678,
                    ipv4: Some(Ipv4Addr::new(192, 168, 1, 1)),
                    ipv6: None,
                }),
            },
        ];

        let msg = build_session_establishment_response(&sess, &created_pdrs).unwrap();
        assert_eq!(msg.msg_type, pfcp_type::SESSION_ESTABLISHMENT_RESPONSE);
        assert_eq!(msg.seid, 0x2000);
        assert!(!msg.data.is_empty());
    }

    #[test]
    fn test_build_session_modification_response() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };

        let msg = build_session_modification_response(&sess, &[]).unwrap();
        assert_eq!(msg.msg_type, pfcp_type::SESSION_MODIFICATION_RESPONSE);
        assert_eq!(msg.seid, 0x2000);
    }

    #[test]
    fn test_build_session_deletion_response() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };

        let msg = build_session_deletion_response(&sess).unwrap();
        assert_eq!(msg.msg_type, pfcp_type::SESSION_DELETION_RESPONSE);
        assert_eq!(msg.seid, 0x2000);
    }

    #[test]
    fn test_build_session_report_request() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };

        let report = UserPlaneReport {
            downlink_data_report: true,
            pdr_id: Some(1),
            ..Default::default()
        };

        let msg = build_session_report_request(&sess, &report).unwrap();
        assert_eq!(msg.msg_type, pfcp_type::SESSION_REPORT_REQUEST);
        assert_eq!(msg.seid, 0x2000);
    }

    #[test]
    fn test_user_plane_report_type() {
        let mut report = UserPlaneReport::default();
        assert_eq!(report.report_type(), 0);

        report.downlink_data_report = true;
        assert_eq!(report.report_type(), 0x01);

        report.error_indication_report = true;
        assert_eq!(report.report_type(), 0x05);

        report.usage_report = true;
        assert_eq!(report.report_type(), 0x07);
    }

    #[test]
    fn test_created_pdr() {
        let pdr = CreatedPdr {
            pdr_id: 123,
            local_f_teid: Some(LocalFTeid {
                teid: 0xABCD,
                ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
                ipv6: None,
            }),
        };
        assert_eq!(pdr.pdr_id, 123);
        assert!(pdr.local_f_teid.is_some());
    }
}
