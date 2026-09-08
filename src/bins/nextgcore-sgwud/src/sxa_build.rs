//! SGWU SXA Message Builder
//!
//! Port of src/sgwu/sxa-build.c - Build PFCP response messages for SXA interface

use crate::context::{SgwuSess, UsageReportTrigger, Volume};

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
    // ---- Usage reporting (issue #215) ----
    pub const URR_ID: u16 = 81;
    pub const USAGE_REPORT_TRIGGER: u16 = 63;
    pub const VOLUME_MEASUREMENT: u16 = 66;
    pub const DURATION_MEASUREMENT: u16 = 67;
    pub const START_TIME: u16 = 75;
    pub const END_TIME: u16 = 76;
    pub const TIME_OF_FIRST_PACKET: u16 = 69;
    pub const TIME_OF_LAST_PACKET: u16 = 70;
    pub const UR_SEQN: u16 = 104;
    /// Usage Report within a Session Deletion Response (TS 29.244 §7.5.5.2).
    pub const USAGE_REPORT_SDR: u16 = 79;
    /// Usage Report within a Session Report Request (TS 29.244 §7.5.8.3).
    pub const USAGE_REPORT_SRR: u16 = 80;
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
pub fn build_session_deletion_response(
    sess: &SgwuSess,
    usage_reports: &[UsageReport],
) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(
        pfcp_type::SESSION_DELETION_RESPONSE,
        sess.sgwc_sxa_f_seid.seid,
    );

    let mut data = Vec::new();

    // Cause IE - Request Accepted
    build_cause_ie(&mut data, pfcp_cause::REQUEST_ACCEPTED);

    // Final Usage Reports (issue #215, TS 29.244 §7.5.5.2). Every URR the session
    // held reports its residual usage here -- this is the SGW-U's last chance to
    // hand that volume to the SGW-C, and dropping it loses billable traffic at
    // every session teardown, which is every session.
    for usage in usage_reports {
        build_usage_report_ie(&mut data, usage, pfcp_ie::USAGE_REPORT_SDR);
    }

    msg.data = data;
    log::debug!(
        "Built Session Deletion Response: cp_seid=0x{:x}, {} usage report(s)",
        sess.sgwc_sxa_f_seid.seid,
        usage_reports.len()
    );

    Some(msg)
}

/// Build Session Report Request (for downlink data notification, error indication)
/// Port of nextgcore_pfcp_build_session_report_request
pub fn build_session_report_request(
    sess: &SgwuSess,
    report: &UserPlaneReport,
) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(pfcp_type::SESSION_REPORT_REQUEST, sess.sgwc_sxa_f_seid.seid);

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

    // Usage Reports (issue #215, TS 29.244 §7.5.8.3). One IE per URR.
    for usage in &report.usage_reports {
        build_usage_report_ie(&mut data, usage, pfcp_ie::USAGE_REPORT_SRR);
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
    /// Usage Reports carried by this Session Report Request (issue #215). When
    /// non-empty, `usage_report` (the USAR report-type bit) must be set too --
    /// `UserPlaneReport::with_usage_reports` keeps the two in step.
    pub usage_reports: Vec<UsageReport>,
}

/// A Usage Report (TS 29.244 §7.5.8.3 / §7.5.5.2). Issue #215.
///
/// One value type for both carriers — the Session Report Request (IE 80) and the
/// Session Deletion Response (IE 79) — because the content is identical and only
/// the enclosing IE type differs; two structs would be two places to forget a
/// member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageReport {
    pub urr_id: u32,
    /// UR-SEQN (§8.2.60), monotonic per URR.
    pub ur_seqn: u32,
    /// Usage Report Trigger (§8.2.42): why this report exists.
    pub trigger: UsageReportTrigger,
    /// Volume Measurement (§8.2.32) byte counts; absent members are omitted.
    pub volume: Volume,
    pub total_packets: Option<u64>,
    pub uplink_packets: Option<u64>,
    pub downlink_packets: Option<u64>,
    /// Duration Measurement (§8.2.33) in seconds.
    pub duration_secs: Option<u32>,
    /// Start/End Time (§8.2.36 / §8.2.37) as UNIX seconds.
    pub start_time: Option<u32>,
    pub end_time: Option<u32>,
    /// Time of First/Last Packet (§8.2.34 / §8.2.35) as UNIX seconds.
    pub time_of_first_packet: Option<u32>,
    pub time_of_last_packet: Option<u32>,
}

impl UserPlaneReport {
    /// A Session Report Request carrying Usage Reports, with the USAR bit set.
    ///
    /// #215: before this, the USAR bit was exercised only in a unit test and
    /// nothing in the data path ever set it. Constructing the pair together means
    /// a caller cannot attach reports and forget the bit (which would leave the
    /// SGW-C parsing a report type that claims no usage) or set the bit with no
    /// reports (which would claim usage it does not carry).
    pub fn with_usage_reports(reports: Vec<UsageReport>) -> Self {
        Self {
            usage_report: !reports.is_empty(),
            usage_reports: reports,
            ..Default::default()
        }
    }

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

/// Build a Usage Report IE (issue #215, TS 29.244 §7.5.8.3 / §7.5.5.2).
///
/// `ie_type` selects the carrier: [`pfcp_ie::USAGE_REPORT_SRR`] inside a Session
/// Report Request, [`pfcp_ie::USAGE_REPORT_SDR`] inside a Session Deletion
/// Response. The contents are identical; TS 29.244 gives the two carriers
/// different IE types, which is the only reason this takes a parameter.
///
/// URR ID and UR-SEQN are always present -- a report the CP function cannot
/// attribute to a rule, or cannot order, is not usable for charging. Everything
/// else is emitted only when measured, because an absent Volume Measurement and a
/// zero one say different things to a CDR.
/// Seconds between the NTP epoch (1900-01-01) and the UNIX epoch (1970-01-01).
///
/// #267: TS 29.244 §8.2.34-§8.2.37 each specify "the first four octets of the 64-bit
/// timestamp format defined in clause 6 of IETF RFC 5905", i.e. seconds since 1900.
/// Start Time, End Time, Time of First Packet and Time of Last Packet were written
/// as UNIX seconds, so every one was ~70 years low and a report generated now decoded
/// at the SGW-C as 1956 -- wrong CDR period boundaries and wrong End-Start durations.
/// The same constant exists in `lmfd` (`NTP_UNIX_OFFSET`) and the convention is
/// documented in `nextgcore-gtp`'s Recovery Time Stamp.
const NTP_UNIX_OFFSET_SECS: u64 = 2_208_988_800;

/// A UNIX-epoch second count as the RFC 5905 NTP-epoch `u32` the PFCP timestamp IEs
/// carry. Saturates rather than wrapping past 2036.
fn ntp_seconds(unix_secs: u32) -> u32 {
    (unix_secs as u64)
        .saturating_add(NTP_UNIX_OFFSET_SECS)
        .min(u32::MAX as u64) as u32
}

fn build_usage_report_ie(data: &mut Vec<u8>, report: &UsageReport, ie_type: u16) {
    let mut inner = Vec::new();

    // URR ID (§8.2.54)
    push_u32_ie(&mut inner, pfcp_ie::URR_ID, report.urr_id);
    // UR-SEQN (§8.2.60)
    push_u32_ie(&mut inner, pfcp_ie::UR_SEQN, report.ur_seqn);
    // Usage Report Trigger (§8.2.42) -- three octets
    push_ie(
        &mut inner,
        pfcp_ie::USAGE_REPORT_TRIGGER,
        &usage_report_trigger_octets(&report.trigger),
    );
    if let Some(t) = report.start_time {
        push_u32_ie(&mut inner, pfcp_ie::START_TIME, ntp_seconds(t));
    }
    if let Some(t) = report.end_time {
        push_u32_ie(&mut inner, pfcp_ie::END_TIME, ntp_seconds(t));
    }
    if let Some(volume) = volume_measurement_octets(report) {
        push_ie(&mut inner, pfcp_ie::VOLUME_MEASUREMENT, &volume);
    }
    if let Some(secs) = report.duration_secs {
        push_u32_ie(&mut inner, pfcp_ie::DURATION_MEASUREMENT, secs);
    }
    if let Some(t) = report.time_of_first_packet {
        push_u32_ie(&mut inner, pfcp_ie::TIME_OF_FIRST_PACKET, ntp_seconds(t));
    }
    if let Some(t) = report.time_of_last_packet {
        push_u32_ie(&mut inner, pfcp_ie::TIME_OF_LAST_PACKET, ntp_seconds(t));
    }

    push_ie(data, ie_type, &inner);
}

/// The three Usage Report Trigger octets (TS 29.244 §8.2.42, Figure 8.2.42-1).
///
/// Returned rather than written in place so the bit assignment is unit-testable
/// without decoding a whole message: a trigger encoded into the wrong bit tells
/// the SGW-C the wrong reason and is invisible in a green end-to-end test.
fn usage_report_trigger_octets(trigger: &UsageReportTrigger) -> [u8; 3] {
    let mut flags = [0u8; 3];
    if trigger.periodic {
        flags[0] |= 0x01; // PERIO
    }
    if trigger.volume_threshold {
        flags[0] |= 0x02; // VOLTH
    }
    if trigger.time_threshold {
        flags[0] |= 0x04; // TIMTH
    }
    if trigger.volume_quota {
        // #267: VOLQU is octet 6 bit 1, NOT octet 5 bit 7. This was `flags[0] |= 0x40`,
        // which is DROTH (Dropped DL Traffic Threshold) -- so a quota-exhaustion report
        // told the SGW-C "dropped downlink traffic threshold reached", the CP function
        // never granted new quota, and the CDR attributed the report to the wrong cause.
        // `upfd/src/n4_build.rs` had it right; this copy diverged.
        flags[1] |= 0x01; // VOLQU
    }
    if trigger.termination_report {
        // TEBUR, octet 7 bit 3 (§8.2.42): termination by the UP function, which is
        // what the final report at session deletion is.
        flags[2] |= 0x02;
    }
    flags
}

/// The Volume Measurement IE value (TS 29.244 §8.2.32), or `None` when nothing was
/// measured -- the flags octet with every bit clear would assert "measured, all
/// zero", which is a different statement.
fn volume_measurement_octets(report: &UsageReport) -> Option<Vec<u8>> {
    let mut flags = 0u8;
    if report.volume.total.is_some() {
        flags |= 0x01; // TOVOL
    }
    if report.volume.uplink.is_some() {
        flags |= 0x02; // ULVOL
    }
    if report.volume.downlink.is_some() {
        flags |= 0x04; // DLVOL
    }
    if report.total_packets.is_some() {
        flags |= 0x08; // TONOP
    }
    if report.uplink_packets.is_some() {
        flags |= 0x10; // ULNOP
    }
    if report.downlink_packets.is_some() {
        flags |= 0x20; // DLNOP
    }
    if flags == 0 {
        return None;
    }
    let mut value = Vec::with_capacity(1 + 6 * 8);
    value.push(flags);
    // The order is fixed by §8.2.32 and matches the flag bits above; only the
    // present ones are written, which is what the flags octet announces.
    for v in [
        report.volume.total,
        report.volume.uplink,
        report.volume.downlink,
        report.total_packets,
        report.uplink_packets,
        report.downlink_packets,
    ]
    .into_iter()
    .flatten()
    {
        value.extend_from_slice(&v.to_be_bytes());
    }
    Some(value)
}

/// Append a TLV: 2-octet type, 2-octet length, value.
fn push_ie(data: &mut Vec<u8>, ie_type: u16, value: &[u8]) {
    data.extend_from_slice(&ie_type.to_be_bytes());
    data.extend_from_slice(&(value.len() as u16).to_be_bytes());
    data.extend_from_slice(value);
}

/// Append a TLV whose value is one big-endian `u32`.
fn push_u32_ie(data: &mut Vec<u8>, ie_type: u16, value: u32) {
    push_ie(data, ie_type, &value.to_be_bytes());
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

        let created_pdrs = vec![CreatedPdr {
            pdr_id: 1,
            local_f_teid: Some(LocalFTeid {
                teid: 0x12345678,
                ipv4: Some(Ipv4Addr::new(192, 168, 1, 1)),
                ipv6: None,
            }),
        }];

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

        let msg = build_session_deletion_response(&sess, &[]).unwrap();
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
    // -----------------------------------------------------------------
    // #215: Usage Report IE encoding
    // -----------------------------------------------------------------

    /// Walk a flat TLV list, returning the first value for `ie_type`.
    ///
    /// A real decoder, not a byte-offset assertion: an offset check passes for a
    /// message whose LENGTH fields are wrong, which is precisely the mistake that
    /// makes a peer reject an otherwise-correct IE.
    fn find_ie(data: &[u8], ie_type: u16) -> Option<Vec<u8>> {
        let mut i = 0usize;
        while i + 4 <= data.len() {
            let t = u16::from_be_bytes([data[i], data[i + 1]]);
            let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            let start = i + 4;
            let end = start.checked_add(len)?;
            if end > data.len() {
                return None; // a length that overruns the buffer is malformed
            }
            if t == ie_type {
                return Some(data[start..end].to_vec());
            }
            i = end;
        }
        None
    }

    /// How many top-level TLVs of `ie_type` the buffer holds.
    ///
    /// A sequential walk, like `find_ie`: an offset or byte-pattern search would
    /// match inside a VALUE, which is what the previous byte-scan did.
    fn count_ies(data: &[u8], ie_type: u16) -> usize {
        let mut i = 0usize;
        let mut count = 0usize;
        while i + 4 <= data.len() {
            let t = u16::from_be_bytes([data[i], data[i + 1]]);
            let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            let Some(end) = (i + 4).checked_add(len) else {
                break;
            };
            if end > data.len() {
                break;
            }
            if t == ie_type {
                count += 1;
            }
            i = end;
        }
        count
    }

    fn sample_report() -> UsageReport {
        UsageReport {
            urr_id: 7,
            ur_seqn: 3,
            trigger: UsageReportTrigger {
                volume_threshold: true,
                ..Default::default()
            },
            volume: Volume {
                total: Some(300),
                uplink: Some(200),
                downlink: Some(100),
            },
            total_packets: Some(3),
            uplink_packets: Some(2),
            downlink_packets: Some(1),
            duration_secs: Some(42),
            start_time: Some(1_700_000_000),
            end_time: Some(1_700_000_042),
            time_of_first_packet: Some(1_700_000_001),
            time_of_last_packet: Some(1_700_000_041),
        }
    }

    /// **Issue #215.** A Session Report Request carries the USAR bit and a
    /// well-formed Usage Report IE (type 80, TS 29.244 §7.5.8.3).
    #[test]
    fn session_report_request_carries_a_usage_report_ie() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let report = UserPlaneReport::with_usage_reports(vec![sample_report()]);
        assert!(
            report.usage_report,
            "with_usage_reports must set the USAR bit"
        );
        assert_eq!(report.report_type() & 0x02, 0x02, "USAR is bit 2");

        let msg = build_session_report_request(&sess, &report).expect("built");
        assert_eq!(msg.msg_type, pfcp_type::SESSION_REPORT_REQUEST);

        // The Report Type IE says USAR.
        let rt = find_ie(&msg.data, pfcp_ie::REPORT_TYPE).expect("Report Type IE");
        assert_eq!(rt[0] & 0x02, 0x02);

        let usage = find_ie(&msg.data, pfcp_ie::USAGE_REPORT_SRR).expect("Usage Report IE 80");
        // URR ID and UR-SEQN are always present: a report the CP cannot attribute or
        // order is not usable for charging.
        assert_eq!(
            find_ie(&usage, pfcp_ie::URR_ID).unwrap(),
            7u32.to_be_bytes().to_vec()
        );
        assert_eq!(
            find_ie(&usage, pfcp_ie::UR_SEQN).unwrap(),
            3u32.to_be_bytes().to_vec()
        );
        // VOLTH is octet 5 bit 2 (§8.2.42).
        let trigger = find_ie(&usage, pfcp_ie::USAGE_REPORT_TRIGGER).expect("trigger IE");
        assert_eq!(trigger.len(), 3, "the trigger IE is three octets");
        assert_eq!(trigger[0] & 0x02, 0x02, "VOLTH");
        assert_eq!(trigger[0] & 0x01, 0, "not PERIO");
        assert_eq!(trigger[2], 0, "not TEBUR");
        // Volume Measurement: flags octet then the present counters, in order.
        let volume = find_ie(&usage, pfcp_ie::VOLUME_MEASUREMENT).expect("volume IE");
        assert_eq!(volume[0], 0x3F, "TOVOL|ULVOL|DLVOL|TONOP|ULNOP|DLNOP");
        assert_eq!(volume.len(), 1 + 6 * 8);
        assert_eq!(u64::from_be_bytes(volume[1..9].try_into().unwrap()), 300);
        assert_eq!(u64::from_be_bytes(volume[9..17].try_into().unwrap()), 200);
        assert_eq!(u64::from_be_bytes(volume[17..25].try_into().unwrap()), 100);
        assert_eq!(u64::from_be_bytes(volume[25..33].try_into().unwrap()), 3);
        assert_eq!(
            find_ie(&usage, pfcp_ie::DURATION_MEASUREMENT).unwrap(),
            42u32.to_be_bytes().to_vec()
        );
        assert!(find_ie(&usage, pfcp_ie::TIME_OF_FIRST_PACKET).is_some());
        assert!(find_ie(&usage, pfcp_ie::TIME_OF_LAST_PACKET).is_some());
    }

    /// **Issue #215.** The Session Deletion Response carries the final reports under
    /// IE type **79** (§7.5.5.2), not 80 — the same content, a different carrier.
    #[test]
    fn session_deletion_response_carries_final_usage_reports() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let mut final_report = sample_report();
        final_report.trigger = UsageReportTrigger {
            termination_report: true,
            ..Default::default()
        };
        let mut second = final_report.clone();
        second.urr_id = 8;

        let msg = build_session_deletion_response(&sess, &[final_report, second]).expect("built");
        assert_eq!(msg.msg_type, pfcp_type::SESSION_DELETION_RESPONSE);
        // Cause first, then a Usage Report per URR.
        assert_eq!(
            find_ie(&msg.data, pfcp_ie::CAUSE).unwrap(),
            vec![pfcp_cause::REQUEST_ACCEPTED]
        );
        let usage = find_ie(&msg.data, pfcp_ie::USAGE_REPORT_SDR).expect("Usage Report IE 79");
        assert!(
            find_ie(&msg.data, pfcp_ie::USAGE_REPORT_SRR).is_none(),
            "a deletion response must use IE 79, not the report-request IE 80"
        );
        let trigger = find_ie(&usage, pfcp_ie::USAGE_REPORT_TRIGGER).unwrap();
        assert_eq!(trigger[2] & 0x02, 0x02, "TEBUR on the final report");
        assert_eq!(trigger[0], 0, "and no volume/time trigger");

        // Both reports are there. #267: this used to advance by SCANNING for the raw
        // byte pair 00 4F anywhere in the buffer, INCLUDING value bytes -- so a URR
        // ID of 79 or any counter whose encoding contained that pair would have made
        // the count wrong or panicked on the slice advance. `count_ies` walks the TLV
        // list properly.
        assert_eq!(
            count_ies(&msg.data, pfcp_ie::USAGE_REPORT_SDR),
            2,
            "one Usage Report IE per URR"
        );

        // With no reports the response is exactly what it was before #215.
        let plain = build_session_deletion_response(&sess, &[]).expect("built");
        assert!(find_ie(&plain.data, pfcp_ie::USAGE_REPORT_SDR).is_none());
    }

    /// **Issue #215.** A report that measured nothing omits the Volume Measurement
    /// IE rather than sending an all-zero one.
    ///
    /// The flags octet with every bit clear asserts "measured, all zero", which is a
    /// different statement from "not measured" — a duration-only URR must make the
    /// second.
    #[test]
    fn a_report_with_no_measurement_omits_the_volume_ie() {
        let sess = SgwuSess {
            id: 1,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let duration_only = UsageReport {
            urr_id: 7,
            ur_seqn: 0,
            duration_secs: Some(10),
            ..Default::default()
        };
        let msg = build_session_deletion_response(&sess, &[duration_only]).expect("built");
        let usage = find_ie(&msg.data, pfcp_ie::USAGE_REPORT_SDR).expect("Usage Report IE");
        assert!(
            find_ie(&usage, pfcp_ie::VOLUME_MEASUREMENT).is_none(),
            "nothing measured => no Volume Measurement IE"
        );
        assert_eq!(
            find_ie(&usage, pfcp_ie::DURATION_MEASUREMENT).unwrap(),
            10u32.to_be_bytes().to_vec()
        );
    }

    /// **Issue #267.** The four timestamp IEs carry NTP-epoch seconds, not UNIX.
    ///
    /// TS 29.244 §8.2.34-§8.2.37 all specify the RFC 5905 format. Writing UNIX
    /// seconds made every one ~70 years low, so a report generated now decoded at the
    /// SGW-C as 1956 -- wrong CDR period boundaries and wrong End-Start durations.
    #[test]
    fn usage_report_timestamps_are_ntp_epoch_not_unix() {
        let sess = SgwuSess {
            id: 1,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        // A known UNIX instant, so the offset is checkable by arithmetic rather than
        // by re-deriving it.
        let unix = 1_700_000_000u32;
        let report = UsageReport {
            urr_id: 7,
            start_time: Some(unix),
            end_time: Some(unix + 42),
            time_of_first_packet: Some(unix + 1),
            time_of_last_packet: Some(unix + 41),
            ..Default::default()
        };
        let msg = build_session_deletion_response(&sess, &[report]).expect("built");
        let usage = find_ie(&msg.data, pfcp_ie::USAGE_REPORT_SDR).expect("Usage Report IE");

        let read = |ie: u16| -> u32 {
            let v = find_ie(&usage, ie).unwrap_or_else(|| panic!("IE {ie} missing"));
            u32::from_be_bytes(v.try_into().expect("4-octet timestamp"))
        };
        let offset = 2_208_988_800u32;
        assert_eq!(read(pfcp_ie::START_TIME), unix + offset);
        assert_eq!(read(pfcp_ie::END_TIME), unix + 42 + offset);
        assert_eq!(read(pfcp_ie::TIME_OF_FIRST_PACKET), unix + 1 + offset);
        assert_eq!(read(pfcp_ie::TIME_OF_LAST_PACKET), unix + 41 + offset);
        // And specifically NOT the raw UNIX value, which is what shipped.
        assert_ne!(read(pfcp_ie::START_TIME), unix);
    }

    /// **Issue #267.** A report that measured no volume omits the Volume Measurement
    /// IE **when built through `usage_report_from`** — the path the data plane and
    /// the deletion handler actually use.
    ///
    /// The #215 guards for this built a `UsageReport` literal or asserted on
    /// `measured_volume()`, so neither reached `usage_report_from`, which set the
    /// three packet counters to `Some(0)` unconditionally -- flags 0x38, a 25-octet
    /// IE asserting "measured, all zero" for a measurement never provisioned.
    #[test]
    fn a_duration_only_urr_emits_no_volume_ie_through_usage_report_from() {
        use crate::context::{measurement_method, SgwuUrr};
        let sess = SgwuSess {
            id: 1,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let mut urr = SgwuUrr {
            urr_id: 7,
            measurement_method: measurement_method::DURATION,
            ..Default::default()
        };
        // Packets counted, volume not measured: exactly the state that produced the
        // spurious IE.
        urr.total_packets = 3;
        urr.uplink_packets = 3;

        let report = crate::sxa_handler::usage_report_from(&urr, 0, Default::default());
        assert!(!report.volume.is_set(), "no volume was measured");
        assert_eq!(report.total_packets, None, "so no packet counts either");
        assert_eq!(report.uplink_packets, None);
        assert_eq!(report.downlink_packets, None);

        let msg = build_session_deletion_response(&sess, &[report]).expect("built");
        let usage = find_ie(&msg.data, pfcp_ie::USAGE_REPORT_SDR).expect("Usage Report IE");
        assert!(
            find_ie(&usage, pfcp_ie::VOLUME_MEASUREMENT).is_none(),
            "a DURAT-only URR must emit NO Volume Measurement IE"
        );
    }

    /// **Issue #215.** Each Usage Report Trigger maps to its own bit, so the SGW-C is
    /// told the right reason.
    ///
    /// A trigger encoded into the wrong bit is invisible in an end-to-end test that
    /// only checks a report arrived.
    #[test]
    fn every_usage_report_trigger_has_its_own_bit() {
        let cases = [
            (
                UsageReportTrigger {
                    periodic: true,
                    ..Default::default()
                },
                [0x01u8, 0, 0],
            ),
            (
                UsageReportTrigger {
                    volume_threshold: true,
                    ..Default::default()
                },
                [0x02, 0, 0],
            ),
            (
                UsageReportTrigger {
                    time_threshold: true,
                    ..Default::default()
                },
                [0x04, 0, 0],
            ),
            (
                // #267 FLIP: this asserted [0x40, 0, 0], pinning VOLQU onto octet 5's
                // DROTH bit. VOLQU is octet 6 bit 1 (§8.2.42), which is what
                // `upfd/src/n4_build.rs` has always emitted.
                UsageReportTrigger {
                    volume_quota: true,
                    ..Default::default()
                },
                [0, 0x01, 0],
            ),
            (
                UsageReportTrigger {
                    termination_report: true,
                    ..Default::default()
                },
                [0, 0, 0x02],
            ),
        ];
        for (trigger, expected) in cases {
            assert_eq!(
                usage_report_trigger_octets(&trigger),
                expected,
                "wrong bit for {trigger:?}"
            );
        }
        // No trigger at all encodes as all-clear rather than defaulting to one.
        assert_eq!(
            usage_report_trigger_octets(&UsageReportTrigger::default()),
            [0, 0, 0]
        );
    }
}
