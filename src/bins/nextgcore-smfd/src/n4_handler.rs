//! N4 (PFCP) Response Handler

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//!
//! Port of src/smf/n4-handler.c - PFCP response handling for SMF
//! Handles session establishment, modification, and deletion responses

use crate::n4_build::PfcpCause;

// ============================================================================
// GTP Cause Codes (for conversion)
// ============================================================================

/// GTPv1 Cause codes
pub mod gtp1_cause {
    pub const REQUEST_ACCEPTED: u8 = 128;
    pub const REJ_MS_NOT_GPRS_RESPONDING: u8 = 202;
    pub const CONTEXT_NOT_FOUND: u8 = 201;
    pub const MANDATORY_IE_MISSING: u8 = 193;
    pub const INVALID_MESSAGE_FORMAT: u8 = 194;
    pub const NO_RESOURCES_AVAILABLE: u8 = 199;
    pub const SEMANTIC_ERR_TFT_OPERATION: u8 = 177;
    pub const APN_CONGESTION: u8 = 174;
    pub const SERVICE_NOT_SUPPORTED: u8 = 200;
    pub const SYSTEM_FAILURE: u8 = 204;
    pub const ALL_DYNAMIC_PDP_ADDRS_OCCUPIED: u8 = 205;
}

/// GTPv2 Cause codes
pub mod gtp2_cause {
    pub const REQUEST_ACCEPTED: u8 = 16;
    pub const REQUEST_REJECTED_REASON_NOT_SPECIFIED: u8 = 17;
    pub const CONTEXT_NOT_FOUND: u8 = 64;
    pub const MANDATORY_IE_MISSING: u8 = 70;
    pub const CONDITIONAL_IE_MISSING: u8 = 71;
    pub const INVALID_LENGTH: u8 = 72;
    pub const MANDATORY_IE_INCORRECT: u8 = 73;
    pub const INVALID_MESSAGE_FORMAT: u8 = 74;
    pub const REMOTE_PEER_NOT_RESPONDING: u8 = 100;
    pub const SEMANTIC_ERROR_IN_THE_TFT_OPERATION: u8 = 81;
    pub const GTP_C_ENTITY_CONGESTION: u8 = 101;
    pub const NO_RESOURCES_AVAILABLE: u8 = 73;
    pub const SERVICE_NOT_SUPPORTED: u8 = 68;
    pub const SYSTEM_FAILURE: u8 = 72;
    pub const ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED: u8 = 84;
}


// ============================================================================
// SBI HTTP Status Codes
// ============================================================================

/// SBI HTTP Status codes
pub mod sbi_status {
    pub const OK: u16 = 200;
    pub const BAD_REQUEST: u16 = 400;
    pub const FORBIDDEN: u16 = 403;
    pub const NOT_FOUND: u16 = 404;
    pub const GATEWAY_TIMEOUT: u16 = 504;
    pub const SERVICE_UNAVAILABLE: u16 = 503;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
}

// ============================================================================
// Cause Code Conversion Functions
// ============================================================================

/// Convert PFCP cause to GTP cause code
/// Port of gtp_cause_from_pfcp() from n4-handler.c
pub fn gtp_cause_from_pfcp(pfcp_cause: u8, gtp_version: u8) -> u8 {
    match gtp_version {
        1 => match pfcp_cause {
            c if c == PfcpCause::RequestAccepted as u8 => gtp1_cause::REQUEST_ACCEPTED,
            c if c == PfcpCause::RequestRejected as u8 => gtp1_cause::REJ_MS_NOT_GPRS_RESPONDING,
            c if c == PfcpCause::SessionContextNotFound as u8 => gtp1_cause::CONTEXT_NOT_FOUND,
            c if c == PfcpCause::MandatoryIeMissing as u8 => gtp1_cause::MANDATORY_IE_MISSING,
            c if c == PfcpCause::ConditionalIeMissing as u8 => gtp1_cause::MANDATORY_IE_MISSING,
            c if c == PfcpCause::InvalidLength as u8 => gtp1_cause::INVALID_MESSAGE_FORMAT,
            c if c == PfcpCause::MandatoryIeIncorrect as u8 => gtp1_cause::MANDATORY_IE_MISSING,
            c if c == PfcpCause::InvalidForwardingPolicy as u8 => gtp1_cause::INVALID_MESSAGE_FORMAT,
            c if c == PfcpCause::InvalidFTeidAllocationOption as u8 => gtp1_cause::INVALID_MESSAGE_FORMAT,
            c if c == PfcpCause::NoEstablishedPfcpAssociation as u8 => gtp1_cause::NO_RESOURCES_AVAILABLE,
            c if c == PfcpCause::RuleCreationModificationFailure as u8 => gtp1_cause::SEMANTIC_ERR_TFT_OPERATION,
            c if c == PfcpCause::PfcpEntityInCongestion as u8 => gtp1_cause::APN_CONGESTION,
            c if c == PfcpCause::NoResourcesAvailable as u8 => gtp1_cause::NO_RESOURCES_AVAILABLE,
            c if c == PfcpCause::ServiceNotSupported as u8 => gtp1_cause::SERVICE_NOT_SUPPORTED,
            c if c == PfcpCause::SystemFailure as u8 => gtp1_cause::SYSTEM_FAILURE,
            c if c == PfcpCause::AllDynamicAddressAreOccupied as u8 => gtp1_cause::ALL_DYNAMIC_PDP_ADDRS_OCCUPIED,
            _ => gtp1_cause::SYSTEM_FAILURE,
        },
        2 => match pfcp_cause {
            c if c == PfcpCause::RequestAccepted as u8 => gtp2_cause::REQUEST_ACCEPTED,
            c if c == PfcpCause::RequestRejected as u8 => gtp2_cause::REQUEST_REJECTED_REASON_NOT_SPECIFIED,
            c if c == PfcpCause::SessionContextNotFound as u8 => gtp2_cause::CONTEXT_NOT_FOUND,
            c if c == PfcpCause::MandatoryIeMissing as u8 => gtp2_cause::MANDATORY_IE_MISSING,
            c if c == PfcpCause::ConditionalIeMissing as u8 => gtp2_cause::CONDITIONAL_IE_MISSING,
            c if c == PfcpCause::InvalidLength as u8 => gtp2_cause::INVALID_LENGTH,
            c if c == PfcpCause::MandatoryIeIncorrect as u8 => gtp2_cause::MANDATORY_IE_INCORRECT,
            c if c == PfcpCause::InvalidForwardingPolicy as u8 => gtp2_cause::INVALID_MESSAGE_FORMAT,
            c if c == PfcpCause::InvalidFTeidAllocationOption as u8 => gtp2_cause::INVALID_MESSAGE_FORMAT,
            c if c == PfcpCause::NoEstablishedPfcpAssociation as u8 => gtp2_cause::REMOTE_PEER_NOT_RESPONDING,
            c if c == PfcpCause::RuleCreationModificationFailure as u8 => gtp2_cause::SEMANTIC_ERROR_IN_THE_TFT_OPERATION,
            c if c == PfcpCause::PfcpEntityInCongestion as u8 => gtp2_cause::GTP_C_ENTITY_CONGESTION,
            c if c == PfcpCause::NoResourcesAvailable as u8 => gtp2_cause::NO_RESOURCES_AVAILABLE,
            c if c == PfcpCause::ServiceNotSupported as u8 => gtp2_cause::SERVICE_NOT_SUPPORTED,
            c if c == PfcpCause::SystemFailure as u8 => gtp2_cause::SYSTEM_FAILURE,
            c if c == PfcpCause::AllDynamicAddressAreOccupied as u8 => gtp2_cause::ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED,
            _ => gtp2_cause::SYSTEM_FAILURE,
        },
        _ => gtp2_cause::SYSTEM_FAILURE,
    }
}


/// Convert PFCP cause to SBI HTTP status code
/// Port of sbi_status_from_pfcp() from n4-handler.c
pub fn sbi_status_from_pfcp(pfcp_cause: u8) -> u16 {
    match pfcp_cause {
        c if c == PfcpCause::RequestAccepted as u8 => sbi_status::OK,
        c if c == PfcpCause::RequestRejected as u8 => sbi_status::FORBIDDEN,
        c if c == PfcpCause::SessionContextNotFound as u8 => sbi_status::NOT_FOUND,
        c if c == PfcpCause::MandatoryIeMissing as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::ConditionalIeMissing as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::InvalidLength as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::MandatoryIeIncorrect as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::InvalidForwardingPolicy as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::InvalidFTeidAllocationOption as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::RuleCreationModificationFailure as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::PfcpEntityInCongestion as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::NoResourcesAvailable as u8 => sbi_status::BAD_REQUEST,
        c if c == PfcpCause::NoEstablishedPfcpAssociation as u8 => sbi_status::GATEWAY_TIMEOUT,
        c if c == PfcpCause::ServiceNotSupported as u8 => sbi_status::SERVICE_UNAVAILABLE,
        c if c == PfcpCause::SystemFailure as u8 => sbi_status::INTERNAL_SERVER_ERROR,
        _ => sbi_status::INTERNAL_SERVER_ERROR,
    }
}

// ============================================================================
// Delete Trigger Types
// ============================================================================

/// PFCP Delete Trigger types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeleteTrigger {
    LocalInitiated = 1,
    UeRequested = 2,
    AmfUpdateSmContext = 3,
    AmfReleaseSmContext = 4,
    PcfInitiated = 5,
}

// ============================================================================
// Modify Flags
// ============================================================================

/// PFCP Modify flags for session modification
pub mod modify_flags {
    pub const SESSION: u64 = 1 << 0;
    pub const DL_ONLY: u64 = 1 << 1;
    pub const UL_ONLY: u64 = 1 << 2;
    pub const ACTIVATE: u64 = 1 << 3;
    pub const DEACTIVATE: u64 = 1 << 4;
    pub const CREATE: u64 = 1 << 5;
    pub const REMOVE: u64 = 1 << 6;
    pub const TFT_NEW: u64 = 1 << 7;
    pub const TFT_ADD: u64 = 1 << 8;
    pub const TFT_REPLACE: u64 = 1 << 9;
    pub const TFT_DELETE: u64 = 1 << 10;
    pub const QOS_MODIFY: u64 = 1 << 11;
    pub const OUTER_HEADER_REMOVAL: u64 = 1 << 12;
    pub const NETWORK_REQUESTED: u64 = 1 << 13;
    pub const UE_REQUESTED: u64 = 1 << 14;
    pub const ERROR_INDICATION: u64 = 1 << 15;
    pub const XN_HANDOVER: u64 = 1 << 16;
    pub const N2_HANDOVER: u64 = 1 << 17;
    pub const INDIRECT: u64 = 1 << 18;
    pub const HANDOVER_CANCEL: u64 = 1 << 19;
    pub const HOME_ROUTED_ROAMING: u64 = 1 << 20;
    pub const FROM_ACTIVATING: u64 = 1 << 21;
    pub const URR: u64 = 1 << 22;
}


// ============================================================================
// Session Establishment Response Handler (5GC)
// ============================================================================

/// Result of session establishment response handling
#[derive(Debug, Clone)]
pub struct SessionEstablishmentResult {
    pub cause: u8,
    pub upf_n4_seid: Option<u64>,
    pub local_dl_teid: Option<u32>,
    pub local_ul_teid: Option<u32>,
}

impl Default for SessionEstablishmentResult {
    fn default() -> Self {
        Self {
            cause: PfcpCause::RequestAccepted as u8,
            upf_n4_seid: None,
            local_dl_teid: None,
            local_ul_teid: None,
        }
    }
}

/// Handle 5GC session establishment response
/// Port of smf_5gc_n4_handle_session_establishment_response() from n4-handler.c
pub fn handle_5gc_session_establishment_response(
    up_f_seid_present: bool,
    up_f_seid: Option<u64>,
    cause_present: bool,
    cause_value: Option<u8>,
    created_pdrs: &[(u16, Option<u32>, u8)], // (pdr_id, f_teid, src_if)
) -> SessionEstablishmentResult {
    let mut result = SessionEstablishmentResult::default();

    // Check UP F-SEID presence
    if !up_f_seid_present {
        log::error!("No UP F-SEID");
        result.cause = PfcpCause::MandatoryIeMissing as u8;
        return result;
    }

    // Check cause presence and value
    if cause_present {
        if let Some(cause) = cause_value {
            if cause != PfcpCause::RequestAccepted as u8 {
                log::error!("PFCP Cause [{cause}] : Not Accepted");
                result.cause = cause;
                return result;
            }
        }
    } else {
        log::error!("No Cause");
        result.cause = PfcpCause::MandatoryIeMissing as u8;
        return result;
    }

    // Process created PDRs
    for (pdr_id, f_teid, src_if) in created_pdrs {
        log::debug!("Processing created PDR: id={pdr_id}, src_if={src_if}");
        
        // PFCP_INTERFACE_CORE = 1, PFCP_INTERFACE_ACCESS = 0
        if *src_if == 1 {
            // Core interface - downlink
            if let Some(teid) = f_teid {
                result.local_dl_teid = Some(*teid);
            }
        } else if *src_if == 0 {
            // Access interface - uplink
            if let Some(teid) = f_teid {
                result.local_ul_teid = Some(*teid);
            }
        }
    }

    // Check for UP F-TEID
    if result.local_ul_teid.is_none() {
        log::error!("No UP F-TEID");
        result.cause = PfcpCause::SessionContextNotFound as u8;
        return result;
    }

    // Store UP F-SEID
    result.upf_n4_seid = up_f_seid;
    result.cause = PfcpCause::RequestAccepted as u8;

    result
}


// ============================================================================
// Session Modification Response Handler (5GC)
// ============================================================================

/// Result of session modification response handling
#[derive(Debug, Clone)]
pub struct SessionModificationResult {
    pub status: u16,
    pub flags: u64,
    pub trigger: Option<u8>,
    pub local_dl_teid: Option<u32>,
    pub local_ul_teid: Option<u32>,
    pub handover_local_dl_teid: Option<u32>,
}

impl Default for SessionModificationResult {
    fn default() -> Self {
        Self {
            status: sbi_status::OK,
            flags: 0,
            trigger: None,
            local_dl_teid: None,
            local_ul_teid: None,
            handover_local_dl_teid: None,
        }
    }
}

/// Handle 5GC session modification response
/// Port of smf_5gc_n4_handle_session_modification_response() from n4-handler.c
pub fn handle_5gc_session_modification_response(
    flags: u64,
    trigger: Option<u8>,
    cause_present: bool,
    cause_value: Option<u8>,
    created_pdrs: &[(u16, Option<u32>, u8, u8)], // (pdr_id, f_teid, src_if, dst_if)
) -> SessionModificationResult {
    let mut result = SessionModificationResult::default();
    result.flags = flags;
    result.trigger = trigger;

    // Check cause presence and value
    if cause_present {
        if let Some(cause) = cause_value {
            if cause != PfcpCause::RequestAccepted as u8 {
                log::warn!("PFCP Cause [{cause}] : Not Accepted");
                result.status = sbi_status_from_pfcp(cause);
                return result;
            }
        }
    } else {
        log::error!("No Cause");
        result.status = sbi_status::BAD_REQUEST;
        return result;
    }

    // Process created PDRs
    for (pdr_id, f_teid, src_if, dst_if) in created_pdrs {
        log::debug!("Processing created PDR: id={pdr_id}, src_if={src_if}, dst_if={dst_if}");
        
        // PFCP_INTERFACE_CORE = 1, PFCP_INTERFACE_ACCESS = 0
        if *src_if == 1 {
            // Core interface - downlink
            if let Some(teid) = f_teid {
                result.local_dl_teid = Some(*teid);
            }
        } else if *src_if == 0 {
            // Access interface
            if let Some(teid) = f_teid {
                if *dst_if == 1 {
                    // Core destination - uplink
                    result.local_ul_teid = Some(*teid);
                } else if *dst_if == 0 {
                    // Access destination - handover indirect forwarding
                    result.handover_local_dl_teid = Some(*teid);
                }
            }
        }
    }

    result.status = sbi_status::OK;
    result
}


// ============================================================================
// Session Deletion Response Handler (5GC)
// ============================================================================

/// Handle 5GC session deletion response
/// Port of smf_5gc_n4_handle_session_deletion_response() from n4-handler.c
pub fn handle_5gc_session_deletion_response(
    trigger: u8,
    cause_present: bool,
    cause_value: Option<u8>,
) -> u16 {
    let mut status = sbi_status::OK;

    // Check cause presence and value
    if cause_present {
        if let Some(cause) = cause_value {
            if cause != PfcpCause::RequestAccepted as u8 {
                log::warn!("PFCP Cause [{cause}] : Not Accepted");
                status = sbi_status_from_pfcp(cause);
            }
        }
    } else {
        log::error!("No Cause");
        status = sbi_status::BAD_REQUEST;
    }

    if status != sbi_status::OK {
        log::error!("[{trigger}] PFCP Cause : Not Accepted");
    }

    status
}

// ============================================================================
// Session Establishment Response Handler (EPC)
// ============================================================================

/// Result of EPC session establishment response handling
#[derive(Debug, Clone)]
pub struct EpcSessionEstablishmentResult {
    pub cause: u8,
    pub upf_n4_seid: Option<u64>,
    pub pgw_s5u_teid: Option<u32>,
}

impl Default for EpcSessionEstablishmentResult {
    fn default() -> Self {
        Self {
            cause: PfcpCause::RequestAccepted as u8,
            upf_n4_seid: None,
            pgw_s5u_teid: None,
        }
    }
}

/// Handle EPC session establishment response
/// Port of smf_epc_n4_handle_session_establishment_response() from n4-handler.c
pub fn handle_epc_session_establishment_response(
    up_f_seid_present: bool,
    up_f_seid: Option<u64>,
    cause_present: bool,
    cause_value: Option<u8>,
    created_pdrs: &[(u16, Option<u32>, u8)], // (pdr_id, f_teid, src_if)
) -> EpcSessionEstablishmentResult {
    let mut result = EpcSessionEstablishmentResult::default();

    // Check UP F-SEID presence
    if !up_f_seid_present {
        log::error!("No UP F-SEID");
        result.cause = PfcpCause::MandatoryIeMissing as u8;
        return result;
    }

    // Check cause presence and value
    if cause_present {
        if let Some(cause) = cause_value {
            if cause != PfcpCause::RequestAccepted as u8 {
                log::warn!("PFCP Cause [{cause}] : Not Accepted");
                result.cause = cause;
                return result;
            }
        }
    } else {
        log::error!("No Cause");
        result.cause = PfcpCause::MandatoryIeMissing as u8;
        return result;
    }

    // Process created PDRs for bearer F-TEID
    for (pdr_id, f_teid, src_if) in created_pdrs {
        log::debug!("Processing created PDR: id={pdr_id}, src_if={src_if}");
        
        // PFCP_INTERFACE_ACCESS = 0
        if *src_if == 0 {
            if let Some(teid) = f_teid {
                result.pgw_s5u_teid = Some(*teid);
            }
        }
    }

    // Check for bearer F-TEID
    if result.pgw_s5u_teid.is_none() {
        log::error!("No UP F-TEID");
        result.cause = PfcpCause::SessionContextNotFound as u8;
        return result;
    }

    // Store UP F-SEID
    result.upf_n4_seid = up_f_seid;
    result.cause = PfcpCause::RequestAccepted as u8;

    result
}


// ============================================================================
// Session Modification Response Handler (EPC)
// ============================================================================

/// Handle EPC session modification response
/// Port of smf_epc_n4_handle_session_modification_response() from n4-handler.c
pub fn handle_epc_session_modification_response(
    flags: u64,
    cause_present: bool,
    cause_value: Option<u8>,
    created_pdrs: &[(u16, Option<u32>, u8)], // (pdr_id, f_teid, src_if)
) -> (u8, Option<u32>) {
    // Check cause presence and value
    if cause_present {
        if let Some(cause) = cause_value {
            if cause != PfcpCause::RequestAccepted as u8 {
                log::error!("PFCP Cause [{cause}] : Not Accepted");
                return (cause, None);
            }
        }
    } else {
        log::error!("No Cause");
        return (PfcpCause::MandatoryIeMissing as u8, None);
    }

    // Process created PDRs for bearer F-TEID
    let mut pgw_s5u_teid = None;
    for (pdr_id, f_teid, src_if) in created_pdrs {
        log::debug!("Processing created PDR: id={pdr_id}, src_if={src_if}, flags={flags}");
        
        // PFCP_INTERFACE_ACCESS = 0
        if *src_if == 0 {
            if let Some(teid) = f_teid {
                pgw_s5u_teid = Some(*teid);
            }
        }
    }

    (PfcpCause::RequestAccepted as u8, pgw_s5u_teid)
}

// ============================================================================
// Session Deletion Response Handler (EPC)
// ============================================================================

/// Usage report data from session deletion response
#[derive(Debug, Clone, Default)]
pub struct UsageReport {
    pub urr_id: u32,
    pub ul_octets: u64,
    pub dl_octets: u64,
    pub duration: u32,
    pub reporting_reason: u32,
}

/// Handle EPC session deletion response
/// Port of smf_epc_n4_handle_session_deletion_response() from n4-handler.c
pub fn handle_epc_session_deletion_response(
    cause_present: bool,
    cause_value: Option<u8>,
    usage_reports: &[UsageReport],
) -> (u8, Vec<UsageReport>) {
    // Check cause presence and value
    if !cause_present {
        log::error!("No Cause");
        return (PfcpCause::MandatoryIeMissing as u8, Vec::new());
    }

    if let Some(cause) = cause_value {
        if cause != PfcpCause::RequestAccepted as u8 {
            log::warn!("PFCP Cause [{cause}] : Not Accepted");
            return (cause, Vec::new());
        }
    }

    // Return usage reports for Gy processing
    (PfcpCause::RequestAccepted as u8, usage_reports.to_vec())
}


// ============================================================================
// Session Report Request Handler
// ============================================================================

/// Report type flags
pub mod report_type {
    pub const DOWNLINK_DATA_REPORT: u8 = 1 << 0;
    pub const ERROR_INDICATION_REPORT: u8 = 1 << 1;
    pub const USAGE_REPORT: u8 = 1 << 2;
    pub const UPLINK_DATA_REPORT: u8 = 1 << 3;
}

/// Result of session report request handling
#[derive(Debug, Clone)]
pub struct SessionReportResult {
    pub cause: u8,
    pub trigger_service_request: bool,
    pub trigger_error_indication: bool,
    pub usage_reports: Vec<UsageReport>,
}

impl Default for SessionReportResult {
    fn default() -> Self {
        Self {
            cause: PfcpCause::RequestAccepted as u8,
            trigger_service_request: false,
            trigger_error_indication: false,
            usage_reports: Vec::new(),
        }
    }
}

/// Handle session report request
/// Port of smf_n4_handle_session_report_request() from n4-handler.c
pub fn handle_session_report_request(
    report_type_present: bool,
    report_type_value: u8,
    pdr_id: Option<u16>,
    _qfi: Option<u8>,
    up_cnx_state: u8, // 0=NULL, 1=ACTIVATED, 2=ACTIVATING, 3=DEACTIVATED, 4=SUSPENDED
    usage_reports: &[UsageReport],
) -> SessionReportResult {
    let mut result = SessionReportResult::default();

    // Check report type presence
    if !report_type_present {
        log::error!("No Report Type");
        result.cause = PfcpCause::MandatoryIeMissing as u8;
        return result;
    }

    // Handle downlink data report
    if (report_type_value & report_type::DOWNLINK_DATA_REPORT) != 0 {
        if pdr_id.is_none() {
            log::error!("No PDR-ID in Downlink Data Report");
            result.cause = PfcpCause::SessionContextNotFound as u8;
            return result;
        }

        // Check UP connection state
        match up_cnx_state {
            0 => {
                // NULL - UE Requested PDU Session is NOT established
                log::debug!("UP connection state is NULL");
            }
            1 => {
                // ACTIVATED
                log::error!("PDU Session had already been ACTIVATED");
            }
            2 => {
                // ACTIVATING
                log::warn!("UE is being triggering Service Request");
            }
            3 => {
                // DEACTIVATED - trigger service request
                result.trigger_service_request = true;
            }
            4 => {
                // SUSPENDED
                log::error!("PDU Session had been SUSPENDED");
            }
            _ => {
                log::error!("Invalid UpCnxState[{up_cnx_state}]");
            }
        }
    }

    // Handle error indication report
    if (report_type_value & report_type::ERROR_INDICATION_REPORT) != 0 {
        result.trigger_error_indication = true;
    }

    // Handle usage report
    if (report_type_value & report_type::USAGE_REPORT) != 0 {
        result.usage_reports = usage_reports.to_vec();
    }

    // Check if at least one valid report type
    if (report_type_value & (report_type::DOWNLINK_DATA_REPORT |
                             report_type::ERROR_INDICATION_REPORT |
                             report_type::USAGE_REPORT)) == 0 {
        log::error!("Not supported Report Type[{report_type_value}]");
        result.cause = PfcpCause::SystemFailure as u8;
        return result;
    }

    result.cause = PfcpCause::RequestAccepted as u8;
    result
}


// ============================================================================
// Gy Reporting Reason Conversion
// ============================================================================

/// Gy Reporting Reason values (3GPP TS 32.299)
pub mod gy_reporting_reason {
    pub const THRESHOLD: u32 = 0;
    pub const QHT: u32 = 1;
    pub const FINAL: u32 = 2;
    pub const QUOTA_EXHAUSTED: u32 = 3;
    pub const VALIDITY_TIME: u32 = 4;
    pub const OTHER_QUOTA_TYPE: u32 = 5;
    pub const RATING_CONDITION_CHANGE: u32 = 6;
    pub const FORCED_REAUTHORISATION: u32 = 7;
    pub const POOL_EXHAUSTED: u32 = 8;
    pub const UNUSED_QUOTA_TIMER: u32 = 9;
}

/// Usage report trigger flags
pub mod usage_report_trigger {
    pub const PERIODIC_REPORTING: u8 = 1 << 0;
    pub const VOLUME_THRESHOLD: u8 = 1 << 1;
    pub const TIME_THRESHOLD: u8 = 1 << 2;
    pub const QUOTA_HOLDING_TIME: u8 = 1 << 3;
    pub const START_OF_TRAFFIC: u8 = 1 << 4;
    pub const STOP_OF_TRAFFIC: u8 = 1 << 5;
    pub const DROPPED_DL_TRAFFIC_THRESHOLD: u8 = 1 << 6;
    pub const IMMEDIATE_REPORT: u8 = 1 << 7;
}

/// Usage report trigger flags (second byte)
pub mod usage_report_trigger2 {
    pub const VOLUME_QUOTA: u8 = 1 << 0;
    pub const TIME_QUOTA: u8 = 1 << 1;
    pub const LINKED_USAGE_REPORTING: u8 = 1 << 2;
    pub const TERMINATION_REPORT: u8 = 1 << 3;
    pub const MONITORING_TIME: u8 = 1 << 4;
    pub const ENVELOPE_CLOSURE: u8 = 1 << 5;
    pub const MAC_ADDRESSES_REPORTING: u8 = 1 << 6;
    pub const EVENT_THRESHOLD: u8 = 1 << 7;
}

/// Usage report trigger flags (third byte)
pub mod usage_report_trigger3 {
    pub const EVENT_QUOTA: u8 = 1 << 0;
    pub const QUOTA_VALIDITY_TIME: u8 = 1 << 1;
    pub const IP_MULTICAST_JOIN_LEAVE: u8 = 1 << 2;
    pub const TERMINATION_BY_UP_FUNCTION_REPORT: u8 = 1 << 3;
    pub const REPORT_THE_END_MARKER_RECEPTION: u8 = 1 << 4;
}

/// Convert PFCP usage report trigger to Gy reporting reason
/// Port of smf_pfcp_urr_usage_report_trigger2diam_gy_reporting_reason() from pfcp-path.c
pub fn usage_report_trigger_to_gy_reporting_reason(
    trigger_byte1: u8,
    trigger_byte2: u8,
    trigger_byte3: u8,
) -> u32 {
    // Check termination report
    if (trigger_byte2 & usage_report_trigger2::TERMINATION_REPORT) != 0 ||
       (trigger_byte3 & usage_report_trigger3::TERMINATION_BY_UP_FUNCTION_REPORT) != 0 {
        return gy_reporting_reason::FINAL;
    }

    // Check threshold
    if (trigger_byte1 & usage_report_trigger::TIME_THRESHOLD) != 0 ||
       (trigger_byte1 & usage_report_trigger::VOLUME_THRESHOLD) != 0 {
        return gy_reporting_reason::THRESHOLD;
    }

    // Check quota exhausted
    if (trigger_byte2 & usage_report_trigger2::TIME_QUOTA) != 0 ||
       (trigger_byte2 & usage_report_trigger2::VOLUME_QUOTA) != 0 ||
       (trigger_byte3 & usage_report_trigger3::EVENT_QUOTA) != 0 {
        return gy_reporting_reason::QUOTA_EXHAUSTED;
    }

    // Check validity time
    if (trigger_byte3 & usage_report_trigger3::QUOTA_VALIDITY_TIME) != 0 {
        return gy_reporting_reason::VALIDITY_TIME;
    }

    // Default
    gy_reporting_reason::UNUSED_QUOTA_TIMER
}


// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_cause_from_pfcp_v1() {
        assert_eq!(
            gtp_cause_from_pfcp(PfcpCause::RequestAccepted as u8, 1),
            gtp1_cause::REQUEST_ACCEPTED
        );
        assert_eq!(
            gtp_cause_from_pfcp(PfcpCause::SessionContextNotFound as u8, 1),
            gtp1_cause::CONTEXT_NOT_FOUND
        );
        assert_eq!(
            gtp_cause_from_pfcp(PfcpCause::SystemFailure as u8, 1),
            gtp1_cause::SYSTEM_FAILURE
        );
        assert_eq!(
            gtp_cause_from_pfcp(PfcpCause::NoResourcesAvailable as u8, 1),
            gtp1_cause::NO_RESOURCES_AVAILABLE
        );
    }

    #[test]
    fn test_gtp_cause_from_pfcp_v2() {
        assert_eq!(
            gtp_cause_from_pfcp(PfcpCause::RequestAccepted as u8, 2),
            gtp2_cause::REQUEST_ACCEPTED
        );
        assert_eq!(
            gtp_cause_from_pfcp(PfcpCause::SessionContextNotFound as u8, 2),
            gtp2_cause::CONTEXT_NOT_FOUND
        );
        assert_eq!(
            gtp_cause_from_pfcp(PfcpCause::MandatoryIeMissing as u8, 2),
            gtp2_cause::MANDATORY_IE_MISSING
        );
        assert_eq!(
            gtp_cause_from_pfcp(PfcpCause::ConditionalIeMissing as u8, 2),
            gtp2_cause::CONDITIONAL_IE_MISSING
        );
    }

    #[test]
    fn test_sbi_status_from_pfcp() {
        assert_eq!(
            sbi_status_from_pfcp(PfcpCause::RequestAccepted as u8),
            sbi_status::OK
        );
        assert_eq!(
            sbi_status_from_pfcp(PfcpCause::RequestRejected as u8),
            sbi_status::FORBIDDEN
        );
        assert_eq!(
            sbi_status_from_pfcp(PfcpCause::SessionContextNotFound as u8),
            sbi_status::NOT_FOUND
        );
        assert_eq!(
            sbi_status_from_pfcp(PfcpCause::NoEstablishedPfcpAssociation as u8),
            sbi_status::GATEWAY_TIMEOUT
        );
        assert_eq!(
            sbi_status_from_pfcp(PfcpCause::ServiceNotSupported as u8),
            sbi_status::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            sbi_status_from_pfcp(PfcpCause::SystemFailure as u8),
            sbi_status::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_handle_5gc_session_establishment_response_success() {
        let created_pdrs = vec![
            (1, Some(0x12345678), 0), // Access interface - uplink
            (2, Some(0x87654321), 1), // Core interface - downlink
        ];

        let result = handle_5gc_session_establishment_response(
            true,
            Some(0xABCDEF0123456789),
            true,
            Some(PfcpCause::RequestAccepted as u8),
            &created_pdrs,
        );

        assert_eq!(result.cause, PfcpCause::RequestAccepted as u8);
        assert_eq!(result.upf_n4_seid, Some(0xABCDEF0123456789));
        assert_eq!(result.local_ul_teid, Some(0x12345678));
        assert_eq!(result.local_dl_teid, Some(0x87654321));
    }

    #[test]
    fn test_handle_5gc_session_establishment_response_no_f_seid() {
        let result = handle_5gc_session_establishment_response(
            false,
            None,
            true,
            Some(PfcpCause::RequestAccepted as u8),
            &[],
        );

        assert_eq!(result.cause, PfcpCause::MandatoryIeMissing as u8);
    }

    #[test]
    fn test_handle_5gc_session_establishment_response_rejected() {
        let result = handle_5gc_session_establishment_response(
            true,
            Some(0x123),
            true,
            Some(PfcpCause::NoResourcesAvailable as u8),
            &[],
        );

        assert_eq!(result.cause, PfcpCause::NoResourcesAvailable as u8);
    }


    #[test]
    fn test_handle_5gc_session_modification_response_success() {
        let created_pdrs = vec![
            (1, Some(0x11111111), 0, 1), // Access->Core - uplink
            (2, Some(0x22222222), 1, 0), // Core->Access - downlink
        ];

        let result = handle_5gc_session_modification_response(
            modify_flags::ACTIVATE,
            None,
            true,
            Some(PfcpCause::RequestAccepted as u8),
            &created_pdrs,
        );

        assert_eq!(result.status, sbi_status::OK);
        assert_eq!(result.local_ul_teid, Some(0x11111111));
        assert_eq!(result.local_dl_teid, Some(0x22222222));
    }

    #[test]
    fn test_handle_5gc_session_modification_response_rejected() {
        let result = handle_5gc_session_modification_response(
            modify_flags::ACTIVATE,
            None,
            true,
            Some(PfcpCause::NoResourcesAvailable as u8),
            &[],
        );

        assert_eq!(result.status, sbi_status::BAD_REQUEST);
    }

    #[test]
    fn test_handle_5gc_session_deletion_response_success() {
        let status = handle_5gc_session_deletion_response(
            DeleteTrigger::UeRequested as u8,
            true,
            Some(PfcpCause::RequestAccepted as u8),
        );

        assert_eq!(status, sbi_status::OK);
    }

    #[test]
    fn test_handle_5gc_session_deletion_response_rejected() {
        let status = handle_5gc_session_deletion_response(
            DeleteTrigger::UeRequested as u8,
            true,
            Some(PfcpCause::SessionContextNotFound as u8),
        );

        assert_eq!(status, sbi_status::NOT_FOUND);
    }

    #[test]
    fn test_handle_epc_session_establishment_response_success() {
        let created_pdrs = vec![
            (1, Some(0xAAAABBBB), 0), // Access interface
        ];

        let result = handle_epc_session_establishment_response(
            true,
            Some(0x123456789ABCDEF0),
            true,
            Some(PfcpCause::RequestAccepted as u8),
            &created_pdrs,
        );

        assert_eq!(result.cause, PfcpCause::RequestAccepted as u8);
        assert_eq!(result.upf_n4_seid, Some(0x123456789ABCDEF0));
        assert_eq!(result.pgw_s5u_teid, Some(0xAAAABBBB));
    }

    #[test]
    fn test_handle_epc_session_modification_response_success() {
        let created_pdrs = vec![
            (1, Some(0xCCCCDDDD), 0),
        ];

        let (cause, teid) = handle_epc_session_modification_response(
            modify_flags::ACTIVATE,
            true,
            Some(PfcpCause::RequestAccepted as u8),
            &created_pdrs,
        );

        assert_eq!(cause, PfcpCause::RequestAccepted as u8);
        assert_eq!(teid, Some(0xCCCCDDDD));
    }

    #[test]
    fn test_handle_epc_session_deletion_response_success() {
        let usage_reports = vec![
            UsageReport {
                urr_id: 1,
                ul_octets: 1000,
                dl_octets: 2000,
                duration: 300,
                reporting_reason: gy_reporting_reason::FINAL,
            },
        ];

        let (cause, reports) = handle_epc_session_deletion_response(
            true,
            Some(PfcpCause::RequestAccepted as u8),
            &usage_reports,
        );

        assert_eq!(cause, PfcpCause::RequestAccepted as u8);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].ul_octets, 1000);
    }

    #[test]
    fn test_handle_session_report_request_downlink_data() {
        let result = handle_session_report_request(
            true,
            report_type::DOWNLINK_DATA_REPORT,
            Some(1),
            None,
            3, // DEACTIVATED
            &[],
        );

        assert_eq!(result.cause, PfcpCause::RequestAccepted as u8);
        assert!(result.trigger_service_request);
    }

    #[test]
    fn test_handle_session_report_request_error_indication() {
        let result = handle_session_report_request(
            true,
            report_type::ERROR_INDICATION_REPORT,
            None,
            None,
            1, // ACTIVATED
            &[],
        );

        assert_eq!(result.cause, PfcpCause::RequestAccepted as u8);
        assert!(result.trigger_error_indication);
    }

    #[test]
    fn test_handle_session_report_request_usage_report() {
        let usage_reports = vec![
            UsageReport {
                urr_id: 1,
                ul_octets: 500,
                dl_octets: 1500,
                duration: 60,
                reporting_reason: gy_reporting_reason::THRESHOLD,
            },
        ];

        let result = handle_session_report_request(
            true,
            report_type::USAGE_REPORT,
            None,
            None,
            1,
            &usage_reports,
        );

        assert_eq!(result.cause, PfcpCause::RequestAccepted as u8);
        assert_eq!(result.usage_reports.len(), 1);
    }

    #[test]
    fn test_usage_report_trigger_to_gy_reporting_reason() {
        // Termination report
        assert_eq!(
            usage_report_trigger_to_gy_reporting_reason(
                0,
                usage_report_trigger2::TERMINATION_REPORT,
                0
            ),
            gy_reporting_reason::FINAL
        );

        // Volume threshold
        assert_eq!(
            usage_report_trigger_to_gy_reporting_reason(
                usage_report_trigger::VOLUME_THRESHOLD,
                0,
                0
            ),
            gy_reporting_reason::THRESHOLD
        );

        // Time quota
        assert_eq!(
            usage_report_trigger_to_gy_reporting_reason(
                0,
                usage_report_trigger2::TIME_QUOTA,
                0
            ),
            gy_reporting_reason::QUOTA_EXHAUSTED
        );

        // Validity time
        assert_eq!(
            usage_report_trigger_to_gy_reporting_reason(
                0,
                0,
                usage_report_trigger3::QUOTA_VALIDITY_TIME
            ),
            gy_reporting_reason::VALIDITY_TIME
        );

        // Default
        assert_eq!(
            usage_report_trigger_to_gy_reporting_reason(0, 0, 0),
            gy_reporting_reason::UNUSED_QUOTA_TIMER
        );
    }
}
