//! SGWU SXA Handler
//!
//! Port of src/sgwu/sxa-handler.c - Handlers for PFCP messages from SGW-C

use crate::context::{SgwuSess, FSeid};
use crate::sxa_build::{pfcp_cause, CreatedPdr, UserPlaneReport};

// ============================================================================
// PFCP Interface Types
// ============================================================================

pub mod pfcp_interface {
    pub const ACCESS: u8 = 0;
    pub const CORE: u8 = 1;
    pub const SGI_LAN_N6_LAN: u8 = 2;
    pub const CP_FUNCTION: u8 = 3;
}

// ============================================================================
// Handler Result
// ============================================================================

/// Result of handler operations
#[derive(Debug)]
pub enum HandlerResult {
    /// Request accepted, send response
    Ok,
    /// Error with PFCP cause value
    Error(u8),
    /// Send session report request to SGWC
    SendSessionReport(UserPlaneReport),
}

// ============================================================================
// Session Establishment Request Data
// ============================================================================

/// Parsed Session Establishment Request
#[derive(Debug, Clone, Default)]
pub struct SessionEstablishmentRequest {
    /// CP F-SEID from SGWC
    pub cp_f_seid: Option<FSeid>,
    /// Create PDR list
    pub create_pdrs: Vec<CreatePdrRequest>,
    /// Create FAR list
    pub create_fars: Vec<CreateFarRequest>,
    /// Create QER list
    pub create_qers: Vec<CreateQerRequest>,
    /// Create BAR
    pub create_bar: Option<CreateBarRequest>,
    /// PFCPSEReq-Flags
    pub sereq_flags: SereqFlags,
}

/// PFCPSEReq-Flags
#[derive(Debug, Clone, Default)]
pub struct SereqFlags {
    /// Restoration Indication
    pub restoration_indication: bool,
}

/// Create PDR Request
#[derive(Debug, Clone, Default)]
pub struct CreatePdrRequest {
    pub pdr_id: u16,
    pub precedence: u32,
    pub pdi: Option<PdiRequest>,
    pub outer_header_removal: Option<u8>,
    pub far_id: Option<u32>,
    pub qer_id: Option<u32>,
}

/// PDI (Packet Detection Information)
#[derive(Debug, Clone, Default)]
pub struct PdiRequest {
    pub source_interface: u8,
    pub local_f_teid: Option<FTeidRequest>,
    pub network_instance: Option<String>,
    pub ue_ip_address: Option<UeIpAddress>,
}

/// F-TEID Request
#[derive(Debug, Clone, Default)]
pub struct FTeidRequest {
    pub ch: bool, // Choose flag - UPF allocates TEID
    pub teid: u32,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

/// UE IP Address
#[derive(Debug, Clone, Default)]
pub struct UeIpAddress {
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

/// Create FAR Request
#[derive(Debug, Clone, Default)]
pub struct CreateFarRequest {
    pub far_id: u32,
    pub apply_action: u8,
    pub forwarding_parameters: Option<ForwardingParameters>,
}

/// Forwarding Parameters
#[derive(Debug, Clone, Default)]
pub struct ForwardingParameters {
    pub destination_interface: u8,
    pub outer_header_creation: Option<OuterHeaderCreation>,
}

/// Outer Header Creation
#[derive(Debug, Clone, Default)]
pub struct OuterHeaderCreation {
    pub teid: u32,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

/// Create QER Request
#[derive(Debug, Clone, Default)]
pub struct CreateQerRequest {
    pub qer_id: u32,
    pub gate_status: Option<u8>,
    pub mbr: Option<Mbr>,
    pub gbr: Option<Gbr>,
}

/// Maximum Bit Rate
#[derive(Debug, Clone, Default)]
pub struct Mbr {
    pub ul: u64,
    pub dl: u64,
}

/// Guaranteed Bit Rate
#[derive(Debug, Clone, Default)]
pub struct Gbr {
    pub ul: u64,
    pub dl: u64,
}

/// Create BAR Request
#[derive(Debug, Clone, Default)]
pub struct CreateBarRequest {
    pub bar_id: u8,
    pub downlink_data_notification_delay: Option<u8>,
}

// ============================================================================
// Session Modification Request Data
// ============================================================================

/// Parsed Session Modification Request
#[derive(Debug, Clone, Default)]
pub struct SessionModificationRequest {
    /// Create PDR list
    pub create_pdrs: Vec<CreatePdrRequest>,
    /// Update PDR list
    pub update_pdrs: Vec<UpdatePdrRequest>,
    /// Remove PDR list
    pub remove_pdrs: Vec<u16>,
    /// Create FAR list
    pub create_fars: Vec<CreateFarRequest>,
    /// Update FAR list
    pub update_fars: Vec<UpdateFarRequest>,
    /// Remove FAR list
    pub remove_fars: Vec<u32>,
    /// Create QER list
    pub create_qers: Vec<CreateQerRequest>,
    /// Update QER list
    pub update_qers: Vec<UpdateQerRequest>,
    /// Remove QER list
    pub remove_qers: Vec<u32>,
    /// Create BAR
    pub create_bar: Option<CreateBarRequest>,
    /// Remove BAR
    pub remove_bar: Option<u8>,
}

/// Update PDR Request
#[derive(Debug, Clone, Default)]
pub struct UpdatePdrRequest {
    pub pdr_id: u16,
    pub pdi: Option<PdiRequest>,
    pub outer_header_removal: Option<u8>,
    pub far_id: Option<u32>,
}

/// Update FAR Request
#[derive(Debug, Clone, Default)]
pub struct UpdateFarRequest {
    pub far_id: u32,
    pub apply_action: Option<u8>,
    pub update_forwarding_parameters: Option<ForwardingParameters>,
    /// PFCPSMReq-Flags
    pub smreq_flags: SmreqFlags,
}

/// PFCPSMReq-Flags
#[derive(Debug, Clone, Default)]
pub struct SmreqFlags {
    /// Send End Marker Packets
    pub send_end_marker_packets: bool,
}

/// Update QER Request
#[derive(Debug, Clone, Default)]
pub struct UpdateQerRequest {
    pub qer_id: u32,
    pub gate_status: Option<u8>,
    pub mbr: Option<Mbr>,
    pub gbr: Option<Gbr>,
}

// ============================================================================
// Session Report Response Data
// ============================================================================

/// Parsed Session Report Response
#[derive(Debug, Clone, Default)]
pub struct SessionReportResponse {
    /// Cause value
    pub cause: Option<u8>,
}

// ============================================================================
// SXA Handlers (from SGW-C)
// ============================================================================

/// Handle Session Establishment Request from SGW-C
/// Port of sgwu_sxa_handle_session_establishment_request
pub fn handle_session_establishment_request(
    sess: Option<&SgwuSess>,
    _xact_id: u64,
    req: &SessionEstablishmentRequest,
) -> (HandlerResult, Vec<CreatedPdr>) {
    log::info!("Session Establishment Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return (HandlerResult::Error(pfcp_cause::MANDATORY_IE_MISSING), vec![]);
        }
    };

    let mut created_pdrs = Vec::new();
    let restoration_indication = req.sereq_flags.restoration_indication;

    // Process Create PDRs
    for create_pdr in &req.create_pdrs {
        match process_create_pdr(sess, create_pdr, restoration_indication) {
            Ok(created_pdr) => {
                if let Some(pdr) = created_pdr {
                    created_pdrs.push(pdr);
                }
            }
            Err(cause) => {
                log::error!("Failed to create PDR: cause={cause}");
                return (HandlerResult::Error(cause), vec![]);
            }
        }
    }

    // Process Create FARs
    for create_far in &req.create_fars {
        if let Err(cause) = process_create_far(sess, create_far) {
            log::error!("Failed to create FAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create QERs
    for create_qer in &req.create_qers {
        if let Err(cause) = process_create_qer(sess, create_qer) {
            log::error!("Failed to create QER: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create BAR
    if let Some(ref create_bar) = req.create_bar {
        if let Err(cause) = process_create_bar(sess, create_bar) {
            log::error!("Failed to create BAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    log::info!(
        "    SGWU_SXA_SEID[0x{:x}] SGWC_SXA_SEID[0x{:x}]",
        sess.sgwu_sxa_seid,
        sess.sgwc_sxa_f_seid.seid
    );
    log::info!(
        "    Created {} PDRs, {} FARs, {} QERs",
        req.create_pdrs.len(),
        req.create_fars.len(),
        req.create_qers.len()
    );

    (HandlerResult::Ok, created_pdrs)
}

/// Handle Session Modification Request from SGW-C
/// Port of sgwu_sxa_handle_session_modification_request
pub fn handle_session_modification_request(
    sess: Option<&SgwuSess>,
    _xact_id: u64,
    req: &SessionModificationRequest,
) -> (HandlerResult, Vec<CreatedPdr>) {
    log::info!("Session Modification Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return (HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND), vec![]);
        }
    };

    let mut created_pdrs = Vec::new();
    let mut send_end_marker = false;

    // Process Create PDRs
    for create_pdr in &req.create_pdrs {
        match process_create_pdr(sess, create_pdr, false) {
            Ok(created_pdr) => {
                if let Some(pdr) = created_pdr {
                    created_pdrs.push(pdr);
                }
            }
            Err(cause) => {
                log::error!("Failed to create PDR: cause={cause}");
                return (HandlerResult::Error(cause), vec![]);
            }
        }
    }

    // Process Update PDRs
    for update_pdr in &req.update_pdrs {
        if let Err(cause) = process_update_pdr(sess, update_pdr) {
            log::error!("Failed to update PDR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Remove PDRs
    for pdr_id in &req.remove_pdrs {
        if let Err(cause) = process_remove_pdr(sess, *pdr_id) {
            log::error!("Failed to remove PDR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create FARs
    for create_far in &req.create_fars {
        if let Err(cause) = process_create_far(sess, create_far) {
            log::error!("Failed to create FAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Update FARs (check for end marker flag first)
    for update_far in &req.update_fars {
        if update_far.smreq_flags.send_end_marker_packets {
            send_end_marker = true;
        }
    }

    // Send End Marker if requested
    if send_end_marker {
        log::debug!("Sending End Marker packets");
        // In actual implementation, send end marker to gNB/eNB
    }

    // Process Update FARs
    for update_far in &req.update_fars {
        if let Err(cause) = process_update_far(sess, update_far) {
            log::error!("Failed to update FAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Remove FARs
    for far_id in &req.remove_fars {
        if let Err(cause) = process_remove_far(sess, *far_id) {
            log::error!("Failed to remove FAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create QERs
    for create_qer in &req.create_qers {
        if let Err(cause) = process_create_qer(sess, create_qer) {
            log::error!("Failed to create QER: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Update QERs
    for update_qer in &req.update_qers {
        if let Err(cause) = process_update_qer(sess, update_qer) {
            log::error!("Failed to update QER: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Remove QERs
    for qer_id in &req.remove_qers {
        if let Err(cause) = process_remove_qer(sess, *qer_id) {
            log::error!("Failed to remove QER: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create BAR
    if let Some(ref create_bar) = req.create_bar {
        if let Err(cause) = process_create_bar(sess, create_bar) {
            log::error!("Failed to create BAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Remove BAR
    if let Some(bar_id) = req.remove_bar {
        if let Err(cause) = process_remove_bar(sess, bar_id) {
            log::error!("Failed to remove BAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    log::info!(
        "    SGWU_SXA_SEID[0x{:x}] SGWC_SXA_SEID[0x{:x}]",
        sess.sgwu_sxa_seid,
        sess.sgwc_sxa_f_seid.seid
    );

    (HandlerResult::Ok, created_pdrs)
}

/// Handle Session Deletion Request from SGW-C
/// Port of sgwu_sxa_handle_session_deletion_request
pub fn handle_session_deletion_request(
    sess: Option<&SgwuSess>,
    _xact_id: u64,
) -> HandlerResult {
    log::info!("Session Deletion Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    SGWU_SXA_SEID[0x{:x}] SGWC_SXA_SEID[0x{:x}]",
        sess.sgwu_sxa_seid,
        sess.sgwc_sxa_f_seid.seid
    );

    // Session will be removed after sending response
    HandlerResult::Ok
}

/// Handle Session Report Response from SGW-C
/// Port of sgwu_sxa_handle_session_report_response
pub fn handle_session_report_response(
    sess: Option<&SgwuSess>,
    _xact_id: u64,
    rsp: &SessionReportResponse,
) -> HandlerResult {
    log::info!("Session Report Response");

    let cause = rsp.cause.unwrap_or(pfcp_cause::MANDATORY_IE_MISSING);

    if sess.is_none() {
        log::warn!("No Context");
        return HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND);
    }

    if cause != pfcp_cause::REQUEST_ACCEPTED {
        log::error!("PFCP Cause[{cause}] : Not Accepted");
        return HandlerResult::Error(cause);
    }

    log::debug!("Session Report Response accepted");
    HandlerResult::Ok
}

// ============================================================================
// Internal Processing Functions
// ============================================================================

/// Process Create PDR
fn process_create_pdr(
    _sess: &SgwuSess,
    req: &CreatePdrRequest,
    restoration_indication: bool,
) -> Result<Option<CreatedPdr>, u8> {
    log::debug!("Creating PDR: id={}", req.pdr_id);

    // In actual implementation:
    // 1. Allocate PDR in PFCP session
    // 2. Set up PDI (source interface, F-TEID, etc.)
    // 3. Set up outer header removal
    // 4. Link to FAR/QER
    // 5. Set up TEID hash for incoming packets

    // Check if F-TEID needs to be allocated
    let local_f_teid = if let Some(ref pdi) = req.pdi {
        if let Some(ref f_teid) = pdi.local_f_teid {
            if f_teid.ch {
                // UPF needs to allocate TEID
                Some(crate::sxa_build::LocalFTeid {
                    teid: generate_teid(),
                    ipv4: Some(std::net::Ipv4Addr::new(127, 0, 0, 1)), // Placeholder
                    ipv6: None,
                })
            } else if restoration_indication {
                // Restoration - swap TEID
                log::debug!("Restoration indication - swapping TEID");
                Some(crate::sxa_build::LocalFTeid {
                    teid: f_teid.teid,
                    ipv4: f_teid.ipv4,
                    ipv6: f_teid.ipv6,
                })
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Return created PDR info if F-TEID was allocated
    if local_f_teid.is_some() {
        Ok(Some(CreatedPdr {
            pdr_id: req.pdr_id,
            local_f_teid,
        }))
    } else {
        Ok(None)
    }
}

/// Process Create FAR
fn process_create_far(_sess: &SgwuSess, req: &CreateFarRequest) -> Result<(), u8> {
    log::debug!("Creating FAR: id={}", req.far_id);

    // In actual implementation:
    // 1. Allocate FAR in PFCP session
    // 2. Set apply action (FORW, DROP, BUFF, etc.)
    // 3. Set up forwarding parameters (destination interface, outer header creation)
    // 4. Set up GTP-U node for forwarding

    Ok(())
}

/// Process Create QER
fn process_create_qer(_sess: &SgwuSess, req: &CreateQerRequest) -> Result<(), u8> {
    log::debug!("Creating QER: id={}", req.qer_id);

    // In actual implementation:
    // 1. Allocate QER in PFCP session
    // 2. Set gate status
    // 3. Set MBR/GBR values

    Ok(())
}

/// Process Create BAR
fn process_create_bar(_sess: &SgwuSess, req: &CreateBarRequest) -> Result<(), u8> {
    log::debug!("Creating BAR: id={}", req.bar_id);

    // In actual implementation:
    // 1. Allocate BAR in PFCP session
    // 2. Set downlink data notification delay

    Ok(())
}

/// Process Update PDR
fn process_update_pdr(_sess: &SgwuSess, req: &UpdatePdrRequest) -> Result<(), u8> {
    log::debug!("Updating PDR: id={}", req.pdr_id);

    // In actual implementation:
    // 1. Find PDR by ID
    // 2. Update PDI if present
    // 3. Update outer header removal if present
    // 4. Update FAR link if present

    Ok(())
}

/// Process Remove PDR
fn process_remove_pdr(_sess: &SgwuSess, pdr_id: u16) -> Result<(), u8> {
    log::debug!("Removing PDR: id={pdr_id}");

    // In actual implementation:
    // 1. Find PDR by ID
    // 2. Remove from TEID hash
    // 3. Free PDR

    Ok(())
}

/// Process Update FAR
fn process_update_far(_sess: &SgwuSess, req: &UpdateFarRequest) -> Result<(), u8> {
    log::debug!("Updating FAR: id={}", req.far_id);

    // In actual implementation:
    // 1. Find FAR by ID
    // 2. Update apply action if present
    // 3. Update forwarding parameters if present
    // 4. Update GTP-U node if needed

    Ok(())
}

/// Process Remove FAR
fn process_remove_far(_sess: &SgwuSess, far_id: u32) -> Result<(), u8> {
    log::debug!("Removing FAR: id={far_id}");

    // In actual implementation:
    // 1. Find FAR by ID
    // 2. Remove from F-TEID hash
    // 3. Free FAR

    Ok(())
}

/// Process Update QER
fn process_update_qer(_sess: &SgwuSess, req: &UpdateQerRequest) -> Result<(), u8> {
    log::debug!("Updating QER: id={}", req.qer_id);

    // In actual implementation:
    // 1. Find QER by ID
    // 2. Update gate status if present
    // 3. Update MBR/GBR if present

    Ok(())
}

/// Process Remove QER
fn process_remove_qer(_sess: &SgwuSess, qer_id: u32) -> Result<(), u8> {
    log::debug!("Removing QER: id={qer_id}");

    // In actual implementation:
    // 1. Find QER by ID
    // 2. Free QER

    Ok(())
}

/// Process Remove BAR
fn process_remove_bar(_sess: &SgwuSess, bar_id: u8) -> Result<(), u8> {
    log::debug!("Removing BAR: id={bar_id}");

    // In actual implementation:
    // 1. Find BAR by ID
    // 2. Free BAR

    Ok(())
}

/// Generate a new TEID
fn generate_teid() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static TEID_COUNTER: AtomicU32 = AtomicU32::new(1);
    TEID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_sess() -> SgwuSess {
        SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        }
    }

    #[test]
    fn test_handle_session_establishment_request_no_sess() {
        let req = SessionEstablishmentRequest::default();
        let (result, _) = handle_session_establishment_request(None, 1, &req);
        matches!(result, HandlerResult::Error(pfcp_cause::MANDATORY_IE_MISSING));
    }

    #[test]
    fn test_handle_session_establishment_request_ok() {
        let sess = create_test_sess();
        let req = SessionEstablishmentRequest {
            create_pdrs: vec![CreatePdrRequest {
                pdr_id: 1,
                precedence: 100,
                pdi: Some(PdiRequest {
                    source_interface: pfcp_interface::ACCESS,
                    local_f_teid: Some(FTeidRequest {
                        ch: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            create_fars: vec![CreateFarRequest {
                far_id: 1,
                apply_action: 0x02, // FORW
                ..Default::default()
            }],
            ..Default::default()
        };

        let (result, created_pdrs) = handle_session_establishment_request(Some(&sess), 1, &req);
        assert!(matches!(result, HandlerResult::Ok));
        assert_eq!(created_pdrs.len(), 1);
    }

    #[test]
    fn test_handle_session_modification_request_no_sess() {
        let req = SessionModificationRequest::default();
        let (result, _) = handle_session_modification_request(None, 1, &req);
        matches!(result, HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND));
    }

    #[test]
    fn test_handle_session_modification_request_ok() {
        let sess = create_test_sess();
        let req = SessionModificationRequest {
            update_fars: vec![UpdateFarRequest {
                far_id: 1,
                apply_action: Some(0x02),
                smreq_flags: SmreqFlags {
                    send_end_marker_packets: true,
                },
                ..Default::default()
            }],
            ..Default::default()
        };

        let (result, _) = handle_session_modification_request(Some(&sess), 1, &req);
        assert!(matches!(result, HandlerResult::Ok));
    }

    #[test]
    fn test_handle_session_deletion_request_no_sess() {
        let result = handle_session_deletion_request(None, 1);
        matches!(result, HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND));
    }

    #[test]
    fn test_handle_session_deletion_request_ok() {
        let sess = create_test_sess();
        let result = handle_session_deletion_request(Some(&sess), 1);
        assert!(matches!(result, HandlerResult::Ok));
    }

    #[test]
    fn test_handle_session_report_response_no_cause() {
        let sess = create_test_sess();
        let rsp = SessionReportResponse { cause: None };
        let result = handle_session_report_response(Some(&sess), 1, &rsp);
        matches!(result, HandlerResult::Error(pfcp_cause::MANDATORY_IE_MISSING));
    }

    #[test]
    fn test_handle_session_report_response_ok() {
        let sess = create_test_sess();
        let rsp = SessionReportResponse {
            cause: Some(pfcp_cause::REQUEST_ACCEPTED),
        };
        let result = handle_session_report_response(Some(&sess), 1, &rsp);
        assert!(matches!(result, HandlerResult::Ok));
    }

    #[test]
    fn test_generate_teid() {
        let teid1 = generate_teid();
        let teid2 = generate_teid();
        assert_ne!(teid1, teid2);
    }
}
