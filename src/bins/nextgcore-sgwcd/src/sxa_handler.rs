//! SGWC SXA Handler
//!
//! Port of src/sgwc/sxa-handler.c - Handlers for PFCP messages from SGW-U

use crate::context::{sgwc_self, SgwcSess};
use crate::s11_handler::gtp_cause;

// ============================================================================
// PFCP Cause Values (from OGS_PFCP_CAUSE_*)
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
// PFCP Modify Flags
// ============================================================================

pub mod pfcp_modify {
    pub const SESSION: u64 = 0x0001;
    pub const DL_ONLY: u64 = 0x0002;
    pub const UL_ONLY: u64 = 0x0004;
    pub const CREATE: u64 = 0x0008;
    pub const REMOVE: u64 = 0x0010;
    pub const ACTIVATE: u64 = 0x0020;
    pub const DEACTIVATE: u64 = 0x0040;
    pub const END_MARKER: u64 = 0x0080;
    pub const ERROR_INDICATION: u64 = 0x0100;
    pub const INDIRECT: u64 = 0x0200;
    pub const OUTER_HEADER_REMOVAL: u64 = 0x0400;
}

// ============================================================================
// Handler Result
// ============================================================================

/// Result of handler operations
#[derive(Debug)]
pub enum HandlerResult {
    /// Request accepted, continue processing
    Ok,
    /// Error with GTP cause value
    Error(u8),
    /// Need to send GTP response to MME
    SendGtpToMme,
    /// Need to send GTP request to PGW
    SendGtpToPgw,
    /// Need to send GTP response to PGW
    SendGtpResponseToPgw,
}

// ============================================================================
// Cause Conversion
// ============================================================================

/// Convert PFCP cause to GTP cause
pub fn gtp_cause_from_pfcp(pfcp_cause: u8) -> u8 {
    match pfcp_cause {
        pfcp_cause::REQUEST_ACCEPTED => gtp_cause::REQUEST_ACCEPTED,
        pfcp_cause::REQUEST_REJECTED => gtp_cause::SYSTEM_FAILURE,
        pfcp_cause::SESSION_CONTEXT_NOT_FOUND => gtp_cause::CONTEXT_NOT_FOUND,
        pfcp_cause::MANDATORY_IE_MISSING => gtp_cause::MANDATORY_IE_MISSING,
        pfcp_cause::CONDITIONAL_IE_MISSING => gtp_cause::CONDITIONAL_IE_MISSING,
        pfcp_cause::INVALID_LENGTH => gtp_cause::INVALID_LENGTH,
        pfcp_cause::MANDATORY_IE_INCORRECT => gtp_cause::MANDATORY_IE_INCORRECT,
        pfcp_cause::INVALID_FORWARDING_POLICY | pfcp_cause::INVALID_F_TEID_ALLOCATION_OPTION => {
            gtp_cause::INVALID_MESSAGE_FORMAT
        }
        pfcp_cause::NO_ESTABLISHED_PFCP_ASSOCIATION => gtp_cause::REMOTE_PEER_NOT_RESPONDING,
        pfcp_cause::NO_RESOURCES_AVAILABLE => gtp_cause::NO_RESOURCES_AVAILABLE,
        pfcp_cause::SYSTEM_FAILURE => gtp_cause::SYSTEM_FAILURE,
        _ => gtp_cause::SYSTEM_FAILURE,
    }
}

// ============================================================================
// SXA Handlers (from SGW-U)
// ============================================================================

/// Handle Session Establishment Response from SGW-U
/// Port of sgwc_sxa_handle_session_establishment_response
pub fn handle_session_establishment_response(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    pfcp_cause: u8,
    up_f_seid: u64,
) -> HandlerResult {
    log::info!("Session Establishment Response");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    // Check PFCP cause
    if pfcp_cause != pfcp_cause::REQUEST_ACCEPTED {
        log::warn!("PFCP Cause [{}] : Not Accepted", pfcp_cause);
        return HandlerResult::Error(gtp_cause_from_pfcp(pfcp_cause));
    }

    let ctx = sgwc_self();

    // Update session with SGW-U SEID
    let mut sess = sess.clone();
    sess.sgwu_sxa_seid = up_f_seid;
    ctx.sess_update(&sess);

    log::info!(
        "    SGW_S5C_TEID[0x{:x}] PGW_S5C_TEID[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.pgw_s5c_teid
    );
    log::info!(
        "    SGWC_SXA_SEID[0x{:x}] SGWU_SXA_SEID[0x{:x}]",
        sess.sgwc_sxa_seid,
        sess.sgwu_sxa_seid
    );

    // Need to send Create Session Request to PGW
    HandlerResult::SendGtpToPgw
}

/// Handle Session Modification Response from SGW-U
/// Port of sgwc_sxa_handle_session_modification_response
pub fn handle_session_modification_response(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    pfcp_cause: u8,
    modify_flags: u64,
) -> HandlerResult {
    log::info!("Session Modification Response");

    // Check PFCP cause first
    if pfcp_cause != pfcp_cause::REQUEST_ACCEPTED {
        log::warn!("PFCP Cause [{}] : Not Accepted", pfcp_cause);
        return HandlerResult::Error(gtp_cause_from_pfcp(pfcp_cause));
    }

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    let ctx = sgwc_self();

    let sgwc_ue = match ctx.ue_find_by_id(sess.sgwc_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("No UE Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );
    log::info!(
        "    SGWC_SXA_SEID[0x{:x}] SGWU_SXA_SEID[0x{:x}]",
        sess.sgwc_sxa_seid,
        sess.sgwu_sxa_seid
    );
    log::debug!("    modify_flags=0x{:x}", modify_flags);

    // Determine next action based on modify flags
    if modify_flags & pfcp_modify::REMOVE != 0 {
        if modify_flags & pfcp_modify::INDIRECT != 0 {
            // Delete Indirect Data Forwarding Tunnel Response
            HandlerResult::SendGtpToMme
        } else {
            // Delete Bearer Response to PGW
            HandlerResult::SendGtpResponseToPgw
        }
    } else if modify_flags & pfcp_modify::CREATE != 0 {
        if modify_flags & pfcp_modify::UL_ONLY != 0 {
            // Create Bearer Request to MME
            HandlerResult::SendGtpToMme
        } else {
            HandlerResult::Ok
        }
    } else if modify_flags & pfcp_modify::ACTIVATE != 0 {
        if modify_flags & pfcp_modify::UL_ONLY != 0 {
            // Create Session Response to MME
            HandlerResult::SendGtpToMme
        } else if modify_flags & pfcp_modify::DL_ONLY != 0 {
            // Modify Bearer Response to MME
            HandlerResult::SendGtpToMme
        } else {
            HandlerResult::Ok
        }
    } else if modify_flags & pfcp_modify::DEACTIVATE != 0 {
        if modify_flags & pfcp_modify::ERROR_INDICATION != 0 {
            // Send Downlink Data Notification
            HandlerResult::SendGtpToMme
        } else {
            // Release Access Bearers Response
            HandlerResult::SendGtpToMme
        }
    } else {
        HandlerResult::Ok
    }
}

/// Handle Session Deletion Response from SGW-U
/// Port of sgwc_sxa_handle_session_deletion_response
pub fn handle_session_deletion_response(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    pfcp_cause: u8,
) -> HandlerResult {
    log::info!("Session Deletion Response");

    // Check PFCP cause first
    if pfcp_cause != pfcp_cause::REQUEST_ACCEPTED {
        log::warn!("PFCP Cause [{}] : Not Accepted", pfcp_cause);
        return HandlerResult::Error(gtp_cause_from_pfcp(pfcp_cause));
    }

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    let ctx = sgwc_self();

    let sgwc_ue = match ctx.ue_find_by_id(sess.sgwc_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("No UE Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );
    log::info!(
        "    SGWC_SXA_SEID[0x{:x}] SGWU_SXA_SEID[0x{:x}]",
        sess.sgwc_sxa_seid,
        sess.sgwu_sxa_seid
    );

    // Remove session
    ctx.sess_remove(sess.id);

    // Send Delete Session Response to MME
    HandlerResult::SendGtpToMme
}

/// Handle Session Report Request from SGW-U
/// Port of sgwc_sxa_handle_session_report_request
pub fn handle_session_report_request(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    report_type: u8,
    pdr_id: Option<u16>,
) -> HandlerResult {
    log::info!("Session Report Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    let ctx = sgwc_self();

    let sgwc_ue = match ctx.ue_find_by_id(sess.sgwc_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("No UE Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );
    log::info!(
        "    SGWC_SXA_SEID[0x{:x}] SGWU_SXA_SEID[0x{:x}]",
        sess.sgwc_sxa_seid,
        sess.sgwu_sxa_seid
    );
    log::info!("    Report Type: {}, PDR ID: {:?}", report_type, pdr_id);

    // Report types:
    // - DLDR (Downlink Data Report): Need to send Downlink Data Notification
    // - ERIR (Error Indication Report): Handle error indication
    // - USAR (Usage Report): Handle usage report
    // - UPIR (User Plane Inactivity Report): Handle inactivity

    const REPORT_TYPE_DLDR: u8 = 1;
    const REPORT_TYPE_ERIR: u8 = 4;

    if report_type & REPORT_TYPE_DLDR != 0 {
        // Downlink Data Report - send DDN to MME
        log::info!("    Downlink Data Report received");
        HandlerResult::SendGtpToMme
    } else if report_type & REPORT_TYPE_ERIR != 0 {
        // Error Indication Report
        log::warn!("    Error Indication Report received");
        HandlerResult::Ok
    } else {
        log::debug!("    Other report type: {}", report_type);
        HandlerResult::Ok
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_cause_from_pfcp() {
        assert_eq!(
            gtp_cause_from_pfcp(pfcp_cause::REQUEST_ACCEPTED),
            gtp_cause::REQUEST_ACCEPTED
        );
        assert_eq!(
            gtp_cause_from_pfcp(pfcp_cause::SESSION_CONTEXT_NOT_FOUND),
            gtp_cause::CONTEXT_NOT_FOUND
        );
        assert_eq!(
            gtp_cause_from_pfcp(pfcp_cause::SYSTEM_FAILURE),
            gtp_cause::SYSTEM_FAILURE
        );
    }

    #[test]
    fn test_session_establishment_response_no_sess() {
        let result = handle_session_establishment_response(
            None,
            1,
            pfcp_cause::REQUEST_ACCEPTED,
            0x1234,
        );
        matches!(result, HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND));
    }

    #[test]
    fn test_session_deletion_response_no_sess() {
        let result = handle_session_deletion_response(
            None,
            1,
            pfcp_cause::REQUEST_ACCEPTED,
        );
        matches!(result, HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND));
    }
}
