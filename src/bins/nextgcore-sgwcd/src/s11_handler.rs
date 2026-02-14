//! SGWC S11 Handler
//!
//! Port of src/sgwc/s11-handler.c - Handlers for GTPv2-C messages from MME

use crate::context::{sgwc_self, SgwcSess, SgwcUe};

// ============================================================================
// GTP Cause Values (from OGS_GTP2_CAUSE_*)
// ============================================================================

pub mod gtp_cause {
    pub const REQUEST_ACCEPTED: u8 = 16;
    pub const REQUEST_ACCEPTED_PARTIALLY: u8 = 17;
    pub const NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE: u8 = 18;
    pub const NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY: u8 = 19;
    pub const CONTEXT_NOT_FOUND: u8 = 64;
    pub const INVALID_MESSAGE_FORMAT: u8 = 65;
    pub const MANDATORY_IE_MISSING: u8 = 70;
    pub const CONDITIONAL_IE_MISSING: u8 = 71;
    pub const INVALID_LENGTH: u8 = 72;
    pub const MANDATORY_IE_INCORRECT: u8 = 73;
    pub const SYSTEM_FAILURE: u8 = 75;
    pub const NO_RESOURCES_AVAILABLE: u8 = 76;
    pub const REMOTE_PEER_NOT_RESPONDING: u8 = 100;
    pub const GRE_KEY_NOT_FOUND: u8 = 80;
}

// ============================================================================
// GTP Message Types (from OGS_GTP2_*_TYPE)
// ============================================================================

pub mod gtp_message_type {
    pub const CREATE_SESSION_REQUEST: u8 = 32;
    pub const CREATE_SESSION_RESPONSE: u8 = 33;
    pub const MODIFY_BEARER_REQUEST: u8 = 34;
    pub const MODIFY_BEARER_RESPONSE: u8 = 35;
    pub const DELETE_SESSION_REQUEST: u8 = 36;
    pub const DELETE_SESSION_RESPONSE: u8 = 37;
    pub const CREATE_BEARER_REQUEST: u8 = 95;
    pub const CREATE_BEARER_RESPONSE: u8 = 96;
    pub const UPDATE_BEARER_REQUEST: u8 = 97;
    pub const UPDATE_BEARER_RESPONSE: u8 = 98;
    pub const DELETE_BEARER_REQUEST: u8 = 99;
    pub const DELETE_BEARER_RESPONSE: u8 = 100;
    pub const RELEASE_ACCESS_BEARERS_REQUEST: u8 = 170;
    pub const RELEASE_ACCESS_BEARERS_RESPONSE: u8 = 171;
    pub const DOWNLINK_DATA_NOTIFICATION: u8 = 176;
    pub const DOWNLINK_DATA_NOTIFICATION_ACK: u8 = 177;
    pub const CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST: u8 = 166;
    pub const CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE: u8 = 167;
    pub const DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST: u8 = 168;
    pub const DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE: u8 = 169;
    pub const BEARER_RESOURCE_COMMAND: u8 = 68;
    pub const BEARER_RESOURCE_FAILURE_INDICATION: u8 = 69;
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
    /// Need to send PFCP request
    SendPfcp,
    /// Need to forward to PGW
    ForwardToPgw,
}

// ============================================================================
// S11 Handlers (from MME)
// ============================================================================

/// Handle Create Session Request from MME
/// Port of sgwc_s11_handle_create_session_request
pub fn handle_create_session_request(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    imsi: &[u8],
    apn: &str,
    mme_s11_teid: u32,
    ebi: u8,
) -> HandlerResult {
    log::info!("Create Session Request");

    // Check SGWC-UE Context
    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            // Create new UE context
            let ctx = sgwc_self();
            match ctx.ue_add(imsi) {
                Some(_) => {
                    log::info!("Created new SGWC UE context");
                }
                None => {
                    log::error!("Failed to create SGWC UE context");
                    return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
                }
            }
            // Re-fetch the UE
            match ctx.ue_find_by_imsi(imsi) {
                Some(ue) => {
                    // Update MME S11 TEID
                    let mut ue = ue;
                    ue.mme_s11_teid = mme_s11_teid;
                    ctx.ue_update(&ue);
                    log::info!(
                        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
                        ue.mme_s11_teid,
                        ue.sgw_s11_teid
                    );
                }
                None => {
                    return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
                }
            }
            return handle_create_session_continue(imsi, apn, ebi);
        }
    };

    // UE exists, update MME TEID
    let ctx = sgwc_self();
    let mut ue = sgwc_ue.clone();
    ue.mme_s11_teid = mme_s11_teid;
    ctx.ue_update(&ue);

    log::info!("UE IMSI[{}] APN[{}]", ue.imsi_bcd, apn);
    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        ue.mme_s11_teid,
        ue.sgw_s11_teid
    );

    handle_create_session_continue(imsi, apn, ebi)
}

fn handle_create_session_continue(imsi: &[u8], apn: &str, ebi: u8) -> HandlerResult {
    let ctx = sgwc_self();

    let ue = match ctx.ue_find_by_imsi(imsi) {
        Some(ue) => ue,
        None => return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND),
    };

    // Check if session already exists
    if let Some(existing_sess) = ctx.sess_find_by_apn(ue.id, apn) {
        log::info!(
            "OLD Session Release [IMSI:{},APN:{}]",
            ue.imsi_bcd,
            apn
        );
        ctx.sess_remove(existing_sess.id);
    }

    // Add new session
    let sess = match ctx.sess_add(ue.id, apn) {
        Some(s) => s,
        None => {
            log::error!("Failed to add session");
            return HandlerResult::Error(gtp_cause::NO_RESOURCES_AVAILABLE);
        }
    };

    // Add default bearer
    let bearer = match ctx.bearer_add(sess.id) {
        Some(mut b) => {
            b.ebi = ebi;
            ctx.bearer_update(&b);
            b
        }
        None => {
            log::error!("Failed to add bearer");
            ctx.sess_remove(sess.id);
            return HandlerResult::Error(gtp_cause::NO_RESOURCES_AVAILABLE);
        }
    };

    log::info!(
        "    Session added: id={}, seid={}, bearer_ebi={}",
        sess.id,
        sess.sgwc_sxa_seid,
        bearer.ebi
    );

    // Need to send PFCP Session Establishment Request to SGW-U
    HandlerResult::SendPfcp
}

/// Handle Modify Bearer Request from MME
/// Port of sgwc_s11_handle_modify_bearer_request
pub fn handle_modify_bearer_request(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    bearer_ebi: u8,
    enb_teid: u32,
) -> HandlerResult {
    log::info!("Modify Bearer Request");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    let ctx = sgwc_self();

    // Find bearer by EBI
    let bearer = match ctx.bearer_find_by_ue_ebi(sgwc_ue.id, bearer_ebi) {
        Some(b) => b,
        None => {
            log::error!("Unknown EPS Bearer ID[{bearer_ebi}]");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    // Update DL tunnel with eNB TEID
    if let Some(mut dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
        dl_tunnel.remote_teid = enb_teid;
        ctx.tunnel_update(&dl_tunnel);
        log::info!(
            "    ENB_S1U_TEID[{}] SGW_S1U_TEID[{}]",
            dl_tunnel.remote_teid,
            dl_tunnel.local_teid
        );
    }

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );

    // Need to send PFCP Session Modification Request
    HandlerResult::SendPfcp
}

/// Handle Delete Session Request from MME
/// Port of sgwc_s11_handle_delete_session_request
pub fn handle_delete_session_request(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    linked_ebi: u8,
    scope_indication: bool,
) -> HandlerResult {
    log::info!("Delete Session Request");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    let _ctx = sgwc_self();

    // Find session by EBI
    let sess = match find_sess_by_ebi(sgwc_ue.id, linked_ebi) {
        Some(s) => s,
        None => {
            log::error!(
                "Unknown EPS Bearer [IMSI:{}, EBI:{}]",
                sgwc_ue.imsi_bcd,
                linked_ebi
            );
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );
    log::info!(
        "    SGW_S5C_TEID[0x{:x}] PGW_S5C_TEID[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.pgw_s5c_teid
    );

    if scope_indication {
        // Local delete - send PFCP Session Deletion Request
        HandlerResult::SendPfcp
    } else {
        // Forward to PGW
        HandlerResult::ForwardToPgw
    }
}

/// Handle Create Bearer Response from MME
/// Port of sgwc_s11_handle_create_bearer_response
pub fn handle_create_bearer_response(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    bearer_ebi: u8,
    cause: u8,
) -> HandlerResult {
    log::info!("Create Bearer Response");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    if cause != gtp_cause::REQUEST_ACCEPTED {
        log::error!("GTP Cause [VALUE:{cause}]");
        return HandlerResult::Error(cause);
    }

    let ctx = sgwc_self();

    // Find bearer
    let bearer = match ctx.bearer_find_by_ue_ebi(sgwc_ue.id, bearer_ebi) {
        Some(b) => b,
        None => {
            log::error!("No Bearer Context [EBI:{bearer_ebi}]");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!("    bearer[EBI={}]", bearer.ebi);

    // Need to send PFCP Session Modification Request
    HandlerResult::SendPfcp
}

/// Handle Update Bearer Response from MME
/// Port of sgwc_s11_handle_update_bearer_response
pub fn handle_update_bearer_response(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    bearer_ebi: u8,
    cause: u8,
) -> HandlerResult {
    log::info!("Update Bearer Response");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    if cause != gtp_cause::REQUEST_ACCEPTED {
        log::error!("GTP Cause [VALUE:{cause}]");
        return HandlerResult::Error(cause);
    }

    let ctx = sgwc_self();

    // Find bearer
    let bearer = match ctx.bearer_find_by_ue_ebi(sgwc_ue.id, bearer_ebi) {
        Some(b) => b,
        None => {
            log::error!("No Bearer Context [EBI:{bearer_ebi}]");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!("    bearer[EBI={}]", bearer.ebi);

    // Forward response to PGW
    HandlerResult::ForwardToPgw
}

/// Handle Delete Bearer Response from MME
/// Port of sgwc_s11_handle_delete_bearer_response
pub fn handle_delete_bearer_response(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    bearer_ebi: u8,
    cause: u8,
) -> HandlerResult {
    log::info!("Delete Bearer Response");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    if cause != gtp_cause::REQUEST_ACCEPTED {
        log::error!("GTP Cause [VALUE:{cause}]");
    }

    let ctx = sgwc_self();

    // Find bearer
    let bearer = match ctx.bearer_find_by_ue_ebi(sgwc_ue.id, bearer_ebi) {
        Some(b) => b,
        None => {
            log::error!("No Bearer Context [EBI:{bearer_ebi}]");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!("    bearer[EBI={}]", bearer.ebi);

    // Need to send PFCP Session Modification Request to remove bearer
    HandlerResult::SendPfcp
}

/// Handle Release Access Bearers Request from MME
/// Port of sgwc_s11_handle_release_access_bearers_request
pub fn handle_release_access_bearers_request(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
) -> HandlerResult {
    log::info!("Release Access Bearers Request");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );

    // Need to send PFCP Session Modification Request to deactivate bearers
    HandlerResult::SendPfcp
}

/// Handle Downlink Data Notification Ack from MME
/// Port of sgwc_s11_handle_downlink_data_notification_ack
pub fn handle_downlink_data_notification_ack(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    cause: u8,
) -> HandlerResult {
    log::info!("Downlink Data Notification Ack");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    if cause != gtp_cause::REQUEST_ACCEPTED {
        log::warn!("GTP Cause [VALUE:{cause}]");
    }

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );

    HandlerResult::Ok
}

/// Handle Create Indirect Data Forwarding Tunnel Request from MME
/// Port of sgwc_s11_handle_create_indirect_data_forwarding_tunnel_request
pub fn handle_create_indirect_data_forwarding_tunnel_request(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
) -> HandlerResult {
    log::info!("Create Indirect Data Forwarding Tunnel Request");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );

    // Need to send PFCP Session Modification Request
    HandlerResult::SendPfcp
}

/// Handle Delete Indirect Data Forwarding Tunnel Request from MME
/// Port of sgwc_s11_handle_delete_indirect_data_forwarding_tunnel_request
pub fn handle_delete_indirect_data_forwarding_tunnel_request(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
) -> HandlerResult {
    log::info!("Delete Indirect Data Forwarding Tunnel Request");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );

    // Need to send PFCP Session Modification Request
    HandlerResult::SendPfcp
}

/// Handle Bearer Resource Command from MME
/// Port of sgwc_s11_handle_bearer_resource_command
pub fn handle_bearer_resource_command(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    linked_ebi: u8,
) -> HandlerResult {
    log::info!("Bearer Resource Command");

    let sgwc_ue = match sgwc_ue {
        Some(ue) => ue,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    // Find session by linked EBI
    let sess = match find_sess_by_ebi(sgwc_ue.id, linked_ebi) {
        Some(s) => s,
        None => {
            log::error!(
                "Unknown EPS Bearer [IMSI:{}, EBI:{}]",
                sgwc_ue.imsi_bcd,
                linked_ebi
            );
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );
    log::info!(
        "    SGW_S5C_TEID[0x{:x}] PGW_S5C_TEID[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.pgw_s5c_teid
    );

    // Forward to PGW
    HandlerResult::ForwardToPgw
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find session by EBI (searches through all sessions for a UE)
fn find_sess_by_ebi(sgwc_ue_id: u64, ebi: u8) -> Option<SgwcSess> {
    let ctx = sgwc_self();
    let ue = ctx.ue_find_by_id(sgwc_ue_id)?;

    for sess_id in &ue.sess_ids {
        if let Some(sess) = ctx.sess_find_by_id(*sess_id) {
            // Check if any bearer in this session has the EBI
            if ctx.bearer_find_by_sess_ebi(sess.id, ebi).is_some() {
                return Some(sess);
            }
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_request_no_ue() {
        let imsi = vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x10];
        let result = handle_create_session_request(
            None,
            1,
            &[],
            &imsi,
            "internet",
            12345,
            5,
        );
        // Should create UE and session, return SendPfcp
        matches!(result, HandlerResult::SendPfcp);
    }

    #[test]
    fn test_modify_bearer_request_no_ue() {
        let result = handle_modify_bearer_request(None, 1, &[], 5, 100);
        matches!(result, HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND));
    }

    #[test]
    fn test_delete_session_request_no_ue() {
        let result = handle_delete_session_request(None, 1, &[], 5, false);
        matches!(result, HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND));
    }
}
