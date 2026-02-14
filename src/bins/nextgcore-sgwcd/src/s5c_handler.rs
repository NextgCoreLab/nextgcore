//! SGWC S5-C Handler
//!
//! Port of src/sgwc/s5c-handler.c - Handlers for GTPv2-C messages from PGW

use crate::context::{sgwc_self, SgwcSess};
use crate::s11_handler::gtp_cause;

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
    /// Need to forward to MME
    ForwardToMme,
}

// ============================================================================
// S5-C Handlers (from PGW)
// ============================================================================

/// Handle Create Session Response from PGW
/// Port of sgwc_s5c_handle_create_session_response
pub fn handle_create_session_response(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    session_cause: u8,
    pgw_s5c_teid: u32,
    pgw_s5u_teid: u32,
) -> HandlerResult {
    log::info!("Create Session Response");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context in TEID [Cause:{session_cause}]");
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

    // Check cause value
    if session_cause != gtp_cause::REQUEST_ACCEPTED
        && session_cause != gtp_cause::REQUEST_ACCEPTED_PARTIALLY
        && session_cause != gtp_cause::NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE
        && session_cause != gtp_cause::NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY
    {
        log::error!("GTP Cause [VALUE:{session_cause}]");
        return HandlerResult::Error(session_cause);
    }

    // Update session with PGW TEIDs
    let mut sess = sess.clone();
    sess.pgw_s5c_teid = pgw_s5c_teid;
    ctx.sess_update(&sess);

    // Update UL tunnel with PGW S5U TEID
    if let Some(bearer) = ctx.default_bearer_in_sess(sess.id) {
        if let Some(mut ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
            ul_tunnel.remote_teid = pgw_s5u_teid;
            ctx.tunnel_update(&ul_tunnel);
            log::info!(
                "    SGW_S5U_TEID[{}] PGW_S5U_TEID[{}]",
                ul_tunnel.local_teid,
                ul_tunnel.remote_teid
            );
        }
    }

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

    // Need to send PFCP Session Modification Request
    HandlerResult::SendPfcp
}

/// Handle Modify Bearer Response from PGW
/// Port of sgwc_s5c_handle_modify_bearer_response
pub fn handle_modify_bearer_response(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    session_cause: u8,
    modify_action: ModifyAction,
) -> HandlerResult {
    log::info!("Modify Bearer Response");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context in TEID [Cause:{session_cause}]");
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

    // Check cause value
    if session_cause != gtp_cause::REQUEST_ACCEPTED {
        log::error!("GTP Cause [VALUE:{session_cause}]");
        return HandlerResult::Error(session_cause);
    }

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

    match modify_action {
        ModifyAction::PathSwitchRequest => {
            // Send Create Session Response to MME
            HandlerResult::ForwardToMme
        }
        ModifyAction::Normal => {
            // Forward Modify Bearer Response to MME
            HandlerResult::ForwardToMme
        }
    }
}

/// Handle Delete Session Response from PGW
/// Port of sgwc_s5c_handle_delete_session_response
pub fn handle_delete_session_response(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    session_cause: u8,
) -> HandlerResult {
    log::info!("Delete Session Response");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context in TEID [Cause:{session_cause}]");
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

    if session_cause != gtp_cause::REQUEST_ACCEPTED {
        log::error!("GTP Cause [VALUE:{session_cause}] - Ignored");
    }

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

    // Need to send PFCP Session Deletion Request
    HandlerResult::SendPfcp
}

/// Handle Create Bearer Request from PGW
/// Port of sgwc_s5c_handle_create_bearer_request
pub fn handle_create_bearer_request(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    linked_ebi: u8,
    bearer_ebi: u8,
    pgw_s5u_teid: u32,
) -> HandlerResult {
    log::info!("Create Bearer Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context in TEID");
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

    // Verify linked EBI exists
    if ctx.bearer_find_by_sess_ebi(sess.id, linked_ebi).is_none() {
        log::error!("No Linked Bearer [EBI:{linked_ebi}]");
        return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
    }

    // Add new bearer
    let bearer = match ctx.bearer_add(sess.id) {
        Some(mut b) => {
            b.ebi = bearer_ebi;
            ctx.bearer_update(&b);
            b
        }
        None => {
            log::error!("Failed to add bearer");
            return HandlerResult::Error(gtp_cause::NO_RESOURCES_AVAILABLE);
        }
    };

    // Update UL tunnel with PGW S5U TEID
    if let Some(mut ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
        ul_tunnel.remote_teid = pgw_s5u_teid;
        ctx.tunnel_update(&ul_tunnel);
        log::info!(
            "    SGW_S5U_TEID[{}] PGW_S5U_TEID[{}]",
            ul_tunnel.local_teid,
            ul_tunnel.remote_teid
        );
    }

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
    log::info!("    bearer[EBI={}]", bearer.ebi);

    // Need to send PFCP Session Modification Request
    HandlerResult::SendPfcp
}

/// Handle Update Bearer Request from PGW
/// Port of sgwc_s5c_handle_update_bearer_request
pub fn handle_update_bearer_request(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    bearer_ebi: u8,
) -> HandlerResult {
    log::info!("Update Bearer Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context in TEID");
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

    // Find bearer
    let bearer = match ctx.bearer_find_by_sess_ebi(sess.id, bearer_ebi) {
        Some(b) => b,
        None => {
            log::error!("No Context for EPS Bearer ID[{bearer_ebi}]");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!("    EBI[{}]", bearer.ebi);
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

    // Forward to MME
    HandlerResult::ForwardToMme
}

/// Handle Delete Bearer Request from PGW
/// Port of sgwc_s5c_handle_delete_bearer_request
pub fn handle_delete_bearer_request(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    bearer_ebi: u8,
    is_linked_bearer: bool,
) -> HandlerResult {
    log::info!("Delete Bearer Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context in TEID");
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

    // Find bearer
    let bearer = match ctx.bearer_find_by_sess_ebi(sess.id, bearer_ebi) {
        Some(b) => b,
        None => {
            log::error!("No Context for EPS Bearer ID[{bearer_ebi}]");
            return HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND);
        }
    };

    log::info!("    EBI[{}]", bearer.ebi);
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

    if is_linked_bearer {
        log::info!("    Linked Bearer - will delete session");
    }

    // Forward to MME
    HandlerResult::ForwardToMme
}

/// Handle Bearer Resource Failure Indication from PGW
/// Port of sgwc_s5c_handle_bearer_resource_failure_indication
pub fn handle_bearer_resource_failure_indication(
    sess: Option<&SgwcSess>,
    _xact_id: u64,
    _gtpbuf: &[u8],
    cause: u8,
) -> HandlerResult {
    log::info!("Bearer Resource Failure Indication");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context in TEID");
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

    log::warn!("Bearer Resource Failure [Cause:{cause}]");
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

    // Forward to MME
    HandlerResult::ForwardToMme
}

// ============================================================================
// Types
// ============================================================================

/// Modify action type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifyAction {
    Normal,
    PathSwitchRequest,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_response_no_sess() {
        let result = handle_create_session_response(
            None,
            1,
            &[],
            gtp_cause::REQUEST_ACCEPTED,
            100,
            200,
        );
        matches!(result, HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND));
    }

    #[test]
    fn test_delete_session_response_no_sess() {
        let result = handle_delete_session_response(
            None,
            1,
            &[],
            gtp_cause::REQUEST_ACCEPTED,
        );
        matches!(result, HandlerResult::Error(gtp_cause::CONTEXT_NOT_FOUND));
    }
}
