//! SGWC S11 Handler
//!
//! Port of src/sgwc/s11-handler.c - Handlers for GTPv2-C messages from MME

use crate::context::{gtp_interface, sgwc_self, SgwcSess, SgwcUe};
use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2IeType, Gtp2Message};
use std::net::Ipv4Addr;

// ============================================================================
// GTP Cause Values (from NEXTGCORE_GTP2_CAUSE_*)
// ============================================================================

pub mod gtp_cause {
    /// Request-initial cause: DDN triggered by Error Indication
    /// (TS 29.274 Section 8.4, value 6)
    pub const ERROR_INDICATION_FROM_RNC_ENODEB: u8 = 6;
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
    pub const SERVICE_NOT_SUPPORTED: u8 = 68;
    pub const REQUEST_REJECTED: u8 = 94;
    pub const REMOTE_PEER_NOT_RESPONDING: u8 = 100;
    pub const GRE_KEY_NOT_FOUND: u8 = 80;
}

// ============================================================================
// GTP Message Types (from NEXTGCORE_GTP2_*_TYPE)
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
        log::info!("OLD Session Release [IMSI:{},APN:{}]", ue.imsi_bcd, apn);
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

/// Handle Create Indirect Data Forwarding Tunnel Request from the MME
/// (TS 29.274 §7.2.18, TS 23.401 §5.5.1.2).
///
/// #48: this used to ignore `_gtpbuf` entirely -- the dispatcher passed `&[]` anyway --
/// allocate nothing, install nothing, and return `SendPfcp` so the dispatcher answered
/// `REQUEST_ACCEPTED` with no forwarding F-TEIDs. A false success: the MME was told the
/// indirect forwarding path existed, and no packet could traverse it.
///
/// Now it parses the request's Bearer Contexts, allocates a DL and a UL
/// data-forwarding tunnel per bearer (interface types 23 and 28, TS 29.274 §8.22), and
/// records the TARGET eNB's endpoints from the request as those tunnels' remote ends so
/// the SGW-U rules point somewhere real.
pub fn handle_create_indirect_data_forwarding_tunnel_request(
    sgwc_ue: Option<&SgwcUe>,
    _xact_id: u64,
    request: &Gtp2Message,
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

    let requested = parse_indirect_forwarding_request(request);
    if requested.is_empty() {
        // §7.2.18 makes Bearer Contexts mandatory, so a request with none is malformed
        // rather than a request for nothing. Answering `REQUEST_ACCEPTED` to it is what
        // this used to do for EVERY request.
        log::error!(
            "CIDFT Request carries no usable Bearer Context: rejecting rather than accepting a \
             forwarding path with no bearers"
        );
        return HandlerResult::Error(gtp_cause::MANDATORY_IE_MISSING);
    }

    let ctx = sgwc_self();
    let Some(gtpu_addr) = ctx.gtpu_address() else {
        log::error!("No SGW-U GTP-U address configured: cannot allocate forwarding tunnels");
        return HandlerResult::Error(gtp_cause::SYSTEM_FAILURE);
    };

    let mut allocated = 0usize;
    for req in &requested {
        let Some(bearer_id) = find_bearer_by_ebi(&ctx, sgwc_ue, req.ebi) else {
            log::warn!(
                "CIDFT Request names EBI {} which this UE does not have; skipped",
                req.ebi
            );
            continue;
        };

        for (interface_type, remote_teid, remote_ip) in [
            (
                gtp_interface::SGW_GTP_U_DL_DATA_FORWARDING,
                req.enb_dl_teid,
                req.enb_dl_ipv4,
            ),
            (
                gtp_interface::SGW_GTP_U_UL_DATA_FORWARDING,
                req.enb_ul_teid,
                req.enb_ul_ipv4,
            ),
        ] {
            // A direction the MME did not ask for gets no tunnel. Allocating one anyway
            // would put an endpoint in the response that the source eNB would then
            // forward to, with no rule at the far end.
            if remote_teid == 0 {
                continue;
            }
            let Some(mut tunnel) = ctx.tunnel_add(bearer_id, interface_type) else {
                log::error!("Failed to allocate a forwarding tunnel for EBI {}", req.ebi);
                continue;
            };
            tunnel.local_teid = ctx.next_gtpu_teid();
            tunnel.local_addr = Some(gtpu_addr);
            tunnel.pdr_id = Some(ctx.next_pdr_id());
            tunnel.far_id = Some(ctx.next_far_id());
            tunnel.remote_teid = remote_teid;
            if let Some(v4) = remote_ip {
                tunnel.remote_ip = crate::context::IpAddr {
                    ipv4: Some(Ipv4Addr::from(v4)),
                    ipv6: None,
                };
            }
            ctx.tunnel_update(&tunnel);
            allocated += 1;
        }
    }

    if allocated == 0 {
        log::error!("CIDFT Request allocated no forwarding tunnels: rejecting");
        return HandlerResult::Error(gtp_cause::SYSTEM_FAILURE);
    }

    log::info!("Allocated {allocated} indirect data-forwarding tunnel(s)");
    HandlerResult::SendPfcp
}

/// One bearer's forwarding request from a CIDFT Request Bearer Context
/// (TS 29.274 Table 7.2.18-2).
#[derive(Debug, Default)]
pub(crate) struct IndirectForwardingRequest {
    pub ebi: u8,
    /// Target eNodeB DL data-forwarding endpoint (instance 0, interface type 19)
    pub enb_dl_teid: u32,
    pub enb_dl_ipv4: Option<[u8; 4]>,
    /// Target eNodeB UL data-forwarding endpoint (instance 4, interface type 20)
    pub enb_ul_teid: u32,
    pub enb_ul_ipv4: Option<[u8; 4]>,
}

/// Parse the Bearer Contexts of a CIDFT Request (TS 29.274 Table 7.2.18-2).
///
/// Keyed by INSTANCE (eNodeB DL at 0, eNodeB UL at 4) and cross-checked against the
/// interface type (§8.22: 19 for eNodeB DL, 20 for eNodeB UL). Both, because an F-TEID
/// whose instance and interface type disagree is contradictory, and believing the
/// instance alone would install a forwarding rule in the wrong direction.
pub(crate) fn parse_indirect_forwarding_request(
    msg: &Gtp2Message,
) -> Vec<IndirectForwardingRequest> {
    /// eNodeB/gNodeB GTP-U interface for DL data forwarding (TS 29.274 §8.22).
    const ENB_DL_FORWARDING: u8 = 19;
    /// eNodeB GTP-U interface for UL data forwarding (TS 29.274 §8.22).
    const ENB_UL_FORWARDING: u8 = 20;

    msg.get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter_map(|ie| {
            let bc = Gtp2BearerContextIe::decode(&ie.value).ok()?;
            let ebi = bc.ebi().ok()?;
            let mut req = IndirectForwardingRequest {
                ebi,
                ..Default::default()
            };
            if let Ok(Some(ft)) = bc.fteid(0) {
                if ft.interface_type == ENB_DL_FORWARDING {
                    req.enb_dl_teid = ft.teid;
                    req.enb_dl_ipv4 = ft.ipv4_addr;
                } else {
                    log::debug!(
                        "CIDFT Request F-TEID at instance 0 has interface type {} (expected {} \
                         for eNodeB DL forwarding); ignored",
                        ft.interface_type,
                        ENB_DL_FORWARDING
                    );
                }
            }
            if let Ok(Some(ft)) = bc.fteid(4) {
                if ft.interface_type == ENB_UL_FORWARDING {
                    req.enb_ul_teid = ft.teid;
                    req.enb_ul_ipv4 = ft.ipv4_addr;
                } else {
                    log::debug!(
                        "CIDFT Request F-TEID at instance 4 has interface type {} (expected {} \
                         for eNodeB UL forwarding); ignored",
                        ft.interface_type,
                        ENB_UL_FORWARDING
                    );
                }
            }
            Some(req)
        })
        .collect()
}

/// Resolve a bearer of this UE by EPS Bearer ID.
fn find_bearer_by_ebi(ctx: &crate::context::SgwcContext, sgwc_ue: &SgwcUe, ebi: u8) -> Option<u64> {
    for sess_id in &sgwc_ue.sess_ids {
        let Some(sess) = ctx.sess_find_by_id(*sess_id) else {
            continue;
        };
        for bearer_id in &sess.bearer_ids {
            if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
                if bearer.ebi == ebi {
                    return Some(bearer.id);
                }
            }
        }
    }
    None
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
        let result = handle_create_session_request(None, 1, &[], &imsi, "internet", 12345, 5);
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

    /// Build a CIDFT Request the way `mmed` does: one Bearer Context carrying the target
    /// eNodeB's DL forwarding F-TEID at instance 0 (interface type 19) and its UL one at
    /// instance 4 (type 20). TS 29.274 Table 7.2.18-2.
    fn cidft_request(ebi: u8, dl_teid: u32, ul_teid: u32) -> Gtp2Message {
        use nextgcore_gtp::v2::header::{Gtp2Header, Gtp2MessageType};
        use nextgcore_gtp::v2::ie::Gtp2FTeidIe;

        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::CreateIndirectDataForwardingTunnelRequest as u8,
            0x1234,
            7,
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(ebi);
        bc.set_fteid(0, &Gtp2FTeidIe::new_ipv4(19, dl_teid, [10, 0, 0, 9]));
        bc.set_fteid(4, &Gtp2FTeidIe::new_ipv4(20, ul_teid, [10, 0, 0, 10]));
        msg.add_bearer_context(0, &bc);
        msg
    }

    /// #48 criterion 7 and criterion 8's third assertion: a CIDFT Request allocates real
    /// DL and UL forwarding tunnels, and the response carries their F-TEIDs.
    ///
    /// The handler used to ignore the request body, allocate nothing, and return
    /// `SendPfcp` so the dispatcher answered `REQUEST_ACCEPTED` with no F-TEIDs at all —
    /// a false success the MME could not distinguish from a working forwarding path. The
    /// pre-existing `test_indirect_tunnel_responses` asserted only that a Cause IE was
    /// present, so it passed against exactly that.
    #[test]
    fn cidft_request_allocates_forwarding_tunnels_and_the_response_carries_them() {
        use crate::s11_build::{
            build_create_indirect_data_forwarding_tunnel_response, f_teid_interface,
        };
        let ctx = sgwc_self();
        ctx.set_gtpu_address(Some(Ipv4Addr::new(10, 11, 0, 7)));

        // Unique IMSI: the context is a process global shared with sibling tests.
        let ue = ctx
            .ue_add(&[0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48])
            .unwrap();
        let sess = ctx.sess_add(ue.id, "internet").unwrap();
        let bearer = ctx.bearer_add(sess.id).unwrap();
        {
            let mut bearer = ctx.bearer_find_by_id(bearer.id).unwrap();
            bearer.ebi = 5;
            ctx.bearer_update(&bearer);
        }
        let ue = ctx.ue_find_by_id(ue.id).unwrap();

        let request = cidft_request(5, 0xDDDD, 0xEEEE);
        let result = handle_create_indirect_data_forwarding_tunnel_request(Some(&ue), 7, &request);
        assert!(
            matches!(result, HandlerResult::SendPfcp),
            "the request must be accepted and gated on the SGW-U, got {result:?}"
        );

        // Two forwarding tunnels exist, each pointing at the endpoint the MME gave.
        let bearer = ctx.bearer_find_by_id(bearer.id).unwrap();
        let mut dl = None;
        let mut ul = None;
        for tid in &bearer.tunnel_ids {
            let t = ctx.tunnel_find_by_id(*tid).unwrap();
            match t.interface_type {
                gtp_interface::SGW_GTP_U_DL_DATA_FORWARDING => dl = Some(t),
                gtp_interface::SGW_GTP_U_UL_DATA_FORWARDING => ul = Some(t),
                _ => {}
            }
        }
        let dl = dl.expect("a DL data-forwarding tunnel must be allocated");
        let ul = ul.expect("a UL data-forwarding tunnel must be allocated");
        assert_ne!(dl.local_teid, 0, "the SGW-U endpoint must be allocated");
        assert_eq!(dl.remote_teid, 0xDDDD, "the target eNB's DL endpoint");
        assert_eq!(ul.remote_teid, 0xEEEE, "the target eNB's UL endpoint");
        assert!(dl.pdr_id.is_some() && dl.far_id.is_some());

        // And the response carries them at the instances TS 29.274 Table 7.2.19-2
        // assigns, with the interface types NOTE 3 and NOTE 4 mandate.
        let response = build_create_indirect_data_forwarding_tunnel_response(
            ue.id,
            9,
            gtp_cause::REQUEST_ACCEPTED,
        )
        .unwrap();
        let bc_ie = response
            .get_ie(Gtp2IeType::BearerContext as u8, 0)
            .expect("the response must carry a Bearer Context, not a bare accept");
        let bc = Gtp2BearerContextIe::decode(&bc_ie.value).unwrap();
        assert_eq!(bc.ebi().unwrap(), 5);

        let dl_ft = bc
            .fteid(0)
            .unwrap()
            .expect("instance 0: S1-U SGW F-TEID for DL data forwarding");
        assert_eq!(
            dl_ft.interface_type,
            f_teid_interface::SGW_GTP_U_DL_DATA_FORWARDING,
            "Table 7.2.19-2 NOTE 3 fixes the DL interface type at 23"
        );
        assert_eq!(dl_ft.interface_type, 23);
        assert_eq!(dl_ft.teid, dl.local_teid);
        assert_eq!(dl_ft.ipv4_addr, Some([10, 11, 0, 7]));

        let ul_ft = bc.fteid(4).unwrap().expect(
            "instance 4: S1-U SGW F-TEID for UL data forwarding; instance 1 is an S12 \
                     DL endpoint and is where this used to go",
        );
        assert_eq!(
            ul_ft.interface_type,
            f_teid_interface::SGW_GTP_U_UL_DATA_FORWARDING,
            "Table 7.2.19-2 NOTE 4 fixes the UL interface type at 28"
        );
        assert_eq!(ul_ft.interface_type, 28);
        assert_eq!(ul_ft.teid, ul.local_teid);
        assert_ne!(
            ul_ft.teid, dl_ft.teid,
            "the two directions must have distinct endpoints"
        );
    }

    /// A CIDFT Request with no Bearer Context is malformed (§7.2.18 makes them
    /// mandatory), so it is REJECTED rather than accepted -- which is what the old
    /// body-ignoring handler did to every request, including this one.
    #[test]
    fn cidft_request_without_bearer_contexts_is_rejected() {
        use nextgcore_gtp::v2::header::{Gtp2Header, Gtp2MessageType};

        let ctx = sgwc_self();
        let ue = ctx
            .ue_add(&[0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49])
            .unwrap();
        let ue = ctx.ue_find_by_id(ue.id).unwrap();

        let empty = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::CreateIndirectDataForwardingTunnelRequest as u8,
            0x1234,
            7,
        ));
        let result = handle_create_indirect_data_forwarding_tunnel_request(Some(&ue), 7, &empty);
        assert!(
            matches!(
                result,
                HandlerResult::Error(gtp_cause::MANDATORY_IE_MISSING)
            ),
            "expected a mandatory-IE-missing rejection, got {result:?}"
        );
    }
}
