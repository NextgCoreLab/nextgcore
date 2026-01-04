//! SGWC S11 Message Builder
//!
//! Port of src/sgwc/s11-build.c - Build GTPv2-C messages for S11 interface

use crate::context::{sgwc_self, SgwcBearer, SgwcSess};
use crate::s11_handler::gtp_cause;

// ============================================================================
// GTP Message Types
// ============================================================================

pub mod gtp_type {
    pub const CREATE_SESSION_RESPONSE: u8 = 33;
    pub const MODIFY_BEARER_RESPONSE: u8 = 35;
    pub const DELETE_SESSION_RESPONSE: u8 = 37;
    pub const DOWNLINK_DATA_NOTIFICATION: u8 = 176;
    pub const RELEASE_ACCESS_BEARERS_RESPONSE: u8 = 171;
    pub const CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE: u8 = 167;
    pub const DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE: u8 = 169;
}

// ============================================================================
// GTP F-TEID Interface Types
// ============================================================================

pub mod f_teid_interface {
    pub const S11_S4_SGW_GTP_C: u8 = 7;
    pub const S5_S8_SGW_GTP_C: u8 = 6;
    pub const S1_U_SGW_GTP_U: u8 = 1;
    pub const S5_S8_SGW_GTP_U: u8 = 4;
}

// ============================================================================
// Message Builder Result
// ============================================================================

/// Built GTP message
#[derive(Debug, Clone)]
pub struct GtpMessage {
    pub msg_type: u8,
    pub teid: u32,
    pub data: Vec<u8>,
}

impl GtpMessage {
    pub fn new(msg_type: u8, teid: u32) -> Self {
        Self {
            msg_type,
            teid,
            data: Vec::new(),
        }
    }
}

// ============================================================================
// S11 Message Builders
// ============================================================================

/// Build Create Session Response
/// Port of sgwc_s11_build_create_session_response
pub fn build_create_session_response(sess: &SgwcSess) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(gtp_type::CREATE_SESSION_RESPONSE, sgwc_ue.mme_s11_teid);

    // Build message data (simplified - actual implementation would use proper TLV encoding)
    let mut data = Vec::new();

    // Cause IE
    data.push(gtp_cause::REQUEST_ACCEPTED);

    // F-TEID for S11 SGW GTP-C
    data.extend_from_slice(&sgwc_ue.sgw_s11_teid.to_be_bytes());

    // F-TEID for S5/S8 SGW GTP-C
    data.extend_from_slice(&sess.sgw_s5c_teid.to_be_bytes());

    // PDN Address Allocation
    data.push(sess.paa.pdn_type);
    if let Some(ipv4) = sess.paa.ipv4_addr {
        data.extend_from_slice(&ipv4.octets());
    }

    // Bearer Contexts Created
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            // EBI
            data.push(bearer.ebi);

            // S1-U SGW F-TEID
            if let Some(dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
                data.extend_from_slice(&dl_tunnel.local_teid.to_be_bytes());
            }

            // S5/S8-U SGW F-TEID
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                data.extend_from_slice(&ul_tunnel.local_teid.to_be_bytes());
            }
        }
    }

    msg.data = data;
    log::debug!(
        "Built Create Session Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Modify Bearer Response
/// Port of sgwc_s11_build_modify_bearer_response (implicit in handler)
pub fn build_modify_bearer_response(sess: &SgwcSess, cause: u8) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(gtp_type::MODIFY_BEARER_RESPONSE, sgwc_ue.mme_s11_teid);

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    // Bearer Contexts Modified
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            // EBI
            data.push(bearer.ebi);
            // Cause
            data.push(gtp_cause::REQUEST_ACCEPTED);
        }
    }

    msg.data = data;
    log::debug!(
        "Built Modify Bearer Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Delete Session Response
/// Port of sgwc_s11_build_delete_session_response (implicit in handler)
pub fn build_delete_session_response(sess: &SgwcSess, cause: u8) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(gtp_type::DELETE_SESSION_RESPONSE, sgwc_ue.mme_s11_teid);

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    msg.data = data;
    log::debug!(
        "Built Delete Session Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Downlink Data Notification
/// Port of sgwc_s11_build_downlink_data_notification
pub fn build_downlink_data_notification(cause_value: u8, bearer: &SgwcBearer) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(bearer.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(gtp_type::DOWNLINK_DATA_NOTIFICATION, sgwc_ue.mme_s11_teid);

    let mut data = Vec::new();

    // Cause IE (if error indication)
    if cause_value != gtp_cause::REQUEST_ACCEPTED {
        data.push(cause_value);
    }

    // EPS Bearer ID
    data.push(bearer.ebi);

    // ARP (Allocation and Retention Priority) - simplified
    data.push(0); // Priority level
    data.push(0); // Pre-emption capability/vulnerability

    msg.data = data;

    log::info!(
        "Downlink Data Notification [bearer_id={}]",
        bearer.id
    );
    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );

    Some(msg)
}

/// Build Release Access Bearers Response
pub fn build_release_access_bearers_response(
    sgwc_ue_id: u64,
    cause: u8,
) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sgwc_ue_id)?;
    let mut msg = GtpMessage::new(
        gtp_type::RELEASE_ACCESS_BEARERS_RESPONSE,
        sgwc_ue.mme_s11_teid,
    );

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    msg.data = data;
    log::debug!(
        "Built Release Access Bearers Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Create Indirect Data Forwarding Tunnel Response
pub fn build_create_indirect_data_forwarding_tunnel_response(
    sgwc_ue_id: u64,
    cause: u8,
) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sgwc_ue_id)?;
    let mut msg = GtpMessage::new(
        gtp_type::CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE,
        sgwc_ue.mme_s11_teid,
    );

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    // Bearer Contexts would be added here with indirect tunnel TEIDs

    msg.data = data;
    log::debug!(
        "Built Create Indirect Data Forwarding Tunnel Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Delete Indirect Data Forwarding Tunnel Response
pub fn build_delete_indirect_data_forwarding_tunnel_response(
    sgwc_ue_id: u64,
    cause: u8,
) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sgwc_ue_id)?;
    let mut msg = GtpMessage::new(
        gtp_type::DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE,
        sgwc_ue.mme_s11_teid,
    );

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    msg.data = data;
    log::debug!(
        "Built Delete Indirect Data Forwarding Tunnel Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_message_new() {
        let msg = GtpMessage::new(gtp_type::CREATE_SESSION_RESPONSE, 12345);
        assert_eq!(msg.msg_type, gtp_type::CREATE_SESSION_RESPONSE);
        assert_eq!(msg.teid, 12345);
        assert!(msg.data.is_empty());
    }
}
