//! SGWC SXA Message Builder
//!
//! Port of src/sgwc/sxa-build.c - Build PFCP messages for SXA interface

use crate::context::{sgwc_self, SgwcSess, SgwcTunnel};

// ============================================================================
// PFCP Message Types
// ============================================================================

pub mod pfcp_type {
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

// ============================================================================
// PFCP IE Types
// ============================================================================

pub mod pfcp_ie {
    pub const CREATE_PDR: u16 = 1;
    pub const PDI: u16 = 2;
    pub const CREATE_FAR: u16 = 3;
    pub const FORWARDING_PARAMETERS: u16 = 4;
    pub const UPDATE_PDR: u16 = 9;
    pub const UPDATE_FAR: u16 = 10;
    pub const REMOVE_PDR: u16 = 15;
    pub const REMOVE_FAR: u16 = 16;
    pub const F_SEID: u16 = 57;
    pub const F_TEID: u16 = 21;
    pub const PDR_ID: u16 = 56;
    pub const FAR_ID: u16 = 108;
    pub const SOURCE_INTERFACE: u16 = 20;
    pub const DESTINATION_INTERFACE: u16 = 42;
    pub const OUTER_HEADER_CREATION: u16 = 84;
    pub const OUTER_HEADER_REMOVAL: u16 = 95;
    pub const APPLY_ACTION: u16 = 44;
}

// ============================================================================
// PFCP Apply Action Flags
// ============================================================================

pub mod apply_action {
    pub const DROP: u8 = 0x01;
    pub const FORW: u8 = 0x02;
    pub const BUFF: u8 = 0x04;
    pub const NOCP: u8 = 0x08;
    pub const DUPL: u8 = 0x10;
}

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
// SXA Message Builders
// ============================================================================

/// Build Session Establishment Request
/// Port of sgwc_sxa_build_session_establishment_request
pub fn build_session_establishment_request(sess: &SgwcSess) -> Option<PfcpMessage> {
    let ctx = sgwc_self();

    // SEID is 0 for establishment request (peer SEID not known yet)
    let mut msg = PfcpMessage::new(pfcp_type::SESSION_ESTABLISHMENT_REQUEST, 0);

    let mut data = Vec::new();

    // F-SEID IE (CP F-SEID)
    data.extend_from_slice(&sess.sgwc_sxa_seid.to_be_bytes());

    // Create PDRs and FARs for each bearer
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            // DL Tunnel (S5/S8 SGW GTP-U)
            if let Some(dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
                build_create_pdr(&mut data, &dl_tunnel, pfcp_interface::CORE);
                build_create_far(&mut data, &dl_tunnel, pfcp_interface::ACCESS);
            }

            // UL Tunnel (S1-U SGW GTP-U)
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                build_create_pdr(&mut data, &ul_tunnel, pfcp_interface::ACCESS);
                build_create_far(&mut data, &ul_tunnel, pfcp_interface::CORE);
            }
        }
    }

    msg.data = data;
    log::debug!(
        "Built Session Establishment Request: seid=0x{:x}, data_len={}",
        sess.sgwc_sxa_seid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Session Modification Request for bearer list
/// Port of sgwc_sxa_build_bearer_to_modify_list
pub fn build_bearer_to_modify_list(
    sess: &SgwcSess,
    modify_flags: u64,
    bearer_ids: &[u64],
) -> Option<PfcpMessage> {
    let ctx = sgwc_self();

    let mut msg = PfcpMessage::new(pfcp_type::SESSION_MODIFICATION_REQUEST, sess.sgwu_sxa_seid);

    let mut data = Vec::new();

    // Process each bearer to modify
    for bearer_id in bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            // DL Tunnel
            if let Some(dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
                if modify_flags & crate::sxa_handler::pfcp_modify::CREATE != 0 {
                    build_create_pdr(&mut data, &dl_tunnel, pfcp_interface::CORE);
                    build_create_far(&mut data, &dl_tunnel, pfcp_interface::ACCESS);
                } else if modify_flags & crate::sxa_handler::pfcp_modify::REMOVE != 0 {
                    build_remove_pdr(&mut data, dl_tunnel.pdr_id);
                    build_remove_far(&mut data, dl_tunnel.far_id);
                } else {
                    build_update_pdr(&mut data, &dl_tunnel);
                    build_update_far(&mut data, &dl_tunnel, modify_flags);
                }
            }

            // UL Tunnel
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                if modify_flags & crate::sxa_handler::pfcp_modify::CREATE != 0 {
                    build_create_pdr(&mut data, &ul_tunnel, pfcp_interface::ACCESS);
                    build_create_far(&mut data, &ul_tunnel, pfcp_interface::CORE);
                } else if modify_flags & crate::sxa_handler::pfcp_modify::REMOVE != 0 {
                    build_remove_pdr(&mut data, ul_tunnel.pdr_id);
                    build_remove_far(&mut data, ul_tunnel.far_id);
                } else {
                    build_update_pdr(&mut data, &ul_tunnel);
                    build_update_far(&mut data, &ul_tunnel, modify_flags);
                }
            }
        }
    }

    msg.data = data;
    log::debug!(
        "Built Session Modification Request: seid=0x{:x}, flags=0x{:x}, data_len={}",
        msg.seid,
        modify_flags,
        msg.data.len()
    );

    Some(msg)
}

/// Build Session Deletion Request
/// Port of sgwc_sxa_build_session_deletion_request
pub fn build_session_deletion_request(sess: &SgwcSess) -> Option<PfcpMessage> {
    let msg = PfcpMessage::new(pfcp_type::SESSION_DELETION_REQUEST, sess.sgwu_sxa_seid);

    // Session Deletion Request has no additional IEs beyond the header
    log::debug!(
        "Built Session Deletion Request: seid=0x{:x}",
        msg.seid
    );

    Some(msg)
}

/// Build Session Report Response
pub fn build_session_report_response(sess: &SgwcSess, cause: u8) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(pfcp_type::SESSION_REPORT_RESPONSE, sess.sgwu_sxa_seid);

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    msg.data = data;
    log::debug!(
        "Built Session Report Response: seid=0x{:x}, cause={}",
        msg.seid,
        cause
    );

    Some(msg)
}

// ============================================================================
// Helper Functions for Building IEs
// ============================================================================

/// Build Create PDR IE
fn build_create_pdr(data: &mut Vec<u8>, tunnel: &SgwcTunnel, src_interface: u8) {
    // PDR ID
    if let Some(pdr_id) = tunnel.pdr_id {
        data.extend_from_slice(&pdr_id.to_be_bytes());
    }

    // Source Interface
    data.push(src_interface);

    // F-TEID (local)
    data.extend_from_slice(&tunnel.local_teid.to_be_bytes());

    // Outer Header Removal (for incoming packets)
    data.push(0); // GTP-U/UDP/IP
}

/// Build Create FAR IE
fn build_create_far(data: &mut Vec<u8>, tunnel: &SgwcTunnel, dst_interface: u8) {
    // FAR ID
    if let Some(far_id) = tunnel.far_id {
        data.extend_from_slice(&far_id.to_be_bytes());
    }

    // Apply Action
    if tunnel.remote_teid != 0 {
        data.push(apply_action::FORW);
    } else {
        data.push(apply_action::BUFF | apply_action::NOCP);
    }

    // Destination Interface
    data.push(dst_interface);

    // Outer Header Creation (for outgoing packets)
    if tunnel.remote_teid != 0 {
        data.extend_from_slice(&tunnel.remote_teid.to_be_bytes());
        // Remote IP would be added here
    }
}

/// Build Update PDR IE
fn build_update_pdr(data: &mut Vec<u8>, tunnel: &SgwcTunnel) {
    // PDR ID
    if let Some(pdr_id) = tunnel.pdr_id {
        data.extend_from_slice(&pdr_id.to_be_bytes());
    }

    // Outer Header Removal
    data.push(0); // GTP-U/UDP/IP
}

/// Build Update FAR IE
fn build_update_far(data: &mut Vec<u8>, tunnel: &SgwcTunnel, modify_flags: u64) {
    // FAR ID
    if let Some(far_id) = tunnel.far_id {
        data.extend_from_slice(&far_id.to_be_bytes());
    }

    // Apply Action
    if modify_flags & crate::sxa_handler::pfcp_modify::ACTIVATE != 0 {
        data.push(apply_action::FORW);
    } else if modify_flags & crate::sxa_handler::pfcp_modify::DEACTIVATE != 0 {
        data.push(apply_action::BUFF | apply_action::NOCP);
    } else {
        data.push(apply_action::FORW);
    }

    // Outer Header Creation
    if tunnel.remote_teid != 0 {
        data.extend_from_slice(&tunnel.remote_teid.to_be_bytes());
    }
}

/// Build Remove PDR IE
fn build_remove_pdr(data: &mut Vec<u8>, pdr_id: Option<u16>) {
    if let Some(id) = pdr_id {
        data.extend_from_slice(&id.to_be_bytes());
    }
}

/// Build Remove FAR IE
fn build_remove_far(data: &mut Vec<u8>, far_id: Option<u32>) {
    if let Some(id) = far_id {
        data.extend_from_slice(&id.to_be_bytes());
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pfcp_message_new() {
        let msg = PfcpMessage::new(pfcp_type::SESSION_ESTABLISHMENT_REQUEST, 0x1234);
        assert_eq!(msg.msg_type, pfcp_type::SESSION_ESTABLISHMENT_REQUEST);
        assert_eq!(msg.seid, 0x1234);
        assert!(msg.data.is_empty());
    }
}
