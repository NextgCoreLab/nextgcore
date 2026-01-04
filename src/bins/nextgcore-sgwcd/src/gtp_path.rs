//! SGWC GTP Path Management
//!
//! Port of src/sgwc/gtp-path.c - GTP-C path management for S11 and S5-C interfaces

use crate::context::{sgwc_self, SgwcBearer, SgwcSess};
use crate::s11_build::{self, GtpMessage};

// ============================================================================
// GTP Path State
// ============================================================================

/// GTP path state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpPathState {
    /// Path is idle
    Idle,
    /// Path is active
    Active,
    /// Path has failed
    Failed,
}

/// GTP node information
#[derive(Debug, Clone)]
pub struct GtpNode {
    pub id: u64,
    pub addr: String,
    pub port: u16,
    pub state: GtpPathState,
}

impl GtpNode {
    pub fn new(id: u64, addr: &str, port: u16) -> Self {
        Self {
            id,
            addr: addr.to_string(),
            port,
            state: GtpPathState::Idle,
        }
    }
}

// ============================================================================
// GTP Path Functions
// ============================================================================

/// Open GTP-C server sockets
/// Port of sgwc_gtp_open
pub fn gtp_open() -> Result<(), String> {
    log::info!("Opening GTP-C server sockets");

    // In actual implementation:
    // - Create UDP sockets for GTPv2-C
    // - Bind to configured addresses (S11 and S5-C)
    // - Register poll callbacks for receiving messages

    // For now, just log success
    log::info!("GTP-C server sockets opened successfully");
    Ok(())
}

/// Close GTP-C server sockets
/// Port of sgwc_gtp_close
pub fn gtp_close() {
    log::info!("Closing GTP-C server sockets");

    // In actual implementation:
    // - Close all GTP sockets
    // - Remove poll registrations
    // - Clean up GTP node lists
}

/// Send Create Session Response to MME
/// Port of sgwc_gtp_send_create_session_response
pub fn send_create_session_response(sess: &SgwcSess, xact_id: u64) -> Result<(), String> {
    let msg = s11_build::build_create_session_response(sess)
        .ok_or_else(|| "Failed to build Create Session Response".to_string())?;

    log::info!(
        "Sending Create Session Response: teid={}, xact_id={}",
        msg.teid,
        xact_id
    );

    // In actual implementation:
    // - Update GTP transaction with response
    // - Send message to MME
    // - Commit transaction

    send_gtp_message(&msg, xact_id)
}

/// Send Modify Bearer Response to MME
pub fn send_modify_bearer_response(
    sess: &SgwcSess,
    xact_id: u64,
    cause: u8,
) -> Result<(), String> {
    let msg = s11_build::build_modify_bearer_response(sess, cause)
        .ok_or_else(|| "Failed to build Modify Bearer Response".to_string())?;

    log::info!(
        "Sending Modify Bearer Response: teid={}, xact_id={}, cause={}",
        msg.teid,
        xact_id,
        cause
    );

    send_gtp_message(&msg, xact_id)
}

/// Send Delete Session Response to MME
pub fn send_delete_session_response(
    sess: &SgwcSess,
    xact_id: u64,
    cause: u8,
) -> Result<(), String> {
    let msg = s11_build::build_delete_session_response(sess, cause)
        .ok_or_else(|| "Failed to build Delete Session Response".to_string())?;

    log::info!(
        "Sending Delete Session Response: teid={}, xact_id={}, cause={}",
        msg.teid,
        xact_id,
        cause
    );

    send_gtp_message(&msg, xact_id)
}

/// Send Downlink Data Notification to MME
/// Port of sgwc_gtp_send_downlink_data_notification
pub fn send_downlink_data_notification(
    cause_value: u8,
    bearer: &SgwcBearer,
) -> Result<(), String> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx
        .ue_find_by_id(bearer.sgwc_ue_id)
        .ok_or_else(|| "UE not found".to_string())?;

    let msg = s11_build::build_downlink_data_notification(cause_value, bearer)
        .ok_or_else(|| "Failed to build Downlink Data Notification".to_string())?;

    log::info!(
        "Downlink Data Notification [bearer_id={}]",
        bearer.id
    );
    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );

    // In actual implementation:
    // - Create local GTP transaction
    // - Set timeout callback for bearer
    // - Send message to MME

    send_gtp_message(&msg, 0)
}

/// Send Release Access Bearers Response to MME
pub fn send_release_access_bearers_response(
    sgwc_ue_id: u64,
    xact_id: u64,
    cause: u8,
) -> Result<(), String> {
    let msg = s11_build::build_release_access_bearers_response(sgwc_ue_id, cause)
        .ok_or_else(|| "Failed to build Release Access Bearers Response".to_string())?;

    log::info!(
        "Sending Release Access Bearers Response: teid={}, xact_id={}, cause={}",
        msg.teid,
        xact_id,
        cause
    );

    send_gtp_message(&msg, xact_id)
}

/// Send Create Indirect Data Forwarding Tunnel Response to MME
pub fn send_create_indirect_data_forwarding_tunnel_response(
    sgwc_ue_id: u64,
    xact_id: u64,
    cause: u8,
) -> Result<(), String> {
    let msg = s11_build::build_create_indirect_data_forwarding_tunnel_response(sgwc_ue_id, cause)
        .ok_or_else(|| "Failed to build Create Indirect Data Forwarding Tunnel Response".to_string())?;

    log::info!(
        "Sending Create Indirect Data Forwarding Tunnel Response: teid={}, xact_id={}",
        msg.teid,
        xact_id
    );

    send_gtp_message(&msg, xact_id)
}

/// Send Delete Indirect Data Forwarding Tunnel Response to MME
pub fn send_delete_indirect_data_forwarding_tunnel_response(
    sgwc_ue_id: u64,
    xact_id: u64,
    cause: u8,
) -> Result<(), String> {
    let msg = s11_build::build_delete_indirect_data_forwarding_tunnel_response(sgwc_ue_id, cause)
        .ok_or_else(|| "Failed to build Delete Indirect Data Forwarding Tunnel Response".to_string())?;

    log::info!(
        "Sending Delete Indirect Data Forwarding Tunnel Response: teid={}, xact_id={}",
        msg.teid,
        xact_id
    );

    send_gtp_message(&msg, xact_id)
}

/// Send GTP error message
pub fn send_error_message(
    xact_id: u64,
    teid: u32,
    msg_type: u8,
    cause: u8,
) -> Result<(), String> {
    log::error!(
        "Sending GTP Error: type={}, teid={}, cause={}",
        msg_type,
        teid,
        cause
    );

    let mut msg = GtpMessage::new(msg_type, teid);
    msg.data.push(cause);

    send_gtp_message(&msg, xact_id)
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Send GTP message (internal)
fn send_gtp_message(msg: &GtpMessage, xact_id: u64) -> Result<(), String> {
    // In actual implementation:
    // - Encode message to buffer
    // - Update transaction
    // - Send via socket

    log::debug!(
        "GTP message sent: type={}, teid={}, xact_id={}, len={}",
        msg.msg_type,
        msg.teid,
        xact_id,
        msg.data.len()
    );

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_node_new() {
        let node = GtpNode::new(1, "127.0.0.1", 2123);
        assert_eq!(node.id, 1);
        assert_eq!(node.addr, "127.0.0.1");
        assert_eq!(node.port, 2123);
        assert_eq!(node.state, GtpPathState::Idle);
    }

    #[test]
    fn test_gtp_open_close() {
        assert!(gtp_open().is_ok());
        gtp_close();
    }
}
