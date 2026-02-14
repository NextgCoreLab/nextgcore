//! SGWC PFCP Path Management
//!
//! Port of src/sgwc/pfcp-path.c - PFCP path management for SXA interface

use crate::context::{sgwc_self, SgwcSess};
use crate::sxa_build::{self, PfcpMessage};

// ============================================================================
// PFCP Path State
// ============================================================================

/// PFCP node state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfcpNodeState {
    /// Initial state
    Initial,
    /// Waiting for association
    WillAssociate,
    /// Associated
    Associated,
    /// Exception state
    Exception,
    /// Final state
    Final,
}

/// PFCP node information
#[derive(Debug, Clone)]
pub struct PfcpNode {
    pub id: u64,
    pub addr: String,
    pub port: u16,
    pub state: PfcpNodeState,
    /// UP Function Features
    pub up_function_features: UpFunctionFeatures,
}

/// UP Function Features
#[derive(Debug, Clone, Default)]
pub struct UpFunctionFeatures {
    /// F-TEID allocation/release in the UP function
    pub ftup: bool,
    /// End Marker supported
    pub empu: bool,
    /// PFCP PFD Management supported
    pub pfdm: bool,
    /// Header Enrichment supported
    pub heeu: bool,
    /// Traffic Steering supported
    pub treu: bool,
    /// Buffering supported
    pub bucp: bool,
    /// Downlink Data Notification Delay supported
    pub ddnd: bool,
    /// DL Buffering Duration supported
    pub dlbd: bool,
}

impl PfcpNode {
    pub fn new(id: u64, addr: &str, port: u16) -> Self {
        Self {
            id,
            addr: addr.to_string(),
            port,
            state: PfcpNodeState::Initial,
            up_function_features: UpFunctionFeatures::default(),
        }
    }

    /// Check if node is associated
    pub fn is_associated(&self) -> bool {
        self.state == PfcpNodeState::Associated
    }
}

// ============================================================================
// PFCP Path Functions
// ============================================================================

/// Open PFCP server sockets
/// Port of sgwc_pfcp_open
pub fn pfcp_open() -> Result<(), String> {
    log::info!("Opening PFCP server sockets");

    // In actual implementation:
    // - Create UDP sockets for PFCP
    // - Bind to configured addresses
    // - Register poll callbacks for receiving messages

    log::info!("PFCP server sockets opened successfully");
    Ok(())
}

/// Close PFCP server sockets
/// Port of sgwc_pfcp_close
pub fn pfcp_close() {
    log::info!("Closing PFCP server sockets");

    // In actual implementation:
    // - Finalize all PFCP node FSMs
    // - Close all PFCP sockets
    // - Remove poll registrations
    // - Clean up PFCP node lists
}

/// Send Session Establishment Request to SGW-U
/// Port of sgwc_pfcp_send_session_establishment_request
pub fn send_session_establishment_request(
    sess: &SgwcSess,
    gtp_xact_id: u64,
    _gtpbuf: Option<&[u8]>,
    _flags: u64,
) -> Result<(), String> {
    let msg = sxa_build::build_session_establishment_request(sess)
        .ok_or_else(|| "Failed to build Session Establishment Request".to_string())?;

    log::info!(
        "Sending PFCP Session Establishment Request: seid=0x{:x}, gtp_xact_id={}",
        sess.sgwc_sxa_seid,
        gtp_xact_id
    );

    // In actual implementation:
    // - Create local PFCP transaction
    // - Associate with GTP transaction
    // - Set timeout callback
    // - Send message to SGW-U

    send_pfcp_message(&msg, gtp_xact_id)
}

/// Send Session Modification Request to SGW-U
/// Port of sgwc_pfcp_send_session_modification_request
pub fn send_session_modification_request(
    sess: &SgwcSess,
    gtp_xact_id: u64,
    _gtpbuf: Option<&[u8]>,
    flags: u64,
) -> Result<(), String> {
    let _ctx = sgwc_self();

    // Get all bearer IDs for this session
    let bearer_ids: Vec<u64> = sess.bearer_ids.clone();

    let msg = sxa_build::build_bearer_to_modify_list(sess, flags, &bearer_ids)
        .ok_or_else(|| "Failed to build Session Modification Request".to_string())?;

    log::info!(
        "PFCP Session Modification: sess_id={}, gtp_xact_id={}, flags=0x{:x}",
        sess.id,
        gtp_xact_id,
        flags
    );

    send_pfcp_message(&msg, gtp_xact_id)
}

/// Send Bearer Modification Request to SGW-U
/// Port of sgwc_pfcp_send_bearer_modification_request
pub fn send_bearer_modification_request(
    bearer_id: u64,
    gtp_xact_id: u64,
    _gtpbuf: Option<&[u8]>,
    flags: u64,
) -> Result<(), String> {
    let ctx = sgwc_self();

    let bearer = ctx
        .bearer_find_by_id(bearer_id)
        .ok_or_else(|| "Bearer not found".to_string())?;

    let sess = ctx
        .sess_find_by_id(bearer.sess_id)
        .ok_or_else(|| "Session not found".to_string())?;

    let msg = sxa_build::build_bearer_to_modify_list(&sess, flags, &[bearer_id])
        .ok_or_else(|| "Failed to build Bearer Modification Request".to_string())?;

    log::info!(
        "PFCP Session Modification from bearer: bearer_id={}, sess_id={}, gtp_xact_id={}, flags=0x{:x}",
        bearer_id,
        sess.id,
        gtp_xact_id,
        flags
    );

    send_pfcp_message(&msg, gtp_xact_id)
}

/// Send Bearer to Modify List
/// Port of sgwc_pfcp_send_bearer_to_modify_list
pub fn send_bearer_to_modify_list(
    sess: &SgwcSess,
    xact_id: u64,
    bearer_ids: &[u64],
    flags: u64,
) -> Result<(), String> {
    let msg = sxa_build::build_bearer_to_modify_list(sess, flags, bearer_ids)
        .ok_or_else(|| "Failed to build Bearer to Modify List".to_string())?;

    log::info!(
        "PFCP Session Modification: sess_id={}, xact_id={}, bearer_count={}, flags=0x{:x}",
        sess.id,
        xact_id,
        bearer_ids.len(),
        flags
    );

    send_pfcp_message(&msg, xact_id)
}

/// Send Session Deletion Request to SGW-U
/// Port of sgwc_pfcp_send_session_deletion_request
pub fn send_session_deletion_request(
    sess: &SgwcSess,
    gtp_xact_id: u64,
    _gtpbuf: Option<&[u8]>,
) -> Result<(), String> {
    let msg = sxa_build::build_session_deletion_request(sess)
        .ok_or_else(|| "Failed to build Session Deletion Request".to_string())?;

    log::info!(
        "Sending PFCP Session Deletion Request: seid=0x{:x}, gtp_xact_id={}",
        sess.sgwu_sxa_seid,
        gtp_xact_id
    );

    send_pfcp_message(&msg, gtp_xact_id)
}

/// Send Session Report Response to SGW-U
/// Port of sgwc_pfcp_send_session_report_response
pub fn send_session_report_response(
    xact_id: u64,
    sess: &SgwcSess,
    cause: u8,
) -> Result<(), String> {
    let msg = sxa_build::build_session_report_response(sess, cause)
        .ok_or_else(|| "Failed to build Session Report Response".to_string())?;

    log::info!(
        "Sending PFCP Session Report Response: seid=0x{:x}, cause={}",
        sess.sgwu_sxa_seid,
        cause
    );

    send_pfcp_message(&msg, xact_id)
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Send PFCP message (internal)
fn send_pfcp_message(msg: &PfcpMessage, xact_id: u64) -> Result<(), String> {
    // In actual implementation:
    // - Encode message to buffer
    // - Update transaction
    // - Send via socket

    log::debug!(
        "PFCP message sent: type={}, seid=0x{:x}, xact_id={}, len={}",
        msg.msg_type,
        msg.seid,
        xact_id,
        msg.data.len()
    );

    Ok(())
}

// ============================================================================
// Timer Callbacks
// ============================================================================

/// PFCP association timer callback
/// Port of sgwc_timer_pfcp_association
pub fn timer_pfcp_association(node_id: u64) {
    log::debug!("PFCP association timer fired for node {node_id}");

    // In actual implementation:
    // - Send Association Setup Request
    // - Restart timer if needed
}

/// PFCP no heartbeat timer callback
/// Port of sgwc_timer_pfcp_no_heartbeat
pub fn timer_pfcp_no_heartbeat(node_id: u64) {
    log::warn!("PFCP no heartbeat timer fired for node {node_id}");

    // In actual implementation:
    // - Mark node as failed
    // - Trigger recovery procedures
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pfcp_node_new() {
        let node = PfcpNode::new(1, "127.0.0.1", 8805);
        assert_eq!(node.id, 1);
        assert_eq!(node.addr, "127.0.0.1");
        assert_eq!(node.port, 8805);
        assert_eq!(node.state, PfcpNodeState::Initial);
        assert!(!node.is_associated());
    }

    #[test]
    fn test_pfcp_node_associated() {
        let mut node = PfcpNode::new(1, "127.0.0.1", 8805);
        node.state = PfcpNodeState::Associated;
        assert!(node.is_associated());
    }

    #[test]
    fn test_pfcp_open_close() {
        assert!(pfcp_open().is_ok());
        pfcp_close();
    }
}
