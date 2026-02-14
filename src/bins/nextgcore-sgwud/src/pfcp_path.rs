//! SGWU PFCP Path Management
//!
//! Port of src/sgwu/pfcp-path.c - PFCP path management for SXA interface

use crate::context::SgwuSess;
use crate::sxa_build::{self, CreatedPdr, PfcpMessage, UserPlaneReport};

// ============================================================================
// PFCP Message Types
// ============================================================================

pub mod pfcp_msg_type {
    pub const HEARTBEAT_REQUEST: u8 = 1;
    pub const HEARTBEAT_RESPONSE: u8 = 2;
    pub const ASSOCIATION_SETUP_REQUEST: u8 = 5;
    pub const ASSOCIATION_SETUP_RESPONSE: u8 = 6;
    pub const ASSOCIATION_UPDATE_REQUEST: u8 = 7;
    pub const ASSOCIATION_UPDATE_RESPONSE: u8 = 8;
    pub const ASSOCIATION_RELEASE_REQUEST: u8 = 9;
    pub const ASSOCIATION_RELEASE_RESPONSE: u8 = 10;
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_ESTABLISHMENT_RESPONSE: u8 = 51;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_MODIFICATION_RESPONSE: u8 = 53;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_DELETION_RESPONSE: u8 = 55;
    pub const SESSION_REPORT_REQUEST: u8 = 56;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

// ============================================================================
// PFCP Node State
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
    /// CP Function Features
    pub cp_function_features: CpFunctionFeatures,
    /// UP Function Features (local)
    pub up_function_features: UpFunctionFeatures,
}

/// CP Function Features (from SGWC)
#[derive(Debug, Clone, Default)]
pub struct CpFunctionFeatures {
    /// Load Control supported
    pub load: bool,
    /// Overload Control supported
    pub ovrl: bool,
}

/// UP Function Features (local SGWU capabilities)
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
            cp_function_features: CpFunctionFeatures::default(),
            up_function_features: UpFunctionFeatures::default(),
        }
    }

    /// Check if node is associated
    pub fn is_associated(&self) -> bool {
        self.state == PfcpNodeState::Associated
    }
}

// ============================================================================
// PFCP Transaction
// ============================================================================

/// PFCP transaction
#[derive(Debug, Clone)]
pub struct PfcpXact {
    pub id: u64,
    pub seq_num: u32,
    pub msg_type: u8,
    pub seid: u64,
}

impl PfcpXact {
    pub fn new(id: u64, seq_num: u32) -> Self {
        Self {
            id,
            seq_num,
            msg_type: 0,
            seid: 0,
        }
    }
}

// ============================================================================
// PFCP Path Functions
// ============================================================================

/// Open PFCP server sockets
/// Port of sgwu_pfcp_open
pub fn pfcp_open() -> Result<(), String> {
    log::info!("Opening PFCP server sockets");

    // In actual implementation:
    // - Create UDP sockets for PFCP (port 8805)
    // - Bind to configured addresses (IPv4 and IPv6)
    // - Register poll callbacks for receiving messages

    log::info!("PFCP server sockets opened successfully");
    Ok(())
}

/// Close PFCP server sockets
/// Port of sgwu_pfcp_close
pub fn pfcp_close() {
    log::info!("Closing PFCP server sockets");

    // In actual implementation:
    // - Finalize all PFCP node FSMs
    // - Close all PFCP sockets
    // - Remove poll registrations
    // - Clean up PFCP node lists
}

// ============================================================================
// PFCP Send Functions (SGWU -> SGWC)
// ============================================================================

/// Send Session Establishment Response to SGW-C
/// Port of sgwu_pfcp_send_session_establishment_response
pub fn send_session_establishment_response(
    xact: &PfcpXact,
    sess: &SgwuSess,
    created_pdrs: &[CreatedPdr],
) -> Result<(), String> {
    let msg = sxa_build::build_session_establishment_response(sess, created_pdrs)
        .ok_or_else(|| "Failed to build Session Establishment Response".to_string())?;

    log::info!(
        "Sending PFCP Session Establishment Response: cp_seid=0x{:x}, up_seid=0x{:x}",
        sess.sgwc_sxa_f_seid.seid,
        sess.sgwu_sxa_seid
    );

    send_pfcp_response(&msg, xact)
}

/// Send Session Modification Response to SGW-C
/// Port of sgwu_pfcp_send_session_modification_response
pub fn send_session_modification_response(
    xact: &PfcpXact,
    sess: &SgwuSess,
    created_pdrs: &[CreatedPdr],
) -> Result<(), String> {
    let msg = sxa_build::build_session_modification_response(sess, created_pdrs)
        .ok_or_else(|| "Failed to build Session Modification Response".to_string())?;

    log::info!(
        "Sending PFCP Session Modification Response: cp_seid=0x{:x}",
        sess.sgwc_sxa_f_seid.seid
    );

    send_pfcp_response(&msg, xact)
}

/// Send Session Deletion Response to SGW-C
/// Port of sgwu_pfcp_send_session_deletion_response
pub fn send_session_deletion_response(
    xact: &PfcpXact,
    sess: &SgwuSess,
) -> Result<(), String> {
    let msg = sxa_build::build_session_deletion_response(sess)
        .ok_or_else(|| "Failed to build Session Deletion Response".to_string())?;

    log::info!(
        "Sending PFCP Session Deletion Response: cp_seid=0x{:x}",
        sess.sgwc_sxa_f_seid.seid
    );

    send_pfcp_response(&msg, xact)
}

/// Send Session Report Request to SGW-C
/// Port of sgwu_pfcp_send_session_report_request
pub fn send_session_report_request(
    sess: &SgwuSess,
    report: &UserPlaneReport,
) -> Result<(), String> {
    let msg = sxa_build::build_session_report_request(sess, report)
        .ok_or_else(|| "Failed to build Session Report Request".to_string())?;

    log::info!(
        "Sending PFCP Session Report Request: cp_seid=0x{:x}, report_type=0x{:x}",
        sess.sgwc_sxa_f_seid.seid,
        report.report_type()
    );

    // In actual implementation:
    // - Create local PFCP transaction
    // - Set timeout callback
    // - Send message to SGWC

    send_pfcp_request(&msg, sess)
}

/// Send PFCP Error Message
pub fn send_error_message(
    xact: &PfcpXact,
    seid: u64,
    msg_type: u8,
    cause: u8,
    offending_ie: u8,
) -> Result<(), String> {
    log::error!(
        "Sending PFCP Error: type={msg_type}, seid=0x{seid:x}, cause={cause}, offending_ie={offending_ie}"
    );

    // Build error response based on message type
    let mut msg = PfcpMessage::new(msg_type, seid);
    
    // Add Cause IE
    msg.data.extend_from_slice(&19u16.to_be_bytes()); // Cause IE type
    msg.data.extend_from_slice(&1u16.to_be_bytes());  // Length
    msg.data.push(cause);

    // Add Offending IE if present
    if offending_ie != 0 {
        msg.data.extend_from_slice(&40u16.to_be_bytes()); // Offending IE type
        msg.data.extend_from_slice(&2u16.to_be_bytes());  // Length
        msg.data.extend_from_slice(&(offending_ie as u16).to_be_bytes());
    }

    send_pfcp_response(&msg, xact)
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Send PFCP response message (internal)
fn send_pfcp_response(msg: &PfcpMessage, xact: &PfcpXact) -> Result<(), String> {
    // In actual implementation:
    // - Update transaction with response
    // - Encode message to buffer
    // - Send via socket
    // - Commit transaction

    log::debug!(
        "PFCP response sent: type={}, seid=0x{:x}, xact_id={}",
        msg.msg_type,
        msg.seid,
        xact.id
    );

    Ok(())
}

/// Send PFCP request message (internal)
fn send_pfcp_request(msg: &PfcpMessage, sess: &SgwuSess) -> Result<(), String> {
    // In actual implementation:
    // - Create local transaction
    // - Encode message to buffer
    // - Send via socket

    log::debug!(
        "PFCP request sent: type={}, seid=0x{:x}, sess_id={}",
        msg.msg_type,
        msg.seid,
        sess.id
    );

    Ok(())
}

// ============================================================================
// PFCP Node FSM Functions
// ============================================================================

/// Initialize PFCP node FSM
/// Port of pfcp_node_fsm_init
pub fn pfcp_node_fsm_init(node: &mut PfcpNode, try_to_associate: bool) {
    log::debug!("Initializing PFCP node FSM for {}", node.addr);

    node.state = PfcpNodeState::Initial;

    if try_to_associate {
        // In actual implementation:
        // - Create association timer
        // - Start timer to trigger association setup
        node.state = PfcpNodeState::WillAssociate;
    }
}

/// Finalize PFCP node FSM
/// Port of pfcp_node_fsm_fini
pub fn pfcp_node_fsm_fini(node: &mut PfcpNode) {
    log::debug!("Finalizing PFCP node FSM for {}", node.addr);

    // In actual implementation:
    // - Delete association timer
    // - Clean up FSM state

    node.state = PfcpNodeState::Final;
}

// ============================================================================
// PFCP Receive Callback
// ============================================================================

/// PFCP receive callback result
#[derive(Debug)]
pub enum PfcpRecvResult {
    /// Message handled successfully
    Handled,
    /// Association setup completed
    AssociationSetup,
    /// Session message processed
    SessionMessage,
    /// Error occurred
    Error(String),
}

/// Handle received PFCP message
/// Port of pfcp_recv_cb
pub fn handle_pfcp_recv(
    data: &[u8],
    from_addr: &str,
) -> PfcpRecvResult {
    // In actual implementation:
    // 1. Parse PFCP message
    // 2. Extract node ID
    // 3. Find or create PFCP node
    // 4. Dispatch to FSM

    if data.len() < 8 {
        return PfcpRecvResult::Error("Message too short".to_string());
    }

    // Parse basic header
    let msg_type = data[1];

    log::debug!(
        "[RECV] PFCP message type={msg_type} from {from_addr}"
    );

    match msg_type {
        pfcp_msg_type::ASSOCIATION_SETUP_REQUEST |
        pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE => {
            PfcpRecvResult::AssociationSetup
        }
        pfcp_msg_type::SESSION_ESTABLISHMENT_REQUEST |
        pfcp_msg_type::SESSION_MODIFICATION_REQUEST |
        pfcp_msg_type::SESSION_DELETION_REQUEST |
        pfcp_msg_type::SESSION_REPORT_RESPONSE => {
            PfcpRecvResult::SessionMessage
        }
        pfcp_msg_type::HEARTBEAT_REQUEST => {
            log::debug!("Heartbeat Request received");
            PfcpRecvResult::Handled
        }
        pfcp_msg_type::HEARTBEAT_RESPONSE => {
            log::debug!("Heartbeat Response received");
            PfcpRecvResult::Handled
        }
        _ => {
            PfcpRecvResult::Error(format!("Unknown message type: {msg_type}"))
        }
    }
}

// ============================================================================
// Timer Callbacks
// ============================================================================

/// PFCP association timer callback
/// Port of sgwu_timer_association
pub fn timer_association(node_id: u64) {
    log::debug!("PFCP association timer fired for node {node_id}");

    // In actual implementation:
    // - Send Association Setup Request (if initiating)
    // - Or wait for Association Setup Request (if responding)
    // - Restart timer if needed
}

/// PFCP no heartbeat timer callback
/// Port of sgwu_timer_no_heartbeat
pub fn timer_no_heartbeat(node_id: u64) {
    log::warn!("PFCP no heartbeat timer fired for node {node_id}");

    // In actual implementation:
    // - Mark node as failed
    // - Remove all sessions for this node
    // - Trigger recovery procedures
}

/// Session report timeout callback
/// Port of sess_timeout
pub fn sess_timeout(xact_id: u64, sess_id: u64, msg_type: u8) {
    log::error!(
        "PFCP session timeout: xact_id={xact_id}, sess_id={sess_id}, type={msg_type}"
    );

    match msg_type {
        pfcp_msg_type::SESSION_REPORT_REQUEST => {
            log::error!("No PFCP session report response");
        }
        _ => {
            log::error!("Not implemented timeout for type: {msg_type}");
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::FSeid;
    use std::net::Ipv4Addr;

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
    fn test_pfcp_xact_new() {
        let xact = PfcpXact::new(1, 100);
        assert_eq!(xact.id, 1);
        assert_eq!(xact.seq_num, 100);
    }

    #[test]
    fn test_pfcp_open_close() {
        assert!(pfcp_open().is_ok());
        pfcp_close();
    }

    #[test]
    fn test_pfcp_node_fsm_init_fini() {
        let mut node = PfcpNode::new(1, "127.0.0.1", 8805);
        
        pfcp_node_fsm_init(&mut node, false);
        assert_eq!(node.state, PfcpNodeState::Initial);

        pfcp_node_fsm_init(&mut node, true);
        assert_eq!(node.state, PfcpNodeState::WillAssociate);

        pfcp_node_fsm_fini(&mut node);
        assert_eq!(node.state, PfcpNodeState::Final);
    }

    #[test]
    fn test_send_session_establishment_response() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let xact = PfcpXact::new(1, 1);
        let created_pdrs = vec![];

        let result = send_session_establishment_response(&xact, &sess, &created_pdrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_modification_response() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let xact = PfcpXact::new(1, 1);

        let result = send_session_modification_response(&xact, &sess, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_deletion_response() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let xact = PfcpXact::new(1, 1);

        let result = send_session_deletion_response(&xact, &sess);
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_report_request() {
        let sess = SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        let report = UserPlaneReport {
            downlink_data_report: true,
            pdr_id: Some(1),
            ..Default::default()
        };

        let result = send_session_report_request(&sess, &report);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_pfcp_recv_short() {
        let data = [0u8; 4];
        let result = handle_pfcp_recv(&data, "10.0.0.1");
        assert!(matches!(result, PfcpRecvResult::Error(_)));
    }

    #[test]
    fn test_handle_pfcp_recv_heartbeat() {
        let mut data = [0u8; 8];
        data[1] = pfcp_msg_type::HEARTBEAT_REQUEST;
        let result = handle_pfcp_recv(&data, "10.0.0.1");
        assert!(matches!(result, PfcpRecvResult::Handled));
    }

    #[test]
    fn test_handle_pfcp_recv_association() {
        let mut data = [0u8; 8];
        data[1] = pfcp_msg_type::ASSOCIATION_SETUP_REQUEST;
        let result = handle_pfcp_recv(&data, "10.0.0.1");
        assert!(matches!(result, PfcpRecvResult::AssociationSetup));
    }

    #[test]
    fn test_handle_pfcp_recv_session() {
        let mut data = [0u8; 8];
        data[1] = pfcp_msg_type::SESSION_ESTABLISHMENT_REQUEST;
        let result = handle_pfcp_recv(&data, "10.0.0.1");
        assert!(matches!(result, PfcpRecvResult::SessionMessage));
    }
}
