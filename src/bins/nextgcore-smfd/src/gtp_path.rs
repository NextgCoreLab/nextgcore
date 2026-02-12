//! GTP Path Management

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//!
//! Port of src/smf/gtp-path.c - GTP path management for SMF
//! Handles GTP-C and GTP-U path setup, teardown, and message sending

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::gtp_build::{
    gtp2_message_type, Gtp2Cause, Gtp2MessageBuilder,
    build_create_session_response, build_delete_session_response,
    build_modify_bearer_response, build_create_bearer_request,
    build_update_bearer_request, build_delete_bearer_request,
    build_error_message, build_echo_response,
};
use crate::context::{SmfSess, SmfBearer};

// ============================================================================
// Constants
// ============================================================================

/// Default GTP-C port
pub const GTPC_PORT: u16 = 2123;

/// Default GTP-U port
pub const GTPU_PORT: u16 = 2152;

/// GTP transaction timeout (seconds)
pub const GTP_XACT_TIMEOUT: u64 = 3;

/// GTP transaction retry count
pub const GTP_XACT_RETRY_COUNT: u32 = 3;

/// GTPv2-C version
pub const GTP2_VERSION: u8 = 2;

// ============================================================================
// GTP Transaction State
// ============================================================================

/// GTP transaction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum GtpXactState {
    /// Initial state
    #[default]
    Initial,
    /// Request sent, waiting for response
    WaitingResponse,
    /// Response received
    ResponseReceived,
    /// Transaction completed
    Completed,
    /// Transaction timed out
    TimedOut,
    /// Transaction failed
    Failed,
}



// ============================================================================
// GTP Transaction
// ============================================================================

/// GTP Transaction
#[derive(Debug)]
pub struct GtpXact {
    /// Transaction ID
    pub id: u64,
    /// Sequence number
    pub sequence: u32,
    /// Message type
    pub message_type: u8,
    /// Transaction state
    pub state: GtpXactState,
    /// Remote TEID
    pub remote_teid: u32,
    /// Remote address
    pub remote_addr: Option<SocketAddr>,
    /// Request buffer (for retransmission)
    pub request_buf: Option<Vec<u8>>,
    /// Response buffer
    pub response_buf: Option<Vec<u8>>,
    /// Associated session ID
    pub sess_id: Option<u64>,
    /// Associated bearer ID
    pub bearer_id: Option<u64>,
    /// Creation time
    pub created_at: Instant,
    /// Last sent time
    pub last_sent_at: Option<Instant>,
    /// Retry count
    pub retry_count: u32,
    /// Update flags (for modify bearer)
    pub update_flags: u64,
    /// Associated GTP buffer (for forwarding)
    pub gtpbuf: Option<Vec<u8>>,
}

impl GtpXact {
    /// Create a new GTP transaction
    pub fn new(id: u64, sequence: u32, message_type: u8) -> Self {
        Self {
            id,
            sequence,
            message_type,
            state: GtpXactState::Initial,
            remote_teid: 0,
            remote_addr: None,
            request_buf: None,
            response_buf: None,
            sess_id: None,
            bearer_id: None,
            created_at: Instant::now(),
            last_sent_at: None,
            retry_count: 0,
            update_flags: 0,
            gtpbuf: None,
        }
    }

    /// Check if transaction has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        if let Some(last_sent) = self.last_sent_at {
            last_sent.elapsed() > timeout
        } else {
            self.created_at.elapsed() > timeout
        }
    }

    /// Check if transaction can be retried
    pub fn can_retry(&self) -> bool {
        self.retry_count < GTP_XACT_RETRY_COUNT
    }

    /// Increment retry count
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
        self.last_sent_at = Some(Instant::now());
    }

    /// Mark as completed
    pub fn complete(&mut self) {
        self.state = GtpXactState::Completed;
    }

    /// Mark as failed
    pub fn fail(&mut self) {
        self.state = GtpXactState::Failed;
    }

    /// Mark as timed out
    pub fn timeout(&mut self) {
        self.state = GtpXactState::TimedOut;
    }
}

// ============================================================================
// GTP Node
// ============================================================================

/// GTP Node (peer)
#[derive(Debug)]
pub struct GtpNode {
    /// Node ID
    pub id: u64,
    /// IPv4 address
    pub addr: Option<Ipv4Addr>,
    /// IPv6 address
    pub addr6: Option<Ipv6Addr>,
    /// Port
    pub port: u16,
    /// Remote TEID
    pub remote_teid: u32,
    /// Recovery value
    pub recovery: u8,
    /// Last echo time
    pub last_echo: Option<Instant>,
    /// Node is reachable
    pub reachable: bool,
}

impl GtpNode {
    /// Create a new GTP node with IPv4 address
    pub fn new_ipv4(id: u64, addr: Ipv4Addr, port: u16) -> Self {
        Self {
            id,
            addr: Some(addr),
            addr6: None,
            port,
            remote_teid: 0,
            recovery: 0,
            last_echo: None,
            reachable: true,
        }
    }

    /// Create a new GTP node with IPv6 address
    pub fn new_ipv6(id: u64, addr: Ipv6Addr, port: u16) -> Self {
        Self {
            id,
            addr: None,
            addr6: Some(addr),
            port,
            remote_teid: 0,
            recovery: 0,
            last_echo: None,
            reachable: true,
        }
    }

    /// Get socket address
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        if let Some(addr) = self.addr {
            Some(SocketAddr::new(addr.into(), self.port))
        } else { self.addr6.map(|addr| SocketAddr::new(addr.into(), self.port)) }
    }

    /// Update echo time
    pub fn update_echo(&mut self) {
        self.last_echo = Some(Instant::now());
        self.reachable = true;
    }

    /// Mark as unreachable
    pub fn mark_unreachable(&mut self) {
        self.reachable = false;
    }
}


// ============================================================================
// GTP Path Manager
// ============================================================================

/// GTP Path Manager
pub struct GtpPathManager {
    /// Local IPv4 address for GTP-C
    pub gtpc_addr: Option<Ipv4Addr>,
    /// Local IPv6 address for GTP-C
    pub gtpc_addr6: Option<Ipv6Addr>,
    /// Local IPv4 address for GTP-U
    pub gtpu_addr: Option<Ipv4Addr>,
    /// Local IPv6 address for GTP-U
    pub gtpu_addr6: Option<Ipv6Addr>,
    /// GTP nodes (peers)
    nodes: RwLock<HashMap<u64, GtpNode>>,
    /// Active transactions
    transactions: RwLock<HashMap<u64, GtpXact>>,
    /// Sequence number generator
    sequence_generator: AtomicU32,
    /// Transaction ID generator
    xact_id_generator: AtomicU32,
    /// Node ID generator
    node_id_generator: AtomicU32,
    /// Recovery counter
    pub recovery: u8,
}

impl GtpPathManager {
    /// Create a new GTP path manager
    pub fn new() -> Self {
        Self {
            gtpc_addr: None,
            gtpc_addr6: None,
            gtpu_addr: None,
            gtpu_addr6: None,
            nodes: RwLock::new(HashMap::new()),
            transactions: RwLock::new(HashMap::new()),
            sequence_generator: AtomicU32::new(1),
            xact_id_generator: AtomicU32::new(1),
            node_id_generator: AtomicU32::new(1),
            recovery: 0,
        }
    }

    /// Set local GTP-C addresses
    pub fn set_gtpc_addr(&mut self, addr: Option<Ipv4Addr>, addr6: Option<Ipv6Addr>) {
        self.gtpc_addr = addr;
        self.gtpc_addr6 = addr6;
    }

    /// Set local GTP-U addresses
    pub fn set_gtpu_addr(&mut self, addr: Option<Ipv4Addr>, addr6: Option<Ipv6Addr>) {
        self.gtpu_addr = addr;
        self.gtpu_addr6 = addr6;
    }

    /// Generate next sequence number
    pub fn next_sequence(&self) -> u32 {
        self.sequence_generator.fetch_add(1, Ordering::SeqCst)
    }

    /// Generate next transaction ID
    fn next_xact_id(&self) -> u64 {
        self.xact_id_generator.fetch_add(1, Ordering::SeqCst) as u64
    }

    /// Generate next node ID
    fn next_node_id(&self) -> u64 {
        self.node_id_generator.fetch_add(1, Ordering::SeqCst) as u64
    }

    // ========================================================================
    // Node Management
    // ========================================================================

    /// Add a GTP node
    pub fn add_node_ipv4(&self, addr: Ipv4Addr, port: u16) -> u64 {
        let id = self.next_node_id();
        let node = GtpNode::new_ipv4(id, addr, port);
        
        if let Ok(mut nodes) = self.nodes.write() {
            nodes.insert(id, node);
        }
        
        id
    }

    /// Add a GTP node with IPv6
    pub fn add_node_ipv6(&self, addr: Ipv6Addr, port: u16) -> u64 {
        let id = self.next_node_id();
        let node = GtpNode::new_ipv6(id, addr, port);
        
        if let Ok(mut nodes) = self.nodes.write() {
            nodes.insert(id, node);
        }
        
        id
    }

    /// Remove a GTP node
    pub fn remove_node(&self, id: u64) -> Option<GtpNode> {
        if let Ok(mut nodes) = self.nodes.write() {
            nodes.remove(&id)
        } else {
            None
        }
    }

    /// Get a GTP node
    pub fn get_node(&self, id: u64) -> Option<GtpNode> {
        if let Ok(nodes) = self.nodes.read() {
            nodes.get(&id).cloned()
        } else {
            None
        }
    }

    /// Find node by IPv4 address
    pub fn find_node_by_ipv4(&self, addr: Ipv4Addr) -> Option<u64> {
        if let Ok(nodes) = self.nodes.read() {
            for (id, node) in nodes.iter() {
                if node.addr == Some(addr) {
                    return Some(*id);
                }
            }
        }
        None
    }

    // ========================================================================
    // Transaction Management
    // ========================================================================

    /// Create a new local transaction (for sending requests)
    pub fn create_local_xact(&self, message_type: u8, sess_id: Option<u64>) -> u64 {
        let id = self.next_xact_id();
        let sequence = self.next_sequence();
        let mut xact = GtpXact::new(id, sequence, message_type);
        xact.sess_id = sess_id;
        xact.state = GtpXactState::Initial;
        
        if let Ok(mut transactions) = self.transactions.write() {
            transactions.insert(id, xact);
        }
        
        id
    }

    /// Create a new remote transaction (for receiving requests)
    pub fn create_remote_xact(&self, sequence: u32, message_type: u8) -> u64 {
        let id = self.next_xact_id();
        let mut xact = GtpXact::new(id, sequence, message_type);
        xact.state = GtpXactState::WaitingResponse;
        
        if let Ok(mut transactions) = self.transactions.write() {
            transactions.insert(id, xact);
        }
        
        id
    }

    /// Get a transaction
    pub fn get_xact(&self, id: u64) -> Option<GtpXact> {
        if let Ok(transactions) = self.transactions.read() {
            transactions.get(&id).cloned()
        } else {
            None
        }
    }

    /// Find transaction by sequence number
    pub fn find_xact_by_sequence(&self, sequence: u32) -> Option<u64> {
        if let Ok(transactions) = self.transactions.read() {
            for (id, xact) in transactions.iter() {
                if xact.sequence == sequence {
                    return Some(*id);
                }
            }
        }
        None
    }

    /// Update transaction state
    pub fn update_xact_state(&self, id: u64, state: GtpXactState) {
        if let Ok(mut transactions) = self.transactions.write() {
            if let Some(xact) = transactions.get_mut(&id) {
                xact.state = state;
            }
        }
    }

    /// Set transaction request buffer
    pub fn set_xact_request(&self, id: u64, buf: Vec<u8>) {
        if let Ok(mut transactions) = self.transactions.write() {
            if let Some(xact) = transactions.get_mut(&id) {
                xact.request_buf = Some(buf);
                xact.last_sent_at = Some(Instant::now());
                xact.state = GtpXactState::WaitingResponse;
            }
        }
    }

    /// Set transaction response buffer
    pub fn set_xact_response(&self, id: u64, buf: Vec<u8>) {
        if let Ok(mut transactions) = self.transactions.write() {
            if let Some(xact) = transactions.get_mut(&id) {
                xact.response_buf = Some(buf);
                xact.state = GtpXactState::ResponseReceived;
            }
        }
    }

    /// Complete and remove transaction
    pub fn commit_xact(&self, id: u64) -> Option<GtpXact> {
        if let Ok(mut transactions) = self.transactions.write() {
            if let Some(mut xact) = transactions.remove(&id) {
                xact.complete();
                return Some(xact);
            }
        }
        None
    }

    /// Remove transaction
    pub fn remove_xact(&self, id: u64) -> Option<GtpXact> {
        if let Ok(mut transactions) = self.transactions.write() {
            transactions.remove(&id)
        } else {
            None
        }
    }

    /// Get timed out transactions
    pub fn get_timed_out_xacts(&self, timeout: Duration) -> Vec<u64> {
        let mut timed_out = Vec::new();
        
        if let Ok(transactions) = self.transactions.read() {
            for (id, xact) in transactions.iter() {
                if xact.is_timed_out(timeout) && xact.state == GtpXactState::WaitingResponse {
                    timed_out.push(*id);
                }
            }
        }
        
        timed_out
    }

    /// Handle transaction timeout
    pub fn handle_xact_timeout(&self, id: u64) -> bool {
        if let Ok(mut transactions) = self.transactions.write() {
            if let Some(xact) = transactions.get_mut(&id) {
                if xact.can_retry() {
                    xact.increment_retry();
                    return true; // Should retry
                } else {
                    xact.timeout();
                    return false; // No more retries
                }
            }
        }
        false
    }

    /// Clean up completed transactions
    pub fn cleanup_completed(&self) {
        if let Ok(mut transactions) = self.transactions.write() {
            transactions.retain(|_, xact| {
                xact.state != GtpXactState::Completed && 
                xact.state != GtpXactState::Failed &&
                xact.state != GtpXactState::TimedOut
            });
        }
    }
}

impl Default for GtpPathManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for GtpNode {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            addr: self.addr,
            addr6: self.addr6,
            port: self.port,
            remote_teid: self.remote_teid,
            recovery: self.recovery,
            last_echo: self.last_echo,
            reachable: self.reachable,
        }
    }
}

impl Clone for GtpXact {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            sequence: self.sequence,
            message_type: self.message_type,
            state: self.state,
            remote_teid: self.remote_teid,
            remote_addr: self.remote_addr,
            request_buf: self.request_buf.clone(),
            response_buf: self.response_buf.clone(),
            sess_id: self.sess_id,
            bearer_id: self.bearer_id,
            created_at: self.created_at,
            last_sent_at: self.last_sent_at,
            retry_count: self.retry_count,
            update_flags: self.update_flags,
            gtpbuf: self.gtpbuf.clone(),
        }
    }
}


// ============================================================================
// Message Sending Functions
// ============================================================================

/// GTP send result
#[derive(Debug)]
pub enum GtpSendResult {
    /// Message sent successfully
    Success { xact_id: u64, message: Vec<u8> },
    /// Failed to send
    Failed(String),
}

impl GtpPathManager {
    /// Send Create Session Response
    pub fn send_create_session_response(
        &self,
        xact_id: u64,
        sess: &SmfSess,
        bearers: &[SmfBearer],
        pco: Option<&[u8]>,
        apco: Option<&[u8]>,
        epco: Option<&[u8]>,
        include_ambr: bool,
        include_bearer_qos: bool,
    ) -> GtpSendResult {
        let message = build_create_session_response(
            sess,
            bearers,
            self.gtpc_addr,
            self.gtpc_addr6,
            pco,
            apco,
            epco,
            include_ambr,
            include_bearer_qos,
        );

        self.set_xact_response(xact_id, message.clone());
        
        GtpSendResult::Success { xact_id, message }
    }

    /// Send Delete Session Response
    pub fn send_delete_session_response(
        &self,
        xact_id: u64,
        teid: u32,
        pco: Option<&[u8]>,
        epco: Option<&[u8]>,
    ) -> GtpSendResult {
        let message = build_delete_session_response(teid, pco, epco);
        
        self.set_xact_response(xact_id, message.clone());
        
        GtpSendResult::Success { xact_id, message }
    }

    /// Send Modify Bearer Response
    pub fn send_modify_bearer_response(
        &self,
        xact_id: u64,
        sess: &SmfSess,
        bearers: &[SmfBearer],
        msisdn: Option<&[u8]>,
        sgw_relocation: bool,
    ) -> GtpSendResult {
        let message = build_modify_bearer_response(sess, bearers, msisdn, sgw_relocation);
        
        self.set_xact_response(xact_id, message.clone());
        
        GtpSendResult::Success { xact_id, message }
    }

    /// Send Create Bearer Request
    pub fn send_create_bearer_request(
        &self,
        sess: &SmfSess,
        bearer: &SmfBearer,
        linked_ebi: u8,
        tft: Option<&[u8]>,
    ) -> GtpSendResult {
        let xact_id = self.create_local_xact(
            gtp2_message_type::CREATE_BEARER_REQUEST,
            Some(sess.id),
        );

        let message = build_create_bearer_request(sess, bearer, linked_ebi, tft);
        
        self.set_xact_request(xact_id, message.clone());
        
        // Store bearer ID in transaction
        if let Ok(mut transactions) = self.transactions.write() {
            if let Some(xact) = transactions.get_mut(&xact_id) {
                xact.bearer_id = Some(bearer.id);
            }
        }
        
        GtpSendResult::Success { xact_id, message }
    }

    /// Send Update Bearer Request
    pub fn send_update_bearer_request(
        &self,
        sess: &SmfSess,
        bearer: &SmfBearer,
        pti: Option<u8>,
        tft: Option<&[u8]>,
        include_qos: bool,
        update_flags: u64,
    ) -> GtpSendResult {
        let xact_id = self.create_local_xact(
            gtp2_message_type::UPDATE_BEARER_REQUEST,
            Some(sess.id),
        );

        let message = build_update_bearer_request(sess, bearer, pti, tft, include_qos);
        
        self.set_xact_request(xact_id, message.clone());
        
        // Store bearer ID and update flags in transaction
        if let Ok(mut transactions) = self.transactions.write() {
            if let Some(xact) = transactions.get_mut(&xact_id) {
                xact.bearer_id = Some(bearer.id);
                xact.update_flags = update_flags;
            }
        }
        
        GtpSendResult::Success { xact_id, message }
    }

    /// Send Delete Bearer Request
    pub fn send_delete_bearer_request(
        &self,
        sess: &SmfSess,
        bearer_ebi: u8,
        linked_ebi: u8,
        pti: Option<u8>,
        cause: Option<Gtp2Cause>,
        bearer_id: u64,
    ) -> GtpSendResult {
        let xact_id = self.create_local_xact(
            gtp2_message_type::DELETE_BEARER_REQUEST,
            Some(sess.id),
        );

        let message = build_delete_bearer_request(sess, bearer_ebi, linked_ebi, pti, cause);
        
        self.set_xact_request(xact_id, message.clone());
        
        // Store bearer ID in transaction
        if let Ok(mut transactions) = self.transactions.write() {
            if let Some(xact) = transactions.get_mut(&xact_id) {
                xact.bearer_id = Some(bearer_id);
            }
        }
        
        GtpSendResult::Success { xact_id, message }
    }

    /// Send Error Message
    pub fn send_error_message(
        &self,
        xact_id: u64,
        message_type: u8,
        teid: u32,
        cause: Gtp2Cause,
    ) -> GtpSendResult {
        let message = build_error_message(message_type, teid, cause);
        
        self.set_xact_response(xact_id, message.clone());
        
        GtpSendResult::Success { xact_id, message }
    }

    /// Send Echo Response
    pub fn send_echo_response(&self, xact_id: u64) -> GtpSendResult {
        let message = build_echo_response(self.recovery);
        
        self.set_xact_response(xact_id, message.clone());
        
        GtpSendResult::Success { xact_id, message }
    }
}


// ============================================================================
// Update Flags
// ============================================================================

/// GTP modify flags
pub mod gtp_modify_flags {
    /// TFT update
    pub const TFT_UPDATE: u64 = 0x01;
    /// QoS update
    pub const QOS_UPDATE: u64 = 0x02;
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_xact_new() {
        let xact = GtpXact::new(1, 100, gtp2_message_type::CREATE_SESSION_REQUEST);
        
        assert_eq!(xact.id, 1);
        assert_eq!(xact.sequence, 100);
        assert_eq!(xact.message_type, gtp2_message_type::CREATE_SESSION_REQUEST);
        assert_eq!(xact.state, GtpXactState::Initial);
        assert_eq!(xact.retry_count, 0);
    }

    #[test]
    fn test_gtp_xact_timeout() {
        let xact = GtpXact::new(1, 100, gtp2_message_type::CREATE_SESSION_REQUEST);
        
        // Should not be timed out immediately
        assert!(!xact.is_timed_out(Duration::from_secs(1)));
    }

    #[test]
    fn test_gtp_xact_retry() {
        let mut xact = GtpXact::new(1, 100, gtp2_message_type::CREATE_SESSION_REQUEST);
        
        assert!(xact.can_retry());
        
        for _ in 0..GTP_XACT_RETRY_COUNT {
            xact.increment_retry();
        }
        
        assert!(!xact.can_retry());
        assert_eq!(xact.retry_count, GTP_XACT_RETRY_COUNT);
    }

    #[test]
    fn test_gtp_node_ipv4() {
        let node = GtpNode::new_ipv4(1, Ipv4Addr::new(192, 168, 1, 1), GTPC_PORT);
        
        assert_eq!(node.id, 1);
        assert_eq!(node.addr, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(node.port, GTPC_PORT);
        assert!(node.reachable);
        
        let socket_addr = node.socket_addr().unwrap();
        assert_eq!(socket_addr.port(), GTPC_PORT);
    }

    #[test]
    fn test_gtp_node_ipv6() {
        let node = GtpNode::new_ipv6(1, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), GTPC_PORT);
        
        assert_eq!(node.id, 1);
        assert!(node.addr.is_none());
        assert!(node.addr6.is_some());
        assert_eq!(node.port, GTPC_PORT);
    }

    #[test]
    fn test_gtp_node_echo() {
        let mut node = GtpNode::new_ipv4(1, Ipv4Addr::new(192, 168, 1, 1), GTPC_PORT);
        
        assert!(node.last_echo.is_none());
        
        node.update_echo();
        
        assert!(node.last_echo.is_some());
        assert!(node.reachable);
        
        node.mark_unreachable();
        assert!(!node.reachable);
    }

    #[test]
    fn test_gtp_path_manager_new() {
        let manager = GtpPathManager::new();
        
        assert!(manager.gtpc_addr.is_none());
        assert!(manager.gtpc_addr6.is_none());
        assert_eq!(manager.recovery, 0);
    }

    #[test]
    fn test_gtp_path_manager_set_addr() {
        let mut manager = GtpPathManager::new();
        
        manager.set_gtpc_addr(Some(Ipv4Addr::new(192, 168, 1, 1)), None);
        
        assert_eq!(manager.gtpc_addr, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(manager.gtpc_addr6.is_none());
    }

    #[test]
    fn test_gtp_path_manager_sequence() {
        let manager = GtpPathManager::new();
        
        let seq1 = manager.next_sequence();
        let seq2 = manager.next_sequence();
        let seq3 = manager.next_sequence();
        
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
    }

    #[test]
    fn test_gtp_path_manager_add_node() {
        let manager = GtpPathManager::new();
        
        let id = manager.add_node_ipv4(Ipv4Addr::new(192, 168, 1, 1), GTPC_PORT);
        
        assert!(id > 0);
        
        let node = manager.get_node(id);
        assert!(node.is_some());
        
        let node = node.unwrap();
        assert_eq!(node.addr, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_gtp_path_manager_remove_node() {
        let manager = GtpPathManager::new();
        
        let id = manager.add_node_ipv4(Ipv4Addr::new(192, 168, 1, 1), GTPC_PORT);
        
        let removed = manager.remove_node(id);
        assert!(removed.is_some());
        
        let node = manager.get_node(id);
        assert!(node.is_none());
    }

    #[test]
    fn test_gtp_path_manager_find_node() {
        let manager = GtpPathManager::new();
        
        let id = manager.add_node_ipv4(Ipv4Addr::new(192, 168, 1, 1), GTPC_PORT);
        
        let found = manager.find_node_by_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(found, Some(id));
        
        let not_found = manager.find_node_by_ipv4(Ipv4Addr::new(192, 168, 1, 2));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_gtp_path_manager_create_xact() {
        let manager = GtpPathManager::new();
        
        let xact_id = manager.create_local_xact(
            gtp2_message_type::CREATE_SESSION_REQUEST,
            Some(1),
        );
        
        assert!(xact_id > 0);
        
        let xact = manager.get_xact(xact_id);
        assert!(xact.is_some());
        
        let xact = xact.unwrap();
        assert_eq!(xact.message_type, gtp2_message_type::CREATE_SESSION_REQUEST);
        assert_eq!(xact.sess_id, Some(1));
    }

    #[test]
    fn test_gtp_path_manager_xact_lifecycle() {
        let manager = GtpPathManager::new();
        
        let xact_id = manager.create_local_xact(
            gtp2_message_type::CREATE_SESSION_REQUEST,
            Some(1),
        );
        
        // Set request
        manager.set_xact_request(xact_id, vec![1, 2, 3]);
        
        let xact = manager.get_xact(xact_id).unwrap();
        assert_eq!(xact.state, GtpXactState::WaitingResponse);
        assert!(xact.request_buf.is_some());
        
        // Set response
        manager.set_xact_response(xact_id, vec![4, 5, 6]);
        
        let xact = manager.get_xact(xact_id).unwrap();
        assert_eq!(xact.state, GtpXactState::ResponseReceived);
        assert!(xact.response_buf.is_some());
        
        // Commit
        let committed = manager.commit_xact(xact_id);
        assert!(committed.is_some());
        
        let xact = committed.unwrap();
        assert_eq!(xact.state, GtpXactState::Completed);
        
        // Should be removed
        let xact = manager.get_xact(xact_id);
        assert!(xact.is_none());
    }

    #[test]
    fn test_gtp_path_manager_find_xact_by_sequence() {
        let manager = GtpPathManager::new();
        
        let xact_id = manager.create_local_xact(
            gtp2_message_type::CREATE_SESSION_REQUEST,
            Some(1),
        );
        
        let xact = manager.get_xact(xact_id).unwrap();
        let sequence = xact.sequence;
        
        let found = manager.find_xact_by_sequence(sequence);
        assert_eq!(found, Some(xact_id));
        
        let not_found = manager.find_xact_by_sequence(99999);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_gtp_path_manager_cleanup() {
        let manager = GtpPathManager::new();
        
        let xact_id = manager.create_local_xact(
            gtp2_message_type::CREATE_SESSION_REQUEST,
            Some(1),
        );
        
        // Complete the transaction
        manager.update_xact_state(xact_id, GtpXactState::Completed);
        
        // Cleanup
        manager.cleanup_completed();
        
        // Should be removed
        let xact = manager.get_xact(xact_id);
        assert!(xact.is_none());
    }

    #[test]
    fn test_gtp_xact_state_default() {
        let state = GtpXactState::default();
        assert_eq!(state, GtpXactState::Initial);
    }

    #[test]
    fn test_constants() {
        assert_eq!(GTPC_PORT, 2123);
        assert_eq!(GTPU_PORT, 2152);
        assert_eq!(GTP_XACT_TIMEOUT, 3);
        assert_eq!(GTP_XACT_RETRY_COUNT, 3);
        assert_eq!(GTP2_VERSION, 2);
    }

    #[test]
    fn test_gtp_modify_flags() {
        assert_eq!(gtp_modify_flags::TFT_UPDATE, 0x01);
        assert_eq!(gtp_modify_flags::QOS_UPDATE, 0x02);
    }
}
