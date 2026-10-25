//! GTP Path Management

//!
//! Port of src/smf/gtp-path.c - GTP path management for SMF
//! Handles GTP-C and GTP-U path setup, teardown, and message sending

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use nextgcore_gtp::v2::xact::{Gtp2XactConfig, Gtp2XactMgr};

use crate::context::{SmfBearer, SmfSess};
use crate::gtp_build::{
    build_create_bearer_request, build_create_session_response, build_delete_bearer_request,
    build_delete_session_response, build_echo_response, build_error_message,
    build_modify_bearer_response, build_update_bearer_request, gtp2_message_type, Gtp2Cause,
};

// ============================================================================
// Constants
// ============================================================================

/// Default GTP-C port
pub const GTPC_PORT: u16 = 2123;

/// A test's SGW-C port in place of [`GTPC_PORT`]; 0 for none (#1091 review A).
/// Tests that set it hold [`crate::context::PROCESS_STATE_TEST_LOCK`].
#[cfg(test)]
static SGW_PORT_FOR_TEST: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

/// The port the SGW-C's S5/S8 GTP-C is addressed at: [`GTPC_PORT`] (TS 29.274 §4.1),
/// or, in a test, an ephemeral one.
pub fn sgw_port() -> u16 {
    #[cfg(test)]
    {
        let port = SGW_PORT_FOR_TEST.load(std::sync::atomic::Ordering::SeqCst);
        if port != 0 {
            return port;
        }
    }
    GTPC_PORT
}

/// Address the SGW-C at `port` (`None`: [`GTPC_PORT`] again).
#[cfg(test)]
pub(crate) fn set_sgw_port_for_test(port: Option<u16>) {
    SGW_PORT_FOR_TEST.store(port.unwrap_or(0), std::sync::atomic::Ordering::SeqCst);
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
        } else {
            self.addr6
                .map(|addr| SocketAddr::new(addr.into(), self.port))
        }
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

    /// Generate the next sequence number for an initial message that is not a
    /// Command: 1..=0x7FFFFF, wrapping back to 1 (#792 review). GTPv2-C carries
    /// 24 bits (TS 29.274 §5.5), and §7.6 reserves the MSB for Command
    /// exchanges, so an unbounded counter would put a Command's bit, then
    /// truncated garbage, on the wire.
    pub fn next_sequence(&self) -> u32 {
        let max = nextgcore_gtp::v2::GTP2_MAX_INITIAL_SEQUENCE;
        let prev = self
            .sequence_generator
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| {
                Some(if s == 0 || s > max {
                    // Out of range (never in normal running): hand out 1 now
                    // and continue from 2, so 1 is not handed out twice.
                    2
                } else if s == max {
                    1
                } else {
                    s + 1
                })
            })
            .unwrap_or(1);
        if prev == 0 || prev > max {
            1
        } else {
            prev
        }
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
                xact.state != GtpXactState::Completed
                    && xact.state != GtpXactState::Failed
                    && xact.state != GtpXactState::TimedOut
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
        tft: &[u8],
    ) -> GtpSendResult {
        let xact_id =
            self.create_local_xact(gtp2_message_type::CREATE_BEARER_REQUEST, Some(sess.id));

        let message = build_create_bearer_request(sess, bearer, linked_ebi, tft, None);

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
        let xact_id =
            self.create_local_xact(gtp2_message_type::UPDATE_BEARER_REQUEST, Some(sess.id));

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
        let xact_id =
            self.create_local_xact(gtp2_message_type::DELETE_BEARER_REQUEST, Some(sess.id));

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
// S5/S8 GTP-C server: the PGW-C role on the wire (#52)
// ============================================================================

/// The PGW-C's S5/S8 GTPv2-C endpoint.
///
/// Before #52 this daemon bound no GTP-C socket at all: `GTPC_PORT` appeared only in
/// in-memory `GtpNode` bookkeeping and test asserts, and every `gtp_handler` function
/// had `#[cfg(test)]` callers only. So nothing terminated S5/S8, no node allocated the
/// PDN Address, and the dual 5G/LTE core had no anchor gateway for LTE.
///
/// **Async, unlike mmed's and sgwcd's servers.** Those are synchronous because the NAS
/// and S1AP paths that originate their messages are; this one is the terminating end,
/// and answering a Create Session Request requires awaiting an N4 exchange with the
/// UPF (`pfcp_session_establish`). An async receive loop lets the handler await that
/// directly, which is why smfd needs none of the deferred-continuation machinery #54
/// had to build for sgwcd.
///
/// The T3-RESPONSE/N3-REQUESTS budget still comes from the shared [`Gtp2XactMgr`], so
/// all three GTP-C endpoints in this tree agree about how long a message may take.
pub struct S5S8Server {
    socket: Arc<tokio::net::UdpSocket>,
    local_addr: SocketAddr,
    restart_counter: u8,
    xact: tokio::sync::Mutex<Gtp2XactMgr>,
    running: Arc<AtomicBool>,
    /// #619: the PGW-initiated requests waiting for their triggered message, by
    /// (SGW-C peer, sequence number). The sender is dropped when N3 runs out, which is
    /// how the waiting procedure learns that no answer is coming.
    pending: std::sync::Mutex<
        std::collections::HashMap<(SocketAddr, u32), tokio::sync::oneshot::Sender<Vec<u8>>>,
    >,
    /// #619: Commands from the SGW-C by (peer, sequence number), so a retransmitted
    /// Command does not start a second bearer: `None` while its procedure runs, then the
    /// time it ended, kept for the peer's retransmission window (`response_hold`).
    commands_seen:
        std::sync::Mutex<std::collections::HashMap<(SocketAddr, u32), Option<std::time::Instant>>>,
    /// How long a finished Command's number is remembered (#619).
    command_hold: std::time::Duration,
    /// #619: the locally configured PCC rules (`smf.pcc_rules`) this PGW-C activates as
    /// dedicated bearers when a PDN connection is established.
    local_pcc_rules: std::sync::RwLock<Vec<crate::eps_bearer::LocalPccRule>>,
    /// #1194, TS 23.007 §18: the remote Restart counter of each SGW-C, by the GTP-C
    /// entity's address (the sender F-TEID's, or an Echo's source). Volatile, as §18
    /// requires.
    peer_restart: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u8>>,
    /// #1194, TS 29.274 §7.6: the response sent to a request tracked by
    /// [`Self::begin_command`], by (peer, sequence number), kept for the hold; a
    /// retransmission of the request is answered with it rather than served again.
    responses: std::sync::Mutex<
        std::collections::HashMap<(SocketAddr, u32), (std::time::Instant, Vec<u8>)>,
    >,
}

/// The process-wide S5/S8 server.
///
/// A `OnceLock` for the same reason mmed's is: the PGW-initiated bearer procedures are
/// triggered from code that threads no transport handle. `None` means the socket was
/// never bound, and a send then reports that rather than pretending to have sent.
static S5S8_SERVER: OnceLock<Arc<S5S8Server>> = OnceLock::new();

/// The installed S5/S8 server, or `None` when the PGW-C role is not bound.
pub fn s5s8_server() -> Option<&'static Arc<S5S8Server>> {
    S5S8_SERVER.get()
}

impl S5S8Server {
    /// Bind the S5/S8 socket and spawn the receive and T3/N3 tasks.
    pub async fn open(bind: SocketAddr, restart_counter: u8) -> Result<Arc<Self>, String> {
        let socket = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|e| format!("bind {bind}: {e}"))?;
        let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
        let server = Arc::new(Self {
            socket: Arc::new(socket),
            local_addr,
            restart_counter,
            xact: tokio::sync::Mutex::new(Gtp2XactMgr::new(Gtp2XactConfig::default())),
            running: Arc::new(AtomicBool::new(true)),
            pending: std::sync::Mutex::new(std::collections::HashMap::new()),
            commands_seen: std::sync::Mutex::new(std::collections::HashMap::new()),
            command_hold: Gtp2XactConfig::default().response_hold,
            local_pcc_rules: std::sync::RwLock::new(Vec::new()),
            peer_restart: std::sync::Mutex::new(std::collections::HashMap::new()),
            responses: std::sync::Mutex::new(std::collections::HashMap::new()),
        });

        // Receive loop.
        {
            let server = server.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while server.running.load(Ordering::SeqCst) {
                    match server.socket.recv_from(&mut buf).await {
                        Ok((len, peer)) => {
                            let datagram = buf[..len].to_vec();
                            let server = server.clone();
                            // Spawned per datagram: answering a Create Session Request
                            // awaits an N4 exchange, and handling it inline would stop
                            // this socket receiving anything else for its duration —
                            // including the SGW-C's retransmission of the very request
                            // being served.
                            tokio::spawn(async move {
                                server.handle_datagram(&datagram, peer).await;
                            });
                        }
                        Err(e) => {
                            if server.running.load(Ordering::SeqCst) {
                                log::error!("S5/S8 recv error: {e}");
                            }
                        }
                    }
                }
            });
        }

        // T3-RESPONSE / N3-REQUESTS loop for the requests this node originates
        // (PGW-initiated Create/Update/Delete Bearer).
        {
            let server = server.clone();
            tokio::spawn(async move {
                while server.running.load(Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    let poll = {
                        let mut xact = server.xact.lock().await;
                        xact.poll(std::time::Instant::now())
                    };
                    for (peer, encoded) in poll.retransmits {
                        log::warn!("S5/S8 T3 expiry: retransmitting to {peer}");
                        if let Err(e) = server.socket.send_to(&encoded, peer).await {
                            log::error!("S5/S8 retransmit to {peer} failed: {e}");
                        }
                    }
                    for xact in poll.exhausted {
                        log::error!(
                            "S5/S8 N3 exhausted: peer {} not responding (type={}, seq={})",
                            xact.peer,
                            xact.message_type,
                            xact.sequence_number
                        );
                        // #619: dropping the sender tells the waiting procedure.
                        server.take_pending(xact.peer, xact.sequence_number);
                    }
                }
            });
        }

        log::info!("SMF/PGW-C S5/S8 GTP-C server listening on {local_addr}");
        Ok(server)
    }

    /// Stop the receive and retransmission tasks.
    pub fn close(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Local bound address, which is also the PGW's S5/S8-C address on the wire.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The restart counter advertised in Recovery IEs.
    pub fn restart_counter(&self) -> u8 {
        self.restart_counter
    }

    /// Send a triggered (response) message, echoing the request's sequence number.
    ///
    /// #1194: the response to a request being served under [`Self::begin_command`] is
    /// kept, so a retransmission of that request gets the same answer (TS 29.274 §7.6).
    pub async fn send_response_public(&self, peer: SocketAddr, encoded: &[u8]) {
        if let Some(seq) = gtp2_sequence_number(encoded) {
            let tracked = self
                .commands_seen
                .lock()
                .is_ok_and(|seen| matches!(seen.get(&(peer, seq)), Some(None)));
            if tracked {
                if let Ok(mut responses) = self.responses.lock() {
                    let now = std::time::Instant::now();
                    responses.retain(|_, (at, _)| now.duration_since(*at) < self.command_hold);
                    responses.insert((peer, seq), (now, encoded.to_vec()));
                }
            }
        }
        if let Err(e) = self.socket.send_to(encoded, peer).await {
            log::error!("S5/S8 response to {peer} failed: {e}");
        }
    }

    /// The response kept for the request `(peer, seq)`, if it was answered within the
    /// hold (#1194).
    pub(crate) fn cached_response(&self, peer: SocketAddr, seq: u32) -> Option<Vec<u8>> {
        let now = std::time::Instant::now();
        let responses = self.responses.lock().ok()?;
        responses
            .get(&(peer, seq))
            .filter(|(at, _)| now.duration_since(*at) < self.command_hold)
            .map(|(_, r)| r.clone())
    }

    /// Note an SGW-C's Restart counter (TS 23.007 §18), for the GTP-C entity at `entity`.
    /// `true` when it says the SGW-C restarted since the stored one: its PDN connections
    /// are then stale (§17.1A.1). The first value is stored; a value behind the stored
    /// one is a reordered datagram, discarded.
    pub(crate) fn note_sgw_restart_counter(&self, entity: std::net::IpAddr, counter: u8) -> bool {
        use nextgcore_gtp::v2::RestartOrder;
        let Ok(mut seen) = self.peer_restart.lock() else {
            return false;
        };
        let mut stored = seen.get(&entity).copied();
        let previous = stored;
        let order = nextgcore_gtp::v2::note_restart_counter(&mut stored, counter);
        if let Some(value) = stored {
            seen.insert(entity, value);
        }
        drop(seen);
        match (order, previous) {
            (RestartOrder::Restarted, Some(previous)) => {
                log::warn!(
                    "S5/S8: SGW-C {entity} restarted (Restart counter {previous} -> {counter}); \
                     its PDN connections are stale (TS 23.007 §18, §17.1A.1)"
                );
                true
            }
            (RestartOrder::Stale, Some(previous)) => {
                log::warn!(
                    "S5/S8: SGW-C {entity} Restart counter {counter} is behind the stored \
                     {previous}: discarded as a reordered message (TS 23.007 §18)"
                );
                false
            }
            _ => false,
        }
    }

    /// Send an initial (request) message and arm T3/N3.
    ///
    /// Used by the PGW-initiated bearer procedures, which are the only messages this
    /// node originates on S5/S8.
    pub async fn send_request(&self, peer: SocketAddr, encoded: Vec<u8>, message_type: u8) -> u32 {
        self.send_request_numbered(peer, encoded, message_type, None)
            .await
    }

    /// Send a request under `sequence` (or a fresh number when `None`) and arm T3/N3.
    ///
    /// #619: a request TRIGGERED by a Command (a Create Bearer Request answering a Bearer
    /// Resource Command) carries the Command's sequence number, TS 29.274 §7.6. With a
    /// fresh number the SGW-C could not correlate it with the Command it relayed, and the
    /// Command would run out its N3 there. The encoded message is renumbered here, so a
    /// caller cannot send one number and register another.
    pub async fn send_request_numbered(
        &self,
        peer: SocketAddr,
        encoded: Vec<u8>,
        message_type: u8,
        sequence: Option<u32>,
    ) -> u32 {
        let (seq, encoded) = {
            let mut xact = self.xact.lock().await;
            let seq = sequence.unwrap_or_else(|| xact.alloc_sequence());
            let encoded = crate::gtp_handler::with_sequence_number(encoded, seq);
            xact.register_request(
                seq,
                message_type,
                peer,
                bytes::Bytes::from(encoded.clone()),
                0,
            );
            (seq, encoded)
        };
        if let Err(e) = self.socket.send_to(&encoded, peer).await {
            log::error!("S5/S8 request to {peer} failed: {e}");
        }
        seq
    }

    /// Send a request and wait for its triggered message (#619).
    ///
    /// Returns the raw triggered message, or an error once T3/N3 runs out. The waiter is
    /// registered BEFORE the datagram leaves, so an answer that arrives before this
    /// task is next polled is not lost.
    pub async fn request(
        &self,
        peer: SocketAddr,
        encoded: Vec<u8>,
        message_type: u8,
        sequence: Option<u32>,
    ) -> Result<Vec<u8>, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (seq, encoded) = {
            let mut xact = self.xact.lock().await;
            let seq = sequence.unwrap_or_else(|| xact.alloc_sequence());
            let encoded = crate::gtp_handler::with_sequence_number(encoded, seq);
            xact.register_request(
                seq,
                message_type,
                peer,
                bytes::Bytes::from(encoded.clone()),
                0,
            );
            if let Ok(mut pending) = self.pending.lock() {
                pending.insert((peer, seq), tx);
            }
            (seq, encoded)
        };
        if let Err(e) = self.socket.send_to(&encoded, peer).await {
            log::error!("S5/S8 request to {peer} failed: {e}");
        }
        rx.await.map_err(|_| {
            format!("no answer from {peer} to message type {message_type} (seq {seq}): N3 ran out")
        })
    }

    fn take_pending(
        &self,
        peer: SocketAddr,
        seq: u32,
    ) -> Option<tokio::sync::oneshot::Sender<Vec<u8>>> {
        self.pending.lock().ok()?.remove(&(peer, seq))
    }

    /// Record that a Command from `peer` is being served; `false` when it already is, or
    /// ended within the peer's retransmission window, which means this datagram is a
    /// retransmission of it (#619). A Command is answered by a Triggered message that
    /// this node does not cache as a response, so without the window a retransmission
    /// arriving after the bearer was set up would start a second one.
    pub(crate) fn begin_command(&self, peer: SocketAddr, seq: u32) -> bool {
        let now = std::time::Instant::now();
        let Ok(mut seen) = self.commands_seen.lock() else {
            return false;
        };
        seen.retain(|_, ended| ended.is_none_or(|t| now.duration_since(t) < self.command_hold));
        if seen.contains_key(&(peer, seq)) {
            return false;
        }
        seen.insert((peer, seq), None);
        true
    }

    /// The Command's procedure finished (#619); its number is remembered for the hold.
    pub(crate) fn end_command(&self, peer: SocketAddr, seq: u32) {
        if let Ok(mut seen) = self.commands_seen.lock() {
            seen.insert((peer, seq), Some(std::time::Instant::now()));
        }
    }

    /// Whether the Command `(peer, seq)` has finished and is remembered (#619 tests).
    #[cfg(test)]
    pub(crate) fn command_ended(&self, peer: SocketAddr, seq: u32) -> bool {
        self.commands_seen
            .lock()
            .is_ok_and(|seen| matches!(seen.get(&(peer, seq)), Some(Some(_))))
    }

    /// Install the locally configured PCC rules (#619).
    pub fn set_local_pcc_rules(&self, rules: Vec<crate::eps_bearer::LocalPccRule>) {
        if let Ok(mut r) = self.local_pcc_rules.write() {
            *r = rules;
        }
    }

    /// The local PCC rules that apply to a PDN connection to `apn` (#619).
    pub(crate) fn local_pcc_rules_for(&self, apn: &str) -> Vec<crate::eps_bearer::LocalPccRule> {
        self.local_pcc_rules
            .read()
            .map(|rules| {
                rules
                    .iter()
                    .filter(|r| r.applies_to(apn))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Outstanding transactions awaiting a triggered message.
    pub async fn outstanding(&self) -> usize {
        self.xact.lock().await.outstanding()
    }

    /// #1194: an Echo's Recovery is the SGW-C's at the message's source address (TS
    /// 23.007 §18); a restart deletes the PDN connections it held (§17.1A.1).
    async fn note_echo_recovery(&self, msg: &nextgcore_gtp::v2::Gtp2Message, peer: SocketAddr) {
        let Some(counter) = msg
            .get_ie(nextgcore_gtp::v2::Gtp2IeType::Recovery as u8, 0)
            .and_then(|ie| ie.value.first().copied())
        else {
            return;
        };
        if self.note_sgw_restart_counter(peer.ip(), counter) {
            crate::gtp_handler::delete_pdn_connections_of_sgw(peer.ip(), "the SGW-C restarted")
                .await;
        }
    }

    async fn handle_datagram(&self, data: &[u8], peer: SocketAddr) {
        let mut bytes = bytes::Bytes::copy_from_slice(data);
        let msg = match nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes) {
            Ok(m) => m,
            Err(e) => {
                log::error!("[DROP] cannot decode S5/S8 datagram from {peer}: {e}");
                return;
            }
        };
        let msg_type = msg.header.message_type;
        let seq = msg.header.sequence_number;

        // Echo: path management, no session state (TS 29.274 §7.1.1). Answered here
        // rather than through the handler layer, which would only add a hop.
        if msg_type == gtp2_message_type::ECHO_REQUEST {
            let mut reply =
                nextgcore_gtp::v2::Gtp2Message::echo_response(seq, self.restart_counter);
            reply.header.sequence_number = seq;
            self.send_response_public(peer, &reply.encode()).await;
            self.note_echo_recovery(&msg, peer).await;
            return;
        }
        if msg_type == gtp2_message_type::ECHO_RESPONSE {
            log::debug!("S5/S8 Echo Response from {peer}");
            self.note_echo_recovery(&msg, peer).await;
            return;
        }

        // A triggered message closes one of this node's own transactions. #619: by
        // (peer, sequence number), so only the SGW-C the request went to can answer it.
        let matched = {
            let mut xact = self.xact.lock().await;
            xact.match_response_from(peer, seq, msg_type)
        };
        if let Some(closed) = matched {
            log::debug!(
                "S5/S8 RX response type={msg_type} seq={seq} from {peer} correlates to type={}",
                closed.message_type
            );
            match self.take_pending(peer, seq) {
                // A send error means the waiting procedure gave up; nothing to do.
                Some(waiter) => drop(waiter.send(data.to_vec())),
                None => crate::gtp_handler::dispatch_s5s8_response(msg_type, data, peer),
            }
            return;
        }

        // An initial message from the SGW-C.
        crate::gtp_handler::dispatch_s5s8_request(self, msg_type, seq, data, peer).await;
    }
}

/// The sequence number of an encoded GTPv2-C message (TS 29.274 §5.5.1): octets 9-11
/// with a TEID, 5-7 without.
fn gtp2_sequence_number(encoded: &[u8]) -> Option<u32> {
    let off = if encoded.first()? & 0x08 != 0 { 8 } else { 4 };
    let b = encoded.get(off..off + 3)?;
    Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

/// Bind the S5/S8 socket from configuration and install it process-wide (#52).
///
/// With no `smf.gtpc.server` configured this returns `Ok(())` and logs why: an SMF with
/// no S5/S8 address is a 5G-only deployment, and refusing to start would break every
/// existing 5GC config that never needed the socket.
pub async fn s5s8_open(
    bind: Option<SocketAddr>,
    restart_counter: u8,
    local_pcc_rules: Vec<crate::eps_bearer::LocalPccRule>,
) -> Result<(), String> {
    let Some(bind) = bind else {
        log::info!(
            "no smf.gtpc.server configured: the S5/S8 (PGW-C) role is NOT bound, so no LTE \
             session can be anchored here"
        );
        return Ok(());
    };
    let server = S5S8Server::open(bind, restart_counter).await?;
    if !local_pcc_rules.is_empty() {
        log::info!(
            "S5/S8: {} local PCC rule(s) will be activated as dedicated bearers",
            local_pcc_rules.len()
        );
    }
    server.set_local_pcc_rules(local_pcc_rules);
    if S5S8_SERVER.set(server).is_err() {
        log::warn!("an S5/S8 server is already installed; this one is dropped");
    }
    Ok(())
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

    /// #792 review: the counter stays in the 23-bit initial space and wraps to 1,
    /// never 0 and never with the Command MSB (TS 29.274 §7.6).
    #[test]
    fn the_sequence_wraps_inside_the_initial_space() {
        let manager = GtpPathManager::new();
        let max = nextgcore_gtp::v2::GTP2_MAX_INITIAL_SEQUENCE;
        manager.sequence_generator.store(max - 1, Ordering::SeqCst);
        assert_eq!(manager.next_sequence(), max - 1);
        assert_eq!(manager.next_sequence(), max);
        assert_eq!(manager.next_sequence(), 1, "wrapped, skipping 0");
        assert_eq!(manager.next_sequence(), 2);
        manager.sequence_generator.store(u32::MAX, Ordering::SeqCst);
        let s = manager.next_sequence();
        assert!((1..=max).contains(&s), "{s:#x}");
        assert_ne!(manager.next_sequence(), s, "not handed out twice");
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

        let xact_id = manager.create_local_xact(gtp2_message_type::CREATE_SESSION_REQUEST, Some(1));

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

        let xact_id = manager.create_local_xact(gtp2_message_type::CREATE_SESSION_REQUEST, Some(1));

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

        let xact_id = manager.create_local_xact(gtp2_message_type::CREATE_SESSION_REQUEST, Some(1));

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

        let xact_id = manager.create_local_xact(gtp2_message_type::CREATE_SESSION_REQUEST, Some(1));

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
