//! PFCP Path Management — the SMF's N4 transaction engine (TS 29.244)
//!
//! Replaces the former dead parallel-builder module: all PFCP messages now
//! leave the SMF through exactly one code path. Session message bodies are
//! built by `n4_build`; node-level messages (Heartbeat, Association
//! Setup/Release) use the nextgcore-pfcp library codec directly.
//!
//! Responsibilities:
//! - request/response transaction matching by sequence number
//! - T1 retransmission up to N1 attempts, exhaustion = abnormal action
//!   (TS 29.244 7.2.1; configured in `timer::SmfTimerConfigs`)
//! - PFCP Association Setup / Release with the UPF
//! - Heartbeat in both directions with Recovery Time Stamp staleness
//!   detection (peer restart ⇒ local session state flushed)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::{BufMut, Bytes};
use nextgcore_pfcp::message::{
    build_message, AssociationReleaseRequest, AssociationSetupRequest, AssociationSetupResponse,
    HeartbeatRequest, HeartbeatResponse, PfcpMessage,
};
use nextgcore_pfcp::types::{CpFunctionFeatures, NodeId, UpFunctionFeatures};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, RwLock};

use crate::context::smf_self;
use crate::timer::SmfTimerConfigs;

// ============================================================================
// PFCP Message Types (TS 29.244 Table 7.3-1)
// ============================================================================

/// PFCP Message types
pub mod pfcp_message_type {
    pub const HEARTBEAT_REQUEST: u8 = 1;
    pub const HEARTBEAT_RESPONSE: u8 = 2;
    pub const PFD_MANAGEMENT_REQUEST: u8 = 3;
    pub const PFD_MANAGEMENT_RESPONSE: u8 = 4;
    pub const ASSOCIATION_SETUP_REQUEST: u8 = 5;
    pub const ASSOCIATION_SETUP_RESPONSE: u8 = 6;
    pub const ASSOCIATION_UPDATE_REQUEST: u8 = 7;
    pub const ASSOCIATION_UPDATE_RESPONSE: u8 = 8;
    pub const ASSOCIATION_RELEASE_REQUEST: u8 = 9;
    pub const ASSOCIATION_RELEASE_RESPONSE: u8 = 10;
    pub const VERSION_NOT_SUPPORTED_RESPONSE: u8 = 11;
    pub const NODE_REPORT_REQUEST: u8 = 12;
    pub const NODE_REPORT_RESPONSE: u8 = 13;
    pub const SESSION_SET_DELETION_REQUEST: u8 = 14;
    pub const SESSION_SET_DELETION_RESPONSE: u8 = 15;
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_ESTABLISHMENT_RESPONSE: u8 = 51;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_MODIFICATION_RESPONSE: u8 = 53;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_DELETION_RESPONSE: u8 = 55;
    pub const SESSION_REPORT_REQUEST: u8 = 56;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

/// PFCP messages refused because their sender is not a UPF this SMF is configured
/// with or associated to, or because a UPF named a session that is not its own
/// (#971). Exported as `smf_pfcp_unauthorized_messages_total`. One unlabelled
/// counter, so a flood of sources adds no series.
pub static PFCP_UNAUTHORIZED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The PFCP port (TS 29.244 §4.2.2), for resolving a UPF's Node ID FQDN.
const PFCP_PORT: u16 = 8805;

/// How often a refused-datagram summary is logged at WARN (#974 review M1).
const UNAUTHORIZED_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// When the last summary went out, and the counter then.
static UNAUTHORIZED_LOGGED: std::sync::Mutex<Option<(std::time::Instant, u64)>> =
    std::sync::Mutex::new(None);

/// Count one refused PFCP datagram, and log it (#974 review M1): each one at DEBUG,
/// and at most one WARN per [`UNAUTHORIZED_LOG_INTERVAL`], carrying how many were
/// refused since the last. A forged-sender flood is then a counter and a log line
/// every 10 s, not a WARN per datagram on the one N4 receive task.
///
/// Returns whether this one was logged at WARN.
pub fn note_unauthorized(what: std::fmt::Arguments<'_>, from: SocketAddr) -> bool {
    let total = PFCP_UNAUTHORIZED.fetch_add(1, Ordering::Relaxed) + 1;
    log::debug!("N4: {what} from {from}: refused");
    let Ok(mut last) = UNAUTHORIZED_LOGGED.try_lock() else {
        return false;
    };
    let now = std::time::Instant::now();
    let since = match *last {
        Some((at, _)) if now.duration_since(at) < UNAUTHORIZED_LOG_INTERVAL => return false,
        Some((_, count)) => count,
        None => 0,
    };
    *last = Some((now, total));
    log::warn!(
        "N4: {} PFCP message(s) refused since the last report, from hosts that are no UPF \
         of this SMF or about sessions that are not the sender's (latest: {what} from \
         {from}; {total} in all, smf_pfcp_unauthorized_messages_total)",
        total - since
    );
    true
}

/// A UPF as the N4 listener sees it (#974 review m4): the endpoint it is dialled
/// at, and every other address it may send from (TS 29.244 §5.8.1).
#[derive(Debug, Clone)]
pub struct N4Peer {
    pub endpoint: SocketAddr,
    pub addrs: Vec<std::net::IpAddr>,
}

impl N4Peer {
    /// A UPF known only by its endpoint.
    pub fn at(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            addrs: Vec::new(),
        }
    }

    fn is_node(&self, from: SocketAddr) -> bool {
        same_pfcp_node(self.endpoint, from)
            || self
                .addrs
                .iter()
                .any(|a| a.to_canonical() == from.ip().to_canonical())
    }
}

/// What the N4 listener does with a datagram (#971).
#[derive(Debug, PartialEq, Eq)]
pub enum N4Admission {
    /// From a configured or associated UPF: handle it as that UPF's.
    Peer(usize),
    /// A Heartbeat Request from an unknown host: answer it with this SMF's own
    /// Recovery Time Stamp (TS 23.007 §19A, "even from unknown peers"), take nothing
    /// from it.
    AnswerHeartbeat,
    /// Any other request from an unknown host: refused with cause 72, "No
    /// established PFCP Association" (TS 29.244 §8.2.1), not executed, counted. An
    /// Association Setup Request is not answered: this SMF does not implement the
    /// UP-initiated setup (§6.2.6.3.2), so it is counted and dropped like a response.
    RefuseRequest,
    /// Everything else from an unknown host, including every response: dropped and
    /// counted. A response is accepted only from the exact endpoint its request went
    /// to (§4.2.3).
    Drop,
}

/// Decide what to do with a datagram of type `msg_type` from `from` (#971). Before,
/// a datagram from an unknown source went to pool slot 0, and nothing checked the
/// sender: anyone reaching UDP 8805 could answer our requests, forge a Session
/// Report for any SEID, or tear UPF 0's association down.
pub fn admit_n4(msg_type: u8, from: SocketAddr, peers: &[N4Peer]) -> N4Admission {
    // The exact endpoint first. A response must come from there (TS 29.244 §4.2.3:
    // its source is the request's destination). A request may come from any source
    // port (§4.2.2) and from any address of the UPF (§5.8.1), and TS 23.007 §19A
    // identifies the peer by its address; a node shared by two pool entries (two
    // UPFs on one host) is matched only by the exact endpoint.
    if let Some(i) = peers.iter().position(|p| p.endpoint == from) {
        return N4Admission::Peer(i);
    }
    if !is_response_type(msg_type) {
        let same_node: Vec<usize> = peers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_node(from))
            .map(|(i, _)| i)
            .collect();
        if let [i] = same_node[..] {
            return N4Admission::Peer(i);
        }
    }
    match msg_type {
        pfcp_message_type::HEARTBEAT_REQUEST => N4Admission::AnswerHeartbeat,
        pfcp_message_type::ASSOCIATION_UPDATE_REQUEST
        | pfcp_message_type::ASSOCIATION_RELEASE_REQUEST
        | pfcp_message_type::NODE_REPORT_REQUEST
        | pfcp_message_type::SESSION_SET_DELETION_REQUEST
        | pfcp_message_type::SESSION_REPORT_REQUEST => N4Admission::RefuseRequest,
        _ => N4Admission::Drop,
    }
}

/// The cause-72 answer to a request from a host with no PFCP association (TS 29.244
/// §8.2.1), for the request types [`admit_n4`] refuses. Node-level responses carry
/// this SMF's Node ID (§7.4.4.4, §7.4.4.6, §7.4.5.2, §7.4.6.2); the Session Report
/// Response carries SEID 0, as the sender has no session here (§7.2.2.4.2).
pub fn refusal_response(msg_type: u8, sequence_number: u32, node_id: &NodeId) -> Option<Vec<u8>> {
    const CAUSE_72: [u8; 5] = [0, 19, 0, 1, 72];
    let node_level = |resp_type: u8| {
        let mut nid = bytes::BytesMut::new();
        node_id.encode(&mut nid);
        let mut body = Vec::with_capacity(4 + nid.len() + CAUSE_72.len());
        body.extend_from_slice(&60u16.to_be_bytes());
        body.extend_from_slice(&(nid.len() as u16).to_be_bytes());
        body.extend_from_slice(&nid);
        body.extend_from_slice(&CAUSE_72);
        encode_wire_message(resp_type, None, sequence_number, &body)
    };
    match msg_type {
        pfcp_message_type::ASSOCIATION_UPDATE_REQUEST => {
            Some(node_level(pfcp_message_type::ASSOCIATION_UPDATE_RESPONSE))
        }
        pfcp_message_type::ASSOCIATION_RELEASE_REQUEST => {
            Some(node_level(pfcp_message_type::ASSOCIATION_RELEASE_RESPONSE))
        }
        pfcp_message_type::NODE_REPORT_REQUEST => {
            Some(node_level(pfcp_message_type::NODE_REPORT_RESPONSE))
        }
        pfcp_message_type::SESSION_SET_DELETION_REQUEST => {
            Some(node_level(pfcp_message_type::SESSION_SET_DELETION_RESPONSE))
        }
        pfcp_message_type::SESSION_REPORT_REQUEST => Some(encode_wire_message(
            pfcp_message_type::SESSION_REPORT_RESPONSE,
            Some(0),
            sequence_number,
            &CAUSE_72,
        )),
        _ => None,
    }
}

/// Whether two PFCP endpoints are the same PFCP node: the canonical IP address (an
/// IPv4-mapped IPv6 address is the IPv4 one), not the port.
pub fn same_pfcp_node(a: SocketAddr, b: SocketAddr) -> bool {
    a.ip().to_canonical() == b.ip().to_canonical()
}

/// This SMF's Recovery Time Stamp (TS 29.244 §8.2.65), one per process (#974 review
/// m7): taken once, at the first use, and carried by every client and by the answer
/// to a stranger's heartbeat alike.
pub fn smf_recovery_time_stamp() -> u32 {
    static STAMP: OnceLock<u32> = OnceLock::new();
    // #995: NTP-era seconds (TS 29.244 §8.2.65), not Unix seconds.
    *STAMP.get_or_init(nextgcore_pfcp::recovery_time::now)
}

/// A Heartbeat Response carrying our Recovery Time Stamp (TS 29.244 §7.4.2.2).
pub fn heartbeat_response(sequence_number: u32, recovery_time_stamp: u32) -> Vec<u8> {
    let msg = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(recovery_time_stamp));
    build_message(&msg, sequence_number, None).to_vec()
}

/// Whether a Session Report for the session with SMF-side SEID `seid` may come from
/// `from` (#971, #974 review m3): the sender must be the UPF that serves it, by the
/// routing every other session message uses ([`client_for_session`]): the recorded
/// UPF, or, for a session with no record (one restored from durable state), the
/// default client. Never open: with no UPF to own it, it is refused. Whether the
/// session exists at all is [`holds_session_seid`].
///
/// #974 review n2: when the listener admitted the datagram as one client's
/// (`admitted`), ownership is that client's identity, not the sender's IP: two pool
/// entries on one host, or a learnt address set that reaches a sibling, cannot
/// report on each other's sessions.
pub fn report_sender_owns_session(
    seid: u64,
    from: SocketAddr,
    admitted: Option<&PfcpClient>,
) -> bool {
    client_for_session(seid).is_some_and(|owner| match admitted {
        Some(a) => std::ptr::eq(Arc::as_ptr(&owner), a),
        None => owner.is_node_address(from),
    })
}

/// Is this message type a response (solicited by one of our requests)?
fn is_response_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        2 | 4 | 6 | 8 | 10 | 11 | 13 | 15 | 51 | 53 | 55 | 57
    )
}

// ============================================================================
// Wire helpers
// ============================================================================

/// Minimal decoded view of a PFCP datagram header
#[derive(Debug, Clone, Copy)]
pub struct WireHeader {
    pub version: u8,
    pub msg_type: u8,
    pub seid_present: bool,
    pub seid: u64,
    pub sequence_number: u32,
    /// Offset of the IE payload within the datagram
    pub body_offset: usize,
}

/// Parse the PFCP header of a raw datagram (TS 29.244 7.2.2).
pub fn parse_wire_header(pkt: &[u8]) -> Option<WireHeader> {
    if pkt.len() < 8 {
        return None;
    }
    let version = pkt[0] >> 5;
    let seid_present = pkt[0] & 0x01 != 0;
    let msg_type = pkt[1];
    if seid_present {
        if pkt.len() < 16 {
            return None;
        }
        let seid = u64::from_be_bytes(pkt[4..12].try_into().ok()?);
        let seq = u32::from_be_bytes([0, pkt[12], pkt[13], pkt[14]]);
        Some(WireHeader {
            version,
            msg_type,
            seid_present,
            seid,
            sequence_number: seq,
            body_offset: 16,
        })
    } else {
        let seq = u32::from_be_bytes([0, pkt[4], pkt[5], pkt[6]]);
        Some(WireHeader {
            version,
            msg_type,
            seid_present,
            seid: 0,
            sequence_number: seq,
            body_offset: 8,
        })
    }
}

/// Encode a complete PFCP datagram from a message body built by `n4_build`.
pub fn encode_wire_message(msg_type: u8, seid: Option<u64>, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(16 + body.len());
    match seid {
        Some(seid) => {
            pkt.push(0x21); // version=1, S=1
            pkt.push(msg_type);
            pkt.extend_from_slice(&((12 + body.len()) as u16).to_be_bytes());
            pkt.extend_from_slice(&seid.to_be_bytes());
        }
        None => {
            pkt.push(0x20); // version=1, S=0
            pkt.push(msg_type);
            pkt.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        }
    }
    pkt.extend_from_slice(&seq.to_be_bytes()[1..4]);
    pkt.push(0); // spare
    pkt.extend_from_slice(body);
    pkt
}

/// Scan a PFCP message body for the Cause IE (type 19) and return its value.
pub fn parse_cause(body: &[u8]) -> Option<u8> {
    find_ie(body, 19).and_then(|v| v.first().copied())
}

/// Scan a flat TLV body for the first IE of the given type.
pub fn find_ie(body: &[u8], ie_type: u16) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let t = u16::from_be_bytes([body[off], body[off + 1]]);
        let l = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        let start = off + 4;
        let end = start + l;
        if end > body.len() {
            return None;
        }
        if t == ie_type {
            return Some(&body[start..end]);
        }
        off = end;
    }
    None
}

/// PFCP cause values used on the N4 reply paths (TS 29.244 8.2.1)
pub mod pfcp_cause {
    pub const REQUEST_ACCEPTED: u8 = 1;
    pub const REQUEST_REJECTED: u8 = 64;
    pub const SESSION_CONTEXT_NOT_FOUND: u8 = 65;
    pub const MANDATORY_IE_MISSING: u8 = 66;
    pub const NO_ESTABLISHED_PFCP_ASSOCIATION: u8 = 72;
}

/// Human-readable PFCP cause name for error reporting
///
/// Delegates to `nextgcore_pfcp::types::PfcpCause` rather than carrying a second
/// copy of TS 29.244 Table 8.2.1-1. The local copy this replaced had drifted
/// from the library enum in a way that mattered: it listed cause 78
/// ("Redirection requested") while the enum did not, so the SMF could *name* a
/// cause its own decoder rejected outright.
pub fn cause_name(cause: u8) -> &'static str {
    match nextgcore_pfcp::types::PfcpCause::try_from(cause) {
        Ok(c) => c.name(),
        Err(_) => "Unknown cause",
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Failure modes of an N4 transaction
#[derive(Debug)]
pub enum PfcpRequestError {
    /// No response after N1 retransmissions — peer unreachable
    Timeout { attempts: u32 },
    /// Peer answered with a non-accepted cause
    Rejected { cause: u8 },
    /// Local I/O or state error
    Local(String),
    /// No PFCP association established with the peer
    NotAssociated,
}

impl std::fmt::Display for PfcpRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { attempts } => {
                write!(f, "no PFCP response after {attempts} attempts")
            }
            Self::Rejected { cause } => {
                write!(
                    f,
                    "PFCP request rejected: cause {cause} ({})",
                    cause_name(*cause)
                )
            }
            Self::Local(e) => write!(f, "local PFCP error: {e}"),
            Self::NotAssociated => write!(f, "no established PFCP association"),
        }
    }
}

impl std::error::Error for PfcpRequestError {}

// ============================================================================
// Association state
// ============================================================================

/// State of the N4 association with the UPF
#[derive(Debug, Clone, Default)]
pub struct AssociationState {
    pub associated: bool,
    /// Recovery Time Stamp the peer reported at association / heartbeat
    pub peer_recovery_time_stamp: Option<u32>,
    /// UP Function Features advertised by the UPF
    pub up_function_features: Option<UpFunctionFeatures>,
    /// Latest load metric (0..=100) the peer reported via a Load Control
    /// Information IE on its heartbeat (issue #20, TS 29.244 §8.2.53).
    /// None until the peer reports one — standard peers never do.
    pub peer_load: Option<u8>,
    /// Load Control Sequence Number of the stored `peer_load`; a stale
    /// (lower) sequence number must not overwrite a newer metric
    /// (TS 29.244 §8.2.52).
    pub peer_load_seq: Option<u32>,
    /// Which association this is: bumped at every successful Association Setup
    /// (#966 follow-up). A session request remembers the one it was sent on, so a late
    /// cause 72 answering it cannot tear down the association set up since.
    pub generation: u64,
}

// ============================================================================
// PFCP client (transaction engine)
// ============================================================================

/// The SMF's PFCP endpoint: one shared socket for requests and responses,
/// transactions matched on sequence number.
pub struct PfcpClient {
    socket: Arc<UdpSocket>,
    /// The UPF endpoint currently dialled. Behind a lock because a peer named by
    /// hostname is re-resolved when Association Setup fails (#658): a UPF pod
    /// that restarts comes back at a new address, and an endpoint fixed at
    /// startup would be retried forever.
    peer: std::sync::RwLock<SocketAddr>,
    /// The hostname and port `peer` was resolved from, when the operator named
    /// the UPF rather than giving a literal address (#658).
    peer_host: Option<(String, u16)>,
    /// The IPv4 address carried in every CP F-SEID (TS 29.244 §8.2.37): the
    /// routable address the UPF sends this SMF's session-level requests to (#797).
    node_ip: [u8; 4],
    /// The PFCP Node ID that identifies this CP function (TS 29.244 §5.8.1,
    /// §8.2.38). Separate from `node_ip` since #797: on k8s it is the Service FQDN,
    /// stable across restarts, while the F-SEID address is the pod IP.
    node_id: NodeId,
    /// Our own Recovery Time Stamp: [`smf_recovery_time_stamp`], the same for every
    /// client (#974 review m7).
    pub recovery_time_stamp: u32,
    /// The UPF's other addresses (TS 29.244 §5.8.1, #974 review m4): its Node ID's
    /// address, or every address its Node ID FQDN, or the hostname it was configured
    /// by, resolves to. Learnt at each Association Setup.
    node_addrs: Arc<std::sync::RwLock<Vec<std::net::IpAddr>>>,
    /// The latest `node_addrs` lookup started (#1091 review E): only its result is
    /// installed, so an older lookup that finishes last cannot overwrite it.
    node_addrs_generation: Arc<std::sync::atomic::AtomicU64>,
    pending: Mutex<HashMap<u32, oneshot::Sender<(u8, Vec<u8>)>>>,
    assoc: RwLock<AssociationState>,
    /// Synchronously-readable projection of `assoc.associated` (#380).
    ///
    /// `assoc` is behind a `tokio::sync::RwLock`, so it can only be read from an async
    /// context — and the Prometheus render that the container healthcheck and the EPC
    /// CI readiness gate poll is a plain `Fn() -> String`. This is the same
    /// sync-readable-projection shape `sgwud`'s `associated_peers` gauge and `upfd`'s
    /// `session_count` already use, for exactly that reason.
    ///
    /// Maintained by [`Self::publish_associated`], which is called inside EVERY write
    /// scope that touches `assoc.associated` and always ASSIGNS what the guard holds —
    /// never toggles — so it cannot report a state the association never had.
    associated_gauge: std::sync::atomic::AtomicBool,
    timers: SmfTimerConfigs,
}

/// The process-wide PFCP client.
///
/// A `RwLock<Option<..>>` rather than a `OnceLock` (issue #289), and this is the
/// production change that issue asked to be decided out loud rather than
/// silently. The decision was forced by evidence, not preference: a `PfcpClient`
/// owns a `tokio::net::UdpSocket`, and a tokio socket belongs to the runtime that
/// created it. Under `#[tokio::test]` — one runtime per test — a client installed
/// permanently by whichever test ran first is a client whose socket is dead for
/// every test after it ("A Tokio 1.x context was found, but it is being
/// shutdown"), so the install-once shape cannot express a UPF stand-in at all.
///
/// What changes for the running SMF: `set_global_client` now overwrites instead
/// of being first-wins. `main` calls it exactly once (through
/// [`set_global_pool`]) at startup, so today's behaviour is identical, and a
/// re-installable pool is the more predictable of the two if a future
/// reconfiguration path ever wants one. What is deliberately NOT added is any
/// caller that swaps the client while sessions are live: the sessions' peer
/// bindings (`SESSION_PEERS`) would still point at the old peer.
static PFCP_CLIENT: std::sync::RwLock<Option<Arc<PfcpClient>>> = std::sync::RwLock::new(None);

/// Install the process-wide PFCP client (at startup, or per test).
pub fn set_global_client(client: Arc<PfcpClient>) {
    if let Ok(mut slot) = PFCP_CLIENT.write() {
        *slot = Some(client);
    }
}

/// The process-wide PFCP client, if initialised. Cloned out of the lock so no
/// guard is ever held across an `await`.
pub fn global_client() -> Option<Arc<PfcpClient>> {
    PFCP_CLIENT.read().ok()?.clone()
}

// ============================================================================
// UPF pool + load-aware selection (issue #20)
// ============================================================================

/// The process-wide UPF pool. Settable for the same reason as [`PFCP_CLIENT`],
/// and always set together with it so the two cannot disagree about which peer
/// is the default.
static PFCP_POOL: std::sync::RwLock<Vec<Arc<PfcpClient>>> = std::sync::RwLock::new(Vec::new());

/// Install the process-wide UPF pool (at startup, or per test). The first entry
/// is also installed as the process-wide default client, so every legacy
/// single-client path keeps its pre-pool behavior.
pub fn set_global_pool(clients: Vec<Arc<PfcpClient>>) {
    if let Some(first) = clients.first() {
        set_global_client(first.clone());
    }
    if let Ok(mut slot) = PFCP_POOL.write() {
        *slot = clients;
    }
}

/// Uninstall the client and pool, returning the process to its pre-startup state.
///
/// Test-only, and the "release" half of the per-test install the stand-in does:
/// a test that asked for a UPF must not leave one behind for a sibling that
/// expects none, and the sibling would find a client whose runtime has since shut
/// down. Not offered to production — a running SMF has no reason to un-install
/// its own N4 endpoint, and doing so mid-session would strand `SESSION_PEERS`.
#[cfg(test)]
pub(crate) fn clear_global_upf_for_test() {
    if let Ok(mut slot) = PFCP_CLIENT.write() {
        *slot = None;
    }
    if let Ok(mut pool) = PFCP_POOL.write() {
        pool.clear();
    }
}

/// A test's extra delay before the address lookup of one name (#1091 review H). It
/// applies to every client, so a test that sets it holds [`N4_TEST_LOCK`] and
/// clears it before releasing the lock.
#[cfg(test)]
static NODE_LOOKUP_DELAY_FOR_TEST: std::sync::Mutex<Option<(String, Duration)>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn node_lookup_delay_for_test(name: &str) -> Option<Duration> {
    NODE_LOOKUP_DELAY_FOR_TEST
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .filter(|(n, _)| n == name)
        .map(|(_, d)| *d)
}

/// Install `addrs` as a UPF's other addresses, learnt by lookup `generation`, unless a
/// later Association Setup started a newer lookup meanwhile (#1091 review E). The
/// lookups run detached, so after a re-association they can finish in either order;
/// the older set, installed last, would refuse the UPF's new secondary addresses
/// until the next association. Returns whether `addrs` was installed.
fn commit_node_addresses(
    known: &std::sync::RwLock<Vec<std::net::IpAddr>>,
    latest: &std::sync::atomic::AtomicU64,
    generation: u64,
    addrs: Vec<std::net::IpAddr>,
) -> bool {
    let Ok(mut known) = known.write() else {
        return false;
    };
    // Under the write lock: a newer lookup has bumped `latest` before it can write.
    if latest.load(std::sync::atomic::Ordering::SeqCst) != generation {
        log::debug!("a stale UPF address lookup finished after a newer one; dropped");
        return false;
    }
    *known = addrs;
    true
}

/// Report, once at boot, the restored sessions whose UPF is no member of `pool`
/// (#1031): they route to the default UPF, which may not hold them. Returns how
/// many there are, per UPF identity.
pub fn unknown_session_upfs(pool: &[Arc<PfcpClient>]) -> HashMap<String, usize> {
    let keys: Vec<String> = pool.iter().map(|c| c.recovery_time_stamp_key()).collect();
    let mut unknown: HashMap<String, usize> = HashMap::new();
    if let Ok(ctx) = smf_self().read() {
        if let Ok(m) = ctx.session_upfs.read() {
            for key in m.values().filter(|k| !keys.contains(k)) {
                *unknown.entry(key.clone()).or_default() += 1;
            }
        }
    }
    for (key, n) in &unknown {
        log::warn!(
            "{n} restored PFCP session(s) were established on UPF {key}, which is not \
             configured now; they are routed to the default UPF (#1031)"
        );
    }
    unknown
}

/// The process-wide UPF pool (all configured peers); empty until installed.
///
/// Returns an owned snapshot rather than a borrow: the pool is now behind a lock,
/// and a guard must not be held across the `await`s every caller performs.
pub fn global_pool() -> Vec<Arc<PfcpClient>> {
    PFCP_POOL
        .read()
        .map(|pool| pool.clone())
        .unwrap_or_default()
}

/// Session → UPF binding: the SMF's own N4 SEID → PFCP peer address,
/// recorded at session establishment. Modification/deletion of an existing
/// session must keep signalling the UPF the session was established on,
/// which stops being implicit once more than one UPF is configured.
///
/// Keyed by the SMF-side SEID (unique per SM context within this SMF), NOT
/// the UPF-chosen SEID: every UPF allocates its SEIDs independently from 1,
/// so UPF SEIDs collide across a multi-UPF pool.
static SESSION_PEERS: OnceLock<std::sync::RwLock<HashMap<u64, SocketAddr>>> = OnceLock::new();

fn session_peers() -> &'static std::sync::RwLock<HashMap<u64, SocketAddr>> {
    SESSION_PEERS.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// Record which UPF a newly established session lives on (keyed by the
/// SMF-side N4 SEID).
pub fn record_session_peer(smf_n4_seid: u64, peer: SocketAddr) {
    if let Ok(mut map) = session_peers().write() {
        map.insert(smf_n4_seid, peer);
    }
}

/// Forget only the in-memory endpoint record, as a restart does (#1059 tests).
#[cfg(test)]
pub(crate) fn forget_session_endpoint_for_test(smf_n4_seid: u64) {
    if let Ok(mut map) = session_peers().write() {
        map.remove(&smf_n4_seid);
    }
}

/// Drop the session → UPF binding once the session is deleted.
///
/// Takes the SMF context's read guard: never call it while holding that guard (a
/// recursive read on a `std::sync::RwLock` deadlocks behind a queued writer, the
/// #636 class).
pub fn forget_session_peer(smf_n4_seid: u64) {
    if let Ok(mut map) = session_peers().write() {
        map.remove(&smf_n4_seid);
    }
    // #1031: and its durable UPF identity.
    if let Ok(ctx) = smf_self().read() {
        if let Ok(mut map) = ctx.session_upfs.write() {
            map.remove(&smf_n4_seid);
        }
    }
    forget_session_bridge_info(smf_n4_seid);
}

/// Record that the session with SMF-side SEID `smf_n4_seid` was established on
/// `client`'s UPF: its endpoint, for this process, and its identity
/// ([`PfcpClient::recovery_time_stamp_key`]), which the durable snapshot carries
/// (#1031). After a restart only the identity is known, and it also survives a
/// hostname UPF moving to a new address.
pub fn record_session_upf(smf_n4_seid: u64, client: &PfcpClient) {
    record_session_peer(smf_n4_seid, client.peer());
    if let Ok(ctx) = smf_self().read() {
        if let Ok(mut map) = ctx.session_upfs.write() {
            map.insert(smf_n4_seid, client.recovery_time_stamp_key());
        }
    }
}

/// The pool member a session was recorded on (#1031): by its endpoint, else by its
/// durable identity (a session restored from the snapshot, or a hostname UPF that
/// moved). `None` when no record names a current member.
fn recorded_client(smf_n4_seid: u64) -> Option<Arc<PfcpClient>> {
    let pool = global_pool();
    // #1059 round 2, m2: the identity first. An endpoint can be reused: a hostname
    // UPF that moved left its old address to another member, and a session recorded
    // there would route to that one. The endpoint decides only with no identity.
    let key = {
        let ctx = smf_self();
        let key = ctx
            .read()
            .ok()
            .and_then(|ctx| ctx.session_upfs.read().ok()?.get(&smf_n4_seid).cloned());
        key
    };
    if let Some(key) = key {
        return pool
            .into_iter()
            .find(|c| c.recovery_time_stamp_key() == key);
    }
    let peer = session_peers()
        .read()
        .ok()
        .and_then(|map| map.get(&smf_n4_seid).copied())?;
    pool.into_iter().find(|c| c.peer() == peer)
}

/// The 5GS bridge info a TSC-capable UPF reported per session (#321), keyed by the
/// SMF-side N4 SEID for the same collision reason as [`SESSION_PEERS`].
static SESSION_BRIDGE_INFO: OnceLock<
    std::sync::RwLock<HashMap<u64, nextgcore_pfcp::types::CreatedBridgeInfoForTsc>>,
> = OnceLock::new();

fn session_bridge_info(
) -> &'static std::sync::RwLock<HashMap<u64, nextgcore_pfcp::types::CreatedBridgeInfoForTsc>> {
    SESSION_BRIDGE_INFO.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// Record the DS-TT port number and 5GS User Plane Node ID a UPF allocated for a
/// session (TS 29.244 §7.5.3.6).
pub fn record_session_bridge_info(
    smf_n4_seid: u64,
    info: nextgcore_pfcp::types::CreatedBridgeInfoForTsc,
) {
    if let Ok(mut map) = session_bridge_info().write() {
        map.insert(smf_n4_seid, info);
    }
}

/// The recorded bridge info for a session, if the UPF supplied any.
pub fn session_bridge_info_for(
    smf_n4_seid: u64,
) -> Option<nextgcore_pfcp::types::CreatedBridgeInfoForTsc> {
    session_bridge_info()
        .read()
        .ok()
        .and_then(|map| map.get(&smf_n4_seid).copied())
}

/// Drop a session's bridge info. Called from [`forget_session_peer`] rather than
/// separately, so the two maps cannot diverge into a bridge record for a session
/// whose UPF binding is gone.
fn forget_session_bridge_info(smf_n4_seid: u64) {
    if let Ok(mut map) = session_bridge_info().write() {
        map.remove(&smf_n4_seid);
    }
}

/// The most recent TSC Management Information a UPF reported per UPF SEID (#321).
///
/// Keyed by the UPF SEID, unlike the two maps above: a Session Report Request
/// arrives addressed to the SMF with the UPF's own SEID in the header, and that is
/// the only key available at the point the report is decoded.
///
/// Holds the LATEST report rather than a history: a TSC report is a statement of
/// current port configuration, so an older one is superseded rather than additional.
static TSC_REPORTS: OnceLock<
    std::sync::RwLock<HashMap<u64, Vec<nextgcore_pfcp::types::TscManagementInformation>>>,
> = OnceLock::new();

fn tsc_reports(
) -> &'static std::sync::RwLock<HashMap<u64, Vec<nextgcore_pfcp::types::TscManagementInformation>>>
{
    TSC_REPORTS.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// Record the TSC Management Information a Session Report carried.
///
/// An EMPTY report list is not stored: it would be indistinguishable from a decoded
/// report that happened to carry nothing, and the caller already logs the
/// TMIR-without-IE case as the peer contradiction it is.
pub fn record_tsc_report(
    upf_seid: u64,
    reports: Vec<nextgcore_pfcp::types::TscManagementInformation>,
) {
    if reports.is_empty() {
        return;
    }
    if let Ok(mut map) = tsc_reports().write() {
        map.insert(upf_seid, reports);
    }
}

/// The TSC Management Information last reported for a UPF SEID.
pub fn tsc_reports_for(
    upf_seid: u64,
) -> Option<Vec<nextgcore_pfcp::types::TscManagementInformation>> {
    tsc_reports()
        .read()
        .ok()
        .and_then(|map| map.get(&upf_seid).cloned())
}

/// Clear the recorded TSC reports.
///
/// Test-only, and declared BESIDE the map rather than in a `mod tests`: the map is
/// process-global, so a test that mutates it races every sibling that reads it, and
/// a lock declared elsewhere is a second agreement rather than one.
#[cfg(test)]
pub fn clear_tsc_reports_for_test() {
    if let Ok(mut map) = tsc_reports().write() {
        map.clear();
    }
}

/// Resolve the PFCP client serving an EXISTING session by the SMF-side N4
/// SEID. Falls back to the process-wide default client when no binding is
/// recorded; with a single configured UPF that is always the same client,
/// so the legacy behavior is unchanged.
pub fn client_for_session(smf_n4_seid: u64) -> Option<Arc<PfcpClient>> {
    recorded_client(smf_n4_seid).or_else(global_client)
}

/// Pick the UPF for a NEW session (issue #20; UPF load is a TS 23.501
/// §6.3.3 selection input).
///
/// Off by default: without the `compute-aware-upf` cargo feature — or with a
/// pool of at most one UPF — this returns the process-wide default client,
/// i.e. exactly the pre-pool single-client path. With the feature enabled
/// and several UPFs configured it returns the least-loaded *associated*
/// peer, using the metric each UPF reports via Load Control Information on
/// its heartbeat.
///
/// Rel-19 "Compute-Aware Networking" has no frozen Stage-3, so treating the
/// metric as a compute signal (rather than plain session-occupancy load) is
/// a non-normative research prototype.
pub async fn select_upf() -> Option<Arc<PfcpClient>> {
    if !cfg!(feature = "compute-aware-upf") {
        return global_client();
    }
    let pool = global_pool();
    if pool.len() <= 1 {
        return global_client();
    }
    match select_upf_from(&pool).await {
        Some(client) => Some(client),
        None => {
            log::warn!(
                "select_upf: no associated UPF in the pool; falling back to the default peer"
            );
            global_client()
        }
    }
}

/// Whether a NEW session has a UPF to go to: the N4 association [`select_upf`] would
/// use is up (#1112). The same choice as `select_upf`: the default client unless the
/// `compute-aware-upf` feature picks from a pool of several, where any associated
/// peer serves. Synchronous, off the association gauges, so the NRF status watcher
/// can poll it cheaply.
pub fn session_upf_associated() -> bool {
    let pool = global_pool();
    if !cfg!(feature = "compute-aware-upf") || pool.len() <= 1 {
        return global_client().is_some_and(|c| c.is_associated_sync());
    }
    pool.iter().any(|c| c.is_associated_sync())
}

/// Least-loaded-associated selection over an explicit candidate slice.
/// Deliberately NOT feature-gated so the default CI build compiles and
/// tests the full selection path; [`select_upf`] gates whether session
/// establishment actually uses it.
pub async fn select_upf_from(pool: &[Arc<PfcpClient>]) -> Option<Arc<PfcpClient>> {
    let mut candidates = Vec::with_capacity(pool.len());
    for client in pool {
        let assoc = client.association().await;
        candidates.push((assoc.associated, assoc.peer_load));
    }
    select_least_loaded(&candidates).map(|idx| pool[idx].clone())
}

/// Pure selection core: index of the least-loaded associated candidate.
///
/// Each slot is `(associated, reported load)`. Un-associated peers are never
/// selected (TS 29.244 §6.2.6.2: no session signalling without an
/// association). An associated peer that has not reported a metric is
/// eligible but ranked worst (unknown load); ties resolve to the lowest
/// index, so the choice is deterministic.
pub fn select_least_loaded(candidates: &[(bool, Option<u8>)]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, (associated, _))| *associated)
        .min_by_key(|(_, (_, load))| load.map(u16::from).unwrap_or(u16::MAX))
        .map(|(idx, _)| idx)
}

/// A UPF peer as configured in `UPF_PFCP_ADDR` (#20, #658): a literal endpoint,
/// or a hostname the client resolves and keeps re-resolving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpfPeerSpec {
    /// `10.0.0.5`, `10.0.0.5:8806`, `[::1]:8805`
    Literal(SocketAddr),
    /// `upf.nextg-system.svc.cluster.local`, `upf:8806`
    Hostname(String, u16),
}

/// Parse one comma-separated `UPF_PFCP_ADDR` entry. An entry without a port
/// takes `default_port`. Anything that is not a literal address is a hostname;
/// it is NOT resolved here, so a name whose DNS record does not exist yet (a UPF
/// pod that is not Ready) does not stop the SMF from starting (#658).
pub fn parse_upf_peer(entry: &str, default_port: u16) -> Result<UpfPeerSpec, String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err("empty UPF peer".into());
    }
    if let Ok(sa) = entry.parse::<SocketAddr>() {
        return Ok(UpfPeerSpec::Literal(sa));
    }
    if let Ok(ip) = entry.parse::<std::net::IpAddr>() {
        return Ok(UpfPeerSpec::Literal(SocketAddr::new(ip, default_port)));
    }
    let (host, port) = match entry.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| format!("invalid port in UPF peer '{entry}'"))?,
        ),
        None => (entry, default_port),
    };
    let valid = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
    if !valid {
        return Err(format!("invalid UPF peer '{entry}'"));
    }
    Ok(UpfPeerSpec::Hostname(host.to_string(), port))
}

/// Build the client for one configured UPF peer. A hostname is resolved once
/// here on a best-effort basis; when it does not resolve yet the client starts
/// at the unspecified address and [`try_associate`] keeps resolving it.
pub async fn client_for_peer(
    socket: Arc<UdpSocket>,
    spec: &UpfPeerSpec,
    identity: &crate::n4_identity::N4Identity,
) -> PfcpClient {
    let node_ip = identity.f_seid_ipv4;
    match spec {
        UpfPeerSpec::Literal(sa) => {
            PfcpClient::new(socket, *sa, node_ip).with_node_id(identity.node_id.clone())
        }
        UpfPeerSpec::Hostname(host, port) => {
            let unresolved = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), *port);
            let client = PfcpClient::new(socket, unresolved, node_ip)
                .with_node_id(identity.node_id.clone())
                .with_peer_hostname(host.clone(), *port);
            if client.reresolve_peer().await.is_none() {
                log::warn!(
                    "PFCP: UPF hostname {host} does not resolve yet; association will retry it"
                );
            }
            client
        }
    }
}

/// One association attempt for a client that is not associated (#658).
///
/// A UPF named by hostname is re-resolved first, every attempt: a restarted UPF
/// pod comes back at a new address, and the previous one will never answer.
/// Before #658 the endpoint was fixed at startup, so the SMF retried a dead IP
/// forever and rejected every PDU session with #26.
pub async fn try_associate(client: &PfcpClient) -> Result<(), PfcpRequestError> {
    client.reresolve_peer().await;
    client.associate().await
}

impl PfcpClient {
    /// Create a client bound to an existing N4 socket.
    pub fn new(socket: Arc<UdpSocket>, peer: SocketAddr, node_ip: [u8; 4]) -> Self {
        let recovery_time_stamp = smf_recovery_time_stamp();
        Self {
            socket,
            peer: std::sync::RwLock::new(peer),
            peer_host: None,
            node_ip,
            node_id: NodeId::new_ipv4(node_ip),
            recovery_time_stamp,
            node_addrs: Arc::new(std::sync::RwLock::new(Vec::new())),
            node_addrs_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pending: Mutex::new(HashMap::new()),
            assoc: RwLock::new(AssociationState::default()),
            associated_gauge: std::sync::atomic::AtomicBool::new(false),
            timers: SmfTimerConfigs::default(),
        }
    }

    /// Republish the sync-readable association gauge from the guard's own value.
    ///
    /// Takes the write guard so it can only be called from inside a critical section
    /// that already holds `assoc` — a projection computed outside the lock could
    /// publish a state the association no longer has. Assignment rather than
    /// set/clear, for the same reason.
    fn publish_associated(&self, assoc: &AssociationState) {
        self.associated_gauge
            .store(assoc.associated, Ordering::Relaxed);
    }

    /// Whether the N4 association is up, readable from a synchronous context
    /// (the Prometheus render; #380).
    ///
    /// The async [`Self::is_associated`] remains the authority; this is its
    /// projection, and the two are kept in step by [`Self::publish_associated`].
    pub fn is_associated_sync(&self) -> bool {
        self.associated_gauge.load(Ordering::Relaxed)
    }

    /// Name the UPF by hostname (#658). `peer` passed to [`Self::new`] is then
    /// only the first resolution — or the unspecified address when the name did
    /// not resolve yet — and [`Self::reresolve_peer`] refreshes it.
    pub fn with_peer_hostname(mut self, host: impl Into<String>, port: u16) -> Self {
        self.peer_host = Some((host.into(), port));
        self
    }

    /// Test-only: shorten Association Setup's T1/N1 so a silent peer fails fast.
    #[cfg(test)]
    pub(crate) fn with_association_timer_for_test(mut self, t1: Duration, n1: u32) -> Self {
        self.timers.pfcp_association.duration = t1;
        self.timers.pfcp_association.max_count = n1;
        self
    }

    /// The UPF endpoint this client talks to.
    pub fn peer(&self) -> SocketAddr {
        *self.peer.read().unwrap_or_else(|e| e.into_inner())
    }

    /// The hostname this client re-resolves, if the UPF was named rather than
    /// addressed.
    pub fn peer_hostname(&self) -> Option<&str> {
        self.peer_host.as_ref().map(|(h, _)| h.as_str())
    }

    /// Whether `peer` holds a usable address. A hostname that did not resolve
    /// at startup leaves the unspecified address in place; nothing is sent to it.
    pub fn has_resolved_peer(&self) -> bool {
        !self.peer().ip().is_unspecified()
    }

    /// Resolve the configured hostname again and adopt the new address if it
    /// moved (#658). Returns the new endpoint when it changed, `None` when there
    /// is no hostname, the lookup failed, or the address is the same.
    ///
    /// Sessions bound to the old address are not flushed here: the new endpoint
    /// is either the same UPF (same Recovery Time Stamp, sessions intact) or a
    /// new incarnation, and the next Association Setup's Recovery Time Stamp
    /// check (`check_peer_restart`) already tears the old sessions down and
    /// notifies the AMFs in that case. IPv4 is preferred because the Node ID this
    /// client sends is IPv4.
    pub async fn reresolve_peer(&self) -> Option<SocketAddr> {
        let (host, port) = self.peer_host.as_ref()?;
        let resolved = match tokio::net::lookup_host((host.as_str(), *port)).await {
            Ok(addrs) => {
                let addrs: Vec<SocketAddr> = addrs.collect();
                addrs
                    .iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| addrs.first())
                    .copied()
            }
            Err(e) => {
                log::warn!("PFCP: resolving UPF hostname {host}:{port} failed: {e}");
                None
            }
        }?;
        let previous = {
            let mut peer = self.peer.write().unwrap_or_else(|e| e.into_inner());
            if *peer == resolved {
                return None;
            }
            std::mem::replace(&mut *peer, resolved)
        };
        if previous.ip().is_unspecified() {
            log::info!("PFCP: UPF hostname {host} resolves to {resolved}");
        } else {
            log::warn!("PFCP: UPF hostname {host} now resolves to {resolved} (was {previous})");
        }
        Some(resolved)
    }

    /// The IPv4 address of this SMF's CP F-SEID (#797: not necessarily the Node ID).
    pub fn node_ip(&self) -> [u8; 4] {
        self.node_ip
    }

    /// The PFCP Node ID this SMF signals (TS 29.244 §8.2.38).
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Signal `node_id` as this SMF's PFCP Node ID instead of the F-SEID address
    /// (#797).
    pub fn with_node_id(mut self, node_id: NodeId) -> Self {
        self.node_id = node_id;
        self
    }

    /// The listener's view of this UPF: the endpoint, and its other addresses.
    pub fn n4_peer(&self) -> N4Peer {
        N4Peer {
            endpoint: self.peer(),
            addrs: self
                .node_addrs
                .read()
                .map(|a| a.clone())
                .unwrap_or_default(),
        }
    }

    /// Whether `from` is this UPF: its endpoint's address, or one of the others
    /// (TS 29.244 §5.8.1).
    pub fn is_node_address(&self, from: SocketAddr) -> bool {
        self.n4_peer().is_node(from)
    }

    /// Learn the UPF's addresses (TS 29.244 §5.8.1): the Node ID's own address, or
    /// what its FQDN resolves to, and what the configured hostname resolves to. Each
    /// lookup is bounded, and one that fails leaves the endpoint's address alone.
    fn learn_node_addresses(&self, node_id: &NodeId) -> tokio::task::JoinHandle<()> {
        // #974 review n4: in its own task, so the association task, which serves
        // every UPF, never waits on a DNS lookup.
        let mut addrs: Vec<std::net::IpAddr> = Vec::new();
        if let Some(v4) = node_id.ipv4_addr {
            addrs.push(std::net::IpAddr::from(v4));
        }
        if let Some(v6) = node_id.ipv6_addr {
            addrs.push(std::net::IpAddr::from(v6));
        }
        let mut names: Vec<String> = Vec::new();
        if let Some(fqdn) = node_id.fqdn.as_deref().filter(|f| !f.is_empty()) {
            names.push(fqdn.trim_end_matches('.').to_string());
        }
        if let Some((host, _)) = &self.peer_host {
            names.push(host.clone());
        }
        let known = self.node_addrs.clone();
        let latest = self.node_addrs_generation.clone();
        let generation = latest.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let own = self.peer();
        tokio::spawn(async move {
            for name in names {
                #[cfg(test)]
                if let Some(delay) = node_lookup_delay_for_test(&name) {
                    tokio::time::sleep(delay).await;
                }
                let lookup = tokio::net::lookup_host((name.as_str(), PFCP_PORT));
                if let Ok(Ok(found)) = tokio::time::timeout(Duration::from_secs(2), lookup).await {
                    addrs.extend(found.map(|a| a.ip()));
                }
            }
            // #974 review n2: an address another pool member is dialled at is that
            // member's, never this one's: a shared Service name, or a Node ID naming
            // a sibling, must not let this UPF vouch for it.
            let others: Vec<std::net::IpAddr> = global_pool()
                .iter()
                .map(|c| c.peer())
                .filter(|p| *p != own)
                .map(|p| p.ip().to_canonical())
                .collect();
            let mut addrs: Vec<std::net::IpAddr> = addrs
                .into_iter()
                .map(|a| a.to_canonical())
                .filter(|a| !others.contains(a))
                .collect();
            addrs.sort();
            addrs.dedup();
            commit_node_addresses(&known, &latest, generation, addrs);
        })
    }

    /// Whether the N4 association is currently established.
    pub async fn is_associated(&self) -> bool {
        self.assoc.read().await.associated
    }

    /// Snapshot of the association state.
    pub async fn association(&self) -> AssociationState {
        self.assoc.read().await.clone()
    }

    /// Test-only: install a stored peer Recovery Time Stamp, as an earlier Heartbeat
    /// would have (#966: the stamp is volatile, TS 23.007 §19A, so nothing installs
    /// one outside a Heartbeat).
    #[cfg(test)]
    pub(crate) async fn seed_peer_recovery_time_stamp(&self, rts: u32) {
        self.assoc.write().await.peer_recovery_time_stamp = Some(rts);
    }

    /// Test-only: force association/load state. Unit tests cannot run the
    /// full Association Setup handshake for every selection scenario.
    #[cfg(test)]
    /// The peer Recovery Time Stamp stored for this UPF.
    #[cfg(test)]
    pub(crate) async fn peer_recovery_time_stamp_for_test(&self) -> Option<u32> {
        self.assoc.read().await.peer_recovery_time_stamp
    }

    /// Set the UPF's other addresses, as an Association Setup would learn them.
    #[cfg(test)]
    pub(crate) fn set_node_addresses_for_test(&self, addrs: Vec<std::net::IpAddr>) {
        if let Ok(mut known) = self.node_addrs.write() {
            *known = addrs;
        }
    }

    pub(crate) async fn set_assoc_state_for_test(
        &self,
        associated: bool,
        peer_load: Option<u8>,
        peer_load_seq: Option<u32>,
    ) {
        let mut assoc = self.assoc.write().await;
        assoc.associated = associated;
        assoc.peer_load = peer_load;
        assoc.peer_load_seq = peer_load_seq;
        // The projection is published here too, so a test that forces association state
        // sees the same gauge the wire path would produce.
        self.publish_associated(&assoc);
    }

    /// T1/N1 parameters for a given request type.
    fn retransmit_params(&self, msg_type: u8) -> (Duration, u32) {
        let cfg = match msg_type {
            pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST
            | pfcp_message_type::SESSION_MODIFICATION_REQUEST => {
                &self.timers.pfcp_no_establishment_response
            }
            pfcp_message_type::SESSION_DELETION_REQUEST => &self.timers.pfcp_no_deletion_response,
            pfcp_message_type::HEARTBEAT_REQUEST => &self.timers.pfcp_no_heartbeat,
            _ => &self.timers.pfcp_association,
        };
        (cfg.duration, cfg.max_count)
    }

    /// Send a request and wait for the matching response, retransmitting on
    /// T1 expiry up to N1 times (TS 29.244 7.2.1). Returns the response
    /// message type and body.
    pub async fn request(
        &self,
        msg_type: u8,
        seid: Option<u64>,
        body: &[u8],
    ) -> Result<(u8, Vec<u8>), PfcpRequestError> {
        self.request_on(msg_type, seid, body).await.0
    }

    /// [`Self::request`], and the association generation the request was last sent on
    /// (#966 follow-up 2): read as each (re)transmission leaves, so an association set
    /// up between the caller's decision and the send is the one the answer is about.
    async fn request_on(
        &self,
        msg_type: u8,
        seid: Option<u64>,
        body: &[u8],
    ) -> (Result<(u8, Vec<u8>), PfcpRequestError>, u64) {
        let mut sent_on = self.assoc.read().await.generation;
        let result = self
            .request_sent_on(msg_type, seid, body, &mut sent_on)
            .await;
        (result, sent_on)
    }

    async fn request_sent_on(
        &self,
        msg_type: u8,
        seid: Option<u64>,
        body: &[u8],
        sent_on: &mut u64,
    ) -> Result<(u8, Vec<u8>), PfcpRequestError> {
        let seq = crate::PFCP_SEQ.fetch_add(1, Ordering::Relaxed) & 0x00FF_FFFF;
        let pkt = encode_wire_message(msg_type, seid, seq, body);
        let (t1, n1) = self.retransmit_params(msg_type);

        // attempts = first transmission + up to N1 retransmissions
        let max_attempts = n1 + 1;
        let mut attempt = 0u32;

        let peer = self.peer();
        if peer.ip().is_unspecified() {
            return Err(PfcpRequestError::Local(format!(
                "UPF {} has not resolved to an address yet",
                self.peer_hostname().unwrap_or("peer")
            )));
        }

        let result = loop {
            attempt += 1;

            // (Re-)register the response slot for this sequence number
            let (tx, rx) = oneshot::channel();
            self.pending.lock().await.insert(seq, tx);

            *sent_on = self.assoc.read().await.generation;
            if let Err(e) = self.socket.send_to(&pkt, peer).await {
                self.pending.lock().await.remove(&seq);
                break Err(PfcpRequestError::Local(format!("send failed: {e}")));
            }
            if attempt > 1 {
                log::warn!(
                    "PFCP T1 expired: retransmitting type={msg_type} seq={seq} \
                     (attempt {attempt}/{max_attempts})"
                );
            }

            match tokio::time::timeout(t1, rx).await {
                Ok(Ok((resp_type, resp_body))) => break Ok((resp_type, resp_body)),
                Ok(Err(_)) => break Err(PfcpRequestError::Local("response channel closed".into())),
                Err(_) => {
                    // T1 expired
                    self.pending.lock().await.remove(&seq);
                    if attempt >= max_attempts {
                        log::error!(
                            "PFCP request type={msg_type} seq={seq} exhausted \
                             {max_attempts} attempts — peer {peer} unreachable"
                        );
                        break Err(PfcpRequestError::Timeout {
                            attempts: max_attempts,
                        });
                    }
                }
            }
        };

        // Exhaustion abnormal action: a node-level silence means the peer is
        // gone — drop the association so new sessions are refused until the
        // association is re-established.
        if matches!(result, Err(PfcpRequestError::Timeout { .. })) {
            let mut assoc = self.assoc.write().await;
            if assoc.associated {
                log::error!("Marking PFCP association with {peer} as DOWN");
                assoc.associated = false;
            }
            // #966 review m3: the remote stamp belongs to the association (TS 23.007
            // §19A, volatile); with it gone, the next Heartbeat or Association Setup
            // starts from none. Kept, an unsolicited Heartbeat Request while
            // unassociated was compared with the old incarnation's stamp, and its
            // "restart" released the sessions before retention could keep them.
            assoc.peer_recovery_time_stamp = None;
            self.publish_associated(&assoc);
        }

        result
    }

    /// A session-level request (Establishment, Modification, Deletion) for the
    /// session with SMF-side SEID `smf_seid`: [`Self::request`], and then the GTP-U
    /// peers of its FARs are learnt from the request the UPF accepted (#994).
    pub async fn session_request(
        &self,
        msg_type: u8,
        smf_seid: u64,
        upf_seid: Option<u64>,
        body: &[u8],
    ) -> Result<(u8, Vec<u8>), PfcpRequestError> {
        // #966 follow-up 2: the generation as the request left, not as this was called.
        let (result, generation) = self.request_on(msg_type, upf_seid, body).await;
        if let Ok((_, response)) = &result {
            crate::up_path::note_session_request(smf_seid, msg_type, body, response);
            // #966 review M1, TS 29.244 §8.2.1 cause 72 "No established PFCP
            // Association": the UP function holds no association with this CP function,
            // so none of its sessions either. A UPF that restarted after the Association
            // Setup and before the association's first Heartbeat is found here: its
            // Heartbeats carry only the new incarnation's stamp, which is that
            // association's baseline, and nothing else would ever notice.
            if find_ie(response, 19).and_then(|v| v.first().copied())
                == Some(nextgcore_pfcp::types::PfcpCause::NoEstablishedPfcpAssociation as u8)
            {
                self.association_lost(
                    generation,
                    "the UPF answered cause 72, No established PFCP Association",
                )
                .await;
            }
        }
        result
    }

    /// The UPF no longer has the association `generation` (#966 review M1): tear it
    /// down once, releasing this UPF's sessions, so the association loop sets it up
    /// again. #966 follow-up: only that association. A cause 72 answering a request sent
    /// before a re-association (a retransmission's late answer, or one the old
    /// incarnation sent as it went) says nothing about the association set up since.
    async fn association_lost(&self, generation: u64, reason: &str) {
        let was_associated = {
            let mut assoc = self.assoc.write().await;
            if assoc.generation != generation {
                log::info!(
                    "PFCP: {} answered a request of an earlier association ({reason}); the \
                     current one is kept",
                    self.peer()
                );
                return;
            }
            std::mem::replace(&mut assoc.associated, false)
        };
        if was_associated {
            log::error!("PFCP association with {} lost: {reason}", self.peer());
            track_restart_fanout(self.begin_teardown(reason).await);
        }
    }

    /// Feed an incoming datagram into the engine. Returns true when the
    /// datagram was consumed (response to a pending request, or a node-level
    /// request that was handled here).
    pub async fn on_datagram(&self, pkt: &[u8], from: SocketAddr) -> bool {
        let header = match parse_wire_header(pkt) {
            Some(h) => h,
            None => return false,
        };

        // Version check (TS 29.244 7.2.2): only v1 is supported
        if header.version != 1 {
            log::warn!("PFCP version {} from {from} not supported", header.version);
            let resp = encode_wire_message(
                pfcp_message_type::VERSION_NOT_SUPPORTED_RESPONSE,
                None,
                header.sequence_number,
                &[],
            );
            let _ = self.socket.send_to(&resp, from).await;
            return true;
        }

        let body = &pkt[header.body_offset.min(pkt.len())..];

        // Responses: complete the matching pending transaction
        if is_response_type(header.msg_type) {
            if let Some(tx) = self.pending.lock().await.remove(&header.sequence_number) {
                let _ = tx.send((header.msg_type, body.to_vec()));
                return true;
            }
            log::debug!(
                "PFCP response type={} seq={} with no pending transaction",
                header.msg_type,
                header.sequence_number
            );
            return true;
        }

        // Node-level requests handled by the engine
        match header.msg_type {
            pfcp_message_type::HEARTBEAT_REQUEST => {
                // Issue #20: the UPF may piggy-back its load metric (Load
                // Control Information) on the heartbeat. Store it for
                // load-aware selection, discarding stale sequence numbers.
                {
                    let mut body_bytes = Bytes::copy_from_slice(body);
                    if let Ok(hb) = HeartbeatRequest::decode(&mut body_bytes) {
                        if let Some(lci) = hb.load_control_information {
                            let mut assoc = self.assoc.write().await;
                            let newer = match assoc.peer_load_seq {
                                Some(seq) => lci.sequence_number >= seq,
                                None => true,
                            };
                            if newer {
                                assoc.peer_load = Some(lci.metric.min(100));
                                assoc.peer_load_seq = Some(lci.sequence_number);
                            }
                        }
                    }
                }
                let msg = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(
                    self.recovery_time_stamp,
                ));
                let resp = build_message(&msg, header.sequence_number, None);
                if let Err(e) = self.socket.send_to(&resp, from).await {
                    log::warn!("Failed to send Heartbeat Response: {e}");
                } else {
                    log::debug!("Heartbeat Response sent to {from}");
                }
                // #721: staleness detection on the peer's Recovery Time Stamp, AFTER
                // the response: the restarted UPF must not declare this SMF dead
                // while its sessions are released, and the releases themselves run
                // off this task.
                //
                // #928 review M3: and only for this client's own UPF. TS 23.007 §19A
                // associates the stamp with the PFCP entity at the message's source
                // address; a Heartbeat Request from anyone else is answered (above, as
                // §19A requires even for unknown peers) but tears nothing down. The
                // listener's gate (#971) already hands this client only its own UPF's
                // datagrams; this is the second layer behind it.
                if self.is_node_address(from) {
                    if let Some(rts) = find_ie(body, 96)
                        .filter(|v| v.len() >= 4)
                        .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
                    {
                        self.check_peer_restart_detached(rts, StampSource::Request)
                            .await;
                    }
                }
                true
            }
            pfcp_message_type::ASSOCIATION_RELEASE_REQUEST => {
                // #928 review M3: only the associated UPF can release its association.
                // Behind the #971 gate, which already refuses a stranger's release
                // with the same cause 72 (TS 29.244 §8.2.1).
                let ours = self.is_node_address(from);
                log::warn!(
                    "PFCP Association Release Request from {from}{}",
                    if ours {
                        ""
                    } else {
                        " (not this association's UPF: refused)"
                    }
                );
                let cause = if ours {
                    nextgcore_pfcp::types::PfcpCause::RequestAccepted
                } else {
                    nextgcore_pfcp::types::PfcpCause::NoEstablishedPfcpAssociation
                };
                let msg = PfcpMessage::AssociationReleaseResponse(
                    nextgcore_pfcp::message::AssociationReleaseResponse::new(
                        self.node_id.clone(),
                        cause,
                    ),
                );
                let resp = build_message(&msg, header.sequence_number, None);
                let _ = self.socket.send_to(&resp, from).await;
                if ours {
                    // #721: the per-session releases run off the receive task.
                    track_restart_fanout(self.begin_teardown("association released by peer").await);
                }
                true
            }
            pfcp_message_type::NODE_REPORT_REQUEST => {
                // #994, TS 29.244 §6.2.9.3: answer, then "process the information being
                // reported as appropriate". Only from this association's UPF, like the
                // Release above; anyone else has no association here (§8.2.1).
                // Behind the #971 gate, which refuses a stranger's Node Report with
                // the same cause 72; any address of this UPF (§5.8.1) is its own.
                let ours = self.is_node_address(from);
                let decoded = if ours {
                    crate::up_path::parse_node_report(body)
                } else {
                    Err((crate::up_path::cause::NO_ESTABLISHED_PFCP_ASSOCIATION, 0))
                };
                let (cause, offending) = match &decoded {
                    Ok(_) => (crate::up_path::cause::REQUEST_ACCEPTED, None),
                    Err((cause, 0)) => (*cause, None),
                    Err((cause, ie)) => (*cause, Some(*ie)),
                };
                if cause != crate::up_path::cause::REQUEST_ACCEPTED {
                    log::warn!(
                        "PFCP Node Report Request from {from} refused: cause {cause} ({}){}",
                        cause_name(cause),
                        offending.map(|ie| format!(", IE {ie}")).unwrap_or_default()
                    );
                }
                let resp = crate::up_path::node_report_response(
                    header.sequence_number,
                    &self.node_id,
                    cause,
                    offending,
                );
                let _ = self.socket.send_to(&resp, from).await;
                if let Ok(report) = decoded {
                    crate::up_path::on_node_report(
                        &self.recovery_time_stamp_key(),
                        self.session_scope(),
                        report,
                    );
                }
                true
            }
            _ => false, // e.g. Session Report Request — handled by main.rs
        }
    }

    /// Compare a peer Recovery Time Stamp with the stored value; a change
    /// means the UPF restarted: all sessions on it are gone (TS 23.527 4.2).
    pub async fn check_peer_restart(&self, rts: u32) {
        if let Some(releases) = self.detect_peer_restart(rts, StampSource::Response).await {
            let _ = releases.await;
        }
    }

    /// [`Self::check_peer_restart`] for the N4 receive task (#721): the teardown
    /// itself (association down, this UPF's sessions flushed) is done when this
    /// returns, but the per-session releases run on in their own task. Awaiting them
    /// here stalled every PFCP message from every UPF for the whole fan-out.
    async fn check_peer_restart_detached(&self, rts: u32, source: StampSource) {
        if let Some(releases) = self.detect_peer_restart(rts, source).await {
            track_restart_fanout(releases);
        }
    }

    /// Detect a peer restart and tear the association down. `Some(fan-out)` when a
    /// restart was detected, the per-session releases still running in it.
    async fn detect_peer_restart(
        &self,
        rts: u32,
        source: StampSource,
    ) -> Option<tokio::task::JoinHandle<()>> {
        // TS 29.244 §8.2.65: NTP-era seconds, compared as sent (#1033).
        //
        // TS 23.007 §19A, under one write guard (#928 review m2): the new stamp is
        // stored at once, so a second path seeing the same stamp (the receive task's
        // Heartbeat Request and the maintenance task's Heartbeat Response) finds it
        // stored and tears nothing down twice. With none stored, the received one is
        // stored.
        //
        // Which change is a restart (#928 round 2, B1):
        // - in the RESPONSE to our own request, any change: the UPF answering now is a
        //   different incarnation, whatever its clock says. Discarding a smaller stamp
        //   there kept a UPF that came back with its clock behind, or past the 2036
        //   wrap, "associated" for good, with every new session refused;
        // - in an unsolicited Heartbeat REQUEST, a stamp NEWER than the stored one in
        //   serial arithmetic (RFC 1982, so the 2036 wrap counts as newer). An older
        //   one is "a possible race condition (newer message arriving before the older
        //   one)": discarded and logged.
        let restarted = {
            let mut assoc = self.assoc.write().await;
            match assoc.peer_recovery_time_stamp {
                Some(stored) if rts == stored => false,
                Some(stored) => match source {
                    StampSource::Response => {
                        assoc.peer_recovery_time_stamp = Some(rts);
                        true
                    }
                    StampSource::Request if stamp_is_newer(rts, stored) => {
                        assoc.peer_recovery_time_stamp = Some(rts);
                        true
                    }
                    // #1004 review: a stored start time in the FUTURE came from a wrong
                    // clock, or from a UPF that does not send NTP-era seconds (a 0.1.x
                    // nextgcore's Unix seconds read as ~2096, #1033). No real earlier
                    // incarnation can be newer than it, so the reorder rule below would
                    // mask every later restart: a differing stamp is a restart.
                    StampSource::Request
                        if nextgcore_pfcp::recovery_time::is_in_the_future(
                            stored,
                            nextgcore_pfcp::recovery_time::now(),
                        ) =>
                    {
                        log::warn!(
                            "UPF {}: stored Recovery Time Stamp {stored} is in the future (a \
                             clock that was not set); {rts} is taken as a restart",
                            self.peer()
                        );
                        assoc.peer_recovery_time_stamp = Some(rts);
                        true
                    }
                    StampSource::Request => {
                        log::error!(
                            "UPF {}: Recovery Time Stamp {rts} in a Heartbeat Request is older \
                             than the stored {stored}; discarded as a reordered message \
                             (TS 23.007 §19A)",
                            self.peer()
                        );
                        false
                    }
                },
                None => {
                    assoc.peer_recovery_time_stamp = Some(rts);
                    false
                }
            }
        };
        if !restarted {
            return None;
        }
        log::error!(
            "UPF {} restarted (recovery time stamp changed to {rts})",
            self.peer()
        );
        // The teardown clears the stored stamp with the association (#966 review m3):
        // the next association's first Heartbeat is its baseline.
        let releases = self.begin_teardown("peer restarted").await;
        Some(releases)
    }

    /// Mark the association down and flush all PFCP session state.
    ///
    /// #193: the consumers are told BEFORE the flush. Every PDU session on this
    /// UPF is gone (TS 23.527 §4.2), and the AMF holds an `smContextStatusUri`
    /// for each one; the join from session to callback runs through the map this
    /// is about to empty, so notifying afterwards would have nobody to notify.
    /// Previously this cleared the map, logged a count, and left every AMF
    /// believing in contexts that could not carry a packet.
    async fn teardown_association(&self, reason: &str) {
        let releases = self.begin_teardown(reason).await;
        let _ = releases.await;
    }

    /// [`Self::teardown_association`] whose #39 fan-out stops at `deadline` (#941
    /// review M1). Only the fan-out is bounded: the EPC PDN connections are told
    /// first (their Delete Bearer Requests do not wait for answers), and the
    /// association-down step and the flush always run.
    async fn teardown_association_until(
        &self,
        reason: &str,
        deadline: Option<tokio::time::Instant>,
    ) {
        let releases = self.begin_teardown_until(reason, deadline).await;
        let _ = releases.await;
    }

    /// [`Self::teardown_association`] up to the per-session releases, which are
    /// returned still running (#721).
    async fn begin_teardown(&self, reason: &str) -> tokio::task::JoinHandle<()> {
        self.begin_teardown_until(reason, None).await
    }

    /// [`Self::begin_teardown`] whose fan-out abandons what it has not sent by
    /// `deadline` (#941 review M1).
    async fn begin_teardown_until(
        &self,
        reason: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> tokio::task::JoinHandle<()> {
        #[cfg(test)]
        assert_teardown_is_serialised();
        #[cfg(test)]
        TEARDOWNS_FOR_TEST.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        {
            let hold = TEARDOWN_HOLD_FOR_TEST
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some((reached, proceed)) = hold {
                reached.notify_one();
                proceed.notified().await;
            }
        }
        // #720: only the sessions on THIS UPF. A pool member's restart, release or
        // heartbeat loss says nothing about the sessions on the other members, which
        // are alive; releasing them sent every UE in the pool a #39 and orphaned
        // their sessions on the healthy UPFs.
        let scope = self.session_scope();
        // #687: the EPC PDN connections on this PGW-U, which have no SM context. First,
        // so no fan-out deadline can cut them (#941 review M1).
        let epc_released =
            crate::restoration::release_epc_pdn_connections_in(reason, Some(&scope)).await;
        let (notified, releases) =
            crate::restoration::begin_unrecoverable_release(reason, Some(&scope), deadline);
        {
            let mut assoc = self.assoc.write().await;
            assoc.associated = false;
            // #966 review m3: the remote stamp goes with the association (TS 23.007
            // §19A); see `request`.
            assoc.peer_recovery_time_stamp = None;
            // Issue #20: a restarted UPF restarts its LCI sequence counter
            // from 1, so the stored high-watermark would reject every fresh
            // (low-seq) load report. Clear the load state so the first
            // post-restart report (peer_load_seq == None) is accepted.
            assoc.peer_load = None;
            assoc.peer_load_seq = None;
            self.publish_associated(&assoc);
        }
        let cleared = clear_pfcp_sessions_in(&scope);
        log::warn!(
            "PFCP association with {} torn down ({reason}); {cleared} stale sessions flushed, \
             {notified} AMF status callback(s) notified, {epc_released} EPC PDN \
             connection(s) deleted toward the SGW",
            self.peer()
        );
        releases
    }

    /// Run the PFCP Association Setup procedure (TS 29.244 6.2.6).
    pub async fn associate(&self) -> Result<(), PfcpRequestError> {
        let mut req = AssociationSetupRequest::new(self.node_id.clone(), self.recovery_time_stamp);
        // CP Function Features: none of the optional CP features (LOAD,
        // OVRL, …) are implemented, so all bits are honestly zero.
        req.cp_function_features = Some(CpFunctionFeatures::default());
        let msg = PfcpMessage::AssociationSetupRequest(req);
        let mut buf = bytes::BytesMut::new();
        msg.encode_body(&mut buf);
        // #718, TS 29.244 §6.2.6.2.1: a CP function that holds PFCP sessions asks
        // the UP function to keep them. Without the IE a conformant UP function
        // deletes every session of an existing association for this Node ID
        // (§6.2.6.2.2). That is right for a fresh incarnation, which knows none of
        // them, and wrong for one that restored them from durable state, or for this
        // same incarnation re-associating after a lost heartbeat. Empty, so every
        // session is kept (Table 7.4.4.1-2): the IE's CP PFCP Entity IP Addresses
        // name CP F-SEID addresses, and every session here carries this one node's.
        let retention_requested = holds_pfcp_sessions_on(self);
        if retention_requested {
            buf.put_u16(PFCP_SESSION_RETENTION_INFORMATION);
            buf.put_u16(0);
        }

        let (resp_type, resp_body) = self
            .request(pfcp_message_type::ASSOCIATION_SETUP_REQUEST, None, &buf)
            .await?;

        if resp_type != pfcp_message_type::ASSOCIATION_SETUP_RESPONSE {
            return Err(PfcpRequestError::Local(format!(
                "unexpected response type {resp_type} to Association Setup"
            )));
        }

        let mut body = Bytes::copy_from_slice(&resp_body);
        let resp = AssociationSetupResponse::decode(&mut body)
            .map_err(|e| PfcpRequestError::Local(format!("malformed response: {e}")))?;

        if resp.cause != nextgcore_pfcp::types::PfcpCause::RequestAccepted {
            return Err(PfcpRequestError::Rejected {
                cause: resp.cause as u8,
            });
        }

        drop(self.learn_node_addresses(&resp.node_id));
        // #966, TS 23.007 §19A and TS 29.244 Table 7.4.4.2-1 NOTE: "A PFCP function
        // shall ignore the Recovery Timestamp received in PFCP Association Setup
        // Request and PFCP Association Setup Response messages". Neither compared nor
        // stored: this is a new association, and the stamp a previous one stored is
        // cleared, so the first Heartbeat stamp of this one is the baseline (§19A, "If
        // no previous value was stored"). Kept, the old stamp made that first Heartbeat
        // of a restarted UPF a second "restart", releasing the sessions established
        // since this Association Setup.
        //
        // Whether a new incarnation answers is the session retention's question
        // (#718): asked for and not confirmed (PSREI, TS 29.244 §8.2.134), the UP
        // function deleted the sessions, or never had them. Believing them anyway
        // would leave every one dead until the UE noticed, so release them as a
        // restart would.
        if retention_requested && !sessions_retained(&resp_body) {
            log::warn!(
                "UPF {} did not retain the PFCP sessions this SMF holds (no PSREI in the \
                 Association Setup Response)",
                self.peer()
            );
            track_restart_fanout(self.begin_teardown("UPF did not retain the sessions").await);
        }

        {
            let mut assoc = self.assoc.write().await;
            assoc.associated = true;
            assoc.generation = assoc.generation.wrapping_add(1);
            assoc.peer_recovery_time_stamp = None;
            assoc.up_function_features = resp.up_function_features;
            self.publish_associated(&assoc);
            log::info!(
                "PFCP association established with {} (UP features={:?})",
                self.peer(),
                assoc
                    .up_function_features
                    .as_ref()
                    .map(|f| (f.ftup, f.empu, f.bucp))
            );
        }
        Ok(())
    }

    /// This UPF's durable identity (#722): the configured `host:port` for a UPF
    /// named by hostname, the address otherwise. The key durable per-UPF state is
    /// recorded under (a session's UPF, #1031; the failed GTP-U peers a Node Report
    /// named, #994).
    ///
    /// Keyed by the resolved address, a UPF that moved while the SMF was down (a pod
    /// rescheduled in the same node drain), or whose name did not resolve yet at
    /// startup (`0.0.0.0:8805`), would not be found again. The name is lower-cased and
    /// loses a trailing root dot, so a cosmetic configuration edit keeps it (#930
    /// review m2). The function keeps its historical name: it keyed the durable Recovery
    /// Time Stamp until #966 made that stamp volatile (TS 23.007 §19A).
    pub fn recovery_time_stamp_key(&self) -> String {
        match &self.peer_host {
            Some((host, port)) => {
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                format!("{host}:{port}")
            }
            None => self.peer().to_string(),
        }
    }

    /// Run the PFCP Association Release procedure (TS 29.244 §6.2.8).
    pub async fn release_association(&self) -> Result<(), PfcpRequestError> {
        self.release_association_within(None).await
    }

    /// [`Self::release_association`] with the local teardown's #39 fan-out bounded by
    /// `teardown_budget` (#809 follow-up, #941 review M1).
    ///
    /// At shutdown the whole sequence must fit the termination grace period. With a
    /// blackholed AMF each release waits out its connect and request timeouts, and
    /// thousands of them at 16 in flight would run for minutes, past the SIGKILL, and
    /// the Association Release would never be sent. When the budget runs out the
    /// remaining #39s are abandoned (counted in the log); the EPC Delete Bearers, the
    /// association-down step and the flush run regardless, and the Association
    /// Release still goes to the UPF, which deletes the sessions.
    pub async fn release_association_within(
        &self,
        teardown_budget: Option<Duration>,
    ) -> Result<(), PfcpRequestError> {
        if !self.is_associated().await {
            return Ok(());
        }
        // TS 29.244 §6.2.8.2 has the CP function delete the association's sessions on
        // a successful Association Release Response. This SMF deletes them locally
        // FIRST, before the request, deliberately (#718 review m5): the UEs (#39) and
        // the SGWs (Delete Bearer) are then told before the request waits on the UPF,
        // up to T1 x (N1+1) = 12 s when the UPF is gone, which a short termination
        // grace period cut off. The UPF's own deletion is unchanged.
        self.teardown_association_until(
            "association release requested locally",
            teardown_budget.map(|budget| tokio::time::Instant::now() + budget),
        )
        .await;
        let msg = PfcpMessage::AssociationReleaseRequest(AssociationReleaseRequest::new(
            self.node_id.clone(),
        ));
        let mut buf = bytes::BytesMut::new();
        msg.encode_body(&mut buf);

        let result = self
            .request(pfcp_message_type::ASSOCIATION_RELEASE_REQUEST, None, &buf)
            .await;

        match result {
            Ok((_, body)) => match parse_cause(&body) {
                Some(pfcp_cause::REQUEST_ACCEPTED) | None => Ok(()),
                Some(cause) => Err(PfcpRequestError::Rejected { cause }),
            },
            Err(e) => Err(e),
        }
    }

    /// Send one Heartbeat Request and validate the response (TS 29.244
    /// 6.2.2). Returns Ok(true) if the peer is alive, Err on timeout.
    pub async fn heartbeat_once(&self) -> Result<bool, PfcpRequestError> {
        let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(self.recovery_time_stamp));
        let mut buf = bytes::BytesMut::new();
        msg.encode_body(&mut buf);

        let (_, resp_body) = self
            .request(pfcp_message_type::HEARTBEAT_REQUEST, None, &buf)
            .await?;

        // Recovery Time Stamp staleness detection
        if let Some(rts) = find_ie(&resp_body, 96)
            .filter(|v| v.len() >= 4)
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
        {
            // #928 review M1: off the association/heartbeat task, like the rest.
            self.check_peer_restart_detached(rts, StampSource::Response)
                .await;
        } else {
            log::warn!("Heartbeat Response missing Recovery Time Stamp (mandatory IE)");
        }
        Ok(true)
    }
}

/// The restart/release fan-outs still running (#928 review m1): the #39 releases a
/// teardown started off the receive or the association task. A graceful shutdown
/// drains them, bounded, before the runtime goes; their sessions are already flushed,
/// so nothing else would tell those UEs. Tests that track or drain them hold
/// [`N4_TEST_LOCK`].
fn restart_fanouts() -> &'static std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>> {
    static FANOUTS: OnceLock<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> = OnceLock::new();
    FANOUTS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Keep `releases` for [`drain_restart_fanouts`], forgetting finished ones.
pub(crate) fn track_restart_fanout(releases: tokio::task::JoinHandle<()>) {
    let mut fanouts = restart_fanouts().lock().unwrap_or_else(|e| e.into_inner());
    fanouts.retain(|h| !h.is_finished());
    fanouts.push(releases);
}

/// [`track_restart_fanout`] for tests.
#[cfg(test)]
pub(crate) fn track_restart_fanout_for_test(releases: tokio::task::JoinHandle<()>) {
    track_restart_fanout(releases);
}

/// Wait, at most `budget`, for every tracked fan-out (#928 review m1).
pub async fn drain_restart_fanouts(budget: Duration) {
    let pending: Vec<_> =
        std::mem::take(&mut *restart_fanouts().lock().unwrap_or_else(|e| e.into_inner()));
    if pending.is_empty() {
        return;
    }
    let n = pending.len();
    let all = async {
        for h in pending {
            let _ = h.await;
        }
    };
    if tokio::time::timeout(budget, all).await.is_err() {
        log::warn!(
            "Shutdown: {n} restart release fan-out(s) still running after {budget:?}; the rest \
             of their UEs are not told"
        );
    }
}

/// How many teardowns ran, for the #928 compare-and-set test.
#[cfg(test)]
pub(crate) static TEARDOWNS_FOR_TEST: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// #1229: when set, a teardown signals the first `Notify` once it has counted itself,
/// then waits on the second before it clears the association and its stamp. A test
/// can then run a second detector in that window deterministically. Guarded, like
/// every teardown, by [`N4_TEST_LOCK`].
#[cfg(test)]
pub(crate) static TEARDOWN_HOLD_FOR_TEST: std::sync::Mutex<
    Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
> = std::sync::Mutex::new(None);

/// An armed [`TEARDOWN_HOLD_FOR_TEST`] (#1239 review). Dropping it, on any exit path
/// and a failed assertion included, disarms the hold and releases a teardown that
/// waits in it. A leaked hold would otherwise block every later teardown in the
/// process, so the suite would hang instead of failing.
#[cfg(test)]
pub(crate) struct TeardownHold {
    pub(crate) reached: Arc<tokio::sync::Notify>,
    proceed: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
impl TeardownHold {
    /// Arm the hold: the next teardown signals `reached` and waits for [`Self::release`].
    pub(crate) fn arm() -> Self {
        let hold = Self {
            reached: Arc::new(tokio::sync::Notify::new()),
            proceed: Arc::new(tokio::sync::Notify::new()),
        };
        *TEARDOWN_HOLD_FOR_TEST
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            Some((hold.reached.clone(), hold.proceed.clone()));
        hold
    }

    /// Stop holding later teardowns; one already waiting stays held.
    pub(crate) fn disarm(&self) {
        *TEARDOWN_HOLD_FOR_TEST
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Let the held teardown go on.
    pub(crate) fn release(&self) {
        self.proceed.notify_one();
    }
}

#[cfg(test)]
impl Drop for TeardownHold {
    fn drop(&mut self) {
        self.disarm();
        self.release();
    }
}

/// Where a peer Recovery Time Stamp came from (#928 round 2, B1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StampSource {
    /// The response to a request of ours: any change is a restart.
    Response,
    /// An unsolicited Heartbeat Request: an older stamp may be a reordered message.
    Request,
}

/// Whether Recovery Time Stamp `a` is newer than `b` in serial-number arithmetic
/// (RFC 1982): the 32-bit NTP seconds field wraps in February 2036, and a stamp just
/// past the wrap is newer than one just before it.
fn stamp_is_newer(a: u32, b: u32) -> bool {
    nextgcore_pfcp::recovery_time::is_newer(a, b)
}

/// PFCP Session Retention Information (TS 29.244 Table 7.4.4.1-2), grouped (#718).
const PFCP_SESSION_RETENTION_INFORMATION: u16 = 183;
/// PFCPASRsp-Flags (TS 29.244 §8.2.134); bit 1 is PSREI (#718).
const PFCPASRSP_FLAGS: u16 = 184;

/// Whether an Association Setup Response body says the UP function retained the
/// sessions (PSREI, TS 29.244 §8.2.134).
fn sessions_retained(body: &[u8]) -> bool {
    find_ie(body, PFCPASRSP_FLAGS)
        .and_then(|v| v.first().copied())
        .is_some_and(|flags| flags & 0x01 != 0)
}

/// Whether this SMF holds any PFCP session it expects a UPF to still have (#718):
/// a 5G PDU session in `pfcp_sessions`, or an EPC PDN connection (which has no
/// `pfcp_sessions` entry, #687).
#[cfg(test)]
fn holds_pfcp_sessions() -> bool {
    !held_session_seids().is_empty()
}

/// The SMF-side N4 SEIDs of every PFCP session this SMF holds: the 5G PDU
/// sessions in `pfcp_sessions` and the EPC PDN connections with a UPF SEID.
///
/// One read guard for the whole walk, released before returning; the 5G SEID is
/// resolved as `smf_n4_seid_for` resolves it (`cp_n4_seids` first, then the
/// derivation), against the guard already held.
/// Whether this SMF holds a PFCP session whose SMF-side SEID is `seid` (#974 review
/// m2): the set [`held_session_seids`] lists, without building it.
pub fn holds_session_seid(seid: u64) -> bool {
    let global = smf_self();
    let Ok(ctx) = global.read() else {
        return false;
    };
    // One map guard at a time, as every writer takes them.
    let inherited_refs: Vec<String> = ctx
        .cp_n4_seids
        .read()
        .map(|m| {
            m.iter()
                .filter(|(_, v)| **v == seid)
                .map(|(r, _)| r.clone())
                .collect()
        })
        .unwrap_or_default();
    let (held_inherited, derived_refs): (bool, Vec<String>) = ctx
        .pfcp_sessions
        .read()
        .map(|m| {
            (
                inherited_refs.iter().any(|r| m.contains_key(r)),
                m.keys()
                    .filter(|r| crate::context::derive_cp_n4_seid(r) == seid)
                    .cloned()
                    .collect(),
            )
        })
        .unwrap_or_default();
    // A derived SEID counts unless the session carries an inherited one instead.
    let held_derived = !derived_refs.is_empty()
        && ctx.cp_n4_seids.read().is_ok_and(|m| {
            derived_refs
                .iter()
                .any(|r| m.get(r).is_none_or(|v| *v == seid))
        });
    let five_g = held_inherited || held_derived;
    // A session's own SEID (EPC, and what `sess_find_by_seid` indexes), as the
    // report handlers resolve it.
    five_g || ctx.sess_find_by_seid(seid).is_some()
}

fn held_session_seids() -> Vec<u64> {
    let global = smf_self();
    let Ok(ctx) = global.read() else {
        return Vec::new();
    };
    let inherited = ctx
        .cp_n4_seids
        .read()
        .map(|m| m.clone())
        .unwrap_or_default();
    let mut seids: Vec<u64> = ctx
        .pfcp_sessions
        .read()
        .map(|m| {
            m.keys()
                .map(|r| {
                    inherited
                        .get(r)
                        .copied()
                        .unwrap_or_else(|| crate::context::derive_cp_n4_seid(r))
                })
                .collect()
        })
        .unwrap_or_default();
    seids.extend(
        ctx.sess_find_all_by(|s| s.epc && s.upf_n4_seid != 0)
            .into_iter()
            .map(|s| s.smf_n4_seid),
    );
    seids
}

/// One read of the state that decides which pool member a session lives on (#1075,
/// #1059 round 2 m4): the default client, each member's identity and endpoint, and
/// the per-session identity and endpoint records. A scope over every session asks it
/// once per session; before, each question took the context and `session_upfs`
/// locks and cloned the pool, so a teardown or an association setup cost
/// O(sessions) lock pairs and pool clones.
struct SessionRouting {
    default: Option<*const PfcpClient>,
    /// Each pool member's (identity, endpoint).
    members: Vec<(String, SocketAddr)>,
    upfs: HashMap<u64, String>,
    peers: HashMap<u64, SocketAddr>,
}

/// How many times the routing state was read (#1150 review m5): a scope must read
/// it once, however many sessions it covers. Process-global: a test that measures
/// it holds `PROCESS_STATE_TEST_LOCK` (#1150 review round 2 n1).
#[cfg(test)]
pub(crate) static SESSION_ROUTING_READS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

impl SessionRouting {
    fn now() -> Self {
        #[cfg(test)]
        SESSION_ROUTING_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let upfs = smf_self()
            .read()
            .ok()
            .and_then(|ctx| ctx.session_upfs.read().ok().map(|m| m.clone()))
            .unwrap_or_default();
        let peers = session_peers()
            .read()
            .map(|m| m.clone())
            .unwrap_or_default();
        Self {
            default: global_client().map(|c| Arc::as_ptr(&c)),
            members: global_pool()
                .iter()
                .map(|c| (c.recovery_time_stamp_key(), c.peer()))
                .collect(),
            upfs,
            peers,
        }
    }

    /// Whether a current member is the one `seid` was recorded on: by its identity
    /// when one is recorded (it decides alone, as in [`recorded_client`]), else by
    /// its endpoint.
    fn names_a_member(&self, seid: u64) -> bool {
        if let Some(key) = self.upfs.get(&seid) {
            return self.members.iter().any(|(k, _)| k == key);
        }
        self.peers
            .get(&seid)
            .is_some_and(|peer| self.members.iter().any(|(_, p)| p == peer))
    }

    /// [`session_served_by`], answered from this read.
    fn served_by(&self, seid: u64, client: &PfcpClient) -> bool {
        let is_default = || self.default == Some(client as *const PfcpClient);
        // #1031, #1059 round 2 m2: the identity first, as `recorded_client` does.
        if let Some(key) = self.upfs.get(&seid) {
            if *key == client.recovery_time_stamp_key() {
                return true;
            }
            // It names another current member: that one's. It names none: the default.
            return !self.members.iter().any(|(k, _)| k == key) && is_default();
        }
        if self.peers.get(&seid) == Some(&client.peer()) {
            return true;
        }
        // A record naming another current member routes there; anything else goes to
        // the default client.
        !self.names_a_member(seid) && is_default()
    }
}

/// Whether `client` is the UPF the session with SMF-side N4 SEID `seid` lives on.
///
/// The recorded peer when it is this client's. Otherwise the routing
/// [`client_for_session`] applies: a session with no record (restored from durable
/// state, where the binding is not persisted), or whose recorded peer no pool
/// member has any more (a hostname UPF re-resolved), goes to the default client.
#[cfg(test)]
fn session_served_by(seid: u64, client: &PfcpClient) -> bool {
    SessionRouting::now().served_by(seid, client)
}

/// Whether this SMF holds a PFCP session on `client`'s UPF (#718 review M1).
///
/// Scoped to the peer. In a UPF pool, a member that associates late, or again
/// after its own heartbeat loss, holds none of the sessions on the other members;
/// asking it to retain them, and then releasing them all when it answered without
/// PSREI, released every UE on the healthy UPFs.
fn holds_pfcp_sessions_on(client: &PfcpClient) -> bool {
    let routing = SessionRouting::now();
    held_session_seids()
        .into_iter()
        .any(|seid| routing.served_by(seid, client))
}

impl PfcpClient {
    /// The sessions whose PFCP session lives on this client's UPF (#720), by the
    /// routing [`session_served_by`] applies. Computed with no guard held across
    /// the ownership check, which takes the N4 maps' own locks.
    pub(crate) fn session_scope(&self) -> crate::restoration::SessionScope {
        let (five_g, epc): (Vec<(String, u64)>, Vec<(u64, u64)>) = match smf_self().read() {
            Ok(ctx) => {
                let inherited = ctx
                    .cp_n4_seids
                    .read()
                    .map(|m| m.clone())
                    .unwrap_or_default();
                let five_g = ctx
                    .pfcp_sessions
                    .read()
                    .map(|m| {
                        m.keys()
                            .map(|r| {
                                let seid = inherited
                                    .get(r)
                                    .copied()
                                    .unwrap_or_else(|| crate::context::derive_cp_n4_seid(r));
                                (r.clone(), seid)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let epc = ctx
                    .sess_find_all_by(|s| s.epc)
                    .into_iter()
                    .map(|s| (s.id, s.smf_n4_seid))
                    .collect();
                (five_g, epc)
            }
            Err(_) => (Vec::new(), Vec::new()),
        };
        // #1075: one read of the routing state for every session.
        let routing = SessionRouting::now();
        let five_g: Vec<(String, u64)> = five_g
            .into_iter()
            .filter(|(_, seid)| routing.served_by(*seid, self))
            .collect();
        let epc: Vec<(u64, u64)> = epc
            .into_iter()
            .filter(|(_, seid)| routing.served_by(*seid, self))
            .collect();
        crate::restoration::SessionScope {
            seids: five_g
                .iter()
                .map(|(_, seid)| *seid)
                .chain(epc.iter().map(|(_, seid)| *seid))
                .collect(),
            refs: five_g.into_iter().map(|(r, _)| r).collect(),
            epc_sess_ids: epc.into_iter().map(|(id, _)| id).collect(),
        }
    }
}

/// Flush the stored PFCP sessions in `scope` (#720): one UPF's sessions, after it
/// restarted or its association was lost. Returns the number removed.
pub fn clear_pfcp_sessions_in(scope: &crate::restoration::SessionScope) -> usize {
    // #779 (review of #879, m2): the production flush, scoped since #809, removes from
    // the process-wide map too, so a test reaching it holds both locks.
    #[cfg(test)]
    assert_teardown_is_serialised();
    let n = match smf_self().read() {
        Ok(ctx) => {
            let n = match ctx.pfcp_sessions.write() {
                Ok(mut sessions) => {
                    let before = sessions.len();
                    sessions.retain(|r, _| !scope.refs.contains(r));
                    before - sessions.len()
                }
                Err(_) => 0,
            };
            // Issue #191: after the write guard drops, as in `clear_pfcp_sessions`.
            if n > 0 {
                ctx.persist();
            }
            n
        }
        Err(_) => 0,
    };
    // The sessions are gone at that UPF, and so is their binding to it.
    for seid in &scope.seids {
        forget_session_peer(*seid);
    }
    // #994: and the GTP-U peers of their FARs.
    crate::up_path::forget_sessions(scope.seids.iter().copied());
    n
}

/// Flush all stored PFCP sessions (UPF restarted / association lost).
/// Returns the number of sessions removed.
#[cfg(test)]
pub fn clear_pfcp_sessions() -> usize {
    // #779: the flush empties the process-wide map, whatever the caller. An unlocked
    // teardown reaching it (the #665 hostname test, fixed by #762) is what made the
    // eps_to_5gs end-to-end test lose its N4 session.
    #[cfg(test)]
    assert_teardown_is_serialised();
    if let Ok(ctx) = smf_self().read() {
        let n = {
            match ctx.pfcp_sessions.write() {
                Ok(mut sessions) => {
                    let n = sessions.len();
                    sessions.clear();
                    Some(n)
                }
                Err(_) => None,
            }
        };
        if let Some(n) = n {
            // Issue #191: the flush must reach the snapshot too. This is the path
            // that makes restoring the session map safe -- a UPF whose Recovery
            // Time Stamp changed no longer holds these sessions, so a snapshot
            // that kept them would re-restore them on every subsequent start.
            ctx.persist();
            return n;
        }
    }
    0
}

// ============================================================================
// Test harness: the process-wide stand-in UPF (issue #289)
// ============================================================================

/// One agreement about every N4 process-global in this crate.
///
/// Three variables are involved and they cannot be guarded separately:
/// - `PFCP_CLIENT` / `PFCP_POOL` (this module) — `OnceLock`s, so the first
///   installer wins for the whole test process;
/// - `SmfContext::pfcp_sessions` (`context.rs`) — `teardown_association` calls
///   `clear_pfcp_sessions`, which clears the map for the WHOLE process rather
///   than for the client that tore down;
/// - the `AssociationState` of the one installed client, which decides whether
///   `pfcp_session_establish` proceeds or bails;
/// - the tracked restart/release fan-outs (`restart_fanouts`, #928 review m4):
///   `drain_restart_fanouts` takes every handle, including a sibling's;
/// - [`PFCP_UNAUTHORIZED`] and its WARN interval (#974 review n3), which tests
///   assert exact deltas of;
/// - [`NODE_LOOKUP_DELAY_FOR_TEST`] (#1091 review H), which delays every client's
///   lookup of the name it holds.
///
/// Any two tests that touch any of these will flush or contradict each other if
/// they interleave — which is how the #191 pair first failed, one clearing the
/// other's session key mid-assertion. A SECOND lock over the same variables
/// would be two disjoint agreements rather than one, and #276 showed that
/// mistake HANGS the suite rather than merely flaking it, so this is deliberately
/// declared here beside the globals and shared by `main.rs`'s tests
/// (`pub(crate)`) instead of being re-declared there.
///
/// Lock order, where a test needs more than one process-global: take
/// [`crate::context::PROCESS_STATE_TEST_LOCK`] — the one agreement about the SMF
/// context, the feature switches and the `UDM_SBI_*` environment — FIRST, then this
/// one. Every call site in the crate follows that order; reversing it anywhere
/// reintroduces the deadlock this comment exists to prevent. Note that
/// [`stand_in::associated_upf`] takes THIS lock on the caller's behalf, so a test
/// that wants both must take the ambient one itself and let the stand-in take this.
#[cfg(test)]
pub(crate) static N4_TEST_LOCK: crate::context::TestLock = crate::context::TestLock::new();

/// #723: a test that reaches [`PfcpClient::teardown_association`] must hold BOTH
/// [`crate::context::PROCESS_STATE_TEST_LOCK`] and [`N4_TEST_LOCK`].
///
/// The teardown is process-wide: it releases every seeded session through its AMF
/// callback (the policy bindings, under the ambient lock), deletes every EPC PDN
/// connection, and empties the global `pfcp_sessions` map (under this one). The #665
/// hostname test reached it holding neither, and wiped the #672 restoration test's
/// session mid-assertion 20 runs out of 20. See
/// [`crate::context::require_test_lock`] for what the check can and cannot see.
#[cfg(test)]
fn assert_teardown_is_serialised() {
    crate::context::require_test_lock(
        &crate::context::PROCESS_STATE_TEST_LOCK,
        "PROCESS_STATE_TEST_LOCK",
        "PfcpClient::teardown_association",
    );
    crate::context::require_test_lock(
        &N4_TEST_LOCK,
        "N4_TEST_LOCK",
        "PfcpClient::teardown_association",
    );
}

/// A PFCP-answering UPF stand-in for tests (issue #289).
///
/// Before this existed, `handle_sm_context_create` could not get past its N4 leg
/// in ANY test: `select_upf()` returned no client, so every create answered
/// `504 UPF_NOT_RESPONDING` and the whole tail after the PFCP block — the session
/// fill-in, the policy binding, the EASDF leg, the N1 accept — was unreachable.
/// Three call sites in that tail were therefore "verified by inspection", and one
/// of them (`easdf::create_dns_context`, #276) had simply been absent for a month
/// while looking wired.
///
/// **The design choice #289 asks to be made explicitly: install-and-release, per
/// test, which required making `PFCP_CLIENT` settable.** The issue proposed
/// installing ONE stand-in permanently and leaving the `OnceLock` alone, calling
/// that the smaller change — and it cannot work here, for a reason the issue did
/// not anticipate: a `PfcpClient` owns a `tokio::net::UdpSocket`, which belongs to
/// the runtime that created it. `#[tokio::test]` gives each test its own runtime,
/// so a client installed by the first test to touch it is dead for every test
/// after ("A Tokio 1.x context was found, but it is being shutdown" — observed,
/// not predicted). So each test installs its own stand-in and RELEASES it on drop
/// (see [`clear_global_upf_for_test`]), leaving the process exactly as a test that
/// never asked for a UPF expects to find it.
///
/// Which association state a test gets is still its own choice
/// ([`associated_upf`] / [`unassociated_upf`]): a failure-path test wants the REAL
/// failure mode (TS 29.244 §6.2.6.2, no session signalling without an
/// association) rather than the absence of a client, which is what those tests
/// were approximating all along.
#[cfg(test)]
pub(crate) mod stand_in {
    use super::*;

    /// The stand-in UPF and the identities it hands out, so a test can assert on
    /// the values that must survive the round trip.
    ///
    /// Holds the [`N4_TEST_LOCK`] guard for as long as the test holds this, and
    /// un-installs the client on drop — so binding it to `_` (which drops it
    /// immediately) would silently give the test no UPF and no serialisation.
    #[must_use = "the stand-in UPF is uninstalled as soon as it is dropped"]
    pub(crate) struct StandInUpf {
        /// The client installed as the process-wide PFCP client + pool.
        pub(crate) client: Arc<PfcpClient>,
        /// Message types the stand-in answered, in order.
        pub(crate) seen: Arc<std::sync::Mutex<Vec<u8>>>,
        /// The UP F-SEID this stand-in allocates for every session.
        pub(crate) upf_seid: u64,
        /// The F-TEID it returns in the Created PDR.
        pub(crate) upf_teid: u32,
        /// The N3 address it reports alongside the F-TEID.
        pub(crate) upf_ip: [u8; 4],
        /// The Cause this stand-in answers Session Modification and Deletion with
        /// (#193). `REQUEST_ACCEPTED` unless a test asks otherwise, which is what
        /// lets one drive the SMF's cause-65 reconciliation over a real round trip
        /// rather than by calling the reconciler directly.
        session_cause: Arc<std::sync::atomic::AtomicU8>,
        /// How long the stand-in waits before answering a Session Modification
        /// (#750): a slow UPF, so a test can interleave another request.
        modification_delay_ms: Arc<std::sync::atomic::AtomicU64>,
        /// How long the stand-in waits before answering a Session Deletion (#1198
        /// review MAJOR): a slow PGW-U. The other messages are answered meanwhile.
        deletion_delay_ms: Arc<std::sync::atomic::AtomicU64>,
        /// Answer Session Modifications with no Created PDR (#751): an incomplete
        /// answer to a request that created PDRs with CHOOSE.
        omit_created_pdrs: Arc<std::sync::atomic::AtomicBool>,
        /// #982 review m1: give every CHOOSE PDR its own F-TEID, as a UPF that does not
        /// honour the CHOOSE ID would.
        ignore_choose_id: Arc<std::sync::atomic::AtomicBool>,
        /// Reject the Nth Session Modification from now (1-based; 0 = none) with
        /// cause 64, accepting the others (#751).
        reject_modification: Arc<std::sync::atomic::AtomicU64>,
        /// Bodies of the Session Modification Requests this stand-in received, in
        /// order (#321).
        ///
        /// `seen` records message TYPES, which cannot answer "did the SMF send the
        /// TSC IE, and with which containers" — the question the `tscu` gate turns
        /// on. A gate test asserting only that a modification was or was not sent
        /// would pass for a modification that carried the wrong IE.
        pub(crate) modification_bodies: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        /// Bodies of the Session ESTABLISHMENT Requests this stand-in received, in
        /// order (#80).
        ///
        /// Recorded for the same reason as the modification bodies above: "an
        /// establishment was sent" cannot answer "did it provision a URR, and was that
        /// URR bound to both PDRs" — which is what #80 turns on, and which the whole
        /// usage-reporting capability was silently missing.
        pub(crate) establishment_bodies: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        /// Serialises every N4 test against every other; released with this value.
        _n4_guard: crate::context::TestLockGuard,
    }

    impl Drop for StandInUpf {
        fn drop(&mut self) {
            // Runs BEFORE `_n4_guard` is released (Rust drops the body first, then
            // the fields), so no sibling can observe the half-torn-down state.
            clear_global_upf_for_test();
        }
    }

    impl StandInUpf {
        /// Message types answered since the last [`Self::clear_seen`].
        pub(crate) fn seen(&self) -> Vec<u8> {
            self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }

        /// Forget the recorded traffic, so a test asserts only about its own.
        pub(crate) fn clear_seen(&self) {
            self.seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
            self.modification_bodies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            self.establishment_bodies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }

        /// Bodies of the Session Establishment Requests received since the last
        /// [`Self::clear_seen`] (#80).
        pub(crate) fn establishment_bodies(&self) -> Vec<Vec<u8>> {
            self.establishment_bodies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// Bodies of the Session Modification Requests received since the last
        /// [`Self::clear_seen`] (#321).
        pub(crate) fn modification_bodies(&self) -> Vec<Vec<u8>> {
            self.modification_bodies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// Answer every Session Modification after `ms` milliseconds (#750).
        pub(crate) fn delay_modifications(&self, ms: u64) {
            self.modification_delay_ms
                .store(ms, std::sync::atomic::Ordering::SeqCst);
        }

        /// Answer every Session Deletion after `ms` milliseconds, serving the other
        /// messages meanwhile (#1198 review MAJOR).
        pub(crate) fn delay_deletions(&self, ms: u64) {
            self.deletion_delay_ms
                .store(ms, std::sync::atomic::Ordering::SeqCst);
        }

        /// #982 review m1: answer each CHOOSE PDR with its own F-TEID, CHOOSE ID or not.
        pub(crate) fn ignore_choose_id(&self, ignore: bool) {
            self.ignore_choose_id
                .store(ignore, std::sync::atomic::Ordering::SeqCst);
        }

        /// Answer Session Modifications with no Created PDR (#751).
        pub(crate) fn omit_created_pdrs(&self, omit: bool) {
            self.omit_created_pdrs
                .store(omit, std::sync::atomic::Ordering::SeqCst);
        }

        /// Reject the `n`th Session Modification from now with cause 64 (#751).
        pub(crate) fn reject_modification(&self, n: u64) {
            self.reject_modification
                .store(n, std::sync::atomic::Ordering::SeqCst);
        }

        /// Answer the next Session Modification / Deletion with `cause` (#193).
        ///
        /// Scoped to the session-level messages on purpose: making the
        /// ASSOCIATION handshake fail is a different test, and a stand-in that
        /// refused everything could not first establish the session the
        /// reconciliation is about.
        pub(crate) fn answer_sessions_with(&self, cause: u8) {
            self.session_cause
                .store(cause, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The F-TEID the stand-in allocates for a PDR CREATED by a Session Modification (#475),
    /// distinct from the establishment's so a test can tell the two tunnels apart.
    pub(crate) const N3_STAND_IN_TEID: u32 = 0x0000_3475;

    /// The value of every top-level Create PDR IE (type 1) in a message body.
    fn create_pdrs(body: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 4 <= body.len() {
            let t = u16::from_be_bytes([body[off], body[off + 1]]);
            let l = usize::from(u16::from_be_bytes([body[off + 2], body[off + 3]]));
            let Some(v) = body.get(off + 4..off + 4 + l) else {
                break;
            };
            if t == 1 {
                out.push(v);
            }
            off += 4 + l;
        }
        out
    }

    /// Flat TLV encoder for the response IEs the SMF's establishment parser reads.
    fn tlv(ie_type: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + value.len());
        out.extend_from_slice(&ie_type.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    /// A Session Establishment Response body: Cause + UP F-SEID + Created PDR
    /// carrying the allocated F-TEID (TS 29.244 §7.5.3).
    ///
    /// Hand-encoded rather than built with the library's message types because
    /// the SMF's own establishment parser is what is under test here: it reads
    /// F-SEID with V4 on **bit 2** (§8.2.37) and F-TEID with V4 on **bit 1**
    /// (§8.2.3), an asymmetry the production parser calls out and a stand-in that
    /// shared an encoder with it could not catch.
    fn establishment_response_body(seid: u64, teid: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut body = tlv(19, &[pfcp_cause::REQUEST_ACCEPTED]);

        let mut f_seid = Vec::with_capacity(13);
        f_seid.push(0x02); // V4 present (bit 2)
        f_seid.extend_from_slice(&seid.to_be_bytes());
        f_seid.extend_from_slice(&ip);
        body.extend_from_slice(&tlv(57, &f_seid));

        let mut f_teid = Vec::with_capacity(9);
        f_teid.push(0x01); // V4 present (bit 1)
        f_teid.extend_from_slice(&teid.to_be_bytes());
        f_teid.extend_from_slice(&ip);
        let mut created_pdr = tlv(56, &[0x00, 0x01]); // PDR ID 1
        created_pdr.extend_from_slice(&tlv(21, &f_teid));
        body.extend_from_slice(&tlv(8, &created_pdr));

        body
    }

    /// Bind a client whose peer socket is returned to the caller and never
    /// answers on its own. Promoted out of this module's `tests` submodule
    /// (issue #289) so both `pfcp_path`'s own tests and the stand-in build their
    /// clients the same way.
    pub(crate) async fn client_with_silent_peer() -> (Arc<PfcpClient>, UdpSocket) {
        client_with_silent_peer_as(&default_identity()).await
    }

    /// The N4 identity every stand-in client signals unless a test chooses one.
    pub(crate) fn default_identity() -> crate::n4_identity::N4Identity {
        crate::n4_identity::N4Identity {
            node_id: NodeId::new_ipv4([127, 0, 0, 1]),
            f_seid_ipv4: [127, 0, 0, 1],
            node_id_explicit: true,
        }
    }

    /// [`client_with_silent_peer`] signalling `identity` (#797).
    pub(crate) async fn client_with_silent_peer_as(
        identity: &crate::n4_identity::N4Identity,
    ) -> (Arc<PfcpClient>, UdpSocket) {
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = Arc::new(
            PfcpClient::new(Arc::new(local), peer_addr, identity.f_seid_ipv4)
                .with_node_id(identity.node_id.clone()),
        );

        // Pump incoming datagrams into the engine
        let c = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, from)) = c.socket.recv_from(&mut buf).await else {
                    break;
                };
                c.on_datagram(&buf[..len], from).await;
            }
        });
        (client, peer_sock)
    }

    /// Install a stand-in UPF as `PFCP_CLIENT` + `PFCP_POOL` for this test, and
    /// serialise against every other N4 test until the returned value drops.
    ///
    /// Not associated yet — [`associated_upf`] adds the handshake.
    pub(crate) async fn install_stand_in_upf() -> StandInUpf {
        install_stand_in_upf_with_features(UpFunctionFeatures {
            ftup: true,
            ..Default::default()
        })
        .await
    }

    /// Install a stand-in UPF advertising exactly `features` (#321).
    ///
    /// The features have to be chosen at INSTALL time, not later: they are baked
    /// into the Association Setup Response, and the SMF reads them from the stored
    /// `AssociationState` afterwards. A setter would only take effect on a
    /// re-association, which is a different test.
    pub(crate) async fn install_stand_in_upf_with_features(
        features: UpFunctionFeatures,
    ) -> StandInUpf {
        install_stand_in_upf_as(features, &default_identity()).await
    }

    /// Install a stand-in UPF whose SMF client signals `identity` (#797).
    pub(crate) async fn install_stand_in_upf_as(
        features: UpFunctionFeatures,
        identity: &crate::n4_identity::N4Identity,
    ) -> StandInUpf {
        let n4_guard = N4_TEST_LOCK.lock().await;
        let (client, upf_sock) = client_with_silent_peer_as(identity).await;
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let modification_bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let establishment_bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let upf_seid = 0x0000_0000_dead_beef_u64;
        let upf_teid = 0x0000_1289_u32;
        let upf_ip = [127, 0, 0, 4];

        let recorded = seen.clone();
        let recorded_bodies = modification_bodies.clone();
        let recorded_establishments = establishment_bodies.clone();
        let session_cause = Arc::new(std::sync::atomic::AtomicU8::new(
            pfcp_cause::REQUEST_ACCEPTED,
        ));
        let answered_cause = session_cause.clone();
        let modification_delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let omit_created_pdrs = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let delay_ms = modification_delay_ms.clone();
        let deletion_delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let deletion_delay = deletion_delay_ms.clone();
        let upf_sock = Arc::new(upf_sock);
        let omit = omit_created_pdrs.clone();
        let ignore_choose_id = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ignore_chid = ignore_choose_id.clone();
        let reject_modification = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reject_nth = reject_modification.clone();
        tokio::spawn(async move {
            let rts = 0x5EED_0289_u32;
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((len, from)) = upf_sock.recv_from(&mut buf).await else {
                    break;
                };
                let Some(h) = parse_wire_header(&buf[..len]) else {
                    continue;
                };
                recorded
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(h.msg_type);
                if h.msg_type == pfcp_message_type::SESSION_MODIFICATION_REQUEST {
                    recorded_bodies
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(buf[h.body_offset..len].to_vec());
                }
                if h.msg_type == pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST {
                    recorded_establishments
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(buf[h.body_offset..len].to_vec());
                }

                let reply = match h.msg_type {
                    pfcp_message_type::ASSOCIATION_SETUP_REQUEST => {
                        let mut resp = AssociationSetupResponse::new(
                            NodeId::new_ipv4(upf_ip),
                            nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                            rts,
                        );
                        resp.up_function_features = Some(features);
                        let mut body = bytes::BytesMut::new();
                        PfcpMessage::AssociationSetupResponse(resp).encode_body(&mut body);
                        // #718: a conformant UPF that holds the sessions the test seeded
                        // retains them when asked, and says so with PSREI.
                        if find_ie(&buf[h.body_offset..len], PFCP_SESSION_RETENTION_INFORMATION)
                            .is_some()
                        {
                            body.put_u16(PFCPASRSP_FLAGS);
                            body.put_u16(1);
                            body.put_u8(0x01);
                        }
                        Some(encode_wire_message(
                            pfcp_message_type::ASSOCIATION_SETUP_RESPONSE,
                            None,
                            h.sequence_number,
                            &body,
                        ))
                    }
                    pfcp_message_type::HEARTBEAT_REQUEST => Some(Vec::from(build_message(
                        &PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(rts)),
                        h.sequence_number,
                        None,
                    ))),
                    pfcp_message_type::ASSOCIATION_RELEASE_REQUEST => {
                        Some(Vec::from(build_message(
                            &PfcpMessage::AssociationReleaseResponse(
                                nextgcore_pfcp::message::AssociationReleaseResponse::new(
                                    NodeId::new_ipv4(upf_ip),
                                    nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                                ),
                            ),
                            h.sequence_number,
                            None,
                        )))
                    }
                    pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST => Some(encode_wire_message(
                        pfcp_message_type::SESSION_ESTABLISHMENT_RESPONSE,
                        Some(h.seid),
                        h.sequence_number,
                        &establishment_response_body(upf_seid, upf_teid, upf_ip),
                    )),
                    pfcp_message_type::SESSION_MODIFICATION_REQUEST => {
                        let mut cause = answered_cause.load(std::sync::atomic::Ordering::SeqCst);
                        let nth = reject_nth.load(std::sync::atomic::Ordering::SeqCst);
                        if nth > 0 {
                            if nth == 1 {
                                cause = 64; // PFCP: Request rejected (reason not specified)
                            }
                            reject_nth.store(nth - 1, std::sync::atomic::Ordering::SeqCst);
                        }
                        let mut body = tlv(19, &[cause]);
                        // #475: a modification that CREATES a PDR whose F-TEID the UP
                        // function chooses is answered with a Created PDR carrying the
                        // allocated F-TEID (TS 29.244 §7.5.5.2), as the establishment is.
                        let req_body = &buf[h.body_offset..len];
                        let delay = delay_ms.load(std::sync::atomic::Ordering::SeqCst);
                        if delay > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        }
                        if cause == pfcp_cause::REQUEST_ACCEPTED
                            && !omit.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            // #583: EVERY Create PDR whose F-TEID is to be chosen (TEID 0)
                            // gets its own, N3_STAND_IN_TEID first; a message naming none
                            // that way keeps the #475 answer for its first Create PDR.
                            //
                            // #982: so does one with the CH flag (TS 29.244 §8.2.3), and
                            // PDRs sharing a CHOOSE ID (CHID) share one F-TEID (§5.5.3).
                            let pdrs = create_pdrs(req_body);
                            fn pdr_f_teid(pdr: &[u8]) -> Option<&[u8]> {
                                find_ie(pdr, 2).and_then(|pdi| find_ie(pdi, 21))
                            }
                            let choose: Vec<&[u8]> = pdrs
                                .iter()
                                .copied()
                                .filter(|pdr| {
                                    pdr_f_teid(pdr).is_some_and(|f| {
                                        f.first().is_some_and(|flags| flags & 0x04 != 0)
                                            || (f.len() >= 5 && f[1..5] == [0; 4])
                                    })
                                })
                                .collect();
                            let answered = if choose.is_empty() {
                                pdrs.into_iter().take(1).collect()
                            } else {
                                choose
                            };
                            let mut by_choose_id = std::collections::HashMap::new();
                            for (k, pdr) in answered.into_iter().enumerate() {
                                let Some(pdr_id) = find_ie(pdr, 56).filter(|v| v.len() >= 2) else {
                                    continue;
                                };
                                let mut teid = N3_STAND_IN_TEID + k as u32;
                                let honour = !ignore_chid.load(std::sync::atomic::Ordering::SeqCst);
                                if let Some(f) = pdr_f_teid(pdr)
                                    .filter(|f| honour && f.len() >= 2 && f[0] & 0x0C == 0x0C)
                                {
                                    teid = *by_choose_id.entry(f[1]).or_insert(teid);
                                }
                                let mut f_teid = vec![0x01];
                                f_teid.extend_from_slice(&teid.to_be_bytes());
                                f_teid.extend_from_slice(&upf_ip);
                                let mut created = tlv(56, &pdr_id[..2]);
                                created.extend_from_slice(&tlv(21, &f_teid));
                                body.extend_from_slice(&tlv(8, &created));
                            }
                        }
                        Some(encode_wire_message(
                            pfcp_message_type::SESSION_MODIFICATION_RESPONSE,
                            Some(h.seid),
                            h.sequence_number,
                            &body,
                        ))
                    }
                    pfcp_message_type::SESSION_DELETION_REQUEST => {
                        let pkt = encode_wire_message(
                            pfcp_message_type::SESSION_DELETION_RESPONSE,
                            Some(h.seid),
                            h.sequence_number,
                            &tlv(
                                19,
                                &[answered_cause.load(std::sync::atomic::Ordering::SeqCst)],
                            ),
                        );
                        let delay = deletion_delay.load(std::sync::atomic::Ordering::SeqCst);
                        if delay > 0 {
                            let sock = upf_sock.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                                let _ = sock.send_to(&pkt, from).await;
                            });
                            None
                        } else {
                            Some(pkt)
                        }
                    }
                    _ => None,
                };
                if let Some(pkt) = reply {
                    let _ = upf_sock.send_to(&pkt, from).await;
                }
            }
        });

        // Installs BOTH globals: `set_global_pool` also sets the default client,
        // so the two can never disagree about which peer is ours.
        set_global_pool(vec![client.clone()]);

        StandInUpf {
            client,
            seen,
            upf_seid,
            upf_teid,
            upf_ip,
            session_cause,
            modification_delay_ms,
            deletion_delay_ms,
            omit_created_pdrs,
            ignore_choose_id,
            reject_modification,
            modification_bodies,
            establishment_bodies,
            _n4_guard: n4_guard,
        }
    }

    /// #583: a REAL UPF -- a running `nextgcore-upfd` at `peer` -- installed as the
    /// process-wide PFCP client and associated, for the env-gated real-binary tests. The
    /// client binds `local` (an address the UPF can answer). Serialised and uninstalled like
    /// the stand-in.
    #[must_use = "the UPF client is uninstalled as soon as it is dropped"]
    pub(crate) struct RealUpf {
        _n4_guard: crate::context::TestLockGuard,
    }

    impl Drop for RealUpf {
        fn drop(&mut self) {
            clear_global_upf_for_test();
        }
    }

    pub(crate) async fn real_upf(local: SocketAddr, peer: SocketAddr) -> RealUpf {
        let n4_guard = N4_TEST_LOCK.lock().await;
        let sock = Arc::new(UdpSocket::bind(local).await.expect("bind the N4 client"));
        let ip = match local.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            std::net::IpAddr::V6(_) => panic!("an IPv4 N4 address"),
        };
        let client = Arc::new(PfcpClient::new(sock, peer, ip));
        let c = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((len, from)) = c.socket.recv_from(&mut buf).await else {
                    break;
                };
                c.on_datagram(&buf[..len], from).await;
            }
        });
        set_global_pool(vec![client.clone()]);
        client
            .associate()
            .await
            .expect("the real UPF must accept the association");
        RealUpf {
            _n4_guard: n4_guard,
        }
    }

    /// A stand-in UPF with its association UP. Use for a test that must reach the
    /// success path.
    pub(crate) async fn associated_upf() -> StandInUpf {
        let upf = install_stand_in_upf().await;
        upf.client
            .associate()
            .await
            .expect("the stand-in UPF must accept the association");
        upf.clear_seen();
        upf
    }

    /// An associated stand-in UPF advertising exactly `features` (#321).
    ///
    /// Note what the DEFAULT stand-in advertises: `ftup` only, so `tscu` is CLEAR.
    /// That makes "a UPF that did not advertise TSC support" the default case rather
    /// than something a test has to arrange, and the TSC-capable case the one that
    /// states itself explicitly.
    pub(crate) async fn associated_upf_with_features(features: UpFunctionFeatures) -> StandInUpf {
        let upf = install_stand_in_upf_with_features(features).await;
        upf.client
            .associate()
            .await
            .expect("the stand-in UPF must accept the association");
        upf.clear_seen();
        upf
    }

    /// An associated stand-in UPF whose SMF client signals `identity` (#797).
    pub(crate) async fn associated_upf_as(identity: &crate::n4_identity::N4Identity) -> StandInUpf {
        let upf = install_stand_in_upf_as(
            UpFunctionFeatures {
                ftup: true,
                ..Default::default()
            },
            identity,
        )
        .await;
        upf.client
            .associate()
            .await
            .expect("the stand-in UPF must accept the association");
        upf.clear_seen();
        upf
    }

    /// A stand-in UPF with its association DOWN. Use for a test that must see
    /// establishment fail at the N4 leg — the real failure mode (TS 29.244
    /// §6.2.6.2), rather than the absence of a client.
    ///
    /// A freshly built client is un-associated already; the state is set
    /// explicitly so the test's intent is visible at the call site. Deliberately
    /// NOT `teardown_association`, which would clear the process-global
    /// `pfcp_sessions` map — a sibling's state rather than this test's.
    pub(crate) async fn unassociated_upf() -> StandInUpf {
        let upf = install_stand_in_upf().await;
        upf.client.set_assoc_state_for_test(false, None, None).await;
        upf.clear_seen();
        upf
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::stand_in::{client_with_silent_peer as make_client_with_peer, unassociated_upf};
    use super::*;

    /// #1031: a session whose only record is its durable UPF identity (restored from
    /// the snapshot) is routed to that pool member, not to the default one; and so
    /// is one whose recorded endpoint is stale because the hostname UPF moved.
    #[tokio::test]
    async fn a_restored_sessions_upf_identity_routes_it() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a = Arc::new(PfcpClient::new(
            local.clone(),
            "127.0.0.1:47931".parse().unwrap(),
            [127, 0, 0, 1],
        ));
        let b = Arc::new(
            PfcpClient::new(local, "127.0.0.1:47932".parse().unwrap(), [127, 0, 0, 1])
                .with_peer_hostname("localhost", 47932),
        );
        let _pool = InstalledPool::new(vec![a.clone(), b.clone()]);
        let restored = 0x1031_0001u64;
        let moved = 0x1031_0002u64;
        if let Ok(ctx) = smf_self().read() {
            let mut m = ctx.session_upfs.write().unwrap();
            m.insert(restored, b.recovery_time_stamp_key());
            m.insert(moved, b.recovery_time_stamp_key());
        }
        // `moved` was recorded at an address b no longer has.
        record_session_peer(moved, "127.0.0.1:40000".parse().unwrap());
        // #1059 round 2, m2: `reused` was recorded at an endpoint A serves now, but
        // its identity is B's: the identity wins.
        let reused = 0x1031_0004u64;
        record_session_peer(reused, a.peer());
        if let Ok(ctx) = smf_self().read() {
            ctx.session_upfs
                .write()
                .unwrap()
                .insert(reused, b.recovery_time_stamp_key());
        }
        let reused_to = (
            client_for_session(reused).map(|c| c.peer()),
            session_served_by(reused, &b),
            session_served_by(reused, &a),
        );
        forget_session_peer(reused);

        let to = |seid| client_for_session(seid).map(|c| c.peer());
        let routed = (to(restored), to(moved));
        let served = (
            session_served_by(restored, &b),
            session_served_by(restored, &a),
        );
        forget_session_peer(restored);
        forget_session_peer(moved);
        let forgotten = smf_self()
            .read()
            .unwrap()
            .session_upfs
            .read()
            .unwrap()
            .contains_key(&restored);

        if let Ok(ctx) = smf_self().read() {
            ctx.session_upfs
                .write()
                .unwrap()
                .insert(0x1031_0003, "gone.example:8805".to_string());
        }
        let unknown = unknown_session_upfs(&[a.clone(), b.clone()]);
        forget_session_peer(0x1031_0003);
        // Other tests' sessions may name other gone UPFs; this one is counted once.
        assert_eq!(unknown.get("gone.example:8805"), Some(&1));
        assert!(!unknown.contains_key(&b.recovery_time_stamp_key()));
        assert_eq!(
            reused_to,
            (Some(b.peer()), true, false),
            "identity before endpoint"
        );
        assert_eq!(routed, (Some(b.peer()), Some(b.peer())));
        assert_eq!(served, (true, false));
        assert!(!forgotten, "forgetting the session forgets its UPF");
    }

    /// #974 review m4: an Association Setup Response's Node ID teaches the client the
    /// UPF's other address (TS 29.244 §5.8.1), and an FQDN Node ID what it resolves to.
    #[tokio::test]
    async fn the_node_id_teaches_the_upfs_other_addresses() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = Arc::new(PfcpClient::new(
            sock,
            "10.0.0.7:8805".parse().unwrap(),
            [127, 0, 0, 1],
        ));
        let _pool = InstalledPool::new(vec![client.clone()]);
        let other: SocketAddr = "10.9.9.9:8805".parse().unwrap();
        assert!(!client.is_node_address(other));
        client
            .learn_node_addresses(&NodeId::new_ipv4([10, 9, 9, 9]))
            .await
            .unwrap();
        assert!(client.is_node_address(other));
        assert!(client.is_node_address("10.0.0.7:40001".parse().unwrap()));
        client
            .learn_node_addresses(&NodeId::new_fqdn("localhost".to_string()))
            .await
            .unwrap();
        assert!(client.is_node_address("127.0.0.1:8805".parse().unwrap()));
        assert!(
            !client.is_node_address(other),
            "relearnt at each association"
        );
    }

    /// #1091 review E: of two lookups for one UPF, the one started later wins, also
    /// when the older one finishes last.
    #[test]
    fn a_stale_address_lookup_cannot_overwrite_a_newer_one() {
        let known = std::sync::RwLock::new(Vec::new());
        let latest = std::sync::atomic::AtomicU64::new(0);
        let older = latest.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let newer = latest.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let moved: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        let before: std::net::IpAddr = "10.0.0.7".parse().unwrap();
        assert!(commit_node_addresses(&known, &latest, newer, vec![moved]));
        assert!(!commit_node_addresses(&known, &latest, older, vec![before]));
        assert_eq!(*known.read().unwrap(), vec![moved]);
    }

    /// #1091 review H: two Association Setups on one client, the first one's lookup
    /// slow: the second's addresses stay, though the first finishes last.
    #[tokio::test]
    async fn the_older_of_two_address_lookups_is_dropped_when_it_finishes_last() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = Arc::new(PfcpClient::new(
            sock,
            "10.0.0.7:8805".parse().unwrap(),
            [127, 0, 0, 1],
        ));
        let _pool = InstalledPool::new(vec![client.clone()]);
        *NODE_LOOKUP_DELAY_FOR_TEST.lock().unwrap() =
            Some(("localhost".to_string(), Duration::from_millis(300)));
        let older = client.learn_node_addresses(&NodeId::new_fqdn("localhost".to_string()));
        let newer = client.learn_node_addresses(&NodeId::new_ipv4([10, 9, 9, 9]));
        newer.await.unwrap();
        older.await.unwrap();
        *NODE_LOOKUP_DELAY_FOR_TEST.lock().unwrap() = None;

        assert!(
            client.is_node_address("10.9.9.9:8805".parse().unwrap()),
            "the newer set stays"
        );
        assert!(
            !client.is_node_address("127.0.0.1:8805".parse().unwrap()),
            "the older one, finished last, is dropped"
        );
    }

    /// #974 review n2: a learnt address that another pool member is dialled at is
    /// dropped: this UPF cannot vouch for its sibling's address.
    #[tokio::test]
    async fn a_learnt_address_of_another_pool_member_is_dropped() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a = Arc::new(PfcpClient::new(
            sock.clone(),
            "10.0.0.7:8805".parse().unwrap(),
            [127, 0, 0, 1],
        ));
        let b = Arc::new(PfcpClient::new(
            sock,
            "10.0.0.8:8805".parse().unwrap(),
            [127, 0, 0, 1],
        ));
        let _pool = InstalledPool::new(vec![a.clone(), b.clone()]);
        // A's Node ID names B's address.
        a.learn_node_addresses(&NodeId::new_ipv4([10, 0, 0, 8]))
            .await
            .unwrap();
        assert!(!a.is_node_address("10.0.0.8:40001".parse().unwrap()));
        assert!(b.is_node_address("10.0.0.8:40001".parse().unwrap()));
    }

    fn body_with_cause(cause: u8) -> Vec<u8> {
        vec![0x00, 19, 0x00, 0x01, cause]
    }

    #[test]
    fn test_parse_wire_header_with_seid() {
        let pkt = encode_wire_message(50, Some(0x1122334455667788), 0x00ABCDEF, &[1, 2, 3]);
        let h = parse_wire_header(&pkt).unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.msg_type, 50);
        assert!(h.seid_present);
        assert_eq!(h.seid, 0x1122334455667788);
        assert_eq!(h.sequence_number, 0x00ABCDEF);
        assert_eq!(&pkt[h.body_offset..], &[1, 2, 3]);
    }

    #[test]
    fn test_parse_wire_header_without_seid() {
        let pkt = encode_wire_message(1, None, 42, &[]);
        let h = parse_wire_header(&pkt).unwrap();
        assert_eq!(h.msg_type, 1);
        assert!(!h.seid_present);
        assert_eq!(h.sequence_number, 42);
        assert_eq!(h.body_offset, 8);
    }

    #[test]
    fn test_parse_cause() {
        assert_eq!(parse_cause(&body_with_cause(1)), Some(1));
        assert_eq!(parse_cause(&body_with_cause(72)), Some(72));
        assert_eq!(parse_cause(&[]), None);
        // Truncated IE must not be mis-parsed
        assert_eq!(parse_cause(&[0x00, 19, 0x00, 0x05, 1]), None);
    }

    #[test]
    fn test_is_response_type() {
        assert!(is_response_type(pfcp_message_type::HEARTBEAT_RESPONSE));
        assert!(is_response_type(
            pfcp_message_type::SESSION_ESTABLISHMENT_RESPONSE
        ));
        assert!(!is_response_type(pfcp_message_type::HEARTBEAT_REQUEST));
        assert!(!is_response_type(pfcp_message_type::SESSION_REPORT_REQUEST));
    }

    /// Association Setup round-trip against a fake UPF answering with the
    /// library-encoded response (mandatory Node ID, Cause, Recovery TS, plus
    /// UP Function Features).
    #[tokio::test]
    async fn test_association_setup_roundtrip() {
        // #718: `associate` asks for session retention when this process holds
        // sessions, and tears them down when the peer does not confirm it, so it
        // reads (and may flush) process-global session state.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, upf) = make_client_with_peer().await;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = upf.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            assert_eq!(h.msg_type, pfcp_message_type::ASSOCIATION_SETUP_REQUEST);
            // The request must carry Node ID (60) and Recovery Time Stamp (96)
            let body = &buf[h.body_offset..len];
            assert!(find_ie(body, 60).is_some(), "Node ID mandatory");
            let node_id = find_ie(body, 60).unwrap();
            assert_eq!(node_id[0], 0, "Node ID type octet = IPv4");
            assert_eq!(&node_id[1..5], &[127, 0, 0, 1]);
            assert!(find_ie(body, 96).is_some(), "Recovery Time Stamp mandatory");

            let mut resp = AssociationSetupResponse::new(
                NodeId::new_ipv4([127, 0, 0, 4]),
                nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                777,
            );
            resp.up_function_features = Some(UpFunctionFeatures {
                ftup: true,
                empu: true,
                ..Default::default()
            });
            let msg = PfcpMessage::AssociationSetupResponse(resp);
            let pkt = build_message(&msg, h.sequence_number, None);
            upf.send_to(&pkt, from).await.unwrap();
        });

        client.associate().await.expect("association must succeed");
        assert!(client.is_associated().await);
        let st = client.association().await;
        assert_eq!(
            st.peer_recovery_time_stamp, None,
            "#966: the Association Setup Response's stamp is ignored (TS 23.007 §19A)"
        );
        assert!(st.up_function_features.unwrap().ftup);
    }

    /// #658: `UPF_PFCP_ADDR` entries parse as literals or hostnames; a hostname
    /// is kept as a name (not resolved, not rejected) so the SMF can start before
    /// the UPF's DNS record exists.
    #[test]
    fn upf_peer_entries_parse_as_literals_or_hostnames() {
        assert_eq!(
            parse_upf_peer("10.0.0.5", 8805),
            Ok(UpfPeerSpec::Literal("10.0.0.5:8805".parse().unwrap()))
        );
        assert_eq!(
            parse_upf_peer("10.0.0.6:8806", 8805),
            Ok(UpfPeerSpec::Literal("10.0.0.6:8806".parse().unwrap()))
        );
        assert_eq!(
            parse_upf_peer("::1", 8805),
            Ok(UpfPeerSpec::Literal("[::1]:8805".parse().unwrap()))
        );
        assert_eq!(
            parse_upf_peer("upf.nextg-system.svc.cluster.local", 8805),
            Ok(UpfPeerSpec::Hostname(
                "upf.nextg-system.svc.cluster.local".into(),
                8805
            ))
        );
        assert_eq!(
            parse_upf_peer("upf:8806", 8805),
            Ok(UpfPeerSpec::Hostname("upf".into(), 8806))
        );
        assert!(parse_upf_peer("upf:notaport", 8805).is_err());
        assert!(parse_upf_peer("bad host", 8805).is_err());
        assert!(parse_upf_peer("", 8805).is_err());
    }

    /// Answer one Association Setup Request on `upf` with Request Accepted.
    async fn accept_one_association(upf: UdpSocket, rts: u32) {
        let mut buf = vec![0u8; 4096];
        let (len, from) = upf.recv_from(&mut buf).await.unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(h.msg_type, pfcp_message_type::ASSOCIATION_SETUP_REQUEST);
        let resp = AssociationSetupResponse::new(
            NodeId::new_ipv4([127, 0, 0, 4]),
            nextgcore_pfcp::types::PfcpCause::RequestAccepted,
            rts,
        );
        let pkt = build_message(
            &PfcpMessage::AssociationSetupResponse(resp),
            h.sequence_number,
            None,
        );
        upf.send_to(&pkt, from).await.unwrap();
    }

    /// The Node ID IE value (TS 29.244 §8.2.38) of a PFCP message body.
    fn node_id_ie(body: &[u8]) -> Vec<u8> {
        let mut off = 0usize;
        while off + 4 <= body.len() {
            let t = u16::from_be_bytes([body[off], body[off + 1]]);
            let l = usize::from(u16::from_be_bytes([body[off + 2], body[off + 3]]));
            if t == 60 {
                return body[off + 4..off + 4 + l].to_vec();
            }
            off += 4 + l;
        }
        panic!("no Node ID IE in {body:02x?}")
    }

    /// #797: the Node ID the SMF signals in Association Setup and Association Release
    /// is the configured one (here the Service FQDN), not the F-SEID address. Before
    /// #797 the Node ID was the N4 bind address, 0.0.0.0 on k8s. The FQDN is RFC 1035
    /// labels without the trailing zero byte (§8.2.38).
    #[tokio::test]
    async fn the_association_signals_the_configured_fqdn_node_id() {
        // #723: the release reaches `teardown_association`, which is process-wide.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let upf = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = pumped_client(
            PfcpClient::new(local, upf.local_addr().unwrap(), [10, 1, 2, 3])
                .with_node_id(NodeId::new_fqdn("smf.nextg.svc".into())),
        )
        .await;
        let expected: &[u8] = &[
            2, 3, b's', b'm', b'f', 5, b'n', b'e', b'x', b't', b'g', 3, b's', b'v', b'c',
        ];

        let answer = tokio::spawn(async move {
            let mut bodies = Vec::new();
            let mut buf = vec![0u8; 4096];
            for _ in 0..2 {
                let (len, from) = upf.recv_from(&mut buf).await.unwrap();
                let h = parse_wire_header(&buf[..len]).unwrap();
                bodies.push((h.msg_type, buf[h.body_offset..len].to_vec()));
                let msg = if h.msg_type == pfcp_message_type::ASSOCIATION_SETUP_REQUEST {
                    PfcpMessage::AssociationSetupResponse(AssociationSetupResponse::new(
                        NodeId::new_ipv4([127, 0, 0, 4]),
                        nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                        5,
                    ))
                } else {
                    PfcpMessage::AssociationReleaseResponse(
                        nextgcore_pfcp::message::AssociationReleaseResponse::new(
                            NodeId::new_ipv4([127, 0, 0, 4]),
                            nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                        ),
                    )
                };
                upf.send_to(&build_message(&msg, h.sequence_number, None), from)
                    .await
                    .unwrap();
            }
            bodies
        });

        client.associate().await.expect("association must succeed");
        client
            .release_association()
            .await
            .expect("release must succeed");
        let bodies = answer.await.unwrap();
        assert_eq!(bodies[0].0, pfcp_message_type::ASSOCIATION_SETUP_REQUEST);
        assert_eq!(node_id_ie(&bodies[0].1), expected);
        assert_eq!(bodies[1].0, pfcp_message_type::ASSOCIATION_RELEASE_REQUEST);
        assert_eq!(node_id_ie(&bodies[1].1), expected);
        assert_eq!(
            client.node_ip(),
            [10, 1, 2, 3],
            "the F-SEID address is separate"
        );
    }

    /// Bind a client to `peer`, pumping its socket into the engine.
    async fn pumped_client(client: PfcpClient) -> Arc<PfcpClient> {
        let client = Arc::new(client);
        let c = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, from)) = c.socket.recv_from(&mut buf).await else {
                    break;
                };
                c.on_datagram(&buf[..len], from).await;
            }
        });
        client
    }

    /// #658: a UPF named by hostname that comes back at a NEW address (a
    /// restarted pod) is found again. The client was associated with the old
    /// UPF; that UPF is gone and its address is dead. The association attempt
    /// re-resolves the name and lands on the new UPF.
    ///
    /// Before #658 the endpoint was fixed at startup and every Association Setup
    /// went to the dead address forever.
    #[tokio::test]
    async fn a_upf_named_by_hostname_is_found_again_at_its_new_address() {
        // #723: reaches `teardown_association`, which is process-wide (AMF
        // callbacks, EPC PDN connections, the `pfcp_sessions` map). Documented
        // order: ambient state first, N4 second.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        // The old UPF incarnation: associates once, then dies.
        let old_upf = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_addr = old_upf.local_addr().unwrap();
        // The new incarnation is bound on another port of the same host, so
        // "localhost" stands in for the Service name that now points at it.
        let new_upf = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_port = new_upf.local_addr().unwrap().port();

        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = pumped_client(
            PfcpClient::new(local, old_addr, [127, 0, 0, 1])
                .with_peer_hostname("localhost", new_port)
                .with_association_timer_for_test(Duration::from_millis(100), 1),
        )
        .await;

        // Associated with the old UPF directly (no re-resolution yet).
        tokio::spawn(accept_one_association(old_upf, 1000));
        client.associate().await.expect("first association");
        assert_eq!(client.peer(), old_addr);
        // The old UPF dies: heartbeat exhaustion marks the association down.
        client.set_assoc_state_for_test(false, None, None).await;

        tokio::spawn(accept_one_association(new_upf, 2000));
        try_associate(&client)
            .await
            .expect("the association must be re-established at the new address");
        assert!(client.is_associated().await);
        assert_eq!(client.peer().port(), new_port);
        assert!(client.peer().ip().is_loopback());
        assert_eq!(
            client.association().await.peer_recovery_time_stamp,
            None,
            "#966: no stamp until the new association's first Heartbeat"
        );
    }

    /// #930 review m2, #966 review m2: a hostname UPF's identity (`recovery_time_stamp_key`,
    /// the key of its restored sessions #1031 and its failed GTP-U peers #994) is the
    /// configured name lower-cased and without a trailing root dot, so a cosmetic
    /// configuration edit keeps it. A literal UPF's is its address.
    #[tokio::test]
    async fn a_hostname_upfs_identity_is_its_normalised_name() {
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let unresolved: SocketAddr = "0.0.0.0:8805".parse().unwrap();
        let named = PfcpClient::new(local.clone(), unresolved, [127, 0, 0, 1])
            .with_peer_hostname("UPF-1.Example.", 8805);
        let literal = PfcpClient::new(local, "10.0.0.9:8805".parse().unwrap(), [127, 0, 0, 1]);
        assert_eq!(named.recovery_time_stamp_key(), "upf-1.example:8805");
        assert_eq!(literal.recovery_time_stamp_key(), "10.0.0.9:8805");
    }

    /// #928 review: two endpoints are one PFCP node when their canonical IP is the
    /// same, whatever the port (TS 29.244 §4.2.2, TS 23.007 §19A).
    #[test]
    fn same_pfcp_node_compares_the_canonical_ip_not_the_port() {
        let a: SocketAddr = "10.0.0.7:8805".parse().unwrap();
        assert!(same_pfcp_node(a, "10.0.0.7:40001".parse().unwrap()));
        assert!(same_pfcp_node(a, "[::ffff:10.0.0.7]:8805".parse().unwrap()));
        assert!(!same_pfcp_node(a, "10.0.0.8:8805".parse().unwrap()));
        assert!(!same_pfcp_node(a, "[2001:db8::7]:8805".parse().unwrap()));
    }

    /// #722, #966: a UPF named by hostname moved while the SMF was down. The restarted
    /// SMF finds it by name although the name now resolves elsewhere, and the new
    /// incarnation, which does not confirm retaining the restored session (no PSREI,
    /// #718), has it flushed and released (#39). No durable stamp is involved: TS
    /// 23.007 §19A keeps the remote stamp in volatile memory.
    #[tokio::test]
    async fn a_restored_session_on_a_moved_hostname_upf_is_released_without_psrei() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        // UPF B, the new incarnation, is where "localhost" now points.
        let upf_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port_b = upf_b.local_addr().unwrap().port();
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let unresolved = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port_b);
        let client = pumped_client(
            PfcpClient::new(local, unresolved, [127, 0, 0, 1])
                .with_peer_hostname("localhost", port_b),
        )
        .await;
        let _pool = InstalledPool::new(vec![client.clone()]);
        let key = format!("localhost:{port_b}");
        assert_eq!(client.recovery_time_stamp_key(), key);
        // A restored session (no recorded UPF), with a UE to release it through.
        seed_pfcp_session("72201", 0x722);
        let mut b = crate::context::PolicyBinding::snapshot_default();
        b.supi = "imsi-001010000000722".to_string();
        b.psi = 5;
        b.sm_context_status_uri = Some("http://127.0.0.1:1/sm-status".to_string());
        smf_self()
            .read()
            .unwrap()
            .policy_bindings
            .write()
            .unwrap()
            .insert("72201".to_string(), b);

        let answered = tokio::spawn(answer_association_setup(upf_b, 200, false));
        try_associate(&client).await.expect("association with B");
        let _ = answered.await;
        // #928: the restart's #39 fan-out runs off the association task; wait for it.
        drain_restart_fanouts(Duration::from_secs(5)).await;
        let kept = pfcp_session_present("72201");
        let released = crate::cancel_gsm_timer_for_test("72201");
        forget_pfcp_session("72201");
        if let Ok(ctx) = smf_self().read() {
            ctx.policy_bindings.write().unwrap().remove("72201");
        }

        assert!(!kept, "the restored session is flushed");
        assert!(released, "and released through the UE (#39)");
        assert_eq!(client.peer().port(), port_b);
    }

    /// Answer one Association Setup Request on `upf` with Request Accepted, the
    /// Recovery Time Stamp `rts`, and PSREI when `psrei`; returns the request body.
    async fn answer_association_setup(upf: UdpSocket, rts: u32, psrei: bool) -> Vec<u8> {
        answer_association_setup_on(&upf, rts, psrei).await
    }

    /// [`answer_association_setup`] on a socket the caller keeps.
    async fn answer_association_setup_on(upf: &UdpSocket, rts: u32, psrei: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let (len, from) = upf.recv_from(&mut buf).await.unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(h.msg_type, pfcp_message_type::ASSOCIATION_SETUP_REQUEST);
        let request = buf[h.body_offset..len].to_vec();
        let resp = AssociationSetupResponse::new(
            NodeId::new_ipv4([127, 0, 0, 4]),
            nextgcore_pfcp::types::PfcpCause::RequestAccepted,
            rts,
        );
        let mut body = bytes::BytesMut::new();
        PfcpMessage::AssociationSetupResponse(resp).encode_body(&mut body);
        if psrei {
            body.put_u16(PFCPASRSP_FLAGS);
            body.put_u16(1);
            body.put_u8(0x01);
        }
        let pkt = encode_wire_message(
            pfcp_message_type::ASSOCIATION_SETUP_RESPONSE,
            None,
            h.sequence_number,
            &body,
        );
        upf.send_to(&pkt, from).await.unwrap();
        request
    }

    fn seed_pfcp_session(sm_context_ref: &str, upf_seid: u64) {
        smf_self()
            .read()
            .unwrap()
            .pfcp_sessions
            .write()
            .unwrap()
            .insert(sm_context_ref.to_string(), upf_seid);
    }

    fn pfcp_session_present(sm_context_ref: &str) -> bool {
        smf_self()
            .read()
            .unwrap()
            .pfcp_sessions
            .read()
            .unwrap()
            .contains_key(sm_context_ref)
    }

    /// #718: an SMF with no sessions (a fresh incarnation without durable state)
    /// does not ask the UPF to retain anything, so a conformant UPF deletes whatever
    /// the previous incarnation left under this Node ID (TS 29.244 §6.2.6.2.2).
    #[tokio::test]
    async fn an_smf_holding_no_sessions_asks_the_upf_to_retain_nothing() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        // Leftovers of earlier tests in this process; both locks are held, so they
        // belong to nobody running now.
        clear_pfcp_sessions();
        if let Ok(ctx) = smf_self().read() {
            for sess in ctx.sess_find_all_by(|s| s.epc && s.upf_n4_seid != 0) {
                ctx.sess_remove(sess.id);
            }
        }
        assert!(
            !holds_pfcp_sessions(),
            "precondition: no 5G or EPC session is held"
        );
        let (client, upf) = make_client_with_peer().await;
        let answered = tokio::spawn(answer_association_setup(upf, 500, false));
        client.associate().await.expect("association");
        let request = answered.await.unwrap();
        assert!(
            find_ie(&request, 60).is_some(),
            "the request is the real one"
        );
        assert!(
            find_ie(&request, PFCP_SESSION_RETENTION_INFORMATION).is_none(),
            "no PFCP Session Retention Information without sessions to keep"
        );
    }

    /// #718: an SMF that holds sessions (restored from durable state, or kept
    /// across a lost heartbeat) asks for all of them to be retained, and keeps them
    /// when the UPF confirms with PSREI.
    #[tokio::test]
    async fn an_smf_holding_sessions_asks_for_them_and_keeps_them_when_retained() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        seed_pfcp_session("71801", 0x718a);
        let (client, upf) = make_client_with_peer().await;
        let seid = crate::context::derive_cp_n4_seid("71801");
        record_session_peer(seid, client.peer());
        let answered = tokio::spawn(answer_association_setup(upf, 600, true));
        client.associate().await.expect("association");
        let request = answered.await.unwrap();
        let kept = pfcp_session_present("71801");
        forget_pfcp_session("71801");
        forget_session_peer(seid);

        assert_eq!(
            find_ie(&request, PFCP_SESSION_RETENTION_INFORMATION),
            Some(&[][..]),
            "an empty retention IE: keep every session (TS 29.244 Table 7.4.4.1-2)"
        );
        assert!(
            kept,
            "PSREI: the UPF retained the session, so the SMF keeps it"
        );
        assert!(client.is_associated().await);
    }

    /// #718: retention was asked for and the UPF did not confirm it. Its sessions
    /// are gone there, so the SMF must not keep believing in them: it releases them,
    /// as it would after a UPF restart.
    #[tokio::test]
    async fn sessions_the_upf_did_not_retain_are_released() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        seed_pfcp_session("71802", 0x718b);
        let (client, upf) = make_client_with_peer().await;
        let seid = crate::context::derive_cp_n4_seid("71802");
        record_session_peer(seid, client.peer());
        // The same stamp as the Heartbeats had: only PSREI tells (#966).
        client.seed_peer_recovery_time_stamp(700).await;
        let answered = tokio::spawn(answer_association_setup(upf, 700, false));
        client.associate().await.expect("association");
        let request = answered.await.unwrap();
        let kept = pfcp_session_present("71802");
        forget_pfcp_session("71802");
        forget_session_peer(seid);

        assert!(find_ie(&request, PFCP_SESSION_RETENTION_INFORMATION).is_some());
        assert!(!kept, "no PSREI: the session is released, not believed");
        assert!(
            client.is_associated().await,
            "the association itself stands; only the sessions were lost"
        );
    }

    /// Answer one Heartbeat Request on `upf` with the Recovery Time Stamp `rts`.
    async fn answer_heartbeat_on(upf: &UdpSocket, rts: u32) {
        let mut buf = vec![0u8; 4096];
        let (len, from) = upf.recv_from(&mut buf).await.unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(h.msg_type, pfcp_message_type::HEARTBEAT_REQUEST);
        let msg = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(rts));
        let pkt = build_message(&msg, h.sequence_number, None);
        upf.send_to(&pkt, from).await.unwrap();
    }

    /// #966, TS 23.007 §19A ("A PFCP function shall ignore the Recovery Timestamp
    /// received in PFCP Association Setup Request and PFCP Association Setup Response
    /// messages") and TS 29.244 Table 7.4.4.2-1 NOTE. The UPF re-associates with a
    /// stamp other than the one its Heartbeats carried, and confirms retaining the
    /// session (PSREI): the session is kept, nothing is torn down, and the stamp is
    /// not stored. Before #966 the stamp was compared and the change released the
    /// session the UPF had just said it kept.
    #[tokio::test]
    async fn the_association_setup_stamp_is_neither_compared_nor_stored() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        seed_pfcp_session("96601", 0x966a);
        let (client, upf) = make_client_with_peer().await;
        let seid = crate::context::derive_cp_n4_seid("96601");
        record_session_peer(seid, client.peer());
        client.seed_peer_recovery_time_stamp(100).await;
        let answered = tokio::spawn(answer_association_setup(upf, 200, true));
        client.associate().await.expect("association");
        let _ = answered.await;
        drain_restart_fanouts(Duration::from_secs(5)).await;
        let kept = pfcp_session_present("96601");
        let released = crate::cancel_gsm_timer_for_test("96601");
        let stored = client.association().await.peer_recovery_time_stamp;
        forget_pfcp_session("96601");
        forget_session_peer(seid);

        assert!(kept, "the retained session is kept");
        assert!(!released, "and not released");
        assert!(client.is_associated().await, "nothing is torn down");
        assert_eq!(stored, None, "the Association Setup stamp is not stored");
    }

    /// #966: a UPF restarted while its Heartbeats went unanswered. The new
    /// association finds the old sessions gone (no PSREI) and releases them; a
    /// session set up on the new association then survives that association's first
    /// Heartbeat, whose stamp is the baseline (§19A "If no previous value was
    /// stored"). Had the previous incarnation's stamp been kept, that Heartbeat read as
    /// a second restart and released the new session too.
    #[tokio::test]
    async fn a_new_associations_first_heartbeat_stamp_is_its_baseline() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        seed_pfcp_session("96602", 0x966b);
        let (client, upf) = make_client_with_peer().await;
        let old = crate::context::derive_cp_n4_seid("96602");
        record_session_peer(old, client.peer());
        // The previous incarnation's stamp, from its Heartbeats.
        client.seed_peer_recovery_time_stamp(100).await;
        let upf = Arc::new(upf);
        let fake = upf.clone();
        let answered =
            tokio::spawn(async move { answer_association_setup_on(&fake, 200, false).await });
        client.associate().await.expect("association");
        let _ = answered.await;
        drain_restart_fanouts(Duration::from_secs(5)).await;
        let old_kept = pfcp_session_present("96602");
        forget_pfcp_session("96602");
        forget_session_peer(old);

        // A session established on the new association.
        seed_pfcp_session("96603", 0x966c);
        let new = crate::context::derive_cp_n4_seid("96603");
        record_session_peer(new, client.peer());
        let fake = upf.clone();
        let answered = tokio::spawn(async move { answer_heartbeat_on(&fake, 200).await });
        let alive = client.heartbeat_once().await;
        let _ = answered.await;
        drain_restart_fanouts(Duration::from_secs(5)).await;
        let new_kept = pfcp_session_present("96603");
        let new_released = crate::cancel_gsm_timer_for_test("96603");
        let stored = client.association().await.peer_recovery_time_stamp;
        forget_pfcp_session("96603");
        forget_session_peer(new);

        assert!(!old_kept, "no PSREI: the old session is released");
        assert!(alive.is_ok());
        assert!(
            new_kept,
            "the new association's session survives its first Heartbeat"
        );
        assert!(!new_released);
        assert!(client.is_associated().await, "no second teardown");
        assert_eq!(
            stored,
            Some(200),
            "the first Heartbeat stamp is the baseline"
        );
    }

    /// #966 review M1: the UPF restarts after the Association Setup and before the
    /// association's first Heartbeat. That Heartbeat carries only the new incarnation's
    /// stamp, which is the baseline, so no stamp shows the restart. The restarted UPF
    /// answers the next session request with cause 72 "No established PFCP Association"
    /// (TS 29.244 §8.2.1): the association is torn down, its sessions released, and the
    /// association loop sets it up again. Before, the SMF stayed "associated" and every
    /// new session on that UPF was refused.
    #[tokio::test]
    async fn a_cause_72_answer_to_a_session_request_tears_the_association_down() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, upf) = make_client_with_peer().await;
        let upf = Arc::new(upf);
        let fake = upf.clone();
        let answered =
            tokio::spawn(async move { answer_association_setup_on(&fake, 200, false).await });
        client.associate().await.expect("association");
        let _ = answered.await;
        // The UPF restarted; the association's first Heartbeat is the new incarnation's.
        let fake = upf.clone();
        let answered = tokio::spawn(async move { answer_heartbeat_on(&fake, 300).await });
        client.heartbeat_once().await.expect("heartbeat");
        let _ = answered.await;
        assert!(client.is_associated().await, "no stamp shows the restart");
        seed_pfcp_session("96604", 0x966d);
        let seid = crate::context::derive_cp_n4_seid("96604");
        record_session_peer(seid, client.peer());

        let fake = upf.clone();
        let answered = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = fake.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            assert_eq!(h.msg_type, pfcp_message_type::SESSION_MODIFICATION_REQUEST);
            // Cause (IE 19) 72, No established PFCP Association.
            let pkt = encode_wire_message(
                pfcp_message_type::SESSION_MODIFICATION_RESPONSE,
                Some(0),
                h.sequence_number,
                &[0x00, 0x13, 0x00, 0x01, 72],
            );
            fake.send_to(&pkt, from).await.unwrap();
        });
        let result = client
            .session_request(
                pfcp_message_type::SESSION_MODIFICATION_REQUEST,
                seid,
                Some(0x966d),
                &[],
            )
            .await;
        let _ = answered.await;
        drain_restart_fanouts(Duration::from_secs(5)).await;
        let kept = pfcp_session_present("96604");
        forget_pfcp_session("96604");
        forget_session_peer(seid);

        assert!(
            result.is_ok(),
            "the answer itself is returned to the caller"
        );
        assert!(
            !client.is_associated().await,
            "the association is torn down"
        );
        assert!(!kept, "and the sessions the UPF no longer has are flushed");
    }

    /// #966 follow-up: a cause 72 that answers a request sent on an EARLIER association
    /// does not tear down the one set up since. Here the request goes out, the
    /// association is replaced (a new Association Setup bumps its generation) while it
    /// is in flight, and its late answer is cause 72: the current association and its
    /// sessions are kept.
    #[tokio::test]
    async fn a_late_cause_72_does_not_tear_down_the_next_association() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _seeded = crate::context::SeededState::track();
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, upf) = make_client_with_peer().await;
        let upf = Arc::new(upf);
        let fake = upf.clone();
        let answered =
            tokio::spawn(async move { answer_association_setup_on(&fake, 200, false).await });
        client.associate().await.expect("association");
        let _ = answered.await;
        seed_pfcp_session("96605", 0x966e);
        let seid = crate::context::derive_cp_n4_seid("96605");
        record_session_peer(seid, client.peer());

        let (received_tx, received_rx) = tokio::sync::oneshot::channel::<()>();
        let (answer_tx, answer_rx) = tokio::sync::oneshot::channel::<()>();
        let fake = upf.clone();
        let answered = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = fake.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            let _ = received_tx.send(());
            let _ = answer_rx.await;
            let pkt = encode_wire_message(
                pfcp_message_type::SESSION_MODIFICATION_RESPONSE,
                Some(0),
                h.sequence_number,
                &[0x00, 0x13, 0x00, 0x01, 72],
            );
            fake.send_to(&pkt, from).await.unwrap();
        });
        let reassociate = async {
            let _ = received_rx.await;
            // What a successful Association Setup does meanwhile.
            client.assoc.write().await.generation += 1;
            let _ = answer_tx.send(());
        };
        let (result, ()) = tokio::join!(
            client.session_request(
                pfcp_message_type::SESSION_MODIFICATION_REQUEST,
                seid,
                Some(0x966e),
                &[],
            ),
            reassociate
        );
        let _ = answered.await;
        drain_restart_fanouts(Duration::from_secs(5)).await;
        let kept = pfcp_session_present("96605");
        forget_pfcp_session("96605");
        forget_session_peer(seid);

        assert!(result.is_ok());
        assert!(
            client.is_associated().await,
            "the association set up since is kept"
        );
        assert!(kept, "and its sessions");
    }

    /// #966 follow-up 2: the generation is the one the request is SENT on. Here the
    /// association is replaced after `session_request` is called and before its datagram
    /// leaves; the cause 72 that answers it is about the association set up since, which
    /// is torn down. Read when `session_request` was called, the generation was the old
    /// one, and that detection was missed.
    #[tokio::test]
    async fn a_cause_72_to_a_request_sent_on_the_new_association_tears_it_down() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _seeded = crate::context::SeededState::track();
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, upf) = make_client_with_peer().await;
        let upf = Arc::new(upf);
        let fake = upf.clone();
        let answered =
            tokio::spawn(async move { answer_association_setup_on(&fake, 200, false).await });
        client.associate().await.expect("association");
        let _ = answered.await;
        seed_pfcp_session("96606", 0x966f);
        let seid = crate::context::derive_cp_n4_seid("96606");
        record_session_peer(seid, client.peer());

        let fake = upf.clone();
        let answered = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = fake.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            let pkt = encode_wire_message(
                pfcp_message_type::SESSION_MODIFICATION_RESPONSE,
                Some(0),
                h.sequence_number,
                &[0x00, 0x13, 0x00, 0x01, 72],
            );
            fake.send_to(&pkt, from).await.unwrap();
        });
        // Held so the request is called but cannot leave until the association is
        // replaced.
        let pending = client.pending.lock().await;
        let reassociate = async {
            client.assoc.write().await.generation += 1;
            drop(pending);
        };
        let (result, ()) = tokio::join!(
            client.session_request(
                pfcp_message_type::SESSION_MODIFICATION_REQUEST,
                seid,
                Some(0x966f),
                &[],
            ),
            reassociate
        );
        let _ = answered.await;
        drain_restart_fanouts(Duration::from_secs(5)).await;
        let kept = pfcp_session_present("96606");
        forget_pfcp_session("96606");
        forget_session_peer(seid);

        assert!(result.is_ok());
        assert!(
            !client.is_associated().await,
            "the association the request was sent on is torn down"
        );
        assert!(!kept, "and its sessions flushed");
    }

    /// #966 review m3: the stored stamp goes when the association does (TS 23.007 §19A,
    /// volatile). A request that runs out N1 marks the association down; an unsolicited
    /// Heartbeat Request while unassociated then stores its stamp as the baseline
    /// instead of reading the old incarnation's as a restart, which released the
    /// sessions before the re-association's retention could keep them.
    #[tokio::test]
    async fn a_lost_association_forgets_the_peer_stamp() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = PfcpClient::new(local, silent.local_addr().unwrap(), [127, 0, 0, 1])
            .with_association_timer_for_test(Duration::from_millis(30), 0);
        client.set_assoc_state_for_test(true, None, None).await;
        client.seed_peer_recovery_time_stamp(100).await;
        let result = client
            // A node-level request: the shortened association T1/N1 applies.
            .request(pfcp_message_type::ASSOCIATION_SETUP_REQUEST, None, &[])
            .await;
        let stored = client.association().await.peer_recovery_time_stamp;
        let restart = client.detect_peer_restart(200, StampSource::Request).await;
        let restarted = restart.is_some();
        if let Some(f) = restart {
            let _ = f.await;
        }

        assert!(matches!(result, Err(PfcpRequestError::Timeout { .. })));
        assert!(!client.is_associated().await);
        assert_eq!(stored, None, "the stamp went with the association");
        assert!(!restarted, "the next stamp is a baseline, not a restart");
    }

    /// #718 review M1: in a UPF pool, a member that holds none of the SMF's sessions
    /// asks for no retention, and its answer without PSREI releases nothing. Before,
    /// the check was process-wide: a pool member associating late asked to retain the
    /// sessions on the OTHER UPF, got no PSREI, and every UE on the healthy UPF was
    /// released with #39.
    #[tokio::test]
    async fn a_pool_member_holding_none_of_the_sessions_asks_for_none_and_releases_none() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        // The session lives on UPF A.
        seed_pfcp_session("71803", 0x718c);
        let (client_a, _upf_a) = make_client_with_peer().await;
        let seid = crate::context::derive_cp_n4_seid("71803");
        record_session_peer(seid, client_a.peer());
        // UPF B associates late: it never had an association, so no PSREI.
        let (client_b, upf_b) = make_client_with_peer().await;
        let answered = tokio::spawn(answer_association_setup(upf_b, 800, false));
        client_b.associate().await.expect("association");
        let request = answered.await.unwrap();
        let kept = pfcp_session_present("71803");
        forget_pfcp_session("71803");
        forget_session_peer(seid);

        assert!(
            find_ie(&request, PFCP_SESSION_RETENTION_INFORMATION).is_none(),
            "UPF B holds none of the sessions, so it is asked to retain none"
        );
        assert!(
            kept,
            "the session on UPF A is untouched by UPF B's association"
        );
        assert!(client_b.is_associated().await);
    }

    /// #718 review M1: a session with no recorded UPF (restored from durable state)
    /// is the default client's, exactly as `client_for_session` routes it; a client
    /// that is not the default does not claim it.
    #[tokio::test]
    async fn a_restored_session_belongs_to_the_default_client_only() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = stand_in::install_stand_in_upf().await;
        let (other, _peer) = make_client_with_peer().await;
        let seid = crate::context::derive_cp_n4_seid("71804");
        assert!(session_served_by(seid, &upf.client));
        assert!(!session_served_by(seid, &other));
        // Recorded on a pool member: that member's, not the default client's.
        record_session_peer(seid, upf.client.peer());
        assert!(session_served_by(seid, &upf.client));
        assert!(!session_served_by(seid, &other));
        forget_session_peer(seid);
    }

    /// #720: a UPF restart affects only that UPF's sessions. Two UPFs in the pool;
    /// a session on each. UPF B restarts (a changed Recovery Time Stamp on its
    /// heartbeat). B's session is released through the UE (#39, T3592 armed) and
    /// flushed; A's session gets no release and stays in the map, as does its
    /// binding. Before #720 the teardown walked every session in the process, so a
    /// restart of B released every UE on A and orphaned A's sessions in A.
    #[tokio::test]
    async fn a_upf_restart_releases_only_that_upfs_sessions() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client_a, _upf_a) = make_client_with_peer().await;
        let (client_b, _upf_b) = make_client_with_peer().await;
        set_global_pool(vec![client_a.clone(), client_b.clone()]);
        let seed = |r: &str, upf_seid: u64, client: &PfcpClient, psi: u8| {
            seed_pfcp_session(r, upf_seid);
            record_session_peer(crate::context::derive_cp_n4_seid(r), client.peer());
            let mut b = crate::context::PolicyBinding::snapshot_default();
            b.supi = "imsi-001010000000720".to_string();
            b.psi = psi;
            // Unreachable: the release is still sent and T3592 armed.
            b.sm_context_status_uri = Some("http://127.0.0.1:1/sm-status".to_string());
            smf_self()
                .read()
                .unwrap()
                .policy_bindings
                .write()
                .unwrap()
                .insert(r.to_string(), b);
        };
        seed("72001", 0x720a, &client_a, 5);
        seed("72002", 0x720b, &client_b, 6);

        // B restarts: a changed stamp after the one it associated with.
        client_b.seed_peer_recovery_time_stamp(100).await;
        client_b.check_peer_restart(200).await;

        let a_kept = pfcp_session_present("72001");
        let b_kept = pfcp_session_present("72002");
        let a_released = crate::cancel_gsm_timer_for_test("72001");
        let b_released = crate::cancel_gsm_timer_for_test("72002");
        let a_binding = crate::lookup_policy_binding_for_test("72001");
        for r in ["72001", "72002"] {
            forget_pfcp_session(r);
            forget_session_peer(crate::context::derive_cp_n4_seid(r));
            smf_self()
                .read()
                .unwrap()
                .policy_bindings
                .write()
                .unwrap()
                .remove(r);
        }
        clear_global_upf_for_test();

        assert!(b_released, "B's session is released through the UE (#39)");
        assert!(!b_kept, "and flushed");
        assert!(!a_released, "A's session gets no release");
        assert!(a_kept, "A's session stays in the map");
        assert!(a_binding, "A's binding stays");
    }

    /// #720: the scope of one UPF's teardown, including EPC PDN connections: only
    /// the sessions recorded on that UPF, and a restored (unrecorded) session is the
    /// default client's.
    #[tokio::test]
    async fn a_upfs_teardown_scope_is_its_own_sessions() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _seeded = crate::context::SeededState::track();
        let _map_guard = N4_TEST_LOCK.lock().await;
        crate::context::smf_context_init(64, 256, 512);
        let (client_a, _upf_a) = make_client_with_peer().await;
        let (client_b, _upf_b) = make_client_with_peer().await;
        set_global_pool(vec![client_a.clone(), client_b.clone()]);
        seed_pfcp_session("72011", 1);
        record_session_peer(crate::context::derive_cp_n4_seid("72011"), client_b.peer());
        seed_pfcp_session("72012", 2); // restored: no recorded peer
        let (epc_a, epc_b) = {
            let ctx = smf_self();
            let ctx = ctx.read().unwrap();
            let ue = ctx.ue_add_by_imsi(b"001010000072010").expect("ue");
            let a = ctx.sess_add_by_apn(ue.id, "internet", 6).expect("a");
            let b = ctx.sess_add_by_apn(ue.id, "ims", 6).expect("b");
            record_session_peer(a.smf_n4_seid, client_a.peer());
            record_session_peer(b.smf_n4_seid, client_b.peer());
            (a, b)
        };

        let scope_a = client_a.session_scope();
        let scope_b = client_b.session_scope();
        for r in ["72011", "72012"] {
            forget_pfcp_session(r);
            forget_session_peer(crate::context::derive_cp_n4_seid(r));
        }
        // #1059 round 2, m3: not under the context guard (forget_session_peer takes
        // it, and a recursive std read deadlocks behind a queued writer).
        for s in [&epc_a, &epc_b] {
            forget_session_peer(s.smf_n4_seid);
        }
        if let Ok(ctx) = smf_self().read() {
            for s in [&epc_a, &epc_b] {
                ctx.sess_remove(s.id);
            }
        }
        clear_global_upf_for_test();

        assert!(scope_b.refs.contains("72011") && !scope_a.refs.contains("72011"));
        assert!(scope_a.refs.contains("72012") && !scope_b.refs.contains("72012"));
        assert!(scope_a.epc_sess_ids.contains(&epc_a.id));
        assert!(!scope_a.epc_sess_ids.contains(&epc_b.id));
        assert!(scope_b.epc_sess_ids.contains(&epc_b.id));
        assert!(!scope_b.epc_sess_ids.contains(&epc_a.id));
    }

    /// Install `clients` as the process pool for a test, and uninstall on drop.
    struct InstalledPool;
    impl InstalledPool {
        fn new(clients: Vec<Arc<PfcpClient>>) -> Self {
            set_global_pool(clients);
            InstalledPool
        }
    }
    impl Drop for InstalledPool {
        fn drop(&mut self) {
            clear_global_upf_for_test();
        }
    }

    /// #809 follow-up: at shutdown the #39 releases are bounded. The AMF accepts the
    /// connection and never answers, so each release would wait out its timeouts.
    /// With a 300 ms budget the release returns at once, and the Association Release
    /// still reaches the UPF.
    #[tokio::test]
    async fn a_blackholed_amf_cannot_hold_the_association_release_past_its_budget() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let blackhole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let amf_port = blackhole.local_addr().unwrap().port();
        let held = tokio::spawn(async move {
            let mut conns = Vec::new();
            while let Ok((c, _)) = blackhole.accept().await {
                conns.push(c);
            }
        });
        let upf = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = pumped_client(PfcpClient::new(
            local,
            upf.local_addr().unwrap(),
            [127, 0, 0, 1],
        ))
        .await;
        client.set_assoc_state_for_test(true, None, None).await;
        let _pool = InstalledPool::new(vec![client.clone()]);
        seed_pfcp_session("80901", 0x809);
        let mut b = crate::context::PolicyBinding::snapshot_default();
        b.supi = "imsi-001010000000809".to_string();
        b.psi = 5;
        b.sm_context_status_uri = Some(format!("http://127.0.0.1:{amf_port}/sm-status"));
        smf_self()
            .read()
            .unwrap()
            .policy_bindings
            .write()
            .unwrap()
            .insert("80901".to_string(), b);
        let released = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = upf.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            let resp = PfcpMessage::AssociationReleaseResponse(
                nextgcore_pfcp::message::AssociationReleaseResponse::new(
                    NodeId::new_ipv4([127, 0, 0, 4]),
                    nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                ),
            );
            upf.send_to(&build_message(&resp, h.sequence_number, None), from)
                .await
                .unwrap();
            h.msg_type
        });

        let started = std::time::Instant::now();
        let result = client
            .release_association_within(Some(Duration::from_millis(300)))
            .await;
        let took = started.elapsed();
        let request = released.await.unwrap();
        crate::cancel_gsm_timer_for_test("80901");
        forget_pfcp_session("80901");
        if let Ok(ctx) = smf_self().read() {
            ctx.policy_bindings.write().unwrap().remove("80901");
        }
        held.abort();

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(request, pfcp_message_type::ASSOCIATION_RELEASE_REQUEST);
        assert!(
            took < Duration::from_secs(1),
            "bounded by the budget: {took:?}"
        );
        assert!(!client.is_associated().await);
    }

    fn forget_pfcp_session(sm_context_ref: &str) {
        smf_self()
            .read()
            .unwrap()
            .pfcp_sessions
            .write()
            .unwrap()
            .remove(sm_context_ref);
    }

    /// #658: a hostname that does not resolve at startup is not fatal and is
    /// never dialled as 0.0.0.0; the request fails locally instead.
    #[tokio::test]
    async fn an_unresolved_upf_hostname_sends_nothing() {
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = client_for_peer(
            local,
            &UpfPeerSpec::Hostname("upf.invalid".into(), 8805),
            &crate::n4_identity::N4Identity {
                node_id: NodeId::new_ipv4([127, 0, 0, 1]),
                f_seid_ipv4: [127, 0, 0, 1],
                node_id_explicit: true,
            },
        )
        .await;
        assert!(!client.has_resolved_peer());
        match client.associate().await {
            Err(PfcpRequestError::Local(msg)) => assert!(msg.contains("upf.invalid"), "{msg}"),
            other => panic!("expected a local error, got {other:?}"),
        }
    }

    /// A rejected Association Setup must surface the real cause value.
    #[tokio::test]
    async fn test_association_setup_rejected_cause() {
        // #718: `associate` asks for session retention when this process holds
        // sessions, and tears them down when the peer does not confirm it, so it
        // reads (and may flush) process-global session state.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, upf) = make_client_with_peer().await;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = upf.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            let resp = AssociationSetupResponse::new(
                NodeId::new_ipv4([127, 0, 0, 4]),
                nextgcore_pfcp::types::PfcpCause::NoResourcesAvailable,
                778,
            );
            let msg = PfcpMessage::AssociationSetupResponse(resp);
            let pkt = build_message(&msg, h.sequence_number, None);
            upf.send_to(&pkt, from).await.unwrap();
        });

        match client.associate().await {
            Err(PfcpRequestError::Rejected { cause }) => {
                assert_eq!(
                    cause,
                    nextgcore_pfcp::types::PfcpCause::NoResourcesAvailable as u8
                )
            }
            other => panic!("expected rejection, got {other:?}"),
        }
        assert!(!client.is_associated().await);
    }

    /// T1 retransmission: the fake UPF stays silent for the first two
    /// transmissions and answers the third — the transaction must succeed
    /// and exactly 3 datagrams must have hit the wire.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_t1_retransmission_then_success() {
        let (client, upf) = make_client_with_peer().await;

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut count = 0u32;
            loop {
                let (len, from) = upf.recv_from(&mut buf).await.unwrap();
                count += 1;
                if count == 3 {
                    let h = parse_wire_header(&buf[..len]).unwrap();
                    let pkt = encode_wire_message(
                        pfcp_message_type::SESSION_DELETION_RESPONSE,
                        Some(7),
                        h.sequence_number,
                        &body_with_cause(1),
                    );
                    upf.send_to(&pkt, from).await.unwrap();
                    return count;
                }
            }
        });

        let (resp_type, body) = client
            .request(pfcp_message_type::SESSION_DELETION_REQUEST, Some(7), &[])
            .await
            .expect("3rd attempt must succeed");
        assert_eq!(resp_type, pfcp_message_type::SESSION_DELETION_RESPONSE);
        assert_eq!(parse_cause(&body), Some(1));
        assert_eq!(handle.await.unwrap(), 3, "exactly 3 transmissions");
    }

    /// Retransmission exhaustion: a silent peer must produce a Timeout error
    /// after 1 + N1 attempts, and the association must be marked down.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_retransmission_exhaustion_marks_peer_down() {
        let (client, upf) = make_client_with_peer().await;
        // Pretend we were associated
        {
            let mut a = client.assoc.write().await;
            a.associated = true;
            a.peer_recovery_time_stamp = Some(1);
        }

        // Count datagrams without ever answering
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let c2 = counter.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if upf.recv_from(&mut buf).await.is_err() {
                    break;
                }
                c2.fetch_add(1, Ordering::SeqCst);
            }
        });

        let start = std::time::Instant::now();
        let res = client
            .request(pfcp_message_type::SESSION_DELETION_REQUEST, Some(9), &[])
            .await;
        match res {
            Err(PfcpRequestError::Timeout { attempts }) => assert_eq!(attempts, 4),
            other => panic!("expected timeout, got {other:?}"),
        }
        // 4 attempts × T1 (3s) ≈ 12s — allow generous lower bound
        assert!(start.elapsed() >= Duration::from_secs(9));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            4,
            "1 initial + 3 retransmits"
        );
        assert!(
            !client.is_associated().await,
            "exhaustion must mark the association down"
        );
    }

    /// Heartbeat staleness: a Heartbeat Response with a changed Recovery
    /// Time Stamp must tear the association down (peer restarted).
    #[tokio::test]
    async fn test_heartbeat_detects_peer_restart() {
        // #723: reaches `teardown_association`, which is process-wide (AMF
        // callbacks, EPC PDN connections, the `pfcp_sessions` map). Documented
        // order: ambient state first, N4 second.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, upf) = make_client_with_peer().await;
        {
            let mut a = client.assoc.write().await;
            a.associated = true;
            a.peer_recovery_time_stamp = Some(100);
        }

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = upf.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            assert_eq!(h.msg_type, pfcp_message_type::HEARTBEAT_REQUEST);
            // Respond with a NEW recovery time stamp → restart
            let msg = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(200));
            let pkt = build_message(&msg, h.sequence_number, None);
            upf.send_to(&pkt, from).await.unwrap();
        });

        client.heartbeat_once().await.expect("heartbeat answered");
        assert!(
            !client.is_associated().await,
            "restart must tear down the association"
        );
        assert_eq!(
            client.association().await.peer_recovery_time_stamp,
            None,
            "#966 review m3: the stamp goes with the association"
        );
    }

    /// Inbound Heartbeat Request must be answered with our recovery
    /// timestamp via the library codec.
    #[tokio::test]
    async fn test_inbound_heartbeat_request_answered() {
        let (client, upf) = make_client_with_peer().await;
        let local_addr = client.socket.local_addr().unwrap();

        let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(555));
        let pkt = build_message(&msg, 33, None);
        upf.send_to(&pkt, local_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), upf.recv_from(&mut buf))
            .await
            .expect("heartbeat response expected")
            .unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(h.msg_type, pfcp_message_type::HEARTBEAT_RESPONSE);
        assert_eq!(h.sequence_number, 33, "response echoes the request seq");
        let rts = find_ie(&buf[h.body_offset..len], 96).expect("recovery TS mandatory");
        let rts = u32::from_be_bytes([rts[0], rts[1], rts[2], rts[3]]);
        assert_eq!(rts, client.recovery_time_stamp);
        assert!(rts > 0, "recovery timestamp must be real");
    }

    /// Inbound Association Release Request must be acknowledged and drop
    /// the association.
    #[tokio::test]
    async fn test_inbound_association_release() {
        // #723: reaches `teardown_association`, which is process-wide (AMF
        // callbacks, EPC PDN connections, the `pfcp_sessions` map). Documented
        // order: ambient state first, N4 second.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, upf) = make_client_with_peer().await;
        client.assoc.write().await.associated = true;
        let local_addr = client.socket.local_addr().unwrap();

        let msg = PfcpMessage::AssociationReleaseRequest(AssociationReleaseRequest::new(
            NodeId::new_ipv4([127, 0, 0, 4]),
        ));
        let pkt = build_message(&msg, 44, None);
        upf.send_to(&pkt, local_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), upf.recv_from(&mut buf))
            .await
            .expect("release response expected")
            .unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(h.msg_type, pfcp_message_type::ASSOCIATION_RELEASE_RESPONSE);
        assert_eq!(
            parse_cause(&buf[h.body_offset..len]),
            Some(pfcp_cause::REQUEST_ACCEPTED)
        );
        assert!(!client.is_associated().await);
    }

    /// An unsupported PFCP version must be answered with Version Not
    /// Supported Response (type 11).
    #[tokio::test]
    async fn test_version_not_supported() {
        let (client, upf) = make_client_with_peer().await;
        let local_addr = client.socket.local_addr().unwrap();

        // version=2 header
        let mut pkt = encode_wire_message(pfcp_message_type::HEARTBEAT_REQUEST, None, 5, &[]);
        pkt[0] = 2 << 5; // version 2
        upf.send_to(&pkt, local_addr).await.unwrap();

        let mut buf = vec![0u8; 256];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), upf.recv_from(&mut buf))
            .await
            .expect("version-not-supported expected")
            .unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(
            h.msg_type,
            pfcp_message_type::VERSION_NOT_SUPPORTED_RESPONSE
        );
    }

    // ── Issue #20: load/compute-aware UPF selection ─────────────────────────

    #[test]
    fn test_select_least_loaded_prefers_associated_minimum() {
        // Least-loaded associated peer wins; the unassociated peer with the
        // lowest metric is never eligible.
        let candidates = [
            (true, Some(80)),
            (false, Some(1)),
            (true, Some(20)),
            (true, None),
        ];
        assert_eq!(select_least_loaded(&candidates), Some(2));

        // Unknown load ranks worst among associated peers.
        assert_eq!(
            select_least_loaded(&[(true, None), (true, Some(100))]),
            Some(1)
        );

        // Ties resolve to the lowest index (deterministic).
        assert_eq!(
            select_least_loaded(&[(true, Some(10)), (true, Some(10))]),
            Some(0)
        );

        // No associated peer -> no selection.
        assert_eq!(
            select_least_loaded(&[(false, Some(3)), (false, None)]),
            None
        );
        assert_eq!(select_least_loaded(&[]), None);
    }

    /// Acceptance (issue #20): with the feature off — or a pool of one —
    /// session establishment selects the sole/global client, i.e. the
    /// pre-pool single-client path.
    ///
    /// Takes its client from the shared stand-in (issue #289) rather than
    /// installing one of its own. `PFCP_CLIENT` and `PFCP_POOL` are `OnceLock`s,
    /// so two installers race on test order and the loser leaves the winner's
    /// silent peer installed for every other test in the process — which is
    /// exactly how a create against the stand-in would have started timing out
    /// instead of establishing. There is one installer in the test build.
    #[tokio::test]
    async fn test_select_upf_defaults_to_global_client_and_bindings_resolve() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // Association state is irrelevant to a single-peer pool: `select_upf`
        // returns the default client without consulting it (the load-aware path
        // needs the feature AND more than one peer).
        let upf = unassociated_upf().await;
        let client = upf.client.clone();

        let selected = select_upf().await.expect("pool installed");
        assert_eq!(
            selected.peer(),
            client.peer(),
            "sole/default client must be selected"
        );

        // client_for_session: unknown SEID falls back to the default client.
        let resolved = client_for_session(0xDEAD).expect("default client");
        assert_eq!(resolved.peer(), client.peer());

        // A recorded binding resolves to the bound peer and survives until
        // the session is forgotten.
        record_session_peer(0x77, client.peer());
        assert_eq!(client_for_session(0x77).unwrap().peer(), client.peer());
        forget_session_peer(0x77);
        assert_eq!(client_for_session(0x77).unwrap().peer(), client.peer());
    }

    /// Acceptance (issue #20): a PFCP Heartbeat Request carrying Load
    /// Control Information is parsed and updates the originating peer's
    /// stored metric on `AssociationState`; stale sequence numbers are
    /// discarded.
    #[tokio::test]
    async fn test_heartbeat_lci_updates_association_state() {
        let (client, upf) = make_client_with_peer().await;
        let local_addr = client.socket.local_addr().unwrap();

        let hb = |seq: u32, lci_seq: u32, metric: u8| {
            let mut req = HeartbeatRequest::new(1111);
            req.load_control_information = Some(
                nextgcore_pfcp::types::LoadControlInformation::new(lci_seq, metric),
            );
            build_message(&PfcpMessage::HeartbeatRequest(req), seq, None)
        };
        // Each send is followed by the engine's Heartbeat Response; waiting
        // for it guarantees the request (and its LCI) was processed.
        async fn exchange(upf: &UdpSocket, to: SocketAddr, pkt: &[u8]) {
            upf.send_to(pkt, to).await.unwrap();
            let mut buf = vec![0u8; 1024];
            tokio::time::timeout(Duration::from_secs(2), upf.recv_from(&mut buf))
                .await
                .expect("heartbeat response expected")
                .unwrap();
        }

        // First report: stored.
        exchange(&upf, local_addr, &hb(1, 10, 30)).await;
        let assoc = client.association().await;
        assert_eq!(assoc.peer_load, Some(30));
        assert_eq!(assoc.peer_load_seq, Some(10));

        // Stale sequence number: ignored.
        exchange(&upf, local_addr, &hb(2, 5, 90)).await;
        assert_eq!(client.association().await.peer_load, Some(30));

        // Newer sequence number: applied.
        exchange(&upf, local_addr, &hb(3, 11, 55)).await;
        let assoc = client.association().await;
        assert_eq!(assoc.peer_load, Some(55));
        assert_eq!(assoc.peer_load_seq, Some(11));
    }

    /// Acceptance (issue #20): the full selection path over real clients —
    /// the least-loaded ASSOCIATED peer wins and an un-associated peer is
    /// never selected. Runs in the default build (select_upf_from is not
    /// feature-gated); the feature only gates whether establishment calls it.
    #[tokio::test]
    async fn test_select_upf_from_picks_least_loaded_associated() {
        let (a, _peer_a) = make_client_with_peer().await;
        let (b, _peer_b) = make_client_with_peer().await;
        let (c, _peer_c) = make_client_with_peer().await;
        a.set_assoc_state_for_test(true, Some(70), Some(1)).await;
        // Least-loaded overall, but un-associated: never eligible.
        b.set_assoc_state_for_test(false, Some(5), Some(1)).await;
        c.set_assoc_state_for_test(true, Some(20), Some(1)).await;

        let pool = vec![a.clone(), b, c.clone()];
        let picked = select_upf_from(&pool)
            .await
            .expect("associated peers exist");
        assert_eq!(picked.peer(), c.peer());

        // All un-associated -> no selection.
        a.set_assoc_state_for_test(false, Some(70), Some(1)).await;
        c.set_assoc_state_for_test(false, Some(20), Some(1)).await;
        assert!(select_upf_from(&pool).await.is_none());
    }

    /// #380: the sync-readable association gauge tracks the REAL wire path.
    ///
    /// This is what the EPC bring-up readiness gate and the PGW-C container healthcheck
    /// poll, through `smf_n4_associations` — so if the gauge did not follow
    /// `associate()`, the gate would be asserting on a number that never moves and a
    /// PGW-C with no Sxb association would pass it. Driven through the stand-in UPF's
    /// Association Setup rather than the test-only setter, because the setter proving
    /// itself proves nothing.
    #[tokio::test]
    async fn the_sync_association_gauge_follows_the_wire_association() {
        // #723: `teardown_association` below is process-wide, so the ambient lock is
        // taken first; `install_stand_in_upf` then takes `N4_TEST_LOCK` for the life
        // of `upf`. Taking N4 here as well would deadlock.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = stand_in::install_stand_in_upf().await;
        // Before Association Setup: honestly zero, which is what makes the gate fail on
        // a PGW-C whose Sxb never came up rather than pass it.
        assert!(
            !upf.client.is_associated_sync(),
            "a fresh client must not report an association"
        );

        upf.client
            .associate()
            .await
            .expect("the stand-in UPF accepts the association");
        assert!(
            upf.client.is_associated_sync(),
            "the gauge must follow a real Association Setup Response"
        );
        // The async authority and its projection must agree.
        assert_eq!(
            upf.client.is_associated().await,
            upf.client.is_associated_sync()
        );

        upf.client.teardown_association("test").await;
        assert!(
            !upf.client.is_associated_sync(),
            "the gauge must clear when the association is torn down"
        );
    }

    /// Issue #20 review regression: association teardown clears the stored
    /// load state, so a restarted UPF (whose LCI sequence counter restarts
    /// from 1) is not stuck behind the old high-watermark.
    #[tokio::test]
    async fn test_teardown_clears_load_state() {
        // #723: reaches `teardown_association`, which is process-wide (AMF
        // callbacks, EPC PDN connections, the `pfcp_sessions` map). Documented
        // order: ambient state first, N4 second.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, _upf) = make_client_with_peer().await;
        client
            .set_assoc_state_for_test(true, Some(40), Some(5000))
            .await;

        client.teardown_association("test: peer restarted").await;

        let assoc = client.association().await;
        assert!(!assoc.associated);
        assert_eq!(assoc.peer_load, None);
        assert_eq!(
            assoc.peer_load_seq, None,
            "a fresh low-seq post-restart report must be acceptable again"
        );
    }

    // ── TS 23.007 §19A: a stored Heartbeat stamp makes a peer restart detectable ──
    //
    // These two drive the process-global session map, as `test_teardown_clears_
    // load_state` above already does via `teardown_association`. Safe because no
    // smfd test asserts on the *contents* of the global `pfcp_sessions` map, and
    // each of these asserts only about its own uniquely-named key rather than
    // about the map being empty.

    /// #1033: a received Recovery Time Stamp is NTP-era seconds (TS 29.244 §8.2.65) and
    /// is compared as sent. The same NTP stamp again is not a restart on either path, a
    /// newer one in a Heartbeat Request is. A Unix-seconds stamp (a 0.1.x UPF) is no
    /// longer re-read as NTP: it is stored as sent, and the NTP rendering of the same
    /// start time is a different stamp, so a Heartbeat Response carrying it is a restart.
    #[tokio::test]
    async fn stamps_are_compared_as_sent_in_ntp_seconds() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, _upf) = make_client_with_peer().await;
        let _pool = InstalledPool::new(vec![client.clone()]);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let started = nextgcore_pfcp::recovery_time::from_unix_secs(now_unix - 86_400);
        client.set_assoc_state_for_test(true, None, None).await;
        assert!(client
            .detect_peer_restart(started, StampSource::Request)
            .await
            .is_none());
        assert_eq!(
            client.association().await.peer_recovery_time_stamp,
            Some(started),
            "the first stamp is the baseline, as sent"
        );
        for source in [StampSource::Request, StampSource::Response] {
            assert!(
                client.detect_peer_restart(started, source).await.is_none(),
                "the same NTP stamp is not a restart ({source:?})"
            );
        }
        let restarted = nextgcore_pfcp::recovery_time::from_unix_secs(now_unix - 60);
        let fanout = client
            .detect_peer_restart(restarted, StampSource::Request)
            .await;
        assert!(fanout.is_some(), "a newer NTP stamp is a restart");
        if let Some(f) = fanout {
            let _ = f.await;
        }
        assert_eq!(client.association().await.peer_recovery_time_stamp, None);

        // A legacy Unix-seconds stamp is not normalised.
        let legacy = (now_unix - 86_400) as u32;
        client.set_assoc_state_for_test(true, None, None).await;
        assert!(client
            .detect_peer_restart(legacy, StampSource::Request)
            .await
            .is_none());
        assert_eq!(
            client.association().await.peer_recovery_time_stamp,
            Some(legacy),
            "stored as sent, not in an NTP reading"
        );
        let fanout = client
            .detect_peer_restart(
                nextgcore_pfcp::recovery_time::from_unix_secs(u64::from(legacy)),
                StampSource::Response,
            )
            .await;
        assert!(
            fanout.is_some(),
            "the NTP rendering of the legacy start time is a different stamp"
        );
        if let Some(f) = fanout {
            let _ = f.await;
        }
    }

    /// #1004 review: an RTC-less UPF booted at 1970; its stamp was read in the Unix
    /// branch and stored as ~2040. After a restart with a synced clock its 2026 stamp
    /// is "older" than that, and a Heartbeat Request carrying it was discarded as
    /// reordered -- the restart masked. A stored start time in the future is not a
    /// reference: a differing stamp is a restart.
    #[tokio::test]
    async fn a_future_stored_stamp_does_not_mask_a_restart() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, _upf) = make_client_with_peer().await;
        let _pool = InstalledPool::new(vec![client.clone()]);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let bogus = nextgcore_pfcp::recovery_time::from_unix_secs(now_unix + 86_400 * 365 * 14);
        client.seed_peer_recovery_time_stamp(bogus).await;
        client.set_assoc_state_for_test(true, None, None).await;

        let synced = nextgcore_pfcp::recovery_time::from_unix_secs(now_unix - 60);
        let fanout = client
            .detect_peer_restart(synced, StampSource::Request)
            .await;
        assert!(fanout.is_some(), "the restart is not masked");
        if let Some(f) = fanout {
            let _ = f.await;
        }
        assert_eq!(
            client.association().await.peer_recovery_time_stamp,
            None,
            "cleared with the association (#966 review m3)"
        );
    }

    /// A genuinely reordered (older) stamp is still discarded when the stored one is
    /// a plausible, past start time.
    #[tokio::test]
    async fn a_reordered_older_stamp_is_still_discarded() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, _upf) = make_client_with_peer().await;
        let _pool = InstalledPool::new(vec![client.clone()]);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current = nextgcore_pfcp::recovery_time::from_unix_secs(now_unix - 60);
        client.seed_peer_recovery_time_stamp(current).await;
        client.set_assoc_state_for_test(true, None, None).await;
        let previous = nextgcore_pfcp::recovery_time::from_unix_secs(now_unix - 86_400);
        assert!(client
            .detect_peer_restart(previous, StampSource::Request)
            .await
            .is_none());
        assert!(client.is_associated().await);
    }

    /// #995: this SMF's own stamp is NTP-era seconds (TS 29.244 §8.2.65).
    #[tokio::test]
    async fn the_smf_recovery_time_stamp_is_ntp_seconds() {
        let (client, _upf) = make_client_with_peer().await;
        let now = nextgcore_pfcp::recovery_time::now();
        assert!(
            now.wrapping_sub(client.recovery_time_stamp) < 60,
            "{}",
            client.recovery_time_stamp
        );
    }

    /// A stamp stored from an earlier Heartbeat is compared with the next one (TS
    /// 23.007 §19A): a different one is a restart, and the sessions are flushed.
    #[tokio::test]
    async fn a_changed_heartbeat_stamp_flushes_the_sessions() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // Serialised: this test can reach a teardown, which flushes the
        // process-global session map (see N4_TEST_LOCK).
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, _upf) = make_client_with_peer().await;
        // #720: the teardown is this UPF's; the client is the pool, as in production.
        let _pool = InstalledPool::new(vec![client.clone()]);
        client.seed_peer_recovery_time_stamp(100).await;
        client.set_assoc_state_for_test(true, None, None).await;
        if let Ok(ctx) = smf_self().read() {
            ctx.pfcp_sessions
                .write()
                .unwrap()
                .insert("seeded-restart-ref".to_string(), 0xabcd);
        }

        // The UPF comes back with a different incarnation: every session it held
        // is gone (TS 29.244 §5.22, TS 23.527 §4.2).
        client.check_peer_restart(200).await;

        assert!(
            !client.is_associated().await,
            "a changed stamp must tear the association down"
        );
        let still_there = smf_self()
            .read()
            .unwrap()
            .pfcp_sessions
            .read()
            .unwrap()
            .contains_key("seeded-restart-ref");
        assert!(
            !still_there,
            "the restored session must be flushed, not left believed-in"
        );
        assert_eq!(
            client.association().await.peer_recovery_time_stamp,
            None,
            "#966 review m3: the stamp goes with the association; the next one's first \
             Heartbeat is its baseline"
        );
    }

    /// The other half of the interlock: an unchanged stamp means the UPF did NOT
    /// restart, so the sessions are genuinely still valid and must be left alone.
    /// Without this, "flush on restart" could be satisfied by a version that
    /// flushes unconditionally.
    #[tokio::test]
    async fn an_unchanged_heartbeat_stamp_leaves_the_sessions_alone() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _seeded = crate::context::SeededState::track();
        // Serialised: this test can reach a teardown, which flushes the
        // process-global session map (see N4_TEST_LOCK).
        let _map_guard = N4_TEST_LOCK.lock().await;
        let (client, _upf) = make_client_with_peer().await;
        client.seed_peer_recovery_time_stamp(300).await;
        client.set_assoc_state_for_test(true, None, None).await;
        if let Ok(ctx) = smf_self().read() {
            ctx.pfcp_sessions
                .write()
                .unwrap()
                .insert("unchanged-stamp-ref".to_string(), 0x1234);
        }

        client.check_peer_restart(300).await;

        assert!(
            client.is_associated().await,
            "the same stamp is not a restart"
        );
        let seid = smf_self()
            .read()
            .unwrap()
            .pfcp_sessions
            .read()
            .unwrap()
            .get("unchanged-stamp-ref")
            .copied();
        assert_eq!(
            seid,
            Some(0x1234),
            "a session on a UPF that did not restart must survive"
        );
    }

    // ── #193: the detection is wired to a SIGNAL, not only to a local flush ──

    /// The end-to-end shape of #193's criterion 1, driven from the same entry
    /// point production uses: a changed Recovery Time Stamp on a heartbeat
    /// reaches `check_peer_restart`, which tears the association
    /// down, and the teardown must now tell the AMF before it empties the map.
    ///
    /// This is the test that guards the WIRING. `restoration`'s own tests call
    /// `notify_sessions_unrecoverable` directly, so they would all still pass with
    /// the call removed from `teardown_association` — which is exactly the defect
    /// #193 describes, one layer up.
    #[tokio::test]
    async fn a_peer_restart_notifies_the_amf_before_flushing_the_session_map() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;

        // Plaintext loopback AMF: declare the dev profile rather than inherit it.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bodies: Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_posts = Arc::clone(&posts);
        let sink_bodies = Arc::clone(&bodies);
        let (amf, amf_addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |req: nextgcore_sbi::message::SbiRequest| {
                let posts = Arc::clone(&sink_posts);
                let bodies = Arc::clone(&sink_bodies);
                async move {
                    posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if let Some(c) = req.http.content.as_deref() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(c) {
                            if let Ok(mut b) = bodies.lock() {
                                b.push(v);
                            }
                        }
                    }
                    nextgcore_sbi::message::SbiResponse::with_status(204)
                }
            },
        )
        .await;
        let status_uri = format!("http://127.0.0.1:{}/callbacks/sm-status", amf_addr.port());

        let (client, _upf) = make_client_with_peer().await;
        // #720: the teardown is this UPF's; the client is the pool, as in production.
        let _pool = InstalledPool::new(vec![client.clone()]);
        client.seed_peer_recovery_time_stamp(4242).await;
        client.set_assoc_state_for_test(true, None, None).await;
        {
            let global = smf_self();
            let ctx = global.read().expect("smf context");
            {
                let mut sessions = ctx.pfcp_sessions.write().expect("sessions");
                sessions.insert("restart-signal-ref".to_string(), 0x0193_1000);
            }
            let mut b = crate::context::PolicyBinding::snapshot_default();
            b.supi = "imsi-001010000000193".to_string();
            b.psi = 9;
            b.sm_context_status_uri = Some(status_uri.clone());
            ctx.policy_bindings
                .write()
                .expect("bindings")
                .insert("restart-signal-ref".to_string(), b);
        }

        // The UPF came back as a new incarnation.
        client.check_peer_restart(9999).await;

        let flushed = {
            let global = smf_self();
            let ctx = global.read().expect("smf context");
            let sessions = ctx.pfcp_sessions.read().expect("sessions");
            let present = sessions.contains_key("restart-signal-ref");
            !present
        };
        {
            let global = smf_self();
            let ctx = global.read().expect("smf context");
            ctx.policy_bindings
                .write()
                .expect("bindings")
                .remove("restart-signal-ref");
        }
        let seen_posts = posts.load(std::sync::atomic::Ordering::SeqCst);
        let seen_bodies = bodies.lock().expect("bodies").clone();
        amf.stop().await.expect("stop amf");

        assert!(flushed, "the stale session is still flushed locally");
        let t3592 = crate::cancel_gsm_timer_for_test("restart-signal-ref");
        assert_eq!(
            seen_posts, 1,
            "the AMF must be told the session is gone -- this is the notification the flush \
             used to replace with a log line"
        );
        // #667: told by releasing the session through the UE for reactivation, which
        // the AMF relays as the N1 release command and the N2 resource release.
        assert_eq!(
            seen_bodies[0]["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"],
            "PDU_RES_REL_CMD",
            "body was {:?}",
            seen_bodies[0]
        );
        assert!(t3592, "T3592 guards the release command");
    }

    /// The interlock's other side, at the wiring level: a UPF that did NOT
    /// restart must produce NO notification. Without this, "notify on teardown"
    /// could be satisfied by a version that notifies unconditionally, which would
    /// release every live session on every heartbeat.
    #[tokio::test]
    async fn an_unchanged_stamp_notifies_nobody() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _map_guard = N4_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink_posts = Arc::clone(&posts);
        let (amf, amf_addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |_req: nextgcore_sbi::message::SbiRequest| {
                let posts = Arc::clone(&sink_posts);
                async move {
                    posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    nextgcore_sbi::message::SbiResponse::with_status(204)
                }
            },
        )
        .await;
        let status_uri = format!("http://127.0.0.1:{}/callbacks/sm-status", amf_addr.port());

        let (client, _upf) = make_client_with_peer().await;
        client.seed_peer_recovery_time_stamp(7777).await;
        client.set_assoc_state_for_test(true, None, None).await;
        {
            let global = smf_self();
            let ctx = global.read().expect("smf context");
            {
                let mut sessions = ctx.pfcp_sessions.write().expect("sessions");
                sessions.insert("no-restart-signal-ref".to_string(), 0x0193_1001);
            }
            let mut b = crate::context::PolicyBinding::snapshot_default();
            b.sm_context_status_uri = Some(status_uri.clone());
            ctx.policy_bindings
                .write()
                .expect("bindings")
                .insert("no-restart-signal-ref".to_string(), b);
        }

        client.check_peer_restart(7777).await;

        {
            let global = smf_self();
            let ctx = global.read().expect("smf context");
            {
                let mut sessions = ctx.pfcp_sessions.write().expect("sessions");
                sessions.remove("no-restart-signal-ref");
            }
            ctx.policy_bindings
                .write()
                .expect("bindings")
                .remove("no-restart-signal-ref");
        }
        let seen = posts.load(std::sync::atomic::Ordering::SeqCst);
        amf.stop().await.expect("stop amf");

        assert_eq!(
            seen, 0,
            "an unchanged stamp is not a restart, so releasing the session would be a fabricated \
             outage"
        );
    }
}
