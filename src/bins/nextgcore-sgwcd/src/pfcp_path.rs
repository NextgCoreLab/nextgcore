//! SGWC PFCP Path Management
//!
//! Port of src/sgwc/pfcp-path.c - PFCP path management for SXA interface
//!
//! #54: this module used to be a facade. `pfcp_open` opened no socket, and
//! `send_pfcp_message` logged a line and returned `Ok(())` — so every SGW-C→SGW-U
//! message was dropped on the floor while its caller was told it had been sent, and no
//! PFCP response could ever arrive. That is why the S11 procedures answered the MME
//! before (or regardless of) the Sxa outcome: there was nothing to wait for.
//!
//! It is now the CP half of the transport #59 gave the SGW-U: one bound UDP socket,
//! transactions matched on sequence number with T1/N1 retransmission, an association
//! initiated toward the SGW-U, and inbound Session Report Requests dispatched into
//! `sxa_handler`. The synchronous S11 dispatch enqueues and the async node performs the
//! I/O, exactly as `gtp_path` does on the SGW-U side and for the same reason: the GTP-C
//! server runs on OS threads with a blocking socket and cannot await.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use nextgcore_pfcp::header::{PfcpHeader, PfcpMessageType};
use nextgcore_pfcp::message::{
    AssociationSetupRequest, AssociationSetupResponse, HeartbeatRequest, HeartbeatResponse,
    NodeReportRequest, NodeReportResponse, PfcpMessage as PfcpLibMessage, SessionReportRequest,
    SessionReportResponse,
};
use nextgcore_pfcp::types::{NodeId, PfcpCause};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

use crate::context::{sgwc_self, SgwcSess};
use crate::sxa_build::{self, PfcpMessage};

/// The PFCP UDP port (TS 29.244 §4.2.2).
pub const PFCP_PORT: u16 = 8805;

/// Sequence numbers are 24-bit (TS 29.244 §7.2.2.1).
const SEQ_MASK: u32 = 0x00FF_FFFF;

/// T1 and N1 for a PFCP transaction. TS 29.244 §7.2.1 fixes neither; three seconds and
/// two retransmissions is the same budget sgwud uses, so the two ends of one interface
/// do not disagree about how long a message may take.
const T1: std::time::Duration = std::time::Duration::from_secs(3);
const N1: u32 = 2;

/// How often an SGW-C with no association to its SGW-U tries the Association Setup
/// again (#1001), each attempt with T1/N1 (TS 29.244 §6.2.6.1). The same 10 s smfd
/// uses (`reassociate_holdoff`).
pub const ASSOCIATION_RETRY: std::time::Duration = std::time::Duration::from_secs(10);

/// How often the SGW-C sends an associated SGW-U a Heartbeat Request (TS 29.244
/// §6.2.2, §7.4.2), so a peer that went away or restarted is noticed without a
/// session request failing first. The same 10 s smfd uses.
pub const HEARTBEAT_PERIOD: std::time::Duration = std::time::Duration::from_secs(10);

// ============================================================================
// PFCP Message Types
// ============================================================================

pub mod pfcp_msg_type {
    pub const HEARTBEAT_REQUEST: u8 = 1;
    pub const HEARTBEAT_RESPONSE: u8 = 2;
    pub const ASSOCIATION_SETUP_REQUEST: u8 = 5;
    pub const ASSOCIATION_SETUP_RESPONSE: u8 = 6;
    pub const ASSOCIATION_RELEASE_REQUEST: u8 = 9;
    pub const ASSOCIATION_RELEASE_RESPONSE: u8 = 10;
    /// TS 29.244 §7.4.5: user plane path failure and recovery reports (#994).
    pub const NODE_REPORT_REQUEST: u8 = 12;
    pub const NODE_REPORT_RESPONSE: u8 = 13;
    /// TS 29.244 §7.2.2.1: answered when the version octet is not 1.
    pub const VERSION_NOT_SUPPORTED_RESPONSE: u8 = 11;
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_ESTABLISHMENT_RESPONSE: u8 = 51;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_MODIFICATION_RESPONSE: u8 = 53;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_DELETION_RESPONSE: u8 = 55;
    pub const SESSION_REPORT_REQUEST: u8 = 56;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

/// Response message types, which complete a pending transaction rather than being
/// dispatched as requests.
fn is_response_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        2 | 4 | 6 | 8 | 10 | 11 | 13 | 15 | 51 | 53 | 55 | 57
    )
}

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
// What the S11 answer needs when the PFCP response finally arrives (#54)
// ============================================================================

/// The S11 procedure a PFCP transaction is gating.
///
/// TS 23.401 §5.3.2.1 has the Serving GW answer the MME **after** the user plane is
/// provisioned, and TS 29.274 §7.2.2 makes `Request accepted` mean the request was
/// actually fulfilled. So the S11 response cannot be built when the request arrives; the
/// pieces it needs — which peer, which sequence number, which TEID — travel with the
/// PFCP transaction and are used when its response lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S11Continuation {
    /// Nothing to answer: the S11 response was already sent, or this modification is
    /// not gating one (see the spec's ceiling on Modify Bearer).
    None,
    /// Answer the MME's Create Session Request.
    CreateSession {
        peer: SocketAddr,
        seq: u32,
        teid: u32,
    },
    /// Answer the MME's Delete Session Request, and remove the local session only when
    /// the SGW-U confirms.
    DeleteSession {
        peer: SocketAddr,
        seq: u32,
        teid: u32,
        sess_id: u64,
    },
    /// Answer the MME's Create Indirect Data Forwarding Tunnel Request once the SGW-U
    /// has installed the forwarding rules (#48).
    ///
    /// Gated for the same reason the Create Session answer is: TS 29.274 §7.2.2 makes
    /// `Request accepted` mean the request was FULFILLED, and this response carries
    /// F-TEIDs the source eNB is about to forward user data to. Answering before the
    /// SGW-U has the rules would advertise a datapath that does not exist yet -- which
    /// is the defect #48 describes, one step earlier.
    IndirectForwarding {
        peer: SocketAddr,
        seq: u32,
        teid: u32,
        sgwc_ue_id: u64,
    },
    /// One session's share of a Modify Bearer Request (#838): the MME is answered
    /// once every session's PFCP Session Modification has (TS 23.401 §5.5.1.1.2
    /// steps 3-4: the SGW answers after switching the downlink path). `join`
    /// names the pending answer in `sxa_response`.
    ModifyBearer { join: u64, sess_id: u64 },
    /// The PDN connection a Delete Bearer Response released (#710): no MME waits,
    /// but the local session goes only once the SGW-U has deleted its own, as for
    /// a Delete Session.
    ReleasePdn { sess_id: u64 },
    /// A PGW Create Bearer Request's dedicated bearers, installed at the SGW-U before
    /// the request goes on to the MME (#607, TS 23.401 §5.4.1 step 2). `join` names
    /// the request in `dedicated_bearer`.
    CreateBearer { join: u64 },
    /// The downlink switch of the bearers the MME accepted, before the PGW is answered
    /// (#607, TS 23.401 §5.4.1 step 8).
    CreateBearerAnswer { join: u64 },
    /// A session established again on a restarted SGW-U (#1010 review): no MME
    /// waits, but a refused or unanswered restoration is counted and logged
    /// ([`RESTORATIONS_FAILED`]).
    Restoration { sess_id: u64 },
}

/// Sessions whose restoration on a restarted SGW-U failed: not sent, refused, or
/// unanswered (#1010 review). Each is also logged with its CP F-SEID.
pub static RESTORATIONS_FAILED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record one failed restoration of `sess_id`.
pub fn restoration_failed(sess_id: u64, why: &str) {
    RESTORATIONS_FAILED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let seid = crate::context::sgwc_self()
        .sess_find_by_id(sess_id)
        .map(|s| s.sgwc_sxa_seid)
        .unwrap_or(0);
    log::error!(
        "PFCP session {sess_id} (CP F-SEID 0x{seid:x}) NOT restored on the restarted SGW-U: \
         {why}; its user plane is gone until the session is set up again"
    );
}

/// An outbound PFCP request queued by a synchronous caller.
struct QueuedRequest {
    msg_type: u8,
    seid: u64,
    body: Vec<u8>,
    to: SocketAddr,
    sess_id: u64,
    continuation: S11Continuation,
}

/// The running node's outbound queue and the node itself.
///
/// Settable rather than install-once, and guarded by one test lock declared beside them —
/// the shape #217 arrived at for sgwud after an install-once `OnceLock` made a node-level
/// message impossible to assert against. A tokio socket belongs to the runtime that
/// created it, so under `#[tokio::test]` a permanently installed node is a dead socket for
/// every test after the first.
static OUTBOUND: std::sync::RwLock<Option<mpsc::UnboundedSender<QueuedRequest>>> =
    std::sync::RwLock::new(None);

/// The running Sxa node, so the synchronous S11 dispatch can resolve a peer.
static SXA_NODE: std::sync::RwLock<Option<Arc<SxaNode>>> = std::sync::RwLock::new(None);

// The lock that serialises every test touching this process's ambient SGW-C state
// lives beside the largest global it guards: `context::PROCESS_STATE_TEST_LOCK`. It
// used to be declared here as `SXA_TEST_LOCK`, covering only [`SXA_NODE`] /
// [`OUTBOUND`] and the S11 server; #368 widened its remit to the scalar address
// slots on the global context, which were unguarded and flaked.

/// The process-wide Sxa node, once [`pfcp_open`] has run.
pub fn sxa_node() -> Option<Arc<SxaNode>> {
    SXA_NODE.read().ok()?.clone()
}

fn outbound() -> Option<mpsc::UnboundedSender<QueuedRequest>> {
    OUTBOUND.read().ok()?.clone()
}

/// Uninstall the node and its queue. Test-only: the release half of a per-test install.
#[cfg(test)]
pub(crate) fn clear_sxa_globals_for_test() {
    if let Ok(mut slot) = SXA_NODE.write() {
        *slot = None;
    }
    if let Ok(mut slot) = OUTBOUND.write() {
        *slot = None;
    }
    // #387: the configured Sxa peer and Node ID are the same kind of single-slot process
    // state, and are read by every Sxa send. Reset alongside the node so a test starts
    // from "nothing configured" whichever side of the guard it looks at.
    let ctx = sgwc_self();
    ctx.set_sgwu_peers(Vec::new());
    ctx.set_pfcp_node_ip(None);
}

/// Holds [`crate::context::PROCESS_STATE_TEST_LOCK`] and leaves the ambient globals
/// empty on both sides of a test.
///
/// Take it once per test and pass `&ProcessStateGuard` to the helpers that touch
/// ambient state; see the lock's own documentation for why they require the reference
/// rather than acquiring it themselves.
#[cfg(test)]
pub(crate) struct ProcessStateGuard(#[allow(dead_code)] tokio::sync::MutexGuard<'static, ()>);

#[cfg(test)]
impl Drop for ProcessStateGuard {
    fn drop(&mut self) {
        clear_sxa_globals_for_test();
        // The S11 server is installed by the same tests, for the same reason (the gated
        // answer goes through the process-global one). Cleared here rather than under a
        // second lock: one agreement about both, so there is no lock order to get wrong.
        crate::gtp_path::clear_s11_server_for_test();
    }
}

#[cfg(test)]
pub(crate) async fn process_state_test_guard() -> ProcessStateGuard {
    let guard = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    clear_sxa_globals_for_test();
    ProcessStateGuard(guard)
}

/// The sync `#[test]` counterpart. `blocking_lock` is sound here precisely because a
/// sync test has no runtime to block.
#[cfg(test)]
pub(crate) fn process_state_test_guard_blocking() -> ProcessStateGuard {
    let guard = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
    clear_sxa_globals_for_test();
    ProcessStateGuard(guard)
}

// ============================================================================
// The Sxa node (CP side)
// ============================================================================

/// One SGW-U peer as seen from the SGW-C.
#[derive(Debug, Clone)]
pub struct SxaPeer {
    pub addr: SocketAddr,
    pub state: PfcpNodeState,
    /// The peer's Recovery Time Stamp; a change means it restarted (TS 23.007 §19A).
    pub recovery_time_stamp: Option<u32>,
    pub up_function_features: UpFunctionFeatures,
}

/// Failure modes of an Sxa transaction.
#[derive(Debug)]
pub enum PfcpRequestError {
    /// No response after N1 retransmissions.
    Timeout { attempts: u32 },
    /// Local I/O or state error.
    Local(String),
}

impl std::fmt::Display for PfcpRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { attempts } => {
                write!(f, "no PFCP response after {attempts} attempt(s)")
            }
            Self::Local(e) => write!(f, "{e}"),
        }
    }
}

/// The SGW-C's PFCP endpoint on Sxa.
pub struct SxaNode {
    socket: Arc<UdpSocket>,
    /// The address this node puts in its own Node ID IE.
    local_ip: Ipv4Addr,
    /// Our Recovery Time Stamp, reported in every Association Setup and Heartbeat.
    pub recovery_time_stamp: u32,
    seq: AtomicU32,
    pending: Mutex<HashMap<u32, oneshot::Sender<(u8, Vec<u8>)>>>,
    peers: RwLock<HashMap<SocketAddr, SxaPeer>>,
    /// Associated peers, readable synchronously (the S11 dispatch cannot await).
    associated_peers: AtomicUsize,
    /// T1 of every transaction, in milliseconds ([`T1`] unless a test shortens it).
    t1_ms: std::sync::atomic::AtomicU64,
    /// The SGW-U restarted (#1010 review): once the association is set up again,
    /// its PFCP sessions are established again ([`Self::restore_sessions`]).
    restore_pending: std::sync::atomic::AtomicBool,
}

impl SxaNode {
    /// Bind the Sxa socket and install the node process-wide.
    pub async fn open(bind: SocketAddr, local_ip: Ipv4Addr) -> std::io::Result<Arc<Self>> {
        let socket = UdpSocket::bind(bind).await?;
        let bound = socket.local_addr()?;
        // #995: NTP-era seconds (TS 29.244 §8.2.65), not Unix seconds.
        let recovery_time_stamp = nextgcore_pfcp::recovery_time::now();
        let node = Arc::new(Self {
            socket: Arc::new(socket),
            local_ip,
            recovery_time_stamp,
            seq: AtomicU32::new(1),
            pending: Mutex::new(HashMap::new()),
            peers: RwLock::new(HashMap::new()),
            associated_peers: AtomicUsize::new(0),
            t1_ms: std::sync::atomic::AtomicU64::new(T1.as_millis() as u64),
            restore_pending: std::sync::atomic::AtomicBool::new(false),
        });
        log::info!(
            "PFCP/Sxa listening on {bound} (Node ID {local_ip}, Recovery Time Stamp \
             {recovery_time_stamp})"
        );
        if let Ok(mut slot) = SXA_NODE.write() {
            *slot = Some(node.clone());
        }
        Ok(node)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// A snapshot of the peers, for the metrics render and for tests.
    pub async fn peers(&self) -> Vec<SxaPeer> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Associated peers, readable from a synchronous context.
    pub fn associated_peer_count(&self) -> usize {
        self.associated_peers.load(Ordering::Relaxed)
    }

    /// Drop the association with `peer` as a lost one would be (tests).
    #[cfg(test)]
    pub async fn drop_association_for_test(&self, peer: SocketAddr) {
        self.mark_association_lost(peer, "test").await;
    }

    /// T1 of this node's transactions.
    fn t1(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.t1_ms.load(Ordering::Relaxed))
    }

    /// Shorten T1 (tests: a heartbeat loss is T1 x (N1 + 1)).
    #[cfg(test)]
    pub fn set_t1_for_test(&self, t1: std::time::Duration) {
        self.t1_ms.store(t1.as_millis() as u64, Ordering::Relaxed);
    }

    pub async fn is_associated(&self) -> bool {
        self.peers
            .read()
            .await
            .values()
            .any(|p| p.state == PfcpNodeState::Associated)
    }

    async fn refresh_peer_gauge(&self) {
        let n = self
            .peers
            .read()
            .await
            .values()
            .filter(|p| p.state == PfcpNodeState::Associated)
            .count();
        self.associated_peers.store(n, Ordering::Relaxed);
    }

    fn alloc_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed) & SEQ_MASK
    }

    /// Encode a header + body and put it on the wire.
    ///
    /// `seid` is `None` for a NODE-level message (Heartbeat, Association): TS 29.244
    /// §7.2.2.1 clears the S flag for those, so a SEID field of 0 would be a malformed
    /// header rather than a zero SEID.
    async fn send(
        &self,
        msg_type: u8,
        seid: Option<u64>,
        seq: u32,
        body: &[u8],
        to: SocketAddr,
    ) -> Result<(), String> {
        let message_type = PfcpMessageType::try_from(msg_type)
            .map_err(|e| format!("unknown PFCP message type {msg_type}: {e}"))?;
        let mut header = match seid {
            Some(seid) => PfcpHeader::new_with_seid(message_type, seid, seq),
            None => PfcpHeader::new(message_type, seq),
        };
        let after_length = if seid.is_some() { 12 } else { 4 };
        header.length = (after_length + body.len()) as u16;
        let mut buf = BytesMut::with_capacity(4 + after_length + body.len());
        header.encode(&mut buf);
        buf.extend_from_slice(body);
        self.socket
            .send_to(&buf, to)
            .await
            .map_err(|e| format!("send to {to} failed: {e}"))?;
        log::debug!(
            "[SEND] PFCP type={msg_type} seq={seq} to {to} ({} IE bytes)",
            body.len()
        );
        Ok(())
    }

    /// Send a request and wait for its response, retransmitting on T1 expiry up to N1
    /// attempts (TS 29.244 §7.2.1).
    pub async fn request(
        &self,
        msg_type: u8,
        seid: Option<u64>,
        body: &[u8],
        to: SocketAddr,
    ) -> Result<(u8, Vec<u8>), PfcpRequestError> {
        let seq = self.alloc_seq();
        let max_attempts = N1 + 1;
        let mut attempt = 0u32;

        loop {
            attempt += 1;
            let (tx, rx) = oneshot::channel();
            self.pending.lock().await.insert(seq, tx);

            if let Err(e) = self.send(msg_type, seid, seq, body, to).await {
                self.pending.lock().await.remove(&seq);
                return Err(PfcpRequestError::Local(e));
            }
            if attempt > 1 {
                log::warn!(
                    "PFCP T1 expired: retransmitting type={msg_type} seq={seq} to {to} \
                     (attempt {attempt}/{max_attempts})"
                );
            }

            match tokio::time::timeout(self.t1(), rx).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(_)) => {
                    return Err(PfcpRequestError::Local("response channel closed".into()))
                }
                Err(_) => {
                    self.pending.lock().await.remove(&seq);
                    if attempt >= max_attempts {
                        log::error!(
                            "PFCP request type={msg_type} seq={seq} to {to} unanswered after \
                             {attempt} attempts"
                        );
                        return Err(PfcpRequestError::Timeout { attempts: attempt });
                    }
                }
            }
        }
    }

    /// Set up the PFCP association toward the SGW-U (TS 29.244 §6.2.6.2).
    ///
    /// The CP function initiates: TS 29.244 §6.2.6.2 has no session signalling before an
    /// association exists, so this runs before the first Create Session Request can be
    /// served — and its failure is loud, because every session request after it would be
    /// rejected by a conformant UP function.
    pub async fn associate(self: &Arc<Self>, peer: SocketAddr) -> Result<(), String> {
        let mut body = BytesMut::new();
        PfcpLibMessage::AssociationSetupRequest(AssociationSetupRequest::new(
            NodeId::new_ipv4(self.local_ip.octets()),
            self.recovery_time_stamp,
        ))
        .encode_body(&mut body);

        let (resp_type, resp_body) = self
            .request(pfcp_msg_type::ASSOCIATION_SETUP_REQUEST, None, &body, peer)
            .await
            .map_err(|e| format!("Association Setup to {peer} failed: {e}"))?;
        if resp_type != pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE {
            return Err(format!(
                "unexpected response type {resp_type} to an Association Setup Request"
            ));
        }
        let mut cursor = Bytes::copy_from_slice(&resp_body);
        let rsp = AssociationSetupResponse::decode(&mut cursor)
            .map_err(|e| format!("malformed Association Setup Response from {peer}: {e}"))?;
        if rsp.cause != PfcpCause::RequestAccepted {
            return Err(format!(
                "SGW-U {peer} refused the association: cause={:?}",
                rsp.cause
            ));
        }

        let features = rsp.up_function_features.as_ref();
        let peer_record = SxaPeer {
            addr: peer,
            state: PfcpNodeState::Associated,
            // #995: kept in the NTP reading (a pre-#995 SGW-U sends Unix seconds).
            recovery_time_stamp: Some(nextgcore_pfcp::recovery_time::normalize_received(
                rsp.recovery_time_stamp,
            )),
            up_function_features: UpFunctionFeatures {
                ftup: features.map(|f| f.ftup).unwrap_or(false),
                empu: features.map(|f| f.empu).unwrap_or(false),
                bucp: features.map(|f| f.bucp).unwrap_or(false),
                ddnd: features.map(|f| f.ddnd).unwrap_or(false),
                dlbd: features.map(|f| f.dlbd).unwrap_or(false),
                ..Default::default()
            },
        };
        self.peers.write().await.insert(peer, peer_record);
        self.refresh_peer_gauge().await;
        log::info!(
            "PFCP association with SGW-U {peer} established (Recovery Time Stamp {}, FTUP={})",
            rsp.recovery_time_stamp,
            features.map(|f| f.ftup).unwrap_or(false)
        );
        Ok(())
    }

    /// Whether the association with `peer` is up.
    pub async fn is_associated_with(&self, peer: SocketAddr) -> bool {
        self.peers
            .read()
            .await
            .get(&peer)
            .is_some_and(|p| p.state == PfcpNodeState::Associated)
    }

    /// The association with `peer` is gone (#1001): its record is dropped, so session
    /// requests are refused until [`Self::maintain_association`] sets it up again.
    async fn mark_association_lost(&self, peer: SocketAddr, why: &str) {
        let was = self.peers.write().await.remove(&peer).is_some();
        self.refresh_peer_gauge().await;
        if was {
            log::warn!(
                "PFCP association with SGW-U {peer} lost: {why}; setting it up again \
                 (TS 29.244 §6.2.6)"
            );
        }
    }

    /// One Heartbeat Request to `peer` (TS 29.244 §7.4.2), with T1/N1. Returns the
    /// peer's Recovery Time Stamp.
    pub async fn heartbeat(&self, peer: SocketAddr) -> Result<u32, String> {
        let mut body = BytesMut::new();
        PfcpLibMessage::HeartbeatRequest(HeartbeatRequest::new(self.recovery_time_stamp))
            .encode_body(&mut body);
        let (resp_type, resp_body) = self
            .request(pfcp_msg_type::HEARTBEAT_REQUEST, None, &body, peer)
            .await
            .map_err(|e| e.to_string())?;
        if resp_type != pfcp_msg_type::HEARTBEAT_RESPONSE {
            return Err(format!(
                "unexpected response type {resp_type} to a Heartbeat Request"
            ));
        }
        let mut cursor = Bytes::copy_from_slice(&resp_body);
        HeartbeatResponse::decode(&mut cursor)
            .map(|r| r.recovery_time_stamp)
            .map_err(|e| format!("malformed Heartbeat Response from {peer}: {e}"))
    }

    /// A Recovery Time Stamp `peer` reported (TS 29.244 §8.2.65). Normalised to
    /// the NTP reading as the stored one is (#995), so a pre-#995 SGW-U's Unix
    /// seconds do not read as a restart on every heartbeat. Only a stamp NEWER
    /// than the stored one (RFC 1982, wrap-aware) is a restart: the SGW-U lost
    /// the association and every session (TS 29.244 §6.2.2, TS 23.007 §19A), so
    /// the association is set up again and its sessions restored. An older one
    /// (a reordered message from before a restart already seen) is ignored.
    async fn check_peer_recovery(&self, peer: SocketAddr, reported: u32) {
        use nextgcore_pfcp::recovery_time::{is_newer, normalize_received};
        if reported == 0 {
            return;
        }
        let reported = normalize_received(reported);
        let stored = self
            .peers
            .read()
            .await
            .get(&peer)
            .filter(|p| p.state == PfcpNodeState::Associated)
            .and_then(|p| p.recovery_time_stamp);
        let Some(stored) = stored else {
            return;
        };
        if is_newer(reported, stored) {
            self.restore_pending.store(true, Ordering::SeqCst);
            self.mark_association_lost(
                peer,
                &format!("the SGW-U restarted (Recovery Time Stamp {stored} -> {reported})"),
            )
            .await;
        } else if reported != stored {
            log::debug!(
                "SGW-U {peer} reported Recovery Time Stamp {reported}, older than the \
                 associated {stored}: a reordered message, not a restart"
            );
        }
    }

    /// Establish every PFCP session of this SGW-C again on the SGW-U, after it
    /// restarted and the association was set up anew (#1010 review). The SGW-C
    /// allocates every F-TEID, PDR and FAR itself, and its CP F-SEID is
    /// unchanged, so the restored sessions are the ones the MME and PGW hold:
    /// the same S1-U and S5/S8-U endpoints, with each FAR forwarding or
    /// buffering as the bearer's current state says. The SGW-U's new UP F-SEID
    /// is recorded from each response. Returns the number of sessions sent.
    pub fn restore_sessions(&self) -> usize {
        let ctx = crate::context::sgwc_self();
        let (mut sent, mut unsent) = (0usize, 0usize);
        for sess in ctx.sess_list_all() {
            if sess.sgwu_sxa_seid == 0 {
                // Never established: the procedure creating it is still running.
                continue;
            }
            match send_session_establishment_request(
                &sess,
                0,
                None,
                0,
                S11Continuation::Restoration { sess_id: sess.id },
            ) {
                Ok(()) => sent += 1,
                Err(e) => {
                    unsent += 1;
                    restoration_failed(sess.id, &format!("not sent ({e})"));
                }
            }
        }
        if unsent > 0 {
            log::error!(
                "SGW-U restarted: {sent} PFCP session(s) sent for restoration, {unsent} could \
                 not be sent (TS 23.007, CUPS user plane restart)"
            );
        } else {
            log::warn!(
                "SGW-U restarted: {sent} PFCP session(s) sent for restoration with their \
                 F-TEIDs (TS 23.007, CUPS user plane restart); each answer is checked"
            );
        }
        sent
    }

    /// An Association Setup Request from the UP function (TS 29.244 §6.2.6.2.1:
    /// either function may set the association up; #1010 review). The configured
    /// SGW-U is answered Request accepted, with this node's Node ID and Recovery
    /// Time Stamp, and recorded as associated; anyone else is refused (Request
    /// rejected). A newer Recovery Time Stamp than the association had is a
    /// restart: its sessions are restored, as for one seen in a heartbeat.
    async fn handle_association_setup_request(
        &self,
        header: &PfcpHeader,
        body: &[u8],
        from: SocketAddr,
    ) {
        use nextgcore_pfcp::recovery_time::{is_newer, normalize_received};
        let configured = configured_sgwu_addr();
        let decoded = AssociationSetupRequest::decode(&mut Bytes::copy_from_slice(body));
        let cause = if from.ip() != configured.ip() {
            log::warn!(
                "Association Setup Request from {from}, which is not the SGW-U {configured}"
            );
            PfcpCause::RequestRejected
        } else {
            match &decoded {
                Ok(_) => PfcpCause::RequestAccepted,
                Err(nextgcore_pfcp::error::PfcpError::MissingMandatoryIe(_)) => {
                    PfcpCause::MandatoryIeMissing
                }
                Err(e) => {
                    log::warn!("Association Setup Request from {from} is malformed: {e}");
                    PfcpCause::MandatoryIeIncorrect
                }
            }
        };
        // #1126: an accepted association is recorded before it is answered, so
        // a message the SGW-U sends right after the response finds it
        // (TS 29.244 §6.2.6.2.1). Session restoration still follows the response.
        let restarted = match (cause, &decoded) {
            (PfcpCause::RequestAccepted, Ok(req)) => {
                let reported = normalize_received(req.recovery_time_stamp);
                let features = req.up_function_features.as_ref();
                let restarted = {
                    let mut peers = self.peers.write().await;
                    let restarted = peers
                        .get(&configured)
                        .and_then(|p| p.recovery_time_stamp)
                        .is_some_and(|stored| is_newer(reported, stored));
                    peers.insert(
                        configured,
                        SxaPeer {
                            addr: configured,
                            state: PfcpNodeState::Associated,
                            recovery_time_stamp: Some(reported),
                            up_function_features: UpFunctionFeatures {
                                ftup: features.map(|f| f.ftup).unwrap_or(false),
                                empu: features.map(|f| f.empu).unwrap_or(false),
                                bucp: features.map(|f| f.bucp).unwrap_or(false),
                                ddnd: features.map(|f| f.ddnd).unwrap_or(false),
                                dlbd: features.map(|f| f.dlbd).unwrap_or(false),
                                ..Default::default()
                            },
                        },
                    );
                    restarted
                };
                self.refresh_peer_gauge().await;
                Some((reported, restarted))
            }
            _ => None,
        };
        let mut buf = BytesMut::new();
        AssociationSetupResponse::new(
            NodeId::new_ipv4(self.local_ip.octets()),
            cause,
            self.recovery_time_stamp,
        )
        .encode(&mut buf);
        let _ = self
            .send(
                pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE,
                None,
                header.sequence_number,
                &buf,
                from,
            )
            .await;
        let Some((reported, restarted)) = restarted else {
            return;
        };
        log::info!(
            "PFCP association set up by SGW-U {from} (Recovery Time Stamp {reported}{})",
            if restarted { ", a restart" } else { "" }
        );
        if restarted || self.restore_pending.swap(false, Ordering::SeqCst) {
            self.restore_sessions();
        }
    }

    /// Keep the association with `peer` up for the life of the node (#1001).
    ///
    /// While unassociated the Association Setup is tried every `retry`: a refused or
    /// unanswered first Setup (an SGW-U that comes up later, or one whose allowlist has
    /// not yet resolved a restarted SGW-C's new address) no longer leaves the SGW-C
    /// unassociated until a session request happens to need it. While associated a
    /// Heartbeat Request goes every `heartbeat` (TS 29.244 §6.2.2).
    ///
    /// No Heartbeat Response after T1/N1 is a PFCP PATH failure, not the loss of
    /// the association (#1010 review): the association and its sessions are kept
    /// and heartbeating goes on. Setting the association up again over a path that
    /// merely blinked would make a conformant SGW-U drop every session it was not
    /// told to retain (TS 29.244 §6.2.6.2.2). Only a newer Recovery Time Stamp, in
    /// a Heartbeat Response or the SGW-U's own Heartbeat Request, says the SGW-U
    /// restarted: then the association is set up again and its sessions restored
    /// ([`Self::restore_sessions`]).
    pub async fn maintain_association(
        self: Arc<Self>,
        peer: SocketAddr,
        retry: std::time::Duration,
        heartbeat: std::time::Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut failing = false;
        let mut path_failed = false;
        loop {
            if *shutdown.borrow() {
                return;
            }
            if !self.is_associated_with(peer).await {
                match self.associate(peer).await {
                    Ok(()) => {
                        failing = false;
                        path_failed = false;
                        if self.restore_pending.swap(false, Ordering::SeqCst) {
                            self.restore_sessions();
                        }
                    }
                    Err(e) if !failing => {
                        failing = true;
                        log::warn!(
                            "No PFCP association with SGW-U {peer} ({e}); session requests \
                             are refused until it is set up; retrying every {}s",
                            retry.as_secs_f32()
                        );
                    }
                    Err(e) => log::debug!("PFCP Association Setup with {peer} still failing: {e}"),
                }
            }
            let associated = self.is_associated_with(peer).await;
            let wait = if associated { heartbeat } else { retry };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
            if associated && self.is_associated_with(peer).await {
                match self.heartbeat(peer).await {
                    Ok(reported) => {
                        if std::mem::take(&mut path_failed) {
                            log::info!("PFCP path to SGW-U {peer} restored");
                        }
                        self.check_peer_recovery(peer, reported).await
                    }
                    Err(e) => {
                        if !path_failed {
                            path_failed = true;
                            log::warn!(
                                "PFCP path to SGW-U {peer} failed: no Heartbeat Response \
                                 ({e}); the association and its sessions are kept and \
                                 heartbeating continues (TS 29.244 §6.2.2)"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The receive loop, plus the drain of the synchronous senders' queue.
    pub async fn run(self: Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let (tx, mut queued) = mpsc::unbounded_channel();
        if let Ok(mut slot) = OUTBOUND.write() {
            if slot.is_some() {
                log::warn!("PFCP outbound queue replaced: the previous node's queue is dropped");
            }
            *slot = Some(tx);
        }
        let mut buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buf) => match received {
                    Ok((len, from)) => {
                        let datagram = buf[..len].to_vec();
                        // Handled inline rather than spawned: PFCP session state is
                        // per-peer ordered, and a spawn would let a Deletion overtake
                        // the Establishment it deletes.
                        self.clone().on_datagram(&datagram, from).await;
                    }
                    Err(e) => {
                        log::error!("PFCP receive failed: {e}");
                        break;
                    }
                },
                Some(req) = queued.recv() => {
                    let node = self.clone();
                    // Spawned: a request awaits T1 x N1, and blocking the receive loop
                    // for that long would stall the response it is waiting for.
                    tokio::spawn(async move {
                        let msg_type = req.msg_type;
                        match node.request(msg_type, Some(req.seid), &req.body, req.to).await {
                            Ok((resp_type, body)) => {
                                crate::sxa_response::dispatch(
                                    req.sess_id,
                                    req.continuation,
                                    resp_type,
                                    &body,
                                );
                            }
                            Err(e) => {
                                log::error!(
                                    "PFCP request type={msg_type} for session {} failed: {e}",
                                    req.sess_id
                                );
                                // The MME is waiting: a transaction that never completes
                                // must not leave the procedure hanging until its own
                                // GTP-C timer fires (TS 29.274 §7.6).
                                crate::sxa_response::fail(req.continuation, &e.to_string());
                            }
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::info!("PFCP/Sxa receive loop shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Decode one datagram and act on it.
    pub async fn on_datagram(self: Arc<Self>, pkt: &[u8], from: SocketAddr) {
        // The version is read off octet 1 BEFORE decoding: the library's decoder refuses
        // a version it does not support, so a check afterwards could never fire, and
        // TS 29.244 §7.2.2.1 requires the answer rather than a drop.
        if let Some(version) = pkt.first().map(|b| (b >> 5) & 0x07) {
            if version != 1 {
                let seq = if pkt.len() >= 8 {
                    u32::from_be_bytes([0, pkt[4], pkt[5], pkt[6]])
                } else {
                    0
                };
                log::warn!("PFCP version {version} from {from} not supported");
                let _ = self
                    .send(
                        pfcp_msg_type::VERSION_NOT_SUPPORTED_RESPONSE,
                        None,
                        seq,
                        &[],
                        from,
                    )
                    .await;
                return;
            }
        }
        let mut cursor = Bytes::copy_from_slice(pkt);
        let header = match PfcpHeader::decode(&mut cursor) {
            Ok(h) => h,
            Err(e) => {
                log::warn!("[RECV] undecodable PFCP header from {from}: {e}");
                return;
            }
        };
        let msg_type = header.message_type as u8;
        let body = cursor.to_vec();
        log::debug!(
            "[RECV] PFCP type={msg_type} seq={} seid={:?} from {from} ({} IE bytes)",
            header.sequence_number,
            header.seid,
            body.len()
        );

        if is_response_type(msg_type) {
            if let Some(tx) = self.pending.lock().await.remove(&header.sequence_number) {
                let _ = tx.send((msg_type, body));
            } else {
                log::debug!(
                    "PFCP response type={msg_type} seq={} with no pending transaction",
                    header.sequence_number
                );
            }
            return;
        }

        match msg_type {
            pfcp_msg_type::ASSOCIATION_SETUP_REQUEST => {
                self.handle_association_setup_request(&header, &body, from)
                    .await;
            }
            pfcp_msg_type::HEARTBEAT_REQUEST => {
                // #1001: the peer's own heartbeat reports its Recovery Time Stamp too; a
                // changed one is a restart, noticed here before our next heartbeat.
                if let Ok(req) = HeartbeatRequest::decode(&mut Bytes::copy_from_slice(&body)) {
                    self.check_peer_recovery(from, req.recovery_time_stamp)
                        .await;
                }
                // TS 29.244 §6.2.2.2: answer at any time. A CP function that does not is
                // declared down by the UP function's own heartbeat monitor.
                let mut buf = BytesMut::new();
                PfcpLibMessage::HeartbeatResponse(HeartbeatResponse::new(self.recovery_time_stamp))
                    .encode_body(&mut buf);
                let _ = self
                    .send(
                        pfcp_msg_type::HEARTBEAT_RESPONSE,
                        None,
                        header.sequence_number,
                        &buf,
                        from,
                    )
                    .await;
            }
            pfcp_msg_type::SESSION_REPORT_REQUEST => {
                self.handle_session_report_request(&header, &body, from)
                    .await;
            }
            pfcp_msg_type::NODE_REPORT_REQUEST => {
                self.handle_node_report_request(&header, &body, from).await;
            }
            other => {
                log::warn!("PFCP message type {other} from {from} is not handled on Sxa (CP side)");
            }
        }
    }

    /// An inbound Node Report Request (TS 29.244 §7.4.5.1, #994): the SGW-U reports a
    /// GTP-U path toward a remote peer as failed or recovered (TS 23.007 §20.3.4).
    ///
    /// The Node Report Response carries our Node ID and a Cause, and is sent before
    /// anything is acted on:
    /// - 72 No established PFCP Association when the sender is not the SGW-U this
    ///   SGW-C is associated with (§6.2.6.1);
    /// - 66 Mandatory IE missing, with the Offending IE, when the Node ID or the
    ///   Node Report Type is absent;
    /// - 67 Conditional IE missing, with the Offending IE, when the report the Node
    ///   Report Type announces (UPFR, UPRR) is absent;
    /// - 69 Mandatory IE incorrect when the message cannot be decoded;
    /// - 1 Request accepted otherwise.
    ///
    /// [`crate::up_path`] then handles the reported peers.
    async fn handle_node_report_request(&self, header: &PfcpHeader, body: &[u8], from: SocketAddr) {
        use nextgcore_pfcp::ie::IeType;
        let decoded = NodeReportRequest::decode(&mut Bytes::copy_from_slice(body));
        let (cause, offending, request) = if !self.is_associated_with(from).await {
            log::warn!("Node Report Request from {from}, which is not an associated SGW-U");
            (PfcpCause::NoEstablishedPfcpAssociation, None, None)
        } else {
            match decoded {
                Ok(req) => {
                    let missing = if req.node_report_type.upfr
                        && req.user_plane_path_failure_report.is_none()
                    {
                        Some(IeType::UserPlanePathFailureReport)
                    } else if req.node_report_type.uprr
                        && req.user_plane_path_recovery_report.is_none()
                    {
                        Some(IeType::UserPlanePathRecoveryReport)
                    } else {
                        None
                    };
                    match missing {
                        // A report the Node Report Type announces is a
                        // conditional IE (TS 29.244 Table 7.4.5.1-1): cause 67.
                        Some(ie) => (PfcpCause::ConditionalIeMissing, Some(ie as u16), None),
                        None => (PfcpCause::RequestAccepted, None, Some(req)),
                    }
                }
                Err(nextgcore_pfcp::error::PfcpError::MissingMandatoryIe(name)) => {
                    let ie = if name.contains("Report Type") {
                        IeType::NodeReportType
                    } else {
                        IeType::NodeId
                    };
                    (PfcpCause::MandatoryIeMissing, Some(ie as u16), None)
                }
                Err(e) => {
                    log::warn!("Node Report Request from {from} is malformed: {e}");
                    (PfcpCause::MandatoryIeIncorrect, None, None)
                }
            }
        };
        let mut buf = BytesMut::new();
        NodeReportResponse {
            node_id: NodeId::new_ipv4(self.local_ip.octets()),
            cause,
            offending_ie: offending,
        }
        .encode(&mut buf);
        let _ = self
            .send(
                pfcp_msg_type::NODE_REPORT_RESPONSE,
                None,
                header.sequence_number,
                &buf,
                from,
            )
            .await;
        let Some(req) = request else {
            return;
        };

        let peers_of = |report: &Option<nextgcore_pfcp::types::UserPlanePathFailureReport>| {
            report
                .iter()
                .flat_map(|r| r.remote_gtpu_peers.iter())
                .flat_map(|p| {
                    p.ipv4
                        .map(std::net::IpAddr::from)
                        .into_iter()
                        .chain(p.ipv6.map(std::net::IpAddr::from))
                })
                .collect::<Vec<_>>()
        };
        if req.node_report_type.uprr {
            crate::up_path::on_recovery(&peers_of(&req.user_plane_path_recovery_report));
        }
        if req.node_report_type.upfr {
            let hold = crate::up_path::hold();
            for (peer, generation) in
                crate::up_path::on_failure(&peers_of(&req.user_plane_path_failure_report))
            {
                tokio::spawn(async move {
                    tokio::time::sleep(hold).await;
                    crate::up_path::on_hold_expired(peer, generation);
                });
            }
        }
    }

    /// An inbound Session Report Request (TS 29.244 §7.5.8): the DLDR that makes idle-mode
    /// downlink delivery work.
    ///
    /// #54: `sxa_handler::handle_session_report_request` classified the report and returned
    /// `SendGtpToMme`, and had **zero callers** — so a real Downlink Data Report from the
    /// SGW-U produced no Downlink Data Notification and the MME was never asked to page.
    async fn handle_session_report_request(
        &self,
        header: &PfcpHeader,
        body: &[u8],
        from: SocketAddr,
    ) {
        let ctx = sgwc_self();
        let Some(sess) = header.seid.and_then(|seid| ctx.sess_find_by_seid(seid)) else {
            log::warn!(
                "Session Report for unknown SEID {:?} from {from}",
                header.seid
            );
            let mut buf = BytesMut::new();
            SessionReportResponse::new(PfcpCause::SessionContextNotFound).encode(&mut buf);
            let _ = self
                .send(
                    pfcp_msg_type::SESSION_REPORT_RESPONSE,
                    Some(header.seid.unwrap_or(0)),
                    header.sequence_number,
                    &buf,
                    from,
                )
                .await;
            return;
        };

        let mut cursor = Bytes::copy_from_slice(body);
        let (report_type, pdr_id) = match SessionReportRequest::decode(&mut cursor) {
            Ok(req) => (
                req.report_type.encode(),
                req.downlink_data_report.as_ref().map(|d| d.pdr_id),
            ),
            Err(e) => {
                log::warn!("Session Report Request from {from} is malformed: {e}");
                (0u8, None)
            }
        };

        let result = crate::sxa_handler::handle_session_report_request(
            Some(&sess),
            header.sequence_number as u64,
            report_type,
            pdr_id,
        );

        // Answer the SGW-U first: the DDN toward the MME is a separate procedure, and
        // holding the PFCP response until it completes would retransmit the report.
        let cause = match result {
            crate::sxa_handler::HandlerResult::Error(_) => {
                crate::sxa_handler::pfcp_cause::REQUEST_REJECTED
            }
            _ => crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
        };
        if let Some(msg) = sxa_build::build_session_report_response(&sess, cause) {
            let _ = self
                .send(
                    pfcp_msg_type::SESSION_REPORT_RESPONSE,
                    Some(msg.seid),
                    header.sequence_number,
                    &msg.data,
                    from,
                )
                .await;
        }

        if matches!(result, crate::sxa_handler::HandlerResult::SendGtpToMme) {
            crate::sxa_response::downlink_data_notification(sess.id, pdr_id);
        }
    }
}

// ============================================================================
// PFCP Path Functions
// ============================================================================

/// Open the Sxa PFCP socket and associate with the configured SGW-U (#54).
///
/// `SGWC_PFCP_BIND_ADDR` / `SGWC_PFCP_NODE_IP` / `SGWC_SGWU_ADDR` override the defaults
/// so a test — or a host with several interfaces — can pick each.
///
/// #387: the Node ID now comes from `sgwc.pfcp.server[0].address` (published into the
/// context by `config::apply`) when `SGWC_PFCP_NODE_IP` is unset, instead of falling
/// straight through to loopback. TS 29.244 §5.8.1 makes the Node ID the identity of the
/// association and §6.2.6.2.2 has the UP function STORE it as that identifier, so
/// `127.0.0.1` asked every remote SGW-U to key the association on an address that is
/// meaningless off-host. Loopback remains the last resort, because it is the right answer
/// for a single-host test rig and refusing to start would be worse than a warned-about
/// default — `config::apply` logs that warning when nothing is configured.
pub async fn pfcp_open() -> Result<Arc<SxaNode>, String> {
    let bind: SocketAddr = std::env::var("SGWC_PFCP_BIND_ADDR")
        .unwrap_or_else(|_| format!("0.0.0.0:{PFCP_PORT}"))
        .parse()
        .map_err(|e| format!("SGWC_PFCP_BIND_ADDR is not a socket address: {e}"))?;
    let local_ip = configured_node_ip()?;
    SxaNode::open(bind, local_ip)
        .await
        .map_err(|e| format!("failed to bind PFCP socket on {bind}: {e}"))
}

/// The address this SGW-C advertises in the Node ID IE of every node-level Sxa message
/// (TS 29.244 §8.2.38).
///
/// `SGWC_PFCP_NODE_IP` first — the test escape hatch, and the way a multi-homed host
/// overrides the file — then the configured `sgwc.pfcp.server` address, then loopback.
pub(crate) fn configured_node_ip() -> Result<Ipv4Addr, String> {
    if let Ok(value) = std::env::var("SGWC_PFCP_NODE_IP") {
        return value
            .parse()
            .map_err(|e| format!("SGWC_PFCP_NODE_IP is not an IPv4 address: {e}"));
    }
    Ok(sgwc_self().pfcp_node_ip().unwrap_or(Ipv4Addr::LOCALHOST))
}

/// The SGW-U this SGW-C provisions user planes on.
///
/// #387: resolved from the configured `sgwc.pfcp.client.sgwu` peer, which
/// `config::apply` publishes into the context at startup. Before that this function read
/// **only** `SGWC_SGWU_ADDR` — which no compose file sets anywhere in the tree — and fell
/// back to `Ipv4Addr::LOCALHOST`, so the SGW-C sent its Association Setup Request to its
/// own Sxa socket, received its own request back ("PFCP message type 5 ... is not handled
/// on Sxa (CP side)"), retransmitted to T1/N1 exhaustion and never associated. TS 29.244
/// §6.2.6.2.1 requires the CP function to retrieve an IP address **of the UP function**;
/// there was nowhere for that address to come from.
///
/// Order of precedence, and why:
///
/// 1. `SGWC_SGWU_ADDR` — kept as an override because the tests need it: `stand_in_sgwu`
///    puts an SGW-U on an ephemeral loopback port rather than fighting a live daemon for
///    UDP/8805, and an env var is what the sibling daemons use for the same purpose. It
///    takes either `ip` (PFCP's own port is assumed) or `ip:port`.
/// 2. the configured peer from the YAML file — what production uses.
/// 3. `127.0.0.1:8805` — the single-host default. Kept rather than made fatal so an
///    unconfigured daemon still starts and still serves S11 diagnostics; `config::apply`
///    warns loudly when nothing is configured, which is what was missing before.
pub fn configured_sgwu_addr() -> SocketAddr {
    if let Ok(value) = std::env::var("SGWC_SGWU_ADDR") {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return addr;
        }
        if let Ok(ip) = value.parse::<Ipv4Addr>() {
            return SocketAddr::from((ip, PFCP_PORT));
        }
        log::warn!(
            "SGWC_SGWU_ADDR='{value}' is neither an IPv4 address nor ip:port; falling back to \
             the configured sgwc.pfcp.client.sgwu peer"
        );
    }
    sgwc_self()
        .sgwu_peer()
        .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, PFCP_PORT)))
}

/// Close the Sxa PFCP path.
pub async fn pfcp_close() {
    if let Some(node) = sxa_node() {
        node.peers.write().await.clear();
        node.refresh_peer_gauge().await;
    }
    log::info!("PFCP/Sxa path closed");
}

// ============================================================================
// PFCP Send Functions (SGWC -> SGWU)
// ============================================================================

/// Whether the Sxa association with the SGW-U is up, so a PFCP session message
/// can be sent (TS 29.244 §6.2.6.1). Synchronous, for the S11 dispatch.
pub fn sgwu_associated() -> bool {
    sxa_node().is_some_and(|n| n.associated_peer_count() > 0)
}

/// Enqueue an outbound request. Callable from the synchronous S11 dispatch.
fn enqueue(msg: &PfcpMessage, sess_id: u64, continuation: S11Continuation) -> Result<(), String> {
    let tx = outbound()
        .ok_or_else(|| "PFCP path is not running: no Sxa transport to send on".to_string())?;
    // TS 29.244 §6.2.6.1: no PFCP session message before the association is set up
    // (#1001). `maintain_association` sets it up, and sets it up again when it is lost.
    if !sgwu_associated() {
        return Err(format!(
            "no PFCP association with the SGW-U {}: session messages wait for it \
             (TS 29.244 §6.2.6.1)",
            configured_sgwu_addr()
        ));
    }
    tx.send(QueuedRequest {
        msg_type: msg.msg_type,
        seid: msg.seid,
        body: msg.data.clone(),
        to: configured_sgwu_addr(),
        sess_id,
        continuation,
    })
    .map_err(|_| "PFCP outbound queue is closed".to_string())
}

/// Send Session Establishment Request to SGW-U
/// Port of sgwc_pfcp_send_session_establishment_request
pub fn send_session_establishment_request(
    sess: &SgwcSess,
    gtp_xact_id: u64,
    _gtpbuf: Option<&[u8]>,
    _flags: u64,
    continuation: S11Continuation,
) -> Result<(), String> {
    let msg = sxa_build::build_session_establishment_request(sess)
        .ok_or_else(|| "Failed to build Session Establishment Request".to_string())?;

    log::info!(
        "Sending PFCP Session Establishment Request: seid=0x{:x}, gtp_xact_id={}",
        sess.sgwc_sxa_seid,
        gtp_xact_id
    );
    enqueue(&msg, sess.id, continuation)
}

/// Send Session Modification Request to SGW-U
/// Port of sgwc_pfcp_send_session_modification_request
pub fn send_session_modification_request(
    sess: &SgwcSess,
    gtp_xact_id: u64,
    _gtpbuf: Option<&[u8]>,
    flags: u64,
) -> Result<(), String> {
    let bearer_ids: Vec<u64> = sess.bearer_ids.clone();
    let msg = sxa_build::build_bearer_to_modify_list(sess, flags, &bearer_ids)
        .ok_or_else(|| "Failed to build Session Modification Request".to_string())?;

    log::info!(
        "PFCP Session Modification: sess_id={}, gtp_xact_id={}, flags=0x{:x}",
        sess.id,
        gtp_xact_id,
        flags
    );
    enqueue(&msg, sess.id, S11Continuation::None)
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
    enqueue(&msg, sess.id, S11Continuation::None)
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
    enqueue(&msg, sess.id, S11Continuation::None)
}

/// [`send_bearer_to_modify_list`] for a modification that gates an S11 answer:
/// `continuation` is run when the SGW-U responds, or the transaction fails (#838).
pub fn send_bearer_to_modify_list_gating(
    sess: &SgwcSess,
    bearer_ids: &[u64],
    flags: u64,
    continuation: S11Continuation,
) -> Result<(), String> {
    let msg = sxa_build::build_bearer_to_modify_list(sess, flags, bearer_ids)
        .ok_or_else(|| "Failed to build Bearer to Modify List".to_string())?;
    enqueue(&msg, sess.id, continuation)
}

/// Install the indirect data-forwarding rules on the SGW-U (#48).
///
/// A Session Modification carrying a Create PDR / Create FAR pair per forwarding
/// tunnel: the PDR matches on the tunnel's own local F-TEID and the FAR forwards to the
/// endpoint the MME gave for that direction. Without this the SGW-C allocated F-TEIDs
/// and answered `REQUEST_ACCEPTED` while the SGW-U had no rule for them, so anything the
/// source eNB forwarded was dropped at the user plane.
pub fn send_indirect_forwarding_tunnels(
    sess: &SgwcSess,
    bearer_ids: &[u64],
    continuation: S11Continuation,
) -> Result<(), String> {
    let msg = sxa_build::build_indirect_forwarding_rules(sess, bearer_ids)
        .ok_or_else(|| "Failed to build indirect forwarding rules".to_string())?;
    log::info!(
        "PFCP Session Modification for indirect forwarding: sess_id={}, bearers={}",
        sess.id,
        bearer_ids.len()
    );
    enqueue(&msg, sess.id, continuation)
}

/// Send Session Deletion Request to SGW-U
/// Port of sgwc_pfcp_send_session_deletion_request
pub fn send_session_deletion_request(
    sess: &SgwcSess,
    gtp_xact_id: u64,
    _gtpbuf: Option<&[u8]>,
    continuation: S11Continuation,
) -> Result<(), String> {
    let msg = sxa_build::build_session_deletion_request(sess)
        .ok_or_else(|| "Failed to build Session Deletion Request".to_string())?;

    log::info!(
        "Sending PFCP Session Deletion Request: seid=0x{:x}, gtp_xact_id={}",
        sess.sgwu_sxa_seid,
        gtp_xact_id
    );
    enqueue(&msg, sess.id, continuation)
}

/// Delete the SGW-U session `up_seid` that no local session holds any more: one
/// whose Establishment Response arrived after its session was removed. No MME
/// waits for it.
pub fn send_session_deletion_for_seid(up_seid: u64, sess_id: u64) -> Result<(), String> {
    let mut msg = PfcpMessage::new(sxa_build::pfcp_type::SESSION_DELETION_REQUEST, up_seid);
    let mut body = bytes::BytesMut::new();
    nextgcore_pfcp::message::SessionDeletionRequest::new().encode(&mut body);
    msg.data = body.to_vec();
    enqueue(&msg, sess_id, S11Continuation::None)
}

/// Send Session Report Response to SGW-U
/// Port of sgwc_pfcp_send_session_report_response
///
/// Kept for callers outside the receive path; the receive path answers inline, because
/// the response has to echo the request's sequence number and only it knows that.
pub fn send_session_report_response(
    xact_id: u64,
    sess: &SgwcSess,
    cause: u8,
) -> Result<(), String> {
    let msg = sxa_build::build_session_report_response(sess, cause)
        .ok_or_else(|| "Failed to build Session Report Response".to_string())?;

    log::info!(
        "Sending PFCP Session Report Response: seid=0x{:x}, cause={}, xact_id={}",
        sess.sgwu_sxa_seid,
        cause,
        xact_id
    );
    enqueue(&msg, sess.id, S11Continuation::None)
}

/// Ask the SGW-U to DISCARD the packets it has buffered for a session, and stop
/// buffering (TS 29.244 §5.2.3 / PFCPSMReq-Flags DROBU, TS 23.401 §5.3.4.2).
///
/// #54: sent when the MME says the DDN cannot be served — a non-accepted DDN Acknowledge
/// or a DDN Failure Indication. Before this, both were only logged, so the buffered
/// packets stayed on the SGW-U for the life of the session: an unbounded buffer that no
/// message ever drained.
pub fn send_drop_buffered_packets(sess: &SgwcSess) -> Result<(), String> {
    let msg = sxa_build::build_drop_buffered_packets_request(sess)
        .ok_or_else(|| "Failed to build the buffered-packet discard".to_string())?;
    log::info!(
        "Sending PFCP Session Modification (DROBU) for session {}: discard buffered downlink \
         packets",
        sess.id
    );
    enqueue(&msg, sess.id, S11Continuation::None)
}

// ============================================================================
// Timer Callbacks
// ============================================================================

/// PFCP association timer callback
/// Port of sgwc_timer_pfcp_association
pub fn timer_pfcp_association(node_id: u64) {
    log::debug!("PFCP association timer fired for node {node_id}");
}

/// PFCP no heartbeat timer callback
/// Port of sgwc_timer_pfcp_no_heartbeat
pub fn timer_pfcp_no_heartbeat(node_id: u64) {
    log::warn!("PFCP no heartbeat timer fired for node {node_id}");
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

    /// #995: the SGW-C's Recovery Time Stamp is NTP-era seconds (TS 29.244 §8.2.65).
    #[tokio::test]
    async fn the_sgwc_recovery_time_stamp_is_ntp_seconds() {
        let _guard = process_state_test_guard().await;
        let node = SxaNode::open("127.0.0.1:0".parse().unwrap(), Ipv4Addr::LOCALHOST)
            .await
            .unwrap();
        let now = nextgcore_pfcp::recovery_time::now();
        assert!(now.wrapping_sub(node.recovery_time_stamp) < 60);
    }

    /// #54: `pfcp_open` binds a real socket. It used to log "In actual implementation:
    /// Create UDP sockets for PFCP" and return Ok without binding anything, so this is
    /// the assertion that separates a bound socket from a claim about one.
    #[tokio::test]
    async fn test_pfcp_open_close() {
        let _guard = process_state_test_guard().await;
        std::env::set_var("SGWC_PFCP_BIND_ADDR", "127.0.0.1:0");
        let node = pfcp_open().await.expect("bind");
        assert_ne!(node.local_addr().port(), 0, "a real socket was bound");
        assert!(sxa_node().is_some(), "the node is installed process-wide");
        pfcp_close().await;
        std::env::remove_var("SGWC_PFCP_BIND_ADDR");
    }

    /// #387: the Sxa destination comes from the CONFIGURED SGW-U, not from loopback.
    ///
    /// Asserted as equality against `172.24.0.6:8805` — the address only reachable by
    /// actually reading `docker/rust/configs/epc/sgwc.yaml` — rather than as "is not
    /// loopback", which a second bug could satisfy by accident. Before this change
    /// `configured_sgwu_addr` read only `SGWC_SGWU_ADDR`, which no compose file sets, and
    /// returned `127.0.0.1:8805`: the SGW-C's own socket.
    ///
    /// Takes the process-state guard because it writes `sgwu_peers` on the global context
    /// and removes `SGWC_SGWU_ADDR` from the environment — both are single-slot process
    /// state that every concurrent Sxa send reads (see `context::PROCESS_STATE_TEST_LOCK`).
    #[tokio::test]
    async fn the_sxa_destination_is_the_configured_sgwu_not_loopback() {
        let _guard = process_state_test_guard().await;
        // The override has to be out of the way for the configured value to be the answer;
        // sibling tests set it and the guard serialises, but it is not otherwise cleared.
        std::env::remove_var("SGWC_SGWU_ADDR");

        let expected = SocketAddr::from(([172, 24, 0, 6], PFCP_PORT));
        let config = crate::config::load_config("../../../docker/rust/configs/epc/sgwc.yaml");
        crate::config::apply(&sgwc_self(), &config);
        assert_eq!(
            configured_sgwu_addr(),
            expected,
            "every Sxa send must address the SGW-U named in sgwc.pfcp.client.sgwu"
        );

        // The same resolution the startup association and `enqueue` both go through, so
        // this is not asserting one call site's behaviour.
        assert_eq!(
            sgwc_self().sgwu_peer(),
            Some(expected),
            "the context is what both Sxa call sites read"
        );

        // And the Node ID advertised in the Association Setup Request is the SGW-C's own
        // configured address, not loopback (TS 29.244 §8.2.38 / §6.2.6.2.2).
        std::env::remove_var("SGWC_PFCP_NODE_IP");
        assert_eq!(
            configured_node_ip().expect("the configured node id parses"),
            Ipv4Addr::new(172, 24, 0, 3),
            "the UP function stores the CP function's Node ID as the association identifier"
        );
    }

    /// #703: the Session Establishment's Node ID and CP F-SEID carry the CONFIGURED
    /// address, the same one the association advertises, not loopback.
    ///
    /// Equality against 172.24.0.3, reachable only by reading the compose config,
    /// decoded with the library the SGW-U uses. Before #703 both carried 127.0.0.1
    /// unless `SGWC_PFCP_NODE_IP` was set, which no deployment does.
    #[tokio::test]
    async fn the_session_establishment_names_the_configured_node_ip() {
        let _guard = process_state_test_guard().await;
        std::env::remove_var("SGWC_PFCP_NODE_IP");
        let config = crate::config::load_config("../../../docker/rust/configs/epc/sgwc.yaml");
        crate::config::apply(&sgwc_self(), &config);

        let sess = crate::context::SgwcSess {
            id: 1,
            sgwc_sxa_seid: 0x1,
            ..Default::default()
        };
        let msg = crate::sxa_build::build_session_establishment_request(&sess).expect("built");
        let mut body = bytes::Bytes::copy_from_slice(&msg.data);
        let req = nextgcore_pfcp::message::SessionEstablishmentRequest::decode(&mut body)
            .expect("decodable");
        assert_eq!(
            req.cp_f_seid.ipv4_addr,
            Some([172, 24, 0, 3]),
            "the CP F-SEID is where the SGW-U sends its Session Reports"
        );
        assert_eq!(req.cp_f_seid.seid, 0x1);
        assert_eq!(
            req.node_id,
            nextgcore_pfcp::types::NodeId::new_ipv4([172, 24, 0, 3]),
            "the session-level Node ID agrees with the association's"
        );
    }

    /// The env override still wins, because `stand_in_sgwu` depends on it to put an SGW-U
    /// on an ephemeral port instead of fighting a live daemon for UDP/8805.
    #[tokio::test]
    async fn the_env_override_beats_the_configured_peer() {
        let _guard = process_state_test_guard().await;
        sgwc_self().set_sgwu_peers(vec![SocketAddr::from(([172, 24, 0, 6], PFCP_PORT))]);
        std::env::set_var("SGWC_SGWU_ADDR", "127.0.0.1:19805");
        assert_eq!(
            configured_sgwu_addr(),
            SocketAddr::from(([127, 0, 0, 1], 19805))
        );
        std::env::remove_var("SGWC_SGWU_ADDR");
    }

    /// With nothing configured and no override the answer is loopback — the single-host
    /// default, kept deliberately (a daemon that refuses to start is worse) and warned
    /// about by `config::apply`.
    #[tokio::test]
    async fn an_unconfigured_sgwc_still_resolves_loopback() {
        let _guard = process_state_test_guard().await;
        std::env::remove_var("SGWC_SGWU_ADDR");
        assert_eq!(
            configured_sgwu_addr(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, PFCP_PORT)),
            "the guard leaves nothing configured, so this is the unconfigured answer"
        );
    }

    /// A session request cannot be sent before the transport is running, and says so
    /// instead of returning Ok — the shape the old `send_pfcp_message` had.
    #[tokio::test]
    async fn a_session_request_without_a_running_transport_is_an_error_not_a_silent_ok() {
        let _guard = process_state_test_guard().await;
        let sess = SgwcSess {
            id: 1,
            sgwc_sxa_seid: 0x1000,
            sgwu_sxa_seid: 0x2000,
            ..Default::default()
        };
        let err = send_session_deletion_request(&sess, 0, None, S11Continuation::None)
            .expect_err("with no transport installed this must not report success");
        assert!(
            err.contains("not running"),
            "the error must name why nothing was sent, got {err}"
        );
    }

    /// A stand-in SGW-U for the association tests: Association Setup Requests are
    /// answered in turn from `refusals` (true = refused) and then accepted, each with
    /// the current `rts`; Heartbeat Requests are answered with `rts` too.
    struct AssocSgwu {
        addr: SocketAddr,
        sock: Arc<UdpSocket>,
        setups: Arc<AtomicU32>,
        heartbeats: Arc<AtomicU32>,
        rts: Arc<AtomicU32>,
        /// Node Report Responses received: (sequence number, body).
        node_report_responses: Arc<std::sync::Mutex<Vec<(u32, Vec<u8>)>>>,
        /// Session Modification Request bodies received (each answered accepted).
        modifications: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        /// (sequence number, CP F-SEID) of the Session Establishment Requests
        /// received, retransmissions included; they are not answered.
        establishments: Arc<std::sync::Mutex<Vec<(u32, u64)>>>,
    }

    async fn assoc_sgwu(refusals: Vec<bool>) -> AssocSgwu {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let setups = Arc::new(AtomicU32::new(0));
        let heartbeats = Arc::new(AtomicU32::new(0));
        let rts = Arc::new(AtomicU32::new(100));
        let establishments = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (s, h, r, up, est) = (
            setups.clone(),
            heartbeats.clone(),
            rts.clone(),
            sock.clone(),
            establishments.clone(),
        );
        let node_report_responses = Arc::new(std::sync::Mutex::new(Vec::new()));
        let modifications = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (nrr, mods) = (node_report_responses.clone(), modifications.clone());
        tokio::spawn(async move {
            let mut refusals = std::collections::VecDeque::from(refusals);
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, from)) = up.recv_from(&mut buf).await else {
                    return;
                };
                let mut cursor = Bytes::copy_from_slice(&buf[..len]);
                let Ok(header) = PfcpHeader::decode(&mut cursor) else {
                    continue;
                };
                let mut body = BytesMut::new();
                match header.message_type as u8 {
                    pfcp_msg_type::NODE_REPORT_RESPONSE => {
                        nrr.lock()
                            .unwrap()
                            .push((header.sequence_number, cursor.to_vec()));
                        continue;
                    }
                    pfcp_msg_type::SESSION_MODIFICATION_REQUEST => {
                        mods.lock().unwrap().push(cursor.to_vec());
                        nextgcore_pfcp::message::SessionModificationResponse::new(
                            PfcpCause::RequestAccepted,
                        )
                        .encode(&mut body);
                        let mut out = BytesMut::new();
                        let mut h = PfcpHeader::new_with_seid(
                            PfcpMessageType::SessionModificationResponse,
                            header.seid.unwrap_or(0),
                            header.sequence_number,
                        );
                        h.length = (12 + body.len()) as u16;
                        h.encode(&mut out);
                        out.extend_from_slice(&body);
                        let _ = up.send_to(&out, from).await;
                        continue;
                    }
                    _ => {}
                }
                let resp_type = match header.message_type as u8 {
                    pfcp_msg_type::ASSOCIATION_SETUP_REQUEST => {
                        s.fetch_add(1, Ordering::SeqCst);
                        let cause = if refusals.pop_front().unwrap_or(false) {
                            PfcpCause::RequestRejected
                        } else {
                            PfcpCause::RequestAccepted
                        };
                        AssociationSetupResponse::new(
                            NodeId::new_ipv4([127, 0, 0, 9]),
                            cause,
                            r.load(Ordering::SeqCst),
                        )
                        .encode(&mut body);
                        PfcpMessageType::AssociationSetupResponse
                    }
                    pfcp_msg_type::SESSION_ESTABLISHMENT_REQUEST => {
                        if let Ok(req) =
                            nextgcore_pfcp::message::SessionEstablishmentRequest::decode(
                                &mut cursor,
                            )
                        {
                            est.lock()
                                .unwrap()
                                .push((header.sequence_number, req.cp_f_seid.seid));
                        }
                        continue;
                    }
                    pfcp_msg_type::HEARTBEAT_REQUEST => {
                        h.fetch_add(1, Ordering::SeqCst);
                        HeartbeatResponse::new(r.load(Ordering::SeqCst)).encode(&mut body);
                        PfcpMessageType::HeartbeatResponse
                    }
                    _ => continue,
                };
                let mut out = BytesMut::new();
                let mut h = PfcpHeader::new(resp_type, header.sequence_number);
                h.length = (4 + body.len()) as u16;
                h.encode(&mut out);
                out.extend_from_slice(&body);
                let _ = up.send_to(&out, from).await;
            }
        });
        AssocSgwu {
            addr,
            sock,
            setups,
            heartbeats,
            rts,
            node_report_responses,
            modifications,
            establishments,
        }
    }

    /// A relay in front of `real` that drops every request from the SGW-C while
    /// `silent` is set, counting what it dropped. Returns its address.
    async fn silenceable_relay(
        real: SocketAddr,
        silent: Arc<std::sync::atomic::AtomicBool>,
        dropped: Arc<AtomicU32>,
    ) -> SocketAddr {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        tokio::spawn(async move {
            let mut client = None;
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, from)) = relay.recv_from(&mut buf).await else {
                    return;
                };
                if from == real {
                    if let Some(c) = client {
                        let _ = relay.send_to(&buf[..len], c).await;
                    }
                } else if silent.load(Ordering::SeqCst) {
                    dropped.fetch_add(1, Ordering::SeqCst);
                } else {
                    client = Some(from);
                    let _ = relay.send_to(&buf[..len], real).await;
                }
            }
        });
        relay_addr
    }

    /// #1010 review, TS 29.244 §6.2.2 / §6.2.6.2.2: an SGW-U that stops answering
    /// heartbeats (T1 x (N1 + 1)) is a PFCP path failure. The association and the
    /// sessions are kept, heartbeating goes on, and no new Association Setup is
    /// sent when the path comes back: a re-Setup would make a conformant SGW-U
    /// drop every session it was not told to retain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unanswered_heartbeat_is_a_path_failure_that_keeps_the_association() {
        let guard = process_state_test_guard().await;
        let real = assoc_sgwu(Vec::new()).await;
        let silent = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(AtomicU32::new(0));
        let relay = silenceable_relay(real.addr, silent.clone(), dropped.clone()).await;
        let (node, stop) = maintained_node(
            &guard,
            relay,
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(50),
        )
        .await;
        let (setups, heartbeats) = (real.setups.clone(), real.heartbeats.clone());
        eventually("a heartbeat", || heartbeats.load(Ordering::SeqCst) >= 1).await;

        // More than one whole unanswered heartbeat (N1 + 1 transmissions).
        silent.store(true, Ordering::SeqCst);
        let d = dropped.clone();
        eventually("two unanswered heartbeats", || {
            d.load(Ordering::SeqCst) > 2 * (N1 + 1)
        })
        .await;
        assert_eq!(node.associated_peer_count(), 1, "the association is kept");
        assert!(node.is_associated_with(relay).await);

        silent.store(false, Ordering::SeqCst);
        let before = heartbeats.load(Ordering::SeqCst);
        eventually("heartbeats answered again", || {
            heartbeats.load(Ordering::SeqCst) > before + 1
        })
        .await;
        assert_eq!(setups.load(Ordering::SeqCst), 1, "no new Association Setup");
        assert_eq!(node.associated_peer_count(), 1);
        let _ = stop.send(true);
    }

    /// #1010 review: a pre-#995 SGW-U reports its Recovery Time Stamp in Unix
    /// seconds. Normalised as the stored stamp is, it compares equal on every
    /// heartbeat: the association does not flap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_unix_seconds_recovery_time_stamp_is_not_a_restart() {
        let guard = process_state_test_guard().await;
        let sgwu = assoc_sgwu(Vec::new()).await;
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
            - 3600;
        sgwu.rts.store(unix, Ordering::SeqCst);
        let (node, stop) = maintained_node(
            &guard,
            sgwu.addr,
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(20),
        )
        .await;
        let heartbeats = sgwu.heartbeats.clone();
        eventually("five heartbeats", || heartbeats.load(Ordering::SeqCst) >= 5).await;
        assert_eq!(sgwu.setups.load(Ordering::SeqCst), 1, "no re-Setup");
        assert_eq!(
            node.peers().await[0].recovery_time_stamp,
            Some(nextgcore_pfcp::recovery_time::from_unix_secs(u64::from(
                unix
            ))),
            "kept in the NTP reading"
        );
        let _ = stop.send(true);
    }

    /// #1010 review, TS 23.007: a restarted SGW-U (a newer Recovery Time Stamp)
    /// is associated again and every established PFCP session is established on
    /// it again, with the SGW-C's own CP F-SEID. A session still being set up is
    /// left to its own procedure, and an older stamp (a reordered message) is
    /// not a restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_sgwu_gets_its_sessions_back() {
        let guard = process_state_test_guard().await;
        let ctx = sgwc_self();
        let ue = ctx
            .ue_add(&[0x21, 0x43, 0x65, 0x87, 0x09, 0x10, 0xf0])
            .unwrap();
        let mut established = ctx.sess_add(ue.id, "internet").unwrap();
        established.sgwu_sxa_seid = 0x5555_0001;
        ctx.sess_update(&established);
        let pending = ctx.sess_add(ue.id, "ims").unwrap();
        assert_eq!(pending.sgwu_sxa_seid, 0);

        let sgwu = assoc_sgwu(Vec::new()).await;
        let sock = sgwu.sock.clone();
        // Session messages go to the configured SGW-U.
        std::env::set_var("SGWC_SGWU_ADDR", sgwu.addr.to_string());
        let (node, stop) = maintained_node(
            &guard,
            sgwu.addr,
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(50),
        )
        .await;
        let setups = sgwu.setups.clone();
        eventually("the association", || setups.load(Ordering::SeqCst) >= 1).await;
        eventually("associated", || node.associated_peer_count() == 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // An older stamp in the SGW-U's own Heartbeat Request: not a restart.
        let hb = |rts: u32| {
            let mut body = BytesMut::new();
            HeartbeatRequest::new(rts).encode(&mut body);
            let mut out = BytesMut::new();
            let mut h = PfcpHeader::new(PfcpMessageType::HeartbeatRequest, 0x99);
            h.length = (4 + body.len()) as u16;
            h.encode(&mut out);
            out.extend_from_slice(&body);
            out
        };
        sock.send_to(&hb(50), node.local_addr()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            setups.load(Ordering::SeqCst),
            1,
            "an older stamp is no restart"
        );

        // The restart; the stand-in now records the requests it ignores.
        sgwu.rts.store(400, Ordering::SeqCst);
        sock.send_to(&hb(400), node.local_addr()).await.unwrap();
        eventually("the Setup after the restart", || {
            setups.load(Ordering::SeqCst) >= 2
        })
        .await;
        let establishments = sgwu.establishments.clone();
        let seid = established.sgwc_sxa_seid;
        eventually("the restored session", || {
            establishments
                .lock()
                .unwrap()
                .iter()
                .any(|(_, s)| *s == seid)
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // (The context is process-wide: other tests' sessions may be restored too.)
        let sent = establishments.lock().unwrap().clone();
        let mut requests: Vec<u32> = sent
            .iter()
            .filter(|(_, s)| *s == seid)
            .map(|(q, _)| *q)
            .collect();
        requests.dedup();
        assert_eq!(requests.len(), 1, "restored once, with its own CP F-SEID");
        assert!(
            !sent.iter().any(|(_, s)| *s == pending.sgwc_sxa_seid),
            "a session still being set up is left to its procedure"
        );
        // #1010 review: the stand-in never answers the restoration: after T1 x
        // (N1 + 1) it is counted (and logged) as failed.
        let failed0 = RESTORATIONS_FAILED.load(Ordering::Relaxed);
        eventually("the unanswered restoration counted", || {
            RESTORATIONS_FAILED.load(Ordering::Relaxed) > failed0
        })
        .await;
        let _ = stop.send(true);
        std::env::remove_var("SGWC_SGWU_ADDR");
        ctx.ue_remove(ue.id);
    }

    /// #1001, TS 29.244 §6.2.6.1: no PFCP session message goes before the association
    /// is set up; with the transport running but unassociated the send is an error that
    /// says so, and once associated it goes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_session_message_before_the_association() {
        let _guard = process_state_test_guard().await;
        let sgwu = assoc_sgwu(Vec::new()).await;
        std::env::set_var("SGWC_SGWU_ADDR", sgwu.addr.to_string());
        let node = SxaNode::open("127.0.0.1:0".parse().unwrap(), Ipv4Addr::LOCALHOST)
            .await
            .unwrap();
        let (stop, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(node.clone().run(rx));
        let sess = SgwcSess {
            id: 1,
            sgwc_sxa_seid: 0x1000,
            sgwu_sxa_seid: 0x2000,
            ..Default::default()
        };
        let mut err = String::new();
        for _ in 0..200 {
            match send_session_deletion_request(&sess, 0, None, S11Continuation::None) {
                Err(e) if e.contains("not running") => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await
                }
                Err(e) => {
                    err = e;
                    break;
                }
                Ok(()) => panic!("sent with no association"),
            }
        }
        assert!(err.contains("no PFCP association"), "got {err:?}");
        node.associate(sgwu.addr).await.unwrap();
        assert!(send_session_deletion_request(&sess, 0, None, S11Continuation::None).is_ok());
        std::env::remove_var("SGWC_SGWU_ADDR");
        let _ = stop.send(true);
    }

    /// The SGW-C's node, running, with the association kept by `maintain_association`.
    async fn maintained_node(
        _ambient: &ProcessStateGuard,
        peer: SocketAddr,
        retry: std::time::Duration,
        heartbeat: std::time::Duration,
    ) -> (Arc<SxaNode>, tokio::sync::watch::Sender<bool>) {
        let node = SxaNode::open("127.0.0.1:0".parse().unwrap(), Ipv4Addr::LOCALHOST)
            .await
            .unwrap();
        // A heartbeat loss is T1 x (N1 + 1): 300 ms rather than 9 s.
        node.set_t1_for_test(std::time::Duration::from_millis(100));
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(node.clone().run(rx.clone()));
        tokio::spawn(
            node.clone()
                .maintain_association(peer, retry, heartbeat, rx),
        );
        (node, tx)
    }

    async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
        for _ in 0..300 {
            if cond() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// #1001 acceptance: an SGW-C whose first Association Setup is refused (an SGW-U
    /// whose allowlist has not resolved it yet) associates on the next retry, with no
    /// session request to prompt it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_association_setup_is_retried_on_the_timer() {
        let guard = process_state_test_guard().await;
        let sgwu = assoc_sgwu(vec![true]).await;
        let (node, stop) = maintained_node(
            &guard,
            sgwu.addr,
            std::time::Duration::from_millis(200),
            std::time::Duration::from_secs(60),
        )
        .await;
        let setups = sgwu.setups.clone();
        eventually("the first Setup", || setups.load(Ordering::SeqCst) >= 1).await;
        assert!(!node.is_associated_with(sgwu.addr).await, "refused");
        assert_eq!(node.associated_peer_count(), 0);
        let mut associated = false;
        for _ in 0..300 {
            if node.is_associated_with(sgwu.addr).await {
                associated = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(associated, "associated on the retry");
        assert_eq!(sgwu.setups.load(Ordering::SeqCst), 2);
        assert_eq!(node.associated_peer_count(), 1);
        let _ = stop.send(true);
    }

    /// #1001: an associated SGW-U is heartbeated, and one that restarted (a new
    /// Recovery Time Stamp, TS 23.007 §19A) has lost the association: it is set up
    /// again. A restart its own Heartbeat Request reports is noticed the same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_sgwu_is_associated_again() {
        let guard = process_state_test_guard().await;
        let sgwu = assoc_sgwu(Vec::new()).await;
        let (node, stop) = maintained_node(
            &guard,
            sgwu.addr,
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(100),
        )
        .await;
        let (setups, heartbeats) = (sgwu.setups.clone(), sgwu.heartbeats.clone());
        eventually("a heartbeat on the association", || {
            heartbeats.load(Ordering::SeqCst) >= 1
        })
        .await;
        assert_eq!(setups.load(Ordering::SeqCst), 1, "same peer: no new Setup");

        // Restart seen by our heartbeat.
        sgwu.rts.store(200, Ordering::SeqCst);
        eventually("the Setup after the restart", || {
            setups.load(Ordering::SeqCst) >= 2
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let peer = node.peers().await;
        assert_eq!(peer.len(), 1);
        assert_eq!(peer[0].state, PfcpNodeState::Associated);
        assert_eq!(peer[0].recovery_time_stamp, Some(200));

        // Restart reported by the SGW-U's own Heartbeat Request (our heartbeats
        // still see 200, so only the inbound report can trigger this Setup).
        let mut body = BytesMut::new();
        HeartbeatRequest::new(300).encode(&mut body);
        let mut out = BytesMut::new();
        let mut h = PfcpHeader::new(PfcpMessageType::HeartbeatRequest, 0x77);
        h.length = (4 + body.len()) as u16;
        h.encode(&mut out);
        out.extend_from_slice(&body);
        let before = setups.load(Ordering::SeqCst);
        sgwu.sock.send_to(&out, node.local_addr()).await.unwrap();
        eventually("the Setup after the reported restart", || {
            setups.load(Ordering::SeqCst) > before
        })
        .await;
        let _ = stop.send(true);
    }

    /// A Node Report Request with a failure and/or recovery report for the peers.
    fn node_report(seq: u32, failed: &[[u8; 4]], recovered: &[[u8; 4]]) -> Vec<u8> {
        use nextgcore_pfcp::types::{NodeReportType, RemoteGtpUPeer, UserPlanePathFailureReport};
        let report = |ips: &[[u8; 4]]| {
            (!ips.is_empty()).then(|| UserPlanePathFailureReport {
                remote_gtpu_peers: ips
                    .iter()
                    .map(|ip| RemoteGtpUPeer {
                        ipv4: Some(*ip),
                        ipv6: None,
                    })
                    .collect(),
            })
        };
        node_report_pdu(
            seq,
            NodeReportRequest {
                node_id: NodeId::new_ipv4([127, 0, 0, 9]),
                node_report_type: NodeReportType {
                    upfr: !failed.is_empty(),
                    uprr: !recovered.is_empty(),
                    ..Default::default()
                },
                user_plane_path_failure_report: report(failed),
                user_plane_path_recovery_report: report(recovered),
            },
        )
    }

    fn node_report_pdu(seq: u32, req: NodeReportRequest) -> Vec<u8> {
        let mut body = BytesMut::new();
        req.encode(&mut body);
        let mut out = BytesMut::new();
        let mut h = PfcpHeader::new(PfcpMessageType::NodeReportRequest, seq);
        h.length = (4 + body.len()) as u16;
        h.encode(&mut out);
        out.extend_from_slice(&body);
        out.to_vec()
    }

    /// A UE with one bearer whose downlink S1-U endpoint is `enb`.
    fn ue_toward(imsi: &[u8], enb: [u8; 4]) -> (u64, u64) {
        let ctx = sgwc_self();
        let ue = ctx.ue_add(imsi).expect("ue");
        let sess = ctx.sess_add(ue.id, "internet").expect("sess");
        let mut bearer = ctx.bearer_add(sess.id).expect("bearer");
        bearer.ebi = 5;
        ctx.bearer_update(&bearer);
        let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).expect("dl tunnel");
        dl.far_id = Some(0x0994);
        dl.remote_teid = 0x9940;
        dl.remote_ip.ipv4 = Some(Ipv4Addr::from(enb));
        ctx.tunnel_update(&dl);
        (ue.id, bearer.id)
    }

    /// The SGW-C's node, running and associated with `sgwu` (no maintenance task).
    async fn associated_node(
        _ambient: &ProcessStateGuard,
        sgwu: &AssocSgwu,
    ) -> (Arc<SxaNode>, tokio::sync::watch::Sender<bool>) {
        std::env::set_var("SGWC_SGWU_ADDR", sgwu.addr.to_string());
        let node = SxaNode::open("127.0.0.1:0".parse().unwrap(), Ipv4Addr::LOCALHOST)
            .await
            .unwrap();
        let (stop, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(node.clone().run(rx));
        node.associate(sgwu.addr).await.unwrap();
        // `run` installs the outbound queue in its own body.
        for _ in 0..200 {
            if outbound().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        (node, stop)
    }

    fn response_cause(body: &[u8]) -> (PfcpCause, Option<u16>) {
        let rsp = NodeReportResponse::decode(&mut Bytes::copy_from_slice(body)).unwrap();
        (rsp.cause, rsp.offending_ie)
    }

    /// #994, TS 29.244 §7.4.5 / TS 23.007 §20.3.4: a User Plane Path Failure Report
    /// from the associated SGW-U is answered Request accepted (its sequence number
    /// echoed). The UE whose downlink S1-U endpoint is the failed eNodeB has its S1-U
    /// bearers released with Release Access Bearers semantics: the endpoint is
    /// forgotten, and its downlink FAR goes to BUFF + NOCP at the SGW-U, so downlink
    /// data is buffered and notified (DDN, paging). A UE on another eNodeB is left
    /// alone. A repeated report changes nothing, and the Recovery Report clears the
    /// peer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_path_failure_report_releases_the_s1u_bearers_toward_that_enb() {
        let guard = process_state_test_guard().await;
        crate::up_path::clear_for_test();
        let sgwu = assoc_sgwu(Vec::new()).await;
        let (node, stop) = associated_node(&guard, &sgwu).await;
        let (ue_a, bearer_a) = ue_toward(b"001010994000001", [10, 0, 0, 50]);
        let (ue_b, bearer_b) = ue_toward(b"001010994000002", [10, 0, 0, 51]);
        let ctx = sgwc_self();
        let failures0 = crate::up_path::FAILURES_TOTAL.load(Ordering::Relaxed);
        let to = node.local_addr();

        sgwu.sock
            .send_to(&node_report(0x99_0001, &[[10, 0, 0, 50]], &[]), to)
            .await
            .unwrap();
        let responses = sgwu.node_report_responses.clone();
        eventually("the Node Report Response", || {
            !responses.lock().unwrap().is_empty()
        })
        .await;
        let (seq, body) = responses.lock().unwrap()[0].clone();
        assert_eq!(seq, 0x99_0001, "the sequence number is echoed");
        assert_eq!(response_cause(&body).0, PfcpCause::RequestAccepted);

        let mods = sgwu.modifications.clone();
        eventually("the deactivation", || !mods.lock().unwrap().is_empty()).await;
        let req = nextgcore_pfcp::message::SessionModificationRequest::decode(
            &mut Bytes::copy_from_slice(&mods.lock().unwrap()[0]),
        )
        .unwrap();
        let far = req
            .update_fars
            .iter()
            .find(|f| f.far_id == 0x0994)
            .expect("the downlink FAR is updated");
        let aa = far.apply_action.expect("with an Apply Action");
        assert!(aa.buff && aa.nocp && !aa.forw, "BUFF + NOCP: {aa:?}");
        let dl_a = ctx.dl_tunnel_in_bearer(bearer_a).unwrap();
        assert_eq!((dl_a.remote_teid, dl_a.remote_ip.ipv4), (0, None));
        let dl_b = ctx.dl_tunnel_in_bearer(bearer_b).unwrap();
        assert_eq!(
            dl_b.remote_ip.ipv4,
            Some(Ipv4Addr::new(10, 0, 0, 51)),
            "the UE on another eNodeB is untouched"
        );
        assert_eq!(mods.lock().unwrap().len(), 1, "one session modified");
        assert!(crate::up_path::is_failed("10.0.0.50".parse().unwrap()));
        assert_eq!(
            crate::up_path::FAILURES_TOTAL.load(Ordering::Relaxed),
            failures0 + 1
        );

        // Repeated: answered, no second count.
        sgwu.sock
            .send_to(&node_report(0x99_0002, &[[10, 0, 0, 50]], &[]), to)
            .await
            .unwrap();
        eventually("the second response", || {
            responses.lock().unwrap().len() >= 2
        })
        .await;
        assert_eq!(
            crate::up_path::FAILURES_TOTAL.load(Ordering::Relaxed),
            failures0 + 1
        );

        // Recovered.
        sgwu.sock
            .send_to(&node_report(0x99_0003, &[], &[[10, 0, 0, 50]]), to)
            .await
            .unwrap();
        eventually("the third response", || {
            responses.lock().unwrap().len() >= 3
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!crate::up_path::is_failed("10.0.0.50".parse().unwrap()));
        assert!(crate::main_render_metrics_for_test().contains("sgwc_up_paths_failed 0"));
        ctx.ue_remove(ue_a);
        ctx.ue_remove(ue_b);
        std::env::remove_var("SGWC_SGWU_ADDR");
        let _ = stop.send(true);
    }

    /// #994: a Node Report from anyone but the associated SGW-U is refused with cause
    /// 72 (TS 29.244 §6.2.6.1) and not acted on; one announcing a failure report it
    /// does not carry is refused with 67 Conditional IE missing and the Offending IE.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_report_from_a_stranger_or_without_its_report_is_refused() {
        let guard = process_state_test_guard().await;
        crate::up_path::clear_for_test();
        let sgwu = assoc_sgwu(Vec::new()).await;
        let (node, stop) = associated_node(&guard, &sgwu).await;
        let (ue, bearer) = ue_toward(b"001010994000003", [10, 0, 0, 52]);
        let ctx = sgwc_self();

        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger
            .send_to(&node_report(7, &[[10, 0, 0, 52]], &[]), node.local_addr())
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stranger.recv_from(&mut buf),
        )
        .await
        .expect("answered")
        .unwrap();
        let mut cursor = Bytes::copy_from_slice(&buf[..len]);
        let header = PfcpHeader::decode(&mut cursor).unwrap();
        assert_eq!(
            header.message_type as u8,
            pfcp_msg_type::NODE_REPORT_RESPONSE
        );
        assert_eq!(header.sequence_number, 7);
        assert_eq!(
            response_cause(&cursor).0,
            PfcpCause::NoEstablishedPfcpAssociation
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!crate::up_path::is_failed("10.0.0.52".parse().unwrap()));
        assert_eq!(
            ctx.dl_tunnel_in_bearer(bearer).unwrap().remote_teid,
            0x9940,
            "not released"
        );

        // UPFR set, report absent.
        let pkt = node_report_pdu(
            8,
            NodeReportRequest {
                node_id: NodeId::new_ipv4([127, 0, 0, 9]),
                node_report_type: nextgcore_pfcp::types::NodeReportType {
                    upfr: true,
                    ..Default::default()
                },
                user_plane_path_failure_report: None,
                user_plane_path_recovery_report: None,
            },
        );
        sgwu.sock.send_to(&pkt, node.local_addr()).await.unwrap();
        let responses = sgwu.node_report_responses.clone();
        eventually("the response", || !responses.lock().unwrap().is_empty()).await;
        let (seq, body) = responses.lock().unwrap()[0].clone();
        assert_eq!(seq, 8);
        assert_eq!(
            response_cause(&body),
            (
                PfcpCause::ConditionalIeMissing,
                Some(nextgcore_pfcp::ie::IeType::UserPlanePathFailureReport as u16)
            )
        );
        assert!(!crate::up_path::is_failed("10.0.0.52".parse().unwrap()));
        ctx.ue_remove(ue);
        std::env::remove_var("SGWC_SGWU_ADDR");
        let _ = stop.send(true);
    }

    /// #994, TS 23.007 §20.3.1: a path still down when the maximum path failure
    /// duration expires has its record dropped, and a bearer a later Modify Bearer
    /// pointed at it again is released then. A recovery inside the hold voids it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hold_expires_only_for_a_path_still_down() {
        let guard = process_state_test_guard().await;
        crate::up_path::clear_for_test();
        std::env::set_var("SGWC_UP_PATH_FAILURE_HOLD_SECS", "1");
        let sgwu = assoc_sgwu(Vec::new()).await;
        let (node, stop) = associated_node(&guard, &sgwu).await;
        let (ue, bearer) = ue_toward(b"001010994000004", [10, 0, 0, 53]);
        let ctx = sgwc_self();
        let expired0 = crate::up_path::HOLDS_EXPIRED_TOTAL.load(Ordering::Relaxed);
        let mods = sgwu.modifications.clone();
        let to = node.local_addr();

        sgwu.sock
            .send_to(&node_report(1, &[[10, 0, 0, 53], [10, 0, 0, 54]], &[]), to)
            .await
            .unwrap();
        eventually("the release", || mods.lock().unwrap().len() == 1).await;
        // 10.0.0.54 recovers inside the hold.
        sgwu.sock
            .send_to(&node_report(2, &[], &[[10, 0, 0, 54]]), to)
            .await
            .unwrap();
        // A Modify Bearer points the UE at the failed eNodeB again.
        let mut dl = ctx.dl_tunnel_in_bearer(bearer).unwrap();
        dl.remote_teid = 0x9941;
        dl.remote_ip.ipv4 = Some(Ipv4Addr::new(10, 0, 0, 53));
        ctx.tunnel_update(&dl);
        assert!(crate::up_path::is_failed("10.0.0.53".parse().unwrap()));

        let mut released_again = false;
        for _ in 0..300 {
            if mods.lock().unwrap().len() >= 2 {
                released_again = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(released_again, "released again at the hold's expiry");
        assert_eq!(ctx.dl_tunnel_in_bearer(bearer).unwrap().remote_teid, 0);
        assert!(
            !crate::up_path::is_failed("10.0.0.53".parse().unwrap()),
            "dropped"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            crate::up_path::HOLDS_EXPIRED_TOTAL.load(Ordering::Relaxed),
            expired0 + 1,
            "only the path still down expired"
        );
        ctx.ue_remove(ue);
        std::env::remove_var("SGWC_UP_PATH_FAILURE_HOLD_SECS");
        std::env::remove_var("SGWC_SGWU_ADDR");
        let _ = stop.send(true);
    }

    /// #1014 review: a Modify Bearer that points a bearer at an eNodeB whose user
    /// plane path is failed is answered, and the UE's S1-U bearers are released at
    /// once (downlink buffered for a DDN), not black-holed until the hold expires.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_modify_bearer_toward_a_failed_enb_is_released_at_once() {
        let guard = process_state_test_guard().await;
        crate::up_path::clear_for_test();
        let sgwu = assoc_sgwu(Vec::new()).await;
        let (node, stop) = associated_node(&guard, &sgwu).await;
        let (ue, bearer) = ue_toward(b"001010994000005", [10, 0, 0, 60]);
        let ctx = sgwc_self();
        let mods = sgwu.modifications.clone();
        // 10.0.0.61 fails; the UE is on 10.0.0.60, so nothing is released yet.
        sgwu.sock
            .send_to(&node_report(1, &[[10, 0, 0, 61]], &[]), node.local_addr())
            .await
            .unwrap();
        eventually("the failure", || {
            crate::up_path::is_failed("10.0.0.61".parse().unwrap())
        })
        .await;
        assert!(mods.lock().unwrap().is_empty());

        // The MME moves the UE's downlink to the failed eNodeB.
        let mut dl = ctx.dl_tunnel_in_bearer(bearer).unwrap();
        dl.remote_teid = 0x9961;
        dl.remote_ip.ipv4 = Some(Ipv4Addr::new(10, 0, 0, 61));
        ctx.tunnel_update(&dl);
        crate::sxa_response::answer_modify_bearer(
            &crate::sxa_response::PendingModifyBearer {
                peer: "127.0.0.1:2123".parse().unwrap(),
                seq: 1,
                mme_teid: 1,
                waiting: Default::default(),
                modified: vec![(bearer, 5)],
                marked_for_removal: Vec::new(),
            },
            None,
        );
        assert_eq!(
            ctx.dl_tunnel_in_bearer(bearer).unwrap().remote_teid,
            0,
            "released at once"
        );
        eventually("the BUFF + NOCP modification", || {
            mods.lock().unwrap().len() == 1
        })
        .await;
        ctx.ue_remove(ue);
        std::env::remove_var("SGWC_SGWU_ADDR");
        let _ = stop.send(true);
    }

    /// #1014 review: the release finds the UEs toward an eNodeB through the
    /// downlink-peer index, which follows every tunnel update and removal.
    #[test]
    fn the_downlink_peer_index_follows_the_tunnels() {
        let ctx = sgwc_self();
        let (ue, bearer) = ue_toward(b"001010994000006", [10, 0, 0, 70]);
        let a: std::net::IpAddr = "10.0.0.70".parse().unwrap();
        let b: std::net::IpAddr = "10.0.0.71".parse().unwrap();
        assert_eq!(ctx.ue_ids_with_downlink_toward(a), vec![ue]);
        let mut dl = ctx.dl_tunnel_in_bearer(bearer).unwrap();
        dl.remote_ip.ipv4 = Some(Ipv4Addr::new(10, 0, 0, 71));
        ctx.tunnel_update(&dl);
        assert!(ctx.ue_ids_with_downlink_toward(a).is_empty(), "moved");
        assert_eq!(ctx.ue_ids_with_downlink_toward(b), vec![ue]);
        dl.remote_teid = 0;
        ctx.tunnel_update(&dl);
        assert!(
            ctx.ue_ids_with_downlink_toward(b).is_empty(),
            "an S1-U released forwards nowhere"
        );
        dl.remote_teid = 0x9971;
        ctx.tunnel_update(&dl);
        assert_eq!(ctx.ue_ids_with_downlink_toward(b), vec![ue]);
        ctx.ue_remove(ue);
        assert!(ctx.ue_ids_with_downlink_toward(b).is_empty(), "removed");
    }

    /// #1010 review, TS 29.244 §6.2.6.2.1: the SGW-U may set the association up
    /// itself. The configured SGW-U's Association Setup Request is answered
    /// Request accepted with this node's Node ID and Recovery Time Stamp, and the
    /// association is recorded; anyone else's is refused (Request rejected).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_sgwu_initiated_association_setup_is_answered() {
        let _guard = process_state_test_guard().await;
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        std::env::set_var("SGWC_SGWU_ADDR", up_addr.to_string());
        let node = SxaNode::open("127.0.0.1:0".parse().unwrap(), Ipv4Addr::LOCALHOST)
            .await
            .unwrap();
        let (stop, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(node.clone().run(rx));
        let setup = |seq: u32| {
            let mut body = BytesMut::new();
            AssociationSetupRequest::new(
                NodeId::new_ipv4([127, 0, 0, 9]),
                nextgcore_pfcp::recovery_time::now(),
            )
            .encode(&mut body);
            let mut out = BytesMut::new();
            let mut h = PfcpHeader::new(PfcpMessageType::AssociationSetupRequest, seq);
            h.length = (4 + body.len()) as u16;
            h.encode(&mut out);
            out.extend_from_slice(&body);
            out
        };
        async fn answer(sock: &UdpSocket) -> (PfcpHeader, AssociationSetupResponse) {
            let mut buf = [0u8; 512];
            let (len, _) =
                tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf))
                    .await
                    .expect("answered")
                    .unwrap();
            let mut cursor = Bytes::copy_from_slice(&buf[..len]);
            let header = PfcpHeader::decode(&mut cursor).unwrap();
            let rsp = AssociationSetupResponse::decode(&mut cursor).unwrap();
            (header, rsp)
        }

        // #1126: the response follows the recording. While the peer table is
        // held the SGW-C cannot record the association, so it must not answer.
        let held = node.peers.read().await;
        up.send_to(&setup(0x51), node.local_addr()).await.unwrap();
        let mut probe = [0u8; 512];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                up.recv_from(&mut probe)
            )
            .await
            .is_err(),
            "not answered before the association is recorded"
        );
        drop(held);
        let (header, rsp) = answer(&up).await;
        assert_eq!(
            header.message_type as u8,
            pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE
        );
        assert_eq!(header.sequence_number, 0x51);
        assert_eq!(rsp.cause, PfcpCause::RequestAccepted);
        assert_eq!(rsp.recovery_time_stamp, node.recovery_time_stamp);
        assert!(node.is_associated_with(up_addr).await, "recorded");
        assert_eq!(node.associated_peer_count(), 1);

        let stranger = UdpSocket::bind("127.0.0.2:0").await;
        if let Ok(stranger) = stranger {
            stranger
                .send_to(&setup(0x52), node.local_addr())
                .await
                .unwrap();
            let (_, rsp) = answer(&stranger).await;
            assert_eq!(rsp.cause, PfcpCause::RequestRejected, "not the SGW-U");
            assert_eq!(node.associated_peer_count(), 1);
        }
        std::env::remove_var("SGWC_SGWU_ADDR");
        let _ = stop.send(true);
    }

    /// #1014 / #1028 review, TS 29.244 §7.4.5.1 and §8.2.70 (Figure 8.2.70-1):
    /// a Node Report Request built byte by byte as an SGW-U sends it, not
    /// through the library's encoder. The Remote GTP-U Peer flags octet carries
    /// V4 as bit 2 (0x02), then the IPv4 address. The SGW-C reads 10.0.0.80 as
    /// the failed peer and releases the S1-U bearers toward it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_report_in_spec_bytes_releases_the_s1u_toward_its_ipv4_peer() {
        let guard = process_state_test_guard().await;
        crate::up_path::clear_for_test();
        let sgwu = assoc_sgwu(Vec::new()).await;
        let (node, stop) = associated_node(&guard, &sgwu).await;
        let (ue, bearer) = ue_toward(b"001010994000080", [10, 0, 0, 80]);
        let body: Vec<u8> = vec![
            0x00, 0x3c, 0x00, 0x05, 0x00, 127, 0, 0, 9, // Node ID (60): IPv4 127.0.0.9
            0x00, 0x65, 0x00, 0x01, 0x01, // Node Report Type (101): UPFR
            0x00, 0x66, 0x00, 0x09, // User Plane Path Failure Report (102), grouped:
            0x00, 0x67, 0x00, 0x05, 0x02, 10, 0, 0, 80, // Remote GTP-U Peer (103): V4
        ];
        let mut pdu = vec![0x20, 0x0c]; // version 1, no SEID; Node Report Request (12)
        pdu.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        pdu.extend_from_slice(&[0x00, 0x10, 0x14, 0x00]); // sequence 0x001014, spare
        pdu.extend_from_slice(&body);
        sgwu.sock.send_to(&pdu, node.local_addr()).await.unwrap();

        let responses = sgwu.node_report_responses.clone();
        eventually("the Node Report Response", || {
            !responses.lock().unwrap().is_empty()
        })
        .await;
        let (seq, rsp) = responses.lock().unwrap()[0].clone();
        assert_eq!(seq, 0x00_1014);
        assert_eq!(response_cause(&rsp).0, PfcpCause::RequestAccepted);
        eventually("the IPv4 peer recorded failed", || {
            crate::up_path::is_failed("10.0.0.80".parse().unwrap())
        })
        .await;
        let mods = sgwu.modifications.clone();
        eventually("the S1-U release", || !mods.lock().unwrap().is_empty()).await;
        assert_eq!(
            sgwc_self().dl_tunnel_in_bearer(bearer).unwrap().remote_teid,
            0
        );
        sgwc_self().ue_remove(ue);
        std::env::remove_var("SGWC_SGWU_ADDR");
        let _ = stop.send(true);
    }

    /// #1065 review: the V6 case of Figure 8.2.70-1 in spec bytes. The flags
    /// octet 0x01 (V6, bit 1) is followed by the 16 IPv6 octets. The SGW-C
    /// records that IPv6 peer as failed and releases the S1-U of the UE whose
    /// downlink goes to it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_report_in_spec_bytes_releases_the_s1u_toward_its_ipv6_peer() {
        let guard = process_state_test_guard().await;
        crate::up_path::clear_for_test();
        let sgwu = assoc_sgwu(Vec::new()).await;
        let (node, stop) = associated_node(&guard, &sgwu).await;
        let enb6: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x65,
        ];
        let ctx = sgwc_self();
        let (ue, bearer) = ue_toward(b"001010994000081", [10, 0, 0, 81]);
        let mut dl = ctx.dl_tunnel_in_bearer(bearer).unwrap();
        dl.remote_ip.ipv4 = None;
        dl.remote_ip.ipv6 = Some(std::net::Ipv6Addr::from(enb6));
        ctx.tunnel_update(&dl);
        let mut peer = vec![0x00, 0x67, 0x00, 0x11, 0x01]; // Remote GTP-U Peer (103): V6
        peer.extend_from_slice(&enb6);
        let mut body: Vec<u8> = vec![
            0x00, 0x3c, 0x00, 0x05, 0x00, 127, 0, 0, 9, // Node ID (60): IPv4 127.0.0.9
            0x00, 0x65, 0x00, 0x01, 0x01, // Node Report Type (101): UPFR
            0x00, 0x66, // User Plane Path Failure Report (102), grouped
        ];
        body.extend_from_slice(&(peer.len() as u16).to_be_bytes());
        body.extend_from_slice(&peer);
        let mut pdu = vec![0x20, 0x0c];
        pdu.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        pdu.extend_from_slice(&[0x00, 0x10, 0x65, 0x00]);
        pdu.extend_from_slice(&body);
        sgwu.sock.send_to(&pdu, node.local_addr()).await.unwrap();

        let responses = sgwu.node_report_responses.clone();
        eventually("the Node Report Response", || {
            !responses.lock().unwrap().is_empty()
        })
        .await;
        assert_eq!(
            response_cause(&responses.lock().unwrap()[0].1).0,
            PfcpCause::RequestAccepted
        );
        eventually("the IPv6 peer recorded failed", || {
            crate::up_path::is_failed(std::net::IpAddr::from(enb6))
        })
        .await;
        let mods = sgwu.modifications.clone();
        eventually("the S1-U release", || !mods.lock().unwrap().is_empty()).await;
        assert_eq!(ctx.dl_tunnel_in_bearer(bearer).unwrap().remote_teid, 0);
        assert!(
            !crate::up_path::is_failed("10.0.0.81".parse().unwrap()),
            "not read as an IPv4 peer"
        );
        ctx.ue_remove(ue);
        std::env::remove_var("SGWC_SGWU_ADDR");
        let _ = stop.send(true);
    }
}
