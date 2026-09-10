//! SGWU PFCP Path Management — the Sxa transaction engine (TS 29.244)
//!
//! Port of src/sgwu/pfcp-path.c, made real by issue #59: this module used to be
//! log-only, so the SGW-U had no PFCP wire presence at all.
//!
//! Responsibilities:
//! - bind UDP/8805 and serve a receive loop (TS 29.244 §4.1)
//! - decode inbound messages with the shared `nextgcore-pfcp` codec and dispatch
//!   them into `sxa_handler`, answering with `sxa_build`'s bodies
//! - Heartbeat in both directions, with Recovery Time Stamp comparison
//!   (TS 29.244 §6.2.2.2, TS 23.007 §19A)
//! - request/response transaction matching by sequence number, with T1
//!   retransmission up to N1 attempts (§7.2.1)
//! - peer-failure detection driving the FSM's restoration path, so a failed
//!   SGW-C's sessions are removed rather than left believed-in

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::{Bytes, BytesMut};
use nextgcore_pfcp::header::{PfcpHeader, PfcpMessageType};
use nextgcore_pfcp::message::{
    AssociationReleaseResponse, AssociationSetupRequest, AssociationSetupResponse,
    HeartbeatRequest, HeartbeatResponse, PfcpMessage as PfcpLibMessage,
    SessionEstablishmentRequest as LibSessionEstablishmentRequest,
    SessionModificationRequest as LibSessionModificationRequest,
};
use nextgcore_pfcp::types::{
    ApplyAction as LibApplyAction, CreateFar as LibCreateFar, CreatePdr as LibCreatePdr,
    CreateQer as LibCreateQer, CreateUrr as LibCreateUrr, FSeid as LibFSeid, FTeid as LibFTeid,
    GateStatus as LibGateStatus, NodeId, PfcpCause, UpFunctionFeatures as LibUpFunctionFeatures,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

use crate::context::{sgwu_self, SgwuSess};
use crate::event::SgwuEvent;
use crate::pfcp_sm::PfcpStateMachine;
use crate::sxa_build::{self, UserPlaneReport};
use crate::timer::SgwuTimerConfigs;

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

// ============================================================================
// Errors
// ============================================================================

/// Failure modes of an Sxa transaction (issue #59).
#[derive(Debug)]
pub enum PfcpRequestError {
    /// No response after N1 retransmissions — the peer is unreachable.
    Timeout { attempts: u32 },
    /// Local I/O or state error.
    Local(String),
}

impl std::fmt::Display for PfcpRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { attempts } => write!(f, "no PFCP response after {attempts} attempts"),
            Self::Local(e) => write!(f, "local PFCP error: {e}"),
        }
    }
}

impl std::error::Error for PfcpRequestError {}

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
// Sxa PFCP transport (issue #59)
// ============================================================================
//
// Before #59 this module was log-only: `pfcp_open` printed "In actual
// implementation: Create UDP sockets for PFCP (port 8805)" and bound nothing,
// both send helpers returned `Ok(())` without touching a socket, and
// `handle_pfcp_recv` read `data[1]` and match-dispatched on the message-type byte
// without decoding a single IE. Together with a `main()` that fell through to
// cleanup, the SGW-U could not answer a Heartbeat (TS 29.244 §6.2.2.2 makes that
// mandatory), could not process a Session Establishment on Sxa, and could not
// detect a peer restart — while the deployment reported it healthy.
//
// The wire codec is `nextgcore-pfcp` (already a dependency), not a second
// hand-rolled one: `PfcpHeader` for the header in both directions, and the
// library message decoders for the bodies. `sxa_build`'s response bodies are kept
// — they are flat TLV IE sequences, which is what a PFCP message body IS; what was
// missing was the header, the socket and the dispatch.

/// Sequence numbers are 3 octets (TS 29.244 §7.2.2).
const SEQ_MASK: u32 = 0x00FF_FFFF;

/// The standard PFCP port (TS 29.244 §4.1).
pub const PFCP_PORT: u16 = 8805;

/// How many consecutive unanswered Heartbeat Requests mean the peer is gone.
///
/// TS 23.007 §19A requires heartbeat-driven peer-failure detection but fixes no
/// count; three misses at the `no_heartbeat` interval is the same shape upfd uses,
/// and it is deliberately more than one so a single lost datagram cannot flush a
/// live peer's sessions.
const HEARTBEAT_MISSES_BEFORE_FAILURE: u32 = 3;

/// One SGW-C peer as seen from the SGW-U.
#[derive(Debug, Clone)]
pub struct SxaPeer {
    /// The PFCP node id sessions are tagged with, so a peer failure can find them.
    pub node_id: u64,
    pub addr: SocketAddr,
    pub state: PfcpNodeState,
    /// The peer's Recovery Time Stamp; a change means it restarted (TS 23.007).
    pub recovery_time_stamp: Option<u32>,
    /// CP Function Features the peer advertised at association.
    pub cp_function_features: CpFunctionFeatures,
    /// Consecutive Heartbeat Requests this peer has not answered.
    pub missed_heartbeats: u32,
    /// This peer's PFCP FSM, driven from the live path (issue #59).
    ///
    /// Before #59 `PfcpStateMachine` was reachable only from its own unit tests, so
    /// its `pfcp_restoration` hook -- the one thing that removes a failed CP's
    /// sessions -- could never run in a deployment. It is held per peer here and
    /// driven by the transport, which is what makes criterion 5's "verified reachable
    /// from the running daemon" true rather than asserted.
    pub fsm: PfcpStateMachine,
}

/// An outbound PFCP request queued by a synchronous caller (issue #59).
///
/// `gtp_path` is the data path and runs on OS threads with a blocking socket, so
/// it cannot await. It still has to be able to send a Session Report Request — that
/// is the whole point of a Downlink Data Report — so the sync API enqueues here and
/// the async node performs the I/O with T1/N1 retransmission. The alternative,
/// making the data path async, is a far larger change than this issue and would put
/// a per-packet executor in front of user-plane forwarding.
struct QueuedRequest {
    msg_type: u8,
    seid: u64,
    body: Vec<u8>,
    to: SocketAddr,
    sess_id: u64,
}

static OUTBOUND: OnceLock<mpsc::UnboundedSender<QueuedRequest>> = OnceLock::new();

/// The running Sxa node, so the sync API can resolve a peer and the metrics
/// endpoint can report association state.
static SXA_NODE: OnceLock<Arc<SxaNode>> = OnceLock::new();

/// PFCP node ids, unique for the whole PROCESS rather than per `SxaNode`.
///
/// Sessions are tagged with a node id and the session store is process-global, so
/// per-node numbering would let two nodes both mint id 1 — and
/// `sess_remove_all_for_pfcp_node(1)` would then remove the other node's sessions.
/// A running daemon has one node, so this only matters where several exist at once
/// (the transport tests), which is exactly where the collision would be silent.
static NEXT_NODE_ID: AtomicU32 = AtomicU32::new(1);

/// The process-wide Sxa node, once [`SxaNode::open`] has run.
pub fn sxa_node() -> Option<Arc<SxaNode>> {
    SXA_NODE.get().cloned()
}

/// The SGW-U's PFCP endpoint on Sxa: one UDP socket, transactions matched on
/// sequence number, peers tracked for heartbeat-driven failure detection.
pub struct SxaNode {
    socket: Arc<UdpSocket>,
    /// The address this node puts in its own Node ID IE.
    local_ip: Ipv4Addr,
    /// Our Recovery Time Stamp (seconds since the epoch at startup), reported in
    /// every Association Setup Response and Heartbeat (TS 29.244 §8.2.65).
    pub recovery_time_stamp: u32,
    seq: AtomicU32,
    pending: Mutex<HashMap<u32, oneshot::Sender<(u8, Vec<u8>)>>>,
    peers: RwLock<HashMap<SocketAddr, SxaPeer>>,
    /// Associated-peer count, readable without awaiting.
    ///
    /// A derived mirror of `peers`, and deliberately a small one: the metrics
    /// endpoint's render closure is synchronous (`Fn() -> String`), so it cannot take
    /// the async `RwLock`. Updated by [`Self::refresh_peer_gauge`] immediately after
    /// every mutation of `peers`, which is the only way the two can disagree.
    associated_peers: std::sync::atomic::AtomicUsize,
    timers: SgwuTimerConfigs,
}

impl SxaNode {
    /// Bind the Sxa PFCP socket and install the process-wide node.
    ///
    /// Binding is what `pfcp_open` claimed to do and did not. The bound address is
    /// returned so a test can drive a real exchange against an ephemeral port.
    pub async fn open(bind: SocketAddr, local_ip: Ipv4Addr) -> std::io::Result<Arc<Self>> {
        Self::open_with_timers(bind, local_ip, SgwuTimerConfigs::default()).await
    }

    /// [`Self::open`] with an explicit timer configuration.
    ///
    /// Exists so a test can assert T1 retransmission without waiting the configured
    /// 10-second interval three times over — the alternative was a 20-second test,
    /// which is a fifth of this crate's whole suite spent proving one timer.
    pub async fn open_with_timers(
        bind: SocketAddr,
        local_ip: Ipv4Addr,
        timers: SgwuTimerConfigs,
    ) -> std::io::Result<Arc<Self>> {
        let socket = UdpSocket::bind(bind).await?;
        let bound = socket.local_addr()?;
        let recovery_time_stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(1);
        let node = Arc::new(Self {
            socket: Arc::new(socket),
            local_ip,
            recovery_time_stamp,
            seq: AtomicU32::new(1),
            pending: Mutex::new(HashMap::new()),
            peers: RwLock::new(HashMap::new()),
            associated_peers: std::sync::atomic::AtomicUsize::new(0),
            timers,
        });
        log::info!(
            "PFCP/Sxa listening on {bound} (Node ID {local_ip}, Recovery Time Stamp \
             {recovery_time_stamp})"
        );
        let _ = SXA_NODE.set(node.clone());
        Ok(node)
    }

    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// A snapshot of the peers, for the metrics endpoint and for tests.
    pub async fn peers(&self) -> Vec<SxaPeer> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Whether any peer is associated (TS 29.244 §6.2.6.2: no session signalling
    /// without one). This is what the container health probe asks about.
    pub async fn is_associated(&self) -> bool {
        self.peers
            .read()
            .await
            .values()
            .any(|p| p.state == PfcpNodeState::Associated)
    }

    /// Associated peers, readable from a synchronous context (the metrics render).
    pub fn associated_peer_count(&self) -> usize {
        self.associated_peers.load(Ordering::Relaxed)
    }

    /// Recompute the sync gauge from the authoritative map. Called under, or right
    /// after, every `peers` mutation.
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

    /// Encode and send one datagram. The only place a PFCP byte leaves this
    /// daemon, so every message shares one header encoder.
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
        // The length field covers everything after the first 4 octets (TS 29.244
        // §7.2.2.1): the SEID when present, the 3-octet sequence number, the spare
        // octet, and the IE payload.
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

    /// Send a request and wait for its response, retransmitting on T1 expiry up to
    /// N1 attempts (TS 29.244 §7.2.1).
    ///
    /// This is what `send_pfcp_request`'s "In actual implementation: create local
    /// transaction, set timeout callback, send message" comment described.
    pub async fn request(
        &self,
        msg_type: u8,
        seid: u64,
        body: &[u8],
        to: SocketAddr,
    ) -> Result<(u8, Vec<u8>), PfcpRequestError> {
        let seq = self.alloc_seq();
        // The `no_heartbeat` interval doubles as T1 and its `max_count` as N1: it is
        // the only retransmission budget this daemon is configured with, and using
        // it keeps one knob rather than inventing a second.
        let t1 = self.timers.no_heartbeat.duration;
        let n1 = self.timers.no_heartbeat.max_count.max(2);
        let max_attempts = n1 + 1;
        let mut attempt = 0u32;

        loop {
            attempt += 1;
            let (tx, rx) = oneshot::channel();
            self.pending.lock().await.insert(seq, tx);

            if let Err(e) = self.send(msg_type, Some(seid), seq, body, to).await {
                self.pending.lock().await.remove(&seq);
                return Err(PfcpRequestError::Local(e));
            }
            if attempt > 1 {
                log::warn!(
                    "PFCP T1 expired: retransmitting type={msg_type} seq={seq} to {to} \
                     (attempt {attempt}/{max_attempts})"
                );
            }

            match tokio::time::timeout(t1, rx).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(_)) => {
                    return Err(PfcpRequestError::Local("response channel closed".into()))
                }
                Err(_) => {
                    self.pending.lock().await.remove(&seq);
                    if attempt >= max_attempts {
                        log::error!(
                            "PFCP request type={msg_type} seq={seq} exhausted {max_attempts} \
                             attempts — peer {to} unreachable"
                        );
                        return Err(PfcpRequestError::Timeout {
                            attempts: max_attempts,
                        });
                    }
                }
            }
        }
    }

    /// The Sxa receive loop. Runs until the socket dies or `shutdown` fires.
    ///
    /// Also drains the outbound queue the synchronous data path enqueues on, so one
    /// task owns the socket and no lock is shared with `gtp_path`'s threads.
    pub async fn run(self: Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let (tx, mut queued) = mpsc::unbounded_channel();
        if OUTBOUND.set(tx).is_err() {
            log::warn!("PFCP outbound queue already installed; this run() will not drain it");
        }
        let mut buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buf) => match received {
                    Ok((len, from)) => {
                        let datagram = buf[..len].to_vec();
                        let node = self.clone();
                        // Handled inline rather than spawned: PFCP session state is
                        // per-peer ordered, and a spawn would let a Deletion overtake
                        // the Establishment it deletes.
                        node.on_datagram(&datagram, from).await;
                    }
                    Err(e) => {
                        log::error!("PFCP receive failed: {e}");
                        break;
                    }
                },
                Some(req) = queued.recv() => {
                    let node = self.clone();
                    // Spawned: a request awaits T1 x N1, and blocking the receive loop
                    // for that long would stall every inbound message including the
                    // response this request is waiting for.
                    tokio::spawn(async move {
                        match node.request(req.msg_type, req.seid, &req.body, req.to).await {
                            Ok((resp_type, body)) => {
                                sess_report_response_received(req.sess_id, resp_type, &body);
                            }
                            Err(e) => log::error!(
                                "PFCP request type={} for session {} failed: {e}",
                                req.msg_type,
                                req.sess_id
                            ),
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
    pub async fn on_datagram(&self, pkt: &[u8], from: SocketAddr) {
        // The version is read off octet 1 BEFORE decoding, because the library's
        // decoder refuses a version it does not support -- so a check after `decode`
        // could never fire, and TS 29.244 §7.2.2.1 requires the answer rather than a
        // drop. The sequence number is read the same way for the same reason: the
        // response has to echo it, and the decode that would have produced it failed.
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

        // Responses complete the transaction that is waiting for them.
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
            pfcp_msg_type::HEARTBEAT_REQUEST => {
                self.handle_heartbeat_request(&header, &body, from).await;
            }
            pfcp_msg_type::ASSOCIATION_SETUP_REQUEST => {
                self.handle_association_setup_request(&header, &body, from)
                    .await;
            }
            pfcp_msg_type::ASSOCIATION_RELEASE_REQUEST => {
                self.handle_association_release_request(&header, from).await;
            }
            pfcp_msg_type::SESSION_ESTABLISHMENT_REQUEST => {
                self.handle_session_establishment_request(&header, &body, from)
                    .await;
            }
            pfcp_msg_type::SESSION_MODIFICATION_REQUEST => {
                self.handle_session_modification_request(&header, &body, from)
                    .await;
            }
            pfcp_msg_type::SESSION_DELETION_REQUEST => {
                self.handle_session_deletion_request(&header, from).await;
            }
            other => {
                log::warn!("PFCP message type {other} from {from} is not handled on Sxa");
            }
        }
    }

    /// TS 29.244 §6.2.2.2: "a UP function shall be prepared to receive a Heartbeat
    /// Request at any time ... and it shall reply with a Heartbeat Response."
    ///
    /// The peer's Recovery Time Stamp is compared on the way through: a change means
    /// the SGW-C restarted and holds none of the sessions we do (TS 23.007 §19A).
    async fn handle_heartbeat_request(&self, header: &PfcpHeader, body: &[u8], from: SocketAddr) {
        let mut cursor = Bytes::copy_from_slice(body);
        match HeartbeatRequest::decode(&mut cursor) {
            Ok(req) => {
                self.note_peer_recovery_time_stamp(from, req.recovery_time_stamp)
                    .await
            }
            Err(e) => log::warn!("Heartbeat Request from {from} is malformed: {e}"),
        }
        let mut buf = BytesMut::new();
        PfcpLibMessage::HeartbeatResponse(HeartbeatResponse::new(self.recovery_time_stamp))
            .encode_body(&mut buf);
        if let Err(e) = self
            .send(
                pfcp_msg_type::HEARTBEAT_RESPONSE,
                None,
                header.sequence_number,
                &buf,
                from,
            )
            .await
        {
            log::warn!("Failed to answer Heartbeat Request from {from}: {e}");
        }
    }

    /// TS 29.244 §6.2.6: accept the association and report what this UP function
    /// supports. The peer is recorded here, which is what makes every later session
    /// attributable to a node — and therefore removable when that node fails.
    async fn handle_association_setup_request(
        &self,
        header: &PfcpHeader,
        body: &[u8],
        from: SocketAddr,
    ) {
        let mut cursor = Bytes::copy_from_slice(body);
        let req = match AssociationSetupRequest::decode(&mut cursor) {
            Ok(req) => req,
            Err(e) => {
                log::warn!("Association Setup Request from {from} is malformed: {e}");
                let mut buf = BytesMut::new();
                PfcpLibMessage::AssociationSetupResponse(AssociationSetupResponse::new(
                    NodeId::new_ipv4(self.local_ip.octets()),
                    PfcpCause::MandatoryIeMissing,
                    self.recovery_time_stamp,
                ))
                .encode_body(&mut buf);
                let _ = self
                    .send(
                        pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE,
                        None,
                        header.sequence_number,
                        &buf,
                        from,
                    )
                    .await;
                return;
            }
        };

        let restarted = {
            let mut peers = self.peers.write().await;
            let next_id = NEXT_NODE_ID.fetch_add(1, Ordering::SeqCst) as u64;
            let peer = peers.entry(from).or_insert_with(|| {
                let mut fsm = PfcpStateMachine::new(next_id);
                fsm.set_node_addr(&from.to_string());
                SxaPeer {
                    node_id: next_id,
                    addr: from,
                    state: PfcpNodeState::Initial,
                    recovery_time_stamp: None,
                    cp_function_features: CpFunctionFeatures::default(),
                    missed_heartbeats: 0,
                    fsm,
                }
            });
            let restarted = matches!(peer.recovery_time_stamp, Some(stored) if stored != req.recovery_time_stamp);
            peer.state = PfcpNodeState::Associated;
            peer.recovery_time_stamp = Some(req.recovery_time_stamp);
            peer.missed_heartbeats = 0;
            // Drive the FSM the same way the association just went on the wire:
            // Initial -> WillAssociate -> Associated. Keeping it in step is what lets
            // the failure path below reach `pfcp_restoration` through the FSM rather
            // than around it.
            if !peer.fsm.is_associated() {
                peer.fsm.dispatch(&SgwuEvent::entry());
                peer.fsm.dispatch(&SgwuEvent::sxa_message(
                    peer.node_id,
                    0,
                    vec![pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE],
                ));
            }
            if let Some(features) = req.cp_function_features.as_ref() {
                peer.cp_function_features = CpFunctionFeatures {
                    load: features.load,
                    ovrl: features.ovrl,
                };
            }
            log::info!(
                "PFCP association established with {from} (node {}, peer RTS={})",
                peer.node_id,
                req.recovery_time_stamp
            );
            restarted.then_some(peer.node_id)
        };
        // A re-association from a restarted CP means it holds none of the sessions we
        // do (TS 23.007 §19A). Flushing them is the restoration path that existed only
        // as an FSM hook nothing could reach.
        if restarted.is_some() {
            log::error!(
                "SGW-C {from} restarted (Recovery Time Stamp changed): flushing its sessions"
            );
            self.run_restoration(from).await;
        }

        self.refresh_peer_gauge().await;

        let mut resp = AssociationSetupResponse::new(
            NodeId::new_ipv4(self.local_ip.octets()),
            PfcpCause::RequestAccepted,
            self.recovery_time_stamp,
        );
        // What this SGW-U genuinely does: it allocates F-TEIDs for the CP (FTUP) and
        // forwards End Markers. Everything else is honestly absent rather than
        // advertised — a UP function that claims BUCP and cannot buffer is worse than
        // one that claims nothing.
        resp.up_function_features = Some(LibUpFunctionFeatures {
            ftup: true,
            empu: true,
            ..Default::default()
        });
        let mut buf = BytesMut::new();
        PfcpLibMessage::AssociationSetupResponse(resp).encode_body(&mut buf);
        if let Err(e) = self
            .send(
                pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE,
                None,
                header.sequence_number,
                &buf,
                from,
            )
            .await
        {
            log::warn!("Failed to answer Association Setup Request from {from}: {e}");
        }
    }

    /// TS 29.244 §6.2.9: acknowledge, then drop the peer and its sessions.
    async fn handle_association_release_request(&self, header: &PfcpHeader, from: SocketAddr) {
        let mut buf = BytesMut::new();
        PfcpLibMessage::AssociationReleaseResponse(AssociationReleaseResponse::new(
            NodeId::new_ipv4(self.local_ip.octets()),
            PfcpCause::RequestAccepted,
        ))
        .encode_body(&mut buf);
        let _ = self
            .send(
                pfcp_msg_type::ASSOCIATION_RELEASE_RESPONSE,
                None,
                header.sequence_number,
                &buf,
                from,
            )
            .await;
        self.declare_peer_failure(from, "association released by peer")
            .await;
    }

    /// Record a peer's Recovery Time Stamp, flushing its sessions if it changed.
    async fn note_peer_recovery_time_stamp(&self, from: SocketAddr, rts: u32) {
        let restarted = {
            let mut peers = self.peers.write().await;
            let Some(peer) = peers.get_mut(&from) else {
                // A heartbeat from a node we never associated with: answered (the spec
                // says answer at any time) but not tracked.
                return;
            };
            peer.missed_heartbeats = 0;
            let restarted = matches!(peer.recovery_time_stamp, Some(stored) if stored != rts)
                .then_some(peer.node_id);
            peer.recovery_time_stamp = Some(rts);
            restarted
        };
        if restarted.is_some() {
            log::error!("SGW-C {from} restarted (Recovery Time Stamp changed to {rts})");
            self.run_restoration(from).await;
        }
    }

    /// Run the FSM restoration for a peer that is STAYING associated (a restart
    /// detected on a heartbeat or a re-association): its sessions are gone on the CP
    /// side, but the peer itself is still there to talk to.
    async fn run_restoration(&self, from: SocketAddr) {
        let mut peers = self.peers.write().await;
        let Some(peer) = peers.get_mut(&from) else {
            return;
        };
        let before = sgwu_self().sess_count();
        peer.fsm.set_restoration_required(true);
        peer.fsm.dispatch(&SgwuEvent::entry());
        let after = sgwu_self().sess_count();
        log::warn!(
            "PFCP restoration for {from}: {} session(s) removed",
            before.saturating_sub(after)
        );
    }

    /// Mark a peer down and remove every session it owned.
    ///
    /// This is the call the FSM's `pfcp_restoration` hook made from a state machine
    /// nothing drove. It is reachable from the running daemon now: from a heartbeat
    /// that went unanswered N times, from an Association Release, and from a peer
    /// whose Recovery Time Stamp changed.
    pub async fn declare_peer_failure(&self, from: SocketAddr, reason: &str) {
        let mut peer = {
            let mut peers = self.peers.write().await;
            match peers.remove(&from) {
                Some(peer) => peer,
                None => return,
            }
        };
        let before = sgwu_self().sess_count();
        // Through the FSM, not around it: in the Associated state an FSM entry with
        // `restoration_required` set runs `pfcp_restoration`, which is the call that
        // invokes `sess_remove_all_for_pfcp_node`. That hook existed and was reachable
        // only from unit tests; this is the path that makes it run in the daemon.
        peer.fsm.set_restoration_required(true);
        peer.fsm.dispatch(&SgwuEvent::entry());
        peer.fsm
            .dispatch(&SgwuEvent::sxa_no_heartbeat(peer.node_id));
        let after = sgwu_self().sess_count();
        self.refresh_peer_gauge().await;
        log::warn!(
            "PFCP peer {from} declared down ({reason}); {} session(s) removed",
            before.saturating_sub(after)
        );
    }

    /// Heartbeat monitor: probe every associated peer and fail the ones that stop
    /// answering (TS 29.244 §6.2.2, TS 23.007 §19A).
    pub async fn heartbeat_monitor(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let interval = self.timers.no_heartbeat.duration;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
            }
            let peers: Vec<SocketAddr> = self
                .peers
                .read()
                .await
                .values()
                .filter(|p| p.state == PfcpNodeState::Associated)
                .map(|p| p.addr)
                .collect();
            for peer in peers {
                let mut buf = BytesMut::new();
                PfcpLibMessage::HeartbeatRequest(HeartbeatRequest::new(self.recovery_time_stamp))
                    .encode_body(&mut buf);
                let seq = self.alloc_seq();
                let (tx, rx) = oneshot::channel();
                self.pending.lock().await.insert(seq, tx);
                if let Err(e) = self
                    .send(pfcp_msg_type::HEARTBEAT_REQUEST, None, seq, &buf, peer)
                    .await
                {
                    log::warn!("Heartbeat to {peer} could not be sent: {e}");
                }
                let answered = tokio::time::timeout(interval, rx).await.is_ok();
                self.pending.lock().await.remove(&seq);
                if answered {
                    continue;
                }
                let missed = {
                    let mut peers = self.peers.write().await;
                    match peers.get_mut(&peer) {
                        Some(p) => {
                            p.missed_heartbeats += 1;
                            p.missed_heartbeats
                        }
                        None => continue,
                    }
                };
                log::warn!(
                    "No Heartbeat Response from {peer} ({missed}/{HEARTBEAT_MISSES_BEFORE_FAILURE})"
                );
                if missed >= HEARTBEAT_MISSES_BEFORE_FAILURE {
                    self.declare_peer_failure(peer, "no heartbeat response")
                        .await;
                }
            }
        }
    }
}

// ============================================================================
// Inbound session messages: decode → sxa_handler → encoded response
// ============================================================================

impl SxaNode {
    /// TS 29.244 Table 7.5.2.1-1, dispatched into `sxa_handler`.
    ///
    /// The session is created here (the CP F-SEID is what identifies it) and tagged
    /// with the peer's node id — without that tag `sess_remove_all_for_pfcp_node`
    /// matches nothing, so the restoration path would have removed zero sessions even
    /// once it became reachable.
    async fn handle_session_establishment_request(
        &self,
        header: &PfcpHeader,
        body: &[u8],
        from: SocketAddr,
    ) {
        let mut cursor = Bytes::copy_from_slice(body);
        let req = match LibSessionEstablishmentRequest::decode(&mut cursor) {
            Ok(req) => req,
            Err(e) => {
                log::error!("Session Establishment Request from {from} is malformed: {e}");
                self.reply_error(
                    header,
                    pfcp_msg_type::SESSION_ESTABLISHMENT_RESPONSE,
                    header.seid.unwrap_or(0),
                    sxa_build::pfcp_cause::MANDATORY_IE_MISSING,
                    from,
                )
                .await;
                return;
            }
        };

        let node_id = self.peers.read().await.get(&from).map(|p| p.node_id);
        let cp_f_seid = f_seid_from_lib(&req.cp_f_seid);
        let ctx = sgwu_self();
        let sess = match ctx.sess_find_by_sgwc_sxa_seid(cp_f_seid.seid) {
            // A repeated Establishment for a CP F-SEID we already hold is the CP
            // retransmitting: answer from the existing session rather than allocating a
            // second one for the same UE.
            Some(existing) => existing,
            None => match ctx.sess_add(&cp_f_seid) {
                Some(mut sess) => {
                    sess.pfcp_node_id = node_id;
                    ctx.sess_update(&sess);
                    sess
                }
                None => {
                    log::error!(
                        "Cannot add SGW-U session for CP F-SEID 0x{:x}",
                        cp_f_seid.seid
                    );
                    self.reply_error(
                        header,
                        pfcp_msg_type::SESSION_ESTABLISHMENT_RESPONSE,
                        cp_f_seid.seid,
                        sxa_build::pfcp_cause::NO_RESOURCES_AVAILABLE,
                        from,
                    )
                    .await;
                    return;
                }
            },
        };

        let parsed = establishment_from_lib(&req, &cp_f_seid);
        let (result, created_pdrs) =
            crate::sxa_handler::handle_session_establishment_request(Some(&sess), 0, &parsed);
        // Re-read: the handler installs PDRs/FARs/QERs/URRs on the stored session.
        let sess = ctx.sess_find_by_id(sess.id).unwrap_or(sess);
        match result {
            crate::sxa_handler::HandlerResult::Error(cause) => {
                self.reply_error(
                    header,
                    pfcp_msg_type::SESSION_ESTABLISHMENT_RESPONSE,
                    cp_f_seid.seid,
                    cause,
                    from,
                )
                .await;
            }
            _ => {
                let Some(msg) =
                    sxa_build::build_session_establishment_response(&sess, &created_pdrs)
                else {
                    log::error!("Failed to build Session Establishment Response");
                    return;
                };
                let _ = self
                    .send(
                        msg.msg_type,
                        Some(msg.seid),
                        header.sequence_number,
                        &msg.data,
                        from,
                    )
                    .await;
            }
        }
    }

    /// TS 29.244 Table 7.5.4.1-1.
    async fn handle_session_modification_request(
        &self,
        header: &PfcpHeader,
        body: &[u8],
        from: SocketAddr,
    ) {
        let mut cursor = Bytes::copy_from_slice(body);
        let req = match LibSessionModificationRequest::decode(&mut cursor) {
            Ok(req) => req,
            Err(e) => {
                log::error!("Session Modification Request from {from} is malformed: {e}");
                self.reply_error(
                    header,
                    pfcp_msg_type::SESSION_MODIFICATION_RESPONSE,
                    header.seid.unwrap_or(0),
                    sxa_build::pfcp_cause::MANDATORY_IE_MISSING,
                    from,
                )
                .await;
                return;
            }
        };
        let ctx = sgwu_self();
        // The SEID in the header is OUR SEID (the one we gave the CP at
        // establishment), which is how TS 29.244 §7.2.2.4.2 addresses an existing
        // session.
        let Some(sess) = header
            .seid
            .and_then(|seid| ctx.sess_find_by_sgwu_sxa_seid(seid))
        else {
            log::warn!(
                "Session Modification for unknown SEID {:?} from {from}",
                header.seid
            );
            self.reply_error(
                header,
                pfcp_msg_type::SESSION_MODIFICATION_RESPONSE,
                header.seid.unwrap_or(0),
                sxa_build::pfcp_cause::SESSION_CONTEXT_NOT_FOUND,
                from,
            )
            .await;
            return;
        };
        let parsed = modification_from_lib(&req);
        let (result, created_pdrs) =
            crate::sxa_handler::handle_session_modification_request(Some(&sess), 0, &parsed);
        let sess = ctx.sess_find_by_id(sess.id).unwrap_or(sess);
        match result {
            crate::sxa_handler::HandlerResult::Error(cause) => {
                self.reply_error(
                    header,
                    pfcp_msg_type::SESSION_MODIFICATION_RESPONSE,
                    sess.sgwc_sxa_f_seid.seid,
                    cause,
                    from,
                )
                .await;
            }
            _ => {
                let Some(msg) =
                    sxa_build::build_session_modification_response(&sess, &created_pdrs)
                else {
                    log::error!("Failed to build Session Modification Response");
                    return;
                };
                let _ = self
                    .send(
                        msg.msg_type,
                        Some(msg.seid),
                        header.sequence_number,
                        &msg.data,
                        from,
                    )
                    .await;
            }
        }
    }

    /// TS 29.244 Table 7.5.6.1-1: no IEs in the request; the response carries the
    /// final Usage Reports, which `send_session_deletion_response` drains BEFORE the
    /// session is removed (#215).
    async fn handle_session_deletion_request(&self, header: &PfcpHeader, from: SocketAddr) {
        let ctx = sgwu_self();
        let Some(sess) = header
            .seid
            .and_then(|seid| ctx.sess_find_by_sgwu_sxa_seid(seid))
        else {
            log::warn!(
                "Session Deletion for unknown SEID {:?} from {from}",
                header.seid
            );
            self.reply_error(
                header,
                pfcp_msg_type::SESSION_DELETION_RESPONSE,
                header.seid.unwrap_or(0),
                sxa_build::pfcp_cause::SESSION_CONTEXT_NOT_FOUND,
                from,
            )
            .await;
            return;
        };
        let result = crate::sxa_handler::handle_session_deletion_request(Some(&sess), 0);
        if let crate::sxa_handler::HandlerResult::Error(cause) = result {
            self.reply_error(
                header,
                pfcp_msg_type::SESSION_DELETION_RESPONSE,
                sess.sgwc_sxa_f_seid.seid,
                cause,
                from,
            )
            .await;
            return;
        }
        // Drain the usage reports and build the response BEFORE removing the session:
        // `sess_remove` discards URRs, so collecting afterwards always reports nothing.
        let usage_reports = crate::sxa_handler::take_final_usage_reports(sess.id);
        let msg = sxa_build::build_session_deletion_response(&sess, &usage_reports);
        ctx.sess_remove(sess.id);
        if let Some(msg) = msg {
            let _ = self
                .send(
                    msg.msg_type,
                    Some(msg.seid),
                    header.sequence_number,
                    &msg.data,
                    from,
                )
                .await;
        }
    }

    /// A response carrying only a Cause (and an Offending IE when one is known).
    async fn reply_error(
        &self,
        header: &PfcpHeader,
        msg_type: u8,
        seid: u64,
        cause: u8,
        to: SocketAddr,
    ) {
        let mut body = Vec::new();
        body.extend_from_slice(&19u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.push(cause);
        if let Err(e) = self
            .send(msg_type, Some(seid), header.sequence_number, &body, to)
            .await
        {
            log::warn!("Failed to send PFCP error response to {to}: {e}");
        }
    }
}

// ============================================================================
// Library type → sxa_handler type mapping
// ============================================================================

/// The CP F-SEID as this crate models it (`{ seid, ip }`).
///
/// A CP F-SEID with neither address present is not addressable — nothing can send it
/// a Session Report — so it is recorded loudly rather than silently mapped to an
/// unspecified address that would look routable.
fn f_seid_from_lib(f_seid: &LibFSeid) -> crate::context::FSeid {
    match (f_seid.ipv4_addr, f_seid.ipv6_addr) {
        (Some(v4), _) => crate::context::FSeid::with_ipv4(f_seid.seid, Ipv4Addr::from(v4)),
        (None, Some(v6)) => {
            crate::context::FSeid::with_ipv6(f_seid.seid, std::net::Ipv6Addr::from(v6))
        }
        (None, None) => {
            log::warn!(
                "CP F-SEID 0x{:x} carries no address: this session cannot be sent a \
                 Session Report Request",
                f_seid.seid
            );
            crate::context::FSeid::with_ipv4(f_seid.seid, Ipv4Addr::UNSPECIFIED)
        }
    }
}

/// TS 29.244 §8.2.26: Apply Action bits — DROP, FORW, BUFF, NOCP, DUPL.
///
/// Encoded here because the library models the IE as booleans and the SGW-U's rule
/// store keeps the packed octet (which is what the data path matches on).
fn apply_action_octet(action: &LibApplyAction) -> u8 {
    (action.drop as u8)
        | ((action.forw as u8) << 1)
        | ((action.buff as u8) << 2)
        | ((action.nocp as u8) << 3)
        | ((action.dupl as u8) << 4)
}

/// TS 29.244 §8.2.7: bits 1-2 are the UL gate and bits 3-4 the DL gate, each
/// `0` = OPEN and `1` = CLOSED — the packing `SgwuQer.gate_status` documents. The
/// library models the two as `true` = open, so both are inverted here.
fn gate_status_octet(gate: &LibGateStatus) -> u8 {
    ((!gate.ul_gate) as u8) | (((!gate.dl_gate) as u8) << 2)
}

/// Scan a flat TLV body for the Cause IE (type 19).
fn find_cause(body: &[u8]) -> Option<u8> {
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let ie_type = u16::from_be_bytes([body[off], body[off + 1]]);
        let len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        let start = off + 4;
        let end = start + len;
        if end > body.len() {
            return None;
        }
        if ie_type == 19 {
            return body.get(start).copied();
        }
        off = end;
    }
    None
}

fn f_teid_from_lib(f_teid: &LibFTeid) -> crate::sxa_handler::FTeidRequest {
    crate::sxa_handler::FTeidRequest {
        ch: f_teid.ch,
        teid: f_teid.teid,
        ipv4: f_teid.ipv4_addr.map(Ipv4Addr::from),
        ipv6: f_teid.ipv6_addr.map(std::net::Ipv6Addr::from),
    }
}

fn pdr_from_lib(pdr: &LibCreatePdr) -> crate::sxa_handler::CreatePdrRequest {
    crate::sxa_handler::CreatePdrRequest {
        pdr_id: pdr.pdr_id,
        precedence: pdr.precedence,
        pdi: Some(crate::sxa_handler::PdiRequest {
            source_interface: pdr.pdi.source_interface as u8,
            local_f_teid: pdr.pdi.local_f_teid.as_ref().map(f_teid_from_lib),
            network_instance: pdr.pdi.network_instance.clone(),
            ue_ip_address: pdr.pdi.ue_ip_address.as_ref().map(|ue| {
                crate::sxa_handler::UeIpAddress {
                    ipv4: ue.ipv4_addr.map(Ipv4Addr::from),
                    ipv6: ue.ipv6_addr.map(std::net::Ipv6Addr::from),
                }
            }),
        }),
        outer_header_removal: pdr
            .outer_header_removal
            .as_ref()
            .map(|ohr| ohr.description as u8),
        far_id: pdr.far_id,
        qer_id: pdr.qer_id,
        urr_ids: pdr.urr_ids.clone(),
    }
}

fn far_from_lib(far: &LibCreateFar) -> crate::sxa_handler::CreateFarRequest {
    crate::sxa_handler::CreateFarRequest {
        far_id: far.far_id,
        apply_action: apply_action_octet(&far.apply_action),
        forwarding_parameters: far.forwarding_parameters.as_ref().map(|fp| {
            crate::sxa_handler::ForwardingParameters {
                destination_interface: fp.destination_interface as u8,
                outer_header_creation: fp.outer_header_creation.as_ref().map(|ohc| {
                    crate::sxa_handler::OuterHeaderCreation {
                        teid: ohc.teid.unwrap_or(0),
                        ipv4: ohc.ipv4_addr.map(Ipv4Addr::from),
                        ipv6: ohc.ipv6_addr.map(std::net::Ipv6Addr::from),
                    }
                }),
            }
        }),
    }
}

fn qer_from_lib(qer: &LibCreateQer) -> crate::sxa_handler::CreateQerRequest {
    crate::sxa_handler::CreateQerRequest {
        qer_id: qer.qer_id,
        gate_status: Some(gate_status_octet(&qer.gate_status)),
        mbr: qer
            .maximum_bitrate
            .as_ref()
            .map(|br| crate::sxa_handler::Mbr {
                ul: br.uplink,
                dl: br.downlink,
            }),
        gbr: qer
            .guaranteed_bitrate
            .as_ref()
            .map(|br| crate::sxa_handler::Gbr {
                ul: br.uplink,
                dl: br.downlink,
            }),
    }
}

fn urr_from_lib(urr: &LibCreateUrr) -> crate::sxa_handler::CreateUrrRequest {
    let volume = |v: Option<&nextgcore_pfcp::types::VolumeThreshold>| {
        v.map(|v| crate::context::Volume {
            total: v.tovol.then_some(v.total_volume),
            uplink: v.ulvol.then_some(v.uplink_volume),
            downlink: v.dlvol.then_some(v.downlink_volume),
        })
        .unwrap_or_default()
    };
    crate::sxa_handler::CreateUrrRequest {
        urr_id: urr.urr_id,
        measurement_method: urr.measurement_method.encode(),
        // The handler models the first TWO octets of Reporting Triggers (§8.2.41)
        // as a u16 with octet 5 in the low byte; the library encodes all three.
        reporting_triggers: {
            let t = urr.reporting_triggers.encode();
            u16::from(t[0]) | (u16::from(t[1]) << 8)
        },
        volume_threshold: volume(urr.volume_threshold.as_ref()),
        volume_quota: volume(urr.volume_quota.as_ref()),
        time_threshold: urr.time_threshold,
        measurement_period: urr.measurement_period,
    }
}

fn establishment_from_lib(
    req: &LibSessionEstablishmentRequest,
    cp_f_seid: &crate::context::FSeid,
) -> crate::sxa_handler::SessionEstablishmentRequest {
    crate::sxa_handler::SessionEstablishmentRequest {
        cp_f_seid: Some(cp_f_seid.clone()),
        create_pdrs: req.create_pdrs.iter().map(pdr_from_lib).collect(),
        create_fars: req.create_fars.iter().map(far_from_lib).collect(),
        create_qers: req.create_qers.iter().map(qer_from_lib).collect(),
        create_urrs: req.create_urrs.iter().map(urr_from_lib).collect(),
        // Create BAR and the PFCPSEReq-Flags are not modelled by the library's
        // message type, so they are not mapped. Left absent rather than defaulted to
        // something that reads as provisioned: a BAR this SGW-U claimed to have
        // installed and had not would make buffering look configured.
        create_bar: None,
        sereq_flags: Default::default(),
    }
}

fn modification_from_lib(
    req: &LibSessionModificationRequest,
) -> crate::sxa_handler::SessionModificationRequest {
    crate::sxa_handler::SessionModificationRequest {
        create_pdrs: req.create_pdrs.iter().map(pdr_from_lib).collect(),
        update_pdrs: req
            .update_pdrs
            .iter()
            .map(|pdr| crate::sxa_handler::UpdatePdrRequest {
                pdr_id: pdr.pdr_id,
                // `None` leaves the existing URR association alone; the library's
                // UpdatePdr carries no URR ID, so an Update that re-points a
                // measurement cannot be conveyed (see the note on update_qers below).
                urr_ids: None,
                pdi: pdr.pdi.as_ref().map(|pdi| crate::sxa_handler::PdiRequest {
                    source_interface: pdi.source_interface as u8,
                    local_f_teid: pdi.local_f_teid.as_ref().map(f_teid_from_lib),
                    network_instance: pdi.network_instance.clone(),
                    ue_ip_address: pdi.ue_ip_address.as_ref().map(|ue| {
                        crate::sxa_handler::UeIpAddress {
                            ipv4: ue.ipv4_addr.map(Ipv4Addr::from),
                            ipv6: ue.ipv6_addr.map(std::net::Ipv6Addr::from),
                        }
                    }),
                }),
                outer_header_removal: pdr
                    .outer_header_removal
                    .as_ref()
                    .map(|ohr| ohr.description as u8),
                far_id: pdr.far_id,
            })
            .collect(),
        remove_pdrs: req.remove_pdrs.iter().map(|r| r.pdr_id).collect(),
        create_fars: req.create_fars.iter().map(far_from_lib).collect(),
        update_fars: req
            .update_fars
            .iter()
            .map(|far| crate::sxa_handler::UpdateFarRequest {
                far_id: far.far_id,
                apply_action: far.apply_action.as_ref().map(apply_action_octet),
                smreq_flags: Default::default(),
                update_forwarding_parameters: far.forwarding_parameters.as_ref().map(|fp| {
                    crate::sxa_handler::ForwardingParameters {
                        destination_interface: fp.destination_interface as u8,
                        outer_header_creation: fp.outer_header_creation.as_ref().map(|ohc| {
                            crate::sxa_handler::OuterHeaderCreation {
                                teid: ohc.teid.unwrap_or(0),
                                ipv4: ohc.ipv4_addr.map(Ipv4Addr::from),
                                ipv6: ohc.ipv6_addr.map(std::net::Ipv6Addr::from),
                            }
                        }),
                    }
                }),
            })
            .collect(),
        remove_fars: req.remove_fars.iter().map(|r| r.far_id).collect(),
        create_qers: req.create_qers.iter().map(qer_from_lib).collect(),
        create_urrs: req.create_urrs.iter().map(urr_from_lib).collect(),
        // The library's SessionModificationRequest models no Update QER / Remove QER /
        // Update URR / Remove URR (the IE types exist; the structs do not), so those
        // lists arrive EMPTY however the SGW-C populated them. The handler's code for
        // them is therefore still reachable only in-process. Filed as its own issue
        // rather than hand-decoded here, which would put a second IE decoder beside
        // the library one.
        update_qers: Vec::new(),
        remove_qers: Vec::new(),
        update_urrs: Vec::new(),
        remove_urrs: Vec::new(),
        create_bar: None,
        remove_bar: None,
    }
}

// ============================================================================
// PFCP Path Functions
// ============================================================================

/// Open the Sxa PFCP socket and start serving (issue #59).
///
/// Replaces the log-only `pfcp_open`. `PFCP_BIND_ADDR` / `PFCP_NODE_IP` override the
/// defaults so a test — or a host with several interfaces — can pick both.
pub async fn pfcp_open() -> Result<Arc<SxaNode>, String> {
    let bind: SocketAddr = std::env::var("PFCP_BIND_ADDR")
        .unwrap_or_else(|_| format!("0.0.0.0:{PFCP_PORT}"))
        .parse()
        .map_err(|e| format!("PFCP_BIND_ADDR is not a socket address: {e}"))?;
    let local_ip: Ipv4Addr = std::env::var("PFCP_NODE_IP")
        .unwrap_or_else(|_| "127.0.0.1".to_string())
        .parse()
        .map_err(|e| format!("PFCP_NODE_IP is not an IPv4 address: {e}"))?;
    SxaNode::open(bind, local_ip)
        .await
        .map_err(|e| format!("failed to bind PFCP socket on {bind}: {e}"))
}

/// Close the Sxa PFCP path. The socket closes with the node; this drops the
/// process-wide handle's peers so a subsequent open starts clean.
pub async fn pfcp_close() {
    if let Some(node) = sxa_node() {
        let peers: Vec<SocketAddr> = node.peers().await.into_iter().map(|p| p.addr).collect();
        for peer in peers {
            node.declare_peer_failure(peer, "SGW-U shutting down").await;
        }
    }
    log::info!("PFCP/Sxa path closed");
}

// ============================================================================
// PFCP Send Functions (SGWU -> SGWC)
// ============================================================================

/// Send Session Report Request to SGW-C (TS 29.244 §7.5.8).
///
/// Callable from the SYNCHRONOUS data path (`gtp_path` runs on OS threads with a
/// blocking socket), so it enqueues onto the running node rather than awaiting. The
/// request is then sent with T1/N1 retransmission by the node's own task.
///
/// Before #59 this was a log-only no-op, so every Downlink Data Report and Error
/// Indication Report the data path produced was discarded — which is why paging for
/// an idle UE could not work.
pub fn send_session_report_request(
    sess: &SgwuSess,
    report: &UserPlaneReport,
) -> Result<(), String> {
    let msg = sxa_build::build_session_report_request(sess, report)
        .ok_or_else(|| "Failed to build Session Report Request".to_string())?;
    let to = sgwc_peer_addr(sess)?;

    log::info!(
        "Queueing PFCP Session Report Request: cp_seid=0x{:x}, report_type=0x{:x} -> {to}",
        sess.sgwc_sxa_f_seid.seid,
        report.report_type()
    );
    let tx = OUTBOUND
        .get()
        .ok_or_else(|| "PFCP path is not running: no Sxa transport to send on".to_string())?;
    tx.send(QueuedRequest {
        msg_type: msg.msg_type,
        seid: msg.seid,
        body: msg.data,
        to,
        sess_id: sess.id,
    })
    .map_err(|_| "PFCP outbound queue is closed".to_string())
}

/// Where to send a session-level request for `sess`: the SGW-C address from the CP
/// F-SEID it established the session with, on the PFCP port.
fn sgwc_peer_addr(sess: &SgwuSess) -> Result<SocketAddr, String> {
    match (sess.sgwc_sxa_f_seid.ip.ipv4, sess.sgwc_sxa_f_seid.ip.ipv6) {
        (Some(v4), _) => Ok(SocketAddr::from((v4, PFCP_PORT))),
        (None, Some(v6)) => Ok(SocketAddr::from((v6, PFCP_PORT))),
        (None, None) => Err(format!(
            "session {} has no SGW-C address on its CP F-SEID",
            sess.id
        )),
    }
}

/// Feed a Session Report Response back into the handler that cares about it.
fn sess_report_response_received(sess_id: u64, resp_type: u8, body: &[u8]) {
    if resp_type != pfcp_msg_type::SESSION_REPORT_RESPONSE {
        log::warn!("Unexpected response type {resp_type} to a Session Report Request");
        return;
    }
    let rsp = crate::sxa_handler::SessionReportResponse {
        cause: find_cause(body),
        update_bar: None,
    };
    let sess = sgwu_self().sess_find_by_id(sess_id);
    let result = crate::sxa_handler::handle_session_report_response(sess.as_ref(), 0, &rsp);
    if let crate::sxa_handler::HandlerResult::Error(cause) = result {
        log::warn!("Session Report Response for session {sess_id} rejected: cause={cause}");
    }
}

/// Is this message type a response (solicited by one of our requests)?
fn is_response_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        2 | 4 | 6 | 8 | 10 | 11 | 13 | 15 | 51 | 53 | 55 | 57
    )
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
        node.state = PfcpNodeState::WillAssociate;
    }
}

/// Finalize PFCP node FSM
/// Port of pfcp_node_fsm_fini
pub fn pfcp_node_fsm_fini(node: &mut PfcpNode) {
    log::debug!("Finalizing PFCP node FSM for {}", node.addr);

    node.state = PfcpNodeState::Final;
}

// ============================================================================
// Tests
// ============================================================================
//
// The transport tests drive a REAL socket exchange against a bound `SxaNode`,
// which is what #59's test expectation asks for ("an integration test sends a real
// PFCP Heartbeat and Session Establishment Request to a running sgwud instance and
// asserts the decoded, spec-conformant responses"). Every assertion is on bytes
// that crossed a UDP socket and were decoded with the library codec — not on a
// function having been called.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{sgwu_context_init, FSeid};
    use nextgcore_pfcp::types::{
        ApplyAction, CreateFar, CreatePdr, DestinationInterface, FTeid, ForwardingParameters,
        GateStatus, MeasurementMethod, Pdi, ReportingTriggers, SourceInterface, VolumeThreshold,
    };
    use nextgcore_pfcp::types::{CreateQer, CreateUrr};

    /// A bound node plus a socket standing in for the SGW-C.
    async fn node_and_peer() -> (Arc<SxaNode>, UdpSocket) {
        sgwu_context_init(1024);
        // A CH F-TEID asks the UP function to allocate, which needs its own GTP-U
        // address; without one `process_create_pdr` correctly answers
        // NO_RESOURCES_AVAILABLE, so a test that omitted this would be asserting the
        // wrong refusal.
        sgwu_self().set_gtpu_address(Some(Ipv4Addr::new(127, 0, 0, 1)));
        let node = SxaNode::open("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(127, 0, 0, 1))
            .await
            .expect("bind Sxa socket");
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
        (node, peer)
    }

    /// Encode a PFCP message the way an SGW-C would put it on the wire.
    fn wire(msg_type: u8, seid: Option<u64>, seq: u32, body: &[u8]) -> Vec<u8> {
        let message_type = PfcpMessageType::try_from(msg_type).expect("known type");
        let mut header = match seid {
            Some(seid) => PfcpHeader::new_with_seid(message_type, seid, seq),
            None => PfcpHeader::new(message_type, seq),
        };
        header.length = ((if seid.is_some() { 12 } else { 4 }) + body.len()) as u16;
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        buf.extend_from_slice(body);
        buf.to_vec()
    }

    /// Receive one datagram and decode its header + body.
    async fn recv_decoded(peer: &UdpSocket) -> (PfcpHeader, Vec<u8>) {
        let mut buf = vec![0u8; 8192];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv_from(&mut buf))
                .await
                .expect("a PFCP response must arrive")
                .expect("recv");
        let mut cursor = Bytes::copy_from_slice(&buf[..len]);
        let header = PfcpHeader::decode(&mut cursor).expect("decodable header");
        (header, cursor.to_vec())
    }

    /// Feed one datagram into the node as if it had been received.
    async fn deliver(node: &SxaNode, peer: &UdpSocket, pkt: &[u8]) {
        let to = node.local_addr();
        peer.send_to(pkt, to).await.expect("send to node");
        let mut buf = vec![0u8; 8192];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            node.socket.recv_from(&mut buf),
        )
        .await
        .expect("the node must receive it")
        .expect("recv");
        node.on_datagram(&buf[..len], from).await;
    }

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
    fn test_pfcp_node_fsm_init_fini() {
        let mut node = PfcpNode::new(1, "127.0.0.1", 8805);

        pfcp_node_fsm_init(&mut node, false);
        assert_eq!(node.state, PfcpNodeState::Initial);

        pfcp_node_fsm_init(&mut node, true);
        assert_eq!(node.state, PfcpNodeState::WillAssociate);

        pfcp_node_fsm_fini(&mut node);
        assert_eq!(node.state, PfcpNodeState::Final);
    }

    /// #59 criterion 1: the socket is actually bound.
    ///
    /// `pfcp_open` used to log "In actual implementation: Create UDP sockets for PFCP
    /// (port 8805)" and return Ok without binding anything, so this is the assertion
    /// that separates a bound socket from a claim about one.
    #[tokio::test]
    async fn the_sxa_socket_is_really_bound() {
        let (node, _peer) = node_and_peer().await;
        let bound = node.local_addr();
        assert_ne!(bound.port(), 0, "an ephemeral bind must resolve to a port");
        assert!(sxa_node().is_some(), "the node is installed process-wide");
    }

    /// #59 criterion 2: an inbound Heartbeat Request is decoded with the library
    /// codec and answered (TS 29.244 §6.2.2.2 — "shall reply").
    #[tokio::test]
    async fn an_inbound_heartbeat_request_is_answered_with_our_recovery_time_stamp() {
        let (node, peer) = node_and_peer().await;
        let mut body = BytesMut::new();
        PfcpLibMessage::HeartbeatRequest(HeartbeatRequest::new(4242)).encode_body(&mut body);

        deliver(
            &node,
            &peer,
            &wire(pfcp_msg_type::HEARTBEAT_REQUEST, None, 77, &body),
        )
        .await;

        let (header, body) = recv_decoded(&peer).await;
        assert_eq!(header.message_type as u8, pfcp_msg_type::HEARTBEAT_RESPONSE);
        assert_eq!(
            header.sequence_number, 77,
            "a response echoes the request's sequence number"
        );
        let mut cursor = Bytes::copy_from_slice(&body);
        let rsp = HeartbeatResponse::decode(&mut cursor).expect("decodable Heartbeat Response");
        assert_eq!(
            rsp.recovery_time_stamp, node.recovery_time_stamp,
            "the mandatory Recovery Time Stamp must be ours, and real"
        );
        assert!(rsp.recovery_time_stamp > 0);
    }

    /// #59 criterion 3, first half: an Association Setup Request is fully decoded and
    /// answered, and the peer is recorded — which is what makes later sessions
    /// attributable to a node.
    #[tokio::test]
    async fn an_association_setup_request_is_accepted_and_the_peer_recorded() {
        let (node, peer) = node_and_peer().await;
        let mut body = BytesMut::new();
        PfcpLibMessage::AssociationSetupRequest(AssociationSetupRequest::new(
            NodeId::new_ipv4([127, 0, 0, 9]),
            999,
        ))
        .encode_body(&mut body);

        deliver(
            &node,
            &peer,
            &wire(pfcp_msg_type::ASSOCIATION_SETUP_REQUEST, None, 5, &body),
        )
        .await;

        let (header, body) = recv_decoded(&peer).await;
        assert_eq!(
            header.message_type as u8,
            pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE
        );
        let mut cursor = Bytes::copy_from_slice(&body);
        let rsp =
            AssociationSetupResponse::decode(&mut cursor).expect("decodable Association Response");
        assert_eq!(rsp.cause, PfcpCause::RequestAccepted);
        assert_eq!(rsp.recovery_time_stamp, node.recovery_time_stamp);
        let features = rsp
            .up_function_features
            .expect("a UP function must state its features");
        assert!(features.ftup, "this SGW-U allocates F-TEIDs for the CP");

        let peers = node.peers().await;
        assert_eq!(peers.len(), 1, "the peer must be recorded");
        assert_eq!(peers[0].state, PfcpNodeState::Associated);
        assert_eq!(peers[0].recovery_time_stamp, Some(999));
        assert!(node.is_associated().await, "the health probe's question");
    }

    /// #59 criterion 3, second half: a Session Establishment Request is decoded down
    /// to its IEs, dispatched into `sxa_handler`, and answered with a correctly
    /// encoded response carrying the UP F-SEID and the allocated F-TEID.
    ///
    /// The old `handle_pfcp_recv` read `data[1]` and returned an enum variant, so
    /// nothing here was reachable: no session was created, no rule installed, no
    /// response produced.
    #[tokio::test]
    async fn a_session_establishment_request_creates_a_session_and_is_answered() {
        let (node, peer) = node_and_peer().await;

        // Associate first: TS 29.244 §6.2.6.2 has no session signalling without one,
        // and the peer record is what tags the session with its node.
        let mut assoc = BytesMut::new();
        PfcpLibMessage::AssociationSetupRequest(AssociationSetupRequest::new(
            NodeId::new_ipv4([127, 0, 0, 9]),
            1000,
        ))
        .encode_body(&mut assoc);
        deliver(
            &node,
            &peer,
            &wire(pfcp_msg_type::ASSOCIATION_SETUP_REQUEST, None, 1, &assoc),
        )
        .await;
        let _ = recv_decoded(&peer).await;

        // A minimal but conformant Establishment: Node ID + CP F-SEID + one uplink
        // PDR whose F-TEID asks the UP function to choose (CH), and its FAR.
        let cp_seid = 0x0000_0000_0000_1234u64;
        let mut req = LibSessionEstablishmentRequest::new(
            NodeId::new_ipv4([127, 0, 0, 9]),
            LibFSeid::new_ipv4(cp_seid, [127, 0, 0, 9]),
        );
        let mut pdi = Pdi::new(SourceInterface::Access);
        let mut f_teid = FTeid::new_ipv4(0, [127, 0, 0, 1]);
        f_teid.ch = true;
        pdi.local_f_teid = Some(f_teid);
        let mut pdr = CreatePdr::new(1, 100, pdi);
        pdr.far_id = Some(1);
        req.create_pdrs.push(pdr);
        let mut far = CreateFar::new(1, ApplyAction::forward());
        far.forwarding_parameters = Some(ForwardingParameters::new(DestinationInterface::Core));
        req.create_fars.push(far);
        let mut body = BytesMut::new();
        req.encode(&mut body);

        deliver(
            &node,
            &peer,
            &wire(
                pfcp_msg_type::SESSION_ESTABLISHMENT_REQUEST,
                Some(0),
                9,
                &body,
            ),
        )
        .await;

        let (header, resp_body) = recv_decoded(&peer).await;
        assert_eq!(
            header.message_type as u8,
            pfcp_msg_type::SESSION_ESTABLISHMENT_RESPONSE
        );
        assert_eq!(
            header.seid,
            Some(cp_seid),
            "the response is addressed to the CP's own SEID (TS 29.244 §7.2.2.4.2)"
        );
        assert_eq!(header.sequence_number, 9);
        assert_eq!(
            find_cause(&resp_body),
            Some(sxa_build::pfcp_cause::REQUEST_ACCEPTED),
            "Cause is mandatory in the response"
        );

        // The session exists, is attributed to the peer's node, and holds the rule.
        let ctx = sgwu_self();
        let sess = ctx
            .sess_find_by_sgwc_sxa_seid(cp_seid)
            .expect("the Establishment must create a session");
        assert!(
            sess.pfcp_node_id.is_some(),
            "an untagged session is invisible to sess_remove_all_for_pfcp_node, so a \
             peer failure would remove nothing"
        );
        assert!(
            ctx.pdr_find(sess.id, 1).is_some(),
            "the Create PDR must have been INSTALLED on the session, not just parsed"
        );
    }

    /// #59 criterion 4: `request` performs real socket I/O and retransmits on T1
    /// expiry up to N1 attempts, then reports a timeout.
    ///
    /// The peer deliberately stays silent for the first two attempts and answers the
    /// third, so both halves are asserted: the retransmission happened, and the
    /// transaction completed on the answer rather than on a timer.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_retransmits_on_t1_and_completes_on_the_answer() {
        sgwu_context_init(1024);
        // A 200ms T1 with N1 = 2, so the assertion is about the retransmission rather
        // than about the production interval.
        let timers = SgwuTimerConfigs {
            no_heartbeat: crate::timer::TimerConfig::new_millis(2, 200),
            ..SgwuTimerConfigs::default()
        };
        let node = SxaNode::open_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            Ipv4Addr::new(127, 0, 0, 1),
            timers,
        )
        .await
        .expect("bind");
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
        let peer_addr = peer.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut count = 0u32;
            loop {
                let (len, from) = peer.recv_from(&mut buf).await.expect("recv");
                count += 1;
                if count == 3 {
                    let mut cursor = Bytes::copy_from_slice(&buf[..len]);
                    let header = PfcpHeader::decode(&mut cursor).expect("header");
                    let mut body = Vec::new();
                    body.extend_from_slice(&19u16.to_be_bytes());
                    body.extend_from_slice(&1u16.to_be_bytes());
                    body.push(sxa_build::pfcp_cause::REQUEST_ACCEPTED);
                    let pkt = wire(
                        pfcp_msg_type::SESSION_REPORT_RESPONSE,
                        Some(1),
                        header.sequence_number,
                        &body,
                    );
                    peer.send_to(&pkt, from).await.expect("answer");
                    return count;
                }
            }
        });

        // Pump the node's socket so the response reaches the pending transaction.
        let pump = node.clone();
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move { pump.run(rx).await });

        let (resp_type, body) = node
            .request(pfcp_msg_type::SESSION_REPORT_REQUEST, 1, &[], peer_addr)
            .await
            .expect("the third attempt must be answered");
        assert_eq!(resp_type, pfcp_msg_type::SESSION_REPORT_RESPONSE);
        assert_eq!(
            find_cause(&body),
            Some(sxa_build::pfcp_cause::REQUEST_ACCEPTED)
        );
        assert_eq!(
            responder.await.unwrap(),
            3,
            "exactly three transmissions reached the wire"
        );
    }

    /// #59 criterion 5: peer failure runs the FSM's restoration path, which removes
    /// the failed node's sessions.
    ///
    /// Asserted through `declare_peer_failure` — the function the heartbeat monitor,
    /// the Association Release handler and the restart check all reach — and on the
    /// SESSION COUNT rather than on the FSM's state, because `pfcp_restoration` doing
    /// nothing would leave the state identical.
    #[tokio::test]
    async fn peer_failure_runs_the_fsm_restoration_and_removes_that_nodes_sessions() {
        let (node, peer) = node_and_peer().await;
        let mut assoc = BytesMut::new();
        PfcpLibMessage::AssociationSetupRequest(AssociationSetupRequest::new(
            NodeId::new_ipv4([127, 0, 0, 9]),
            1234,
        ))
        .encode_body(&mut assoc);
        deliver(
            &node,
            &peer,
            &wire(pfcp_msg_type::ASSOCIATION_SETUP_REQUEST, None, 1, &assoc),
        )
        .await;
        let _ = recv_decoded(&peer).await;
        let node_id = node.peers().await[0].node_id;

        // Two sessions on this peer, and one on a different node that must survive.
        let ctx = sgwu_self();
        for seid in [0xAA01u64, 0xAA02] {
            let mut sess = ctx
                .sess_add(&FSeid::with_ipv4(seid, Ipv4Addr::new(127, 0, 0, 9)))
                .expect("add");
            sess.pfcp_node_id = Some(node_id);
            ctx.sess_update(&sess);
        }
        let mut other = ctx
            .sess_add(&FSeid::with_ipv4(0xBB01, Ipv4Addr::new(127, 0, 0, 8)))
            .expect("add");
        other.pfcp_node_id = Some(node_id + 1000);
        ctx.sess_update(&other);

        node.declare_peer_failure(peer.local_addr().unwrap(), "test: no heartbeat")
            .await;

        assert!(
            ctx.sess_find_by_sgwc_sxa_seid(0xAA01).is_none()
                && ctx.sess_find_by_sgwc_sxa_seid(0xAA02).is_none(),
            "the failed node's sessions must be removed (TS 23.007 §19A)"
        );
        assert!(
            ctx.sess_find_by_sgwc_sxa_seid(0xBB01).is_some(),
            "another node's session must survive: failure is per peer, not global"
        );
        assert!(
            node.peers().await.is_empty(),
            "and the peer itself is gone, so no session signalling is accepted for it"
        );
    }

    /// A restarted SGW-C holds none of the sessions we do, so a changed Recovery Time
    /// Stamp on a re-association flushes them (TS 23.007 §19A).
    #[tokio::test]
    async fn a_changed_recovery_time_stamp_flushes_that_peers_sessions() {
        let (node, peer) = node_and_peer().await;
        let assoc = |rts: u32| {
            let mut body = BytesMut::new();
            PfcpLibMessage::AssociationSetupRequest(AssociationSetupRequest::new(
                NodeId::new_ipv4([127, 0, 0, 9]),
                rts,
            ))
            .encode_body(&mut body);
            wire(pfcp_msg_type::ASSOCIATION_SETUP_REQUEST, None, 1, &body)
        };
        deliver(&node, &peer, &assoc(100)).await;
        let _ = recv_decoded(&peer).await;
        let node_id = node.peers().await[0].node_id;

        let ctx = sgwu_self();
        let mut sess = ctx
            .sess_add(&FSeid::with_ipv4(0xCC01, Ipv4Addr::new(127, 0, 0, 9)))
            .expect("add");
        sess.pfcp_node_id = Some(node_id);
        ctx.sess_update(&sess);

        // Same stamp: not a restart, so the session survives.
        deliver(&node, &peer, &assoc(100)).await;
        let _ = recv_decoded(&peer).await;
        assert!(
            ctx.sess_find_by_sgwc_sxa_seid(0xCC01).is_some(),
            "the same stamp is not a restart, and flushing unconditionally would make \
             every re-association lose the live sessions"
        );

        // Changed stamp: the peer restarted.
        deliver(&node, &peer, &assoc(200)).await;
        let _ = recv_decoded(&peer).await;
        assert!(
            ctx.sess_find_by_sgwc_sxa_seid(0xCC01).is_none(),
            "a changed Recovery Time Stamp means the CP holds none of these sessions"
        );
    }

    /// A Session Deletion for a live session answers with the final Usage Reports and
    /// removes it; one for an unknown SEID answers SESSION_CONTEXT_NOT_FOUND rather
    /// than succeeding silently.
    #[tokio::test]
    async fn a_session_deletion_is_answered_and_an_unknown_seid_is_refused() {
        let (node, peer) = node_and_peer().await;
        let ctx = sgwu_self();
        let sess = ctx
            .sess_add(&FSeid::with_ipv4(0xDD01, Ipv4Addr::new(127, 0, 0, 9)))
            .expect("add");
        let up_seid = sess.sgwu_sxa_seid;

        deliver(
            &node,
            &peer,
            &wire(
                pfcp_msg_type::SESSION_DELETION_REQUEST,
                Some(up_seid),
                3,
                &[],
            ),
        )
        .await;
        let (header, body) = recv_decoded(&peer).await;
        assert_eq!(
            header.message_type as u8,
            pfcp_msg_type::SESSION_DELETION_RESPONSE
        );
        assert_eq!(
            find_cause(&body),
            Some(sxa_build::pfcp_cause::REQUEST_ACCEPTED)
        );
        assert!(
            ctx.sess_find_by_sgwu_sxa_seid(up_seid).is_none(),
            "the session must be gone after the deletion is answered"
        );

        deliver(
            &node,
            &peer,
            &wire(
                pfcp_msg_type::SESSION_DELETION_REQUEST,
                Some(0xFFFF_FFFF),
                4,
                &[],
            ),
        )
        .await;
        let (_, body) = recv_decoded(&peer).await;
        assert_eq!(
            find_cause(&body),
            Some(sxa_build::pfcp_cause::SESSION_CONTEXT_NOT_FOUND),
            "an unknown SEID must be refused, not accepted"
        );
    }

    /// An unsupported version is answered with Version Not Supported Response
    /// (TS 29.244 §7.2.2.1), not dropped.
    #[tokio::test]
    async fn an_unsupported_version_is_answered_rather_than_dropped() {
        let (node, peer) = node_and_peer().await;
        let mut pkt = wire(pfcp_msg_type::HEARTBEAT_REQUEST, None, 6, &[]);
        pkt[0] = (2 << 5) | (pkt[0] & 0x07); // version 2

        deliver(&node, &peer, &pkt).await;

        let (header, _) = recv_decoded(&peer).await;
        assert_eq!(
            header.message_type as u8,
            pfcp_msg_type::VERSION_NOT_SUPPORTED_RESPONSE
        );
    }

    /// The IE mapping from the library's types onto this crate's request structs.
    ///
    /// Worth asserting directly as well as through the wire tests: an Apply Action or
    /// gate-status octet packed the wrong way round produces a rule that forwards
    /// when it should drop, and neither the establishment response nor the session
    /// count would look any different.
    #[test]
    fn the_library_ie_mapping_preserves_what_the_data_path_matches_on() {
        assert_eq!(apply_action_octet(&ApplyAction::forward()), 0x02, "FORW");
        assert_eq!(apply_action_octet(&ApplyAction::drop()), 0x01, "DROP");

        // TS 29.244 §8.2.7: 0 = OPEN, 1 = CLOSED, UL in bits 1-2 and DL in bits 3-4.
        assert_eq!(gate_status_octet(&GateStatus::both_open()), 0x00);
        assert_eq!(gate_status_octet(&GateStatus::both_closed()), 0x05);

        let mut qer = CreateQer::new(7, GateStatus::both_closed());
        qer.qfi = Some(5);
        let mapped = qer_from_lib(&qer);
        assert_eq!(mapped.qer_id, 7);
        assert_eq!(mapped.gate_status, Some(0x05));

        let mut urr = CreateUrr::new(
            3,
            MeasurementMethod {
                volum: true,
                ..Default::default()
            },
            ReportingTriggers::default(),
        );
        urr.volume_threshold = Some(VolumeThreshold::new_total(1_000));
        urr.volume_quota = Some(VolumeThreshold::new_total(2_000));
        let mapped = urr_from_lib(&urr);
        assert_eq!(mapped.urr_id, 3);
        assert_eq!(mapped.volume_threshold.total, Some(1_000));
        assert_eq!(
            mapped.volume_quota.total,
            Some(2_000),
            "a decoded Volume Quota must reach the rule store, or the quota is enforced \
             against zero"
        );
        // This asserts the MAPPING only: it builds the library struct directly, so it
        // passes whether or not the codec carries the IE on the wire. Removing the
        // library's decode arm left this test green, which is why the wire half is
        // `nextgcore_pfcp::types::tests::a_create_urr_carries_its_volume_quota_over_the_wire`.

        let f_seid = f_seid_from_lib(&LibFSeid::new_ipv4(0x99, [10, 0, 0, 7]));
        assert_eq!(f_seid.seid, 0x99);
        assert_eq!(
            f_seid.ip.ipv4,
            Some(Ipv4Addr::new(10, 0, 0, 7)),
            "the CP address is what a Session Report is addressed to"
        );
    }

    /// A Session Report Request cannot be sent before the transport is running, and
    /// says so instead of returning Ok.
    ///
    /// This is the shape the old stub had: `send_pfcp_request` logged and returned
    /// `Ok(())`, so every Downlink Data Report the data path produced was silently
    /// discarded while its caller believed it had been sent.
    #[test]
    fn a_session_report_without_a_running_transport_is_an_error_not_a_silent_ok() {
        sgwu_context_init(1024);
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
        // Either the queue is not installed (this test alone) or it is (a sibling
        // started a node first). Both are correct; what must never happen is an
        // unsendable report reported as sent.
        match send_session_report_request(&sess, &report) {
            Err(e) => assert!(
                e.contains("not running") || e.contains("closed"),
                "the error must name why nothing was sent, got {e}"
            ),
            Ok(()) => assert!(
                OUTBOUND.get().is_some(),
                "Ok is only honest when there is a transport to send on"
            ),
        }
    }
}
