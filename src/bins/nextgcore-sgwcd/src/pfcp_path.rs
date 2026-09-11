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
    AssociationSetupRequest, AssociationSetupResponse, HeartbeatResponse,
    PfcpMessage as PfcpLibMessage, SessionReportRequest, SessionReportResponse,
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

/// Serialises every test that reads or writes [`SXA_NODE`] / [`OUTBOUND`]. One lock for
/// both: they are always installed together.
#[cfg(test)]
pub(crate) static SXA_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
}

/// Holds [`SXA_TEST_LOCK`] and leaves the globals empty on both sides of a test.
#[cfg(test)]
pub(crate) struct SxaTestGuard(#[allow(dead_code)] tokio::sync::MutexGuard<'static, ()>);

#[cfg(test)]
impl Drop for SxaTestGuard {
    fn drop(&mut self) {
        clear_sxa_globals_for_test();
        // The S11 server is installed by the same tests, for the same reason (the gated
        // answer goes through the process-global one). Cleared here rather than under a
        // second lock: one agreement about both, so there is no lock order to get wrong.
        crate::gtp_path::clear_s11_server_for_test();
    }
}

#[cfg(test)]
pub(crate) async fn sxa_test_guard() -> SxaTestGuard {
    let guard = SXA_TEST_LOCK.lock().await;
    clear_sxa_globals_for_test();
    SxaTestGuard(guard)
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
}

impl SxaNode {
    /// Bind the Sxa socket and install the node process-wide.
    pub async fn open(bind: SocketAddr, local_ip: Ipv4Addr) -> std::io::Result<Arc<Self>> {
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
            associated_peers: AtomicUsize::new(0),
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

            match tokio::time::timeout(T1, rx).await {
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
            recovery_time_stamp: Some(rsp.recovery_time_stamp),
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
            pfcp_msg_type::HEARTBEAT_REQUEST => {
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
            other => {
                log::warn!("PFCP message type {other} from {from} is not handled on Sxa (CP side)");
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
pub async fn pfcp_open() -> Result<Arc<SxaNode>, String> {
    let bind: SocketAddr = std::env::var("SGWC_PFCP_BIND_ADDR")
        .unwrap_or_else(|_| format!("0.0.0.0:{PFCP_PORT}"))
        .parse()
        .map_err(|e| format!("SGWC_PFCP_BIND_ADDR is not a socket address: {e}"))?;
    let local_ip: Ipv4Addr = std::env::var("SGWC_PFCP_NODE_IP")
        .unwrap_or_else(|_| "127.0.0.1".to_string())
        .parse()
        .map_err(|e| format!("SGWC_PFCP_NODE_IP is not an IPv4 address: {e}"))?;
    SxaNode::open(bind, local_ip)
        .await
        .map_err(|e| format!("failed to bind PFCP socket on {bind}: {e}"))
}

/// The SGW-U this SGW-C provisions user planes on.
///
/// `SGWC_SGWU_ADDR` takes either `ip` (PFCP's own port is assumed) or `ip:port`. The port
/// form exists so a test can stand in for an SGW-U on an ephemeral port rather than
/// fighting a live one for UDP/8805.
pub fn configured_sgwu_addr() -> SocketAddr {
    let value = std::env::var("SGWC_SGWU_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return addr;
    }
    let ip: Ipv4Addr = value.parse().unwrap_or(Ipv4Addr::LOCALHOST);
    SocketAddr::from((ip, PFCP_PORT))
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

/// Enqueue an outbound request. Callable from the synchronous S11 dispatch.
fn enqueue(msg: &PfcpMessage, sess_id: u64, continuation: S11Continuation) -> Result<(), String> {
    let tx = outbound()
        .ok_or_else(|| "PFCP path is not running: no Sxa transport to send on".to_string())?;
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

    /// #54: `pfcp_open` binds a real socket. It used to log "In actual implementation:
    /// Create UDP sockets for PFCP" and return Ok without binding anything, so this is
    /// the assertion that separates a bound socket from a claim about one.
    #[tokio::test]
    async fn test_pfcp_open_close() {
        let _guard = sxa_test_guard().await;
        std::env::set_var("SGWC_PFCP_BIND_ADDR", "127.0.0.1:0");
        let node = pfcp_open().await.expect("bind");
        assert_ne!(node.local_addr().port(), 0, "a real socket was bound");
        assert!(sxa_node().is_some(), "the node is installed process-wide");
        pfcp_close().await;
        std::env::remove_var("SGWC_PFCP_BIND_ADDR");
    }

    /// A session request cannot be sent before the transport is running, and says so
    /// instead of returning Ok — the shape the old `send_pfcp_message` had.
    #[tokio::test]
    async fn a_session_request_without_a_running_transport_is_an_error_not_a_silent_ok() {
        let _guard = sxa_test_guard().await;
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
}
