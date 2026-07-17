//! UPF PFCP Path Management
//!
//! Port of src/upf/pfcp-path.c - PFCP path management for UPF

use crate::n4_build::{
    build_association_release_response, build_association_setup_response, build_failure_response,
    build_heartbeat_response, build_session_deletion_response,
    build_session_establishment_response, build_session_modification_response,
    build_session_report_request, parse_create_bar, parse_create_far, parse_create_pdr,
    parse_create_qer, parse_create_urr, parse_pfcpsmreq_flags, parse_recovery_time_stamp, pfcp_ie,
    pfcp_type, pfcpsmreq_flags, CreatedPdr, DownlinkDataReport, DownlinkDataServiceInfo,
    ErrorIndicationReport, FSeid, FTeid, NodeId, ParsedCreateBar, ParsedCreateFar, ParsedCreatePdr,
    ParsedCreateQer, ParsedCreateUrr, ParsedFSeid, ParsedIe, ParsedPfcpHeader, PfcpCause,
    ReportType, UserPlaneReport,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// ============================================================================
// PFCP Header
// ============================================================================

/// PFCP message header
#[derive(Debug, Clone, Default)]
pub struct PfcpHeader {
    pub version: u8,
    pub msg_type: u8,
    pub length: u16,
    pub seid: u64,
    pub sequence_number: u32,
}

impl PfcpHeader {
    /// Create a new PFCP header
    pub fn new(msg_type: u8, seid: u64, seq: u32) -> Self {
        Self {
            version: 1,
            msg_type,
            length: 0,
            seid,
            sequence_number: seq,
        }
    }

    /// Encode header to bytes
    pub fn encode(&self, payload_len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        let flags = (self.version << 5) | 0x01; // SEID present
        buf.push(flags);
        buf.push(self.msg_type);
        let total_len = (12 + payload_len) as u16; // header after length + payload
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&self.seid.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes()[1..4]); // 3 bytes
        buf.push(0); // spare
        buf
    }
}

// ============================================================================
// PFCP Transaction
// ============================================================================

/// PFCP transaction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XactState {
    Initial,
    Pending,
    Complete,
    Timeout,
}

/// PFCP transaction
#[derive(Debug, Clone)]
pub struct PfcpXact {
    pub id: u64,
    pub sequence_number: u32,
    pub msg_type: u8,
    pub state: XactState,
    pub local: bool,
    pub remote_addr: Option<SocketAddr>,
    pub seid: u64,
    pub request: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}

impl PfcpXact {
    /// Create a new local transaction
    pub fn local_create(seq: u32, seid: u64) -> Self {
        Self {
            id: seq as u64,
            sequence_number: seq,
            msg_type: 0,
            state: XactState::Initial,
            local: true,
            remote_addr: None,
            seid,
            request: None,
            response: None,
        }
    }

    /// Create a new remote transaction
    pub fn remote_create(seq: u32, seid: u64, remote_addr: SocketAddr) -> Self {
        Self {
            id: seq as u64,
            sequence_number: seq,
            msg_type: 0,
            state: XactState::Initial,
            local: false,
            remote_addr: Some(remote_addr),
            seid,
            request: None,
            response: None,
        }
    }

    /// Update transaction with TX message
    pub fn update_tx(&mut self, header: &PfcpHeader, payload: Vec<u8>) {
        self.msg_type = header.msg_type;
        let mut msg = header.encode(payload.len());
        msg.extend(payload);
        if self.local {
            self.request = Some(msg);
        } else {
            self.response = Some(msg);
        }
        self.state = XactState::Pending;
    }

    /// Commit transaction (send message)
    pub fn commit(&mut self) -> Result<Vec<u8>, &'static str> {
        self.state = XactState::Complete;
        if self.local {
            self.request.clone().ok_or("No request to send")
        } else {
            self.response.clone().ok_or("No response to send")
        }
    }
}

// ============================================================================
// PFCP Node
// ============================================================================

/// PFCP peer node
#[derive(Debug, Clone)]
pub struct PfcpNode {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub recovery_time_stamp: u32,
    pub associated: bool,
    pub restoration_required: bool,
}

impl Default for PfcpNode {
    fn default() -> Self {
        Self {
            node_id: NodeId::Ipv4(Ipv4Addr::UNSPECIFIED),
            addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8805),
            recovery_time_stamp: 0,
            associated: false,
            restoration_required: false,
        }
    }
}

// ============================================================================
// PFCP Path Context
// ============================================================================

/// PFCP path context for UPF
#[derive(Debug, Default)]
pub struct PfcpPathContext {
    pub local_node_id: NodeId,
    pub local_addr: Option<SocketAddr>,
    pub recovery_time_stamp: u32,
    pub peer_nodes: HashMap<String, PfcpNode>,
    pub next_sequence: u32,
    pub transactions: HashMap<u32, PfcpXact>,
}

impl PfcpPathContext {
    /// Create a new PFCP path context
    pub fn new() -> Self {
        Self {
            local_node_id: NodeId::Ipv4(Ipv4Addr::UNSPECIFIED),
            local_addr: None,
            recovery_time_stamp: 0,
            peer_nodes: HashMap::new(),
            next_sequence: 1,
            transactions: HashMap::new(),
        }
    }

    /// Get next sequence number
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if self.next_sequence == 0 {
            self.next_sequence = 1;
        }
        seq
    }

    /// Create a local transaction
    pub fn create_local_xact(&mut self, seid: u64) -> u32 {
        let seq = self.next_seq();
        let xact = PfcpXact::local_create(seq, seid);
        self.transactions.insert(seq, xact);
        seq
    }

    /// Find transaction by sequence number
    pub fn find_xact(&mut self, seq: u32) -> Option<&mut PfcpXact> {
        self.transactions.get_mut(&seq)
    }

    /// Remove transaction
    pub fn remove_xact(&mut self, seq: u32) -> Option<PfcpXact> {
        self.transactions.remove(&seq)
    }
}

// ============================================================================
// PFCP Send Functions
// ============================================================================

/// Send Session Establishment Response
/// Port of upf_pfcp_send_session_establishment_response
pub fn send_session_establishment_response(
    ctx: &mut PfcpPathContext,
    xact: &mut PfcpXact,
    upf_n4_seid: u64,
    smf_n4_seid: u64,
    created_pdrs: &[CreatedPdr],
) -> Result<Vec<u8>, &'static str> {
    let f_seid = FSeid {
        seid: upf_n4_seid,
        ipv4: match &ctx.local_node_id {
            NodeId::Ipv4(addr) => Some(*addr),
            _ => None,
        },
        ipv6: match &ctx.local_node_id {
            NodeId::Ipv6(addr) => Some(*addr),
            _ => None,
        },
    };

    let payload = build_session_establishment_response(
        crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
        upf_n4_seid,
        &ctx.local_node_id,
        &f_seid,
        created_pdrs,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Modification Response
/// Port of upf_pfcp_send_session_modification_response
pub fn send_session_modification_response(
    xact: &mut PfcpXact,
    smf_n4_seid: u64,
    created_pdrs: &[CreatedPdr],
) -> Result<Vec<u8>, &'static str> {
    let payload = build_session_modification_response(
        crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
        created_pdrs,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Deletion Response
/// Port of upf_pfcp_send_session_deletion_response
pub fn send_session_deletion_response(
    xact: &mut PfcpXact,
    smf_n4_seid: u64,
    usage_reports: &[crate::n4_build::UsageReport],
) -> Result<Vec<u8>, &'static str> {
    let payload = build_session_deletion_response(
        crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
        usage_reports,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Report Request
/// Port of upf_pfcp_send_session_report_request
pub fn send_session_report_request(
    ctx: &mut PfcpPathContext,
    smf_n4_seid: u64,
    report: &UserPlaneReport,
) -> Result<(u32, Vec<u8>), &'static str> {
    let seq = ctx.create_local_xact(smf_n4_seid);

    let payload =
        build_session_report_request(crate::n4_build::pfcp_type::SESSION_REPORT_REQUEST, report);

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_REPORT_REQUEST,
        smf_n4_seid,
        seq,
    );

    if let Some(xact) = ctx.find_xact(seq) {
        xact.update_tx(&header, payload);
        let msg = xact.commit()?;
        Ok((seq, msg))
    } else {
        Err("Transaction not found")
    }
}

// ============================================================================
// PFCP Open/Close
// ============================================================================

/// Open PFCP path (initialize)
/// Port of upf_pfcp_open
pub fn pfcp_open(ctx: &mut PfcpPathContext, local_addr: SocketAddr) -> Result<(), &'static str> {
    ctx.local_addr = Some(local_addr);
    ctx.local_node_id = match local_addr {
        SocketAddr::V4(addr) => NodeId::Ipv4(*addr.ip()),
        SocketAddr::V6(addr) => NodeId::Ipv6(*addr.ip()),
    };
    ctx.recovery_time_stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    log::info!("PFCP path opened on {local_addr}");
    Ok(())
}

/// Close PFCP path (cleanup)
/// Port of upf_pfcp_close
pub fn pfcp_close(ctx: &mut PfcpPathContext) {
    ctx.peer_nodes.clear();
    ctx.transactions.clear();
    ctx.local_addr = None;
    log::info!("PFCP path closed");
}

// ============================================================================
// PFCP Session Event (for data plane notification)
// ============================================================================

/// Event sent to data plane when PFCP session is created/modified/deleted
#[derive(Debug, Clone)]
pub enum PfcpSessionEvent {
    /// Session established - create forwarding rules
    SessionEstablished {
        upf_seid: u64,
        smf_seid: u64,
        /// UE IPv4 address assigned
        ue_ipv4: Option<Ipv4Addr>,
        /// Uplink TEID (UPF receives from gNB)
        ul_teid: u32,
        /// Downlink TEID (UPF sends to gNB)
        dl_teid: u32,
        /// gNB address for downlink
        gnb_addr: Option<Ipv4Addr>,
        /// Parsed PDR rules from PFCP
        pdrs: Vec<ParsedCreatePdr>,
        /// Parsed FAR rules from PFCP
        fars: Vec<ParsedCreateFar>,
        /// Parsed QER rules from PFCP
        qers: Vec<ParsedCreateQer>,
        /// Parsed URR rules from PFCP
        urrs: Vec<ParsedCreateUrr>,
        /// Parsed BAR rules from PFCP
        bars: Vec<ParsedCreateBar>,
    },
    /// Session modified - update forwarding rules
    SessionModified {
        upf_seid: u64,
        /// Updated downlink TEID
        dl_teid: Option<u32>,
        /// Updated gNB address
        gnb_addr: Option<Ipv4Addr>,
        /// Updated FAR rules
        updated_fars: Vec<ParsedCreateFar>,
        /// Updated QERs
        updated_qers: Vec<ParsedCreateQer>,
        /// Created/updated BARs
        updated_bars: Vec<ParsedCreateBar>,
        /// SMF requested End Marker packets on the old DL tunnel (SNDEM)
        send_end_marker: bool,
        /// SMF requested buffered packets to be dropped (DROBU)
        drop_buffered: bool,
        /// DL tunnel endpoint before this modification (TEID, gNB address)
        old_dl_tunnel: Option<(u32, Ipv4Addr)>,
    },
    /// Session deleted - remove forwarding rules
    SessionDeleted {
        upf_seid: u64,
        ue_ipv4: Option<Ipv4Addr>,
    },
    /// The control-plane peer restarted (Recovery Time Stamp changed) or the
    /// association was released: all sessions belonging to it are stale and
    /// must be removed (TS 23.527 4.2).
    PeerFailure { peer: SocketAddr },
}

// ============================================================================
// Async PFCP Server
// ============================================================================

/// State of the PFCP association with a control-plane peer (TS 29.244 6.2.6)
#[derive(Debug, Clone)]
pub struct PfcpAssociation {
    pub peer_addr: SocketAddr,
    /// The peer's Recovery Time Stamp from Association Setup / Heartbeat —
    /// a change means the peer restarted and all its sessions are stale
    pub recovery_time_stamp: u32,
}

/// PFCP request retransmission timer T1 (TS 29.244 / Open5GS default 3s).
/// A request message (e.g. a Session Report Request carrying a Downlink Data
/// Report) is retransmitted if no response arrives within this window.
pub const PFCP_T1_DURATION: std::time::Duration = std::time::Duration::from_secs(3);

/// PFCP maximum retransmission count N1 (TS 29.244 / Open5GS default 3).
/// After the original transmission plus N1 retransmissions go unanswered, the
/// request is abandoned and the peer is treated as unresponsive.
pub const PFCP_N1_MAX_RETRANSMIT: u32 = 3;

/// A request message awaiting a response, tracked for T1/N1 retransmission
/// (TS 29.244 §7.2.2.3). Keyed by PFCP sequence number.
#[derive(Debug, Clone)]
pub struct PendingReport {
    /// Fully encoded PFCP request message (resent verbatim with same seq).
    pub message: Vec<u8>,
    /// Destination (the CP function / SMF address).
    pub dest: SocketAddr,
    /// UPF SEID of the owning session (for diagnostics / give-up cleanup).
    pub upf_seid: u64,
    /// Number of retransmissions performed so far (0 = only the original sent).
    pub attempts: u32,
    /// When the current (re)transmission was sent.
    pub last_sent: std::time::Instant,
}

/// Async PFCP server for handling SMF requests
pub struct PfcpServer {
    socket: Arc<UdpSocket>,
    _local_addr: SocketAddr,
    local_node_id: NodeId,
    recovery_time_stamp: u32,
    next_seid: AtomicU64,
    next_teid: AtomicU32,
    /// Sequence numbers for UPF-initiated requests (Session Report, Heartbeat)
    next_seq: AtomicU32,
    shutdown: Arc<AtomicBool>,
    /// Channel to send session events to data plane
    session_tx: mpsc::Sender<PfcpSessionEvent>,
    /// Active sessions: UPF SEID -> SessionInfo
    sessions: tokio::sync::RwLock<HashMap<u64, PfcpSessionInfo>>,
    /// Current PFCP association (None until Association Setup succeeds)
    association: tokio::sync::RwLock<Option<PfcpAssociation>>,
    /// Data plane handle for pulling final URR counters on session deletion
    data_plane: std::sync::RwLock<Option<Arc<crate::data_plane::DataPlane>>>,
    /// UPF-initiated requests awaiting a response, tracked by sequence number
    /// for T1/N1 retransmission (TS 29.244 §7.2.2.3). Currently used for
    /// Session Report Requests (Downlink Data / Error Indication Reports).
    pending_reports: tokio::sync::Mutex<HashMap<u32, PendingReport>>,
}

/// PFCP session information stored in server
#[derive(Debug, Clone)]
pub struct PfcpSessionInfo {
    pub upf_seid: u64,
    pub smf_seid: u64,
    pub smf_addr: SocketAddr,
    pub ue_ipv4: Option<Ipv4Addr>,
    pub ul_teid: u32,
    pub dl_teid: u32,
    pub gnb_addr: Option<Ipv4Addr>,
}

impl PfcpServer {
    /// Create a new PFCP server
    pub async fn new(
        local_addr: SocketAddr,
        shutdown: Arc<AtomicBool>,
        session_tx: mpsc::Sender<PfcpSessionEvent>,
    ) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(local_addr).await?;
        log::info!("PFCP server bound to {local_addr}");

        let local_node_id = match local_addr {
            SocketAddr::V4(addr) => NodeId::Ipv4(*addr.ip()),
            SocketAddr::V6(addr) => NodeId::Ipv6(*addr.ip()),
        };

        let recovery_time_stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        Ok(Self {
            socket: Arc::new(socket),
            _local_addr: local_addr,
            local_node_id,
            recovery_time_stamp,
            next_seid: AtomicU64::new(1),
            next_teid: AtomicU32::new(0x10000), // Start TEIDs from 0x10000
            next_seq: AtomicU32::new(1),
            shutdown,
            session_tx,
            sessions: tokio::sync::RwLock::new(HashMap::new()),
            association: tokio::sync::RwLock::new(None),
            data_plane: std::sync::RwLock::new(None),
            pending_reports: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Allocate a new SEID
    fn alloc_seid(&self) -> u64 {
        self.next_seid.fetch_add(1, Ordering::SeqCst)
    }

    /// Allocate a new TEID
    fn alloc_teid(&self) -> u32 {
        self.next_teid.fetch_add(1, Ordering::SeqCst)
    }

    /// Allocate the next sequence number for a UPF-initiated request
    fn alloc_seq(&self) -> u32 {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst) & 0x00FF_FFFF;
        if seq == 0 {
            self.next_seq.fetch_add(1, Ordering::SeqCst) & 0x00FF_FFFF
        } else {
            seq
        }
    }

    /// Whether a PFCP association with a CP function is currently up
    pub async fn is_associated(&self) -> bool {
        self.association.read().await.is_some()
    }

    /// Handle a peer restart or association teardown: drop the association,
    /// clear all sessions, and tell the data plane to flush its state.
    async fn declare_peer_failure(&self, peer: SocketAddr, reason: &str) {
        log::warn!("PFCP peer {peer} failure ({reason}): clearing association and sessions");
        *self.association.write().await = None;
        let count = {
            let mut sessions = self.sessions.write().await;
            let n = sessions.len();
            sessions.clear();
            n
        };
        log::warn!("Cleared {count} PFCP sessions after peer failure");
        let _ = self
            .session_tx
            .send(PfcpSessionEvent::PeerFailure { peer })
            .await;
    }

    /// Run the PFCP server main loop
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let mut buf = vec![0u8; 65536];
        log::info!("PFCP server starting main loop");

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                log::info!("PFCP server shutting down");
                break;
            }

            // Use timeout to check shutdown periodically
            let recv_result = tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                self.socket.recv_from(&mut buf),
            )
            .await;

            match recv_result {
                Ok(Ok((len, src_addr))) => {
                    let data = &buf[..len];
                    log::debug!("PFCP received {len} bytes from {src_addr}");

                    if let Err(e) = self.handle_message(data, src_addr).await {
                        log::error!("PFCP message handling error: {e}");
                    }
                }
                Ok(Err(e)) => {
                    log::error!("PFCP socket error: {e}");
                }
                Err(_) => {
                    // Timeout - continue loop
                }
            }

            // Drive PFCP request retransmission (T1) / give-up (N1) for any
            // outstanding Session Report Requests (TS 29.244 §7.2.2.3). The
            // 100ms recv timeout gives this a sub-second polling cadence,
            // well under the multi-second T1 window.
            self.retransmit_pending_reports().await;
        }

        Ok(())
    }

    /// Handle incoming PFCP message
    async fn handle_message(&self, data: &[u8], src_addr: SocketAddr) -> Result<(), String> {
        let (header, payload) = ParsedPfcpHeader::parse(data).map_err(|e| e.to_string())?;

        log::debug!(
            "PFCP message: type={}, seq={}, seid={:#x}",
            header.msg_type,
            header.sequence_number,
            header.seid
        );

        match header.msg_type {
            pfcp_type::HEARTBEAT_REQUEST => {
                self.handle_heartbeat_request(&header, payload, src_addr)
                    .await?;
            }
            pfcp_type::HEARTBEAT_RESPONSE => {
                // Response to a UPF-initiated heartbeat: check the peer's
                // recovery timestamp for restart detection
                if let Some(rts) = parse_recovery_time_stamp(payload) {
                    self.check_peer_recovery(src_addr, rts).await;
                }
            }
            pfcp_type::ASSOCIATION_SETUP_REQUEST => {
                self.handle_association_setup_request(&header, payload, src_addr)
                    .await?;
            }
            pfcp_type::ASSOCIATION_RELEASE_REQUEST => {
                self.handle_association_release_request(&header, src_addr)
                    .await?;
            }
            pfcp_type::SESSION_ESTABLISHMENT_REQUEST => {
                self.handle_session_establishment_request(&header, payload, src_addr)
                    .await?;
            }
            pfcp_type::SESSION_MODIFICATION_REQUEST => {
                self.handle_session_modification_request(&header, payload, src_addr)
                    .await?;
            }
            pfcp_type::SESSION_DELETION_REQUEST => {
                self.handle_session_deletion_request(&header, payload, src_addr)
                    .await?;
            }
            pfcp_type::SESSION_REPORT_RESPONSE => {
                // Response to a UPF-initiated Session Report Request: clear the
                // matching pending request so T1/N1 retransmission stops
                // (TS 29.244 §7.2.2.3).
                let removed = self
                    .pending_reports
                    .lock()
                    .await
                    .remove(&header.sequence_number)
                    .is_some();
                let ies = ParsedIe::parse_all(payload);
                let cause = ParsedIe::find_ie(&ies, pfcp_ie::CAUSE)
                    .and_then(|ie| ie.value.first().copied())
                    .unwrap_or(0);
                if cause == PfcpCause::RequestAccepted as u8 {
                    log::debug!(
                        "Session Report accepted (seq={}, tracked={removed})",
                        header.sequence_number
                    );
                } else {
                    log::warn!(
                        "Session Report rejected: cause={cause} (seq={})",
                        header.sequence_number
                    );
                }
            }
            _ => {
                log::warn!("Unhandled PFCP message type: {}", header.msg_type);
            }
        }

        Ok(())
    }

    /// Compare a peer-reported Recovery Time Stamp against the stored
    /// association; a change means the peer restarted (TS 29.244 6.2.7.2).
    async fn check_peer_recovery(&self, src_addr: SocketAddr, rts: u32) {
        let restarted = {
            let assoc = self.association.read().await;
            match assoc.as_ref() {
                Some(a) => a.recovery_time_stamp != rts,
                None => false,
            }
        };
        if restarted {
            self.declare_peer_failure(src_addr, "recovery time stamp changed")
                .await;
        }
    }

    /// Handle Heartbeat Request
    async fn handle_heartbeat_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        log::debug!("Handling Heartbeat Request from {src_addr}");

        // Peer restart detection from the Recovery Time Stamp (mandatory IE)
        if let Some(rts) = parse_recovery_time_stamp(payload) {
            self.check_peer_recovery(src_addr, rts).await;
        } else {
            log::warn!("Heartbeat Request from {src_addr} missing Recovery Time Stamp");
        }

        let payload = build_heartbeat_response(self.recovery_time_stamp);
        let response = self.build_response(
            pfcp_type::HEARTBEAT_RESPONSE,
            0, // No SEID for heartbeat
            header.sequence_number,
            &payload,
            false, // No SEID in header
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        log::debug!("Sent Heartbeat Response to {src_addr}");
        Ok(())
    }

    /// Handle Association Setup Request
    async fn handle_association_setup_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        log::info!("Handling Association Setup Request from {src_addr}");

        // Node ID and Recovery Time Stamp are mandatory (TS 29.244 7.4.4.1)
        let ies = ParsedIe::parse_all(payload);
        let node_id_present = ParsedIe::find_ie(&ies, pfcp_ie::NODE_ID).is_some();
        let rts = parse_recovery_time_stamp(payload);

        if !node_id_present || rts.is_none() {
            let offending = if node_id_present {
                pfcp_ie::RECOVERY_TIME_STAMP
            } else {
                pfcp_ie::NODE_ID
            };
            log::warn!(
                "Association Setup Request from {src_addr} missing mandatory IE {offending}"
            );
            let resp_payload =
                build_failure_response(PfcpCause::MandatoryIeMissing, Some(offending));
            let response = self.build_response(
                pfcp_type::ASSOCIATION_SETUP_RESPONSE,
                0,
                header.sequence_number,
                &resp_payload,
                false,
            );
            self.socket
                .send_to(&response, src_addr)
                .await
                .map_err(|e| format!("Send error: {e}"))?;
            return Ok(());
        }
        let rts = rts.unwrap();

        // If we already had an association with a different recovery
        // timestamp, the peer restarted — flush stale sessions first
        self.check_peer_recovery(src_addr, rts).await;

        *self.association.write().await = Some(PfcpAssociation {
            peer_addr: src_addr,
            recovery_time_stamp: rts,
        });

        let resp_payload = build_association_setup_response(
            &self.local_node_id,
            self.recovery_time_stamp,
            PfcpCause::RequestAccepted,
        );

        let response = self.build_response(
            pfcp_type::ASSOCIATION_SETUP_RESPONSE,
            0,
            header.sequence_number,
            &resp_payload,
            false,
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        log::info!("PFCP Association established with {src_addr} (peer RTS={rts})");
        Ok(())
    }

    /// Handle Association Release Request (TS 29.244 7.4.4.2): acknowledge,
    /// drop the association, and delete all sessions belonging to the peer.
    async fn handle_association_release_request(
        &self,
        header: &ParsedPfcpHeader,
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        log::info!("Handling Association Release Request from {src_addr}");

        let resp_payload =
            build_association_release_response(&self.local_node_id, PfcpCause::RequestAccepted);
        let response = self.build_response(
            pfcp_type::ASSOCIATION_RELEASE_RESPONSE,
            0,
            header.sequence_number,
            &resp_payload,
            false,
        );
        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        self.declare_peer_failure(src_addr, "association released by peer")
            .await;
        Ok(())
    }

    /// Send a Heartbeat Request to the associated CP peer (UPF-initiated
    /// direction, TS 29.244 7.4.2). Returns the peer address if one was sent.
    pub async fn send_heartbeat_request(&self) -> Option<SocketAddr> {
        let peer = self.association.read().await.as_ref()?.peer_addr;
        let seq = self.alloc_seq();
        // Issue #20 (compute-aware-upf): piggy-back the session-occupancy
        // load metric on the periodic heartbeat as a Load Control
        // Information IE. The LCI sequence number reuses this request's
        // monotonic PFCP sequence number so the SMF can discard stale
        // updates. Off by default: the wire bytes are unchanged unless the
        // feature is enabled.
        #[cfg(feature = "compute-aware-upf")]
        let payload = crate::n4_build::build_heartbeat_request_with_load(
            self.recovery_time_stamp,
            seq,
            crate::context::upf_self().get_load(),
        );
        #[cfg(not(feature = "compute-aware-upf"))]
        let payload = crate::n4_build::build_heartbeat_request(self.recovery_time_stamp);
        let message = self.build_response(pfcp_type::HEARTBEAT_REQUEST, 0, seq, &payload, false);
        match self.socket.send_to(&message, peer).await {
            Ok(_) => {
                log::debug!("Sent Heartbeat Request to {peer} (seq={seq})");
                Some(peer)
            }
            Err(e) => {
                log::warn!("Failed to send Heartbeat Request to {peer}: {e}");
                None
            }
        }
    }

    /// Handle Session Establishment Request
    async fn handle_session_establishment_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        log::info!("Handling Session Establishment Request from {src_addr}");

        let ies = ParsedIe::parse_all(payload);

        // TS 29.244 6.2.6.2: session messages require an established
        // PFCP association with the peer
        if !self.is_associated().await {
            log::warn!("Session Establishment from {src_addr} without PFCP association");
            let resp_payload =
                build_failure_response(PfcpCause::NoEstablishedPfcpAssociation, None);
            let response = self.build_response(
                pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
                header.seid,
                header.sequence_number,
                &resp_payload,
                true,
            );
            self.socket
                .send_to(&response, src_addr)
                .await
                .map_err(|e| format!("Send error: {e}"))?;
            return Ok(());
        }

        // Mandatory IEs per TS 29.244 Table 7.5.2.1-1: Node ID, CP F-SEID,
        // Create PDR, Create FAR
        let missing_ie = if ParsedIe::find_ie(&ies, pfcp_ie::NODE_ID).is_none() {
            Some(pfcp_ie::NODE_ID)
        } else if ParsedIe::find_ie(&ies, pfcp_ie::F_SEID).is_none() {
            Some(pfcp_ie::F_SEID)
        } else if ParsedIe::find_ie(&ies, pfcp_ie::CREATE_PDR).is_none() {
            Some(pfcp_ie::CREATE_PDR)
        } else if ParsedIe::find_ie(&ies, pfcp_ie::CREATE_FAR).is_none() {
            Some(pfcp_ie::CREATE_FAR)
        } else {
            None
        };
        if let Some(offending) = missing_ie {
            log::warn!(
                "Session Establishment from {src_addr} missing mandatory IE {offending} — rejecting"
            );
            let resp_payload =
                build_failure_response(PfcpCause::MandatoryIeMissing, Some(offending));
            let response = self.build_response(
                pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
                header.seid,
                header.sequence_number,
                &resp_payload,
                true,
            );
            self.socket
                .send_to(&response, src_addr)
                .await
                .map_err(|e| format!("Send error: {e}"))?;
            return Ok(());
        }

        // Parse CP F-SEID (SMF's SEID) — presence checked above
        let f_seid_ie = ParsedIe::find_ie(&ies, pfcp_ie::F_SEID).unwrap();
        let smf_seid = match ParsedFSeid::parse(&f_seid_ie.value) {
            Ok(f_seid) => {
                log::debug!("SMF F-SEID: {:#x}", f_seid.seid);
                f_seid.seid
            }
            Err(e) => {
                log::warn!("Malformed CP F-SEID from {src_addr}: {e}");
                let resp_payload =
                    build_failure_response(PfcpCause::MandatoryIeIncorrect, Some(pfcp_ie::F_SEID));
                let response = self.build_response(
                    pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
                    header.seid,
                    header.sequence_number,
                    &resp_payload,
                    true,
                );
                self.socket
                    .send_to(&response, src_addr)
                    .await
                    .map_err(|e| format!("Send error: {e}"))?;
                return Ok(());
            }
        };

        // Allocate UPF SEID
        let upf_seid = self.alloc_seid();
        log::debug!("Allocated UPF SEID: {upf_seid:#x}");

        // Parse Create PDRs
        let mut ue_ipv4: Option<Ipv4Addr> = None;
        let mut ul_teid: u32 = 0;
        let mut created_pdrs = Vec::new();
        let mut parsed_pdrs = Vec::new();

        for pdr_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_PDR) {
            match parse_create_pdr(&pdr_ie.value) {
                Ok(pdr) => {
                    log::debug!(
                        "PDR {}: src_if={}, precedence={}, far_id={:?}, qer_id={:?}, urr_ids={:?}",
                        pdr.pdr_id,
                        pdr.pdi.source_interface,
                        pdr.precedence,
                        pdr.far_id,
                        pdr.qer_id,
                        pdr.urr_ids,
                    );

                    // Check if this PDR needs a local F-TEID (uplink PDR).
                    //
                    // The SMF asks the UPF to allocate the N3 uplink F-TEID in
                    // one of two ways (TS 29.244 8.2.3 / 7.5.3.2):
                    //   * CH (CHOOSE) flag set — the canonical "UP function
                    //     shall assign the F-TEID" request, with TEID/address
                    //     omitted on the wire; or
                    //   * a PDI F-TEID with TEID == 0 (no concrete tunnel to
                    //     bind to). Our SMF signals allocation this way.
                    // In either case the UPF allocates a fresh non-zero TEID +
                    // its N3 GTP-U address and returns it in the Created PDR so
                    // uplink GTP-U traffic matches.
                    let local_f_teid = if let Some(ref fteid) = pdr.pdi.local_f_teid {
                        if fteid.ch || fteid.teid == 0 {
                            ul_teid = self.alloc_teid();
                            log::debug!(
                                "Allocated uplink F-TEID: teid={ul_teid:#x} (ch={})",
                                fteid.ch
                            );
                            Some(FTeid {
                                teid: ul_teid,
                                ipv4: match &self.local_node_id {
                                    NodeId::Ipv4(addr) => Some(*addr),
                                    _ => None,
                                },
                                ipv6: None,
                                choose: false,
                                choose_id: None,
                            })
                        } else {
                            ul_teid = fteid.teid;
                            None
                        }
                    } else {
                        None
                    };

                    // Extract UE IP address
                    if let Some(ref ue_ip) = pdr.pdi.ue_ip_address {
                        if let Some(addr) = ue_ip.ipv4 {
                            ue_ipv4 = Some(addr);
                            log::debug!("UE IPv4: {addr}");
                        }
                    }

                    created_pdrs.push(CreatedPdr {
                        pdr_id: pdr.pdr_id,
                        local_f_teid,
                        ue_ip_address: None,
                    });
                    parsed_pdrs.push(pdr);
                }
                Err(e) => {
                    log::warn!("Failed to parse PDR: {e}");
                }
            }
        }

        // Parse Create FARs
        let mut dl_teid: u32 = 0;
        let mut gnb_addr: Option<Ipv4Addr> = None;
        let mut parsed_fars = Vec::new();

        for far_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_FAR) {
            match parse_create_far(&far_ie.value) {
                Ok(far) => {
                    log::debug!("FAR {}: apply_action={:#x}", far.far_id, far.apply_action);

                    if let Some(ref fp) = far.forwarding_parameters {
                        if let Some(ref ohc) = fp.outer_header_creation {
                            dl_teid = ohc.teid;
                            gnb_addr = ohc.ipv4;
                            log::debug!("Downlink: TEID={dl_teid:#x}, gNB={gnb_addr:?}");
                        }
                    }
                    parsed_fars.push(far);
                }
                Err(e) => {
                    log::warn!("Failed to parse FAR: {e}");
                }
            }
        }

        // Parse Create QERs
        let mut parsed_qers = Vec::new();
        for qer_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_QER) {
            match parse_create_qer(&qer_ie.value) {
                Ok(qer) => {
                    log::debug!(
                        "QER {}: ul_gate={}, dl_gate={}, ul_mbr={}, dl_mbr={}, qfi={:?}",
                        qer.qer_id,
                        qer.ul_gate,
                        qer.dl_gate,
                        qer.ul_mbr,
                        qer.dl_mbr,
                        qer.qfi
                    );
                    parsed_qers.push(qer);
                }
                Err(e) => {
                    log::warn!("Failed to parse QER: {e}");
                }
            }
        }

        // Parse Create URRs
        let mut parsed_urrs = Vec::new();
        for urr_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_URR) {
            match parse_create_urr(&urr_ie.value) {
                Ok(urr) => {
                    log::debug!(
                        "URR {}: vol_thresh={:?}, time_thresh={:?}",
                        urr.urr_id,
                        urr.volume_threshold_total,
                        urr.time_threshold_secs
                    );
                    parsed_urrs.push(urr);
                }
                Err(e) => {
                    log::warn!("Failed to parse URR: {e}");
                }
            }
        }

        // Parse Create BARs
        let mut parsed_bars = Vec::new();
        for bar_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_BAR) {
            match parse_create_bar(&bar_ie.value) {
                Ok(bar) => {
                    log::debug!(
                        "BAR {}: suggested_pkts={:?}, ddn_delay={:?}",
                        bar.bar_id,
                        bar.suggested_buffering_packets_count,
                        bar.ddn_delay
                    );
                    parsed_bars.push(bar);
                }
                Err(e) => {
                    log::warn!("Failed to parse BAR: {e}");
                }
            }
        }

        // Build response
        let f_seid = FSeid {
            seid: upf_seid,
            ipv4: match &self.local_node_id {
                NodeId::Ipv4(addr) => Some(*addr),
                _ => None,
            },
            ipv6: None,
        };

        let resp_payload = build_session_establishment_response(
            pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            upf_seid,
            &self.local_node_id,
            &f_seid,
            &created_pdrs,
        );

        let response = self.build_response(
            pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            smf_seid,
            header.sequence_number,
            &resp_payload,
            true,
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        // Store session info
        let session_info = PfcpSessionInfo {
            upf_seid,
            smf_seid,
            smf_addr: src_addr,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(upf_seid, session_info.clone());
        }

        // Notify data plane with full rule set
        let event = PfcpSessionEvent::SessionEstablished {
            upf_seid,
            smf_seid,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
            pdrs: parsed_pdrs,
            fars: parsed_fars,
            qers: parsed_qers,
            urrs: parsed_urrs,
            bars: parsed_bars,
        };

        if let Err(e) = self.session_tx.send(event).await {
            log::error!("Failed to send session event: {e}");
        }

        log::info!(
            "Session established: UPF_SEID={upf_seid:#x}, SMF_SEID={smf_seid:#x}, UE_IP={ue_ipv4:?}, UL_TEID={ul_teid:#x}, DL_TEID={dl_teid:#x}"
        );

        Ok(())
    }

    /// Handle Session Modification Request
    async fn handle_session_modification_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        let upf_seid = header.seid;
        log::info!("Handling Session Modification Request for SEID {upf_seid:#x}");

        let ies = ParsedIe::parse_all(payload);

        // Parse Update FARs
        let mut updated_dl_teid: Option<u32> = None;
        let mut updated_gnb_addr: Option<Ipv4Addr> = None;
        let mut mod_fars = Vec::new();

        // Update FAR IE type = 10
        for far_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::UPDATE_FAR) {
            match parse_create_far(&far_ie.value) {
                Ok(far) => {
                    log::debug!(
                        "Update FAR {}: apply_action={:#x}",
                        far.far_id,
                        far.apply_action
                    );
                    if let Some(ref fp) = far.forwarding_parameters {
                        if let Some(ref ohc) = fp.outer_header_creation {
                            updated_dl_teid = Some(ohc.teid);
                            updated_gnb_addr = ohc.ipv4;
                            log::debug!(
                                "Updated downlink: TEID={:#x}, gNB={:?}",
                                ohc.teid,
                                ohc.ipv4
                            );
                        }
                    }
                    mod_fars.push(far);
                }
                Err(e) => {
                    log::warn!("Failed to parse Update FAR: {e}");
                }
            }
        }

        // Parse Update QERs (IE type 14)
        let mut mod_qers = Vec::new();
        for qer_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::UPDATE_QER) {
            match parse_create_qer(&qer_ie.value) {
                Ok(qer) => {
                    log::debug!("Update QER {}: qfi={:?}", qer.qer_id, qer.qfi);
                    mod_qers.push(qer);
                }
                Err(e) => {
                    log::warn!("Failed to parse Update QER: {e}");
                }
            }
        }

        // Parse Create/Update BARs
        let mut mod_bars = Vec::new();
        for bar_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_BAR)
            .into_iter()
            .chain(ParsedIe::find_all_ies(&ies, pfcp_ie::UPDATE_BAR))
        {
            match parse_create_bar(&bar_ie.value) {
                Ok(bar) => mod_bars.push(bar),
                Err(e) => log::warn!("Failed to parse BAR: {e}"),
            }
        }

        // PFCPSMReq-Flags (TS 29.244 8.2.50): SNDEM → emit End Marker on the
        // old DL tunnel; DROBU → discard buffered DL packets
        let smreq_flags = parse_pfcpsmreq_flags(payload).unwrap_or(0);
        let send_end_marker = smreq_flags & pfcpsmreq_flags::SNDEM != 0;
        let drop_buffered = smreq_flags & pfcpsmreq_flags::DROBU != 0;

        // Update session info; respond Session Context Not Found for an
        // unknown SEID (TS 29.244 7.5.5, cause 65)
        let lookup = {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(&upf_seid) {
                let old_tunnel = session.gnb_addr.map(|addr| (session.dl_teid, addr));
                if let Some(teid) = updated_dl_teid {
                    session.dl_teid = teid;
                }
                if let Some(addr) = updated_gnb_addr {
                    session.gnb_addr = Some(addr);
                }
                Some((session.smf_seid, old_tunnel))
            } else {
                None
            }
        };
        let (smf_seid, old_dl_tunnel) = match lookup {
            Some(v) => v,
            None => {
                log::warn!("Session Modification for unknown SEID {upf_seid:#x} — rejecting");
                let resp_payload = build_failure_response(PfcpCause::SessionContextNotFound, None);
                let response = self.build_response(
                    pfcp_type::SESSION_MODIFICATION_RESPONSE,
                    0, // CP SEID unknown
                    header.sequence_number,
                    &resp_payload,
                    true,
                );
                self.socket
                    .send_to(&response, src_addr)
                    .await
                    .map_err(|e| format!("Send error: {e}"))?;
                return Ok(());
            }
        };

        // Build response
        let resp_payload = build_session_modification_response(
            pfcp_type::SESSION_MODIFICATION_RESPONSE,
            &[], // No created PDRs for modification
        );

        let response = self.build_response(
            pfcp_type::SESSION_MODIFICATION_RESPONSE,
            smf_seid,
            header.sequence_number,
            &resp_payload,
            true,
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        // Notify data plane
        let has_changes = updated_dl_teid.is_some()
            || updated_gnb_addr.is_some()
            || !mod_fars.is_empty()
            || !mod_qers.is_empty()
            || !mod_bars.is_empty()
            || send_end_marker
            || drop_buffered;

        if has_changes {
            let event = PfcpSessionEvent::SessionModified {
                upf_seid,
                dl_teid: updated_dl_teid,
                gnb_addr: updated_gnb_addr,
                updated_fars: mod_fars,
                updated_qers: mod_qers,
                updated_bars: mod_bars,
                send_end_marker,
                drop_buffered,
                old_dl_tunnel,
            };

            if let Err(e) = self.session_tx.send(event).await {
                log::error!("Failed to send session event: {e}");
            }
        }

        log::info!("Session {upf_seid:#x} modified");
        Ok(())
    }

    /// Handle Session Deletion Request
    async fn handle_session_deletion_request(
        &self,
        header: &ParsedPfcpHeader,
        _payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        let upf_seid = header.seid;
        log::info!("Handling Session Deletion Request for SEID {upf_seid:#x}");

        // Remove session
        let session_info = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&upf_seid)
        };

        // Unknown SEID → Session Context Not Found (TS 29.244 7.5.7, cause 65)
        let session_info = match session_info {
            Some(info) => info,
            None => {
                log::warn!("Session Deletion for unknown SEID {upf_seid:#x} — rejecting");
                let resp_payload = build_failure_response(PfcpCause::SessionContextNotFound, None);
                let response = self.build_response(
                    pfcp_type::SESSION_DELETION_RESPONSE,
                    0,
                    header.sequence_number,
                    &resp_payload,
                    true,
                );
                self.socket
                    .send_to(&response, src_addr)
                    .await
                    .map_err(|e| format!("Send error: {e}"))?;
                return Ok(());
            }
        };
        let smf_seid = session_info.smf_seid;
        let ue_ipv4 = session_info.ue_ipv4;

        // Final usage reports (TS 29.244 7.5.7.1: Usage Report within
        // Session Deletion Response with the TERMR trigger) pulled from the
        // data-plane URR accounting state
        let usage_reports = self.collect_final_usage_reports(upf_seid);
        let resp_payload =
            build_session_deletion_response(pfcp_type::SESSION_DELETION_RESPONSE, &usage_reports);

        let response = self.build_response(
            pfcp_type::SESSION_DELETION_RESPONSE,
            smf_seid,
            header.sequence_number,
            &resp_payload,
            true,
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        // Notify data plane
        let event = PfcpSessionEvent::SessionDeleted { upf_seid, ue_ipv4 };

        if let Err(e) = self.session_tx.send(event).await {
            log::error!("Failed to send session event: {e}");
        }

        log::info!("Session {upf_seid:#x} deleted");
        Ok(())
    }

    /// Attach the data plane so PFCP handlers can pull final URR counters
    /// for Session Deletion Responses.
    pub fn set_data_plane(&self, dp: Arc<crate::data_plane::DataPlane>) {
        *self.data_plane.write().unwrap() = Some(dp);
    }

    /// Collect final usage reports (TERMR trigger) from the data-plane URRs
    /// of a session that is being deleted.
    fn collect_final_usage_reports(&self, upf_seid: u64) -> Vec<crate::n4_build::UsageReport> {
        let dp = match self.data_plane.read().unwrap().clone() {
            Some(dp) => dp,
            None => return Vec::new(),
        };
        let session = match dp.sessions.find_by_seid(upf_seid) {
            Some(s) => s,
            None => return Vec::new(),
        };
        let urrs = session.urrs.read().unwrap();
        urrs.values()
            .map(|urr| {
                let mut trigger = crate::n4_build::UsageReportTrigger::default();
                trigger.termination_report = true;
                crate::n4_build::UsageReport {
                    urr_id: urr.urr_id,
                    ur_seqn: urr.next_ur_seqn(),
                    trigger,
                    volume_measurement: Some(crate::n4_build::VolumeMeasurement {
                        total_volume: Some(
                            urr.acc_total_bytes
                                .load(std::sync::atomic::Ordering::Relaxed),
                        ),
                        uplink_volume: Some(
                            urr.acc_ul_bytes.load(std::sync::atomic::Ordering::Relaxed),
                        ),
                        downlink_volume: Some(
                            urr.acc_dl_bytes.load(std::sync::atomic::Ordering::Relaxed),
                        ),
                        total_packets: Some(
                            urr.acc_total_pkts
                                .load(std::sync::atomic::Ordering::Relaxed),
                        ),
                        uplink_packets: Some(
                            urr.acc_ul_pkts.load(std::sync::atomic::Ordering::Relaxed),
                        ),
                        downlink_packets: Some(
                            urr.acc_dl_pkts.load(std::sync::atomic::Ordering::Relaxed),
                        ),
                    }),
                    ..Default::default()
                }
            })
            .collect()
    }

    /// Send a Session Report Request carrying a Downlink Data Report
    /// (TS 29.244 7.5.8.2) when the first DL packet is buffered under a
    /// BUFF+NOCP FAR.
    pub async fn send_downlink_data_report(
        &self,
        upf_seid: u64,
        smf_seid: u64,
        pdr_id: u16,
        qfi: Option<u8>,
    ) -> Result<(), String> {
        let smf_addr = {
            let sessions = self.sessions.read().await;
            sessions.get(&upf_seid).map(|s| s.smf_addr)
        }
        .ok_or_else(|| format!("Session {upf_seid:#x} not found for DL data report"))?;

        let report = UserPlaneReport {
            report_type: ReportType {
                downlink_data_report: true,
                ..Default::default()
            },
            downlink_data_report: Some(DownlinkDataReport {
                pdr_id,
                downlink_data_service_info: qfi.map(|q| DownlinkDataServiceInfo {
                    ppi: None,
                    qfi: Some(q),
                }),
            }),
            ..Default::default()
        };

        let payload = build_session_report_request(pfcp_type::SESSION_REPORT_REQUEST, &report);
        self.send_and_track_report(
            upf_seid,
            smf_seid,
            smf_addr,
            &payload,
            "Downlink Data Report",
        )
        .await?;
        log::info!(
            "Sent Downlink Data Report to {smf_addr}: SEID=0x{upf_seid:x}, PDR={pdr_id}, QFI={qfi:?}"
        );
        Ok(())
    }

    /// Send a Session Report Request carrying an Error Indication Report
    /// (TS 29.244 7.5.8.4) after a GTP-U Error Indication was received on a
    /// DL tunnel.
    pub async fn send_error_indication_report(
        &self,
        upf_seid: u64,
        smf_seid: u64,
        remote_teid: u32,
        peer_ipv4: Option<Ipv4Addr>,
    ) -> Result<(), String> {
        let smf_addr = {
            let sessions = self.sessions.read().await;
            sessions.get(&upf_seid).map(|s| s.smf_addr)
        }
        .ok_or_else(|| format!("Session {upf_seid:#x} not found for error indication report"))?;

        let report = UserPlaneReport {
            report_type: ReportType {
                error_indication_report: true,
                ..Default::default()
            },
            error_indication_report: Some(ErrorIndicationReport {
                remote_f_teid: FTeid {
                    teid: remote_teid,
                    ipv4: peer_ipv4,
                    ipv6: None,
                    choose: false,
                    choose_id: None,
                },
            }),
            ..Default::default()
        };

        let payload = build_session_report_request(pfcp_type::SESSION_REPORT_REQUEST, &report);
        self.send_and_track_report(
            upf_seid,
            smf_seid,
            smf_addr,
            &payload,
            "Error Indication Report",
        )
        .await?;
        log::info!(
            "Sent Error Indication Report to {smf_addr}: SEID=0x{upf_seid:x}, TEID=0x{remote_teid:x}"
        );
        Ok(())
    }

    /// Send a PFCP Session Report Request for URR usage reports.
    /// Called by the URR threshold check task when thresholds are exceeded.
    pub async fn send_urr_report(
        &self,
        upf_seid: u64,
        smf_seid: u64,
        reports: Vec<crate::data_plane::UrrReportEntry>,
    ) -> Result<(), String> {
        // Look up the SMF address from the session
        let smf_addr = {
            let sessions = self.sessions.read().await;
            sessions.get(&upf_seid).map(|s| s.smf_addr)
        };

        let smf_addr = match smf_addr {
            Some(addr) => addr,
            None => {
                return Err(format!("Session {upf_seid:#x} not found for URR report"));
            }
        };

        // Build usage reports
        let usage_reports: Vec<crate::n4_build::UsageReport> = reports
            .iter()
            .map(|r| {
                let mut trigger = crate::n4_build::UsageReportTrigger::default();
                trigger.volume_threshold = true;

                crate::n4_build::UsageReport {
                    urr_id: r.urr_id,
                    ur_seqn: r.ur_seqn,
                    trigger,
                    volume_measurement: Some(crate::n4_build::VolumeMeasurement {
                        total_volume: Some(r.total_bytes),
                        uplink_volume: Some(r.ul_bytes),
                        downlink_volume: Some(r.dl_bytes),
                        total_packets: Some(r.total_pkts),
                        uplink_packets: Some(r.ul_pkts),
                        downlink_packets: Some(r.dl_pkts),
                    }),
                    ..Default::default()
                }
            })
            .collect();

        let user_plane_report = UserPlaneReport {
            report_type: crate::n4_build::ReportType {
                usage_report: true,
                ..Default::default()
            },
            usage_reports,
            ..Default::default()
        };

        let payload =
            build_session_report_request(pfcp_type::SESSION_REPORT_REQUEST, &user_plane_report);

        self.send_and_track_report(
            upf_seid,
            smf_seid,
            smf_addr,
            &payload,
            "Session Report Request (URR)",
        )
        .await?;

        log::info!(
            "Sent Session Report Request to {smf_addr} for SEID={upf_seid:#x} ({} URR reports)",
            reports.len()
        );
        Ok(())
    }

    /// Build a Session Report Request from a pre-built payload, send it, and
    /// register it for T1/N1 retransmission (TS 29.244 §7.2.2.3). The request
    /// is removed from the pending set when the matching Session Report
    /// Response arrives (see `handle_message`) or abandoned after N1 retries
    /// (see `retransmit_pending_reports`).
    async fn send_and_track_report(
        &self,
        upf_seid: u64,
        smf_seid: u64,
        smf_addr: SocketAddr,
        payload: &[u8],
        what: &str,
    ) -> Result<(), String> {
        let seq = self.alloc_seq();
        let message = self.build_response(
            pfcp_type::SESSION_REPORT_REQUEST,
            smf_seid,
            seq,
            payload,
            true,
        );

        // Register BEFORE sending so a fast response cannot race the insert.
        {
            let mut pending = self.pending_reports.lock().await;
            pending.insert(
                seq,
                PendingReport {
                    message: message.clone(),
                    dest: smf_addr,
                    upf_seid,
                    attempts: 0,
                    last_sent: std::time::Instant::now(),
                },
            );
        }

        if let Err(e) = self.socket.send_to(&message, smf_addr).await {
            // Send failed outright: drop the pending entry, nothing to retry on.
            self.pending_reports.lock().await.remove(&seq);
            return Err(format!("Failed to send {what}: {e}"));
        }
        Ok(())
    }

    /// Retransmit any Session Report Requests whose T1 timer has expired and
    /// abandon those that have exhausted N1 retransmissions (TS 29.244
    /// §7.2.2.3). Called periodically from the server run loop.
    async fn retransmit_pending_reports(&self) {
        // Collect work under the lock, then send without holding it.
        let now = std::time::Instant::now();
        let mut to_send: Vec<(u32, Vec<u8>, SocketAddr)> = Vec::new();
        let mut gave_up: Vec<(u32, u64)> = Vec::new();
        {
            let mut pending = self.pending_reports.lock().await;
            pending.retain(|&seq, p| {
                if now.duration_since(p.last_sent) < PFCP_T1_DURATION {
                    return true; // T1 not yet expired
                }
                if p.attempts >= PFCP_N1_MAX_RETRANSMIT {
                    // N1 exhausted: give up on this request.
                    gave_up.push((seq, p.upf_seid));
                    return false;
                }
                p.attempts += 1;
                p.last_sent = now;
                to_send.push((seq, p.message.clone(), p.dest));
                true
            });
        }
        for (seq, msg, dest) in to_send {
            match self.socket.send_to(&msg, dest).await {
                Ok(_) => log::warn!(
                    "Retransmitting Session Report Request (seq={seq}) to {dest} (T1 expired)"
                ),
                Err(e) => log::error!("Failed to retransmit Session Report (seq={seq}): {e}"),
            }
        }
        for (seq, upf_seid) in gave_up {
            log::error!(
                "Session Report Request (seq={seq}, SEID=0x{upf_seid:x}) abandoned after {} retransmissions (N1) — peer unresponsive",
                PFCP_N1_MAX_RETRANSMIT
            );
        }
    }

    /// Number of Session Report Requests currently awaiting a response
    /// (test/diagnostic accessor).
    pub async fn pending_report_count(&self) -> usize {
        self.pending_reports.lock().await.len()
    }

    /// Build PFCP response message
    fn build_response(
        &self,
        msg_type: u8,
        seid: u64,
        seq: u32,
        payload: &[u8],
        seid_present: bool,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(16 + payload.len());

        // Flags: version=1, SEID present flag
        let flags = if seid_present { 0x21 } else { 0x20 };
        response.push(flags);
        response.push(msg_type);

        // Length (will be calculated)
        let length = if seid_present {
            12 + payload.len() as u16
        } else {
            4 + payload.len() as u16
        };
        response.extend_from_slice(&length.to_be_bytes());

        // SEID if present
        if seid_present {
            response.extend_from_slice(&seid.to_be_bytes());
        }

        // Sequence number (3 bytes) + spare
        response.extend_from_slice(&seq.to_be_bytes()[1..4]);
        response.push(0); // spare

        // Payload
        response.extend_from_slice(payload);

        response
    }
}

#[cfg(test)]
impl PfcpServer {
    /// Test hook: insert a session so UPF-initiated reports can resolve the
    /// CP function (SMF) address.
    async fn test_insert_session(&self, info: PfcpSessionInfo) {
        self.sessions.write().await.insert(info.upf_seid, info);
    }

    /// Test hook: force every pending report's T1 timer to be considered
    /// expired so the next `retransmit_pending_reports` acts immediately
    /// (avoids waiting the real multi-second T1 window).
    async fn test_expire_pending_t1(&self) {
        let past = std::time::Instant::now() - PFCP_T1_DURATION - std::time::Duration::from_secs(1);
        let mut pending = self.pending_reports.lock().await;
        for p in pending.values_mut() {
            p.last_sent = past;
        }
    }

    /// Test hook: the sequence number of the single pending report (panics if
    /// not exactly one).
    async fn test_only_pending_seq(&self) -> u32 {
        let pending = self.pending_reports.lock().await;
        assert_eq!(pending.len(), 1, "expected exactly one pending report");
        *pending.keys().next().unwrap()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // ------------------------------------------------------------------
    // Strict-peer test harness: a real PfcpServer on localhost plus a fake
    // SMF socket that sends raw PFCP messages and inspects the responses.
    // ------------------------------------------------------------------

    async fn spawn_test_server() -> (
        Arc<PfcpServer>,
        UdpSocket,
        SocketAddr,
        mpsc::Receiver<PfcpSessionEvent>,
    ) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel(32);
        let server = Arc::new(
            PfcpServer::new("127.0.0.1:0".parse().unwrap(), shutdown, tx)
                .await
                .unwrap(),
        );
        let server_addr = server.socket.local_addr().unwrap();
        let smf_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv = server.clone();
        tokio::spawn(async move { srv.run().await });
        (server, smf_sock, server_addr, rx)
    }

    fn encode_pfcp(msg_type: u8, seid: Option<u64>, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        match seid {
            Some(seid) => {
                pkt.push(0x21);
                pkt.push(msg_type);
                pkt.extend_from_slice(&((12 + payload.len()) as u16).to_be_bytes());
                pkt.extend_from_slice(&seid.to_be_bytes());
            }
            None => {
                pkt.push(0x20);
                pkt.push(msg_type);
                pkt.extend_from_slice(&((4 + payload.len()) as u16).to_be_bytes());
            }
        }
        pkt.extend_from_slice(&seq.to_be_bytes()[1..4]);
        pkt.push(0);
        pkt.extend_from_slice(payload);
        pkt
    }

    async fn exchange(sock: &UdpSocket, server: SocketAddr, pkt: &[u8]) -> Vec<u8> {
        sock.send_to(pkt, server).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf))
                .await
                .expect("server must respond")
                .unwrap();
        buf.truncate(len);
        buf
    }

    fn response_cause(resp: &[u8]) -> u8 {
        let (header, payload) = ParsedPfcpHeader::parse(resp).unwrap();
        let _ = header;
        let ies = ParsedIe::parse_all(payload);
        ParsedIe::find_ie(&ies, pfcp_ie::CAUSE)
            .and_then(|ie| ie.value.first().copied())
            .unwrap_or(0)
    }

    fn build_association_setup_request_payload(rts: Option<u32>) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        if let Some(rts) = rts {
            b.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, rts);
        }
        b.build()
    }

    #[tokio::test]
    async fn test_association_setup_roundtrip_and_features() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let payload = build_association_setup_request_payload(Some(0x5000_0000));
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_SETUP_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert!(server.is_associated().await);

        // The response must advertise the real UP Function Features
        // (8 feature octets; FTUP + EMPU set, nothing else)
        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        let feat = ParsedIe::find_ie(&ies, pfcp_ie::UP_FUNCTION_FEATURES)
            .expect("UP Function Features must be present");
        assert_eq!(feat.value.len(), 8, "full Rel-17 feature octets");
        let mut bytes = bytes::Bytes::copy_from_slice(&feat.value);
        let decoded = nextgcore_pfcp::types::UpFunctionFeatures::decode(&mut bytes).unwrap();
        assert!(decoded.ftup, "FTUP must be advertised");
        assert!(decoded.empu, "EMPU must be advertised");
        assert!(
            !decoded.bucp && !decoded.udbc && !decoded.quoac && !decoded.trace,
            "unimplemented features must not be advertised"
        );
        // Recovery Time Stamp must be present and non-zero
        let rts = crate::n4_build::parse_recovery_time_stamp(body).unwrap();
        assert!(rts > 0, "recovery time stamp must be real, not hardcoded 0");
    }

    #[tokio::test]
    async fn test_association_setup_missing_recovery_ts_rejected() {
        let (_server, smf, addr, _rx) = spawn_test_server().await;
        let payload = build_association_setup_request_payload(None);
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 2, &payload)).await;
        assert_eq!(response_cause(&resp), PfcpCause::MandatoryIeMissing as u8);
        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        let off = ParsedIe::find_ie(&ies, pfcp_ie::OFFENDING_IE).unwrap();
        assert_eq!(
            u16::from_be_bytes([off.value[0], off.value[1]]),
            pfcp_ie::RECOVERY_TIME_STAMP
        );
    }

    #[tokio::test]
    async fn test_session_establishment_without_association_rejected() {
        let (_server, smf, addr, _rx) = spawn_test_server().await;
        // Valid-looking establishment, but no association exists yet
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&FSeid {
            seid: 0x42,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        let resp = exchange(&smf, addr, &encode_pfcp(50, Some(0), 3, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
    }

    #[tokio::test]
    async fn test_session_establishment_missing_mandatory_ie_rejected() {
        let (_server, smf, addr, _rx) = spawn_test_server().await;
        // Associate first
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;

        // Establishment without CP F-SEID → cause 66 + Offending IE 57
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let resp = exchange(&smf, addr, &encode_pfcp(50, Some(0), 4, &b.build())).await;
        assert_eq!(resp[1], pfcp_type::SESSION_ESTABLISHMENT_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::MandatoryIeMissing as u8);
        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        let off = ParsedIe::find_ie(&ies, pfcp_ie::OFFENDING_IE).unwrap();
        assert_eq!(
            u16::from_be_bytes([off.value[0], off.value[1]]),
            pfcp_ie::F_SEID
        );
    }

    #[tokio::test]
    async fn test_session_modification_unknown_seid_rejected() {
        let (_server, smf, addr, _rx) = spawn_test_server().await;
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;

        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(0xDEAD), 5, &[])).await;
        assert_eq!(resp[1], pfcp_type::SESSION_MODIFICATION_RESPONSE);
        assert_eq!(
            response_cause(&resp),
            PfcpCause::SessionContextNotFound as u8
        );
    }

    #[tokio::test]
    async fn test_session_deletion_unknown_seid_rejected() {
        let (_server, smf, addr, _rx) = spawn_test_server().await;
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;

        let resp = exchange(&smf, addr, &encode_pfcp(54, Some(0xBEEF), 6, &[])).await;
        assert_eq!(resp[1], pfcp_type::SESSION_DELETION_RESPONSE);
        assert_eq!(
            response_cause(&resp),
            PfcpCause::SessionContextNotFound as u8
        );
    }

    #[tokio::test]
    async fn test_heartbeat_roundtrip_and_restart_detection() {
        let (server, smf, addr, mut rx) = spawn_test_server().await;
        // Associate with RTS=100
        let assoc = build_association_setup_request_payload(Some(100));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        assert!(server.is_associated().await);

        // Heartbeat with the same RTS → plain response, association kept
        let mut hb = crate::n4_build::PfcpMessageBuilder::new();
        hb.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, 100);
        let resp = exchange(&smf, addr, &encode_pfcp(1, None, 2, &hb.build())).await;
        assert_eq!(resp[1], pfcp_type::HEARTBEAT_RESPONSE);
        assert!(crate::n4_build::parse_recovery_time_stamp(
            ParsedPfcpHeader::parse(&resp).unwrap().1
        )
        .is_some());
        assert!(server.is_associated().await);

        // Heartbeat with a NEW RTS → peer restarted: association dropped and
        // a PeerFailure event raised so the data plane clears sessions
        let mut hb2 = crate::n4_build::PfcpMessageBuilder::new();
        hb2.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, 200);
        let _ = exchange(&smf, addr, &encode_pfcp(1, None, 3, &hb2.build())).await;
        assert!(!server.is_associated().await, "stale association must drop");
        let evt = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(evt, PfcpSessionEvent::PeerFailure { .. }));
    }

    #[tokio::test]
    async fn test_association_release_clears_state() {
        let (server, smf, addr, mut rx) = spawn_test_server().await;
        let assoc = build_association_setup_request_payload(Some(7));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;

        let mut rel = crate::n4_build::PfcpMessageBuilder::new();
        rel.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let resp = exchange(&smf, addr, &encode_pfcp(9, None, 2, &rel.build())).await;
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_RELEASE_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert!(!server.is_associated().await);
        let evt = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(evt, PfcpSessionEvent::PeerFailure { .. }));
    }

    #[test]
    fn test_parse_create_bar_roundtrip() {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::BAR_ID, 3);
        b.add_u8(pfcp_ie::SUGGESTED_BUFFERING_PACKETS_COUNT, 16);
        b.add_u8(pfcp_ie::DOWNLINK_DATA_NOTIFICATION_DELAY, 2);
        let bar = parse_create_bar(&b.build()).unwrap();
        assert_eq!(bar.bar_id, 3);
        assert_eq!(bar.suggested_buffering_packets_count, Some(16));
        assert_eq!(bar.ddn_delay, Some(2));

        // BAR without BAR ID must be rejected (mandatory IE)
        let mut b2 = crate::n4_build::PfcpMessageBuilder::new();
        b2.add_u8(pfcp_ie::SUGGESTED_BUFFERING_PACKETS_COUNT, 16);
        assert!(parse_create_bar(&b2.build()).is_err());
    }

    #[test]
    fn test_parse_pfcpsmreq_flags() {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::SNDEM);
        assert_eq!(
            parse_pfcpsmreq_flags(&b.build()),
            Some(pfcpsmreq_flags::SNDEM)
        );
        assert_eq!(parse_pfcpsmreq_flags(&[]), None);
    }

    #[test]
    fn test_pfcp_header_new() {
        let header = PfcpHeader::new(51, 0x1234, 1);
        assert_eq!(header.version, 1);
        assert_eq!(header.msg_type, 51);
        assert_eq!(header.seid, 0x1234);
        assert_eq!(header.sequence_number, 1);
    }

    #[test]
    fn test_pfcp_header_encode() {
        let header = PfcpHeader::new(51, 0x1234, 1);
        let encoded = header.encode(10);
        assert_eq!(encoded[0], 0x21); // version=1, SEID present
        assert_eq!(encoded[1], 51); // msg_type
                                    // length = 12 + 10 = 22
        assert_eq!(&encoded[2..4], &22u16.to_be_bytes());
    }

    #[test]
    fn test_pfcp_xact_local_create() {
        let xact = PfcpXact::local_create(1, 0x1234);
        assert_eq!(xact.sequence_number, 1);
        assert_eq!(xact.seid, 0x1234);
        assert!(xact.local);
        assert_eq!(xact.state, XactState::Initial);
    }

    #[test]
    fn test_pfcp_xact_remote_create() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        let xact = PfcpXact::remote_create(1, 0x1234, addr);
        assert!(!xact.local);
        assert_eq!(xact.remote_addr, Some(addr));
    }

    #[test]
    fn test_pfcp_xact_update_tx_and_commit() {
        let mut xact = PfcpXact::local_create(1, 0x1234);
        let header = PfcpHeader::new(56, 0x1234, 1);
        xact.update_tx(&header, vec![1, 2, 3]);
        assert_eq!(xact.state, XactState::Pending);

        let msg = xact.commit().unwrap();
        assert!(!msg.is_empty());
        assert_eq!(xact.state, XactState::Complete);
    }

    #[test]
    fn test_pfcp_path_context_new() {
        let ctx = PfcpPathContext::new();
        assert_eq!(ctx.next_sequence, 1);
        assert!(ctx.peer_nodes.is_empty());
        assert!(ctx.transactions.is_empty());
    }

    #[test]
    fn test_pfcp_path_context_next_seq() {
        let mut ctx = PfcpPathContext::new();
        assert_eq!(ctx.next_seq(), 1);
        assert_eq!(ctx.next_seq(), 2);
        assert_eq!(ctx.next_seq(), 3);
    }

    #[test]
    fn test_pfcp_path_context_create_local_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        assert_eq!(seq, 1);
        assert!(ctx.transactions.contains_key(&1));
    }

    #[test]
    fn test_pfcp_path_context_find_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        let xact = ctx.find_xact(seq);
        assert!(xact.is_some());
        assert_eq!(xact.unwrap().seid, 0x1234);
    }

    #[test]
    fn test_pfcp_path_context_remove_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        let xact = ctx.remove_xact(seq);
        assert!(xact.is_some());
        assert!(ctx.transactions.is_empty());
    }

    #[test]
    fn test_pfcp_open() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        let result = pfcp_open(&mut ctx, addr);
        assert!(result.is_ok());
        assert_eq!(ctx.local_addr, Some(addr));
        assert!(ctx.recovery_time_stamp > 0);
    }

    #[test]
    fn test_pfcp_close() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();
        ctx.create_local_xact(0x1234);

        pfcp_close(&mut ctx);

        assert!(ctx.local_addr.is_none());
        assert!(ctx.transactions.is_empty());
        assert!(ctx.peer_nodes.is_empty());
    }

    #[test]
    fn test_send_session_establishment_response() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();

        let seq = ctx.create_local_xact(0x1234);
        // Set up the xact first
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }

        let created_pdrs = vec![CreatedPdr {
            pdr_id: 1,
            local_f_teid: None,
            ue_ip_address: None,
        }];

        // Now get xact again and call the function
        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let node_id = ctx.local_node_id.clone();

        let f_seid = FSeid {
            seid: 0x5678,
            ipv4: match &node_id {
                NodeId::Ipv4(addr) => Some(*addr),
                _ => None,
            },
            ipv6: None,
        };

        let payload = build_session_establishment_response(
            crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            0x5678,
            &node_id,
            &f_seid,
            &created_pdrs,
        );

        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            0x1234,
            xact.sequence_number,
        );

        xact.update_tx(&header, payload);
        let result = xact.commit();

        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_modification_response() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }

        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let payload = build_session_modification_response(
            crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
            &[],
        );
        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
            0x1234,
            xact.sequence_number,
        );
        xact.update_tx(&header, payload);
        let result = xact.commit();

        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_deletion_response() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }

        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let payload = build_session_deletion_response(
            crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
            &[],
        );
        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
            0x1234,
            xact.sequence_number,
        );
        xact.update_tx(&header, payload);
        let result = xact.commit();

        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_report_request() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();

        let report = UserPlaneReport::default();
        let result = send_session_report_request(&mut ctx, 0x1234, &report);

        assert!(result.is_ok());
        let (seq, msg) = result.unwrap();
        assert_eq!(seq, 1);
        assert!(!msg.is_empty());
    }

    // ------------------------------------------------------------------
    // T1/N1 retransmission of Session Report Requests (TS 29.244 §7.2.2.3)
    // ------------------------------------------------------------------

    /// Build a standalone PfcpServer (no run loop) plus a fake SMF socket, and
    /// register one session pointing at the SMF.
    async fn server_with_session() -> (Arc<PfcpServer>, UdpSocket, u64, u64) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, _rx) = mpsc::channel(32);
        let server = Arc::new(
            PfcpServer::new("127.0.0.1:0".parse().unwrap(), shutdown, tx)
                .await
                .unwrap(),
        );
        let smf = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let smf_addr = smf.local_addr().unwrap();
        let (upf_seid, smf_seid) = (0x77u64, 0x1077u64);
        server
            .test_insert_session(PfcpSessionInfo {
                upf_seid,
                smf_seid,
                smf_addr,
                ue_ipv4: Some(Ipv4Addr::new(10, 45, 0, 7)),
                ul_teid: 0x100,
                dl_teid: 0x200,
                gnb_addr: Some(Ipv4Addr::new(127, 0, 0, 1)),
            })
            .await;
        (server, smf, upf_seid, smf_seid)
    }

    async fn recv_report(smf: &UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("a Session Report Request must arrive")
                .unwrap();
        buf.truncate(len);
        buf
    }

    /// A Session Report Request (Downlink Data Report) is tracked pending, and
    /// cleared when the SMF returns a Session Report Response with the same seq
    /// — no retransmission then occurs.
    #[tokio::test]
    async fn test_ddn_cleared_on_response_no_retransmit() {
        let (server, smf, upf_seid, smf_seid) = server_with_session().await;

        server
            .send_downlink_data_report(upf_seid, smf_seid, 2, Some(9))
            .await
            .unwrap();

        // Original transmission received and one request is pending.
        let original = recv_report(&smf).await;
        assert_eq!(original[1], pfcp_type::SESSION_REPORT_REQUEST);
        assert_eq!(server.pending_report_count().await, 1);
        let seq = server.test_only_pending_seq().await;

        // SMF acknowledges with a Session Report Response carrying that seq.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::CAUSE, PfcpCause::RequestAccepted as u8);
        let resp = encode_pfcp(
            pfcp_type::SESSION_REPORT_RESPONSE,
            Some(smf_seid),
            seq,
            &b.build(),
        );
        // Drive the response through the message handler directly (no run loop).
        server
            .handle_message(&resp, smf.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(
            server.pending_report_count().await,
            0,
            "response must clear the pending request"
        );

        // After expiring T1, no retransmission happens (nothing pending).
        server.test_expire_pending_t1().await;
        server.retransmit_pending_reports().await;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(200),
                smf.recv_from(&mut [0u8; 64])
            )
            .await
            .is_err(),
            "no retransmission after acknowledgement"
        );
    }

    /// With no response, a Session Report Request is retransmitted on each T1
    /// expiry up to N1 times, then abandoned (TS 29.244 §7.2.2.3).
    #[tokio::test]
    async fn test_ddn_retransmits_then_gives_up() {
        let (server, smf, upf_seid, smf_seid) = server_with_session().await;

        server
            .send_downlink_data_report(upf_seid, smf_seid, 2, Some(9))
            .await
            .unwrap();
        let _original = recv_report(&smf).await; // attempt 0 (original)
        assert_eq!(server.pending_report_count().await, 1);

        // N1 retransmissions: each T1 expiry resends the same request.
        for n in 1..=PFCP_N1_MAX_RETRANSMIT {
            server.test_expire_pending_t1().await;
            server.retransmit_pending_reports().await;
            let retx = recv_report(&smf).await;
            assert_eq!(
                retx[1],
                pfcp_type::SESSION_REPORT_REQUEST,
                "retransmission {n} must be a Session Report Request"
            );
            assert_eq!(
                server.pending_report_count().await,
                1,
                "still pending after retransmission {n}"
            );
        }

        // One more T1 expiry: N1 is now exhausted → abandon the request.
        server.test_expire_pending_t1().await;
        server.retransmit_pending_reports().await;
        assert_eq!(
            server.pending_report_count().await,
            0,
            "request abandoned after N1 retransmissions"
        );
        // And no further packet is sent on the give-up pass.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(200),
                smf.recv_from(&mut [0u8; 64])
            )
            .await
            .is_err(),
            "no send on the give-up pass"
        );
    }
}
