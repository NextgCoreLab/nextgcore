//! UPF PFCP Path Management
//!
//! Port of src/upf/pfcp-path.c - PFCP path management for UPF

use crate::n4_build::{
    build_association_release_response, build_association_setup_response, build_failure_response,
    build_heartbeat_response, build_session_deletion_response,
    build_session_establishment_response, build_session_modification_response,
    build_session_modification_response_full, build_session_report_request, parse_create_bar,
    parse_create_far, parse_create_pdr, parse_create_qer, parse_create_urr, parse_pfcpsmreq_flags,
    parse_recovery_time_stamp, pfcp_ie, pfcp_type, pfcpsmreq_flags, CreatedPdr, DownlinkDataReport,
    DownlinkDataServiceInfo, ErrorIndicationReport, FSeid, FTeid, NodeId, ParsedCreateBar,
    ParsedCreateFar, ParsedCreatePdr, ParsedCreateQer, ParsedCreateUrr, ParsedFSeid, ParsedIe,
    ParsedPfcpHeader, PfcpCause, ReportType, UserPlaneReport,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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
    ///
    /// Carries every rule operation TS 29.244 Table 7.5.4.1-1 defines. Before #306
    /// it carried Update FAR, Update QER and BAR only, and the handler parsed only
    /// those — so a Create/Update/Remove URR, a Remove QER and every PDR and FAR
    /// operation were answered `RequestAccepted` and dropped.
    SessionModified {
        upf_seid: u64,
        /// Updated downlink TEID
        dl_teid: Option<u32>,
        /// Updated gNB address
        gnb_addr: Option<Ipv4Addr>,
        /// Rule ids to detach, applied BEFORE the creates so a modification that
        /// removes and re-creates the same id ends with the new rule (§7.5.4).
        removed_pdr_ids: Vec<u16>,
        removed_far_ids: Vec<u32>,
        removed_qer_ids: Vec<u32>,
        removed_urr_ids: Vec<u32>,
        /// Rules created on this live session.
        created_pdrs: Vec<ParsedCreatePdr>,
        created_fars: Vec<ParsedCreateFar>,
        created_qers: Vec<ParsedCreateQer>,
        created_urrs: Vec<ParsedCreateUrr>,
        /// Updated PDR rules
        updated_pdrs: Vec<ParsedCreatePdr>,
        /// Updated FAR rules
        updated_fars: Vec<ParsedCreateFar>,
        /// Updated QERs
        updated_qers: Vec<ParsedCreateQer>,
        /// Updated URRs. Re-threshold in place: the volume already measured against
        /// the rule must survive (see `DataPlaneUrr::set_reporting`).
        updated_urrs: Vec<ParsedCreateUrr>,
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
    /// How many sessions [`Self::sessions`] holds, published for
    /// `UpfContext::get_load` (#325).
    ///
    /// `sessions` is behind a `tokio` lock, so a synchronous load gauge cannot read
    /// it; this is the sync-readable projection. Maintained by
    /// [`Self::publish_session_count`], which is called inside EVERY write scope
    /// that changes the map's size and always ASSIGNS `sessions.len()` -- never
    /// increments -- so it cannot hold a count the map never had. A future mutation
    /// site that forgot it would leave a stale number until the next write, which is
    /// a wrong gauge, not a wrong forwarding decision.
    session_count: Arc<AtomicUsize>,
    /// Current PFCP association (None until Association Setup succeeds)
    association: tokio::sync::RwLock<Option<PfcpAssociation>>,
    /// Data plane handle for pulling final URR counters on session deletion
    data_plane: std::sync::RwLock<Option<Arc<crate::data_plane::DataPlane>>>,
    /// UPF-initiated requests awaiting a response, tracked by sequence number
    /// for T1/N1 retransmission (TS 29.244 §7.2.2.3). Currently used for
    /// Session Report Requests (Downlink Data / Error Indication Reports).
    pending_reports: tokio::sync::Mutex<HashMap<u32, PendingReport>>,
    /// Heartbeat state: outstanding request sequence numbers and how many
    /// heartbeat rounds in a row went unanswered (TS 23.007 §19A).
    ///
    /// Without this the heartbeat was fire-and-forget, so a silently dead
    /// SMF/SGW-C was never detected: the association and every session stayed
    /// in place indefinitely while traffic blackholed.
    heartbeat: tokio::sync::Mutex<HeartbeatState>,
}

/// Outstanding-heartbeat bookkeeping for peer-failure detection.
#[derive(Debug, Default)]
pub struct HeartbeatState {
    /// Sequence numbers sent and not yet answered.
    pub outstanding: std::collections::HashSet<u32>,
    /// Consecutive heartbeat rounds with no response at all.
    ///
    /// Counting ROUNDS rather than elapsed time is the point: the previous
    /// fallback sweep fired on `last_check.elapsed() > timeout`, which signals
    /// on liveness of the timer rather than on missed responses, so it would
    /// have declared failure against a perfectly healthy peer.
    pub consecutive_misses: u32,
}

/// Consecutive unanswered heartbeat rounds before the peer is declared down
/// (TS 23.007 §19A). Three rounds at the ~10 s heartbeat cadence is ~30 s of
/// silence, which tolerates a transient loss without holding dead state for
/// minutes.
pub const HEARTBEAT_MAX_MISSES: u32 = 3;

/// Why a Usage Report is being generated, which decides its Usage Report Trigger
/// (TS 29.244 §8.2.36, #306).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageReportReason {
    /// The URR is going away — the session is being deleted, or the URR removed.
    Termination,
    /// The CP function asked for a report now (QAURR).
    Immediate,
}

/// Record the FIRST rule operation that could not be honoured (#306).
///
/// First and not last, because TS 29.244 §7.5.5 gives ONE Cause and ONE Offending IE
/// for the whole message: with several failures the CP function can only act on one,
/// and the earliest is the one whose rejection explains the rest.
fn note_first_failure(slot: &mut Option<(PfcpCause, u16)>, cause: PfcpCause, ie_type: u16) {
    if slot.is_none() {
        *slot = Some((cause, ie_type));
    }
}

/// Pull the `u32` rule id out of a Remove X IE body (TS 29.244 §7.5.4.6-§7.5.4.9).
///
/// `None` when the id sub-IE is absent or short — a malformed removal, which the
/// caller reports rather than skipping.
fn parse_rule_id_u32(body: &[u8], id_ie_type: u16) -> Option<u32> {
    let ies = ParsedIe::parse_all(body);
    let ie = ParsedIe::find_ie(&ies, id_ie_type)?;
    if ie.value.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([
        ie.value[0],
        ie.value[1],
        ie.value[2],
        ie.value[3],
    ]))
}

/// [`parse_rule_id_u32`] for the PDR ID, which TS 29.244 §8.2.36 makes 16-bit.
fn parse_rule_id_u16(body: &[u8], id_ie_type: u16) -> Option<u16> {
    let ies = ParsedIe::parse_all(body);
    let ie = ParsedIe::find_ie(&ies, id_ie_type)?;
    if ie.value.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([ie.value[0], ie.value[1]]))
}

/// Parse every IE of one type with the establishment path's parser, noting a
/// malformed body as an Offending IE rather than dropping it silently (#306).
fn parse_rule_list<T>(
    ies: &[ParsedIe],
    ie_type: u16,
    parse: impl Fn(&[u8]) -> Result<T, &'static str>,
    failure: &mut Option<(PfcpCause, u16)>,
) -> Vec<T> {
    let mut out = Vec::new();
    for ie in ParsedIe::find_all_ies(ies, ie_type) {
        match parse(&ie.value) {
            Ok(rule) => out.push(rule),
            Err(e) => {
                log::warn!("Failed to parse rule in IE {ie_type}: {e}");
                note_first_failure(failure, PfcpCause::MandatoryIeIncorrect, ie_type);
            }
        }
    }
    out
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
    /// Which rule ids this session holds, by kind (#306).
    ///
    /// The PFCP layer tracks the ids; the data plane holds the rules' behaviour.
    /// Both are needed, and the split is not redundancy: a Session Modification
    /// Response has to be built and sent BEFORE the data plane has consumed the
    /// event, so validating an Update against the data plane's store would reject
    /// a rule created by a modification one round earlier that the consumer has
    /// not applied yet. These sets are written synchronously in the handler, in
    /// the same order the CP function sent the requests, so they are the only
    /// race-free answer to "does this rule exist" at response-building time.
    pub rules: SessionRuleIds,
    /// The 5GS TSN bridge this session is part of, once the SMF has configured one
    /// over N4 (#321, TS 23.501 §5.28).
    ///
    /// `None` until a Session Modification carries TSC management information —
    /// which is the transition #284's criterion 4 asks to be demonstrated.
    ///
    /// # Why here and not on `context::UpfSess`
    ///
    /// `UpfSess` also has a `tsn_bridge` field, and it is UNREACHABLE: nothing in
    /// production calls `UpfContext::sess_add`, so that session store is never
    /// populated (`rule_match` reads it and therefore always finds nothing).
    /// Populating it would be a correct change in a place no wire path runs through,
    /// and a test for it could only assert against a session it had hand-built
    /// itself — which is exactly the unit test that already exists and is exactly
    /// why #284's criterion 4 stayed unmet. THIS map is the store the N4 handler
    /// writes, so it is the one where "the UPF's own state" means something. The
    /// parallel-store defect is filed as its own issue rather than fixed here.
    pub tsn_bridge: Option<crate::context::TsnBridge>,
}

/// The rule ids a session holds, by kind (TS 29.244 §7.5.4, #306).
#[derive(Debug, Clone, Default)]
pub struct SessionRuleIds {
    pub pdr_ids: std::collections::HashSet<u16>,
    pub far_ids: std::collections::HashSet<u32>,
    pub qer_ids: std::collections::HashSet<u32>,
    pub urr_ids: std::collections::HashSet<u32>,
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
            session_count: Arc::new(AtomicUsize::new(0)),
            association: tokio::sync::RwLock::new(None),
            data_plane: std::sync::RwLock::new(None),
            pending_reports: tokio::sync::Mutex::new(HashMap::new()),
            heartbeat: tokio::sync::Mutex::new(HeartbeatState::default()),
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
    ///
    /// Only the peer that currently HOLDS the association may tear it down.
    /// An association is scoped to one CP/UP function pair (TS 29.244 6.2.6),
    /// Association Release is scoped to the requesting peer's own association
    /// (7.4.4.2), and stale-session cleanup is scoped to the failed peer's
    /// sessions (TS 23.527 4.2). Without this guard a departing SMF's Release
    /// wiped the association a NEWLY started SMF had just set up -- every
    /// following Session Establishment was rejected with cause 72, which is
    /// exactly what a rolling restart produces once two SMF pods overlap.
    async fn declare_peer_failure(&self, peer: SocketAddr, reason: &str) {
        match self.association.read().await.as_ref() {
            Some(a) if a.peer_addr == peer => {}
            Some(a) => {
                log::warn!(
                    "ignoring PFCP peer failure from {peer} ({reason}): the association \
                     belongs to {} -- not clearing it",
                    a.peer_addr
                );
                return;
            }
            None => {
                log::warn!(
                    "ignoring PFCP peer failure from {peer} ({reason}): no association is up"
                );
                return;
            }
        }
        log::warn!("PFCP peer {peer} failure ({reason}): clearing association and sessions");
        *self.association.write().await = None;
        let count = {
            let mut sessions = self.sessions.write().await;
            let n = sessions.len();
            sessions.clear();
            self.publish_session_count(&sessions);
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
                // Response to a UPF-initiated heartbeat: clear the outstanding
                // request so silence is distinguishable from liveness, then
                // check the peer's recovery timestamp for restart detection.
                self.note_heartbeat_response(header.sequence_number).await;
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
    /// Only the associated peer's own timestamp is meaningful here: a datagram
    /// from any other address says nothing about whether THIS association's
    /// peer restarted.
    async fn check_peer_recovery(&self, src_addr: SocketAddr, rts: u32) {
        let restarted = {
            let assoc = self.association.read().await;
            match assoc.as_ref() {
                Some(a) => a.peer_addr == src_addr && a.recovery_time_stamp != rts,
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
                // Track it: an untracked heartbeat can never reveal silence.
                self.heartbeat.lock().await.outstanding.insert(seq);
                log::debug!("Sent Heartbeat Request to {peer} (seq={seq})");
                Some(peer)
            }
            Err(e) => {
                log::warn!("Failed to send Heartbeat Request to {peer}: {e}");
                None
            }
        }
    }

    /// Clear the outstanding heartbeat for `seq` and reset the miss counter.
    ///
    /// Any heartbeat response resets the counter, not just the matching one: a
    /// response proves the peer is alive regardless of which round it answers,
    /// and an out-of-order or duplicated response must not leave a peer marked
    /// as missing.
    async fn note_heartbeat_response(&self, seq: u32) {
        let mut hb = self.heartbeat.lock().await;
        hb.outstanding.remove(&seq);
        if hb.consecutive_misses > 0 {
            log::debug!(
                "Heartbeat response received; clearing {} missed round(s)",
                hb.consecutive_misses
            );
        }
        hb.consecutive_misses = 0;
    }

    /// Close one heartbeat round: if nothing was answered, count a miss and
    /// declare the peer down once [`HEARTBEAT_MAX_MISSES`] rounds have gone
    /// unanswered (TS 23.007 §19A).
    ///
    /// Returns the number of consecutive misses after this round, so the caller
    /// and tests can observe the progression rather than only its end state.
    pub async fn close_heartbeat_round(&self) -> u32 {
        let (misses, had_outstanding) = {
            let mut hb = self.heartbeat.lock().await;
            if hb.outstanding.is_empty() {
                // Everything sent has been answered.
                hb.consecutive_misses = 0;
                (0, false)
            } else {
                hb.consecutive_misses += 1;
                // Drop the stale sequence numbers: the next round issues its own,
                // and keeping them would grow the set without bound.
                hb.outstanding.clear();
                (hb.consecutive_misses, true)
            }
        };

        if had_outstanding && misses >= HEARTBEAT_MAX_MISSES {
            let peer = self.association.read().await.as_ref().map(|a| a.peer_addr);
            if let Some(peer) = peer {
                log::error!(
                    "PFCP peer {peer} missed {misses} consecutive heartbeat rounds;                      declaring it down (TS 23.007 Section 19A)"
                );
                self.declare_peer_failure(peer, "heartbeat timeout").await;
                self.heartbeat.lock().await.consecutive_misses = 0;
            }
        }
        misses
    }

    /// Current consecutive-miss count (test and diagnostic accessor).
    pub async fn heartbeat_misses(&self) -> u32 {
        self.heartbeat.lock().await.consecutive_misses
    }

    /// Whether any heartbeat is outstanding (test and diagnostic accessor).
    pub async fn heartbeat_outstanding(&self) -> usize {
        self.heartbeat.lock().await.outstanding.len()
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

        // Store session info, including which rule ids the session now holds so a
        // later modification's Update/Remove can be validated against them (#306).
        let session_info = PfcpSessionInfo {
            upf_seid,
            smf_seid,
            smf_addr: src_addr,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
            rules: SessionRuleIds {
                pdr_ids: parsed_pdrs.iter().map(|p| p.pdr_id).collect(),
                far_ids: parsed_fars.iter().map(|f| f.far_id).collect(),
                qer_ids: parsed_qers.iter().map(|q| q.qer_id).collect(),
                urr_ids: parsed_urrs.iter().map(|u| u.urr_id).collect(),
            },
            // #321: no bridge until the SMF configures one. An establishment
            // deliberately does not create an empty one — `Some(empty bridge)` and
            // `None` would then both mean "not configured", and the transition
            // #284's criterion 4 asks about would no longer be observable.
            tsn_bridge: None,
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(upf_seid, session_info.clone());
            self.publish_session_count(&sessions);
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

        // Every rule operation TS 29.244 Table 7.5.4.1-1 defines. Before #306 this
        // parsed Update FAR, Update QER and BAR only; the rest were answered
        // `RequestAccepted` and dropped on the floor.
        //
        // `offending` records the first IE type whose operation could not be honoured,
        // so the response can carry a Cause plus an Offending IE (§7.5.5) rather than
        // a bare acceptance. Collected while parsing and evaluated once, because
        // §7.5.5 gives ONE Cause for the whole message: a partially-applied
        // modification has no truthful per-rule answer on this message, and reporting
        // the FIRST failure is the only thing the CP function can act on.
        let mut failure: Option<(PfcpCause, u16)> = None;

        let mut updated_dl_teid: Option<u32> = None;
        let mut updated_gnb_addr: Option<Ipv4Addr> = None;

        // ---- Removals: rule id only (TS 29.244 §7.5.4.6-7.5.4.9) ----
        let removed_pdr_ids: Vec<u16> = ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_PDR)
            .iter()
            .filter_map(|ie| parse_rule_id_u16(&ie.value, pfcp_ie::PDR_ID))
            .collect();
        let removed_far_ids: Vec<u32> = ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_FAR)
            .iter()
            .filter_map(|ie| parse_rule_id_u32(&ie.value, pfcp_ie::FAR_ID))
            .collect();
        let removed_qer_ids: Vec<u32> = ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_QER)
            .iter()
            .filter_map(|ie| parse_rule_id_u32(&ie.value, pfcp_ie::QER_ID))
            .collect();
        let removed_urr_ids: Vec<u32> = ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_URR)
            .iter()
            .filter_map(|ie| parse_rule_id_u32(&ie.value, pfcp_ie::URR_ID))
            .collect();

        // A Remove IE whose rule-id sub-IE is missing or short is malformed, and is
        // reported rather than skipped: silently dropping it is the defect #306 is
        // about, one level down.
        for (ie_type, parsed, total) in [
            (
                pfcp_ie::REMOVE_PDR,
                removed_pdr_ids.len(),
                ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_PDR).len(),
            ),
            (
                pfcp_ie::REMOVE_FAR,
                removed_far_ids.len(),
                ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_FAR).len(),
            ),
            (
                pfcp_ie::REMOVE_QER,
                removed_qer_ids.len(),
                ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_QER).len(),
            ),
            (
                pfcp_ie::REMOVE_URR,
                removed_urr_ids.len(),
                ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_URR).len(),
            ),
        ] {
            if parsed < total {
                log::warn!(
                    "{} of {total} Remove IE {ie_type} carried no rule id",
                    total - parsed
                );
                note_first_failure(&mut failure, PfcpCause::MandatoryIeMissing, ie_type);
            }
        }

        // ---- Creates and updates ----
        // Update X carries the same IE set as Create X (Table 7.5.4.2-1 vs
        // 7.5.2.2-1 and siblings), so the establishment path's parsers are reused
        // rather than duplicated.
        let created_pdrs = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_PDR,
            crate::n4_build::parse_create_pdr,
            &mut failure,
        );
        let updated_pdrs = parse_rule_list(
            &ies,
            pfcp_ie::UPDATE_PDR,
            crate::n4_build::parse_create_pdr,
            &mut failure,
        );
        let created_fars =
            parse_rule_list(&ies, pfcp_ie::CREATE_FAR, parse_create_far, &mut failure);
        let mod_fars = parse_rule_list(&ies, pfcp_ie::UPDATE_FAR, parse_create_far, &mut failure);
        let created_qers =
            parse_rule_list(&ies, pfcp_ie::CREATE_QER, parse_create_qer, &mut failure);
        let mod_qers = parse_rule_list(&ies, pfcp_ie::UPDATE_QER, parse_create_qer, &mut failure);
        let created_urrs = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_URR,
            crate::n4_build::parse_create_urr,
            &mut failure,
        );
        let mod_urrs = parse_rule_list(
            &ies,
            pfcp_ie::UPDATE_URR,
            crate::n4_build::parse_create_urr,
            &mut failure,
        );

        // The DL tunnel this session forwards on is whatever the LAST Outer Header
        // Creation on the message names, from a Create or an Update alike. Creates
        // are considered first so an Update in the same message wins, which is the
        // order §7.5.4 applies them in.
        for far in created_fars.iter().chain(mod_fars.iter()) {
            if let Some(ohc) = far
                .forwarding_parameters
                .as_ref()
                .and_then(|fp| fp.outer_header_creation.as_ref())
            {
                updated_dl_teid = Some(ohc.teid);
                updated_gnb_addr = ohc.ipv4;
                log::debug!("Updated downlink: TEID={:#x}, gNB={:?}", ohc.teid, ohc.ipv4);
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

        // TSC Management Information (IE 199, TS 29.244 §7.5.4.18), #321. Parsed
        // here with the rest of the message so a malformed instance is reported
        // through the same `failure` channel as every other rule operation, rather
        // than being answered `RequestAccepted` and dropped — the defect #306 fixed
        // for the rule IEs and this issue fixes for the TSC ones.
        let mut tsc_ies: Vec<nextgcore_pfcp::types::TscManagementInformation> = Vec::new();
        for ie in ParsedIe::find_all_ies(
            &ies,
            pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST,
        ) {
            let mut data = bytes::Bytes::copy_from_slice(&ie.value);
            match nextgcore_pfcp::types::TscManagementInformation::decode(&mut data) {
                Ok(tsc) if tsc.conditional_holds() => tsc_ies.push(tsc),
                Ok(_) => {
                    // A PMIC with no NW-TT Port Number names no port to apply it to.
                    // Answered with the Conditional-IE-missing cause rather than
                    // accepted, because accepting it would report success for
                    // configuration the UPF cannot attribute.
                    log::warn!(
                        "TSC Management Information carries a PMIC with no NW-TT Port \
                         Number (TS 29.244 Table 7.5.4.18-1)"
                    );
                    note_first_failure(
                        &mut failure,
                        PfcpCause::ConditionalIeMissing,
                        pfcp_ie::NW_TT_PORT_NUMBER,
                    );
                }
                Err(e) => {
                    log::warn!("malformed TSC Management Information IE: {e}");
                    note_first_failure(
                        &mut failure,
                        PfcpCause::MandatoryIeIncorrect,
                        pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST,
                    );
                }
            }
        }

        // PFCPSMReq-Flags (TS 29.244 8.2.50): SNDEM → emit End Marker on the
        // old DL tunnel; DROBU → discard buffered DL packets; QAURR → report every
        // URR immediately in this response. QAURR was declared as a constant and
        // read nowhere until #306, so an SMF asking for all usage reports got a
        // bare acceptance and no reports.
        let smreq_flags = parse_pfcpsmreq_flags(payload).unwrap_or(0);
        let send_end_marker = smreq_flags & pfcpsmreq_flags::SNDEM != 0;
        let drop_buffered = smreq_flags & pfcpsmreq_flags::DROBU != 0;
        let query_all_urrs = smreq_flags & pfcpsmreq_flags::QAURR != 0;

        // Update session info; respond Session Context Not Found for an
        // unknown SEID (TS 29.244 7.5.5, cause 65)
        //
        // The rule-id bookkeeping is updated in the SAME critical section, in
        // §7.5.4's application order — remove, then create, then update — so a
        // modification that removes and re-creates one id ends holding it, and an
        // Update naming a rule this session does not hold is caught HERE, before a
        // response claiming acceptance has been sent.
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

                // Removing a rule the session does not hold is IDEMPOTENT SUCCESS,
                // deliberately: the CP function asked for the rule to be gone and it
                // is gone, so answering §7.5.5's rule-failure cause would fail a
                // modification that achieved exactly what was requested. Logged at
                // debug so it is visible without being an error.
                for id in &removed_pdr_ids {
                    if !session.rules.pdr_ids.remove(id) {
                        log::debug!("Remove PDR {id}: not held by SEID {upf_seid:#x}, idempotent");
                    }
                }
                for id in &removed_far_ids {
                    if !session.rules.far_ids.remove(id) {
                        log::debug!("Remove FAR {id}: not held by SEID {upf_seid:#x}, idempotent");
                    }
                }
                for id in &removed_qer_ids {
                    if !session.rules.qer_ids.remove(id) {
                        log::debug!("Remove QER {id}: not held by SEID {upf_seid:#x}, idempotent");
                    }
                }
                for id in &removed_urr_ids {
                    if !session.rules.urr_ids.remove(id) {
                        log::debug!("Remove URR {id}: not held by SEID {upf_seid:#x}, idempotent");
                    }
                }

                for p in &created_pdrs {
                    session.rules.pdr_ids.insert(p.pdr_id);
                }
                for f in &created_fars {
                    session.rules.far_ids.insert(f.far_id);
                }
                for q in &created_qers {
                    session.rules.qer_ids.insert(q.qer_id);
                }
                for u in &created_urrs {
                    session.rules.urr_ids.insert(u.urr_id);
                }

                // Updating a rule the session does NOT hold is a different case from
                // removing one: the new threshold, gate or forwarding action has
                // nowhere to land, so the CP function's intent is not satisfied and
                // §7.5.5's Rule creation/modification Failure is the truthful answer.
                // Ignoring it is precisely the "accepted a modification it did not
                // apply" defect this issue is about.
                for p in &updated_pdrs {
                    if !session.rules.pdr_ids.contains(&p.pdr_id) {
                        log::warn!(
                            "Update PDR {}: no such rule on SEID {upf_seid:#x}",
                            p.pdr_id
                        );
                        note_first_failure(
                            &mut failure,
                            PfcpCause::RuleCreationModificationFailure,
                            pfcp_ie::UPDATE_PDR,
                        );
                    }
                }
                for f in &mod_fars {
                    if !session.rules.far_ids.contains(&f.far_id) {
                        log::warn!(
                            "Update FAR {}: no such rule on SEID {upf_seid:#x}",
                            f.far_id
                        );
                        note_first_failure(
                            &mut failure,
                            PfcpCause::RuleCreationModificationFailure,
                            pfcp_ie::UPDATE_FAR,
                        );
                    }
                }
                for q in &mod_qers {
                    if !session.rules.qer_ids.contains(&q.qer_id) {
                        log::warn!(
                            "Update QER {}: no such rule on SEID {upf_seid:#x}",
                            q.qer_id
                        );
                        note_first_failure(
                            &mut failure,
                            PfcpCause::RuleCreationModificationFailure,
                            pfcp_ie::UPDATE_QER,
                        );
                    }
                }
                for u in &mod_urrs {
                    if !session.rules.urr_ids.contains(&u.urr_id) {
                        log::warn!(
                            "Update URR {}: no such rule on SEID {upf_seid:#x}",
                            u.urr_id
                        );
                        note_first_failure(
                            &mut failure,
                            PfcpCause::RuleCreationModificationFailure,
                            pfcp_ie::UPDATE_URR,
                        );
                    }
                }

                // #321: apply the TSC containers in the SAME critical section as the
                // rule bookkeeping, so the response's echo (IE 200) describes state
                // that is already committed rather than state a concurrent
                // modification could still change.
                if !tsc_ies.is_empty() {
                    let bridge = session.tsn_bridge.get_or_insert_with(|| {
                        // The bridge ID is the UPF's own 5GS User Plane Node ID. The
                        // SEID is used as its basis so it is stable per session and
                        // distinct across sessions; a real deployment reads it from
                        // configuration (TS 29.244 §5.26.2 says these identities "may
                        // be pre-configured in the UPF based on deployment"), which is
                        // a recorded ceiling rather than something to invent here.
                        crate::context::TsnBridge::new(upf_seid.to_be_bytes())
                    });
                    let mut applied = 0usize;
                    for tsc in &tsc_ies {
                        if bridge.apply_tsc_management_information(tsc) {
                            applied += 1;
                        }
                    }
                    log::info!(
                        "TSC management information applied to SEID {upf_seid:#x}: \
                         {applied}/{} IE(s), bridge now holds {} port(s)",
                        tsc_ies.len(),
                        bridge.port_count()
                    );
                }

                Some((
                    session.smf_seid,
                    old_tunnel,
                    session
                        .tsn_bridge
                        .as_ref()
                        .map(|b| b.tsc_management_information())
                        .unwrap_or_default(),
                ))
            } else {
                None
            }
        };
        let (smf_seid, old_dl_tunnel, tsc_echo) = match lookup {
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

        // Usage Reports the response owes the CP function, carried in IE 78
        // (USAGE_REPORT_SMR — the Session-Modification-Response carrier).
        //
        // A removed URR must report before it is detached (TS 29.244 §8.2.36's TERMR
        // covers "removal of the URR" as well as session termination). Dropping the
        // residual instead would lose measured volume the CP function is billing on —
        // the compromise #215 had to settle for on the SGW-U side, and it is
        // avoidable here because this server already holds a data-plane handle for the
        // deletion path's final reports.
        //
        // QAURR (§8.2.50) asks for every URR to report immediately; the flag was
        // parsed nowhere before #306, so an SMF setting it got a bare acceptance and
        // no reports at all.
        let mut usage_reports = Vec::new();
        if !removed_urr_ids.is_empty() {
            usage_reports.extend(self.collect_usage_reports(
                upf_seid,
                Some(&removed_urr_ids),
                UsageReportReason::Termination,
            ));
        }
        if query_all_urrs {
            let already: std::collections::HashSet<u32> =
                usage_reports.iter().map(|r| r.urr_id).collect();
            usage_reports.extend(
                self.collect_usage_reports(upf_seid, None, UsageReportReason::Immediate)
                    .into_iter()
                    // A URR removed by this same message has already reported with
                    // TERMR; reporting it twice would double-count it.
                    .filter(|r| !already.contains(&r.urr_id)),
            );
        }

        // Build response. A rule operation that could not be honoured answers with
        // §7.5.5's Cause and Offending IE instead of a bare RequestAccepted — the
        // whole point of #306.
        let resp_payload = match failure {
            Some((cause, offending_ie)) => {
                log::warn!(
                    "Session Modification for SEID {upf_seid:#x} rejected: cause {} offending IE {offending_ie}",
                    cause as u8
                );
                build_failure_response(cause, Some(offending_ie))
            }
            None => build_session_modification_response_full(
                pfcp_type::SESSION_MODIFICATION_RESPONSE,
                &[], // No created PDRs for modification
                &usage_reports,
                // #321: echo the TSC configuration this session now holds, so the SMF
                // can tell an applied modification from a merely accepted one. Empty
                // for every non-TSC session, so no existing response changes.
                &tsc_echo,
            ),
        };

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

        // A rejected modification applies NOTHING. Sending the event anyway would
        // leave the data plane holding rules the response just said were refused,
        // which is the same divergence in the other direction.
        if failure.is_some() {
            return Ok(());
        }

        // Notify data plane
        let has_changes = updated_dl_teid.is_some()
            || updated_gnb_addr.is_some()
            || !removed_pdr_ids.is_empty()
            || !removed_far_ids.is_empty()
            || !removed_qer_ids.is_empty()
            || !removed_urr_ids.is_empty()
            || !created_pdrs.is_empty()
            || !created_fars.is_empty()
            || !created_qers.is_empty()
            || !created_urrs.is_empty()
            || !updated_pdrs.is_empty()
            || !mod_fars.is_empty()
            || !mod_qers.is_empty()
            || !mod_urrs.is_empty()
            || !mod_bars.is_empty()
            || send_end_marker
            || drop_buffered;

        if has_changes {
            let event = PfcpSessionEvent::SessionModified {
                upf_seid,
                dl_teid: updated_dl_teid,
                gnb_addr: updated_gnb_addr,
                removed_pdr_ids,
                removed_far_ids,
                removed_qer_ids,
                removed_urr_ids,
                created_pdrs,
                created_fars,
                created_qers,
                created_urrs,
                updated_pdrs,
                updated_fars: mod_fars,
                updated_qers: mod_qers,
                updated_urrs: mod_urrs,
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
            let removed = sessions.remove(&upf_seid);
            self.publish_session_count(&sessions);
            removed
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

    /// Republish the session count from the map's own length.
    ///
    /// Takes the write guard so it can only be called from inside a critical section
    /// that already holds the map — which is the point: a projection computed
    /// outside the lock could publish a length the map no longer has. Assignment
    /// rather than increment/decrement for the same reason.
    fn publish_session_count(&self, sessions: &HashMap<u64, PfcpSessionInfo>) {
        self.session_count
            .store(sessions.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// A read handle on the live N4 session count, for `UpfContext::get_load`.
    ///
    /// Handed to the process-global context at start-up rather than read from it:
    /// this server owns the session store, and the context owning a *copy* is the
    /// two-stores-one-path shape #325 rejected.
    pub fn session_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.session_count)
    }

    /// Collect final usage reports (TERMR trigger) from the data-plane URRs
    /// of a session that is being deleted.
    fn collect_final_usage_reports(&self, upf_seid: u64) -> Vec<crate::n4_build::UsageReport> {
        self.collect_usage_reports(upf_seid, None, UsageReportReason::Termination)
    }

    /// Read the current counters of a session's URRs and build Usage Reports.
    ///
    /// `only` restricts the set to named URR ids — which is what a Remove URR needs,
    /// so a modification reports the residual volume of the rules it is detaching and
    /// nothing else (#306). `None` means every URR on the session, for a deletion's
    /// final reports or a QAURR query.
    ///
    /// Read-only on the counters: the caller decides whether the URR survives, and
    /// resetting here would zero a rule that is merely being queried.
    fn collect_usage_reports(
        &self,
        upf_seid: u64,
        only: Option<&[u32]>,
        reason: UsageReportReason,
    ) -> Vec<crate::n4_build::UsageReport> {
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
            .filter(|urr| only.is_none_or(|ids| ids.contains(&urr.urr_id)))
            .map(|urr| {
                let mut trigger = crate::n4_build::UsageReportTrigger::default();
                match reason {
                    // TS 29.244 §8.2.36: TERMR covers the removal of the URR as well
                    // as the termination of the session.
                    UsageReportReason::Termination => trigger.termination_report = true,
                    UsageReportReason::Immediate => trigger.immediate_report = true,
                }
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
        let mut sessions = self.sessions.write().await;
        sessions.insert(info.upf_seid, info);
        self.publish_session_count(&sessions);
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

    // ================================================================
    // #306: a Session Modification's rule operations reach the rule store
    //
    // Every one of these drives a REAL datagram into the bound socket and then runs
    // the event through `crate::handle_pfcp_session_event` -- the production apply
    // path, not a copy of it. Asserting the parsed event alone would pass in exactly
    // the broken state this issue describes, because before #306 the parse was the
    // half that was missing and the apply was the half that did not exist.
    // ================================================================

    /// Body of a Create/Update URR IE. Update URR carries the same IE set as Create
    /// URR (TS 29.244 Table 7.5.4.10-1 vs 7.5.2.4-1), which is why one helper serves.
    fn urr_body(
        id: u32,
        vol_total: Option<u64>,
        time_threshold: Option<u32>,
        period: Option<u32>,
    ) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u32(pfcp_ie::URR_ID, id);
        // Measurement Method: VOLUM | DURAT
        b.add_u8(pfcp_ie::MEASUREMENT_METHOD, 0x02 | 0x01);
        // Reporting Triggers: PERIO | VOLTH | TIMTH
        b.add_u8(pfcp_ie::REPORTING_TRIGGERS, 0x01 | 0x02 | 0x04);
        if let Some(v) = vol_total {
            // Volume Threshold (§8.2.13): flags byte then the selected u64s.
            let mut value = vec![0x01u8];
            value.extend_from_slice(&v.to_be_bytes());
            b.add_tlv(pfcp_ie::VOLUME_THRESHOLD, &value);
        }
        if let Some(s) = time_threshold {
            b.add_u32(pfcp_ie::TIME_THRESHOLD, s);
        }
        if let Some(s) = period {
            b.add_u32(pfcp_ie::MEASUREMENT_PERIOD, s);
        }
        b.build()
    }

    /// Body of a Remove FAR / Remove QER / Remove URR IE: the rule id, nothing else.
    fn remove_body_u32(id_ie: u16, id: u32) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u32(id_ie, id);
        b.build()
    }

    /// Body of a Remove PDR IE (the PDR ID is 16-bit).
    fn remove_body_u16(id: u16) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_pdr_id(id);
        b.build()
    }

    fn qer_body(id: u32, qfi: u8) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u32(pfcp_ie::QER_ID, id);
        b.add_u8(pfcp_ie::QFI, qfi);
        b.build()
    }

    fn far_body(id: u32, apply_action: u16) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u32(pfcp_ie::FAR_ID, id);
        b.add_u16(pfcp_ie::APPLY_ACTION, apply_action);
        b.build()
    }

    fn pdr_body(pdr_id: u16, precedence: u32, far_id: u32, qer_id: u32, urr_id: u32) -> Vec<u8> {
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0); // Access
        pdi.add_f_teid(&crate::n4_build::FTeid {
            teid: 0x1234,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 4)),
            ipv6: None,
            choose: false,
            choose_id: None,
        });
        pdi.add_ue_ip_address(
            &crate::n4_build::UeIpAddress {
                ipv4: Some(Ipv4Addr::new(10, 45, 0, 42)),
                ipv6: None,
                ipv6_prefix_len: 0,
            },
            false,
        );
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_pdr_id(pdr_id);
        b.add_u32(pfcp_ie::PRECEDENCE, precedence);
        b.add_tlv(pfcp_ie::PDI, &pdi.build());
        b.add_u32(pfcp_ie::FAR_ID, far_id);
        b.add_u32(pfcp_ie::QER_ID, qer_id);
        b.add_u32(pfcp_ie::URR_ID, urr_id);
        b.build()
    }

    /// An associated server with ONE established session carrying PDR 1, FAR 1,
    /// QER 1 and URR 1, applied to a real data plane.
    ///
    /// The data plane is attached to the server (`set_data_plane`), which is what
    /// lets a Remove URR pull the residual counters for its Usage Report.
    async fn established_session() -> (
        Arc<PfcpServer>,
        UdpSocket,
        SocketAddr,
        mpsc::Receiver<PfcpSessionEvent>,
        Arc<crate::data_plane::DataPlane>,
        u64,
    ) {
        let (server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());

        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x4242,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr_body(1, 100, 1, 1, 1));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.add_tlv(pfcp_ie::CREATE_QER, &qer_body(1, 5));
        b.add_tlv(
            pfcp_ie::CREATE_URR,
            &urr_body(1, Some(1_000_000), Some(60), Some(30)),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RequestAccepted as u8,
            "the establishment this fixture depends on must succeed"
        );
        let (hdr, _) = ParsedPfcpHeader::parse(&resp).unwrap();
        let _ = hdr;
        let upf_seid = server
            .sessions
            .read()
            .await
            .keys()
            .copied()
            .next()
            .expect("the server must hold the session it just accepted");

        let evt = rx.recv().await.expect("SessionEstablished");
        crate::handle_pfcp_session_event(&dp, evt).await;
        assert!(
            dp.sessions.find_by_seid(upf_seid).is_some(),
            "the data plane must hold the session before any modification"
        );
        (server, smf, addr, rx, dp, upf_seid)
    }

    /// Apply the next session event through the production handler.
    async fn apply_next(
        rx: &mut mpsc::Receiver<PfcpSessionEvent>,
        dp: &crate::data_plane::DataPlane,
    ) {
        let evt = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("a session event must be emitted")
            .expect("channel open");
        crate::handle_pfcp_session_event(dp, evt).await;
    }

    fn usage_reports_in(resp: &[u8]) -> Vec<(u32, u64)> {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        ParsedIe::find_all_ies(&ies, pfcp_ie::USAGE_REPORT_SMR)
            .iter()
            .filter_map(|ie| {
                let inner = ParsedIe::parse_all(&ie.value);
                let id = ParsedIe::find_ie(&inner, pfcp_ie::URR_ID)?;
                let urr_id =
                    u32::from_be_bytes([id.value[0], id.value[1], id.value[2], id.value[3]]);
                // Volume Measurement (§8.2.14): flags byte then the selected u64s,
                // total first.
                let vm = ParsedIe::find_ie(&inner, pfcp_ie::VOLUME_MEASUREMENT)?;
                let total = if vm.value.len() >= 9 && vm.value[0] & 0x01 != 0 {
                    u64::from_be_bytes(vm.value[1..9].try_into().ok()?)
                } else {
                    0
                };
                Some((urr_id, total))
            })
            .collect()
    }

    /// Criterion 1: provisioning charging mid-session is the normal way it is added,
    /// and before #306 the UPF answered `RequestAccepted` and measured nothing.
    #[tokio::test]
    async fn a_modification_creating_a_urr_provisions_measurement() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(
            pfcp_ie::CREATE_URR,
            &urr_body(7, Some(555), Some(11), Some(9)),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(resp[1], pfcp_type::SESSION_MODIFICATION_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        let session = dp.sessions.find_by_seid(upf_seid).unwrap();
        let urrs = session.urrs.read().unwrap();
        let urr = urrs.get(&7).expect("Create URR must install the rule");
        assert_eq!(urr.volume_threshold_total(), Some(555));
        assert_eq!(urr.time_threshold_secs(), Some(11));
        assert_eq!(
            urr.measurement_period_secs(),
            Some(9),
            "the Measurement Period must survive the wire: the PERIO trigger is \
             useless without it"
        );
    }

    /// Criterion 2, and the reason the thresholds are atomic: re-thresholding must
    /// not zero the volume the CP function is accounting on.
    #[tokio::test]
    async fn an_update_urr_rethresholds_without_resetting_the_measured_volume() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;

        // Measure something against URR 1 first.
        {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            let urrs = session.urrs.read().unwrap();
            let urr = urrs.get(&1).expect("the fixture installs URR 1");
            urr.record(4096, true);
            urr.record(2048, false);
            assert_eq!(urr.acc_total_bytes.load(Ordering::Relaxed), 6144);
        }

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_URR, &urr_body(1, Some(99), Some(5), None));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        let session = dp.sessions.find_by_seid(upf_seid).unwrap();
        let urrs = session.urrs.read().unwrap();
        let urr = urrs.get(&1).expect("Update URR must not remove the rule");
        assert_eq!(
            urr.volume_threshold_total(),
            Some(99),
            "the new threshold must be in force"
        );
        assert_eq!(
            urr.acc_total_bytes.load(Ordering::Relaxed),
            6144,
            "an Update URR must NOT reset the volume measured so far"
        );
        assert_eq!(urr.acc_ul_bytes.load(Ordering::Relaxed), 4096);
        assert_eq!(
            urr.measurement_period_secs(),
            None,
            "a period the update omits is withdrawn, not silently retained"
        );
    }

    /// Criterion 3 plus the leak the issue names: a removed URR must report what it
    /// measured and then stop measuring.
    #[tokio::test]
    async fn a_removed_urr_reports_its_residual_volume_then_stops_measuring() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;

        let urr_arc = {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            let urrs = session.urrs.read().unwrap();
            let urr = urrs.get(&1).unwrap().clone();
            urr.record(1500, true);
            urr.record(500, false);
            urr
        };

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::REMOVE_URR, &remove_body_u32(pfcp_ie::URR_ID, 1));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);

        // The residual volume leaves in the RESPONSE, in IE 78. Dropping it would
        // lose measured traffic the CP function is billing on.
        assert_eq!(
            usage_reports_in(&resp),
            vec![(1, 2000)],
            "a removed URR must report its residual volume before being detached"
        );

        apply_next(&mut rx, &dp).await;
        let session = dp.sessions.find_by_seid(upf_seid).unwrap();
        assert!(
            !session.urrs.read().unwrap().contains_key(&1),
            "Remove URR must detach the rule"
        );
        // And the counters are unreachable from the data path: `urr_record`'s only
        // route to them is the map the rule was just removed from.
        assert_eq!(Arc::strong_count(&urr_arc), 1);
    }

    /// Criterion 4: the other three removals.
    #[tokio::test]
    async fn removing_a_qer_a_pdr_and_a_far_detaches_each_of_them() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;
        {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            assert!(session.qers.read().unwrap().contains_key(&1));
            assert!(session.fars.read().unwrap().contains_key(&1));
            assert_eq!(session.pdrs.read().unwrap().len(), 1);
        }

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::REMOVE_QER, &remove_body_u32(pfcp_ie::QER_ID, 1));
        b.add_tlv(pfcp_ie::REMOVE_FAR, &remove_body_u32(pfcp_ie::FAR_ID, 1));
        b.add_tlv(pfcp_ie::REMOVE_PDR, &remove_body_u16(1));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        let session = dp.sessions.find_by_seid(upf_seid).unwrap();
        assert!(
            session.qers.read().unwrap().is_empty(),
            "Remove QER must remove the policing, not leave it installed"
        );
        assert!(session.fars.read().unwrap().is_empty());
        assert!(
            session.pdrs.read().unwrap().is_empty(),
            "Remove PDR must remove the detection rule"
        );
    }

    /// Criterion 5. An Update naming a rule the session does not hold has nowhere to
    /// land, so §7.5.5's Cause and Offending IE are the truthful answer -- and
    /// NOTHING is applied, because a response that refused must not be followed by
    /// an event that applies.
    #[tokio::test]
    async fn an_update_for_an_absent_rule_is_refused_with_an_offending_ie() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_URR, &urr_body(4242, Some(1), None, None));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8,
            "an unapplicable rule operation must not be answered RequestAccepted"
        );
        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        let off = ParsedIe::find_ie(&ies, pfcp_ie::OFFENDING_IE)
            .expect("§7.5.5 pairs the cause with the offending IE");
        assert_eq!(
            u16::from_be_bytes([off.value[0], off.value[1]]),
            pfcp_ie::UPDATE_URR
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "a refused modification must emit no apply event"
        );
        let session = dp.sessions.find_by_seid(upf_seid).unwrap();
        assert!(!session.urrs.read().unwrap().contains_key(&4242));
    }

    /// The other half of criterion 5's decision, stated so it is not mistaken for an
    /// oversight: a REMOVAL of something absent is idempotent success, because the
    /// end state is exactly what the CP function asked for.
    #[tokio::test]
    async fn a_removal_of_an_absent_rule_is_idempotent_success() {
        let (_server, smf, addr, _rx, _dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::REMOVE_URR, &remove_body_u32(pfcp_ie::URR_ID, 999));
        b.add_tlv(pfcp_ie::REMOVE_QER, &remove_body_u32(pfcp_ie::QER_ID, 999));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RequestAccepted as u8,
            "the rule is gone, which is what was asked -- failing would refuse a \
             modification that achieved its intent"
        );
    }

    /// A malformed rule body is reported rather than skipped: dropping it silently is
    /// this issue's defect one level down.
    #[tokio::test]
    async fn a_malformed_rule_body_is_reported_as_an_offending_ie() {
        let (_server, smf, addr, _rx, _dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        // A Create URR with no URR ID at all.
        let mut bad = crate::n4_build::PfcpMessageBuilder::new();
        bad.add_u32(pfcp_ie::TIME_THRESHOLD, 10);
        b.add_tlv(pfcp_ie::CREATE_URR, &bad.build());
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::MandatoryIeIncorrect as u8);
        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        let off = ParsedIe::find_ie(&ies, pfcp_ie::OFFENDING_IE).unwrap();
        assert_eq!(
            u16::from_be_bytes([off.value[0], off.value[1]]),
            pfcp_ie::CREATE_URR
        );
    }

    /// QAURR (§8.2.50) was a constant with no reader: an SMF asking for every URR to
    /// report got a bare acceptance and no reports.
    #[tokio::test]
    async fn qaurr_reports_every_urr_in_the_response() {
        let (_server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            let urrs = session.urrs.read().unwrap();
            urrs.get(&1).unwrap().record(777, true);
        }

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            usage_reports_in(&resp),
            vec![(1, 777)],
            "QAURR must produce a Usage Report per URR"
        );
    }

    /// A create and a remove of the SAME id in one message must end holding the NEW
    /// rule: §7.5.4 applies removals before creates, and getting that order wrong
    /// leaves the session with nothing.
    #[tokio::test]
    async fn a_remove_and_create_of_one_id_ends_with_the_new_rule() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::REMOVE_URR, &remove_body_u32(pfcp_ie::URR_ID, 1));
        b.add_tlv(pfcp_ie::CREATE_URR, &urr_body(1, Some(4242), None, None));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        let session = dp.sessions.find_by_seid(upf_seid).unwrap();
        let urrs = session.urrs.read().unwrap();
        let urr = urrs
            .get(&1)
            .expect("the re-created rule must be the one that survives");
        assert_eq!(urr.volume_threshold_total(), Some(4242));
        assert_eq!(
            urr.acc_total_bytes.load(Ordering::Relaxed),
            0,
            "it is a NEW rule, so its counters start at zero -- unlike an update"
        );
    }

    /// #306 criterion 6's cost, guarded rather than accepted.
    ///
    /// This PR extends upfd's own `ParsedIe` walk instead of moving onto
    /// `nextgcore_pfcp::message::SessionModificationRequest` (see the spec for why).
    /// The argument against that choice is drift: two decoders for one message.
    ///
    /// So the two are pinned against each other. The message is built by the LIBRARY
    /// encoder and decoded by BOTH, and the rule ids and thresholds must agree. If
    /// the library's wire format moves and upfd's walk does not follow, this fails
    /// here rather than in a deployment -- which is the guarantee moving onto the
    /// library decoder would have given for free.
    #[test]
    fn the_library_decoder_and_upfds_walk_agree_on_one_modification() {
        use bytes::BytesMut;
        use nextgcore_pfcp::message::SessionModificationRequest;
        use nextgcore_pfcp::types::{RemoveQer, RemoveUrr, UpdateUrr, VolumeThreshold};

        let mut req = SessionModificationRequest::new();
        req.remove_urrs.push(RemoveUrr::new(11));
        req.remove_qers.push(RemoveQer::new(22));
        let mut update = UpdateUrr {
            urr_id: 33,
            ..Default::default()
        };
        update.measurement_period = Some(77);
        update.volume_threshold = Some(VolumeThreshold::new_total(8888));
        req.update_urrs.push(update);

        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let wire = buf.freeze();

        // Round trip through the library, so a change in ITS decoder is visible too.
        let via_library = SessionModificationRequest::decode(&mut wire.clone())
            .expect("the library must decode what it encoded");
        assert_eq!(
            via_library
                .remove_urrs
                .iter()
                .map(|r| r.urr_id)
                .collect::<Vec<_>>(),
            vec![11]
        );

        // And through upfd's walk, which is what the handler actually uses.
        let ies = ParsedIe::parse_all(&wire);
        let removed_urrs: Vec<u32> = ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_URR)
            .iter()
            .filter_map(|ie| super::parse_rule_id_u32(&ie.value, pfcp_ie::URR_ID))
            .collect();
        let removed_qers: Vec<u32> = ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_QER)
            .iter()
            .filter_map(|ie| super::parse_rule_id_u32(&ie.value, pfcp_ie::QER_ID))
            .collect();
        let mut failure = None;
        let updated_urrs = super::parse_rule_list(
            &ies,
            pfcp_ie::UPDATE_URR,
            crate::n4_build::parse_create_urr,
            &mut failure,
        );

        assert_eq!(removed_urrs, vec![11], "Remove URR must decode identically");
        assert_eq!(removed_qers, vec![22], "Remove QER must decode identically");
        assert!(
            failure.is_none(),
            "the library's Update URR must parse cleanly"
        );
        assert_eq!(updated_urrs.len(), 1);
        assert_eq!(updated_urrs[0].urr_id, 33);
        assert_eq!(
            updated_urrs[0].measurement_period_secs,
            Some(77),
            "the Measurement Period the library encodes is the one upfd reads"
        );
        assert_eq!(updated_urrs[0].volume_threshold_total, Some(8888));
    }

    // ------------------------------------------------------------------
    // 5GS TSC bridge configuration over N4 (#321)
    // ------------------------------------------------------------------

    /// Build a TSC Management Information IE payload (#321). Uses the library
    /// codec, which is the encoder a real SMF uses, so the test exercises the same
    /// bytes rather than a test-local approximation.
    fn tsc_ie(pmic: Option<(&[u8], u32)>, umic: Option<&[u8]>) -> Vec<u8> {
        let tsc = nextgcore_pfcp::types::TscManagementInformation {
            port_management_container: pmic.map(|(c, _)| c.to_vec()),
            nw_tt_port_number: pmic.map(|(_, p)| p),
            user_plane_node_management_container: umic.map(|c| c.to_vec()),
        };
        let mut buf = bytes::BytesMut::new();
        tsc.encode(&mut buf);
        buf.to_vec()
    }

    /// #284's criterion 4, which is what #321 exists to make satisfiable: a Session
    /// Modification carrying a PMIC/UMIC takes `tsn_bridge` from `None` to
    /// populated.
    ///
    /// Asserted from `PfcpServer::sessions` — the store the N4 wire path writes —
    /// and NOT from a log line, and not from a hand-built session either. The
    /// session here was established over the socket by the fixture.
    #[tokio::test]
    async fn test_tsc_management_information_populates_the_tsn_bridge() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;

        // The precondition #284's criterion 4 is stated against.
        assert!(
            server
                .sessions
                .read()
                .await
                .get(&upf_seid)
                .expect("session")
                .tsn_bridge
                .is_none(),
            "precondition: an established session has NO TSN bridge until the SMF \
             configures one"
        );

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(
            pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST,
            &tsc_ie(Some((&[0x11, 0x22, 0x33], 7)), None),
        );
        b.add_tlv(
            pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST,
            &tsc_ie(None, Some(&[0xAB, 0xCD])),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 9, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RequestAccepted as u8,
            "a well-formed TSC modification must be accepted"
        );

        let sessions = server.sessions.read().await;
        let bridge = sessions
            .get(&upf_seid)
            .expect("session")
            .tsn_bridge
            .as_ref()
            .expect("the TSN bridge must exist after a TSC modification");

        assert_eq!(
            bridge
                .port_management_containers
                .get(&7)
                .map(|c| c.as_slice()),
            Some(&[0x11, 0x22, 0x33][..]),
            "the PMIC must be stored against the NW-TT port number it arrived with, \
             byte-exact (it is an opaque TS 24.539 payload)"
        );
        assert_eq!(
            bridge.user_plane_node_management_container.as_deref(),
            Some(&[0xAB, 0xCD][..]),
            "the UMIC is bridge-level, so it is stored once and not per port"
        );
        assert_eq!(
            bridge.port_count(),
            1,
            "the PMIC's port must exist as a bridge port: naming it in a PMIC is how \
             the UPF learns the NW-TT side exists"
        );
        assert_eq!(
            bridge.ports.get(&7).map(|p| p.port_type),
            Some(crate::context::TsnPortType::NetworkSideTt),
            "a port learned from a TSC Management Information IE is network-side: the \
             IE carries an NW-TT Port Number and no DS-TT one"
        );
    }

    /// The response echoes what was applied (IE 200, TS 29.244 §7.5.5.3), so the
    /// SMF can tell an APPLIED modification from a merely accepted one.
    #[tokio::test]
    async fn test_tsc_modification_response_echoes_what_was_applied() {
        let (_server, smf, addr, _rx, _dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(
            pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST,
            &tsc_ie(Some((&[0x55], 3)), None),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 10, &b.build())).await;

        let (_h, payload) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(payload);
        let echoed = ParsedIe::find_all_ies(
            &ies,
            pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_RESPONSE,
        );
        assert_eq!(
            echoed.len(),
            1,
            "the response must carry the applied TSC configuration under IE 200"
        );
        let mut data = bytes::Bytes::copy_from_slice(&echoed[0].value);
        let decoded = nextgcore_pfcp::types::TscManagementInformation::decode(&mut data).unwrap();
        assert_eq!(decoded.nw_tt_port_number, Some(3));
        assert_eq!(
            decoded.port_management_container.as_deref(),
            Some(&[0x55][..])
        );
    }

    /// A PMIC with no NW-TT Port Number is REJECTED with the conditional-IE cause,
    /// not accepted and dropped.
    ///
    /// This is the shape §7.5.4.18's conditional exists to forbid: port
    /// configuration with no port to attribute it to. Accepting it would report
    /// success for something the UPF cannot apply — the defect class #306 fixed for
    /// the rule IEs.
    #[tokio::test]
    async fn test_tsc_pmic_without_port_number_is_rejected() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(
            pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST,
            // PMIC present, NW-TT Port Number absent.
            &tsc_ie_pmic_only(&[0x99]),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 11, &b.build())).await;

        assert_eq!(
            response_cause(&resp),
            PfcpCause::ConditionalIeMissing as u8,
            "a PMIC with no NW-TT Port Number must be refused, not silently dropped"
        );
        assert!(
            server
                .sessions
                .read()
                .await
                .get(&upf_seid)
                .expect("session")
                .tsn_bridge
                .is_none(),
            "a refused modification must apply NOTHING: a bridge created from a \
             rejected message is the divergence the Cause exists to prevent"
        );
    }

    /// A PMIC with no port number, built directly rather than through the codec's
    /// `port()` constructor (which requires one).
    fn tsc_ie_pmic_only(pmic: &[u8]) -> Vec<u8> {
        let tsc = nextgcore_pfcp::types::TscManagementInformation {
            port_management_container: Some(pmic.to_vec()),
            nw_tt_port_number: None,
            user_plane_node_management_container: None,
        };
        let mut buf = bytes::BytesMut::new();
        tsc.encode(&mut buf);
        buf.to_vec()
    }

    /// A modification with no TSC IE leaves `tsn_bridge` alone, so no existing
    /// session acquires a bridge as a side effect of this feature.
    #[tokio::test]
    async fn test_non_tsc_modification_leaves_the_bridge_absent() {
        let (server, smf, addr, mut rx, dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_QER, &qer_body(1, 6));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 12, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        assert!(
            server
                .sessions
                .read()
                .await
                .get(&upf_seid)
                .expect("session")
                .tsn_bridge
                .is_none(),
            "an ordinary modification must not create a TSN bridge"
        );

        let (_h, payload) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(payload);
        assert!(
            ParsedIe::find_all_ies(
                &ies,
                pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_RESPONSE,
            )
            .is_empty(),
            "and its response must carry no TSC IE"
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

    /// #325 criterion 3: the store the production load reader reads is the store the
    /// production N4 writer writes.
    ///
    /// A test cannot assert the *absence* of some future parallel session store, but
    /// it can assert that property — and its violation was the bug.
    /// `UpfContext::get_load` read `sess_list`, which only `mod tests` ever wrote, so
    /// the gauge was 0 in every deployment while a test that called `sess_add`
    /// directly proved 20% for 2-of-10 and passed.
    ///
    /// So nothing here touches a session store: the count is driven entirely by
    /// Association Setup / Session Establishment / Session Deletion over the socket,
    /// through the real handlers.
    // A `std::sync::Mutex` guard across awaits, deliberately: the lock's whole job is
    // to serialise this test against every sibling that touches the process-global
    // context, and the awaits are exactly the window a sibling could interleave in. A
    // second, `tokio` lock for the async half would recreate the split this lock
    // exists to prevent (#308).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn the_load_gauge_follows_the_live_n4_session_store() {
        let _guard = crate::context::UPF_GLOBAL_TEST_LOCK.lock().unwrap();

        let (server, smf, addr, _rx) = spawn_test_server().await;
        crate::context::upf_self().set_session_gauge(server.session_count_handle());

        assert_eq!(
            crate::context::upf_self().sess_count(),
            0,
            "no session has been established yet"
        );

        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x325,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr_body(1, 100, 1, 1, 1));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        let resp = exchange(&smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RequestAccepted as u8,
            "the establishment this assertion depends on must succeed"
        );

        let upf_seid = server
            .sessions
            .read()
            .await
            .keys()
            .copied()
            .next()
            .expect("the server must hold the session it just accepted");
        assert_eq!(
            crate::context::upf_self().sess_count(),
            1,
            "an established N4 session must be visible to the load gauge; 0 here is \
             the shipped defect, a UPF advertising load 0 while serving a session"
        );

        // A ceiling makes get_load report a percentage rather than a raw count.
        crate::context::upf_self().init(4);
        assert_eq!(
            crate::context::upf_self().get_load(),
            25,
            "1 of 4 sessions is 25%"
        );

        let resp = exchange(&smf, addr, &encode_pfcp(54, Some(upf_seid), 3, &[])).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RequestAccepted as u8,
            "the deletion this assertion depends on must succeed"
        );
        assert_eq!(
            crate::context::upf_self().sess_count(),
            0,
            "a deleted session must leave the gauge; a gauge that only ever counts up \
             would pass the establishment assertion above and still be wrong"
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

    /// A rolling SMF restart briefly runs two pods. The old one sends its
    /// Association Release on shutdown, AFTER the new one has associated.
    /// That Release must not touch the new peer's association -- otherwise
    /// every following Session Establishment is rejected with cause 72.
    #[tokio::test]
    async fn test_association_release_from_other_peer_is_ignored() {
        let (server, smf_a, addr, mut rx) = spawn_test_server().await;

        // Peer A associates and owns the association.
        let assoc = build_association_setup_request_payload(Some(100));
        let _ = exchange(&smf_a, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        assert!(server.is_associated().await);

        // Peer B (a different source address) releases ITS association.
        let smf_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut rel = crate::n4_build::PfcpMessageBuilder::new();
        rel.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let resp = exchange(&smf_b, addr, &encode_pfcp(9, None, 2, &rel.build())).await;

        // B is still answered per TS 29.244 7.4.4.2 ...
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_RELEASE_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        // ... but A's association and sessions survive.
        assert!(
            server.is_associated().await,
            "a Release from a non-owning peer must not clear the association"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "no PeerFailure may be raised for a peer that holds no association"
        );
    }

    /// The same guard for the heartbeat path: another peer's Recovery Time
    /// Stamp says nothing about whether THIS association's peer restarted.
    #[tokio::test]
    async fn test_recovery_timestamp_change_from_other_peer_is_ignored() {
        let (server, smf_a, addr, mut rx) = spawn_test_server().await;

        let assoc = build_association_setup_request_payload(Some(100));
        let _ = exchange(&smf_a, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        assert!(server.is_associated().await);

        // Peer B heartbeats with a DIFFERENT RTS.
        let smf_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut hb = crate::n4_build::PfcpMessageBuilder::new();
        hb.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, 200);
        let resp = exchange(&smf_b, addr, &encode_pfcp(1, None, 2, &hb.build())).await;
        assert_eq!(resp[1], pfcp_type::HEARTBEAT_RESPONSE);

        assert!(
            server.is_associated().await,
            "another peer's RTS must not declare failure for the associated peer"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "no PeerFailure may be raised from a non-owning peer's heartbeat"
        );
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
                rules: SessionRuleIds::default(),
                tsn_bridge: None,
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

    // ================================================================
    // nextgcore #61: PFCP heartbeat peer-failure detection (TS 23.007 19A)
    // ================================================================

    /// A heartbeat that is sent but not TRACKED can never reveal peer silence.
    /// Before this, `send_heartbeat_request` recorded nothing, so a dead CP
    /// function kept its association and every session indefinitely.
    #[tokio::test]
    async fn heartbeat_rounds_count_misses_and_reset_on_any_response() {
        let (server, _smf, _addr, _rx) = spawn_test_server().await;

        // No association: nothing is outstanding, so no round can miss.
        assert_eq!(server.heartbeat_outstanding().await, 0);
        assert_eq!(server.close_heartbeat_round().await, 0);

        // Simulate three sent-but-unanswered rounds by seeding the outstanding
        // set directly, which is what send_heartbeat_request now does.
        for round in 1..=3u32 {
            server.heartbeat.lock().await.outstanding.insert(round);
            let misses = server.close_heartbeat_round().await;
            assert_eq!(misses, round, "round {round} must count as a miss");
        }

        // Any response resets the counter, even one answering an older round:
        // a response proves liveness whichever round it belongs to.
        server.heartbeat.lock().await.outstanding.insert(99);
        server.note_heartbeat_response(99).await;
        assert_eq!(
            server.heartbeat_misses().await,
            0,
            "a response clears misses"
        );
        assert_eq!(server.heartbeat_outstanding().await, 0);
    }

    /// An answered round must not count as a miss.
    #[tokio::test]
    async fn answered_round_is_not_a_miss() {
        let (server, _smf, _addr, _rx) = spawn_test_server().await;
        server.heartbeat.lock().await.outstanding.insert(7);
        server.note_heartbeat_response(7).await;
        assert_eq!(
            server.close_heartbeat_round().await,
            0,
            "a round whose response arrived is not a miss"
        );
    }

    /// The outstanding set must not grow without bound: each closed round drops
    /// its stale sequence numbers, since the next round issues its own.
    #[tokio::test]
    async fn closing_a_round_drops_stale_outstanding_sequences() {
        let (server, _smf, _addr, _rx) = spawn_test_server().await;
        for seq in 1..=5u32 {
            server.heartbeat.lock().await.outstanding.insert(seq);
        }
        assert_eq!(server.heartbeat_outstanding().await, 5);
        server.close_heartbeat_round().await;
        assert_eq!(
            server.heartbeat_outstanding().await,
            0,
            "stale sequences are cleared, not accumulated"
        );
    }

    /// An out-of-order or duplicated response must not leave the peer marked as
    /// missing, and must not panic on an unknown sequence number.
    #[tokio::test]
    async fn unknown_or_duplicate_heartbeat_response_is_harmless() {
        let (server, _smf, _addr, _rx) = spawn_test_server().await;
        server.note_heartbeat_response(4242).await;
        server.note_heartbeat_response(4242).await;
        assert_eq!(server.heartbeat_misses().await, 0);
        assert_eq!(server.heartbeat_outstanding().await, 0);
    }

    /// The miss threshold is what turns silence into a declared failure.
    #[test]
    fn heartbeat_miss_threshold_is_three_rounds() {
        assert_eq!(
            HEARTBEAT_MAX_MISSES, 3,
            "three rounds at the ~10s cadence is ~30s of silence"
        );
    }
}
