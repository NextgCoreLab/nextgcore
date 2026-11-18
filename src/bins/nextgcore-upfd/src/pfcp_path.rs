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
use nextgcore_pfcp::peer_policy::{
    is_request_type, is_response_type, same_host, PeerAllowlist, RefusalLog,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    // #995: NTP-era seconds (TS 29.244 §8.2.65).
    ctx.recovery_time_stamp = nextgcore_pfcp::recovery_time::now();

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
        /// Updated PDR rules: each the changes to merge into the stored PDR
        /// (#1673, TS 29.244 §5.6.3).
        updated_pdrs: Vec<crate::n4_build::ParsedUpdatePdr>,
        /// Updated FAR rules
        updated_fars: Vec<ParsedCreateFar>,
        /// Updated QERs
        updated_qers: Vec<crate::n4_build::ParsedUpdateQer>,
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
    /// The CP function's Node ID IE value, the identifier of the association
    /// (TS 29.244 §6.2.6.2.2), kept as the raw IE value so an FQDN Node ID compares
    /// exactly as an IPv4 or IPv6 one does (#718).
    ///
    /// The source address does NOT identify the association: a restarted SMF pod
    /// comes back with the same Node ID at a new IP.
    pub node_id: Vec<u8>,
    /// The peer's Recovery Time Stamp from Association Setup / Heartbeat —
    /// a change means the peer restarted and all its sessions are stale
    pub recovery_time_stamp: u32,
    /// The host addresses this association's CP function speaks from (security,
    /// #968): the Association Setup source and, for an IPv4 or IPv6 Node ID, the
    /// Node ID address. Compared by IP only: TS 29.244 §6.2.6 associates Node IDs,
    /// not one UDP 4-tuple, so an SMF that sends requests from another port, or from
    /// the address its Node ID names, is still this association.
    pub addrs: Vec<IpAddr>,
}

impl PfcpAssociation {
    /// Whether `ip` is one of this association's own host addresses.
    pub fn owns(&self, ip: IpAddr) -> bool {
        self.addrs.iter().any(|a| same_host(*a, ip))
    }
}

/// The FQDN of a Node ID IE value of type 2 (§8.2.38), decoded from its DNS label
/// encoding (TS 23.003 §19.4.2). `None` for any other type or a malformed value.
fn node_id_fqdn(node_id: &[u8]) -> Option<String> {
    if node_id.first().map(|b| b & 0x0f) != Some(2) {
        return None;
    }
    let mut labels = Vec::new();
    let mut rest = &node_id[1..];
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len);
        if len == 0 {
            break;
        }
        let label = tail.get(..len)?;
        if !label
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        {
            return None;
        }
        labels.push(std::str::from_utf8(label).ok()?);
        rest = &tail[len..];
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

/// How long an FQDN Node ID may take to resolve while its Association Setup is
/// answered. Bounded so a slow resolver cannot stall the N4 receive loop.
const NODE_ID_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// The addresses an FQDN Node ID resolves to (empty on failure or timeout).
async fn resolve_node_id_fqdn(fqdn: &str) -> Vec<IpAddr> {
    match tokio::time::timeout(
        NODE_ID_RESOLVE_TIMEOUT,
        tokio::net::lookup_host((fqdn, nextgcore_pfcp::PFCP_UDP_PORT)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip().to_canonical()).collect(),
        Ok(Err(e)) => {
            log::warn!("PFCP Node ID FQDN '{fqdn}' does not resolve: {e}");
            Vec::new()
        }
        Err(_) => {
            log::warn!("PFCP Node ID FQDN '{fqdn}' did not resolve in time");
            Vec::new()
        }
    }
}

/// The host addresses of an association set up from `src` with Node ID IE value
/// `node_id` (§8.2.38: octet 0 bits 1-4 are the type, 0 = IPv4, 1 = IPv6, 2 = FQDN).
/// An FQDN Node ID's addresses are added by the caller once resolved.
fn association_addrs(src: SocketAddr, node_id: &[u8]) -> Vec<IpAddr> {
    let mut addrs = vec![src.ip().to_canonical()];
    let from_node_id = match (node_id.first().map(|b| b & 0x0f), node_id.len()) {
        (Some(0), 5) => Some(IpAddr::from([
            node_id[1], node_id[2], node_id[3], node_id[4],
        ])),
        (Some(1), 17) => <[u8; 16]>::try_from(&node_id[1..17])
            .ok()
            .map(|o| IpAddr::from(o).to_canonical()),
        _ => None,
    };
    if let Some(ip) = from_node_id {
        if !addrs.contains(&ip) {
            addrs.push(ip);
        }
    }
    addrs
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
    /// The usage this request carries, TAKEN from its URRs by the harvest (#771).
    /// Handed back to the data plane if the request is abandoned after N1, so a
    /// report the CP function never acknowledged does not take its usage with it
    /// (#780 review m2). Empty for requests that carry no harvested usage.
    pub usage: Vec<crate::data_plane::UrrReportEntry>,
}

/// PFCP messages refused because they did not come from the associated CP function
/// (rejected requests and dropped responses). Rendered as
/// `upf_pfcp_unauthorized_messages_total`.
pub static PFCP_UNAUTHORIZED: AtomicU64 = AtomicU64::new(0);

/// Rate limit for the refusal log lines (#968 review): the counter above counts every
/// refused datagram; the log speaks once per interval so a flood is not a log flood.
static REFUSAL_LOG: RefusalLog = RefusalLog::new();

/// Count one refused PFCP message and log it, rate-limited.
fn note_refusal(what: std::fmt::Arguments<'_>) {
    PFCP_UNAUTHORIZED.fetch_add(1, Ordering::Relaxed);
    if let Some(suppressed) = REFUSAL_LOG.note() {
        if suppressed > 0 {
            log::warn!("{what} ({suppressed} earlier refusal(s) not logged)");
        } else {
            log::warn!("{what}");
        }
    }
}

/// #1389 part 2: N6 Delay Measurement Report IEs per Node Report Request.
pub const N6_REPORTS_PER_NODE_REPORT: usize = 16;

/// What the CP function of the current association has been told about the N3/N9
/// user-plane paths (#1513).
///
/// TS 29.244 §6.2.9.2: only a PFCP Node Report Response "with the cause success"
/// means the information was delivered. A path report is sent once per transition, so
/// one the CP function refused (cause 72 "No established PFCP Association", §8.2.1,
/// from an SMF that has marked this UPF down) or never answered (N1) would otherwise
/// be lost. The current path state is re-reported instead: T1 after such a refusal,
/// and at once after every re-association that retains the sessions.
///
/// Bound: at most [`PFCP_N1_MAX_RETRANSMIT`] re-report rounds follow each live path
/// report (one sent for a transition) and each retained re-association. Rounds are
/// counted, not refusals, so a CP function that accepts one report of a round and
/// refuses another cannot keep the rounds going (#1531 review).
#[derive(Debug, Default)]
struct PathReportLedger {
    /// Peers named in a failure report to this CP function and not since named in a
    /// recovery report it accepted: the CP function may hold them as failed.
    told_failed: std::collections::HashSet<IpAddr>,
    /// The sequence number of the latest path report naming each peer, so a late
    /// acceptance of an older report does not undo a newer one.
    latest: HashMap<IpAddr, u32>,
    /// Path reports awaiting their response: sequence number -> (failure, peers).
    in_flight: HashMap<u32, (bool, Vec<IpAddr>)>,
    /// When the current path state is next re-reported.
    resend_at: Option<std::time::Instant>,
    /// Re-report rounds run since the last live path report or retained Setup.
    resends: u32,
}

impl PathReportLedger {
    /// A path report with sequence number `seq` was sent: a live one (`resend`
    /// false) for a transition, or one of a re-report round.
    fn sent(&mut self, seq: u32, failure: bool, peers: &[IpAddr], resend: bool) {
        if !resend {
            self.resends = 0;
        }
        for ip in peers {
            self.latest.insert(*ip, seq);
            if failure {
                self.told_failed.insert(*ip);
            }
        }
        self.in_flight.insert(seq, (failure, peers.to_vec()));
    }

    /// The response to `seq` arrived with `accepted` (cause success), or the request
    /// was abandoned after N1 (`accepted` false). Whether `seq` was a path report.
    fn answered(&mut self, seq: u32, accepted: bool) -> bool {
        let Some((failure, peers)) = self.in_flight.remove(&seq) else {
            return false;
        };
        if accepted {
            if !failure {
                for ip in peers {
                    if self.latest.get(&ip) == Some(&seq) {
                        self.latest.remove(&ip);
                        self.told_failed.remove(&ip);
                    }
                }
            }
        } else if self.resend_at.is_some() {
            // A re-report is already scheduled; it carries the whole state.
        } else if self.resends < PFCP_N1_MAX_RETRANSMIT {
            self.resend_at = Some(std::time::Instant::now() + PFCP_T1_DURATION);
        } else {
            log::warn!(
                "user-plane path state still not delivered after {} re-report rounds; it \
                 is re-reported after the next transition or retained re-association",
                self.resends
            );
        }
        true
    }

    /// Start a re-report round if one is due: whether one starts.
    fn start_round(&mut self, now: std::time::Instant) -> bool {
        match self.resend_at {
            Some(at) if at <= now => {
                self.resend_at = None;
                self.resends += 1;
                true
            }
            _ => false,
        }
    }
}

/// #1815: the local F-TEIDs this UP function chose (CH set, or this tree's zero TEID,
/// TS 29.244 §5.5.3), and the cursor the next one is taken from.
///
/// A TEID is held from the moment a request asks for it until the request is
/// rejected or the PDRs that detect on it are gone, and only then given back. Before
/// this, a bare counter handed out TEIDs and nothing ever gave one back: a rejected
/// Session Modification burned the TEIDs chosen while parsing it, and after the
/// counter wrapped a new tunnel could be given a live session's TEID (or TEID 0).
/// The cursor still walks forward, so a released TEID is not reused until the space
/// wraps, which keeps a late G-PDU on a just-freed tunnel from reaching a new
/// session.
#[derive(Debug)]
pub(crate) struct TeidPool {
    inner: std::sync::Mutex<TeidPoolInner>,
}

#[derive(Debug)]
struct TeidPoolInner {
    next: u32,
    in_use: std::collections::HashSet<u32>,
}

impl TeidPool {
    /// The first TEID this UPF hands out; lower values are left to statically
    /// configured tunnels.
    const FIRST: u32 = 0x10000;

    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(TeidPoolInner {
                next: Self::FIRST,
                in_use: std::collections::HashSet::new(),
            }),
        }
    }

    /// The next free TEID, or `None` when every TEID from [`Self::FIRST`] up is held.
    fn alloc(&self) -> Option<u32> {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if p.in_use.len() as u64 > u64::from(u32::MAX - Self::FIRST) {
            return None;
        }
        loop {
            let teid = p.next;
            p.next = if teid == u32::MAX {
                Self::FIRST
            } else {
                teid + 1
            };
            if p.in_use.insert(teid) {
                return Some(teid);
            }
        }
    }

    /// #1834: hold `teid`, which the CP function named itself (TS 29.244 §5.5.3:
    /// F-TEID allocation by the UP function is optional), so [`Self::alloc`] never
    /// hands it to another session. `false` when it is already held.
    fn reserve(&self, teid: u32) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .in_use
            .insert(teid)
    }

    /// #1834: whether `teid` is held, by any session or by a request in flight.
    fn is_held(&self, teid: u32) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .in_use
            .contains(&teid)
    }

    /// Give `teid` back. A TEID the pool did not hand out is ignored.
    fn release(&self, teid: u32) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .in_use
            .remove(&teid);
    }

    /// How many TEIDs are held.
    #[cfg(test)]
    pub(crate) fn in_use(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .in_use
            .len()
    }
}

/// Async PFCP server for handling SMF requests
pub struct PfcpServer {
    socket: Arc<UdpSocket>,
    _local_addr: SocketAddr,
    local_node_id: NodeId,
    recovery_time_stamp: u32,
    next_seid: AtomicU64,
    /// #1815: the local F-TEIDs this UPF chose, held until released.
    teids: TeidPool,
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
    /// Synchronously-readable projection of whether [`Self::association`] is `Some`
    /// (#380), for the Prometheus render — a plain `Fn() -> String` that cannot take
    /// the `tokio` guard. Same shape and same reason as `session_count` above.
    ///
    /// Maintained by [`Self::publish_associated`], called inside every write scope that
    /// changes the association and always ASSIGNING `is_some()` rather than toggling, so
    /// it cannot report a state the association never held.
    associated: Arc<AtomicBool>,
    /// Data plane handle for pulling final URR counters on session deletion
    data_plane: std::sync::RwLock<Option<Arc<crate::data_plane::DataPlane>>>,
    /// #1389: per GTP-U path QoS monitoring is enabled by the operator
    /// (`--gtpu-path-qos-monitoring`). Only then is GPQM advertised and GTP-U
    /// Path QoS Control Information acted on.
    gpqm: AtomicBool,
    /// #1389 part 2: N6 delay measurement (UN6DM) enabled.
    un6dm: AtomicBool,
    /// #1389 part 3: per QoS flow per UE QoS monitoring (QFQM) enabled
    /// (`--qos-flow-monitoring`). Only then is QFQM advertised and an SRR's QoS
    /// Monitoring per QoS flow Control Information acted on.
    qfqm: AtomicBool,
    /// UPF-initiated requests awaiting a response, tracked by sequence number
    /// for T1/N1 retransmission (TS 29.244 §7.2.2.3). Currently used for
    /// Session Report Requests (Downlink Data / Error Indication Reports).
    pending_reports: tokio::sync::Mutex<HashMap<u32, PendingReport>>,
    /// #1513: what the CP function has been told about the user-plane paths.
    path_ledger: std::sync::Mutex<PathReportLedger>,
    /// #1531 review M-1: held while a path report is numbered and sent, and while a
    /// re-report round reads the path table and sends. Path reports therefore leave
    /// in the order their state was read, so a transition the round did not see is
    /// reported after it, never before.
    path_send: tokio::sync::Mutex<()>,
    /// Test hook: a re-report round signals the first and waits for the second
    /// after it has read the path table.
    #[cfg(test)]
    resend_hold: std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    /// Setups from unlisted addresses waiting for a re-resolution (#1112).
    admission: std::sync::Mutex<PendingAdmission>,
    /// Set while a held Setup is judged again, so it is answered, not held twice.
    rejudging: AtomicBool,
    /// How a held Setup's re-resolution resolves: [`PeerAllowlist::resolve_hosts`],
    /// or a test's stand-in for a slow resolver.
    resolver: std::sync::RwLock<fn(&PeerAllowlist)>,
    /// Heartbeat state: outstanding request sequence numbers and how many
    /// heartbeat rounds in a row went unanswered (TS 23.007 §19A).
    ///
    /// Without this the heartbeat was fire-and-forget, so a silently dead
    /// SMF/SGW-C was never detected: the association and every session stayed
    /// in place indefinitely while traffic blackholed.
    heartbeat: tokio::sync::Mutex<HeartbeatState>,
    /// The CP-function hosts an Association Setup is accepted from (security, #968).
    /// Fail closed: empty refuses every Setup.
    allowed_peers: std::sync::RwLock<PeerAllowlist>,
    /// The IPv6 N3 GTP-U address, set once the IPv6 GTP-U socket is bound (#985).
    n3_ipv6: std::sync::RwLock<Option<Ipv6Addr>>,
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
fn note_first_failure(slot: &mut Option<N4Failure>, cause: PfcpCause, ie_type: u16) {
    if slot.is_none() {
        *slot = Some(N4Failure::Ie(cause, ie_type));
    }
}

/// [`note_first_failure`] for a rule that could not be created or modified (#1154):
/// answered "Rule creation/modification Failure" with the Failed Rule ID, not an
/// Offending IE (TS 29.244 Table 7.5.5.1-1).
fn note_first_rule_failure(slot: &mut Option<N4Failure>, rule: crate::n4_build::FailedRule) {
    if slot.is_none() {
        *slot = Some(N4Failure::Rule(rule));
    }
}

/// Why a Session Modification is refused: a missing or faulty IE (its Cause and
/// Offending IE), or a rule it could not create or modify (Failed Rule ID, #1154).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum N4Failure {
    Ie(PfcpCause, u16),
    Rule(crate::n4_build::FailedRule),
}

impl N4Failure {
    fn response_body(self) -> Vec<u8> {
        match self {
            Self::Ie(cause, ie) => build_failure_response(cause, Some(ie)),
            Self::Rule(rule) => crate::n4_build::build_rule_failure_response(rule),
        }
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

/// The rule-ID IE a rule-bearing grouped IE embeds as Mandatory (TS 29.244
/// Tables 7.5.2.2-1 to 7.5.2.5-1 and 7.5.2.9-1 for Create, 7.5.4.2-1 to 7.5.4.5-1
/// and 7.5.4.20-1 for Update, 7.5.4.6-1 to 7.5.4.10-1 and 7.5.4.19-1 for Remove
/// and Query URR), or `None` for an IE that is not a rule (#1598).
fn embedded_rule_id_ie(grouped: u16) -> Option<u16> {
    match grouped {
        pfcp_ie::CREATE_PDR | pfcp_ie::UPDATE_PDR | pfcp_ie::REMOVE_PDR => Some(pfcp_ie::PDR_ID),
        pfcp_ie::CREATE_FAR | pfcp_ie::UPDATE_FAR | pfcp_ie::REMOVE_FAR => Some(pfcp_ie::FAR_ID),
        pfcp_ie::CREATE_URR | pfcp_ie::UPDATE_URR | pfcp_ie::REMOVE_URR | pfcp_ie::QUERY_URR => {
            Some(pfcp_ie::URR_ID)
        }
        pfcp_ie::CREATE_QER | pfcp_ie::UPDATE_QER | pfcp_ie::REMOVE_QER => Some(pfcp_ie::QER_ID),
        pfcp_ie::CREATE_SRR | pfcp_ie::UPDATE_SRR | pfcp_ie::REMOVE_SRR => Some(pfcp_ie::SRR_ID),
        _ => None,
    }
}

/// The type of the rule-ID IE `body` (a `grouped` IE's value) lacks, if it lacks
/// it (#1598).
fn missing_rule_id(grouped: u16, body: &[u8]) -> Option<u16> {
    let id = embedded_rule_id_ie(grouped)?;
    ParsedIe::find_ie(&ParsedIe::parse_all(body), id)
        .is_none()
        .then_some(id)
}

/// The Cause for a rule-bearing grouped IE whose rule ID is absent (#1598).
///
/// The rule ID is Mandatory inside every Create, Update and Remove rule IE, and
/// TS 29.244 §7.2.2.4.1 (29244-k00.txt:14248-14274) sets how the receiver views
/// it: Mandatory inside a Mandatory grouped IE, Conditional inside a Conditional
/// one. Session Establishment carries Create PDR and Create FAR as M and Create
/// URR and Create QER as C (Table 7.5.2.1-1); every rule IE of a Session
/// Modification is C (Table 7.5.4.1-1). §7.6.6 then answers a missing Mandatory
/// IE "Mandatory IE missing" (66) and a missing Conditional one "Conditional IE
/// missing" (67), each with the missing IE's own type as the Offending IE. Cause
/// 69 (§7.6.8) is for an ID that is present but wrong, not absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleIdPresence {
    /// The grouped IE is Mandatory in this message: a missing ID is cause 66.
    Mandatory,
    /// The grouped IE is Conditional in this message: a missing ID is cause 67.
    Conditional,
}

impl RuleIdPresence {
    fn missing_cause(self) -> PfcpCause {
        match self {
            Self::Mandatory => PfcpCause::MandatoryIeMissing,
            Self::Conditional => PfcpCause::ConditionalIeMissing,
        }
    }
}

/// Parse every IE of one type with the establishment path's parser, noting a
/// malformed body as an Offending IE rather than dropping it silently (#306;
/// Session Establishment too since #1532).
///
/// A body without its rule ID is noted as that ID missing, with the cause
/// `presence` gives (#1598); any other refusal is "Mandatory IE incorrect" with
/// the grouped IE as the Offending IE (§7.6.8).
fn parse_rule_list<T>(
    ies: &[ParsedIe],
    ie_type: u16,
    presence: RuleIdPresence,
    parse: impl Fn(&[u8]) -> Result<T, &'static str>,
    failure: &mut Option<N4Failure>,
) -> Vec<T> {
    let mut out = Vec::new();
    for ie in ParsedIe::find_all_ies(ies, ie_type) {
        if let Some(id) = missing_rule_id(ie_type, &ie.value) {
            log::warn!("rule IE {ie_type} carries no rule ID (IE {id})");
            note_first_failure(failure, presence.missing_cause(), id);
            continue;
        }
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
    /// The IPv4 and IPv6 addresses of the CP F-SEID. They name the CP PFCP entity
    /// that a PFCP Session Retention Information IE lists (TS 29.244 §8.2.135, #718).
    pub cp_f_seid_ipv4: Option<Ipv4Addr>,
    pub cp_f_seid_ipv6: Option<std::net::Ipv6Addr>,
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

/// The UE IPv4 address an Update PDR's PDI moves the session to (#1682): the one it
/// carries, unless it is the unspecified address, which names no UE (smfd puts it in
/// a PDI for a session with no IPv4 address).
pub(crate) fn update_pdr_ue_ipv4(pdi: &crate::n4_build::ParsedPdi) -> Option<Ipv4Addr> {
    pdi.ue_ip_address
        .as_ref()
        .and_then(|ue| ue.ipv4)
        .filter(|ip| !ip.is_unspecified())
}

/// The FARs a Session Modification creates with a tunnel of their own (#619): each
/// one a PDR created by the same message uses, and created with an Outer Header
/// Creation.
///
/// That is #583's indirect forwarding tunnel (an Access PDR's FAR toward the target
/// RAN) or a dedicated EPS bearer's S5/S8-U tunnel (a Core PDR's FAR toward the SGW,
/// TS 23.401 §5.4.1). Neither is the session's downlink tunnel. A FAR created with no
/// endpoint (FAR 2 buffering until the access side is known) is the session's, and
/// its first Update sets the session's tunnel. The PFCP layer and the data plane
/// both apply this one rule, each to its own store.
pub(crate) fn own_tunnel_fars_created(
    created_pdrs: &[crate::n4_build::ParsedCreatePdr],
    created_fars: &[crate::n4_build::ParsedCreateFar],
) -> std::collections::HashSet<u32> {
    let used: std::collections::HashSet<u32> =
        created_pdrs.iter().filter_map(|p| p.far_id).collect();
    created_fars
        .iter()
        .filter(|f| used.contains(&f.far_id))
        .filter(|f| {
            f.forwarding_parameters
                .as_ref()
                .is_some_and(|fp| fp.outer_header_creation.is_some())
        })
        .map(|f| f.far_id)
        .collect()
}

/// The FARs a Session Establishment creates with a tunnel of their own (#619 review):
/// each one a PDR of the message uses, created with an Outer Header Creation that is not
/// the session's downlink tunnel (`session_tunnel`, the TEID and IPv4 address the
/// establishment takes as the session's).
///
/// A session established with a dedicated bearer already in it (a restoration, or an
/// SMF that sends the whole rule set at once) has that bearer's FAR toward its own
/// tunnel; without this, the session's first move re-pointed it.
pub(crate) fn own_tunnel_fars_established(
    pdrs: &[crate::n4_build::ParsedCreatePdr],
    fars: &[crate::n4_build::ParsedCreateFar],
    session_tunnel: (u32, Option<Ipv4Addr>),
) -> std::collections::HashSet<u32> {
    let used: std::collections::HashSet<u32> = pdrs.iter().filter_map(|p| p.far_id).collect();
    fars.iter()
        .filter(|f| used.contains(&f.far_id))
        .filter(|f| {
            f.forwarding_parameters
                .as_ref()
                .and_then(|fp| fp.outer_header_creation.as_ref())
                .is_some_and(|ohc| (ohc.teid, ohc.ipv4) != session_tunnel)
        })
        .map(|f| f.far_id)
        .collect()
}

/// The rule ids a session holds, by kind (TS 29.244 §7.5.4, #306).
#[derive(Debug, Clone, Default)]
pub struct SessionRuleIds {
    pub pdr_ids: std::collections::HashSet<u16>,
    pub far_ids: std::collections::HashSet<u32>,
    pub qer_ids: std::collections::HashSet<u32>,
    pub urr_ids: std::collections::HashSet<u32>,
    /// FARs with a tunnel endpoint of their own, not the session's downlink tunnel
    /// (#619): a FAR created by a Session Modification together with a PDR that uses
    /// it. That is #583's indirect forwarding tunnel (Access PDR) or a dedicated EPS
    /// bearer's S5/S8-U tunnel (Core PDR, TS 23.401 §5.4.1). An Update FAR on one of
    /// these moves that FAR only, never the session's tunnel.
    pub own_tunnel_far_ids: std::collections::HashSet<u32>,
    /// #1389 part 3: the SRRs the session holds (only with QFQM enabled).
    pub srr_ids: std::collections::HashSet<u8>,
    /// #1682: the local F-TEID (TEID) each PDR of the session detects on, from
    /// its Create PDR (establishment or modification) or its latest Update PDR.
    /// The UPF-wide set of these is what an Update PDR naming its own F-TEID is
    /// checked against: a TEID another session holds is refused, because it
    /// routes that session's uplink.
    pub pdr_teids: HashMap<u16, u32>,
    /// #1815: the TEIDs of [`Self::pdr_teids`] the session holds in the UPF's
    /// TEID pool: the ones this UPF chose, and (#1834) the ones the CP function
    /// named itself, reserved so the pool never hands them to another session.
    /// Each goes back to the pool once no PDR of the session detects on it, or
    /// with the session.
    pub held_teids: std::collections::HashSet<u32>,
}

/// #1741: whether a Session Modification leaves `id` held: created by it, or held
/// before it and not removed by it (TS 29.244 §7.5.4 applies removals, then creates,
/// then updates). Lets an Update naming no rule be refused before anything is written.
fn held_after<T: Copy + Eq + std::hash::Hash>(
    held: &std::collections::HashSet<T>,
    removed: &[T],
    mut created: impl Iterator<Item = T>,
    id: T,
) -> bool {
    created.any(|c| c == id) || (held.contains(&id) && !removed.contains(&id))
}

/// The time IEs of a usage report, from the times taken with its usage (#818, TS
/// 29.244 Table 7.5.8.3-1): Start Time and End Time always; Duration Measurement when
/// the URR measures time; Time of First / Last Packet when traffic was seen.
fn report_time_ies(
    t: &crate::data_plane::ReportTimes,
) -> (
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
) {
    use crate::data_plane::ntp_secs;
    (
        Some(ntp_secs(t.start)),
        Some(ntp_secs(t.end)),
        t.duration.map(|d| d.as_secs().min(u32::MAX as u64) as u32),
        t.first_pkt.map(ntp_secs),
        t.last_pkt.map(ntp_secs),
    )
}

/// Association Setup Requests from addresses the last resolution of the allowlist's
/// host names does not contain, held while those names are re-resolved (#1112).
///
/// A restarted SMF pod is at an IP the periodic refresh may not have seen yet: it was
/// refused cause 64 and admitted only on its retry, 10 s later, while it took creates
/// it had no UPF for. Now its Setup waits for a fresh resolution and is judged
/// against it. The lookup runs off the receive task, so nobody's PFCP traffic
/// waits for DNS; the held Setups are judged again by the receive loop when it
/// ends (or after [`ADMISSION_LOOKUP_MAX`]). Still fail-closed: an address the fresh
/// answer does not list is refused, as is one beyond [`ADMISSION_MAX_HELD`].
#[derive(Default)]
struct PendingAdmission {
    /// The resolution in flight, and when it began.
    lookup: Option<(tokio::task::JoinHandle<()>, std::time::Instant)>,
    /// The Setups waiting for it: (datagram, source).
    held: Vec<(Vec<u8>, SocketAddr)>,
}

/// How long held Setups wait for a resolution before they are judged without it.
const ADMISSION_LOOKUP_MAX: std::time::Duration = std::time::Duration::from_secs(2);

/// How many Setups may wait at once; beyond it they are refused at once.
const ADMISSION_MAX_HELD: usize = 64;

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

        // #995: NTP-era seconds (TS 29.244 §8.2.65), not Unix seconds.
        let recovery_time_stamp = nextgcore_pfcp::recovery_time::now();

        Ok(Self {
            socket: Arc::new(socket),
            _local_addr: local_addr,
            local_node_id,
            recovery_time_stamp,
            next_seid: AtomicU64::new(1),
            teids: TeidPool::new(),
            next_seq: AtomicU32::new(1),
            shutdown,
            session_tx,
            sessions: tokio::sync::RwLock::new(HashMap::new()),
            session_count: Arc::new(AtomicUsize::new(0)),
            association: tokio::sync::RwLock::new(None),
            associated: Arc::new(AtomicBool::new(false)),
            data_plane: std::sync::RwLock::new(None),
            gpqm: AtomicBool::new(false),
            un6dm: AtomicBool::new(false),
            qfqm: AtomicBool::new(false),
            pending_reports: tokio::sync::Mutex::new(HashMap::new()),
            path_ledger: std::sync::Mutex::new(PathReportLedger::default()),
            path_send: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            resend_hold: std::sync::Mutex::new(None),
            heartbeat: tokio::sync::Mutex::new(HeartbeatState::default()),
            allowed_peers: std::sync::RwLock::new(PeerAllowlist::default()),
            admission: std::sync::Mutex::new(PendingAdmission::default()),
            rejudging: AtomicBool::new(false),
            resolver: std::sync::RwLock::new(|list: &PeerAllowlist| {
                list.resolve_hosts();
            }),
            n3_ipv6: std::sync::RwLock::new(None),
        })
    }

    /// The UPF's IPv6 N3 GTP-U address, once its IPv6 GTP-U socket is bound
    /// (`--gtpu-addr6`, #985). Only then may a local F-TEID carry an IPv6 address.
    pub fn set_n3_ipv6(&self, addr: Option<Ipv6Addr>) {
        if let Ok(mut a) = self.n3_ipv6.write() {
            *a = addr;
        }
    }

    /// The addresses of a local F-TEID the UP function assigns (TS 29.244 §8.2.3,
    /// #985). With CH set, "the UP function shall assign an F-TEID with an IPv4 or an
    /// IPv6 address if the V4 or V6 bit is set respectively", and both may be set.
    /// The IPv4 address is the Node ID's, as before. An IPv6 address is given only
    /// when the UPF has an IPv6 GTP-U socket. No flag at all (this tree's SMF asks
    /// with a zero TEID and no address) means IPv4.
    ///
    /// `None` when IPv6 alone is asked for and the UPF has no IPv6 N3 address: the
    /// request cannot be met, so the caller refuses the rule rather than answering
    /// with an IPv4 F-TEID the CP function did not ask for (#985 review). With V4 and
    /// V6 both set, IPv4 alone meets it.
    fn local_f_teid_addrs(
        &self,
        req: &crate::n4_build::ParsedFTeid,
    ) -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let node_v4 = match &self.local_node_id {
            NodeId::Ipv4(addr) => Some(*addr),
            _ => None,
        };
        let n3_v6 = self.n3_ipv6.read().ok().and_then(|a| *a);
        let ipv6 = if req.v6 { n3_v6 } else { None };
        let ipv4 = if req.v4 || !req.v6 { node_v4 } else { None };
        if req.v6 && !req.v4 && ipv6.is_none() {
            log::warn!(
                "F-TEID with IPv6 only requested, but the UPF has no IPv6 GTP-U socket \
                 (set --gtpu-addr6): the PDR is refused"
            );
            return None;
        }
        Some((ipv4, ipv6))
    }

    /// Allocate a new SEID
    fn alloc_seid(&self) -> u64 {
        self.next_seid.fetch_add(1, Ordering::SeqCst)
    }

    /// #1815: choose a local F-TEID for a PDR, recording it in `chosen` so the
    /// request can give it back if it is rejected. PDRs naming one CHOOSE ID share
    /// one TEID (TS 29.244 §5.5.3), so a CHOOSE ID seen before returns its TEID and
    /// allocates nothing. `None` when the pool is exhausted.
    fn choose_teid(
        &self,
        choose_id: Option<u8>,
        by_choose_id: &mut HashMap<u8, u32>,
        chosen: &mut Vec<u32>,
    ) -> Option<u32> {
        if let Some(teid) = choose_id.and_then(|id| by_choose_id.get(&id)) {
            return Some(*teid);
        }
        let teid = self.teids.alloc()?;
        chosen.push(teid);
        if let Some(id) = choose_id {
            by_choose_id.insert(id, teid);
        }
        Some(teid)
    }

    /// #1815: give back the TEIDs a rejected or abandoned request chose.
    fn release_teids(&self, teids: impl IntoIterator<Item = u32>) {
        for teid in teids {
            self.teids.release(teid);
        }
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

    /// Set the CP-function addresses an Association Setup Request is accepted from
    /// (`--pfcp-allowed-peers`, security #968).
    pub fn set_allowed_peers(&self, allowlist: PeerAllowlist) {
        if let Ok(mut a) = self.allowed_peers.write() {
            *a = allowlist;
        }
    }

    fn allowed_peers(&self) -> PeerAllowlist {
        self.allowed_peers
            .read()
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    /// Whether a PFCP association with a CP function is currently up
    pub async fn is_associated(&self) -> bool {
        self.association.read().await.is_some()
    }

    /// Republish the sync-readable association gauge from the guard's own value (#380).
    ///
    /// Takes the guard so it can only be called from inside a critical section that
    /// already holds the association — a projection computed outside the lock could
    /// publish a state the association no longer has.
    fn publish_associated(&self, association: &Option<PfcpAssociation>) {
        self.associated
            .store(association.is_some(), Ordering::Relaxed);
    }

    /// A read handle on the live association state, for the Prometheus render (#380).
    ///
    /// Handed out rather than read through the server, matching
    /// [`Self::session_count_handle`]: this server owns the association, and the render
    /// owning a *copy* of the state would be the two-stores-one-path shape #325
    /// rejected.
    pub fn associated_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.associated)
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
            Some(a) if a.owns(peer.ip()) => {}
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
        {
            let mut association = self.association.write().await;
            *association = None;
            self.publish_associated(&association);
        }
        self.clear_path_qos_control();
        self.clear_n6_delay_control();
        // #1513: the CP function's sessions are gone, and with them what it was told.
        *self.path_ledger.lock().unwrap() = PathReportLedger::default();
        self.delete_association_sessions(peer, reason).await;
    }

    /// Delete every PFCP session of the association with `peer`, here and in the
    /// data plane.
    ///
    /// This UPF holds one association at a time, so "the association's sessions" is
    /// all of them.
    async fn delete_association_sessions(&self, peer: SocketAddr, reason: &str) {
        let count = {
            let mut sessions = self.sessions.write().await;
            let n = sessions.len();
            // #1815: the sessions' TEIDs go back with them.
            for info in sessions.values() {
                self.release_teids(info.rules.held_teids.iter().copied());
            }
            sessions.clear();
            self.publish_session_count(&sessions);
            n
        };
        log::warn!("Cleared {count} PFCP sessions of the association with {peer} ({reason})");
        // #1451 review m5: every session's QoS monitoring goes with them here,
        // including one whose data-plane install never happened (the data plane
        // only removes the sessions it holds).
        if let Some(dp) = self.data_plane.read().unwrap().clone() {
            dp.with_qos_flow_monitor(|m| m.clear());
        }
        let _ = self
            .session_tx
            .send(PfcpSessionEvent::PeerFailure { peer })
            .await;
    }

    /// Keep the sessions a PFCP Session Retention Information IE asks for, delete the
    /// rest, and re-address the kept ones to the association's new peer (#718,
    /// TS 29.244 §6.2.6.2.2).
    ///
    /// `entities` empty means keep every session (Table 7.4.4.1-2). Otherwise a
    /// session is kept when its CP F-SEID address is one of the listed CP PFCP
    /// entities (§8.2.135), or, as an extension the spec does not define, when the
    /// address the session was established from is: a CP function that put an
    /// unroutable address in its F-SEID (smfd before #797 sent 0.0.0.0) is still
    /// matched by the address it actually used. Kept sessions now report to
    /// `new_peer`: the association is the same CP function at a new address, and the
    /// old address may be dead. Returns how many sessions were kept.
    async fn retain_association_sessions(
        &self,
        entities: &[std::net::IpAddr],
        new_peer: SocketAddr,
    ) -> usize {
        let wanted = |info: &PfcpSessionInfo| {
            entities.is_empty()
                || entities.iter().any(|ip| {
                    *ip == info.smf_addr.ip()
                        || info.cp_f_seid_ipv4.map(std::net::IpAddr::V4) == Some(*ip)
                        || info.cp_f_seid_ipv6.map(std::net::IpAddr::V6) == Some(*ip)
                })
        };
        let (kept, dropped) = {
            let mut sessions = self.sessions.write().await;
            let dropped: Vec<(u64, Option<Ipv4Addr>)> = sessions
                .values()
                .filter(|info| !wanted(info))
                .map(|info| (info.upf_seid, info.ue_ipv4))
                .collect();
            for (seid, _) in &dropped {
                // #1815: a dropped session's TEIDs go back with it.
                if let Some(info) = sessions.remove(seid) {
                    self.release_teids(info.rules.held_teids);
                }
            }
            for info in sessions.values_mut() {
                info.smf_addr = new_peer;
            }
            self.publish_session_count(&sessions);
            (sessions.len(), dropped)
        };
        for (upf_seid, ue_ipv4) in &dropped {
            let event = PfcpSessionEvent::SessionDeleted {
                upf_seid: *upf_seid,
                ue_ipv4: *ue_ipv4,
            };
            if let Err(e) = self.session_tx.send(event).await {
                log::error!("Failed to send session event: {e}");
            }
        }
        log::info!(
            "PFCP Session Retention Information from {new_peer}: kept {kept} session(s), \
             deleted {} not requested",
            dropped.len()
        );
        kept
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
                    log::trace!("PFCP received {len} bytes from {src_addr}");

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
            // #1513: re-report the user-plane path state the CP function refused.
            self.resend_path_state_if_due().await;
            // #1112: Setups held for a re-resolution of the allowed CP names.
            self.rejudge_held_setups().await;
        }

        Ok(())
    }

    /// Handle incoming PFCP message
    async fn handle_message(&self, data: &[u8], src_addr: SocketAddr) -> Result<(), String> {
        let (header, payload) = ParsedPfcpHeader::parse(data).map_err(|e| e.to_string())?;

        log::trace!(
            "PFCP message: type={}, seq={}, seid={:#x}",
            header.msg_type,
            header.sequence_number,
            header.seid
        );

        // SECURITY (#968): only the ASSOCIATED CP function may drive sessions, release
        // the association or answer our requests. Only Heartbeat Request and Association
        // Setup Request may come from anyone (TS 29.244 §8.2.1 cause 72), and the Setup
        // handler applies the peer allowlist itself. Before, a Session Modification or
        // Deletion from ANY source was executed on a guessed SEID -- redirecting or
        // tearing down a UE's user plane -- and a stray response could acknowledge our
        // reports or keep a dead peer looking alive.
        //
        // The source is matched by IP, never by port: the association is between Node
        // IDs (§6.2.6), so any of the association's host addresses qualifies (its Setup
        // source, its IPv4/IPv6 Node ID, or the addresses its FQDN Node ID resolves to).
        let src_ip = src_addr.ip();
        let from_peer = self
            .association
            .read()
            .await
            .as_ref()
            .is_some_and(|a| a.owns(src_ip));
        // A report response is accepted from the host its request went to.
        let answers_our_report = header.msg_type == pfcp_type::SESSION_REPORT_RESPONSE
            && self
                .pending_reports
                .lock()
                .await
                .get(&header.sequence_number)
                .is_some_and(|p| same_host(p.dest.ip(), src_ip));
        if !from_peer && !answers_our_report {
            let t = header.msg_type;
            match t {
                pfcp_type::HEARTBEAT_REQUEST | pfcp_type::ASSOCIATION_SETUP_REQUEST => {}
                t if is_response_type(t) => {
                    // Not ours to accept: dropped and counted.
                    note_refusal(format_args!(
                        "PFCP response type={t} seq={} from {src_addr}, which is not the \
                         associated CP function: dropped",
                        header.sequence_number
                    ));
                    return Ok(());
                }
                t if is_request_type(t) => {
                    // A request: rejected with "No established PFCP Association" (§5.8.3,
                    // cause 72), never executed, and counted.
                    note_refusal(format_args!(
                        "PFCP request type={t} from {src_addr}, which is not the associated \
                         CP function: rejected (cause 72), not executed"
                    ));
                    let resp_payload =
                        build_failure_response(PfcpCause::NoEstablishedPfcpAssociation, None);
                    let session_level = t >= pfcp_type::SESSION_ESTABLISHMENT_REQUEST;
                    // `t` is a Table 7.3-1 request type, so `t + 1` is its response.
                    let response = self.build_response(
                        t + 1,
                        0,
                        header.sequence_number,
                        &resp_payload,
                        session_level,
                    );
                    let _ = self.socket.send_to(&response, src_addr).await;
                    return Ok(());
                }
                t => {
                    // An unknown message type is ignored (TS 29.244 §7.6), never answered:
                    // there is no response type to answer it with (255 + 1 overflowed).
                    note_refusal(format_args!(
                        "PFCP message of unknown type {t} from {src_addr}: ignored"
                    ));
                    return Ok(());
                }
            }
        }

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
                self.handle_association_setup_request(&header, payload, data, src_addr)
                    .await?;
            }
            pfcp_type::ASSOCIATION_RELEASE_REQUEST => {
                self.handle_association_release_request(&header, src_addr)
                    .await?;
            }
            pfcp_type::ASSOCIATION_UPDATE_REQUEST => {
                self.handle_association_update_request(&header, payload, src_addr)
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
            pfcp_type::NODE_REPORT_RESPONSE => {
                // #935: the CP function answered a Node Report; stop T1/N1.
                let removed = self
                    .pending_reports
                    .lock()
                    .await
                    .remove(&header.sequence_number)
                    .is_some();
                // #1513, TS 29.244 §6.2.9.2: only the cause "success" delivers the
                // report. A refused path report is re-reported (see PathReportLedger).
                let ies = ParsedIe::parse_all(payload);
                let cause = ParsedIe::find_ie(&ies, pfcp_ie::CAUSE)
                    .and_then(|ie| ie.value.first().copied())
                    .unwrap_or(0);
                let accepted = cause == PfcpCause::RequestAccepted as u8;
                let path_report = removed
                    && self
                        .path_ledger
                        .lock()
                        .unwrap()
                        .answered(header.sequence_number, accepted);
                if accepted {
                    log::debug!(
                        "Node Report accepted (seq={}, tracked={removed})",
                        header.sequence_number
                    );
                } else {
                    log::warn!(
                        "Node Report refused: cause={cause} (seq={}){}",
                        header.sequence_number,
                        if path_report {
                            "; the user-plane path state is re-reported"
                        } else {
                            ""
                        }
                    );
                }
                return Ok(());
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
                Some(a) => a.owns(src_addr.ip()) && a.recovery_time_stamp != rts,
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

    /// Hold the Setup `datagram` from the unlisted `src_addr` for a re-resolution of
    /// the allowlist's host names (#1112): `true` when held, `false` when it is to be
    /// refused now -- it is being judged again already, the list names no host, a
    /// resolution just ran (its answer decides), or too many are held.
    fn hold_for_resolution(
        &self,
        allowed: &PeerAllowlist,
        datagram: &[u8],
        src_addr: SocketAddr,
    ) -> bool {
        if self.rejudging.load(Ordering::SeqCst) || allowed.hosts().is_empty() {
            return false;
        }
        let mut pending = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        // One held Setup per source (#1115 review n3): a retransmission is answered
        // once, and one host cannot fill the queue with Setups under new sequence
        // numbers and so push a real CP function's Setup past the cap.
        if pending.held.iter().any(|(_, from)| *from == src_addr) {
            return true;
        }
        if pending.held.len() >= ADMISSION_MAX_HELD {
            return false;
        }
        if pending.lookup.is_none() {
            if !allowed.try_begin_resolution() {
                return false;
            }
            let list = allowed.clone();
            let resolve = *self.resolver.read().unwrap_or_else(|e| e.into_inner());
            let lookup = tokio::task::spawn_blocking(move || resolve(&list));
            pending.lookup = Some((lookup, std::time::Instant::now()));
        }
        log::info!(
            "PFCP Association Setup Request from {src_addr}, not in the last resolution of \
             {:?}: held while they are re-resolved",
            allowed.hosts()
        );
        pending.held.push((datagram.to_vec(), src_addr));
        true
    }

    /// Resolve held Setups' names with `resolver` instead (a slow DNS, in a test).
    #[cfg(test)]
    fn set_resolver_for_test(&self, resolver: fn(&PeerAllowlist)) {
        *self.resolver.write().unwrap_or_else(|e| e.into_inner()) = resolver;
    }

    /// Judge again the Setups held for a resolution that has ended, or has taken
    /// longer than [`ADMISSION_LOOKUP_MAX`] (#1112). Called by the receive loop.
    async fn rejudge_held_setups(&self) {
        let held = {
            let mut pending = self.admission.lock().unwrap_or_else(|e| e.into_inner());
            let due = pending.lookup.as_ref().is_some_and(|(lookup, began)| {
                lookup.is_finished() || began.elapsed() >= ADMISSION_LOOKUP_MAX
            });
            if !due {
                return;
            }
            pending.lookup = None;
            std::mem::take(&mut pending.held)
        };
        self.rejudging.store(true, Ordering::SeqCst);
        for (datagram, src_addr) in held {
            if let Err(e) = self.handle_message(&datagram, src_addr).await {
                log::error!("PFCP held Association Setup from {src_addr}: {e}");
            }
        }
        self.rejudging.store(false, Ordering::SeqCst);
    }

    /// Handle Association Setup Request
    async fn handle_association_setup_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        datagram: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        log::info!("Handling Association Setup Request from {src_addr}");

        // SECURITY (#968): an association is accepted only from a configured CP function.
        // A refused Setup changes nothing: the live association and its sessions stay.
        let allowed = self.allowed_peers();
        if !allowed.permits(src_addr.ip()) {
            // #1112: held for a fresh resolution of the allowed names, and judged again
            // when it ends, instead of refused on a resolution that predates the peer.
            if self.hold_for_resolution(&allowed, datagram, src_addr) {
                return Ok(());
            }
            // Refused. The background refresh is still kicked (rate-limited, sharing the
            // slot above) so a later attempt is judged against current DNS.
            allowed.kick_refresh();
            note_refusal(format_args!(
                "PFCP Association Setup Request from {src_addr}, which is not an allowed CP \
                 function ({allowed}): rejected (cause 64)"
            ));
            return self
                .reject_association_setup(header.sequence_number, src_addr)
                .await;
        }

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
        // TS 29.244 §8.2.65: NTP-era seconds, kept as sent (#1033).
        let rts = rts.unwrap();
        let node_id = ParsedIe::find_ie(&ies, pfcp_ie::NODE_ID)
            .map(|ie| ie.value.clone())
            .unwrap_or_default();
        let retention = crate::n4_build::parse_session_retention_information(payload);

        // #718, TS 29.244 §6.2.6.2.2: a request from a Node ID that already has an
        // association overwrites it "regardless of the Recovery Timestamp", and the
        // existing association's sessions are deleted unless the request asks for them
        // to be retained. Keyed by Node ID, not source address: a restarted SMF pod
        // keeps its Node ID and comes back at a new IP, and keying by address left
        // every session of the previous incarnation here with no CP function able to
        // modify or release it, while the new incarnation reused its CP SEIDs.
        //
        // A request from a DIFFERENT Node ID also replaces the association, because
        // this UPF holds one at a time. The replaced CP function can no longer
        // control its sessions, so they are deleted too; retention is defined only
        // for the same Node ID.
        let previous = self.association.read().await.clone();
        // SECURITY (#968): only an allowlisted CP function got this far (fail closed,
        // above). It may replace or move a LIVE association only if it is one of that
        // association's hosts, or presents the same Node ID (the same CP function at a
        // new address, #718). A DIFFERENT CP function waits until the association is
        // gone (Release or heartbeat timeout), so one listed host cannot evict
        // another's sessions. Residual risk: the Node ID is written by the sender, so
        // with a broad allowlist (a pod CIDR, 0.0.0.0/0) any host in range that knows
        // the SMF's Node ID can still take the association over; list the CP's own
        // address or headless Service name where possible.
        if let Some(prev) = previous.as_ref() {
            if !prev.owns(src_addr.ip()) && prev.node_id != node_id {
                note_refusal(format_args!(
                    "PFCP Association Setup Request from {src_addr} with another Node ID \
                     would replace the live association with {}: rejected (cause 64), \
                     association and sessions kept",
                    prev.peer_addr
                ));
                return self
                    .reject_association_setup(header.sequence_number, src_addr)
                    .await;
            }
        }
        let mut sessions_retained = false;
        if let Some(prev) = previous {
            let same_node = prev.node_id == node_id;
            match (&retention, same_node) {
                (Some(entities), true) => {
                    self.retain_association_sessions(entities, src_addr).await;
                    sessions_retained = true;
                }
                _ => {
                    let reason = if same_node {
                        "the same Node ID set up a new association without session retention"
                    } else {
                        "a different CP function replaced the association"
                    };
                    log::warn!(
                        "Association Setup from {src_addr} replaces the association with {} \
                         (peer RTS {} -> {rts}): {reason}",
                        prev.peer_addr,
                        prev.recovery_time_stamp
                    );
                    self.delete_association_sessions(prev.peer_addr, reason)
                        .await;
                }
            }
        }

        // Resolved ONCE, here: a CP whose FQDN later resolves to new addresses must
        // re-associate for them to count.
        // A CP function identified by an FQDN may send from any address it resolves to
        // (§6.2.6: the association is the Node ID's), and one with an IPv4/IPv6 Node ID
        // from that address. Only addresses the allowlist permits are taken.
        let mut addrs = association_addrs(src_addr, &node_id);
        addrs.retain(|ip| same_host(*ip, src_addr.ip()) || allowed.permits(*ip));
        if let Some(fqdn) = node_id_fqdn(&node_id) {
            for ip in resolve_node_id_fqdn(&fqdn).await {
                if allowed.permits(ip) && !addrs.contains(&ip) {
                    addrs.push(ip);
                }
            }
        }
        {
            let mut association = self.association.write().await;
            *association = Some(PfcpAssociation {
                peer_addr: src_addr,
                addrs,
                node_id,
                recovery_time_stamp: rts,
            });
            self.publish_associated(&association);
        }

        // #1513: a CP function that keeps its sessions is told the current path state
        // once this response is out (the run loop sends it): a report it refused while
        // it considered this UPF down, or one it never received, is not lost. Without
        // retention its sessions are gone, and with them what it was told.
        {
            let mut ledger = self.path_ledger.lock().unwrap();
            if sessions_retained {
                ledger.resends = 0;
                ledger.resend_at = Some(std::time::Instant::now());
            } else {
                *ledger = PathReportLedger::default();
            }
        }

        // #1389: a new association replaces the GTP-U path QoS monitoring with
        // what this request provisions (none clears it).
        self.apply_path_qos_control(payload, true);
        // #1389 part 2: likewise the N6 delay measurement (§5.33.8.2).
        self.apply_n6_delay_control(payload, true);

        let resp_payload = build_association_setup_response(
            &self.local_node_id,
            self.recovery_time_stamp,
            PfcpCause::RequestAccepted,
            sessions_retained,
            self.optional_features(),
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

    /// Answer a refused Association Setup Request with "Request rejected" (cause 64,
    /// §8.2.1) and change nothing.
    async fn reject_association_setup(&self, seq: u32, src_addr: SocketAddr) -> Result<(), String> {
        let resp_payload = build_association_setup_response(
            &self.local_node_id,
            self.recovery_time_stamp,
            PfcpCause::RequestRejected,
            false,
            self.optional_features(),
        );
        let response = self.build_response(
            pfcp_type::ASSOCIATION_SETUP_RESPONSE,
            0,
            seq,
            &resp_payload,
            false,
        );
        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;
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
        let (smf_seid, cp_f_seid_ipv4, cp_f_seid_ipv6) = match ParsedFSeid::parse(&f_seid_ie.value)
        {
            Ok(f_seid) => {
                log::debug!("SMF F-SEID: {:#x}", f_seid.seid);
                (f_seid.seid, f_seid.ipv4, f_seid.ipv6)
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

        // #1478: the Create QERs are parsed before anything is allocated. A malformed
        // one (an MBR or GBR shorter than its two 5-octet fields, TS 29.244 §8.2.8,
        // §8.2.9) rejects the establishment with "Mandatory IE incorrect" (§7.6.8). It
        // used to be dropped with a warning, so the session ran without that QER's
        // gates and rate caps.
        let mut parsed_qers = Vec::new();
        for qer_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_QER) {
            match parse_create_qer(&qer_ie.value) {
                Ok(qer) => {
                    log::debug!(
                        "QER {}: ul_gate={}, dl_gate={}, ul_mbr={} kbps, dl_mbr={} kbps, qfi={:?}",
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
                    log::warn!(
                        "Session Establishment from {src_addr}: malformed Create QER ({e}) — \
                         rejecting"
                    );
                    // #1598: a Create QER without its QER ID is "Conditional IE
                    // missing" with the QER ID's type (Create QER is C at
                    // establishment, Table 7.5.2.1-1, §7.2.2.4.1, §7.6.6); any other
                    // refusal stays "Mandatory IE incorrect" with the Create QER.
                    let resp_payload = match missing_rule_id(pfcp_ie::CREATE_QER, &qer_ie.value) {
                        Some(id) => {
                            build_failure_response(PfcpCause::ConditionalIeMissing, Some(id))
                        }
                        None => build_failure_response(
                            PfcpCause::MandatoryIeIncorrect,
                            Some(pfcp_ie::CREATE_QER),
                        ),
                    };
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
                    return Ok(());
                }
            }
        }

        // #1532: the Create PDRs, FARs and URRs too, before anything is allocated. A
        // Create PDR, FAR or URR its parser refuses (a malformed F-TEID, UE IP
        // Address or Outer Header Creation inside it) is a mandatory or verifiable
        // conditional IE with a semantically invalid value, so the request is
        // discarded and answered "Mandatory IE incorrect" with the offending grouped
        // IE (TS 29.244 §7.6.8), as Session Modification already does
        // (`parse_rule_list`). #1598: one with no PDR/FAR/URR ID is instead a missing
        // IE, cause 66 for the Mandatory Create PDR and FAR and 67 for the
        // Conditional Create URR (`RuleIdPresence`). These used to be logged and
        // skipped, so the session ran without that rule: a PDR that never matched,
        // a missing FAR, a URR that never reported.
        let mut malformed: Option<N4Failure> = None;
        let create_pdrs = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_PDR,
            RuleIdPresence::Mandatory,
            parse_create_pdr,
            &mut malformed,
        );
        let create_fars = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_FAR,
            RuleIdPresence::Mandatory,
            parse_create_far,
            &mut malformed,
        );
        let create_urrs = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_URR,
            RuleIdPresence::Conditional,
            parse_create_urr,
            &mut malformed,
        );
        if let Some(failure) = malformed {
            log::warn!("Session Establishment from {src_addr}: {failure:?} — rejecting");
            let resp_payload = failure.response_body();
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
            return Ok(());
        }

        // Allocate UPF SEID
        let upf_seid = self.alloc_seid();
        log::debug!("Allocated UPF SEID: {upf_seid:#x}");

        // Parse Create PDRs
        let mut ue_ipv4: Option<Ipv4Addr> = None;
        let mut ul_teid: u32 = 0;
        let mut created_pdrs = Vec::new();
        let mut parsed_pdrs = Vec::new();
        // #1682: the TEID each PDR detects on, for `SessionRuleIds::pdr_teids`.
        let mut pdr_teids: HashMap<u16, u32> = HashMap::new();
        // #1815: the TEIDs this request holds in the pool, chosen or (#1834) named
        // by the CP function and reserved; given back if it is refused.
        let mut chosen_teids: Vec<u32> = Vec::new();

        for pdr in create_pdrs {
            log::debug!(
                "PDR {}: src_if={}, precedence={}, far_id={:?}, qer_ids={:?}, urr_ids={:?}",
                pdr.pdr_id,
                pdr.pdi.source_interface,
                pdr.precedence,
                pdr.far_id,
                pdr.qer_ids,
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
                    // #1815: one TEID per PDR here, as before; no CHOOSE ID sharing
                    // at establishment.
                    let chosen = self.local_f_teid_addrs(fteid).and_then(|addrs| {
                        let teid =
                            self.choose_teid(None, &mut HashMap::new(), &mut chosen_teids)?;
                        Some((addrs, teid))
                    });
                    let Some(((ipv4, ipv6), teid)) = chosen else {
                        // #985 review: an IPv6-only F-TEID this UPF cannot
                        // assign refuses the establishment (§7.5.3.1), and so
                        // does an exhausted TEID pool (#1815).
                        // #1154: the Failed Rule ID, not an Offending IE.
                        // #1815: the TEIDs earlier PDRs took go back.
                        self.release_teids(chosen_teids.drain(..));
                        let resp_payload = crate::n4_build::build_rule_failure_response(
                            crate::n4_build::FailedRule::Pdr(pdr.pdr_id),
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
                        return Ok(());
                    };
                    ul_teid = teid;
                    pdr_teids.insert(pdr.pdr_id, ul_teid);
                    log::debug!(
                        "Allocated uplink F-TEID: teid={ul_teid:#x} (ch={})",
                        fteid.ch
                    );
                    Some(FTeid {
                        teid: ul_teid,
                        ipv4,
                        ipv6,
                        choose: false,
                        choose_id: None,
                    })
                } else {
                    // #1834: a TEID the SMF named itself is held in the pool like a
                    // chosen one, so no later CHOOSE hands it to another session. One
                    // another session (or request) already holds would route that
                    // session's uplink here: refused as a rule failure (§7.5.3.1),
                    // and the TEIDs earlier PDRs took go back. PDRs of this one
                    // establishment may share it.
                    let teid = fteid.teid;
                    if !chosen_teids.contains(&teid) {
                        if !self.teids.reserve(teid) {
                            log::warn!(
                                "PDR {}: F-TEID {teid:#x} named by the CP function is \
                                 another session's; the establishment is refused",
                                pdr.pdr_id
                            );
                            self.release_teids(chosen_teids.drain(..));
                            let resp_payload = crate::n4_build::build_rule_failure_response(
                                crate::n4_build::FailedRule::Pdr(pdr.pdr_id),
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
                            return Ok(());
                        }
                        chosen_teids.push(teid);
                    }
                    ul_teid = teid;
                    pdr_teids.insert(pdr.pdr_id, ul_teid);
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

        // Parse Create FARs
        let mut dl_teid: u32 = 0;
        let mut gnb_addr: Option<Ipv4Addr> = None;
        let mut parsed_fars = Vec::new();

        for far in create_fars {
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

        // #619 (#1170 review): the session's downlink tunnel is the one its catch-all
        // downlink takes -- the FAR of the Core-source PDR with no SDF filter (the
        // default bearer's / flow's). A dedicated bearer's Core PDR carries its TFT's
        // filters and a FAR toward its own tunnel; taking the last OHC on the wire
        // made that FAR the session's whenever it came after the default one. With no
        // such PDR the last OHC stands, as before.
        if let Some((teid, addr)) = parsed_pdrs
            .iter()
            .filter(|p| p.pdi.source_interface == 1 && p.pdi.sdf_flow_description.is_none())
            .filter_map(|p| p.far_id)
            .find_map(|id| {
                parsed_fars
                    .iter()
                    .find(|f| f.far_id == id)
                    .and_then(|f| f.forwarding_parameters.as_ref())
                    .and_then(|fp| fp.outer_header_creation.as_ref())
                    .map(|ohc| (ohc.teid, ohc.ipv4))
            })
        {
            dl_teid = teid;
            gnb_addr = addr;
        }

        // Parse Create URRs
        let mut parsed_urrs = Vec::new();
        for urr in create_urrs {
            log::debug!(
                "URR {}: vol_thresh={:?}, time_thresh={:?}",
                urr.urr_id,
                urr.volume_threshold_total,
                urr.time_threshold_secs
            );
            parsed_urrs.push(urr);
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

        // #1389 part 3: Create SRR (Table 7.5.2.9-1), acted on only with QFQM. A
        // malformed one is logged and skipped, as a malformed PDR is above.
        let mut parsed_srrs = Vec::new();
        if self.qfqm() {
            for srr_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_SRR) {
                match crate::n4_build::parse_srr(&srr_ie.value) {
                    Ok(srr) => parsed_srrs.push(srr),
                    Err(e) => log::warn!("Failed to parse Create SRR: {e}"),
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

        if let Err(e) = self.socket.send_to(&response, src_addr).await {
            // #1815: the session is not stored, so nothing would ever give its TEIDs
            // back; the CP function's retransmission chooses afresh.
            self.release_teids(chosen_teids);
            return Err(format!("Send error: {e}"));
        }

        // Store session info, including which rule ids the session now holds so a
        // later modification's Update/Remove can be validated against them (#306).
        let session_info = PfcpSessionInfo {
            upf_seid,
            smf_seid,
            smf_addr: src_addr,
            cp_f_seid_ipv4,
            cp_f_seid_ipv6,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
            rules: SessionRuleIds {
                pdr_ids: parsed_pdrs.iter().map(|p| p.pdr_id).collect(),
                far_ids: parsed_fars.iter().map(|f| f.far_id).collect(),
                qer_ids: parsed_qers.iter().map(|q| q.qer_id).collect(),
                urr_ids: parsed_urrs.iter().map(|u| u.urr_id).collect(),
                own_tunnel_far_ids: own_tunnel_fars_established(
                    &parsed_pdrs,
                    &parsed_fars,
                    (dl_teid, gnb_addr),
                ),
                srr_ids: parsed_srrs.iter().map(|r| r.srr_id).collect(),
                pdr_teids,
                held_teids: chosen_teids.into_iter().collect(),
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
        self.apply_srrs(upf_seid, &[], &parsed_srrs, &[]);

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
        let mut failure: Option<N4Failure> = None;

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
        // Query URR (IE 77, TS 29.244 §7.5.4.10): report these URRs' ongoing
        // measurement now. The per-URR counterpart of the QAURR flag below, which
        // this daemon has honoured since #306 while the explicit IE was ignored
        // outright -- an SMF naming individual URRs got a bare acceptance and no
        // reports, which is the same defect QAURR had before #306, one level down.
        //
        // Parsed with the same helper as the removals so a Query URR whose URR ID
        // sub-IE is missing or short is counted as malformed below rather than
        // silently dropped.
        let queried_urr_ids: Vec<u32> = ParsedIe::find_all_ies(&ies, pfcp_ie::QUERY_URR)
            .iter()
            .filter_map(|ie| parse_rule_id_u32(&ie.value, pfcp_ie::URR_ID))
            .collect();
        // #1835: Query URR Reference (IE 125, §8.2.90, an Unsigned32). Optional,
        // beside a Query URR or QAURR (Table 7.5.4.1-1), and echoed in every usage
        // report sent in response to the query (§5.2.2.3.1, Table 7.5.5.2-1), so the
        // SMF can tell which query a report answers. It was not parsed at all. One
        // too short to hold its value is an optional IE with an invalid value, so it
        // is discarded and the message processed as if it were absent (§7.6.8).
        let query_urr_reference: Option<u32> =
            ParsedIe::find_ie(&ies, pfcp_ie::QUERY_URR_REFERENCE).and_then(|ie| {
                let value = ie.value.get(..4).and_then(|v| <[u8; 4]>::try_from(v).ok());
                if value.is_none() {
                    log::warn!(
                        "Query URR Reference shorter than its 4-octet value; discarded \
                         (TS 29.244 §7.6.8)"
                    );
                }
                value.map(u32::from_be_bytes)
            });

        // A Remove IE whose rule-id sub-IE is missing or short is malformed, and is
        // reported rather than skipped: silently dropping it is the defect #306 is
        // about, one level down. #1598: a missing ID is "Conditional IE missing"
        // with the ID's own type (every Remove and Query IE is C in a Session
        // Modification, §7.2.2.4.1, §7.6.6); a present but short one is "Mandatory
        // IE incorrect" with the grouped IE (§7.6.8), as a short Create QER ID is.
        for ie_type in [
            pfcp_ie::REMOVE_PDR,
            pfcp_ie::REMOVE_FAR,
            pfcp_ie::REMOVE_QER,
            pfcp_ie::REMOVE_URR,
            pfcp_ie::QUERY_URR,
        ] {
            for ie in ParsedIe::find_all_ies(&ies, ie_type) {
                let id_ok = if ie_type == pfcp_ie::REMOVE_PDR {
                    parse_rule_id_u16(&ie.value, pfcp_ie::PDR_ID).is_some()
                } else {
                    embedded_rule_id_ie(ie_type)
                        .and_then(|id| parse_rule_id_u32(&ie.value, id))
                        .is_some()
                };
                if id_ok {
                    continue;
                }
                if let Some(id) = missing_rule_id(ie_type, &ie.value) {
                    log::warn!("Remove/Query IE {ie_type} carries no rule ID (IE {id})");
                    note_first_failure(&mut failure, PfcpCause::ConditionalIeMissing, id);
                } else {
                    log::warn!("Remove/Query IE {ie_type} carries a short rule ID");
                    note_first_failure(&mut failure, PfcpCause::MandatoryIeIncorrect, ie_type);
                }
            }
        }

        // ---- Creates and updates ----
        // Update X carries the same IE set as Create X (Table 7.5.4.2-1 vs
        // 7.5.2.2-1 and siblings), so the establishment path's parsers are reused
        // rather than duplicated.
        let mut created_pdrs = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_PDR,
            RuleIdPresence::Conditional,
            crate::n4_build::parse_create_pdr,
            &mut failure,
        );
        // #583: a PDR created mid-session whose F-TEID the UP function is to choose (CH,
        // or a zero TEID as this tree's SMF signals it) gets one now, exactly as at
        // establishment, and the response carries it in a Created PDR (TS 29.244
        // §7.5.5.2). Before this the modification answered no Created PDR at all, so the
        // N3 uplink of an EPS→5GS handover and every indirect forwarding tunnel had no
        // F-TEID. PDRs sharing a CHOOSE ID share the TEID (§5.5.3). The allocated value is
        // written back into the parsed PDR, so the data plane detects on it.
        let mut allocated_pdrs = Vec::new();
        // #1682: shared with the Update PDRs below, so a CHOOSE ID names one TEID
        // across the whole message.
        let mut by_choose_id: HashMap<u8, u32> = HashMap::new();
        // #1815: every TEID this message takes from the pool. A rejected modification
        // applies nothing (TS 29.244 §6.3.3), so they all go back; an accepted one
        // hands them to the session.
        let mut chosen_teids: Vec<u32> = Vec::new();
        {
            for pdr in created_pdrs.iter_mut() {
                let Some(fteid) = pdr.pdi.local_f_teid.as_mut() else {
                    continue;
                };
                if !(fteid.ch || fteid.teid == 0) {
                    continue;
                }
                let Some((ipv4, ipv6)) = self.local_f_teid_addrs(fteid) else {
                    // #985 review: refused, not answered with an IPv4 F-TEID.
                    note_first_rule_failure(
                        &mut failure,
                        crate::n4_build::FailedRule::Pdr(pdr.pdr_id),
                    );
                    continue;
                };
                let choose_id = fteid.choose_id.filter(|_| fteid.chid);
                let Some(teid) = self.choose_teid(choose_id, &mut by_choose_id, &mut chosen_teids)
                else {
                    log::warn!("PDR {}: no free TEID; refused", pdr.pdr_id);
                    note_first_rule_failure(
                        &mut failure,
                        crate::n4_build::FailedRule::Pdr(pdr.pdr_id),
                    );
                    continue;
                };
                *fteid = crate::n4_build::ParsedFTeid {
                    teid,
                    ipv4,
                    ipv6,
                    v4: ipv4.is_some(),
                    v6: ipv6.is_some(),
                    ch: false,
                    chid: false,
                    choose_id: None,
                };
                log::debug!(
                    "PDR {}: allocated F-TEID {teid:#x} in a modification",
                    pdr.pdr_id
                );
                allocated_pdrs.push(CreatedPdr {
                    pdr_id: pdr.pdr_id,
                    local_f_teid: Some(FTeid {
                        teid,
                        ipv4,
                        ipv6,
                        choose: false,
                        choose_id: None,
                    }),
                    ue_ip_address: None,
                });
            }
        }
        let mut updated_pdrs = parse_rule_list(
            &ies,
            pfcp_ie::UPDATE_PDR,
            RuleIdPresence::Conditional,
            // #1673: only the changes it carries (TS 29.244 §5.6.3).
            crate::n4_build::parse_update_pdr,
            &mut failure,
        );
        // #1682: an Update PDR's PDI replaces the stored one (Table 7.5.4.2-1), so a
        // Local F-TEID in it with CHOOSE set (or this tree's zero TEID) asks for a new
        // F-TEID, allocated as for a Create PDR above, and the response carries it in
        // an Updated PDR (§7.5.5.5). The value is written back into the parsed PDI, so
        // the data plane detects on it.
        let mut reallocated_pdrs = Vec::new();
        for pdr in updated_pdrs.iter_mut() {
            let Some(fteid) = pdr.pdi.as_mut().and_then(|p| p.local_f_teid.as_mut()) else {
                continue;
            };
            if !(fteid.ch || fteid.teid == 0) {
                continue;
            }
            let Some((ipv4, ipv6)) = self.local_f_teid_addrs(fteid) else {
                note_first_rule_failure(&mut failure, crate::n4_build::FailedRule::Pdr(pdr.pdr_id));
                continue;
            };
            let choose_id = fteid.choose_id.filter(|_| fteid.chid);
            let Some(teid) = self.choose_teid(choose_id, &mut by_choose_id, &mut chosen_teids)
            else {
                log::warn!("Update PDR {}: no free TEID; refused", pdr.pdr_id);
                note_first_rule_failure(&mut failure, crate::n4_build::FailedRule::Pdr(pdr.pdr_id));
                continue;
            };
            *fteid = crate::n4_build::ParsedFTeid {
                teid,
                ipv4,
                ipv6,
                v4: ipv4.is_some(),
                v6: ipv6.is_some(),
                ch: false,
                chid: false,
                choose_id: None,
            };
            log::debug!("Update PDR {}: allocated F-TEID {teid:#x}", pdr.pdr_id);
            reallocated_pdrs.push(CreatedPdr {
                pdr_id: pdr.pdr_id,
                local_f_teid: Some(FTeid {
                    teid,
                    ipv4,
                    ipv6,
                    choose: false,
                    choose_id: None,
                }),
                ue_ip_address: None,
            });
        }
        let created_fars = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_FAR,
            RuleIdPresence::Conditional,
            parse_create_far,
            &mut failure,
        );
        let mod_fars = parse_rule_list(
            &ies,
            pfcp_ie::UPDATE_FAR,
            RuleIdPresence::Conditional,
            parse_create_far,
            &mut failure,
        );
        let created_qers = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_QER,
            RuleIdPresence::Conditional,
            parse_create_qer,
            &mut failure,
        );
        // #1478: an Update QER keeps which IEs it carries (Table 7.5.4.5-1).
        let mod_qers = parse_rule_list(
            &ies,
            pfcp_ie::UPDATE_QER,
            RuleIdPresence::Conditional,
            crate::n4_build::parse_update_qer,
            &mut failure,
        );
        let created_urrs = parse_rule_list(
            &ies,
            pfcp_ie::CREATE_URR,
            RuleIdPresence::Conditional,
            crate::n4_build::parse_create_urr,
            &mut failure,
        );
        let mod_urrs = parse_rule_list(
            &ies,
            pfcp_ie::UPDATE_URR,
            RuleIdPresence::Conditional,
            crate::n4_build::parse_create_urr,
            &mut failure,
        );
        // #1389 part 3: Remove / Create / Update SRR (Tables 7.5.4.19-1, 7.5.2.9-1,
        // 7.5.4.20-1), acted on only with QFQM: a UPF that did not advertise it
        // ignores them, as before.
        let (removed_srr_ids, created_srrs, mod_srrs) = if self.qfqm() {
            let removes = ParsedIe::find_all_ies(&ies, pfcp_ie::REMOVE_SRR);
            let removed: Vec<u8> = removes
                .iter()
                .filter_map(|ie| crate::n4_build::parse_remove_srr(&ie.value))
                .collect();
            // #1598: as for the other Remove IEs, a missing SRR ID is cause 67
            // with the SRR ID's type, an empty one 69 with the Remove SRR.
            for ie in &removes {
                if crate::n4_build::parse_remove_srr(&ie.value).is_some() {
                    continue;
                }
                log::warn!("a Remove SRR carried no usable SRR ID");
                match missing_rule_id(pfcp_ie::REMOVE_SRR, &ie.value) {
                    Some(id) => {
                        note_first_failure(&mut failure, PfcpCause::ConditionalIeMissing, id)
                    }
                    None => note_first_failure(
                        &mut failure,
                        PfcpCause::MandatoryIeIncorrect,
                        pfcp_ie::REMOVE_SRR,
                    ),
                }
            }
            (
                removed,
                parse_rule_list(
                    &ies,
                    pfcp_ie::CREATE_SRR,
                    RuleIdPresence::Conditional,
                    crate::n4_build::parse_srr,
                    &mut failure,
                ),
                parse_rule_list(
                    &ies,
                    pfcp_ie::UPDATE_SRR,
                    RuleIdPresence::Conditional,
                    crate::n4_build::parse_srr,
                    &mut failure,
                ),
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        // The DL tunnel this session forwards on is whatever the LAST Outer Header
        // Creation on the message names, from a Create or an Update alike. Creates
        // are considered first so an Update in the same message wins, which is the
        // order §7.5.4 applies them in.
        //
        // #583: except a FAR created together with an ACCESS-source PDR that uses it --
        // a tunnel relaying toward the access side (indirect data forwarding), whose
        // endpoint is its own and not the session's downlink.
        //
        // #619: and likewise a FAR created together with a CORE-source PDR that uses
        // it: a second downlink tunnel of the session (a dedicated EPS bearer's own
        // S5/S8-U tunnel, TS 23.401 §5.4.1). Counting it as the session's tunnel
        // moving re-pointed the default bearer's FAR at the dedicated bearer's TEID.
        // Such a FAR is remembered (`own_tunnel_far_ids`, and the data plane's
        // `DataPlaneSession::own_tunnel_fars`), so a later Update FAR on it moves that
        // FAR alone, and a move of the session's tunnel leaves it where it points. Which Updates move the session's tunnel therefore
        // depends on the session, and is decided under its lock below.
        let own_tunnel_fars = own_tunnel_fars_created(&created_pdrs, &created_fars);
        let tunnel_of = |far: &crate::n4_build::ParsedCreateFar| {
            far.forwarding_parameters
                .as_ref()
                .and_then(|fp| fp.outer_header_creation.as_ref())
                .map(|ohc| (far.far_id, ohc.teid, ohc.ipv4))
        };
        let created_tunnels: Vec<(u32, u32, Option<Ipv4Addr>)> = created_fars
            .iter()
            .filter(|f| !own_tunnel_fars.contains(&f.far_id))
            .filter_map(tunnel_of)
            .collect();
        let updated_tunnels: Vec<(u32, u32, Option<Ipv4Addr>)> =
            mod_fars.iter().filter_map(tunnel_of).collect();

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
        // #1816: QAURR and the Query URR IE are EXCLUSIVE in one Session Modification
        // Request (TS 29.244 Table 7.5.4.1-1 NOTE 3, `29244-k00.txt:22672`), so a
        // request carrying both is not one the CP function may send. It is REJECTED,
        // here with the rest of the message's checks so that nothing of it is applied
        // (§6.3.3): no rule changes, and no URR reports or resets its counters.
        // Before, it was answered Request accepted with no Usage Report at all, which
        // told the SMF its query had been honoured. Cause "Mandatory IE incorrect"
        // with the PFCPSMReq-Flags as the offending IE (§7.6.8): each Query URR is
        // well formed on its own, and it is the QAURR bit that NOTE 3 rules out
        // beside them.
        if query_all_urrs && !queried_urr_ids.is_empty() {
            log::warn!(
                "Session Modification for SEID {upf_seid:#x} carries BOTH the QAURR flag \
                 and {} Query URR IE(s), which TS 29.244 Table 7.5.4.1-1 NOTE 3 makes \
                 exclusive; rejected, nothing applied",
                queried_urr_ids.len()
            );
            note_first_failure(
                &mut failure,
                PfcpCause::MandatoryIeIncorrect,
                pfcp_ie::PFCPSMREQ_FLAGS,
            );
        }

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
            // #1682: an Update PDR's new F-TEID or UE IP address must not be another
            // session's: that key routes the other session's uplink or downlink, so
            // taking it would hijack its traffic. Checked against every other session
            // here, under the same lock that commits the change below. A linear scan,
            // and only for an Update PDR that carries a PDI with one of these keys.
            let key_collisions: Vec<u16> = updated_pdrs
                .iter()
                .filter_map(|u| {
                    let pdi = u.pdi.as_ref()?;
                    let teid = pdi.local_f_teid.as_ref().map(|f| f.teid);
                    let ue_ip = update_pdr_ue_ipv4(pdi);
                    sessions
                        .iter()
                        .filter(|(seid, _)| **seid != upf_seid)
                        .any(|(_, other)| {
                            teid.is_some_and(|t| other.rules.pdr_teids.values().any(|v| *v == t))
                                || (ue_ip.is_some() && other.ue_ipv4 == ue_ip)
                        })
                        .then_some(u.pdr_id)
                })
                .collect();
            if let Some(session) = sessions.get_mut(&upf_seid) {
                let old_tunnel = session.gnb_addr.map(|addr| (session.dl_teid, addr));
                // #1682 review M1: a collision is known before anything is written, so
                // a colliding modification writes NOTHING here: no rule IDs removed or
                // created, no `dl_teid`/`gnb_addr` moved, no TSC applied. TS 29.244
                // §6.3.3 (29244-k00.txt:13687-13693): a rejected request leaves the
                // PFCP session context "as if the PFCP Session Modification Request
                // had not been received". The data plane is left alone below too.
                if !key_collisions.is_empty() {
                    for pdr_id in &key_collisions {
                        log::warn!(
                            "Update PDR {pdr_id} on SEID {upf_seid:#x}: its F-TEID or UE IP \
                             address is another session's; refused, nothing applied"
                        );
                        note_first_rule_failure(
                            &mut failure,
                            crate::n4_build::FailedRule::Pdr(*pdr_id),
                        );
                    }
                } else {
                    // #1741: every check that can reject the modification runs BEFORE
                    // anything is written. A rejected request leaves the PFCP session
                    // context "as if the PFCP Session Modification Request had not been
                    // received" (TS 29.244 §6.3.3, 29244-k00.txt:13687-13693), so the
                    // "no such rule" refusals below are judged against the rule set the
                    // message WOULD leave (held, minus its removals, plus its creates, in
                    // §7.5.4's order), and only an accepted modification then writes it.
                    // #1834: a TEID the CP function names itself in a Create PDR or
                    // an Update PDR must not be one the pool holds for another
                    // session (or for this message's own CHOOSE): that would route
                    // the other session's uplink here. One this session already
                    // holds is fine, since its PDRs may share an F-TEID. The rest are
                    // reserved below, only if the modification is accepted.
                    let mut cp_teids: Vec<u32> = Vec::new();
                    let named = created_pdrs
                        .iter()
                        .map(|p| (p.pdr_id, p.pdi.local_f_teid.as_ref()))
                        .chain(updated_pdrs.iter().map(|u| {
                            (
                                u.pdr_id,
                                u.pdi.as_ref().and_then(|p| p.local_f_teid.as_ref()),
                            )
                        }));
                    for (pdr_id, fteid) in named {
                        let Some(teid) = fteid.filter(|f| !f.ch && f.teid != 0).map(|f| f.teid)
                        else {
                            continue;
                        };
                        if chosen_teids.contains(&teid)
                            || session.rules.held_teids.contains(&teid)
                            || cp_teids.contains(&teid)
                        {
                            continue;
                        }
                        if self.teids.is_held(teid) {
                            log::warn!(
                                "PDR {pdr_id} on SEID {upf_seid:#x}: F-TEID {teid:#x} named \
                                 by the CP function is another session's; refused"
                            );
                            note_first_rule_failure(
                                &mut failure,
                                crate::n4_build::FailedRule::Pdr(pdr_id),
                            );
                        } else {
                            cp_teids.push(teid);
                        }
                    }

                    for r in &mod_srrs {
                        if !held_after(
                            &session.rules.srr_ids,
                            &removed_srr_ids,
                            created_srrs.iter().map(|c| c.srr_id),
                            r.srr_id,
                        ) {
                            log::warn!(
                                "Update SRR {}: no such rule on SEID {upf_seid:#x}",
                                r.srr_id
                            );
                            note_first_rule_failure(
                                &mut failure,
                                crate::n4_build::FailedRule::Srr(r.srr_id),
                            );
                        }
                    }

                    // Updating a rule the session does NOT hold is a different case from
                    // removing one: the new threshold, gate or forwarding action has
                    // nowhere to land, so the CP function's intent is not satisfied and
                    // §7.5.5's Rule creation/modification Failure is the truthful answer.
                    // Ignoring it is precisely the "accepted a modification it did not
                    // apply" defect this issue is about.
                    for p in &updated_pdrs {
                        if !held_after(
                            &session.rules.pdr_ids,
                            &removed_pdr_ids,
                            created_pdrs.iter().map(|c| c.pdr_id),
                            p.pdr_id,
                        ) {
                            log::warn!(
                                "Update PDR {}: no such rule on SEID {upf_seid:#x}",
                                p.pdr_id
                            );
                            note_first_rule_failure(
                                &mut failure,
                                crate::n4_build::FailedRule::Pdr(p.pdr_id),
                            );
                        }
                    }
                    for f in &mod_fars {
                        if !held_after(
                            &session.rules.far_ids,
                            &removed_far_ids,
                            created_fars.iter().map(|c| c.far_id),
                            f.far_id,
                        ) {
                            log::warn!(
                                "Update FAR {}: no such rule on SEID {upf_seid:#x}",
                                f.far_id
                            );
                            note_first_rule_failure(
                                &mut failure,
                                crate::n4_build::FailedRule::Far(f.far_id),
                            );
                        }
                    }
                    for q in &mod_qers {
                        if !held_after(
                            &session.rules.qer_ids,
                            &removed_qer_ids,
                            created_qers.iter().map(|c| c.qer_id),
                            q.qer_id,
                        ) {
                            log::warn!(
                                "Update QER {}: no such rule on SEID {upf_seid:#x}",
                                q.qer_id
                            );
                            note_first_rule_failure(
                                &mut failure,
                                crate::n4_build::FailedRule::Qer(q.qer_id),
                            );
                        }
                    }
                    for u in &mod_urrs {
                        if !held_after(
                            &session.rules.urr_ids,
                            &removed_urr_ids,
                            created_urrs.iter().map(|c| c.urr_id),
                            u.urr_id,
                        ) {
                            log::warn!(
                                "Update URR {}: no such rule on SEID {upf_seid:#x}",
                                u.urr_id
                            );
                            note_first_rule_failure(
                                &mut failure,
                                crate::n4_build::FailedRule::Urr(u.urr_id),
                            );
                        }
                    }

                    if failure.is_none() {
                        for id in &removed_far_ids {
                            session.rules.own_tunnel_far_ids.remove(id);
                        }
                        for f in &created_fars {
                            if own_tunnel_fars.contains(&f.far_id) {
                                session.rules.own_tunnel_far_ids.insert(f.far_id);
                            } else {
                                // A re-created id that is now an ordinary FAR.
                                session.rules.own_tunnel_far_ids.remove(&f.far_id);
                            }
                        }
                        for &(far_id, teid, ipv4) in created_tunnels.iter().chain(
                            updated_tunnels
                                .iter()
                                .filter(|(id, ..)| !session.rules.own_tunnel_far_ids.contains(id)),
                        ) {
                            updated_dl_teid = Some(teid);
                            updated_gnb_addr = ipv4;
                            log::debug!(
                                "Updated downlink: FAR {far_id}, TEID={teid:#x}, gNB={ipv4:?}"
                            );
                        }
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
                                log::debug!(
                                    "Remove PDR {id}: not held by SEID {upf_seid:#x}, idempotent"
                                );
                            }
                        }
                        for id in &removed_far_ids {
                            if !session.rules.far_ids.remove(id) {
                                log::debug!(
                                    "Remove FAR {id}: not held by SEID {upf_seid:#x}, idempotent"
                                );
                            }
                        }
                        for id in &removed_qer_ids {
                            if !session.rules.qer_ids.remove(id) {
                                log::debug!(
                                    "Remove QER {id}: not held by SEID {upf_seid:#x}, idempotent"
                                );
                            }
                        }
                        for id in &removed_urr_ids {
                            if !session.rules.urr_ids.remove(id) {
                                log::debug!(
                                    "Remove URR {id}: not held by SEID {upf_seid:#x}, idempotent"
                                );
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
                        for id in &removed_srr_ids {
                            if !session.rules.srr_ids.remove(id) {
                                log::debug!(
                                    "Remove SRR {id}: not held by SEID {upf_seid:#x}, idempotent"
                                );
                            }
                        }
                        for r in &created_srrs {
                            session.rules.srr_ids.insert(r.srr_id);
                        }
                        // #1682: which F-TEID each PDR detects on, and the session's UE IP
                        // address, in §7.5.4's order (remove, create, update). Committed only
                        // for a modification that is accepted: a rejected one applies nothing
                        // (below), so recording its keys would refuse a later session the TEID
                        // or address this one never took.
                        let teids = &mut session.rules.pdr_teids;
                        for id in &removed_pdr_ids {
                            teids.remove(id);
                        }
                        let pdis = created_pdrs.iter().map(|p| (p.pdr_id, &p.pdi)).chain(
                            updated_pdrs
                                .iter()
                                .filter_map(|u| Some((u.pdr_id, u.pdi.as_ref()?))),
                        );
                        for (pdr_id, pdi) in pdis {
                            match pdi.local_f_teid.as_ref().filter(|f| !f.ch && f.teid != 0) {
                                Some(f) => teids.insert(pdr_id, f.teid),
                                None => teids.remove(&pdr_id),
                            };
                        }
                        // #1815: the session now holds what this message chose, and a
                        // chosen TEID no PDR detects on any more (removed, or moved by
                        // an Update PDR) goes back to the pool.
                        let chosen = &mut session.rules.held_teids;
                        chosen.extend(chosen_teids.drain(..));
                        // #1834: and the CP-named TEIDs it now detects on.
                        for teid in cp_teids {
                            self.teids.reserve(teid);
                            chosen.insert(teid);
                        }
                        let held: std::collections::HashSet<u32> =
                            teids.values().copied().collect();
                        let freed: Vec<u32> = chosen
                            .iter()
                            .filter(|t| !held.contains(t))
                            .copied()
                            .collect();
                        for teid in &freed {
                            chosen.remove(teid);
                        }
                        self.release_teids(freed);
                        for u in &updated_pdrs {
                            if let Some(ip) = u.pdi.as_ref().and_then(update_pdr_ue_ipv4) {
                                session.ue_ipv4 = Some(ip);
                            }
                        }
                    }

                    // #321: apply the TSC containers in the SAME critical section as the
                    // rule bookkeeping, so the response's echo (IE 200) describes state
                    // that is already committed rather than state a concurrent
                    // modification could still change.
                    // #1741: and only for an accepted modification.
                    if failure.is_none() && !tsc_ies.is_empty() {
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
        // #1815: a modification that did not commit (rejected, or for an unknown
        // SEID) gives back every TEID it chose; an accepted one drained them into
        // the session above.
        self.release_teids(chosen_teids);
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
        //
        // #1741: only for an ACCEPTED modification. Taking a report resets the URR's
        // counters (§5.2.2.3.1), and a rejected response carries no Usage Report, so a
        // rejected Remove URR or QAURR taken here lost that usage outright: it reached
        // neither this response nor any later report. A rejected request applies
        // nothing (§6.3.3), and the counters are part of what it must not touch.
        let mut usage_reports = Vec::new();
        if failure.is_none() && !removed_urr_ids.is_empty() {
            usage_reports.extend(self.collect_usage_reports(
                upf_seid,
                Some(&removed_urr_ids),
                UsageReportReason::Termination,
            ));
        }
        // QAURR together with a Query URR IE was rejected above (#1816, NOTE 3), so
        // at most one of the two forms reaches here.
        if failure.is_none() && (query_all_urrs || !queried_urr_ids.is_empty()) {
            let already: std::collections::HashSet<u32> =
                usage_reports.iter().map(|r| r.urr_id).collect();
            // `None` means every URR of the session (QAURR); `Some(ids)` means the
            // ones the Query URR IEs named. One call either way, so the two forms
            // cannot drift in how they build a report.
            let only: Option<&[u32]> = if query_all_urrs {
                None
            } else {
                Some(&queried_urr_ids)
            };
            usage_reports.extend(
                self.collect_usage_reports(upf_seid, only, UsageReportReason::Immediate)
                    .into_iter()
                    // A URR removed by this same message has already reported with
                    // TERMR; reporting it twice would double-count it.
                    .filter(|r| !already.contains(&r.urr_id))
                    // #1835: each report answering the query carries its reference.
                    // A TERMR report for a removed URR answers the removal, not the
                    // query, so it carries none.
                    .map(|mut r| {
                        r.query_urr_reference = query_urr_reference;
                        r
                    }),
            );
        }

        // Build response. A rule operation that could not be honoured answers with
        // §7.5.5's Cause and Offending IE instead of a bare RequestAccepted — the
        // whole point of #306.
        let resp_payload = match failure {
            Some(why) => {
                log::warn!("Session Modification for SEID {upf_seid:#x} rejected: {why:?}");
                why.response_body()
            }
            None => build_session_modification_response_full(
                pfcp_type::SESSION_MODIFICATION_RESPONSE,
                &allocated_pdrs,
                &reallocated_pdrs,
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

        // #1389 part 3: what a stopped QoS monitoring measured is reported once
        // more (§5.24.4.3), after the response.
        let stop_reports = self.apply_srrs(upf_seid, &removed_srr_ids, &created_srrs, &mod_srrs);
        if !stop_reports.is_empty() {
            if let Err(e) = self
                .send_qos_monitoring_report(upf_seid, &stop_reports)
                .await
            {
                log::warn!("QoS monitoring stop report was NOT sent: {e}");
            }
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
        // #1815: the session's TEIDs go back with it.
        if let Some(info) = &session_info {
            self.release_teids(info.rules.held_teids.iter().copied());
        }

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

    /// #1389: enable per GTP-U path QoS monitoring (GPQM, TS 29.244 §5.24.5).
    pub fn set_path_qos_monitoring(&self, enabled: bool) {
        self.gpqm.store(enabled, Ordering::Relaxed);
    }

    fn gpqm(&self) -> bool {
        self.gpqm.load(Ordering::Relaxed)
    }

    /// #1389 part 2: enable N6 delay measurement and reporting (UN6DM, TS 29.244
    /// §5.33.8).
    pub fn set_n6_delay_measurement(&self, enabled: bool) {
        self.un6dm.store(enabled, Ordering::Relaxed);
    }

    fn un6dm(&self) -> bool {
        self.un6dm.load(Ordering::Relaxed)
    }

    /// #1389 part 3: enable per QoS flow per UE QoS monitoring for packet delay
    /// (QFQM, TS 29.244 §5.24.4).
    pub fn set_qos_flow_monitoring(&self, enabled: bool) {
        self.qfqm.store(enabled, Ordering::Relaxed);
    }

    fn qfqm(&self) -> bool {
        self.qfqm.load(Ordering::Relaxed)
    }

    fn optional_features(&self) -> crate::n4_build::OptionalFeatures {
        crate::n4_build::OptionalFeatures {
            gpqm: self.gpqm(),
            un6dm: self.un6dm(),
            qfqm: self.qfqm(),
        }
    }

    /// #1389 part 3: apply an establishment's or modification's SRR operations to
    /// the per QoS flow monitor, in §7.5.4's order (remove, create, update).
    /// Returns the stop reports of the monitoring that ended.
    fn apply_srrs(
        &self,
        upf_seid: u64,
        removed: &[u8],
        created: &[crate::n4_build::ParsedSrr],
        updated: &[crate::n4_build::ParsedSrr],
    ) -> Vec<crate::qos_flow_mon::SrrReport> {
        if removed.is_empty() && created.is_empty() && updated.is_empty() {
            return Vec::new();
        }
        let Some(dp) = self.data_plane.read().unwrap().clone() else {
            return Vec::new();
        };
        let now = std::time::Instant::now();
        let wall = std::time::SystemTime::now();
        let mut out = Vec::new();
        dp.with_qos_flow_monitor(|m| {
            for id in removed {
                out.extend(m.remove_srr(upf_seid, *id, wall));
            }
            for r in created {
                let controls = crate::qos_flow_mon::controls_of(&r.qos_controls);
                if !controls.is_empty() {
                    log::info!(
                        "SEID {upf_seid:#x}: SRR {} provisions QoS monitoring of QFI(s) {:?}",
                        r.srr_id,
                        controls
                            .iter()
                            .flat_map(|c| c.qfis.clone())
                            .collect::<Vec<_>>()
                    );
                }
                // A Create of an SRR ID already held replaces it: what it measured
                // is reported, as for a removal.
                out.extend(m.remove_srr(upf_seid, r.srr_id, wall));
                m.create_srr(upf_seid, r.srr_id, controls, now, wall);
            }
            for r in updated {
                let controls = crate::qos_flow_mon::controls_of(&r.qos_controls);
                out.extend(m.update_srr(upf_seid, r.srr_id, controls, now, wall));
            }
        });
        out
    }

    /// #1389 part 3: report per QoS flow QoS monitoring to the CP function in a
    /// PFCP Session Report Request (§5.24.4.3, Report Type SESR, Session Report
    /// IE per SRR), tracked for T1/N1 retransmission.
    pub async fn send_qos_monitoring_report(
        &self,
        upf_seid: u64,
        reports: &[crate::qos_flow_mon::SrrReport],
    ) -> Result<(), String> {
        if reports.is_empty() {
            return Err("no QoS monitoring reports".to_string());
        }
        let (smf_seid, smf_addr) = {
            let sessions = self.sessions.read().await;
            sessions.get(&upf_seid).map(|s| (s.smf_seid, s.smf_addr))
        }
        .ok_or_else(|| {
            // A monitor entry that outlived its PFCP session reports nothing
            // further (#1451 review m5).
            if let Some(dp) = self.data_plane.read().unwrap().clone() {
                dp.with_qos_flow_monitor(|m| m.remove_session(upf_seid));
            }
            format!("Session {upf_seid:#x} not found for a QoS monitoring report")
        })?;
        // A message stays well under the path MTU: 16 reports of at most ~50 octets.
        for chunk in reports.chunks(16) {
            let payload = crate::n4_build::build_qos_monitoring_session_report(chunk);
            self.send_and_track_report(
                upf_seid,
                smf_seid,
                smf_addr,
                &payload,
                "QoS Monitoring Report",
                Vec::new(),
            )
            .await?;
        }
        for (srr, r) in reports {
            let m = r.qos_monitoring_measurement;
            if m.packet_delay_measurement_failure {
                log::info!(
                    "QoS monitoring report to {smf_addr}: SEID {upf_seid:#x} SRR {srr} QFI {} \
                     packet delay measurement FAILURE",
                    r.qfi
                );
            } else {
                log::info!(
                    "QoS monitoring report to {smf_addr}: SEID {upf_seid:#x} SRR {srr} QFI {} \
                     DL {:?} ms UL {:?} ms RTT {:?} ms",
                    r.qfi,
                    m.downlink_packet_delay,
                    m.uplink_packet_delay,
                    m.round_trip_packet_delay
                );
            }
        }
        Ok(())
    }

    /// #1389 part 2: apply the N6 Delay Measurement Control Information of an
    /// Association Setup (`setup`: replaces everything) or Update Request
    /// (§5.33.8.2: per instance). Ignored unless UN6DM is enabled: a UPF that did
    /// not advertise the feature does not act on it.
    fn apply_n6_delay_control(&self, payload: &[u8], setup: bool) {
        if !self.un6dm() {
            return;
        }
        let values = crate::n4_build::n6_delay_control_values(payload);
        let Some(dp) = self.data_plane.read().unwrap().clone() else {
            return;
        };
        let mut m = dp.n6_delay.lock().unwrap();
        if setup {
            use nextgcore_pfcp::qos_monitoring::{N6DelayMeasurementControlInformation, TypedIe};
            let ies: Vec<_> = values
                .iter()
                .filter_map(
                    |v| match N6DelayMeasurementControlInformation::decode_value(v) {
                        Ok(ie) => Some(ie),
                        Err(e) => {
                            log::warn!("N6 Delay Measurement Control Information ignored: {e}");
                            None
                        }
                    },
                )
                .collect();
            m.configure(&ies);
        } else if !values.is_empty() {
            m.apply_update(&values);
        }
    }

    /// #1389 part 2: stop N6 delay measurement (the association is gone).
    fn clear_n6_delay_control(&self) {
        if let Some(dp) = self.data_plane.read().unwrap().as_ref() {
            dp.n6_delay.lock().unwrap().clear();
        }
    }

    /// #1389 part 2: report N6 delay measurements to the CP function in PFCP
    /// Node Report Requests with N6DR (§5.33.8.3, §7.4.5.1), at most
    /// [`N6_REPORTS_PER_NODE_REPORT`] IEs each so a message stays well under the
    /// path MTU, each tracked for T1/N1 retransmission.
    pub async fn send_n6_delay_report(
        &self,
        reports: &[nextgcore_pfcp::qos_monitoring::N6DelayMeasurementReport],
    ) -> Result<(), String> {
        if reports.is_empty() {
            return Err("no N6 delay measurement reports".to_string());
        }
        for chunk in reports.chunks(N6_REPORTS_PER_NODE_REPORT) {
            let payload = crate::n4_build::build_n6_delay_node_report(&self.local_node_id, chunk);
            let peer = self.send_tracked_node_report(&payload).await?;
            for r in chunk {
                let a = r.measurement_endpoint_address;
                let endpoint = a
                    .ipv4
                    .map(IpAddr::from)
                    .or(a.ipv6.map(IpAddr::from))
                    .map_or_else(|| "?".to_string(), |ip| ip.to_string());
                let t = r.measurement_reporting_type;
                let kind = [(t.per, "PER"), (t.evt, "EVT"), (t.ire, "IRE")]
                    .iter()
                    .filter(|(on, _)| *on)
                    .map(|(_, k)| *k)
                    .collect::<Vec<_>>()
                    .join("+");
                match (r.information, r.failure_information) {
                    (Some(i), _) => log::info!(
                        "N6 delay report to {peer}: endpoint {endpoint} {kind} avg {} ms \
                         min {:?} max {:?}",
                        i.average_packet_delay,
                        i.minimum_packet_delay,
                        i.maximum_packet_delay
                    ),
                    (None, f) => log::info!(
                        "N6 delay report to {peer}: endpoint {endpoint} {kind} FAILURE cause {:?}",
                        f.map(|f| f.cause)
                    ),
                }
            }
        }
        Ok(())
    }

    /// Send a UPF-initiated Node Report Request with `payload` to the associated
    /// CP function, tracked for T1/N1 retransmission. Returns the peer.
    async fn send_tracked_node_report(&self, payload: &[u8]) -> Result<SocketAddr, String> {
        let Some(peer) = self.association.read().await.as_ref().map(|a| a.peer_addr) else {
            return Err("no PFCP association: no CP function to report to".to_string());
        };
        let seq = self.alloc_seq();
        let message = self.build_response(pfcp_type::NODE_REPORT_REQUEST, 0, seq, payload, false);
        self.pending_reports.lock().await.insert(
            seq,
            PendingReport {
                message: message.clone(),
                dest: peer,
                upf_seid: 0,
                attempts: 0,
                last_sent: std::time::Instant::now(),
                usage: Vec::new(),
            },
        );
        if let Err(e) = self.socket.send_to(&message, peer).await {
            self.pending_reports.lock().await.remove(&seq);
            return Err(format!("Failed to send Node Report Request: {e}"));
        }
        Ok(peer)
    }

    /// #1389: apply the GTP-U Path QoS Control Information of an Association
    /// Setup or Update Request (§5.24.5.2). Ignored unless GPQM is enabled: a
    /// UPF that did not advertise the feature does not act on it.
    fn apply_path_qos_control(&self, payload: &[u8], replace_when_absent: bool) {
        if !self.gpqm() {
            return;
        }
        let controls = crate::n4_build::parse_gtpu_path_qos_control_information(payload);
        if controls.is_empty() && !replace_when_absent {
            return;
        }
        if let Some(dp) = self.data_plane.read().unwrap().as_ref() {
            dp.path_qos.lock().unwrap().configure(&controls);
        }
        if !controls.is_empty() {
            log::info!(
                "GTP-U path QoS monitoring provisioned: {} control instance(s)",
                controls.len()
            );
        }
    }

    /// #1389: stop GTP-U path QoS monitoring (the association is gone).
    fn clear_path_qos_control(&self) {
        if let Some(dp) = self.data_plane.read().unwrap().as_ref() {
            dp.path_qos.lock().unwrap().clear();
        }
    }

    /// #1389: report GTP-U path QoS to the CP function in a PFCP Node Report
    /// Request (§5.24.5.2, §7.4.5.1), tracked for T1/N1 retransmission.
    pub async fn send_gtpu_path_qos_report(
        &self,
        reports: &[nextgcore_pfcp::qos_monitoring::GtpUPathQosReport],
    ) -> Result<(), String> {
        if reports.is_empty() {
            return Err("no GTP-U path QoS reports".to_string());
        }
        let payload =
            crate::n4_build::build_gtpu_path_qos_node_report(&self.local_node_id, reports);
        let peer = self.send_tracked_node_report(&payload).await?;
        for r in reports {
            log::info!(
                "GTP-U path QoS report to {peer}: peer {:?}{:?} trigger {:?} avg {} ms",
                r.remote_gtpu_peer.ipv4,
                r.remote_gtpu_peer.ipv6,
                r.qos_report_trigger,
                r.qos_information
                    .first()
                    .map_or(0, |q| q.average_packet_delay)
            );
        }
        Ok(())
    }

    /// Handle an Association Update Request (TS 29.244 §7.4.4.3) from the
    /// associated CP function (#1389): acknowledged with the UP Function
    /// Features, and its GTP-U Path QoS Control Information applied. An update
    /// without one leaves the current monitoring as it is.
    async fn handle_association_update_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        let ies = ParsedIe::parse_all(payload);
        let node_id = ParsedIe::find_ie(&ies, pfcp_ie::NODE_ID).map(|ie| ie.value.clone());
        // §6.2.7.2.2: an Update from a Node ID with no established association is
        // answered "No established PFCP Association" (cause 72) and changes nothing
        // (#1417 review M1). Only the associated CP function may update it.
        let associated = match &node_id {
            Some(id) => self
                .association
                .read()
                .await
                .as_ref()
                .is_some_and(|a| &a.node_id == id),
            None => false,
        };
        let cause = match (&node_id, associated) {
            (None, _) => PfcpCause::MandatoryIeMissing,
            (Some(_), false) => {
                note_refusal(format_args!(
                    "PFCP Association Update Request from {src_addr} whose Node ID has no \
                     established association: rejected (cause 72)"
                ));
                PfcpCause::NoEstablishedPfcpAssociation
            }
            (Some(_), true) => {
                self.apply_path_qos_control(payload, false);
                self.apply_n6_delay_control(payload, false);
                PfcpCause::RequestAccepted
            }
        };
        let mut resp_payload = crate::n4_build::build_association_update_response(
            &self.local_node_id,
            cause,
            self.optional_features(),
        );
        if cause == PfcpCause::MandatoryIeMissing {
            let mut offending = crate::n4_build::PfcpMessageBuilder::new();
            offending.add_u16(pfcp_ie::OFFENDING_IE, pfcp_ie::NODE_ID);
            resp_payload.extend_from_slice(&offending.build());
        }
        let response = self.build_response(
            pfcp_type::ASSOCIATION_UPDATE_RESPONSE,
            0,
            header.sequence_number,
            &resp_payload,
            false,
        );
        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;
        Ok(())
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

    /// TAKE the usage of a session's URRs and build Usage Reports (#821).
    ///
    /// `only` restricts the set to named URR ids — which is what a Remove URR needs,
    /// so a modification reports the residual volume of the rules it is detaching and
    /// nothing else (#306). `None` means every URR on the session, for a deletion's
    /// final reports or a QAURR query.
    ///
    /// Resetting, as TS 29.244 §5.2.2.3.1 requires of every usage report ("reset its
    /// ongoing measurement counts"): a query reports the usage since the last report
    /// and starts a new measurement. It used to READ the counters, so a racing or later
    /// harvest re-reported the same bytes and a CP function summing reports billed
    /// them twice.
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
        dp.take_urr_reports(upf_seid, only)
            .into_iter()
            .map(|r| {
                let mut trigger = crate::n4_build::UsageReportTrigger::default();
                match reason {
                    // TS 29.244 §8.2.36: TERMR covers the removal of the URR as well
                    // as the termination of the session.
                    UsageReportReason::Termination => trigger.termination_report = true,
                    UsageReportReason::Immediate => trigger.immediate_report = true,
                }
                let times = report_time_ies(&r.times);
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
                    start_time: times.0,
                    end_time: times.1,
                    duration_measurement: times.2,
                    time_of_first_packet: times.3,
                    time_of_last_packet: times.4,
                    query_urr_reference: None,
                }
            })
            .collect()
    }

    /// #1513: when a re-report is due, tell the CP function the current user-plane
    /// path state, from the data plane's path table: every failed path, and every
    /// path it may hold as failed that has answered since. Nothing is sent when there
    /// is nothing to tell.
    async fn resend_path_state_if_due(&self) {
        if !self
            .path_ledger
            .lock()
            .unwrap()
            .start_round(std::time::Instant::now())
        {
            return;
        }
        let Some(dp) = self.data_plane.read().unwrap().clone() else {
            return;
        };
        // The table is read under `path_send` (#1531 review M-1). A transition after
        // the read is reported live, which waits for this round's sends, so the
        // newer state always reaches the CP function last.
        let _sending = self.path_send.lock().await;
        let states = dp.path_table.read().unwrap().path_states();
        #[cfg(test)]
        {
            let hold = self.resend_hold.lock().unwrap().clone();
            if let Some((reached, proceed)) = hold {
                reached.notify_one();
                proceed.notified().await;
            }
        }
        let mut failed: Vec<IpAddr> = states
            .iter()
            .filter(|(_, failed)| **failed)
            .map(|(ip, _)| *ip)
            .collect();
        let mut recovered: Vec<IpAddr> = {
            let ledger = self.path_ledger.lock().unwrap();
            ledger
                .told_failed
                .iter()
                .filter(|ip| states.get(ip) == Some(&false))
                .copied()
                .collect()
        };
        failed.sort();
        recovered.sort();
        for (failure, peers) in [(true, failed), (false, recovered)] {
            if peers.is_empty() {
                continue;
            }
            if let Err(e) = self.send_path_report(failure, &peers, true).await {
                log::warn!("User-plane path state for {peers:?} was NOT re-reported: {e}");
            }
        }
    }

    /// Report N3/N9 user-plane path FAILURE or RECOVERY for `peers` to the CP
    /// function in a PFCP Node Report Request (#935, TS 29.244 §7.4.5.1), tracked for
    /// T1/N1 retransmission like a Session Report Request until its Node Report
    /// Response arrives. Without an association there is nobody to report to.
    pub async fn send_node_report(
        &self,
        failure: bool,
        peers: &[std::net::IpAddr],
    ) -> Result<(), String> {
        let _sending = self.path_send.lock().await;
        self.send_path_report(failure, peers, false).await
    }

    /// [`Self::send_node_report`] with `path_send` held; `resend` for a report of a
    /// re-report round.
    async fn send_path_report(
        &self,
        failure: bool,
        peers: &[std::net::IpAddr],
        resend: bool,
    ) -> Result<(), String> {
        if peers.is_empty() {
            return Err("no peers to report".to_string());
        }
        let Some(peer) = self.association.read().await.as_ref().map(|a| a.peer_addr) else {
            return Err("no PFCP association: no CP function to report the path to".to_string());
        };
        let payload =
            crate::n4_build::build_node_report_request(&self.local_node_id, failure, peers);
        let seq = self.alloc_seq();
        let message = self.build_response(pfcp_type::NODE_REPORT_REQUEST, 0, seq, &payload, false);
        // #1513: recorded before it is sent, so its response always finds it.
        self.path_ledger
            .lock()
            .unwrap()
            .sent(seq, failure, peers, resend);
        self.pending_reports.lock().await.insert(
            seq,
            PendingReport {
                message: message.clone(),
                dest: peer,
                upf_seid: 0,
                attempts: 0,
                last_sent: std::time::Instant::now(),
                usage: Vec::new(),
            },
        );
        if let Err(e) = self.socket.send_to(&message, peer).await {
            self.pending_reports.lock().await.remove(&seq);
            self.path_ledger.lock().unwrap().answered(seq, false);
            return Err(format!("Failed to send Node Report Request: {e}"));
        }
        log::info!(
            "Sent Node Report Request to {peer}: user-plane path {} for {peers:?}",
            if failure { "FAILURE" } else { "RECOVERY" }
        );
        Ok(())
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
            Vec::new(),
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
        peer: Option<IpAddr>,
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
                // §7.5.8.4 / §8.2.3: the Remote F-TEID carries the peer's address
                // in its own family, so an IPv6 gNB is reported as V6 (#985).
                remote_f_teid: FTeid {
                    teid: remote_teid,
                    ipv4: match peer {
                        Some(IpAddr::V4(a)) => Some(a),
                        _ => None,
                    },
                    ipv6: match peer {
                        Some(IpAddr::V6(a)) => Some(a),
                        _ => None,
                    },
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
            Vec::new(),
        )
        .await?;
        log::info!(
            "Sent Error Indication Report to {smf_addr}: SEID=0x{upf_seid:x}, TEID=0x{remote_teid:x}"
        );
        Ok(())
    }

    /// Take the reports due on one session and send them, while the session is held
    /// in the PFCP table (#821).
    ///
    /// The take happens UNDER `sessions.read()`, and the request is registered and on
    /// the wire before that guard is released. A Session Deletion needs
    /// `sessions.write()`, so it either ran first -- the session is gone, nothing is
    /// taken here, and its TERMR carries every byte -- or waits until this report is
    /// sent, and its TERMR carries only what came after. Before, the harvest took the
    /// usage with no such ordering; a deletion in between made the send fail with
    /// "session not found" and the taken usage was in no report.
    ///
    /// A report that cannot be sent hands its usage back (#780 m2).
    pub async fn send_due_urr_reports(
        &self,
        upf_seid: u64,
        smf_seid: u64,
    ) -> Result<usize, String> {
        let sessions = self.sessions.read().await;
        self.send_due_urr_reports_held(&sessions, upf_seid, smf_seid)
            .await
    }

    /// The body of [`Self::send_due_urr_reports`], run while the caller holds the
    /// session table: the take, the send and -- on failure -- the restore all complete
    /// before the guard can be released (#842 review). Restoring after the release let
    /// a deletion waiting on the table build its TERMR in between and miss the bytes.
    async fn send_due_urr_reports_held(
        &self,
        sessions: &HashMap<u64, PfcpSessionInfo>,
        upf_seid: u64,
        smf_seid: u64,
    ) -> Result<usize, String> {
        let Some(smf_addr) = sessions.get(&upf_seid).map(|s| s.smf_addr) else {
            return Ok(0);
        };
        let dp = self.data_plane.read().unwrap().clone();
        let Some(dp) = dp else {
            return Ok(0);
        };
        let reports = dp.take_due_urr_reports(upf_seid);
        if reports.is_empty() {
            return Ok(0);
        }
        let n = reports.len();
        match self
            .send_urr_report_to(upf_seid, smf_seid, smf_addr, reports.clone())
            .await
        {
            Ok(()) => Ok(n),
            Err(e) => {
                dp.restore_urr_usage(&reports);
                Err(e)
            }
        }
    }

    /// Send a PFCP Session Report Request for URR usage reports already taken.
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
        self.send_urr_report_to(upf_seid, smf_seid, smf_addr, reports)
            .await
    }

    async fn send_urr_report_to(
        &self,
        upf_seid: u64,
        smf_seid: u64,
        smf_addr: SocketAddr,
        reports: Vec<crate::data_plane::UrrReportEntry>,
    ) -> Result<(), String> {
        // Build usage reports
        let usage_reports: Vec<crate::n4_build::UsageReport> = reports
            .iter()
            .map(|r| {
                // #80: the trigger the report CARRIES, from the reason it was
                // generated. This used to hardcode `volume_threshold = true` on every
                // report, so a periodic report went out mislabelled as a threshold
                // report and a quota exhaustion could not be expressed at all -- a CP
                // function reading the trigger to decide whether to top a subscriber up
                // was being told the wrong thing (TS 29.244 §8.2.19).
                use crate::data_plane::UrrReportReason;
                let trigger = match r.trigger {
                    UrrReportReason::VolumeThreshold => crate::n4_build::UsageReportTrigger {
                        volume_threshold: true,
                        ..Default::default()
                    },
                    UrrReportReason::TimeThreshold => crate::n4_build::UsageReportTrigger {
                        time_threshold: true,
                        ..Default::default()
                    },
                    UrrReportReason::Periodic => crate::n4_build::UsageReportTrigger {
                        periodic_reporting: true,
                        ..Default::default()
                    },
                    UrrReportReason::VolumeQuota => crate::n4_build::UsageReportTrigger {
                        volume_quota: true,
                        ..Default::default()
                    },
                    UrrReportReason::TimeQuota => crate::n4_build::UsageReportTrigger {
                        time_quota: true,
                        ..Default::default()
                    },
                };

                let times = report_time_ies(&r.times);
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
                    start_time: times.0,
                    end_time: times.1,
                    duration_measurement: times.2,
                    time_of_first_packet: times.3,
                    time_of_last_packet: times.4,
                    query_urr_reference: None,
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
            reports.clone(),
        )
        .await?;

        log::info!(
            "Sent Session Report Request to {smf_addr} for SEID={upf_seid:#x} ({} URR reports)",
            reports.len()
        );
        Ok(())
    }

    /// Send a Session Report Request the instant a Volume/Time Quota is exhausted
    /// (#80, TS 29.244 §5.2.2.2.2, §8.2.19).
    ///
    /// Distinct from [`Self::send_urr_report`] because it is driven by a data-plane
    /// EVENT rather than by the harvest. It TAKES the URR's usage, as every usage report
    /// must (§5.2.2.3.1, #821), so the next report does not carry the same bytes again.
    ///
    /// The take and the send happen while the session is held in the PFCP table (#842
    /// review), as in [`Self::send_due_urr_reports`]: a Session Deletion either ran
    /// first -- nothing is taken and its TERMR carries everything -- or runs after this
    /// report is on the wire. Releasing the table before the take let a deletion's TERMR
    /// miss the bytes this report then sent for a session the SMF had already deleted.
    ///
    /// It also does not clear the exhaustion latch: a report is an announcement, not a
    /// grant. Only the CP function provisioning more quota (an Update URR) resumes
    /// forwarding.
    pub async fn send_quota_exhausted_report(
        &self,
        upf_seid: u64,
        smf_seid: u64,
        urr_id: u32,
    ) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        let smf_addr = sessions
            .get(&upf_seid)
            .map(|s| s.smf_addr)
            .ok_or_else(|| format!("Session {upf_seid:#x} not found for quota report"))?;

        // The live counters and the trigger, read off the URR that latched. Without the
        // data plane attached there is nothing to read, which is not an error: a UPF
        // running with `--no-dataplane` has no forwarding path to have exhausted a quota
        // on, so the event cannot arise.
        // Cloned out of the guard immediately: the guard is a std lock and must not be
        // held across the `.await` below.
        let dp = self.data_plane.read().unwrap().clone();
        let Some(dp) = dp else {
            return Err("no data plane attached; cannot read URR counters".to_string());
        };
        let Some(report) = dp.urr_report_take(upf_seid, urr_id) else {
            return Err(format!(
                "URR {urr_id} not found on SEID {upf_seid:#x} for quota report"
            ));
        };

        let trigger = match report.trigger {
            crate::data_plane::UrrReportReason::TimeQuota => crate::n4_build::UsageReportTrigger {
                time_quota: true,
                ..Default::default()
            },
            // VOLQU for a volume quota, and for anything else: this path is only
            // reached from a quota exhaustion, so a VOLTH/PERIO reason here would mean
            // the latch and the provisioned values disagree — reported as the volume
            // quota it was rather than silently as a threshold.
            _ => crate::n4_build::UsageReportTrigger {
                volume_quota: true,
                ..Default::default()
            },
        };

        let times = report_time_ies(&report.times);
        let user_plane_report = UserPlaneReport {
            report_type: crate::n4_build::ReportType {
                usage_report: true,
                ..Default::default()
            },
            usage_reports: vec![crate::n4_build::UsageReport {
                urr_id,
                ur_seqn: report.ur_seqn,
                trigger,
                volume_measurement: Some(crate::n4_build::VolumeMeasurement {
                    total_volume: Some(report.total_bytes),
                    uplink_volume: Some(report.ul_bytes),
                    downlink_volume: Some(report.dl_bytes),
                    total_packets: Some(report.total_pkts),
                    uplink_packets: Some(report.ul_pkts),
                    downlink_packets: Some(report.dl_pkts),
                }),
                start_time: times.0,
                end_time: times.1,
                duration_measurement: times.2,
                time_of_first_packet: times.3,
                time_of_last_packet: times.4,
                query_urr_reference: None,
            }],
            ..Default::default()
        };

        let payload =
            build_session_report_request(pfcp_type::SESSION_REPORT_REQUEST, &user_plane_report);
        self.send_and_track_report(
            upf_seid,
            smf_seid,
            smf_addr,
            &payload,
            "Session Report Request (quota exhausted)",
            vec![report.clone()],
        )
        .await
        .inspect_err(|_| {
            // #821: the usage was TAKEN for this report; not sent, it goes back, and the
            // report flag is re-raised so the harvest reports the exhaustion instead.
            dp.restore_urr_usage(std::slice::from_ref(&report));
            if let Some(urr) = dp
                .sessions
                .find_by_seid(upf_seid)
                .and_then(|s| s.urrs.read().unwrap().get(&urr_id).cloned())
            {
                urr.threshold_exceeded
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        })?;
        log::info!(
            "Sent quota-exhausted Usage Report to {smf_addr} for SEID={upf_seid:#x} URR={urr_id} \
             ({}B total) — matching traffic is being dropped (TS 29.244 §5.2.2.2.2)",
            report.total_bytes
        );
        drop(sessions);
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
        usage: Vec<crate::data_plane::UrrReportEntry>,
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
                    usage,
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
        let mut gave_up: Vec<(u32, u64, Vec<crate::data_plane::UrrReportEntry>)> = Vec::new();
        {
            let mut pending = self.pending_reports.lock().await;
            pending.retain(|&seq, p| {
                if now.duration_since(p.last_sent) < PFCP_T1_DURATION {
                    return true; // T1 not yet expired
                }
                if p.attempts >= PFCP_N1_MAX_RETRANSMIT {
                    // N1 exhausted: give up on this request.
                    gave_up.push((seq, p.upf_seid, std::mem::take(&mut p.usage)));
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
        for (seq, upf_seid, usage) in gave_up {
            // #1513: an abandoned path report was not delivered either.
            self.path_ledger.lock().unwrap().answered(seq, false);
            log::error!(
                "Session Report Request (seq={seq}, SEID=0x{upf_seid:x}) abandoned after {} retransmissions (N1) — peer unresponsive",
                PFCP_N1_MAX_RETRANSMIT
            );
            // #780 review m2: no response after N1+1 transmissions, so the CP function
            // has not acknowledged this usage. It goes back to its URRs and rides on the
            // next report rather than vanishing. (The opposite risk -- a request that
            // arrived but whose every response was lost -- is the less likely of the
            // two, and an over-report is visible to the CP function where a dropped one
            // is not.)
            if !usage.is_empty() {
                let dp = self.data_plane.read().unwrap().clone();
                if let Some(dp) = dp {
                    dp.restore_urr_usage(&usage);
                }
            }
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
    /// Test hook (#1513): make a scheduled path state re-report due now (avoids
    /// waiting the real T1). Returns whether one was scheduled.
    fn test_path_resend_now(&self) -> bool {
        let mut ledger = self.path_ledger.lock().unwrap();
        let scheduled = ledger.resend_at.is_some();
        if scheduled {
            ledger.resend_at = Some(std::time::Instant::now());
        }
        scheduled
    }

    /// Test hook (#1513): path reports awaiting their response.
    fn test_path_in_flight(&self) -> usize {
        self.path_ledger.lock().unwrap().in_flight.len()
    }

    /// Test hook (#1513): the peers the CP function may hold as failed.
    fn test_told_failed(&self) -> Vec<IpAddr> {
        let mut v: Vec<IpAddr> = self
            .path_ledger
            .lock()
            .unwrap()
            .told_failed
            .iter()
            .copied()
            .collect();
        v.sort();
        v
    }

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
        // The test SMF's host and its Node ID address (fail closed, #968).
        server.set_allowed_peers(PeerAllowlist::parse("127.0.0.1, 127.0.0.9").unwrap());
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

    /// IE 238 for N3 paths by type, immediate reporting (#1389).
    fn path_qos_control_ie() -> Vec<u8> {
        use nextgcore_pfcp::qos_monitoring::{
            GtpUPathInterfaceType, GtpUPathQosControlInformation, QosReportTrigger, TypedIe,
        };
        let mut buf = bytes::BytesMut::new();
        GtpUPathQosControlInformation {
            gtpu_path_interface_type: Some(GtpUPathInterfaceType {
                n9: false,
                n3: true,
            }),
            qos_report_trigger: QosReportTrigger {
                ire: true,
                ..Default::default()
            },
            ..Default::default()
        }
        .encode_ie(&mut buf);
        buf.to_vec()
    }

    fn up_features(resp: &[u8]) -> Vec<u8> {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        ParsedIe::find_ie(&ies, pfcp_ie::UP_FUNCTION_FEATURES)
            .expect("UP Function Features")
            .value
            .clone()
    }

    /// #1389: OFF by default. An SMF that provisions GTP-U Path QoS Control
    /// Information to a UPF without `--gtpu-path-qos-monitoring` gets the same
    /// 8-octet features as before (no GPQM) and nothing is monitored.
    #[tokio::test]
    async fn path_qos_control_is_ignored_unless_enabled() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let mut payload = build_association_setup_request_payload(Some(0x5000_0000));
        payload.extend_from_slice(&path_qos_control_ie());
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(up_features(&resp), vec![0x10, 0x01, 0, 0, 0, 0, 0, 0]);
        assert!(!dp.path_qos.lock().unwrap().is_active());
    }

    /// #1417 review M1, §6.2.7.2.2: with no association, an Association Update
    /// Request is answered cause 72 and changes nothing, also with GPQM enabled.
    #[tokio::test]
    async fn association_update_without_an_association_is_cause_72() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        server.set_path_qos_monitoring(true);
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let mut upd = crate::n4_build::PfcpMessageBuilder::new();
        upd.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let mut upd = upd.build();
        upd.extend_from_slice(&path_qos_control_ie());
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 1, &upd)).await;
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_UPDATE_RESPONSE);
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
        assert!(!dp.path_qos.lock().unwrap().is_active());
        assert!(!server.is_associated().await);
    }

    /// #1389 (TS 29.244 §5.24.5.1-2, §7.4.4.3): enabled, the UPF advertises GPQM
    /// (octet 9 bit 3, still 8 octets) and applies IE 238 from the Association
    /// Setup; an Association Update replaces it, one without IE 238 keeps it, and
    /// the release of the association clears it.
    #[tokio::test]
    async fn path_qos_control_follows_setup_update_and_release() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        server.set_path_qos_monitoring(true);
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());

        let mut payload = build_association_setup_request_payload(Some(0x5000_0000));
        payload.extend_from_slice(&path_qos_control_ie());
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(up_features(&resp), vec![0x10, 0x01, 0, 0, 0x04, 0, 0, 0]);
        assert!(dp.path_qos.lock().unwrap().controls()[0].n3);

        // Association Update with a periodic control on an explicit peer.
        use nextgcore_pfcp::qos_monitoring::{
            GtpUPathQosControlInformation, QosReportTrigger, TypedIe,
        };
        let mut upd = crate::n4_build::PfcpMessageBuilder::new();
        upd.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let mut upd = upd.build();
        let mut ie = bytes::BytesMut::new();
        GtpUPathQosControlInformation {
            remote_gtpu_peers: vec![nextgcore_pfcp::types::RemoteGtpUPeer {
                ipv4: Some([10, 0, 0, 9]),
                ..Default::default()
            }],
            qos_report_trigger: QosReportTrigger {
                per: true,
                ..Default::default()
            },
            measurement_period: Some(5),
            ..Default::default()
        }
        .encode_ie(&mut ie);
        upd.extend_from_slice(&ie);
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 2, &upd)).await;
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_UPDATE_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(up_features(&resp)[4], 0x04, "GPQM");
        {
            let m = dp.path_qos.lock().unwrap();
            assert_eq!(m.controls().len(), 1);
            assert_eq!(
                m.controls()[0].peers,
                vec!["10.0.0.9".parse::<IpAddr>().unwrap()]
            );
        }

        // An update without IE 238 keeps what was provisioned.
        let mut bare = crate::n4_build::PfcpMessageBuilder::new();
        bare.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 3, &bare.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert!(dp.path_qos.lock().unwrap().is_active());

        // Node ID is M in the Update (Table 7.4.4.3-1).
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 4, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::MandatoryIeMissing as u8);

        // #1417 review M1, §6.2.7.2.2: an Update from another Node ID is cause 72
        // and leaves the provisioning alone, even when it carries IE 238.
        let mut other = crate::n4_build::PfcpMessageBuilder::new();
        other.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        let mut other = other.build();
        other.extend_from_slice(&path_qos_control_ie());
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 6, &other)).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
        assert_eq!(
            dp.path_qos.lock().unwrap().controls()[0].peers,
            vec!["10.0.0.9".parse::<IpAddr>().unwrap()],
            "a foreign Update must not replace the provisioning"
        );

        // Release clears it.
        let mut rel = crate::n4_build::PfcpMessageBuilder::new();
        rel.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let resp = exchange(&smf, addr, &encode_pfcp(9, None, 5, &rel.build())).await;
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_RELEASE_RESPONSE);
        assert!(!dp.path_qos.lock().unwrap().is_active());
    }

    /// #1389: a GTP-U path QoS report goes out as a Node Report Request with GPQR
    /// and the GTP-U Path QoS Report IE, tracked until its response.
    #[tokio::test]
    async fn path_qos_reports_go_out_as_node_reports() {
        use nextgcore_pfcp::qos_monitoring::{
            GtpUPathQosReport, QosInformationInGtpUPathQosReport, QosReportTrigger, TypedIe,
        };
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let payload = build_association_setup_request_payload(Some(0x5000_0000));
        exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        let report = GtpUPathQosReport {
            remote_gtpu_peer: nextgcore_pfcp::types::RemoteGtpUPeer {
                ipv4: Some([10, 0, 0, 5]),
                ..Default::default()
            },
            qos_report_trigger: QosReportTrigger {
                per: true,
                ..Default::default()
            },
            time_stamp: 0xe8a0_0000,
            qos_information: vec![QosInformationInGtpUPathQosReport {
                average_packet_delay: 21,
                ..Default::default()
            }],
            ..Default::default()
        };
        server
            .send_gtpu_path_qos_report(std::slice::from_ref(&report))
            .await
            .unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(buf[1], pfcp_type::NODE_REPORT_REQUEST);
        let (hdr, body) = ParsedPfcpHeader::parse(&buf[..n]).unwrap();
        let ies = ParsedIe::parse_all(body);
        let t = ParsedIe::find_ie(&ies, pfcp_ie::NODE_REPORT_TYPE).unwrap();
        assert_eq!(t.value, vec![0x08], "GPQR (bit 4)");
        let r = ParsedIe::find_ie(&ies, 239).expect("GTP-U Path QoS Report");
        assert_eq!(GtpUPathQosReport::decode_value(&r.value).unwrap(), report);
        assert_eq!(server.pending_report_count().await, 1);
        let mut ack = crate::n4_build::PfcpMessageBuilder::new();
        ack.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        ack.add_cause(PfcpCause::RequestAccepted);
        smf.send_to(
            &encode_pfcp(
                pfcp_type::NODE_REPORT_RESPONSE,
                None,
                hdr.sequence_number,
                &ack.build(),
            ),
            addr,
        )
        .await
        .unwrap();
        for _ in 0..50 {
            if server.pending_report_count().await == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the Node Report Response did not stop retransmission");
    }

    /// IE 355 for one STAMP endpoint, immediate reporting (#1389 part 2).
    fn n6_delay_control_ie(id: u16, endpoint: [u8; 4]) -> Vec<u8> {
        use nextgcore_pfcp::qos_monitoring::{
            MeasurementEndpointAddress, MeasurementReportingType,
            N6DelayMeasurementControlInformation, N6DelayMeasurementProtocols, TypedIe,
        };
        let mut buf = bytes::BytesMut::new();
        N6DelayMeasurementControlInformation {
            id,
            measurement_endpoint_addresses: vec![MeasurementEndpointAddress {
                ipv4: Some(endpoint),
                ipv6: None,
            }],
            network_instance: b"\x08internet".to_vec(),
            measurement_protocols: vec![N6DelayMeasurementProtocols {
                stamp: true,
                ..Default::default()
            }],
            measurement_reporting_type: MeasurementReportingType {
                ire: true,
                ..Default::default()
            },
            ..Default::default()
        }
        .encode_ie(&mut buf);
        buf.to_vec()
    }

    fn n6_ids(dp: &crate::data_plane::DataPlane) -> Vec<u16> {
        dp.n6_delay
            .lock()
            .unwrap()
            .controls()
            .map(|c| c.id)
            .collect()
    }

    fn find(resp: &[u8], ie: u16) -> Option<Vec<u8>> {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        ParsedIe::find_ie(&ParsedIe::parse_all(body), ie).map(|i| i.value.clone())
    }

    /// #1389 part 2: OFF by default. An SMF that provisions N6 Delay Measurement
    /// Control Information to a UPF without `--n6-delay-measurement` gets the same
    /// 8-octet features as before, no N6 Delay Measurement Protocols IE, and
    /// nothing is measured.
    #[tokio::test]
    async fn n6_delay_control_is_ignored_unless_enabled() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let mut payload = build_association_setup_request_payload(Some(0x5000_0000));
        payload.extend_from_slice(&n6_delay_control_ie(1, [10, 0, 0, 1]));
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(up_features(&resp), vec![0x10, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(find(&resp, 354), None);
        assert!(!dp.n6_delay.lock().unwrap().is_active());
        let mut upd = crate::n4_build::PfcpMessageBuilder::new();
        upd.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let mut upd = upd.build();
        upd.extend_from_slice(&n6_delay_control_ie(2, [10, 0, 0, 2]));
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 2, &upd)).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(up_features(&resp), vec![0x10, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(find(&resp, 354), None);
        assert!(!dp.n6_delay.lock().unwrap().is_active());
    }

    /// #1389 part 2 (TS 29.244 §5.33.8.1-2, §8.2.25): enabled, the UPF advertises
    /// UN6DM (octet 14 bit 2, so 10 octets) and STAMP in IE 354, applies IE 355
    /// from the Association Setup, updates it per instance, ignores a foreign
    /// Update (cause 72), and the release clears it.
    #[tokio::test]
    async fn n6_delay_control_follows_setup_update_and_release() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        server.set_n6_delay_measurement(true);
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let mut payload = build_association_setup_request_payload(Some(0x5000_0000));
        payload.extend_from_slice(&n6_delay_control_ie(1, [10, 0, 0, 1]));
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            up_features(&resp),
            vec![0x10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x02]
        );
        assert_eq!(find(&resp, 354), Some(vec![0x04]), "STAMP");
        assert_eq!(n6_ids(&dp), vec![1]);

        // The Update adds instance 2 and keeps 1.
        let node = |b: &mut crate::n4_build::PfcpMessageBuilder| {
            b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        };
        let mut upd = crate::n4_build::PfcpMessageBuilder::new();
        node(&mut upd);
        let mut upd = upd.build();
        upd.extend_from_slice(&n6_delay_control_ie(2, [10, 0, 0, 2]));
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 2, &upd)).await;
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_UPDATE_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(up_features(&resp).len(), 10);
        assert_eq!(find(&resp, 354), Some(vec![0x04]));
        assert_eq!(n6_ids(&dp), vec![1, 2]);

        // A foreign Node ID: cause 72, nothing changes.
        let mut other = crate::n4_build::PfcpMessageBuilder::new();
        other.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        let mut other = other.build();
        other.extend_from_slice(&[0x01, 0x63, 0x00, 0x00]); // IE 355, null length
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 3, &other)).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
        assert_eq!(n6_ids(&dp), vec![1, 2]);

        // ID alone stops instance 1.
        let mut stop1 = crate::n4_build::PfcpMessageBuilder::new();
        node(&mut stop1);
        let mut stop1 = stop1.build();
        stop1.extend_from_slice(&[0x01, 0x63, 0x00, 0x06, 0x01, 0x79, 0x00, 0x02, 0x00, 0x01]);
        let resp = exchange(&smf, addr, &encode_pfcp(7, None, 4, &stop1)).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(n6_ids(&dp), vec![2]);

        // An Update without IE 355 keeps it; one with a null-length IE 355 stops all.
        let mut bare = crate::n4_build::PfcpMessageBuilder::new();
        node(&mut bare);
        exchange(&smf, addr, &encode_pfcp(7, None, 5, &bare.build())).await;
        assert_eq!(n6_ids(&dp), vec![2]);
        let mut all = crate::n4_build::PfcpMessageBuilder::new();
        node(&mut all);
        let mut all = all.build();
        all.extend_from_slice(&[0x01, 0x63, 0x00, 0x00]);
        exchange(&smf, addr, &encode_pfcp(7, None, 6, &all)).await;
        assert!(n6_ids(&dp).is_empty());

        // Provision again, then the release clears it.
        let mut again = crate::n4_build::PfcpMessageBuilder::new();
        node(&mut again);
        let mut again = again.build();
        again.extend_from_slice(&n6_delay_control_ie(3, [10, 0, 0, 3]));
        exchange(&smf, addr, &encode_pfcp(7, None, 7, &again)).await;
        assert_eq!(n6_ids(&dp), vec![3]);
        let mut rel = crate::n4_build::PfcpMessageBuilder::new();
        node(&mut rel);
        let resp = exchange(&smf, addr, &encode_pfcp(9, None, 8, &rel.build())).await;
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_RELEASE_RESPONSE);
        assert!(!dp.n6_delay.lock().unwrap().is_active());
    }

    /// #1389 part 2, mixed versions: the Association Setup Response of a UPF with
    /// UN6DM on (10-octet features, IE 354) decodes with the shared library
    /// decoder an unchanged smfd uses (`AssociationSetupResponse::decode`), with
    /// FTUP and EMPU intact; the extra IE is skipped.
    #[tokio::test]
    async fn un6dm_setup_response_decodes_in_an_unchanged_smf() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        server.set_n6_delay_measurement(true);
        let payload = build_association_setup_request_payload(Some(0x5000_0000));
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let mut b = bytes::Bytes::copy_from_slice(body);
        let decoded = nextgcore_pfcp::message::AssociationSetupResponse::decode(&mut b).unwrap();
        let f = decoded.up_function_features.expect("features");
        assert!(f.ftup && f.empu && f.un6dm && !f.gpqm);
        assert_eq!(decoded.cause as u8, PfcpCause::RequestAccepted as u8);
    }

    /// #1389 part 2: N6 delay reports go out as Node Report Requests with N6DR
    /// (bit 7) and IE 356, at most 16 per message, each tracked until answered.
    #[tokio::test]
    async fn n6_delay_reports_go_out_as_node_reports() {
        use nextgcore_pfcp::qos_monitoring::{
            MeasurementEndpointAddress, MeasurementReportingType, N6DelayMeasurementInformation,
            N6DelayMeasurementReport, TypedIe,
        };
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let payload = build_association_setup_request_payload(Some(0x5000_0000));
        exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        let report = |i: u8| N6DelayMeasurementReport {
            measurement_endpoint_address: MeasurementEndpointAddress {
                ipv4: Some([10, 0, 1, i]),
                ipv6: None,
            },
            network_instance: b"\x08internet".to_vec(),
            measurement_reporting_type: MeasurementReportingType {
                ire: true,
                ..Default::default()
            },
            time_stamp: 0xe8a0_0000,
            information: Some(N6DelayMeasurementInformation {
                average_packet_delay: 21,
                minimum_packet_delay: Some(21),
                maximum_packet_delay: Some(21),
            }),
            ..Default::default()
        };
        let reports: Vec<_> = (0..20).map(report).collect();
        server.send_n6_delay_report(&reports).await.unwrap();
        let mut got = Vec::new();
        let mut buf = vec![0u8; 4096];
        for _ in 0..2 {
            let (n, _) =
                tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(buf[1], pfcp_type::NODE_REPORT_REQUEST);
            let (_, body) = ParsedPfcpHeader::parse(&buf[..n]).unwrap();
            let ies = ParsedIe::parse_all(body);
            let t = ParsedIe::find_ie(&ies, pfcp_ie::NODE_REPORT_TYPE).unwrap();
            assert_eq!(t.value, vec![0x40], "N6DR (bit 7)");
            let these: Vec<_> = ies
                .iter()
                .filter(|ie| ie.ie_type == 356)
                .map(|ie| N6DelayMeasurementReport::decode_value(&ie.value).unwrap())
                .collect();
            assert!(these.len() <= N6_REPORTS_PER_NODE_REPORT);
            got.extend(these);
        }
        assert_eq!(got, reports);
        assert_eq!(server.pending_report_count().await, 2);
    }

    /// #935 (TS 29.244 §7.4.5.1, Tables 7.4.5.1.2-1/7.4.5.1.3-1) on the wire: a path
    /// failure goes out as a Node Report Request with UPFR and a User Plane Path Failure
    /// Report naming the peer; a recovery with UPRR and a User Plane Path Recovery
    /// Report; the Node Report Response stops T1/N1; without an association nothing
    /// is sent.
    #[tokio::test]
    async fn path_reports_go_out_as_node_reports() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        assert!(server
            .send_node_report(true, &["10.0.0.1".parse().unwrap()])
            .await
            .is_err());

        let payload = build_association_setup_request_payload(Some(0x5000_0000));
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);

        for (failure, nrt, ie) in [
            (
                true,
                0x01u8,
                crate::n4_build::pfcp_ie::USER_PLANE_PATH_FAILURE_REPORT,
            ),
            (
                false,
                0x02u8,
                crate::n4_build::pfcp_ie::USER_PLANE_PATH_RECOVERY_REPORT,
            ),
        ] {
            server
                .send_node_report(failure, &["10.0.0.1".parse().unwrap()])
                .await
                .expect("sent");
            let mut buf = vec![0u8; 2048];
            let (len, _) =
                tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                    .await
                    .expect("a Node Report arrives")
                    .expect("recv");
            let (hdr, body) = ParsedPfcpHeader::parse(&buf[..len]).unwrap();
            assert_eq!(buf[1], pfcp_type::NODE_REPORT_REQUEST);
            let ies = ParsedIe::parse_all(body);
            let t = ParsedIe::find_ie(&ies, crate::n4_build::pfcp_ie::NODE_REPORT_TYPE).unwrap();
            assert_eq!(t.value[0], nrt);
            let report = ParsedIe::find_ie(&ies, ie).expect("the path report IE");
            let inner = ParsedIe::parse_all(&report.value);
            let peer =
                ParsedIe::find_ie(&inner, crate::n4_build::pfcp_ie::REMOTE_GTP_U_PEER).unwrap();
            assert_eq!(peer.value, vec![0x02, 10, 0, 0, 1], "V4 flag + 10.0.0.1");
            assert_eq!(server.pending_report_count().await, 1, "tracked for T1/N1");

            // The SMF answers; the request stops being tracked.
            let mut ok = crate::n4_build::PfcpMessageBuilder::new();
            ok.add_u8(pfcp_ie::CAUSE, PfcpCause::RequestAccepted as u8);
            smf.send_to(
                &encode_pfcp(
                    pfcp_type::NODE_REPORT_RESPONSE,
                    None,
                    hdr.sequence_number,
                    &ok.build(),
                ),
                addr,
            )
            .await
            .unwrap();
            for _ in 0..50 {
                if server.pending_report_count().await == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert_eq!(server.pending_report_count().await, 0, "acknowledged");
        }
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
        // #1008: octet 5 first, as a conformant SMF sends it.
        b.add_tlv(
            pfcp_ie::APPLY_ACTION,
            &[apply_action as u8, (apply_action >> 8) as u8],
        );
        b.build()
    }

    fn pdr_body(pdr_id: u16, precedence: u32, far_id: u32, qer_id: u32, urr_id: u32) -> Vec<u8> {
        pdr_body_on(pdr_id, precedence, far_id, qer_id, urr_id, 0x1234)
    }

    /// [`pdr_body`] on the SMF-named TEID `teid`. Two sessions cannot share one
    /// (#1834), so a test establishing several gives each its own.
    fn pdr_body_on(
        pdr_id: u16,
        precedence: u32,
        far_id: u32,
        qer_id: u32,
        urr_id: u32,
        teid: u32,
    ) -> Vec<u8> {
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0); // Access
        pdi.add_f_teid(&crate::n4_build::FTeid {
            teid,
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

    // ------------------------------------------------------------------
    // #1475: the QER MBR is policed at the rate the SMF put on the wire.
    // ------------------------------------------------------------------

    /// A Create/Update QER body as smfd's `build_create_qer` encodes the
    /// Session-AMBR QER: QER ID, Gate Status (both OPEN), MBR, QFI. The MBR IE
    /// is spelled out byte for byte: TS 29.244 §8.2.8, two 5-octet binary
    /// fields in kbit/s (1 kbps = 1000 bps), UL then DL.
    fn ambr_qer_body_1475(id: u32, ul_kbps: u64, dl_kbps: u64) -> Vec<u8> {
        let mut mbr = Vec::new();
        mbr.extend_from_slice(&ul_kbps.to_be_bytes()[3..8]);
        mbr.extend_from_slice(&dl_kbps.to_be_bytes()[3..8]);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u32(pfcp_ie::QER_ID, id);
        b.add_u8(25, 0x00); // Gate Status (§8.2.7): UL and DL OPEN
        b.add_tlv(26, &mbr); // MBR (§8.2.8)
        b.add_u8(pfcp_ie::QFI, 9);
        b.build()
    }

    /// UL G-PDU from UE 10.45.0.42 on TEID 0x1234 (the F-TEID `pdr_body` sets),
    /// carrying an IPv4/UDP packet of exactly `len` bytes.
    fn ul_gpdu_1475(len: usize) -> Vec<u8> {
        let mut ip = vec![0u8; len];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17; // UDP
        ip[12..16].copy_from_slice(&[10, 45, 0, 42]);
        ip[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let csum = crate::data_plane::ipv4_header_checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&csum.to_be_bytes());
        ip[20..22].copy_from_slice(&1234u16.to_be_bytes());
        ip[22..24].copy_from_slice(&53u16.to_be_bytes());
        ip[24..26].copy_from_slice(&((len - 20) as u16).to_be_bytes());
        crate::data_plane::encapsulate_dl_gpdu(&ip, 0x1234, None)
    }

    /// How `offer_ul_1475` spaces its packets.
    #[derive(Clone, Copy)]
    enum Pace1475 {
        /// Back-to-back, as fast as the runner goes.
        Flat,
        /// At least this long between packets (sleep after each send). A
        /// stalled runner only widens the gaps, so the offer never exceeds
        /// the nominal rate and never bunches.
        MinGap(std::time::Duration),
        /// Packet `i` at `start + i * gap`. A stalled runner catches up in a
        /// burst, so the offer never falls below the nominal rate.
        Deadline(std::time::Duration),
    }

    /// Offer exactly `count` UL packets of `len` bytes through the real
    /// `handle_uplink_packet`. The volume is fixed, never "as many as fit in a
    /// wall-clock window", so the outcome depends on the bytes offered and the
    /// elapsed time returned, not on how fast the runner is.
    /// Returns (qer_gate drops, elapsed s).
    async fn offer_ul_1475(
        dp: &crate::data_plane::DataPlane,
        tun: &std::fs::File,
        len: usize,
        count: u32,
        pace: Pace1475,
    ) -> (u64, f64) {
        use crate::data_plane::DropReason;
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(tun);
        let gnb: SocketAddr = "127.0.0.1:2152".parse().unwrap();
        let pkt = ul_gpdu_1475(len);
        let drops_before = dp.stats.drops(DropReason::QerGate);
        let start = tokio::time::Instant::now();
        for i in 0..count {
            match pace {
                Pace1475::Flat => {}
                Pace1475::MinGap(gap) if i > 0 => tokio::time::sleep(gap).await,
                Pace1475::MinGap(_) => {}
                Pace1475::Deadline(gap) => tokio::time::sleep_until(start + gap * i).await,
            }
            dp.handle_uplink_packet(&pkt, gnb, fd).await;
        }
        let elapsed = start.elapsed().as_secs_f64();
        (dp.stats.drops(DropReason::QerGate) - drops_before, elapsed)
    }

    /// **#1475, TS 29.244 §8.2.8 / §5.4.** A Session-AMBR QER installed through
    /// the real N4 path (Establishment, then the Update QER smfd sends when the
    /// PCF lowers the AMBR, as in demo d444a) is policed at the rate on the wire.
    ///
    /// upfd used to scale the kbit/s field to bit/s and hand that to a policer
    /// that takes kbit/s, so 64 kbps was policed as 64 Mbps and nothing was ever
    /// dropped (the EKS run's `qer_gate` stayed 0).
    #[tokio::test]
    async fn a_64_kbps_session_ambr_drops_above_64_kbps_as_qer_gate_1475() {
        use crate::data_plane::DropReason;
        let ms = std::time::Duration::from_millis;
        let (_server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let tun = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("/dev/null stands in for the TUN");

        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;

        // PDR 1 (UL, Access) -> FAR 1 FORW, QER 1 = the subscribed 1 Gbps AMBR.
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0);
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
        pdr.add_pdr_id(1);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 100);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u32(pfcp_ie::FAR_ID, 1);
        pdr.add_u32(pfcp_ie::QER_ID, 1);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x1475,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr.build());
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.add_tlv(
            pfcp_ie::CREATE_QER,
            &ambr_qer_body_1475(1, 1_000_000, 1_000_000),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let (hdr, _) = ParsedPfcpHeader::parse(&resp).unwrap();
        let _ = hdr;
        apply_next(&mut rx, &dp).await;
        let upf_seid = dp
            .sessions
            .find_by_ul_teid(0x1234)
            .expect("the data plane holds the established session")
            .upf_seid;

        // At 1 Gbps (125 MB/s, a 1.25 MB burst that starts full), 1 MB offered
        // back-to-back fits inside the burst and passes untouched however fast
        // the runner offers it (#1487: a fixed-duration offer reached 1.5 Gbps
        // on a fast runner and was rightly policed). A policer reading the
        // field 1000x too LOW (1 Mbps: 125 kB/s, 1500 B burst) would pass only
        // 1500 B + 125 kB/s x elapsed, so it drops here whenever the offer ran
        // above 1 Mbps; asserting 2 Mbps keeps that guard meaningful.
        let (drops, secs) = offer_ul_1475(&dp, &tun, 500, 2000, Pace1475::Flat).await;
        let offered_bps = (2000 * 500 * 8) as f64 / secs;
        assert!(
            offered_bps > 2.0 * 1_000_000.0,
            "the 1 Gbps leg offered only {offered_bps:.0} bit/s: cannot tell 1 Gbps from 1 Mbps"
        );
        assert_eq!(drops, 0, "1 Gbps AMBR must not drop 1 MB (2000 x 500 B)");

        // The PCF lowers UL Session-AMBR to 64 kbps: smfd sends Update QER with
        // UL MBR = 64 (kbit/s) on the wire.
        let mut m = crate::n4_build::PfcpMessageBuilder::new();
        m.add_tlv(pfcp_ie::UPDATE_QER, &ambr_qer_body_1475(1, 64, 1_000_000));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &m.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        // Below the AMBR: 10 x 200 B at least 50 ms apart (<= 32 kbps). Each gap
        // refills a 64 kbps bucket (8000 B/s, 1500 B cap) by >= 400 B, more
        // than the 200 B the next packet takes, so all of it passes however
        // slow the runner is.
        let (drops, _) = offer_ul_1475(&dp, &tun, 200, 10, Pace1475::MinGap(ms(50))).await;
        assert_eq!(drops, 0, "32 kbps under a 64 kbps AMBR must all pass");

        // Above it: 200 x 500 B on a 5 ms schedule (800 kbps) for about 1 s. A
        // late runner catches up, so the offer stays above 64 kbps; the 100 kB
        // offered exceeds what the bucket can pass (1500 B + 8000 B/s) unless
        // the leg takes over 12 s.
        let sent = 200u64;
        let (drops, secs) =
            offer_ul_1475(&dp, &tun, 500, sent as u32, Pace1475::Deadline(ms(5))).await;
        let offered_bps = (sent * 500 * 8) as f64 / secs;
        assert!(
            offered_bps > 2.0 * 64_000.0,
            "the above-rate leg offered only {offered_bps:.0} bit/s"
        );
        assert!(
            drops > 0,
            "traffic above a 64 kbps AMBR must be dropped as qer_gate ({sent} sent)"
        );
        // What passed is the 64 kbps refill plus the 1500 B burst, ~1 packet slack.
        let passed_bytes = ((sent - drops) * 500) as f64;
        let ceiling = 1500.0 + 8000.0 * secs + 500.0;
        assert!(
            passed_bytes <= ceiling,
            "passed {passed_bytes} B in {secs:.3} s: above 64 kbps (ceiling {ceiling:.0} B)"
        );
        assert!(
            passed_bytes >= 0.5 * 8000.0 * secs,
            "passed only {passed_bytes} B in {secs:.3} s: policed well below 64 kbps"
        );
        assert_eq!(
            dp.stats
                .dropped_packets
                .load(std::sync::atomic::Ordering::Relaxed),
            dp.stats.drops(DropReason::QerGate),
            "every drop is qer_gate: {}",
            dp.stats.summary()
        );
    }

    // ------------------------------------------------------------------
    // #1478: an Update QER changes only the IEs it carries (Table 7.5.4.5-1).
    // ------------------------------------------------------------------

    /// A QER body of QER ID `id` with the given IEs, each left out when `None`:
    /// Gate Status octet (§8.2.7), the MBR and GBR as raw values (§8.2.8, §8.2.9: two
    /// 5-octet kbit/s fields), QFI.
    fn qer_body_1478(
        id: u32,
        gate: Option<u8>,
        mbr: Option<&[u8]>,
        gbr: Option<&[u8]>,
        qfi: Option<u8>,
    ) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u32(pfcp_ie::QER_ID, id);
        if let Some(g) = gate {
            b.add_u8(25, g);
        }
        if let Some(m) = mbr {
            b.add_tlv(26, m);
        }
        if let Some(g) = gbr {
            b.add_tlv(27, g);
        }
        if let Some(q) = qfi {
            b.add_u8(pfcp_ie::QFI, q);
        }
        b.build()
    }

    /// An MBR or GBR value: UL then DL, 5 octets each, kbit/s.
    fn rates_1478(ul_kbps: u64, dl_kbps: u64) -> Vec<u8> {
        let mut v = ul_kbps.to_be_bytes()[3..8].to_vec();
        v.extend_from_slice(&dl_kbps.to_be_bytes()[3..8]);
        v
    }

    /// Establish, through the real N4 handler, the #1475 session (UL PDR 1 on TEID
    /// 0x1234, FAR 1 FORW) with QER 1 = `qer`, apply it to `dp` and return the
    /// Establishment Response.
    async fn establish_with_qer_1478(
        smf: &UdpSocket,
        addr: SocketAddr,
        rx: &mut mpsc::Receiver<PfcpSessionEvent>,
        dp: &crate::data_plane::DataPlane,
        qer: &[u8],
    ) -> Vec<u8> {
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0);
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
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        pdr.add_pdr_id(1);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 100);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u32(pfcp_ie::FAR_ID, 1);
        pdr.add_u32(pfcp_ie::QER_ID, 1);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x1478,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr.build());
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.add_tlv(pfcp_ie::CREATE_QER, qer);
        let resp = exchange(smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await;
        if response_cause(&resp) == PfcpCause::RequestAccepted as u8 {
            apply_next(rx, dp).await;
        }
        resp
    }

    /// Send a Session Modification carrying `update_qer` as its only IE; apply the
    /// event when it is accepted. Returns the response.
    async fn update_qer_1478(
        smf: &UdpSocket,
        addr: SocketAddr,
        rx: &mut mpsc::Receiver<PfcpSessionEvent>,
        dp: &crate::data_plane::DataPlane,
        update_qer: &[u8],
    ) -> Vec<u8> {
        let upf_seid = dp.sessions.find_by_ul_teid(0x1234).expect("held").upf_seid;
        let mut m = crate::n4_build::PfcpMessageBuilder::new();
        m.add_tlv(pfcp_ie::UPDATE_QER, update_qer);
        let resp = exchange(smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &m.build())).await;
        if response_cause(&resp) == PfcpCause::RequestAccepted as u8 {
            apply_next(rx, dp).await;
        }
        resp
    }

    fn offending_ie_1478(resp: &[u8]) -> Option<u16> {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        ParsedIe::find_ie(&ies, pfcp_ie::OFFENDING_IE)
            .map(|ie| u16::from_be_bytes([ie.value[0], ie.value[1]]))
    }

    /// **#1478.** A third-party SMF's Update QER that changes only the QFI keeps the
    /// 64 kbps UL MBR: traffic above it is still dropped as qer_gate. upfd used to
    /// rebuild the QER from the Update's IEs, so the cap was lifted and nothing was
    /// dropped. The fixed-volume, deadline-paced offer is the #1487 rule.
    #[tokio::test]
    async fn an_update_qer_without_an_mbr_keeps_the_rate_cap_1478() {
        let ms = std::time::Duration::from_millis;
        let (_server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let tun = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("/dev/null stands in for the TUN");
        let create = qer_body_1478(
            1,
            Some(0x00),
            Some(&rates_1478(64, 1_000_000)),
            None,
            Some(9),
        );
        let resp = establish_with_qer_1478(&smf, addr, &mut rx, &dp, &create).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);

        // The Update carries the QER ID and a new QFI only.
        let update = qer_body_1478(1, None, None, None, Some(5));
        let resp = update_qer_1478(&smf, addr, &mut rx, &dp, &update).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let session = dp.sessions.find_by_ul_teid(0x1234).unwrap();
        {
            let qers = session.qers.read().unwrap();
            assert_eq!(qers[&1].qfi, Some(5), "the QFI it carried is applied");
            assert_eq!((qers[&1].ul_mbr, qers[&1].dl_mbr), (64, 1_000_000));
            assert!(qers[&1].ul_gate_open && qers[&1].dl_gate_open);
        }

        // 200 x 500 B on a 5 ms schedule (800 kbps): above 64 kbps, so it drops.
        let sent = 200u64;
        let (drops, secs) =
            offer_ul_1475(&dp, &tun, 500, sent as u32, Pace1475::Deadline(ms(5))).await;
        let offered_bps = (sent * 500 * 8) as f64 / secs;
        assert!(
            offered_bps > 2.0 * 64_000.0,
            "the offer ran at only {offered_bps:.0} bit/s"
        );
        assert!(drops > 0, "the 64 kbps cap must still drop ({sent} sent)");
        let passed_bytes = ((sent - drops) * 500) as f64;
        let ceiling = 1500.0 + 8000.0 * secs + 500.0;
        assert!(
            passed_bytes <= ceiling,
            "passed {passed_bytes} B in {secs:.3} s: above 64 kbps (ceiling {ceiling:.0} B)"
        );
    }

    /// **#1478.** An Update QER that changes only the MBR leaves a CLOSED uplink gate
    /// closed: every UL packet is still dropped. upfd used to rebuild the QER, so the
    /// absent Gate Status opened both gates.
    #[tokio::test]
    async fn an_update_qer_without_gate_status_keeps_a_closed_gate_1478() {
        use crate::data_plane::DropReason;
        let (_server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let tun = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("/dev/null stands in for the TUN");
        // Gate Status 0x04: UL CLOSED (bits 3-4 = 1), DL OPEN (§8.2.7).
        let create = qer_body_1478(1, Some(0x04), None, None, Some(9));
        let resp = establish_with_qer_1478(&smf, addr, &mut rx, &dp, &create).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);

        let update = qer_body_1478(1, None, Some(&rates_1478(1_000_000, 1_000_000)), None, None);
        let resp = update_qer_1478(&smf, addr, &mut rx, &dp, &update).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let session = dp.sessions.find_by_ul_teid(0x1234).unwrap();
        {
            let qers = session.qers.read().unwrap();
            assert_eq!(qers[&1].ul_mbr, 1_000_000, "the MBR it carried is applied");
            assert!(!qers[&1].ul_gate_open, "the UL gate stays closed");
            assert!(qers[&1].dl_gate_open);
            assert_eq!(qers[&1].qfi, Some(9), "the QFI is kept");
        }

        // 10 x 500 B is far inside the 1 Gbps burst: only the gate can drop them.
        let (drops, _) = offer_ul_1475(&dp, &tun, 500, 10, Pace1475::Flat).await;
        assert_eq!(drops, 10, "a closed UL gate drops every UL packet");
        assert_eq!(dp.stats.drops(DropReason::QerGate), 10);
    }

    /// **#1478.** An MBR or GBR IE shorter than its two 5-octet fields is malformed:
    /// an Update QER carrying one is refused with "Mandatory IE incorrect" naming the
    /// Update QER (§7.6.8), and the QER keeps its cap. It used to be ignored, which
    /// in an Update QER also lifted the cap.
    #[tokio::test]
    async fn a_short_mbr_or_gbr_in_an_update_qer_is_refused_1478() {
        let (_server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let create = qer_body_1478(1, Some(0x00), Some(&rates_1478(64, 64)), None, Some(9));
        let resp = establish_with_qer_1478(&smf, addr, &mut rx, &dp, &create).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);

        let short = rates_1478(1_000_000, 1_000_000)[..9].to_vec();
        for update in [
            qer_body_1478(1, Some(0x00), Some(&short), None, None),
            qer_body_1478(1, Some(0x00), None, Some(&short), None),
            qer_body_1478(1, Some(0x00), Some(&[]), None, None),
        ] {
            let resp = update_qer_1478(&smf, addr, &mut rx, &dp, &update).await;
            assert_eq!(response_cause(&resp), PfcpCause::MandatoryIeIncorrect as u8);
            assert_eq!(offending_ie_1478(&resp), Some(pfcp_ie::UPDATE_QER));
        }
        let session = dp.sessions.find_by_ul_teid(0x1234).unwrap();
        let qers = session.qers.read().unwrap();
        assert_eq!(
            (qers[&1].ul_mbr, qers[&1].dl_mbr),
            (64, 64),
            "the cap stands"
        );
    }

    /// **#1478.** A Create QER with a short MBR rejects the Session Establishment with
    /// "Mandatory IE incorrect" naming the Create QER (§7.6.8); no session is held.
    /// It used to be ignored, so the QER was installed without its cap.
    #[tokio::test]
    async fn a_short_mbr_in_a_create_qer_rejects_the_establishment_1478() {
        let (server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let short = rates_1478(64, 64)[..5].to_vec();
        let create = qer_body_1478(1, Some(0x00), Some(&short), None, Some(9));
        let resp = establish_with_qer_1478(&smf, addr, &mut rx, &dp, &create).await;
        assert_eq!(resp[1], pfcp_type::SESSION_ESTABLISHMENT_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::MandatoryIeIncorrect as u8);
        assert_eq!(offending_ie_1478(&resp), Some(pfcp_ie::CREATE_QER));
        assert!(
            server.sessions.read().await.is_empty(),
            "no session is held"
        );
    }

    /// A grouped IE body holding only `ies`, each `(type, value)`.
    fn grouped_1532(ies: &[(u16, &[u8])]) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        for (t, v) in ies {
            b.add_tlv(*t, v);
        }
        b.build()
    }

    /// An association, then a Session Establishment of PDR 1 (QER 1, URR 1),
    /// FAR 1 FORW, QER 1 and URR 1, plus `extra` IEs. Returns the response.
    async fn establish_1532(
        smf: &UdpSocket,
        addr: SocketAddr,
        seq: u32,
        extra: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(smf, addr, &encode_pfcp(5, None, seq, &assoc)).await;
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x1532,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr_body(1, 100, 1, 1, 1));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.add_tlv(pfcp_ie::CREATE_QER, &qer_body(1, 9));
        b.add_tlv(
            pfcp_ie::CREATE_URR,
            &urr_body(1, Some(1_000_000), None, None),
        );
        for (t, v) in extra {
            b.add_tlv(*t, v);
        }
        exchange(smf, addr, &encode_pfcp(50, Some(0), seq + 1, &b.build())).await
    }

    /// **#1532.** A Create PDR, FAR or URR that its parser refuses rejects the
    /// Session Establishment with "Mandatory IE incorrect" naming the grouped IE
    /// (TS 29.244 §7.6.8); no session is held and nothing reaches the data plane.
    /// Each used to be dropped with a warning and the session accepted without it.
    /// The same request without the malformed IE is accepted.
    #[tokio::test]
    async fn a_malformed_create_pdr_far_or_urr_rejects_the_establishment_1532() {
        let pdi_short_fteid =
            grouped_1532(&[(pfcp_ie::SOURCE_INTERFACE, &[0]), (pfcp_ie::F_TEID, &[])]);
        let pdi_short_ue_ip = grouped_1532(&[
            (pfcp_ie::SOURCE_INTERFACE, &[1]),
            (pfcp_ie::UE_IP_ADDRESS, &[]),
        ]);
        let fp_short_ohc = grouped_1532(&[
            (pfcp_ie::DESTINATION_INTERFACE, &[0]),
            (pfcp_ie::OUTER_HEADER_CREATION, &[0x01, 0x00]),
        ]);
        // #1598: a missing rule ID is cause 66 (Create PDR, Create FAR: M at
        // establishment) or 67 (Create URR: C) with the ID's type; a malformed
        // value stays 69 with the grouped IE.
        let incorrect = PfcpCause::MandatoryIeIncorrect;
        let cases: Vec<(&str, u16, Vec<u8>, PfcpCause, u16)> = vec![
            (
                "PDR without a PDR ID",
                pfcp_ie::CREATE_PDR,
                grouped_1532(&[(pfcp_ie::PRECEDENCE, &200u32.to_be_bytes())]),
                PfcpCause::MandatoryIeMissing,
                pfcp_ie::PDR_ID,
            ),
            (
                "PDR with an empty F-TEID",
                pfcp_ie::CREATE_PDR,
                grouped_1532(&[
                    (pfcp_ie::PDR_ID, &2u16.to_be_bytes()),
                    (pfcp_ie::PRECEDENCE, &200u32.to_be_bytes()),
                    (pfcp_ie::PDI, &pdi_short_fteid),
                    (pfcp_ie::FAR_ID, &1u32.to_be_bytes()),
                ]),
                incorrect,
                pfcp_ie::CREATE_PDR,
            ),
            (
                "PDR with an empty UE IP Address",
                pfcp_ie::CREATE_PDR,
                grouped_1532(&[
                    (pfcp_ie::PDR_ID, &2u16.to_be_bytes()),
                    (pfcp_ie::PRECEDENCE, &200u32.to_be_bytes()),
                    (pfcp_ie::PDI, &pdi_short_ue_ip),
                    (pfcp_ie::FAR_ID, &1u32.to_be_bytes()),
                ]),
                incorrect,
                pfcp_ie::CREATE_PDR,
            ),
            (
                "FAR without a FAR ID",
                pfcp_ie::CREATE_FAR,
                grouped_1532(&[(pfcp_ie::APPLY_ACTION, &[0x02, 0x00])]),
                PfcpCause::MandatoryIeMissing,
                pfcp_ie::FAR_ID,
            ),
            (
                "FAR with a short Outer Header Creation",
                pfcp_ie::CREATE_FAR,
                grouped_1532(&[
                    (pfcp_ie::FAR_ID, &2u32.to_be_bytes()),
                    (pfcp_ie::APPLY_ACTION, &[0x02, 0x00]),
                    (pfcp_ie::FORWARDING_PARAMETERS, &fp_short_ohc),
                ]),
                incorrect,
                pfcp_ie::CREATE_FAR,
            ),
            (
                "URR without a URR ID",
                pfcp_ie::CREATE_URR,
                grouped_1532(&[(pfcp_ie::MEASUREMENT_METHOD, &[0x02])]),
                PfcpCause::ConditionalIeMissing,
                pfcp_ie::URR_ID,
            ),
        ];
        for (seq, (what, ie_type, body, cause, offending)) in (0u32..).step_by(10).zip(cases) {
            let (server, smf, addr, mut rx) = spawn_test_server().await;
            let resp = establish_1532(&smf, addr, seq + 1, &[(ie_type, body)]).await;
            assert_eq!(resp[1], pfcp_type::SESSION_ESTABLISHMENT_RESPONSE, "{what}");
            assert_eq!(response_cause(&resp), cause as u8, "{what}");
            assert_eq!(offending_ie_1478(&resp), Some(offending), "{what}");
            assert!(
                server.sessions.read().await.is_empty(),
                "{what}: no session"
            );
            assert!(rx.try_recv().is_err(), "{what}: nothing installed");
        }

        // Control: the same establishment without the malformed IE is accepted.
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let resp = establish_1532(&smf, addr, 1, &[]).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.sessions.read().await.len(), 1);
    }

    fn usage_reports_in(resp: &[u8]) -> Vec<(u32, u64)> {
        usage_reports_of(resp, pfcp_ie::USAGE_REPORT_SMR)
    }

    /// `(urr_id, total volume)` of the Usage Reports in a Session Report REQUEST.
    fn usage_reports_in_report(req: &[u8]) -> Vec<(u32, u64)> {
        usage_reports_of(req, pfcp_ie::USAGE_REPORT_SRR)
    }

    fn usage_reports_of(resp: &[u8], ie_type: u16) -> Vec<(u32, u64)> {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        ParsedIe::find_all_ies(&ies, ie_type)
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

    /// #583: a forwarding tunnel created mid-session -- an Access-source PDR whose F-TEID
    /// the UPF chooses (zero TEID, this tree's SMF's spelling) and a FAR back toward the
    /// access side. The response must carry the allocated F-TEID in a Created PDR, the
    /// data plane must route that TEID to the session and detect the PDR on it, and the
    /// FAR's endpoint must not move the session's own DL tunnel.
    #[tokio::test]
    async fn a_modification_allocates_the_f_teid_of_a_pdr_it_creates() {
        let (server, smf, addr, mut rx, dp, upf_seid) = established_session().await;
        let dl_before = server.sessions.read().await[&upf_seid].dl_teid;

        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0);
        pdi.add_tlv(pfcp_ie::F_TEID, &[0x00, 0, 0, 0, 0]); // TEID 0: the UPF chooses
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        pdr.add_pdr_id(0x55);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 10);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u8(pfcp_ie::OUTER_HEADER_REMOVAL, 0);
        pdr.add_u32(pfcp_ie::FAR_ID, 0x50);
        pdr.add_u32(pfcp_ie::QER_ID, 0x55);
        let mut fp = crate::n4_build::PfcpMessageBuilder::new();
        fp.add_u8(pfcp_ie::DESTINATION_INTERFACE, 0);
        fp.add_tlv(
            pfcp_ie::OUTER_HEADER_CREATION,
            &[0x01, 0x00, 0x00, 0x00, 0x0F, 0x0D, 127, 58, 3, 1],
        );
        let mut far = crate::n4_build::PfcpMessageBuilder::new();
        far.add_u32(pfcp_ie::FAR_ID, 0x50);
        far.add_tlv(pfcp_ie::APPLY_ACTION, &[0x02, 0x00]); // FORW, octet 5
        far.add_tlv(pfcp_ie::FORWARDING_PARAMETERS, &fp.build());
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr.build());
        b.add_tlv(pfcp_ie::CREATE_FAR, &far.build());
        b.add_tlv(pfcp_ie::CREATE_QER, &qer_body(0x55, 5));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);

        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        let created = ParsedIe::find_ie(&ies, pfcp_ie::CREATED_PDR)
            .expect("a Created PDR for the PDR whose F-TEID the UPF chose");
        let inner = ParsedIe::parse_all(&created.value);
        let id = ParsedIe::find_ie(&inner, pfcp_ie::PDR_ID).unwrap();
        assert_eq!(id.value[..], [0x00, 0x55]);
        let fteid = crate::n4_build::ParsedFTeid::parse(
            &ParsedIe::find_ie(&inner, pfcp_ie::F_TEID).unwrap().value,
        )
        .unwrap();
        assert_ne!(fteid.teid, 0);
        assert!(fteid.ipv4.is_some(), "the UPF's GTP-U address");

        apply_next(&mut rx, &dp).await;
        let session = dp
            .sessions
            .find_by_ul_teid(fteid.teid)
            .expect("the allocated TEID routes to the session");
        assert_eq!(session.upf_seid, upf_seid);
        assert_eq!(
            session.pdr_teids.read().unwrap().get(&0x55),
            Some(&fteid.teid),
            "the PDR detects on the tunnel allocated for it"
        );
        assert_eq!(
            server.sessions.read().await[&upf_seid].dl_teid,
            dl_before,
            "a relay FAR's endpoint is not the session's downlink tunnel"
        );
    }

    /// The F-TEID of the Created PDR for `pdr_id` in a session response.
    fn created_f_teid(resp: &[u8], pdr_id: u16) -> crate::n4_build::ParsedFTeid {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        for created in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATED_PDR) {
            let inner = ParsedIe::parse_all(&created.value);
            let id = ParsedIe::find_ie(&inner, pfcp_ie::PDR_ID).unwrap();
            if id.value[..] == pdr_id.to_be_bytes() {
                return crate::n4_build::ParsedFTeid::parse(
                    &ParsedIe::find_ie(&inner, pfcp_ie::F_TEID).unwrap().value,
                )
                .unwrap();
            }
        }
        panic!("no Created PDR {pdr_id}");
    }

    /// A Session Modification creating Access PDR `pdr_id` whose F-TEID IE value is
    /// `f_teid`; returns the response.
    /// The Failed Rule ID IE value of a response (#1154).
    fn failed_rule_id(resp: &[u8]) -> Option<Vec<u8>> {
        let (_, body) = ParsedPfcpHeader::parse(resp).ok()?;
        ParsedIe::find_ie(&ParsedIe::parse_all(body), pfcp_ie::FAILED_RULE_ID)
            .map(|ie| ie.value.to_vec())
    }

    async fn modify_creating_pdr(
        smf: &UdpSocket,
        addr: SocketAddr,
        upf_seid: u64,
        seq: u32,
        pdr_id: u16,
        f_teid: &[u8],
    ) -> Vec<u8> {
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0);
        pdi.add_tlv(pfcp_ie::F_TEID, f_teid);
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        pdr.add_pdr_id(pdr_id);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 10);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u8(pfcp_ie::OUTER_HEADER_REMOVAL, 0);
        pdr.add_u32(pfcp_ie::FAR_ID, 1);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr.build());
        let resp = exchange(smf, addr, &encode_pfcp(52, Some(upf_seid), seq, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        resp
    }

    // ------------------------------------------------------------------
    // #1815: TEIDs the UPF chose go back to its pool when the request that
    // chose them is rejected, and when the PDRs or the session holding them
    // go away.

    /// A Create PDR `pdr_id` (Access, FAR 1) whose F-TEID is `f_teid`.
    fn create_pdr_1815(pdr_id: u16, f_teid: &[u8]) -> Vec<u8> {
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0);
        pdi.add_tlv(pfcp_ie::F_TEID, f_teid);
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        pdr.add_pdr_id(pdr_id);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 10);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u32(pfcp_ie::FAR_ID, 1);
        pdr.build()
    }

    /// A Session Modification creating PDRs 0x70 (CH|CHID, CHOOSE ID 7), 0x71
    /// (the same CHOOSE ID) and 0x72 (CH): two TEIDs. With `reject`, it also
    /// updates FAR 99, which the session does not hold, so it is refused.
    fn choosing_modification_1815(reject: bool) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_PDR, &create_pdr_1815(0x70, &[0x0D, 7]));
        b.add_tlv(pfcp_ie::CREATE_PDR, &create_pdr_1815(0x71, &[0x0D, 7]));
        b.add_tlv(pfcp_ie::CREATE_PDR, &create_pdr_1815(0x72, &[0x05]));
        if reject {
            b.add_tlv(pfcp_ie::UPDATE_FAR, &far_body(99, 0x02));
        }
        b.build()
    }

    /// **#1815, TS 29.244 §6.3.3.** A rejected Session Modification gives back
    /// every TEID it chose while being parsed: a Create PDR's CHOOSE, a CHOOSE ID
    /// two PDRs share, and an Update PDR's CHOOSE. So does one for an unknown
    /// SEID. Repeating the rejection takes nothing, and the accepted control
    /// shows the same message does take TEIDs. Before, every rejection burned
    /// the TEIDs it chose.
    #[tokio::test]
    async fn a_rejected_modification_gives_back_the_teids_it_chose_1815() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        // #1834: PDR 1's SMF-named TEID 0x1234 is reserved, so the pool holds one.
        assert_eq!(server.teids.in_use(), 1, "PDR 1's SMF-named TEID");
        let base = server.teids.in_use();

        for seq in 10..15 {
            let resp = exchange(
                &smf,
                addr,
                &encode_pfcp(52, Some(upf_seid), seq, &choosing_modification_1815(true)),
            )
            .await;
            assert_eq!(
                response_cause(&resp),
                PfcpCause::RuleCreationModificationFailure as u8,
                "Update FAR 99 names no rule of the session"
            );
            assert_eq!(server.teids.in_use(), base, "rejection {seq} holds no TEID");
        }

        // An Update PDR's CHOOSE in a rejected message is given back too.
        let mut upd = crate::n4_build::PfcpMessageBuilder::new();
        upd.add_pdr_id(1);
        upd.add_tlv(pfcp_ie::PDI, &pdi_1682(0, Some(vec![0x05]), None));
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_PDR, &upd.build());
        b.add_tlv(pfcp_ie::UPDATE_FAR, &far_body(99, 0x02));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 20, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8
        );
        assert_eq!(server.teids.in_use(), base, "the Update PDR's TEID is back");

        // An unknown SEID: the TEIDs were chosen before the lookup failed.
        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(52, Some(0xdead), 21, &choosing_modification_1815(false)),
        )
        .await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::SessionContextNotFound as u8
        );
        assert_eq!(
            server.teids.in_use(),
            base,
            "nothing held for an unknown SEID"
        );

        // Control: accepted, the same PDRs hold two TEIDs (one per CHOOSE ID).
        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(52, Some(upf_seid), 22, &choosing_modification_1815(false)),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.teids.in_use(), base + 2, "CHOOSE ID 7 and PDR 0x72");
    }

    /// **#1815.** A chosen TEID is held while a PDR detects on it and given back
    /// once none does: a Remove PDR of one of two PDRs sharing a CHOOSE ID keeps
    /// it, removing the second frees it, an Update PDR moving off a chosen TEID
    /// frees it, and deleting the session frees the rest.
    #[tokio::test]
    async fn a_chosen_teid_is_held_until_no_pdr_detects_on_it_1815() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        // #1834: PDR 1's SMF-named TEID is held too.
        let base = server.teids.in_use();
        let modify = |seq: u32, body: Vec<u8>| encode_pfcp(52, Some(upf_seid), seq, &body);
        let remove_pdr = |id: u16| {
            let mut r = crate::n4_build::PfcpMessageBuilder::new();
            r.add_pdr_id(id);
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(pfcp_ie::REMOVE_PDR, &r.build());
            b.build()
        };

        let resp = exchange(&smf, addr, &modify(10, choosing_modification_1815(false))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.teids.in_use(), base + 2);

        let resp = exchange(&smf, addr, &modify(11, remove_pdr(0x70))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            server.teids.in_use(),
            base + 2,
            "PDR 0x71 still detects on CHOOSE ID 7's TEID"
        );

        let resp = exchange(&smf, addr, &modify(12, remove_pdr(0x71))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            server.teids.in_use(),
            base + 1,
            "no PDR detects on it any more"
        );

        // PDR 0x72 moves to a TEID the SMF names: its chosen one goes back, and
        // the SMF's 0x7777 is held in its place (#1834).
        let mut upd = crate::n4_build::PfcpMessageBuilder::new();
        upd.add_pdr_id(0x72);
        upd.add_tlv(pfcp_ie::PDI, &pdi_1682(0, Some(f_teid_1682(0x7777)), None));
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_PDR, &upd.build());
        let resp = exchange(&smf, addr, &modify(13, b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            server.teids.in_use(),
            base + 1,
            "the moved PDR's chosen TEID is back, and 0x7777 is held"
        );

        // A fresh CHOOSE, then the session goes, and its TEID with it.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_PDR, &create_pdr_1815(0x73, &[0x05]));
        let resp = exchange(&smf, addr, &modify(14, b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.teids.in_use(), base + 2);
        let resp = exchange(&smf, addr, &encode_pfcp(54, Some(upf_seid), 15, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            server.teids.in_use(),
            0,
            "every TEID the deleted session held is back, the SMF-named ones too"
        );
    }

    /// **#1815.** A refused establishment gives back the TEIDs its earlier PDRs
    /// chose (PDR 2's CH+V6 cannot be met with no IPv6 GTP-U socket), and an
    /// association's sessions give theirs back when the association goes.
    #[tokio::test]
    async fn establishment_and_association_teids_go_back_1815() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let establish = |pdrs: &[(u16, &[u8])]| {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
            b.add_f_seid(&crate::n4_build::FSeid {
                seid: 0x1815,
                ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
                ipv6: None,
            });
            for (id, f) in pdrs {
                b.add_tlv(pfcp_ie::CREATE_PDR, &create_pdr_1815(*id, f));
            }
            b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
            b.build()
        };

        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(50, Some(0), 2, &establish(&[(1, &[0x05]), (2, &[0x06])])),
        )
        .await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8,
            "CH+V6 with no IPv6 socket is refused"
        );
        assert_eq!(server.teids.in_use(), 0, "PDR 1's TEID is back");

        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(50, Some(0), 3, &establish(&[(1, &[0x05]), (2, &[0x05])])),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.teids.in_use(), 2);

        // A Session Retention Information naming another CP entity drops it.
        let kept = server
            .retain_association_sessions(&[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))], addr)
            .await;
        assert_eq!(kept, 0);
        assert_eq!(
            server.teids.in_use(),
            0,
            "a dropped session's TEIDs are back"
        );

        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(50, Some(0), 4, &establish(&[(1, &[0x05]), (2, &[0x05])])),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.teids.in_use(), 2);
        server.delete_association_sessions(addr, "#1815 test").await;
        assert_eq!(
            server.teids.in_use(),
            0,
            "the association's sessions' TEIDs are back"
        );
    }

    /// An establishment from the test SMF (CP F-SEID `cp_seid`) whose PDRs name
    /// the F-TEIDs `teids` (`None` means CH: the UPF chooses).
    fn establishment_1834(cp_seid: u64, teids: &[Option<u32>]) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: cp_seid,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        for (i, teid) in teids.iter().enumerate() {
            let f = match teid {
                Some(t) => f_teid_1682(*t),
                None => vec![0x05],
            };
            b.add_tlv(pfcp_ie::CREATE_PDR, &create_pdr_1815(1 + i as u16, &f));
        }
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.build()
    }

    /// The F-TEID of the Created PDR `pdr_id` in a response.
    fn created_teid_1834(resp: &[u8], pdr_id: u16) -> Option<u32> {
        let (_, body) = ParsedPfcpHeader::parse(resp).ok()?;
        ParsedIe::find_all_ies(&ParsedIe::parse_all(body), pfcp_ie::CREATED_PDR)
            .iter()
            .find_map(|c| {
                let inner = ParsedIe::parse_all(&c.value);
                let id = ParsedIe::find_ie(&inner, pfcp_ie::PDR_ID)?;
                (u16::from_be_bytes([id.value[0], id.value[1]]) == pdr_id).then_some(())?;
                let f = ParsedIe::find_ie(&inner, pfcp_ie::F_TEID)?;
                crate::n4_build::ParsedFTeid::parse(&f.value)
                    .ok()
                    .map(|f| f.teid)
            })
    }

    /// **#1834, TS 29.244 §5.5.3.** A TEID the SMF names itself is held in the
    /// pool, so a later CHOOSE skips it: session A names the very TEID the pool
    /// would hand out next, and session B's CHOOSE gets a different one. Before,
    /// the pool knew only the TEIDs it chose, and gave B session A's tunnel.
    #[tokio::test]
    async fn an_smf_named_teid_is_never_chosen_for_another_session_1834() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let next = TeidPool::FIRST;
        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(50, Some(0), 2, &establishment_1834(0xA, &[Some(next)])),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.teids.in_use(), 1, "A's SMF-named TEID is held");

        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(50, Some(0), 3, &establishment_1834(0xB, &[None])),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let chosen = created_teid_1834(&resp, 1).expect("B's chosen F-TEID");
        assert_ne!(chosen, next, "the pool skips the TEID session A named");
        assert_eq!(chosen, next + 1);
    }

    /// **#1834.** A TEID another session holds, named by the SMF, is refused with
    /// a rule failure naming the PDR and applies nothing: in an establishment
    /// (no session stored, no TEID kept), and in a modification's Create PDR. PDRs
    /// of ONE session may share an SMF-named TEID, at establishment and later. Once
    /// the holder is deleted, the TEID may be named again.
    #[tokio::test]
    async fn a_teid_another_session_holds_is_refused_1834() {
        let (server, smf, addr, _rx, _dp, a_seid) = established_session().await;
        let held = server.teids.in_use();
        let sessions = || server.sessions.try_read().expect("sessions").len();

        // An establishment naming A's 0x1234 (after a CHOOSE, which goes back).
        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(
                50,
                Some(0),
                20,
                &establishment_1834(0xB, &[None, Some(0x1234)]),
            ),
        )
        .await;
        assert_eq!(
            (response_cause(&resp), failed_rule_id(&resp)),
            (
                PfcpCause::RuleCreationModificationFailure as u8,
                Some(vec![0x00, 0x00, 0x02])
            ),
            "PDR 2 names session A's TEID"
        );
        assert_eq!(sessions(), 1, "no session B");
        assert_eq!(server.teids.in_use(), held, "and no TEID kept for it");

        // Two PDRs of one session sharing an SMF-named TEID is fine.
        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(
                50,
                Some(0),
                21,
                &establishment_1834(0xC, &[Some(0x5555), Some(0x5555)]),
            ),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.teids.in_use(), held + 1);
        let c_seid = *server
            .sessions
            .try_read()
            .unwrap()
            .keys()
            .find(|k| **k != a_seid)
            .unwrap();

        // A modification of C creating a PDR on A's TEID: refused, nothing applied.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(
            pfcp_ie::CREATE_PDR,
            &create_pdr_1815(0x77, &f_teid_1682(0x1234)),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(c_seid), 22, &b.build())).await;
        assert_eq!(
            (response_cause(&resp), failed_rule_id(&resp)),
            (
                PfcpCause::RuleCreationModificationFailure as u8,
                Some(vec![0x00, 0x00, 0x77])
            )
        );
        assert!(!server.sessions.try_read().unwrap()[&c_seid]
            .rules
            .pdr_ids
            .contains(&0x77));

        // ... while a PDR on C's own 0x5555, and one on a free TEID, are accepted.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(
            pfcp_ie::CREATE_PDR,
            &create_pdr_1815(0x78, &f_teid_1682(0x5555)),
        );
        b.add_tlv(
            pfcp_ie::CREATE_PDR,
            &create_pdr_1815(0x79, &f_teid_1682(0x6666)),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(c_seid), 23, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(server.teids.in_use(), held + 2, "0x6666 is now C's");

        // A goes; its TEID may be named again.
        let resp = exchange(&smf, addr, &encode_pfcp(54, Some(a_seid), 24, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(50, Some(0), 25, &establishment_1834(0xD, &[Some(0x1234)])),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// **#1815.** The pool skips a TEID still held when its cursor wraps, and
    /// wraps to its first TEID, never to 0.
    #[test]
    fn the_teid_pool_wraps_past_held_teids_1815() {
        let pool = TeidPool::new();
        let first = pool.alloc().unwrap();
        assert_eq!(first, TeidPool::FIRST);
        pool.inner.lock().unwrap().next = u32::MAX;
        assert_eq!(pool.alloc(), Some(u32::MAX));
        assert_eq!(
            pool.alloc(),
            Some(TeidPool::FIRST + 1),
            "wrapped past the held first TEID, not to 0"
        );
        pool.release(first);
        pool.inner.lock().unwrap().next = u32::MAX;
        pool.release(u32::MAX);
        assert_eq!(
            pool.alloc(),
            Some(u32::MAX),
            "a released TEID is free again"
        );
        assert_eq!(pool.alloc(), Some(TeidPool::FIRST));
        assert_eq!(pool.in_use(), 3);
    }

    /// #985 (TS 29.244 §8.2.3): with CH set, V4 / V6 say which address family the UP
    /// function assigns. With an IPv6 GTP-U socket the UPF now answers CH+V6 with its
    /// IPv6 address (it always answered IPv4, so an IPv6 gNB sent uplink to IPv4);
    /// CH+V4+V6 gets both; CH+V4 and this tree's zero-TEID request stay IPv4 only.
    #[tokio::test]
    async fn a_chosen_f_teid_carries_the_ipv6_n3_address_when_v6_is_asked_for() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        let n3_v6: Ipv6Addr = "2001:db8::985".parse().unwrap();
        let node_v4 = Ipv4Addr::LOCALHOST;

        // No IPv6 socket yet: CH+V6 cannot be met, so the PDR is refused (#985
        // review) rather than answered with an IPv4 F-TEID; CH+V4+V6 gets IPv4.
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0);
        pdi.add_tlv(pfcp_ie::F_TEID, &[0x06]);
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        pdr.add_pdr_id(0x60);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 10);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u32(pfcp_ie::FAR_ID, 1);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr.build());
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8
        );
        assert_eq!(
            failed_rule_id(&resp),
            Some(vec![0x00, 0x00, 0x60]),
            "#1154: the Failed Rule ID names PDR 0x60"
        );
        let resp = modify_creating_pdr(&smf, addr, upf_seid, 8, 0x65, &[0x07]).await;
        let f = created_f_teid(&resp, 0x65);
        assert_eq!((f.ipv4, f.ipv6), (Some(node_v4), None));

        server.set_n3_ipv6(Some(n3_v6));
        for (seq, pdr_id, flags, want) in [
            (4, 0x61, vec![0x06], (None, Some(n3_v6))), // CH + V6
            (5, 0x62, vec![0x07], (Some(node_v4), Some(n3_v6))), // CH + V4 + V6
            (6, 0x63, vec![0x05], (Some(node_v4), None)), // CH + V4
            (7, 0x64, vec![0x00, 0, 0, 0, 0], (Some(node_v4), None)), // zero TEID, no flag
        ] {
            let resp = modify_creating_pdr(&smf, addr, upf_seid, seq, pdr_id, &flags).await;
            let f = created_f_teid(&resp, pdr_id);
            assert_ne!(f.teid, 0);
            assert_eq!((f.ipv4, f.ipv6), want, "F-TEID request flags {flags:02x?}");
            assert_eq!((f.v4, f.v6), (want.0.is_some(), want.1.is_some()));
        }
    }

    /// #985: the establishment path assigns the same way: CH+V6 with an IPv6 GTP-U
    /// socket gives an IPv6-only local F-TEID in the Created PDR, and without one the
    /// establishment is refused (#985 review).
    #[tokio::test]
    async fn an_establishment_chosen_f_teid_can_be_ipv6() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let n3_v6: Ipv6Addr = "2001:db8::986".parse().unwrap();
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let refused = exchange(
            &smf,
            addr,
            &encode_pfcp(50, Some(0), 2, &establishment_ch_v6()),
        )
        .await;
        assert_eq!(
            response_cause(&refused),
            PfcpCause::RuleCreationModificationFailure as u8,
            "no IPv6 N3 address: CH+V6 cannot be met"
        );
        assert_eq!(
            failed_rule_id(&refused),
            Some(vec![0x00, 0x00, 0x01]),
            "#1154: the Failed Rule ID names PDR 1"
        );
        let (_, body) = ParsedPfcpHeader::parse(&refused).unwrap();
        assert!(
            ParsedIe::find_ie(&ParsedIe::parse_all(body), pfcp_ie::OFFENDING_IE).is_none(),
            "no Offending IE for a rule failure (Table 7.5.3.1-1)"
        );
        assert!(
            server.sessions.read().await.is_empty(),
            "no session was created"
        );
        server.set_n3_ipv6(Some(n3_v6));
        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(50, Some(0), 3, &establishment_ch_v6()),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let f = created_f_teid(&resp, 1);
        assert_ne!(f.teid, 0);
        assert_eq!((f.ipv4, f.ipv6), (None, Some(n3_v6)));
    }

    /// A Session Establishment Request with one Access PDR whose F-TEID is CH+V6.
    fn establishment_ch_v6() -> Vec<u8> {
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0);
        pdi.add_tlv(pfcp_ie::F_TEID, &[0x06]); // CH + V6
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        pdr.add_pdr_id(1);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 100);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u32(pfcp_ie::FAR_ID, 1);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x4986,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr.build());
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.build()
    }

    /// #985 (TS 29.244 §7.5.8.4, §8.2.3): an Error Indication about an IPv6 gNB is
    /// reported with a V6 Remote F-TEID carrying that address, not an F-TEID with no
    /// address at all. IPv4 still gives a V4 one.
    #[tokio::test]
    async fn an_error_indication_report_carries_an_ipv6_remote_f_teid() {
        let (server, smf, _addr, _rx, _dp, upf_seid) = established_session().await;
        let gnb6: Ipv6Addr = "2001:db8::7".parse().unwrap();
        for (peer, want) in [
            (IpAddr::V6(gnb6), (None, Some(gnb6))),
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                (Some(Ipv4Addr::new(192, 0, 2, 7)), None),
            ),
        ] {
            server
                .send_error_indication_report(upf_seid, 0x4242, 0xABCD, Some(peer))
                .await
                .unwrap();
            let mut buf = [0u8; 2048];
            let (n, _) =
                tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                    .await
                    .expect("a Session Report Request")
                    .unwrap();
            assert_eq!(buf[1], pfcp_type::SESSION_REPORT_REQUEST);
            let (_, body) = ParsedPfcpHeader::parse(&buf[..n]).unwrap();
            let ies = ParsedIe::parse_all(body);
            let eir = ParsedIe::find_ie(&ies, 99).expect("Error Indication Report");
            let inner = ParsedIe::parse_all(&eir.value);
            let f = crate::n4_build::ParsedFTeid::parse(
                &ParsedIe::find_ie(&inner, pfcp_ie::F_TEID).unwrap().value,
            )
            .unwrap();
            assert_eq!(f.teid, 0xABCD);
            assert_eq!((f.ipv4, f.ipv6), want, "peer {peer}");
        }
    }

    /// A Core-source PDR and a FAR forwarding to the access side toward `ohc`
    /// (`(teid, addr)`); `None` for a buffering FAR.
    ///
    /// A dedicated bearer's PDR (any id but 2) carries its TFT's downlink filter as an
    /// SDF Filter; PDR 2 is the catch-all default downlink.
    fn downlink_rule(pdr_id: u16, far_id: u32, ohc: Option<(u32, [u8; 4])>) -> Vec<u8> {
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 1); // Core
        if pdr_id != 2 {
            let fd = b"permit out 17 from 198.51.100.7 5004 to assigned";
            let mut sdf = vec![0x01, 0x00];
            sdf.extend_from_slice(&(fd.len() as u16).to_be_bytes());
            sdf.extend_from_slice(fd);
            pdi.add_tlv(pfcp_ie::SDF_FILTER, &sdf);
        }
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        pdr.add_pdr_id(pdr_id);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 50);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u32(pfcp_ie::FAR_ID, far_id);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr.build());
        b.add_tlv(pfcp_ie::CREATE_FAR, &forwarding_far(far_id, ohc, false));
        b.build()
    }

    /// A FAR (or Update FAR, `update`) body forwarding to Access toward `ohc`, or
    /// buffering when `ohc` is `None`.
    fn forwarding_far(far_id: u32, ohc: Option<(u32, [u8; 4])>, update: bool) -> Vec<u8> {
        let mut far = crate::n4_build::PfcpMessageBuilder::new();
        far.add_u32(pfcp_ie::FAR_ID, far_id);
        match ohc {
            Some((teid, addr)) => {
                let mut fp = crate::n4_build::PfcpMessageBuilder::new();
                fp.add_u8(pfcp_ie::DESTINATION_INTERFACE, 0);
                let mut v = vec![0x01, 0x00];
                v.extend_from_slice(&teid.to_be_bytes());
                v.extend_from_slice(&addr);
                fp.add_tlv(pfcp_ie::OUTER_HEADER_CREATION, &v);
                far.add_u16(pfcp_ie::APPLY_ACTION, 0x02);
                far.add_tlv(
                    if update {
                        pfcp_ie::UPDATE_FORWARDING_PARAMETERS
                    } else {
                        pfcp_ie::FORWARDING_PARAMETERS
                    },
                    &fp.build(),
                );
            }
            None => {
                far.add_u16(pfcp_ie::APPLY_ACTION, 0x04);
            }
        }
        far.build()
    }

    /// #619: a dedicated EPS bearer's downlink tunnel is its own.
    ///
    /// The PGW-C creates the bearer's downlink as a Core PDR with a FAR of its own
    /// toward the SGW's per-bearer S5/S8-U tunnel (TS 23.401 §5.4.1). That must not
    /// move the session's downlink tunnel (FAR 2); a later move of the session's
    /// tunnel must not overwrite it; and an Update FAR moving the dedicated tunnel
    /// moves it alone. Before #619 the first two did: the default bearer's downlink
    /// went into the dedicated bearer's tunnel, and then the dedicated bearer's into
    /// the default's.
    #[tokio::test]
    async fn a_second_downlink_tunnel_keeps_its_endpoint_across_a_move() {
        const DEFAULT: (u32, [u8; 4]) = (0x0000_0A0A, [127, 58, 3, 1]);
        const DEDICATED: (u32, [u8; 4]) = (0x0606_0606, [127, 58, 3, 6]);
        const MOVED: (u32, [u8; 4]) = (0x0000_0C0C, [127, 58, 3, 12]);
        const DEDICATED_MOVED: (u32, [u8; 4]) = (0x0707_0707, [127, 58, 3, 7]);
        let (server, smf, addr, mut rx, dp, upf_seid) = established_session().await;
        let far = |id: u32| {
            dp.sessions
                .find_by_seid(upf_seid)
                .and_then(|s| s.fars.read().unwrap().get(&id).cloned())
                .map(|f| (f.ohc_teid, f.ohc_addr.map(|a| a.to_string())))
        };
        let at =
            |t: (u32, [u8; 4])| Some((Some(t.0), Some(std::net::Ipv4Addr::from(t.1).to_string())));
        let mut seq = 3;
        let mut modify = |body: Vec<u8>| {
            seq += 1;
            encode_pfcp(52, Some(upf_seid), seq, &body)
        };
        let update_far = |id: u32, ohc: Option<(u32, [u8; 4])>| {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(pfcp_ie::UPDATE_FAR, &forwarding_far(id, ohc, true));
            b.build()
        };
        let session_tunnel = || async { server.sessions.read().await[&upf_seid].dl_teid };

        // The default bearer's downlink, then the session's tunnel set by Update FAR
        // 2 -- what smfd's Create Session does.
        let resp = exchange(&smf, addr, &modify(downlink_rule(2, 2, None))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        let resp = exchange(&smf, addr, &modify(update_far(2, Some(DEFAULT)))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert_eq!(far(2), at(DEFAULT));

        // The dedicated bearer's downlink.
        let resp = exchange(
            &smf,
            addr,
            &modify(downlink_rule(0x81, 0x81, Some(DEDICATED))),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert_eq!(
            far(2),
            at(DEFAULT),
            "the default bearer's downlink must stay on its own tunnel"
        );
        assert_eq!(far(0x81), at(DEDICATED));
        assert_eq!(
            session_tunnel().await,
            DEFAULT.0,
            "creating a second tunnel does not move the session's"
        );

        // The session's tunnel moves.
        let resp = exchange(&smf, addr, &modify(update_far(2, Some(MOVED)))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert_eq!(far(2), at(MOVED));
        assert_eq!(
            far(0x81),
            at(DEDICATED),
            "the move must not overwrite the dedicated bearer's tunnel"
        );

        // The dedicated tunnel moves alone.
        let resp = exchange(&smf, addr, &modify(update_far(0x81, Some(DEDICATED_MOVED)))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert_eq!(far(0x81), at(DEDICATED_MOVED));
        assert_eq!(
            far(2),
            at(MOVED),
            "moving the dedicated tunnel moves it alone"
        );
        assert_eq!(session_tunnel().await, MOVED.0);

        // The dedicated FAR buffers (no endpoint), then the session's tunnel moves
        // back: the buffering FAR is not handed the default bearer's endpoint.
        let resp = exchange(&smf, addr, &modify(update_far(0x81, None))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        let resp = exchange(&smf, addr, &modify(update_far(2, Some(DEFAULT)))).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert_eq!(far(2), at(DEFAULT));
        assert_eq!(
            far(0x81),
            Some((None, None)),
            "a buffering dedicated FAR keeps no endpoint across the session's move"
        );
    }

    /// #619 review: a session ESTABLISHED with a dedicated bearer's downlink already in it
    /// (a restoration, or an SMF that sends the whole rule set at once) keeps that
    /// tunnel's endpoint when the session's tunnel moves, as one a modification created
    /// does.
    #[tokio::test]
    async fn a_second_downlink_tunnel_in_the_establishment_keeps_its_endpoint() {
        // Either order on the wire (#1170 review: the dedicated FAR after FAR 2 used to
        // become the session's tunnel).
        for dedicated_first in [true, false] {
            establishment_with_a_second_downlink_tunnel(dedicated_first).await;
        }
    }

    async fn establishment_with_a_second_downlink_tunnel(dedicated_first: bool) {
        const DEFAULT: (u32, [u8; 4]) = (0x0000_0A0A, [127, 58, 4, 1]);
        const DEDICATED: (u32, [u8; 4]) = (0x0606_0606, [127, 58, 4, 6]);
        const MOVED: (u32, [u8; 4]) = (0x0000_0C0C, [127, 58, 4, 12]);
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
            seid: 0x4343,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr_body(1, 100, 1, 1, 1));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.add_tlv(pfcp_ie::CREATE_QER, &qer_body(1, 5));
        let mut body = b.build();
        if dedicated_first {
            body.extend(downlink_rule(0x81, 0x81, Some(DEDICATED)));
            body.extend(downlink_rule(2, 2, Some(DEFAULT)));
        } else {
            body.extend(downlink_rule(2, 2, Some(DEFAULT)));
            body.extend(downlink_rule(0x81, 0x81, Some(DEDICATED)));
        }
        let resp = exchange(&smf, addr, &encode_pfcp(50, Some(0), 2, &body)).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let upf_seid = server
            .sessions
            .read()
            .await
            .keys()
            .copied()
            .next()
            .expect("the session");
        apply_next(&mut rx, &dp).await;
        let far = |id: u32| {
            dp.sessions
                .find_by_seid(upf_seid)
                .and_then(|s| s.fars.read().unwrap().get(&id).cloned())
                .map(|f| (f.ohc_teid, f.ohc_addr.map(|a| a.to_string())))
        };
        let at = |t: (u32, [u8; 4])| Some((Some(t.0), Some(Ipv4Addr::from(t.1).to_string())));
        assert_eq!(far(0x81), at(DEDICATED));
        assert_eq!(
            server.sessions.read().await[&upf_seid].dl_teid,
            DEFAULT.0,
            "the session's tunnel is the catch-all downlink's (dedicated first: {dedicated_first})"
        );

        let mut m = crate::n4_build::PfcpMessageBuilder::new();
        m.add_tlv(pfcp_ie::UPDATE_FAR, &forwarding_far(2, Some(MOVED), true));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &m.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert_eq!(far(2), at(MOVED));
        assert_eq!(
            far(0x81),
            at(DEDICATED),
            "the move must not overwrite the established dedicated tunnel"
        );
        assert_eq!(
            server.sessions.read().await[&upf_seid].dl_teid,
            MOVED.0,
            "the session's tunnel moved (dedicated first: {dedicated_first})"
        );
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
        // #842 review (TS 29.244 §7.5.4): an IE the Update URR does not carry is
        // UNCHANGED. This used to assert the period was withdrawn -- which is how a
        // quota top-up silently stopped periodic reporting.
        assert_eq!(
            urr.measurement_period_secs(),
            Some(30),
            "a period the update omits is kept"
        );
    }

    /// An Update URR body carrying ONLY a total Volume Quota (§8.2.50).
    fn quota_only_update(id: u32, quota: u64) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u32(pfcp_ie::URR_ID, id);
        let mut v = vec![0x01u8];
        v.extend_from_slice(&quota.to_be_bytes());
        b.add_tlv(crate::n4_build::pfcp_ie::VOLUME_QUOTA, &v);
        b.build()
    }

    /// #842 review MAJOR 3 (TS 29.244 §7.5.4): a THRESHOLD-only Update URR leaves the
    /// quota -- and an exhausted subscriber's latch -- alone; a QUOTA-only one leaves
    /// the thresholds and the Measurement Period alone (and re-grants). Before, both
    /// went through the Create setters, so each deleted what it did not carry.
    #[tokio::test]
    async fn an_update_urr_changes_only_the_ies_it_carries() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;
        let urr = urr1(&dp, upf_seid);
        urr.set_quotas(Some(1000), None, None, None);
        assert_eq!(
            urr.record(1500, true),
            crate::data_plane::UrrOutcome::QuotaJustExhausted
        );

        // Threshold-only.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_URR, &{
            let mut u = crate::n4_build::PfcpMessageBuilder::new();
            u.add_u32(pfcp_ie::URR_ID, 1);
            let mut v = vec![0x01u8];
            v.extend_from_slice(&5_000_000u64.to_be_bytes());
            u.add_tlv(pfcp_ie::VOLUME_THRESHOLD, &v);
            u.build()
        });
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert_eq!(urr.volume_threshold_total(), Some(5_000_000));
        assert_eq!(
            urr.volume_quota_total(),
            Some(1000),
            "the quota is unchanged"
        );
        assert!(urr.is_quota_exhausted(), "and the subscriber stays gated");
        assert_eq!(urr.measurement_period_secs(), Some(30));

        // Quota-only: a top-up.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_URR, &quota_only_update(1, 1_000_000));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 4, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert_eq!(urr.volume_quota_total(), Some(1_000_000));
        assert!(!urr.is_quota_exhausted(), "a quota top-up re-grants");
        assert_eq!(
            urr.volume_threshold_total(),
            Some(5_000_000),
            "thresholds kept"
        );
        assert_eq!(urr.time_threshold_secs(), Some(60));
        assert_eq!(urr.measurement_period_secs(), Some(30), "period kept");
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

    /// #1741: a REJECTED modification carrying a Remove URR takes nothing. The
    /// rejection here is an Update FAR naming a rule the session does not hold, which
    /// is judged inside the critical section, after the Remove URR was parsed.
    /// Before the fix the residual was taken (its counters reset) while the response
    /// carried no Usage Report, so the 2000 B were reported nowhere; and the URR's ID
    /// was dropped from the session's rule set although the request was refused.
    #[tokio::test]
    async fn a_rejected_remove_urr_keeps_its_counters_and_its_rule_1741() {
        let (server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            let urrs = session.urrs.read().unwrap();
            let urr = urrs.get(&1).unwrap();
            urr.record(1500, true);
            urr.record(500, false);
        }

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::REMOVE_URR, &remove_body_u32(pfcp_ie::URR_ID, 1));
        b.add_tlv(pfcp_ie::REMOVE_FAR, &remove_body_u32(pfcp_ie::FAR_ID, 1));
        b.add_tlv(pfcp_ie::UPDATE_FAR, &far_body(77, 0x02));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8
        );
        assert_eq!(
            usage_reports_in(&resp),
            vec![],
            "a rejection carries no report"
        );
        {
            let sessions = server.sessions.read().await;
            let rules = &sessions[&upf_seid].rules;
            assert!(
                rules.urr_ids.contains(&1) && rules.far_ids.contains(&1),
                "a rejected modification writes no rule ID (TS 29.244 §6.3.3)"
            );
        }

        // The full usage is still there for the next query.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 4, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            usage_reports_in(&resp),
            vec![(1, 2000)],
            "the rejected Remove URR must not have reset URR 1's counters"
        );
    }

    /// #1741: likewise a rejected QAURR resets nothing.
    #[tokio::test]
    async fn a_rejected_qaurr_keeps_the_counters_1741() {
        let (_server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            let urrs = session.urrs.read().unwrap();
            urrs.get(&1).unwrap().record(900, true);
        }

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
        b.add_tlv(pfcp_ie::UPDATE_FAR, &far_body(77, 0x02));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8
        );

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 4, &b.build())).await;
        assert_eq!(
            usage_reports_in(&resp),
            vec![(1, 900)],
            "the rejected QAURR must not have reset URR 1's counters"
        );
    }

    /// #1741: the "no such rule" checks see the rule set the message would leave, so
    /// an Update of a rule the same message creates is still accepted, and one the
    /// same message removes is still refused.
    #[tokio::test]
    async fn an_update_is_judged_against_the_message_own_removes_and_creates_1741() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(5, 0x02));
        b.add_tlv(pfcp_ie::UPDATE_FAR, &far_body(5, 0x02));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert!(server.sessions.read().await[&upf_seid]
            .rules
            .far_ids
            .contains(&5));

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::REMOVE_FAR, &remove_body_u32(pfcp_ie::FAR_ID, 5));
        b.add_tlv(pfcp_ie::UPDATE_FAR, &far_body(5, 0x02));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 4, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8
        );
        assert!(
            server.sessions.read().await[&upf_seid]
                .rules
                .far_ids
                .contains(&5),
            "and the refused Remove FAR is not applied"
        );
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
    /// land, so §7.5.5's "Rule creation/modification Failure" is the truthful answer --
    /// and NOTHING is applied, because a response that refused must not be followed by
    /// an event that applies.
    ///
    /// #1154: the response names the rule in a Failed Rule ID (TS 29.244 Table 7.5.5.1-1,
    /// §8.2.80: Rule ID Type in octet 5, then the rule's ID as its own IE codes it), and
    /// carries no Offending IE, which that table keeps for a missing or faulty IE.
    /// Golden bytes, one per rule type.
    #[tokio::test]
    async fn an_update_for_an_absent_rule_is_refused_with_its_failed_rule_id() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;

        #[rustfmt::skip]
        let cases: [(u16, Vec<u8>, &[u8]); 4] = [
            (pfcp_ie::UPDATE_URR, urr_body(4242, Some(1), None, None), &[0x03, 0x00, 0x00, 0x10, 0x92]),
            (pfcp_ie::UPDATE_QER, qer_body(0x0A0B_0C0D, 9), &[0x02, 0x0A, 0x0B, 0x0C, 0x0D]),
            (pfcp_ie::UPDATE_FAR, far_body(77, 0x02), &[0x01, 0x00, 0x00, 0x00, 0x4D]),
            (pfcp_ie::UPDATE_PDR, pdr_body(0x0123, 10, 1, 1, 1), &[0x00, 0x01, 0x23]),
        ];
        for (seq, (ie, body, rule)) in (3u32..).zip(cases) {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(ie, &body);
            let resp = exchange(
                &smf,
                addr,
                &encode_pfcp(52, Some(upf_seid), seq, &b.build()),
            )
            .await;
            let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
            // Cause (19): 73; Failed Rule ID (114).
            let mut expected = vec![0x00, 0x13, 0x00, 0x01, 73, 0x00, 0x72, 0x00];
            expected.push(rule.len() as u8);
            expected.extend_from_slice(rule);
            assert_eq!(body, expected.as_slice(), "Update IE {ie}");
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "a refused modification must emit no apply event"
        );
        let session = dp.sessions.find_by_seid(upf_seid).unwrap();
        assert!(!session.urrs.read().unwrap().contains_key(&4242));
    }

    /// #1154: a Failed Rule ID of each type is coded as TS 29.244 §8.2.80 has it.
    #[test]
    fn a_failed_rule_id_is_section_8_2_80_on_the_wire() {
        use crate::n4_build::FailedRule;
        assert_eq!(FailedRule::Pdr(0x0102).encode_value(), [0x00, 0x01, 0x02]);
        assert_eq!(
            FailedRule::Far(0x0102_0304).encode_value(),
            [0x01, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(FailedRule::Qer(5).encode_value(), [0x02, 0, 0, 0, 5]);
        assert_eq!(FailedRule::Urr(6).encode_value(), [0x03, 0, 0, 0, 6]);
        assert_eq!(FailedRule::Bar(7).encode_value(), [0x04, 7]);
        assert_eq!(
            crate::n4_build::build_rule_failure_response(FailedRule::Pdr(0x60)),
            [0x00, 0x13, 0x00, 0x01, 73, 0x00, 0x72, 0x00, 0x03, 0x00, 0x00, 0x60]
        );
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
        // #1598: a missing URR ID in a Session Modification's (Conditional) Create
        // URR is "Conditional IE missing" naming the URR ID, not cause 69.
        assert_eq!(response_cause(&resp), PfcpCause::ConditionalIeMissing as u8);
        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        let off = ParsedIe::find_ie(&ies, pfcp_ie::OFFENDING_IE).unwrap();
        assert_eq!(
            u16::from_be_bytes([off.value[0], off.value[1]]),
            pfcp_ie::URR_ID
        );
    }

    /// `body` with every IE of `ie_type` removed: a rule IE without its rule ID.
    fn without_ie_1598(body: &[u8], ie_type: u16) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        for ie in ParsedIe::parse_all(body) {
            if ie.ie_type != ie_type {
                b.add_tlv(ie.ie_type, &ie.value);
            }
        }
        b.build()
    }

    /// (Cause, Offending IE) of a response.
    fn cause_and_offending_1598(resp: &[u8]) -> (u8, Option<u16>) {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        (
            response_cause(resp),
            ParsedIe::find_ie(&ies, pfcp_ie::OFFENDING_IE)
                .map(|ie| u16::from_be_bytes([ie.value[0], ie.value[1]])),
        )
    }

    /// **#1598, Session Modification.** Every rule IE of a Session Modification
    /// Request is Conditional (TS 29.244 Table 7.5.4.1-1), so a rule ID missing
    /// from a Create, Update, Remove or Query IE is viewed as a missing
    /// Conditional IE (§7.2.2.4.1, 29244-k00.txt:14248-14274) and answered cause
    /// 67 with the rule ID's own type as the Offending IE (§7.6.6). It used to be
    /// 69 (Create, Update) or 66 with the grouped IE (Remove, Query).
    #[tokio::test]
    async fn a_modification_rule_without_its_id_is_conditional_ie_missing_1598() {
        let (_server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        let cases: Vec<(u16, Vec<u8>, u16)> = vec![
            (
                pfcp_ie::CREATE_PDR,
                pdr_body(7, 50, 1, 1, 1),
                pfcp_ie::PDR_ID,
            ),
            (
                pfcp_ie::UPDATE_PDR,
                pdr_body(1, 50, 1, 1, 1),
                pfcp_ie::PDR_ID,
            ),
            (pfcp_ie::CREATE_FAR, far_body(7, 0x02), pfcp_ie::FAR_ID),
            (pfcp_ie::UPDATE_FAR, far_body(1, 0x02), pfcp_ie::FAR_ID),
            (
                pfcp_ie::CREATE_URR,
                urr_body(7, None, Some(10), None),
                pfcp_ie::URR_ID,
            ),
            (
                pfcp_ie::UPDATE_URR,
                urr_body(1, None, Some(10), None),
                pfcp_ie::URR_ID,
            ),
            (pfcp_ie::CREATE_QER, qer_body(7, 9), pfcp_ie::QER_ID),
            (pfcp_ie::UPDATE_QER, qer_body(1, 9), pfcp_ie::QER_ID),
            (pfcp_ie::REMOVE_PDR, remove_body_u16(1), pfcp_ie::PDR_ID),
            (
                pfcp_ie::REMOVE_FAR,
                remove_body_u32(pfcp_ie::FAR_ID, 1),
                pfcp_ie::FAR_ID,
            ),
            (
                pfcp_ie::REMOVE_URR,
                remove_body_u32(pfcp_ie::URR_ID, 1),
                pfcp_ie::URR_ID,
            ),
            (
                pfcp_ie::REMOVE_QER,
                remove_body_u32(pfcp_ie::QER_ID, 1),
                pfcp_ie::QER_ID,
            ),
            (
                pfcp_ie::QUERY_URR,
                remove_body_u32(pfcp_ie::URR_ID, 1),
                pfcp_ie::URR_ID,
            ),
        ];
        for (seq, (grouped, valid, id)) in (10u32..).zip(cases) {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(grouped, &without_ie_1598(&valid, id));
            let resp = exchange(
                &smf,
                addr,
                &encode_pfcp(52, Some(upf_seid), seq, &b.build()),
            )
            .await;
            assert_eq!(
                cause_and_offending_1598(&resp),
                (PfcpCause::ConditionalIeMissing as u8, Some(id)),
                "IE {grouped} without IE {id}"
            );
        }
    }

    /// **#1598**: a Remove IE whose rule ID is present but too short is a
    /// semantically incorrect value, cause 69 with the Remove IE (§7.6.8), the
    /// same answer a short Create QER ID gets. Only an absent ID is cause 67.
    #[tokio::test]
    async fn a_short_remove_rule_id_is_mandatory_ie_incorrect_1598() {
        let (_server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        for (seq, (grouped, id, short)) in (10u32..).zip([
            (pfcp_ie::REMOVE_PDR, pfcp_ie::PDR_ID, vec![0u8]),
            (pfcp_ie::REMOVE_FAR, pfcp_ie::FAR_ID, vec![0u8, 1]),
            (pfcp_ie::REMOVE_URR, pfcp_ie::URR_ID, vec![0u8, 0, 1]),
            (pfcp_ie::REMOVE_QER, pfcp_ie::QER_ID, vec![1u8]),
            (pfcp_ie::QUERY_URR, pfcp_ie::URR_ID, vec![]),
        ]) {
            let mut body = crate::n4_build::PfcpMessageBuilder::new();
            body.add_tlv(id, &short);
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(grouped, &body.build());
            let resp = exchange(
                &smf,
                addr,
                &encode_pfcp(52, Some(upf_seid), seq, &b.build()),
            )
            .await;
            assert_eq!(
                cause_and_offending_1598(&resp),
                (PfcpCause::MandatoryIeIncorrect as u8, Some(grouped)),
                "IE {grouped} with a {}-octet IE {id}",
                short.len()
            );
        }
    }

    /// A Session Establishment Request of PDR 1 (UL, TEID 0x1234), FAR 1 and
    /// `extra` rule IEs, with `pdr` and `far` as the Create PDR and FAR bodies,
    /// through the real handler (#1598). Returns the response.
    async fn establish_1598(
        smf: &UdpSocket,
        addr: SocketAddr,
        seid: u64,
        pdr: &[u8],
        far: &[u8],
        extra: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, pdr);
        b.add_tlv(pfcp_ie::CREATE_FAR, far);
        for (ie_type, body) in extra {
            b.add_tlv(*ie_type, body);
        }
        exchange(smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await
    }

    /// **#1598, Session Establishment.** Create PDR and Create FAR are Mandatory
    /// in a Session Establishment Request and Create URR and Create QER
    /// Conditional (Table 7.5.2.1-1), so a missing PDR ID or FAR ID is cause 66
    /// and a missing URR ID or QER ID cause 67, each with the ID's own type as
    /// the Offending IE (§7.2.2.4.1, §7.6.6). No session is created.
    #[tokio::test]
    async fn an_establishment_rule_without_its_id_is_66_or_67_1598() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let pdr = pdr_body(1, 100, 1, 1, 1);
        let far = far_body(1, 0x02);
        let qer = qer_body(1, 9);
        let urr = urr_body(1, None, Some(10), None);
        let full = || {
            vec![
                (pfcp_ie::CREATE_QER, qer.clone()),
                (pfcp_ie::CREATE_URR, urr.clone()),
            ]
        };
        let strip = |extra: Vec<(u16, Vec<u8>)>, grouped: u16, id: u16| {
            extra
                .into_iter()
                .map(|(t, b)| {
                    if t == grouped {
                        (t, without_ie_1598(&b, id))
                    } else {
                        (t, b)
                    }
                })
                .collect::<Vec<_>>()
        };
        let cases = [
            (
                without_ie_1598(&pdr, pfcp_ie::PDR_ID),
                far.clone(),
                full(),
                PfcpCause::MandatoryIeMissing,
                pfcp_ie::PDR_ID,
            ),
            (
                pdr.clone(),
                without_ie_1598(&far, pfcp_ie::FAR_ID),
                full(),
                PfcpCause::MandatoryIeMissing,
                pfcp_ie::FAR_ID,
            ),
            (
                pdr.clone(),
                far.clone(),
                strip(full(), pfcp_ie::CREATE_URR, pfcp_ie::URR_ID),
                PfcpCause::ConditionalIeMissing,
                pfcp_ie::URR_ID,
            ),
            (
                pdr.clone(),
                far.clone(),
                strip(full(), pfcp_ie::CREATE_QER, pfcp_ie::QER_ID),
                PfcpCause::ConditionalIeMissing,
                pfcp_ie::QER_ID,
            ),
        ];
        for (seid, (pdr, far, extra, cause, id)) in (0x1598_0000u64..).zip(cases) {
            let resp = establish_1598(&smf, addr, seid, &pdr, &far, &extra).await;
            assert_eq!(
                cause_and_offending_1598(&resp),
                (cause as u8, Some(id)),
                "missing IE {id}"
            );
            assert!(
                server.sessions.read().await.is_empty(),
                "a rejected establishment creates no session (missing IE {id})"
            );
        }
        // The same message with every ID present is accepted.
        let resp = establish_1598(&smf, addr, 0x1598_ffff, &pdr, &far, &full()).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// `body` with its `id_ie` replaced by one whose value is `short` (#1605).
    fn with_short_id_1605(body: &[u8], id_ie: u16, short: &[u8]) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(id_ie, short);
        for ie in ParsedIe::parse_all(body) {
            if ie.ie_type != id_ie {
                b.add_tlv(ie.ie_type, &ie.value);
            }
        }
        b.build()
    }

    /// Every too-short value of a rule ID IE of `full` octets: 0 to `full - 1`
    /// octets, each a non-zero byte so a truncated read could not pass as id 0.
    fn short_ids_1605(full: usize) -> Vec<Vec<u8>> {
        (0..full).map(|n| vec![0x01; n]).collect()
    }

    /// **#1605, Session Establishment.** A Create PDR whose PDR ID is shorter
    /// than 2 octets (TS 29.244 §8.2.36), or a Create FAR or Create URR whose
    /// FAR ID or URR ID is shorter than 4 octets (§8.2.74, §8.2.54), carries a
    /// semantically invalid value: the request is refused with "Mandatory IE
    /// incorrect" and the grouped IE as the Offending IE (§7.6.8), as a short
    /// QER ID already is. It used to be accepted with the rule installed as
    /// rule 0. No session is created.
    #[tokio::test]
    async fn an_establishment_rule_with_a_short_id_is_mandatory_ie_incorrect_1605() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let pdr = pdr_body(1, 100, 1, 1, 1);
        let far = far_body(1, 0x02);
        let urr = urr_body(1, None, Some(10), None);
        let mut cases: Vec<(Vec<u8>, Vec<u8>, Vec<(u16, Vec<u8>)>, u16)> = Vec::new();
        for short in short_ids_1605(2) {
            cases.push((
                with_short_id_1605(&pdr, pfcp_ie::PDR_ID, &short),
                far.clone(),
                vec![(pfcp_ie::CREATE_URR, urr.clone())],
                pfcp_ie::CREATE_PDR,
            ));
        }
        for short in short_ids_1605(4) {
            cases.push((
                pdr.clone(),
                with_short_id_1605(&far, pfcp_ie::FAR_ID, &short),
                vec![(pfcp_ie::CREATE_URR, urr.clone())],
                pfcp_ie::CREATE_FAR,
            ));
            cases.push((
                pdr.clone(),
                far.clone(),
                vec![(
                    pfcp_ie::CREATE_URR,
                    with_short_id_1605(&urr, pfcp_ie::URR_ID, &short),
                )],
                pfcp_ie::CREATE_URR,
            ));
        }
        for (seid, (pdr, far, extra, grouped)) in (0x1605_0000u64..).zip(cases) {
            let resp = establish_1598(&smf, addr, seid, &pdr, &far, &extra).await;
            assert_eq!(
                cause_and_offending_1598(&resp),
                (PfcpCause::MandatoryIeIncorrect as u8, Some(grouped)),
                "IE {grouped} with a short rule ID (seid {seid:#x})"
            );
            assert!(
                server.sessions.read().await.is_empty(),
                "a rejected establishment creates no session (IE {grouped})"
            );
        }
        // The same message with full-length IDs is accepted.
        let resp = establish_1598(
            &smf,
            addr,
            0x1605_ffff,
            &pdr,
            &far,
            &[(pfcp_ie::CREATE_URR, urr.clone())],
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// **#1605, Session Modification.** A Create or Update PDR, FAR or URR with
    /// a too-short rule ID is refused with "Mandatory IE incorrect" naming the
    /// grouped IE (TS 29.244 §7.6.8), and the session gains no rule 0. It used
    /// to be accepted, the Create installing rule 0 and the Update rewriting
    /// whatever rule 0 was.
    #[tokio::test]
    async fn a_modification_rule_with_a_short_id_is_mandatory_ie_incorrect_1605() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        let mut cases: Vec<(u16, Vec<u8>)> = Vec::new();
        for short in short_ids_1605(2) {
            for grouped in [pfcp_ie::CREATE_PDR, pfcp_ie::UPDATE_PDR] {
                let body = pdr_body(7, 50, 1, 1, 1);
                cases.push((grouped, with_short_id_1605(&body, pfcp_ie::PDR_ID, &short)));
            }
        }
        for short in short_ids_1605(4) {
            for grouped in [pfcp_ie::CREATE_FAR, pfcp_ie::UPDATE_FAR] {
                let body = far_body(7, 0x02);
                cases.push((grouped, with_short_id_1605(&body, pfcp_ie::FAR_ID, &short)));
            }
            for grouped in [pfcp_ie::CREATE_URR, pfcp_ie::UPDATE_URR] {
                let body = urr_body(7, None, Some(10), None);
                cases.push((grouped, with_short_id_1605(&body, pfcp_ie::URR_ID, &short)));
            }
        }
        for (seq, (grouped, body)) in (10u32..).zip(cases) {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(grouped, &body);
            let resp = exchange(
                &smf,
                addr,
                &encode_pfcp(52, Some(upf_seid), seq, &b.build()),
            )
            .await;
            assert_eq!(
                cause_and_offending_1598(&resp),
                (PfcpCause::MandatoryIeIncorrect as u8, Some(grouped)),
                "IE {grouped} with a short rule ID (seq {seq})"
            );
            let sessions = server.sessions.read().await;
            let rules = &sessions.get(&upf_seid).expect("session kept").rules;
            assert_eq!(
                (
                    rules.pdr_ids.iter().copied().collect::<Vec<_>>(),
                    rules.far_ids.iter().copied().collect::<Vec<_>>(),
                    rules.urr_ids.iter().copied().collect::<Vec<_>>(),
                ),
                (vec![1], vec![1], vec![1]),
                "the refused IE {grouped} added or changed no rule"
            );
        }
    }

    /// Every way a Create/Update PDR body `body` can carry a too-short reference
    /// (#1616): its Precedence, FAR ID, URR ID or QER ID (each 4 octets, TS
    /// 29.244 §8.2.11, §8.2.74, §8.2.54, §8.2.75) cut to 0..3 octets, and a
    /// second URR ID or QER ID that is short after a full first one.
    fn short_pdr_references_1616(body: &[u8]) -> Vec<(&'static str, usize, Vec<u8>)> {
        let mut out = Vec::new();
        for short in short_ids_1605(4) {
            for (name, ie) in [
                ("Precedence", pfcp_ie::PRECEDENCE),
                ("FAR ID", pfcp_ie::FAR_ID),
                ("URR ID", pfcp_ie::URR_ID),
                ("QER ID", pfcp_ie::QER_ID),
            ] {
                out.push((name, short.len(), with_short_id_1605(body, ie, &short)));
            }
            for (name, ie) in [
                ("second URR ID", pfcp_ie::URR_ID),
                ("second QER ID", pfcp_ie::QER_ID),
            ] {
                let mut b = crate::n4_build::PfcpMessageBuilder::new();
                b.add_tlv(ie, &short);
                let mut v = body.to_vec();
                v.extend_from_slice(&b.build());
                out.push((name, short.len(), v));
            }
        }
        out
    }

    /// **#1616, Session Establishment.** A Create PDR whose Precedence, FAR ID,
    /// URR ID or QER ID is shorter than 4 octets carries a semantically invalid
    /// value: the request is refused with "Mandatory IE incorrect" and the
    /// Create PDR as the Offending IE (TS 29.244 §7.6.8), and no session is
    /// created. The short IE used to be skipped, so the PDR was installed with
    /// no FAR, without the URR or QER, or at precedence 0, and accepted.
    #[tokio::test]
    async fn an_establishment_pdr_with_a_short_reference_is_mandatory_ie_incorrect_1616() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let pdr = pdr_body(1, 100, 1, 1, 1);
        let far = far_body(1, 0x02);
        let urr = vec![(pfcp_ie::CREATE_URR, urr_body(1, None, Some(10), None))];
        let cases = short_pdr_references_1616(&pdr);
        assert_eq!(cases.len(), 24);
        for (seid, (name, _, short_pdr)) in (0x1616_0000u64..).zip(cases) {
            let resp = establish_1598(&smf, addr, seid, &short_pdr, &far, &urr).await;
            assert_eq!(
                cause_and_offending_1598(&resp),
                (
                    PfcpCause::MandatoryIeIncorrect as u8,
                    Some(pfcp_ie::CREATE_PDR)
                ),
                "Create PDR with a short {name} (seid {seid:#x})"
            );
            assert!(
                server.sessions.read().await.is_empty(),
                "a rejected establishment creates no session (short {name})"
            );
        }
        // The same message with full-length references is accepted.
        let resp = establish_1598(&smf, addr, 0x1616_ffff, &pdr, &far, &urr).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// **#1673.** An Update PDR changes only the IEs it carries, and a
    /// null-length URR ID, QER ID or Outer Header Removal removes that IE (TS
    /// 29.244 §5.6.3, 29244-k00.txt:6060-6095; Table 7.5.4.2-1). A null FAR ID
    /// is refused instead (#1672): see `a_null_far_id_or_an_empty_pdi_in_an_update_pdr_is_refused_1672`. Each
    /// step goes through the real handler and the production event consumer,
    /// and the PDR the data plane then holds is asserted:
    /// - a precedence-only update keeps the FAR, URR, QER and PDI (it used to
    ///   replace the PDR with one holding only the new precedence);
    /// - an update without Precedence keeps it (it used to become 0);
    /// - a null QER ID, URR ID or Outer Header Removal clears it (#1656
    ///   answered these 69 Mandatory IE incorrect);
    /// - a null URR ID beside a full one leaves just the full one: the list is
    ///   "all the URR IDs to be associated";
    /// - a PDI replaces the stored one.
    #[tokio::test]
    async fn an_update_pdr_changes_only_what_it_carries_1673() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;
        let pdr1 = || {
            dp.sessions
                .find_by_seid(upf_seid)
                .expect("session")
                .pdrs
                .read()
                .unwrap()
                .iter()
                .find(|p| p.pdr_id == 1)
                .cloned()
                .expect("PDR 1 kept")
        };
        let mut seq = 10u32;
        let mut update = |ies: &[(u16, Vec<u8>)]| {
            let mut body = crate::n4_build::PfcpMessageBuilder::new();
            body.add_pdr_id(1);
            for (t, v) in ies {
                body.add_tlv(*t, v);
            }
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(pfcp_ie::UPDATE_PDR, &body.build());
            seq += 1;
            encode_pfcp(52, Some(upf_seid), seq, &b.build())
        };
        let before = pdr1();
        assert_eq!(
            (
                before.precedence,
                before.far_id,
                before.qer_ids.to_vec(),
                before.urr_ids.clone()
            ),
            (100, Some(1), vec![1], vec![1])
        );

        let step = |what: &str, resp: Vec<u8>| {
            assert_eq!(
                response_cause(&resp),
                PfcpCause::RequestAccepted as u8,
                "{what}"
            );
        };
        let resp = exchange(
            &smf,
            addr,
            &update(&[(pfcp_ie::PRECEDENCE, 7u32.to_be_bytes().to_vec())]),
        )
        .await;
        step("precedence only", resp);
        apply_next(&mut rx, &dp).await;
        let p = pdr1();
        assert_eq!(
            (
                p.precedence,
                p.far_id,
                p.qer_ids.to_vec(),
                p.urr_ids.clone(),
                p.source_interface
            ),
            (7, Some(1), vec![1], vec![1], before.source_interface),
            "a precedence-only update keeps the rest"
        );

        let resp = exchange(
            &smf,
            addr,
            &update(&[(pfcp_ie::OUTER_HEADER_REMOVAL, vec![0])]),
        )
        .await;
        step("OHR set", resp);
        apply_next(&mut rx, &dp).await;
        assert_eq!(
            (pdr1().outer_header_removal, pdr1().precedence),
            (Some(0), 7)
        );

        for (what, ie) in [
            ("null QER ID", pfcp_ie::QER_ID),
            ("null URR ID", pfcp_ie::URR_ID),
            ("null OHR", pfcp_ie::OUTER_HEADER_REMOVAL),
        ] {
            let resp = exchange(&smf, addr, &update(&[(ie, Vec::new())])).await;
            step(what, resp);
            apply_next(&mut rx, &dp).await;
        }
        let p = pdr1();
        assert_eq!(
            (
                p.precedence,
                p.far_id,
                p.qer_ids.to_vec(),
                p.urr_ids.clone(),
                p.outer_header_removal
            ),
            (7, Some(1), Vec::new(), Vec::new(), None),
            "each null IE removed only itself"
        );

        let resp = exchange(
            &smf,
            addr,
            &update(&[
                (pfcp_ie::URR_ID, Vec::new()),
                (pfcp_ie::URR_ID, 1u32.to_be_bytes().to_vec()),
                (pfcp_ie::QER_ID, 1u32.to_be_bytes().to_vec()),
                (pfcp_ie::FAR_ID, 1u32.to_be_bytes().to_vec()),
            ]),
        )
        .await;
        step("re-associate", resp);
        apply_next(&mut rx, &dp).await;
        let p = pdr1();
        assert_eq!(
            (p.far_id, p.qer_ids.to_vec(), p.urr_ids.clone()),
            (Some(1), vec![1], vec![1])
        );

        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 1); // Core
        let resp = exchange(&smf, addr, &update(&[(pfcp_ie::PDI, pdi.build())])).await;
        step("PDI", resp);
        apply_next(&mut rx, &dp).await;
        let p = pdr1();
        assert_eq!(
            (p.source_interface, p.precedence, p.far_id),
            (1, 7, Some(1)),
            "the PDI is replaced, the rest kept"
        );
    }

    /// **#1672.** In an Update PDR, a null FAR ID and an empty PDI are refused
    /// with "Mandatory IE incorrect" naming the Update PDR, and the stored PDR
    /// keeps its FAR and PDI.
    ///
    /// TS 29.244 Table 7.5.2.2-1 makes the FAR ID mandatory in a PDR unless
    /// Activate Predefined Rules supplies a FAR or a MAR ID is present, and upfd
    /// supports neither. Removing it would leave a PDR the table does not allow,
    /// one with no forwarding rule, so the null value is semantically invalid
    /// (§7.6.8). §5.6.3's null-length removal names only the URR ID and QER ID
    /// of an Update PDR. An empty PDI has no Source Interface to match on.
    #[tokio::test]
    async fn a_null_far_id_or_an_empty_pdi_in_an_update_pdr_is_refused_1672() {
        let (_server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        for (seq, (what, ie)) in (20u32..).zip([
            ("null FAR ID", pfcp_ie::FAR_ID),
            ("empty PDI", pfcp_ie::PDI),
        ]) {
            let mut body = crate::n4_build::PfcpMessageBuilder::new();
            body.add_pdr_id(1);
            body.add_tlv(ie, &[]);
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(pfcp_ie::UPDATE_PDR, &body.build());
            let resp = exchange(
                &smf,
                addr,
                &encode_pfcp(52, Some(upf_seid), seq, &b.build()),
            )
            .await;
            assert_eq!(
                cause_and_offending_1598(&resp),
                (
                    PfcpCause::MandatoryIeIncorrect as u8,
                    Some(pfcp_ie::UPDATE_PDR)
                ),
                "{what}"
            );
        }
        let session = dp.sessions.find_by_seid(upf_seid).expect("session");
        let pdrs = session.pdrs.read().unwrap();
        let p = pdrs.iter().find(|p| p.pdr_id == 1).expect("PDR 1");
        assert_eq!((p.far_id, p.source_interface), (Some(1), 0));
    }

    /// Establish, through the real N4 handler, the #1475 session (UL PDR 1 on
    /// TEID 0x1234, FAR 1 FORW) whose PDR lists `qer_ids` in that order, with
    /// the QERs `qers`; apply it to `dp` (#1672).
    async fn establish_with_qers_1672(
        smf: &UdpSocket,
        addr: SocketAddr,
        rx: &mut mpsc::Receiver<PfcpSessionEvent>,
        dp: &crate::data_plane::DataPlane,
        qer_ids: &[u32],
        qers: &[Vec<u8>],
    ) {
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, 0);
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
        let mut pdr = crate::n4_build::PfcpMessageBuilder::new();
        pdr.add_pdr_id(1);
        pdr.add_u32(pfcp_ie::PRECEDENCE, 100);
        pdr.add_tlv(pfcp_ie::PDI, &pdi.build());
        pdr.add_u32(pfcp_ie::FAR_ID, 1);
        for id in qer_ids {
            pdr.add_u32(pfcp_ie::QER_ID, *id);
        }
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x1672,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr.build());
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        for q in qers {
            b.add_tlv(pfcp_ie::CREATE_QER, q);
        }
        let resp = exchange(smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(rx, dp).await;
    }

    /// **#1672, TS 29.244 Table 7.5.2.2-1 and §5.4.1.** A PDR lists a QoS
    /// flow's QER (QER 1: QFI 9, gates open, no MBR) and the session-AMBR QER
    /// (QER 2), in that order, and every QER is enforced on its traffic. upfd
    /// kept only the first QER ID, so the session-AMBR QER was never applied:
    /// - QER 2's UL gate CLOSED drops every uplink packet as qer_gate, and
    ///   opening it with an Update QER lets them through;
    /// - QER 2's 1 kbit/s UL MBR (a 1500 B bucket) passes the first 3 of 10
    ///   back-to-back 500 B packets and drops the rest, where QER 1 alone would
    ///   pass all 10.
    #[tokio::test]
    async fn every_qer_of_a_pdr_is_enforced_session_ambr_and_flow_1672() {
        use crate::data_plane::DropReason;
        let (_server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let tun = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("/dev/null stands in for the TUN");
        let flow = qer_body_1478(1, Some(0x00), None, None, Some(9));
        // Gate Status (§8.2.7): UL gate in bits 3-4, 1 = CLOSED.
        let ambr_closed = qer_body_1478(
            2,
            Some(0x04),
            Some(&rates_1478(1_000_000, 1_000_000)),
            None,
            None,
        );
        establish_with_qers_1672(&smf, addr, &mut rx, &dp, &[1, 2], &[flow, ambr_closed]).await;
        let session = dp.sessions.find_by_ul_teid(0x1234).expect("held");
        assert_eq!(
            session.pdrs.read().unwrap()[0].qer_ids.to_vec(),
            vec![1, 2],
            "the PDR keeps every QER ID, in order"
        );

        let (drops, _) = offer_ul_1475(&dp, &tun, 200, 5, Pace1475::Flat).await;
        assert_eq!(drops, 5, "the session-AMBR QER's closed UL gate drops all");

        let open = qer_body_1478(2, Some(0x00), None, None, None);
        let resp = update_qer_1478(&smf, addr, &mut rx, &dp, &open).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let (drops, _) = offer_ul_1475(&dp, &tun, 200, 5, Pace1475::Flat).await;
        assert_eq!(drops, 0, "both gates open: all pass");

        let slow = qer_body_1478(2, None, Some(&rates_1478(1, 1_000_000)), None, None);
        let resp = update_qer_1478(&smf, addr, &mut rx, &dp, &slow).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let (drops, _) = offer_ul_1475(&dp, &tun, 500, 10, Pace1475::Flat).await;
        assert!(
            (6..=8).contains(&drops),
            "a 1 kbit/s session AMBR (1500 B bucket) passes about 3 of 10 x 500 B: {drops} dropped"
        );
        assert_eq!(
            dp.stats
                .dropped_packets
                .load(std::sync::atomic::Ordering::Relaxed),
            dp.stats.drops(DropReason::QerGate),
            "every drop is qer_gate: {}",
            dp.stats.summary()
        );
    }

    /// **#1672.** An Update PDR's QER IDs replace the PDR's whole QER list
    /// (Table 7.5.4.2-1: "the list of all the QER IDs to be associated to the
    /// PDR"), and a null one clears it (§5.6.3).
    #[tokio::test]
    async fn an_update_pdr_replaces_the_qer_list_1672() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;
        let qers = |dp: &crate::data_plane::DataPlane| {
            dp.sessions
                .find_by_seid(upf_seid)
                .expect("session")
                .pdrs
                .read()
                .unwrap()
                .iter()
                .find(|p| p.pdr_id == 1)
                .expect("PDR 1")
                .qer_ids
                .to_vec()
        };
        assert_eq!(qers(&dp), vec![1]);
        let mut seq = 30u32;
        for (ids, want) in [
            (vec![Some(1u32), Some(2)], vec![1, 2]),
            (vec![Some(2)], vec![2]),
            (vec![None], vec![]),
        ] {
            let mut body = crate::n4_build::PfcpMessageBuilder::new();
            body.add_pdr_id(1);
            for id in &ids {
                match id {
                    Some(id) => {
                        body.add_u32(pfcp_ie::QER_ID, *id);
                    }
                    None => {
                        body.add_tlv(pfcp_ie::QER_ID, &[]);
                    }
                }
            }
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(pfcp_ie::UPDATE_PDR, &body.build());
            seq += 1;
            let resp = exchange(
                &smf,
                addr,
                &encode_pfcp(52, Some(upf_seid), seq, &b.build()),
            )
            .await;
            assert_eq!(
                response_cause(&resp),
                PfcpCause::RequestAccepted as u8,
                "{ids:?}"
            );
            apply_next(&mut rx, &dp).await;
            assert_eq!(qers(&dp), want, "after {ids:?}");
        }
    }

    // ------------------------------------------------------------------
    // #1682: an Update PDR's PDI moves the PDR's F-TEID and the session's UE IP.
    // ------------------------------------------------------------------

    /// A G-PDU on `teid` carrying a 100-byte UDP packet from `src` (#1682).
    fn ul_gpdu_1682(teid: u32, src: Ipv4Addr) -> Vec<u8> {
        let len = 100usize;
        let mut ip = vec![0u8; len];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17; // UDP
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let csum = crate::data_plane::ipv4_header_checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&csum.to_be_bytes());
        ip[20..22].copy_from_slice(&1234u16.to_be_bytes());
        ip[22..24].copy_from_slice(&53u16.to_be_bytes());
        ip[24..26].copy_from_slice(&((len - 20) as u16).to_be_bytes());
        crate::data_plane::encapsulate_dl_gpdu(&ip, teid, None)
    }

    /// A PDI body: Source Interface, then the F-TEID IE value `f_teid` (a CP-chosen
    /// TEID, or a CHOOSE request), then the UE IP address (#1682).
    fn pdi_1682(source: u8, f_teid: Option<Vec<u8>>, ue_ip: Option<Ipv4Addr>) -> Vec<u8> {
        let mut pdi = crate::n4_build::PfcpMessageBuilder::new();
        pdi.add_u8(pfcp_ie::SOURCE_INTERFACE, source);
        if let Some(v) = f_teid {
            pdi.add_tlv(pfcp_ie::F_TEID, &v);
        }
        if let Some(ip) = ue_ip {
            pdi.add_ue_ip_address(
                &crate::n4_build::UeIpAddress {
                    ipv4: Some(ip),
                    ipv6: None,
                    ipv6_prefix_len: 0,
                },
                source == 1,
            );
        }
        pdi.build()
    }

    /// The F-TEID IE value (§8.2.3) of a CP-chosen IPv4 F-TEID.
    fn f_teid_1682(teid: u32) -> Vec<u8> {
        let mut v = vec![0x01];
        v.extend_from_slice(&teid.to_be_bytes());
        v.extend_from_slice(&[127, 0, 0, 4]);
        v
    }

    /// Establish, through the real N4 handler, a session with an uplink PDR 1
    /// (Access, F-TEID `teid`, UE IP `ue`, FAR 1 FORW) and a downlink PDR 2 (Core,
    /// UE IP `ue`, FAR 2), apply it to `dp`, and return its UPF SEID (#1682).
    async fn establish_1682(
        smf: &UdpSocket,
        addr: SocketAddr,
        rx: &mut mpsc::Receiver<PfcpSessionEvent>,
        dp: &crate::data_plane::DataPlane,
        cp_seid: u64,
        teid: u32,
        ue: Ipv4Addr,
    ) -> u64 {
        let mut ul = crate::n4_build::PfcpMessageBuilder::new();
        ul.add_pdr_id(1);
        ul.add_u32(pfcp_ie::PRECEDENCE, 100);
        ul.add_tlv(
            pfcp_ie::PDI,
            &pdi_1682(0, Some(f_teid_1682(teid)), Some(ue)),
        );
        ul.add_u32(pfcp_ie::FAR_ID, 1);
        let mut dl = crate::n4_build::PfcpMessageBuilder::new();
        dl.add_pdr_id(2);
        dl.add_u32(pfcp_ie::PRECEDENCE, 200);
        dl.add_tlv(pfcp_ie::PDI, &pdi_1682(1, None, Some(ue)));
        dl.add_u32(pfcp_ie::FAR_ID, 2);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: cp_seid,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &ul.build());
        b.add_tlv(pfcp_ie::CREATE_PDR, &dl.build());
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(2, 0x02));
        let resp = exchange(smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(rx, dp).await;
        dp.sessions
            .find_by_ul_teid(teid)
            .expect("the establishment's TEID routes to the session")
            .upf_seid
    }

    /// A Session Modification carrying one Update PDR for PDR 1 with the PDI `pdi`.
    async fn update_pdi_1682(
        smf: &UdpSocket,
        addr: SocketAddr,
        upf_seid: u64,
        seq: u32,
        pdi: Vec<u8>,
    ) -> Vec<u8> {
        let mut body = crate::n4_build::PfcpMessageBuilder::new();
        body.add_pdr_id(1);
        body.add_tlv(pfcp_ie::PDI, &pdi);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_PDR, &body.build());
        exchange(smf, addr, &encode_pfcp(52, Some(upf_seid), seq, &b.build())).await
    }

    /// Offer one G-PDU; true when the session wrote it to the TUN.
    async fn forwarded_1682(
        dp: &crate::data_plane::DataPlane,
        tun: &std::fs::File,
        upf_seid: u64,
        teid: u32,
        src: Ipv4Addr,
    ) -> bool {
        let session = dp.sessions.find_by_seid(upf_seid).expect("session");
        let before = session.ul_packets.load(Ordering::Relaxed);
        let gnb: SocketAddr = "127.0.0.1:2152".parse().unwrap();
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(tun);
        dp.handle_uplink_packet(&ul_gpdu_1682(teid, src), gnb, fd)
            .await;
        session.ul_packets.load(Ordering::Relaxed) == before + 1
    }

    fn dev_null_tun() -> std::fs::File {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("/dev/null stands in for the TUN")
    }

    /// **#1682, TS 29.244 Table 7.5.4.2-1.** An Update PDR whose PDI names a new
    /// Local F-TEID moves the PDR onto it: G-PDUs on the new TEID are forwarded,
    /// G-PDUs on the old one are dropped as `no_pdr_match` (the UE-IP fallback
    /// still finds the session, but no PDR detects on that tunnel any more), and
    /// the old TEID no longer routes to the session (§5.5.3: freed once no PDR
    /// uses it). The session's other PDR, its FARs and its UE IP are untouched.
    /// upfd replaced the PDR's PDI fields and left the tunnel map alone, so the
    /// old TEID kept forwarding and the new one routed nowhere.
    #[tokio::test]
    async fn an_update_pdr_moves_the_uplink_pdr_to_its_new_f_teid_1682() {
        use crate::data_plane::DropReason;
        let (_server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let tun = dev_null_tun();
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let ue = Ipv4Addr::new(10, 45, 0, 42);
        let seid = establish_1682(&smf, addr, &mut rx, &dp, 0x1682, 0x1234, ue).await;
        assert!(
            forwarded_1682(&dp, &tun, seid, 0x1234, ue).await,
            "control: the establishment's tunnel forwards"
        );
        let pdr2_before = {
            let s = dp.sessions.find_by_seid(seid).unwrap();
            let p = s.pdrs.read().unwrap();
            let p2 = p.iter().find(|p| p.pdr_id == 2).cloned().unwrap();
            (p2.precedence, p2.far_id, p2.source_interface)
        };

        let resp = update_pdi_1682(
            &smf,
            addr,
            seid,
            10,
            pdi_1682(0, Some(f_teid_1682(0x5678)), Some(ue)),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        assert_eq!(
            dp.sessions.find_by_ul_teid(0x5678).map(|s| s.upf_seid),
            Some(seid),
            "the new TEID routes to the session"
        );
        assert!(
            forwarded_1682(&dp, &tun, seid, 0x5678, ue).await,
            "a G-PDU on the new TEID is forwarded"
        );
        let no_match = dp.stats.drops(DropReason::NoPdrMatch);
        assert!(
            !forwarded_1682(&dp, &tun, seid, 0x1234, ue).await,
            "a G-PDU on the old TEID is not forwarded"
        );
        assert_eq!(
            dp.stats.drops(DropReason::NoPdrMatch),
            no_match + 1,
            "it is dropped because no PDR detects on the old tunnel: {}",
            dp.stats.summary()
        );
        assert!(
            dp.sessions
                .find_by_ul_teid(0x1234)
                .is_none_or(|s| s.upf_seid != seid),
            "the old TEID is released"
        );

        {
            let s = dp.sessions.find_by_seid(seid).unwrap();
            let pdrs = s.pdrs.read().unwrap();
            let p2 = pdrs.iter().find(|p| p.pdr_id == 2).expect("PDR 2 kept");
            assert_eq!(
                (p2.precedence, p2.far_id, p2.source_interface),
                pdr2_before,
                "the session's other PDR is untouched"
            );
            assert_eq!(pdrs.len(), 2);
            assert_eq!(s.ue_ipv4(), Some(ue));
            assert_eq!(
                dp.sessions.find_by_ue_ip(ue).map(|s| s.upf_seid),
                Some(seid)
            );
        }

        // A second move releases the tunnel the first one bound.
        let resp = update_pdi_1682(
            &smf,
            addr,
            seid,
            11,
            pdi_1682(0, Some(f_teid_1682(0x6789)), Some(ue)),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert!(forwarded_1682(&dp, &tun, seid, 0x6789, ue).await);
        assert!(
            dp.sessions
                .find_by_ul_teid(0x5678)
                .is_none_or(|s| s.upf_seid != seid),
            "the first move's TEID is released by the second"
        );
    }

    /// **#1682, TS 29.244 §5.5.3 and Table 7.5.5.5-1.** An Update PDR whose PDI's
    /// Local F-TEID has CHOOSE set gets a fresh F-TEID: the response carries it in
    /// an Updated PDR (IE 256) naming the PDR, and the data plane detects on it.
    /// upfd allocated nothing and answered a bare acceptance.
    #[tokio::test]
    async fn an_update_pdr_with_choose_gets_an_f_teid_in_an_updated_pdr_1682() {
        let (_server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let tun = dev_null_tun();
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let ue = Ipv4Addr::new(10, 45, 0, 42);
        let seid = establish_1682(&smf, addr, &mut rx, &dp, 0x1682, 0x1234, ue).await;

        // CH | V6 with no IPv6 GTP-U socket cannot be met: refused, as for a
        // Create PDR (#985 review).
        let resp =
            update_pdi_1682(&smf, addr, seid, 9, pdi_1682(0, Some(vec![0x06]), Some(ue))).await;
        assert_eq!(
            (response_cause(&resp), failed_rule_id(&resp)),
            (
                PfcpCause::RuleCreationModificationFailure as u8,
                Some(vec![0x00, 0x00, 0x01])
            ),
            "CH with IPv6 only is refused"
        );

        // F-TEID flags: CH | V4, no TEID or address (§8.2.3).
        let resp = update_pdi_1682(
            &smf,
            addr,
            seid,
            10,
            pdi_1682(0, Some(vec![0x05]), Some(ue)),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let (_, body) = ParsedPfcpHeader::parse(&resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        assert_eq!(
            pfcp_ie::UPDATED_PDR,
            256,
            "TS 29.244 Table 8.1.2-1 (29244-k00.txt:27573)"
        );
        let updated = ParsedIe::find_ie(&ies, pfcp_ie::UPDATED_PDR)
            .expect("an Updated PDR carries the F-TEID the UPF chose");
        let inner = ParsedIe::parse_all(&updated.value);
        assert_eq!(
            ParsedIe::find_ie(&inner, pfcp_ie::PDR_ID).unwrap().value[..],
            [0x00, 0x01]
        );
        let fteid = crate::n4_build::ParsedFTeid::parse(
            &ParsedIe::find_ie(&inner, pfcp_ie::F_TEID).unwrap().value,
        )
        .unwrap();
        assert!(fteid.teid != 0 && fteid.teid != 0x1234 && !fteid.ch);
        assert!(fteid.ipv4.is_some(), "the UPF's GTP-U address");

        apply_next(&mut rx, &dp).await;
        assert_eq!(
            dp.sessions.find_by_ul_teid(fteid.teid).map(|s| s.upf_seid),
            Some(seid),
            "the allocated TEID routes to the session"
        );
        assert!(
            forwarded_1682(&dp, &tun, seid, fteid.teid, ue).await,
            "and the PDR detects on it"
        );
    }

    /// **#1682.** An Update PDR whose PDI's UE IP address is new moves the
    /// session's UE-IP binding: the downlink lookup finds the session on the new
    /// address and not the old, and uplink anti-spoofing (TS 23.501 §5.6.1) now
    /// expects the new source. upfd kept the old address on both.
    #[tokio::test]
    async fn an_update_pdr_moves_the_ue_ip_binding_1682() {
        let (server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let tun = dev_null_tun();
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let (old, new) = (Ipv4Addr::new(10, 45, 0, 42), Ipv4Addr::new(10, 45, 0, 43));
        let seid = establish_1682(&smf, addr, &mut rx, &dp, 0x1682, 0x1234, old).await;

        let resp = update_pdi_1682(
            &smf,
            addr,
            seid,
            10,
            pdi_1682(0, Some(f_teid_1682(0x1234)), Some(new)),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        assert_eq!(
            dp.sessions.find_by_ue_ip(new).map(|s| s.upf_seid),
            Some(seid)
        );
        assert!(
            dp.sessions.find_by_ue_ip(old).is_none(),
            "the old binding is gone"
        );
        assert_eq!(server.sessions.read().await[&seid].ue_ipv4, Some(new));
        assert!(
            forwarded_1682(&dp, &tun, seid, 0x1234, new).await,
            "uplink from the new address is forwarded"
        );
        let spoofed = dp.stats.drops(crate::data_plane::DropReason::Spoofed);
        assert!(!forwarded_1682(&dp, &tun, seid, 0x1234, old).await);
        assert_eq!(
            dp.stats.drops(crate::data_plane::DropReason::Spoofed),
            spoofed + 1,
            "uplink from the old address is spoofed now"
        );
        assert_eq!(
            dp.sessions.find_by_ul_teid(0x1234).map(|s| s.upf_seid),
            Some(seid),
            "the same F-TEID keeps routing"
        );
    }

    /// **#1682.** An Update PDR naming another session's F-TEID or UE IP address is
    /// refused with Rule creation/modification Failure naming the PDR (§7.5.5), and
    /// neither session changes: the other session's keys still route to it. upfd
    /// accepted it, and the TEID or address would have taken the other session's
    /// traffic once the moves were applied.
    #[tokio::test]
    async fn an_update_pdr_taking_another_sessions_key_is_refused_1682() {
        let (server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let (ue_a, ue_b) = (Ipv4Addr::new(10, 45, 0, 42), Ipv4Addr::new(10, 45, 0, 43));
        let a = establish_1682(&smf, addr, &mut rx, &dp, 0xA, 0x1234, ue_a).await;
        let b = establish_1682(&smf, addr, &mut rx, &dp, 0xB, 0x2345, ue_b).await;

        for (seq, what, pdi) in [
            (
                10,
                "A's F-TEID",
                pdi_1682(0, Some(f_teid_1682(0x1234)), Some(ue_b)),
            ),
            (
                11,
                "A's UE IP",
                pdi_1682(0, Some(f_teid_1682(0x2345)), Some(ue_a)),
            ),
        ] {
            let resp = update_pdi_1682(&smf, addr, b, seq, pdi).await;
            assert_eq!(
                (response_cause(&resp), failed_rule_id(&resp)),
                (
                    PfcpCause::RuleCreationModificationFailure as u8,
                    Some(vec![0x00, 0x00, 0x01])
                ),
                "{what}: refused, naming PDR 1"
            );
            assert!(rx.try_recv().is_err(), "{what}: nothing applied");
        }
        assert_eq!(
            dp.sessions.find_by_ul_teid(0x1234).map(|s| s.upf_seid),
            Some(a)
        );
        assert_eq!(dp.sessions.find_by_ue_ip(ue_a).map(|s| s.upf_seid), Some(a));
        assert_eq!(
            dp.sessions.find_by_ul_teid(0x2345).map(|s| s.upf_seid),
            Some(b)
        );
        assert_eq!(dp.sessions.find_by_ue_ip(ue_b).map(|s| s.upf_seid), Some(b));

        {
            let sessions = server.sessions.read().await;
            assert_eq!(
                (
                    sessions[&b].ue_ipv4,
                    sessions[&b].rules.pdr_teids.get(&1).copied()
                ),
                (Some(ue_b), Some(0x2345)),
                "a refused modification records none of its keys"
            );
        }

        // Control: B's own keys, and a free TEID, are accepted.
        let resp = update_pdi_1682(
            &smf,
            addr,
            b,
            12,
            pdi_1682(0, Some(f_teid_1682(0x3456)), Some(ue_b)),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// **#1682 review M1.** A colliding Update PDR refuses the WHOLE modification
    /// at the PFCP layer too (TS 29.244 §6.3.3): the Remove PDR 2, Create PDR 3,
    /// Remove FAR 2 and Update FAR 1 tunnel sent with it change none of B's rule
    /// IDs or its downlink tunnel, matching the data plane, which is untouched. So
    /// B's next Update PDR 2 is accepted, as the data plane still holds PDR 2.
    ///
    /// REVERT-VERIFIED: with the bookkeeping written before the collision is
    /// noted (as at 10b7a6ff), PDR 2 is gone from `rules.pdr_ids` while the data
    /// plane still holds it, and the follow-up Update PDR 2 is refused.
    #[tokio::test]
    async fn a_colliding_update_pdr_applies_nothing_at_the_pfcp_layer_1682() {
        let (server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let (ue_a, ue_b) = (Ipv4Addr::new(10, 45, 0, 42), Ipv4Addr::new(10, 45, 0, 43));
        let _a = establish_1682(&smf, addr, &mut rx, &dp, 0xA, 0x1234, ue_a).await;
        let b = establish_1682(&smf, addr, &mut rx, &dp, 0xB, 0x2345, ue_b).await;
        let before = {
            let s = server.sessions.read().await;
            let r = &s[&b].rules;
            (
                r.pdr_ids.clone(),
                r.far_ids.clone(),
                s[&b].dl_teid,
                s[&b].gnb_addr,
            )
        };

        let mut upd = crate::n4_build::PfcpMessageBuilder::new();
        upd.add_pdr_id(1);
        upd.add_tlv(
            pfcp_ie::PDI,
            &pdi_1682(0, Some(f_teid_1682(0x1234)), Some(ue_b)),
        );
        let mut pdr3 = crate::n4_build::PfcpMessageBuilder::new();
        pdr3.add_pdr_id(3);
        pdr3.add_u32(pfcp_ie::PRECEDENCE, 300);
        pdr3.add_tlv(pfcp_ie::PDI, &pdi_1682(1, None, Some(ue_b)));
        pdr3.add_u32(pfcp_ie::FAR_ID, 1);
        let mut m = crate::n4_build::PfcpMessageBuilder::new();
        m.add_tlv(pfcp_ie::REMOVE_PDR, &remove_body_u16(2));
        m.add_tlv(pfcp_ie::REMOVE_FAR, &remove_body_u32(pfcp_ie::FAR_ID, 2));
        m.add_tlv(pfcp_ie::CREATE_PDR, &pdr3.build());
        m.add_tlv(
            pfcp_ie::UPDATE_FAR,
            &forwarding_far(1, Some((0x7777, [127, 0, 0, 77])), true),
        );
        m.add_tlv(pfcp_ie::UPDATE_PDR, &upd.build());
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(b), 10, &m.build())).await;
        assert_eq!(
            (response_cause(&resp), failed_rule_id(&resp)),
            (
                PfcpCause::RuleCreationModificationFailure as u8,
                Some(vec![0x00, 0x00, 0x01])
            ),
            "refused, naming the colliding PDR 1"
        );
        assert!(rx.try_recv().is_err(), "nothing reaches the data plane");

        let after = {
            let s = server.sessions.read().await;
            let r = &s[&b].rules;
            (
                r.pdr_ids.clone(),
                r.far_ids.clone(),
                s[&b].dl_teid,
                s[&b].gnb_addr,
            )
        };
        assert_eq!(
            after, before,
            "B's PFCP rule IDs and downlink tunnel unchanged"
        );
        assert!(
            after.0.contains(&2) && !after.0.contains(&3),
            "PDR 2 still held and PDR 3 not created: {:?}",
            after.0
        );

        // The two layers agree, so B can still manage PDR 2.
        let mut upd2 = crate::n4_build::PfcpMessageBuilder::new();
        upd2.add_pdr_id(2);
        upd2.add_u32(pfcp_ie::PRECEDENCE, 210);
        let mut m = crate::n4_build::PfcpMessageBuilder::new();
        m.add_tlv(pfcp_ie::UPDATE_PDR, &upd2.build());
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(b), 11, &m.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RequestAccepted as u8,
            "Update PDR 2 after the refused modification"
        );
    }

    /// **#1682.** The keys follow the move, in both layers: after session A moves
    /// PDR 1 onto TEID 0x5678 and UE IP .44, those are A's, so session C is refused
    /// them; A's old TEID and address are free, so C can be established on them;
    /// and deleting A then leaves C's keys routing to C. Before, deleting A removed
    /// the TEID index entry for A's establishment TEID whoever held it.
    #[tokio::test]
    async fn the_keys_an_update_pdr_frees_and_takes_follow_it_1682() {
        let (_server, smf, addr, mut rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let (ue_a, ue_a2) = (Ipv4Addr::new(10, 45, 0, 42), Ipv4Addr::new(10, 45, 0, 44));
        let a = establish_1682(&smf, addr, &mut rx, &dp, 0xA, 0x1234, ue_a).await;
        let resp = update_pdi_1682(
            &smf,
            addr,
            a,
            10,
            pdi_1682(0, Some(f_teid_1682(0x5678)), Some(ue_a2)),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        let c = establish_1682(&smf, addr, &mut rx, &dp, 0xC, 0x1234, ue_a).await;
        assert_ne!(a, c);
        for (seq, what, pdi) in [
            (
                11,
                "A's new F-TEID",
                pdi_1682(0, Some(f_teid_1682(0x5678)), Some(ue_a)),
            ),
            (
                12,
                "A's new UE IP",
                pdi_1682(0, Some(f_teid_1682(0x1234)), Some(ue_a2)),
            ),
        ] {
            let resp = update_pdi_1682(&smf, addr, c, seq, pdi).await;
            assert_eq!(
                response_cause(&resp),
                PfcpCause::RuleCreationModificationFailure as u8,
                "{what}"
            );
        }

        let resp = exchange(&smf, addr, &encode_pfcp(54, Some(a), 13, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert!(dp.sessions.find_by_seid(a).is_none(), "A is deleted");
        assert_eq!(
            dp.sessions.find_by_ul_teid(0x1234).map(|s| s.upf_seid),
            Some(c),
            "C's TEID survives A's deletion"
        );
        assert_eq!(dp.sessions.find_by_ue_ip(ue_a).map(|s| s.upf_seid), Some(c));
        assert!(
            dp.sessions.find_by_ue_ip(ue_a2).is_none(),
            "A's moved address went with A"
        );
    }

    /// **#1682.** The data plane's own guard: a move onto a TEID or UE IP another
    /// session holds changes nothing, even if the PFCP layer let it through.
    #[test]
    fn the_index_refuses_another_sessions_key_1682() {
        use crate::data_plane::{DataPlaneSession, SessionManager};
        let mgr = SessionManager::new();
        let gnb: SocketAddr = "127.0.0.1:2152".parse().unwrap();
        let (ue_a, ue_b) = (Ipv4Addr::new(10, 45, 0, 42), Ipv4Addr::new(10, 45, 0, 43));
        let a = mgr.add_session(DataPlaneSession::new_empty(
            1,
            1,
            Some(ue_a),
            0x10,
            0,
            gnb,
            None,
            None,
        ));
        let b = mgr.add_session(DataPlaneSession::new_empty(
            2,
            2,
            Some(ue_b),
            0x20,
            0,
            gnb,
            None,
            None,
        ));
        mgr.bind_ul_teid(0x11, 1);
        let pdrs = b.pdrs.read().unwrap().clone();
        assert!(
            !mgr.move_pdr_teid(&b, &pdrs, 1, Some(0x10)),
            "A's establishment TEID"
        );
        assert!(
            !mgr.move_pdr_teid(&b, &pdrs, 1, Some(0x11)),
            "A's modification TEID"
        );
        assert!(!mgr.rebind_ue_ip(&b, ue_a), "A's UE IP");
        assert_eq!(mgr.find_by_ul_teid(0x10).map(|s| s.upf_seid), Some(1));
        assert_eq!(mgr.find_by_ul_teid(0x11).map(|s| s.upf_seid), Some(1));
        assert_eq!(mgr.find_by_ue_ip(ue_a).map(|s| s.upf_seid), Some(1));
        assert_eq!(b.ue_ipv4(), Some(ue_b));
        assert!(b.pdr_teids.read().unwrap().is_empty());
        assert!(
            mgr.move_pdr_teid(&b, &pdrs, 1, Some(0x21)),
            "control: a free TEID"
        );
        let _ = a;
    }

    /// **#1616, Session Modification.** A Create PDR or an Update PDR with a
    /// too-short Precedence, FAR ID, URR ID or QER ID is refused with
    /// "Mandatory IE incorrect" naming the grouped IE (TS 29.244 §7.6.8), and
    /// the session's rules are unchanged. It used to be accepted, the Create
    /// installing a PDR with no FAR (or at precedence 0) and the Update
    /// rewriting PDR 1 the same way.
    ///
    /// In an Update PDR a null (0-octet) URR or QER ID is a removal, not a
    /// short value (TS 29.244 §5.6.3, #1673), so those cases are left out here;
    /// a null FAR ID is still refused (#1672).
    #[tokio::test]
    async fn a_modification_pdr_with_a_short_reference_is_mandatory_ie_incorrect_1616() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        let mut cases: Vec<(u16, &'static str, Vec<u8>)> = Vec::new();
        for (grouped, pdr_id) in [(pfcp_ie::CREATE_PDR, 7), (pfcp_ie::UPDATE_PDR, 1)] {
            for (name, len, body) in short_pdr_references_1616(&pdr_body(pdr_id, 50, 1, 1, 1)) {
                // #1673: in an Update PDR a null URR or QER ID removes it (TS
                // 29.244 §5.6.3); a null Precedence or FAR ID is still refused
                // (#1672).
                if grouped == pfcp_ie::UPDATE_PDR
                    && len == 0
                    && name != "Precedence"
                    && name != "FAR ID"
                {
                    continue;
                }
                cases.push((grouped, name, body));
            }
        }
        assert_eq!(cases.len(), 44);
        for (seq, (grouped, name, body)) in (10u32..).zip(cases) {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(grouped, &body);
            let resp = exchange(
                &smf,
                addr,
                &encode_pfcp(52, Some(upf_seid), seq, &b.build()),
            )
            .await;
            assert_eq!(
                cause_and_offending_1598(&resp),
                (PfcpCause::MandatoryIeIncorrect as u8, Some(grouped)),
                "IE {grouped} with a short {name} (seq {seq})"
            );
            let sessions = server.sessions.read().await;
            let rules = &sessions.get(&upf_seid).expect("session kept").rules;
            assert_eq!(
                rules.pdr_ids.iter().copied().collect::<Vec<_>>(),
                vec![1],
                "the refused IE {grouped} (short {name}) added no PDR"
            );
        }
        // The same Create PDR with full-length references is accepted.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr_body(7, 50, 1, 1, 1));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 99, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// The Usage Report Trigger octets carried by each Usage Report in a Session
    /// Report Request (#80, TS 29.244 §8.2.19).
    ///
    /// Decoded off the wire so the assertion is about the bytes the SMF receives, not
    /// about the Rust value that produced them.
    fn report_triggers_in(pkt: &[u8]) -> Vec<Vec<u8>> {
        let (_, body) = ParsedPfcpHeader::parse(pkt).unwrap();
        let ies = ParsedIe::parse_all(body);
        ParsedIe::find_all_ies(&ies, pfcp_ie::USAGE_REPORT_SRR)
            .into_iter()
            .filter_map(|ur| {
                let inner = ParsedIe::parse_all(&ur.value);
                ParsedIe::find_ie(&inner, pfcp_ie::USAGE_REPORT_TRIGGER).map(|t| t.value.clone())
            })
            .collect()
    }

    /// #80 criterion 6: a PERIODIC usage report is labelled PERIO on the wire, and a
    /// quota exhaustion is labelled VOLQU — neither is labelled VOLTH.
    ///
    /// `send_urr_report` hardcoded `volume_threshold = true` on every report it built,
    /// so a periodic report (reachable since #306 made the harvest fire) already went
    /// out mislabelled as a threshold report, and a quota exhaustion could not be
    /// expressed at all. A CP function reading the trigger to decide whether to top a
    /// subscriber up was being told the wrong thing.
    ///
    /// Driven through the real `send_urr_report` against a real SMF socket, asserting
    /// the decoded trigger octets. Positive assertions on specific bits — the paired
    /// `assert_eq!(.. & 0x02, 0)` for VOLTH is what makes "labelled PERIO" mean "and NOT
    /// labelled VOLTH", which is the actual defect.
    #[tokio::test]
    async fn a_periodic_report_is_labelled_perio_not_volth() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        let _ = addr;

        let entry =
            |trigger: crate::data_plane::UrrReportReason| crate::data_plane::UrrReportEntry {
                upf_seid,
                smf_seid: 0x4242,
                urr_id: 1,
                ur_seqn: 0,
                total_bytes: 1234,
                ul_bytes: 1000,
                dl_bytes: 234,
                total_pkts: 3,
                ul_pkts: 2,
                dl_pkts: 1,
                trigger,
                times: Default::default(),
            };

        // ---- PERIO ----
        server
            .send_urr_report(
                upf_seid,
                0x4242,
                vec![entry(crate::data_plane::UrrReportReason::Periodic)],
            )
            .await
            .expect("the report must be sent");
        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("a Session Report Request must arrive")
                .expect("recv");
        let triggers = report_triggers_in(&buf[..len]);
        assert_eq!(triggers.len(), 1, "one Usage Report");
        assert_eq!(
            triggers[0][0] & 0x01,
            0x01,
            "PERIO must be set on a periodic report (octet 1 bit 1)"
        );
        assert_eq!(
            triggers[0][0] & 0x02,
            0x00,
            "and VOLTH must NOT be: before #80 every report claimed volume_threshold, so \
             a periodic report was indistinguishable from a threshold one"
        );

        // ---- VOLQU ----
        server
            .send_urr_report(
                upf_seid,
                0x4242,
                vec![entry(crate::data_plane::UrrReportReason::VolumeQuota)],
            )
            .await
            .expect("sent");
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("arrives")
                .expect("recv");
        let triggers = report_triggers_in(&buf[..len]);
        assert_eq!(
            triggers[0][1] & 0x01,
            0x01,
            "VOLQU lives in octet 2 bit 1 and is what tells the CP function traffic is \
             being DROPPED rather than merely approaching a limit"
        );
        assert_eq!(triggers[0][0] & 0x02, 0x00, "and not VOLTH");

        // ---- TIMQU ----
        server
            .send_urr_report(
                upf_seid,
                0x4242,
                vec![entry(crate::data_plane::UrrReportReason::TimeQuota)],
            )
            .await
            .expect("sent");
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("arrives")
                .expect("recv");
        assert_eq!(report_triggers_in(&buf[..len])[0][1] & 0x02, 0x02, "TIMQU");

        // ---- TIMTH (#842 review: it used to go out as VOLTH) ----
        server
            .send_urr_report(
                upf_seid,
                0x4242,
                vec![entry(crate::data_plane::UrrReportReason::TimeThreshold)],
            )
            .await
            .expect("sent");
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("arrives")
                .expect("recv");
        let t = &report_triggers_in(&buf[..len])[0];
        assert_eq!(t[0] & 0x04, 0x04, "TIMTH");
        assert_eq!(t[0] & 0x02, 0x00, "and not VOLTH");
    }

    /// The IE types inside the first Usage Report of a Session Report Request.
    fn usage_report_ie_types(req: &[u8]) -> Vec<u16> {
        usage_report_ie_types_in(req, pfcp_ie::USAGE_REPORT_SRR)
    }

    /// The IE types inside the first Usage Report (carrier `ie`) of a PFCP message.
    fn usage_report_ie_types_in(msg: &[u8], ie: u16) -> Vec<u16> {
        let (_, body) = ParsedPfcpHeader::parse(msg).unwrap();
        let ies = ParsedIe::parse_all(body);
        let ur = ParsedIe::find_ie(&ies, ie).expect("a Usage Report");
        ParsedIe::parse_all(&ur.value)
            .iter()
            .map(|ie| ie.ie_type)
            .collect()
    }

    fn assert_time_ies(types: &[u16], what: &str) {
        for (ie, name) in [
            (crate::n4_build::pfcp_ie::START_TIME, "Start Time"),
            (crate::n4_build::pfcp_ie::END_TIME, "End Time"),
            (
                crate::n4_build::pfcp_ie::DURATION_MEASUREMENT,
                "Duration Measurement",
            ),
            (
                crate::n4_build::pfcp_ie::TIME_OF_FIRST_PACKET,
                "Time of First Packet",
            ),
            (
                crate::n4_build::pfcp_ie::TIME_OF_LAST_PACKET,
                "Time of Last Packet",
            ),
        ] {
            assert!(types.contains(&ie), "{what}: {name} missing: {types:?}");
        }
    }

    /// #953 review: the time IEs reach the wire on EVERY send path -- the TERMR in a
    /// Session Deletion Response (the final billing record), the IMMER in a QAURR
    /// Modification Response, and the quota-exhausted Session Report Request.
    #[tokio::test]
    async fn every_report_path_carries_the_time_ies() {
        // QAURR -> Modification Response (IMMER).
        let (_server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        let urr = urr1(&dp, upf_seid);
        urr.set_measure_duration(true);
        urr.record(100, true);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 90, &b.build())).await;
        assert_time_ies(
            &usage_report_ie_types_in(&resp, pfcp_ie::USAGE_REPORT_SMR),
            "IMMER",
        );

        // Deletion -> Deletion Response (TERMR).
        urr.record(100, true);
        let resp = exchange(&smf, addr, &encode_pfcp(54, Some(upf_seid), 91, &[])).await;
        assert_time_ies(
            &usage_report_ie_types_in(&resp, crate::n4_build::pfcp_ie::USAGE_REPORT_SDR),
            "TERMR",
        );

        // Quota exhaustion -> Session Report Request (VOLQU).
        let (server, smf, _addr, _rx, dp, upf_seid) = established_session().await;
        let urr = urr1(&dp, upf_seid);
        urr.set_measure_duration(true);
        urr.set_quotas(Some(100), None, None, None);
        urr.record(500, true);
        server
            .send_quota_exhausted_report(upf_seid, 0x4242, 1)
            .await
            .expect("sent");
        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("arrives")
                .expect("recv");
        assert_time_ies(&usage_report_ie_types(&buf[..len]), "VOLQU");
    }

    /// #818 (Table 7.5.8.3-1) on the wire: a harvested report carries Start Time and End
    /// Time, a Duration Measurement (the fixture's URR measures DURAT), and Time of
    /// First / Last Packet.
    #[tokio::test]
    async fn a_usage_report_carries_its_time_ies_on_the_wire() {
        let (server, smf, _addr, _rx, dp, upf_seid) = established_session().await;
        let urr = urr1(&dp, upf_seid);
        urr.set_measure_duration(true);
        urr.set_reporting(Some(1), None, None, None, None);
        urr.record(300, true);
        assert_eq!(server.send_due_urr_reports(upf_seid, 0x4242).await, Ok(1));
        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("the report reaches the SMF")
                .expect("recv");
        let types = usage_report_ie_types(&buf[..len]);
        for (ie, name) in [
            (crate::n4_build::pfcp_ie::START_TIME, "Start Time"),
            (crate::n4_build::pfcp_ie::END_TIME, "End Time"),
            (
                crate::n4_build::pfcp_ie::DURATION_MEASUREMENT,
                "Duration Measurement",
            ),
            (
                crate::n4_build::pfcp_ie::TIME_OF_FIRST_PACKET,
                "Time of First Packet",
            ),
            (
                crate::n4_build::pfcp_ie::TIME_OF_LAST_PACKET,
                "Time of Last Packet",
            ),
        ] {
            assert!(types.contains(&ie), "{name} missing: {types:?}");
        }
    }

    /// #80 criterion 5 (wire half): the event-driven quota report reaches the SMF with
    /// the VOLQU trigger and the URR's live counters.
    ///
    /// This is the path `UpfReportEvent::QuotaExhausted` drives, i.e. the one that
    /// reports the instant a subscriber is cut off rather than at the next 10-second
    /// harvest (TS 29.244 §5.2.2.2.2).
    ///
    /// #821: it TAKES the URR's usage, as every usage report must (§5.2.2.3.1: "upon
    /// generating a usage report ... reset its ongoing measurement counts"). It used to
    /// read without resetting, so the next harvest re-sent the same 500 B -- asserted
    /// here: the counters are zero after the report and the following harvest has
    /// nothing to send, while the quota latch still gates traffic.
    #[tokio::test]
    async fn the_event_driven_quota_report_carries_volqu_and_takes_the_usage() {
        let (server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        let _ = addr;

        // Provision a quota and exhaust it, so the URR's own state says VOLQU.
        {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            let urrs = session.urrs.read().unwrap();
            let urr = urrs.get(&1).unwrap();
            urr.set_quotas(Some(100), None, None, None);
            assert_eq!(
                urr.record(500, true),
                crate::data_plane::UrrOutcome::QuotaJustExhausted
            );
        }

        server
            .send_quota_exhausted_report(upf_seid, 0x4242, 1)
            .await
            .expect("the quota report must be sent");

        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("a Session Report Request must arrive")
                .expect("recv");
        let triggers = report_triggers_in(&buf[..len]);
        assert_eq!(
            triggers[0][1] & 0x01,
            0x01,
            "the event-driven report must carry VOLQU"
        );
        assert_eq!(
            usage_reports_in_report(&buf[..len]),
            vec![(1, 500)],
            "the quota report carries the measured 500 B"
        );
        // The usage was taken: the next harvest has nothing to re-report.
        let session = dp.sessions.find_by_seid(upf_seid).unwrap();
        let urr = session.urrs.read().unwrap().get(&1).cloned().unwrap();
        assert_eq!(urr.usage().total_bytes(), 0, "the report took the usage");
        assert!(
            dp.collect_urr_reports().is_empty(),
            "the 500 B must not be reported a second time by the harvest"
        );
        assert!(
            urr.is_quota_exhausted(),
            "reporting does not lift the quota"
        );
    }

    fn urr1(
        dp: &crate::data_plane::DataPlane,
        upf_seid: u64,
    ) -> Arc<crate::data_plane::DataPlaneUrr> {
        dp.sessions
            .find_by_seid(upf_seid)
            .unwrap()
            .urrs
            .read()
            .unwrap()
            .get(&1)
            .cloned()
            .unwrap()
    }

    /// #821: a harvest that finds the session already gone from the PFCP table (a
    /// Session Deletion ran first) takes NOTHING, so the deletion's TERMR carries the
    /// usage. Before, the harvest took the usage first and the send then failed with
    /// "session not found", losing it.
    #[tokio::test]
    async fn a_harvest_after_deletion_leaves_the_usage_for_the_termr() {
        let (server, _smf, _addr, _rx, dp, upf_seid) = established_session().await;
        let urr = urr1(&dp, upf_seid);
        urr.set_reporting(Some(1), None, None, None, None);
        urr.record(700, true);
        assert_eq!(dp.due_urr_sessions().len(), 1, "a report is due");

        // The deletion removes the PFCP session before it builds its final reports.
        server.sessions.write().await.remove(&upf_seid);
        assert_eq!(
            server.send_due_urr_reports(upf_seid, 0x4242).await,
            Ok(0),
            "no session, no take"
        );
        assert_eq!(urr.usage().ul_bytes, 700, "the usage is still there");
        let termr = server.collect_final_usage_reports(upf_seid);
        assert_eq!(
            termr
                .iter()
                .map(|r| r.volume_measurement.as_ref().unwrap().total_volume)
                .collect::<Vec<_>>(),
            vec![Some(700)],
            "the TERMR carries the usage the harvest did not take"
        );
        assert_eq!(urr.usage().total_bytes(), 0, "and a final report takes it");
    }

    /// #842 review MAJOR: the quota-exhausted report holds the session table from its
    /// lookup through the take AND the send, so a Session Deletion cannot run between
    /// the take and the send (its TERMR would miss the bytes, and the report would then
    /// go out for a session the SMF had deleted). Deterministic: the send is parked on
    /// the pending-report lock, and while it is parked the table must refuse a writer.
    /// The harvest's send path is checked the same way.
    #[tokio::test]
    async fn reports_hold_the_session_table_from_take_to_send() {
        let (server, smf, _addr, _rx, dp, upf_seid) = established_session().await;
        let urr = urr1(&dp, upf_seid);
        urr.set_quotas(Some(100), None, None, None);
        assert_eq!(
            urr.record(500, true),
            crate::data_plane::UrrOutcome::QuotaJustExhausted
        );

        for path in ["quota", "harvest"] {
            if path == "harvest" {
                urr.set_quotas(None, None, None, None);
                urr.set_reporting(Some(1), None, None, None, None);
                urr.record(300, true);
            }
            let parked = server.pending_reports.lock().await;
            let task = {
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    if path == "quota" {
                        server
                            .send_quota_exhausted_report(upf_seid, 0x4242, 1)
                            .await
                            .map(|_| 1)
                    } else {
                        server.send_due_urr_reports(upf_seid, 0x4242).await
                    }
                })
            };
            // Let the task run up to the parked send.
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            assert_eq!(urr.usage().total_bytes(), 0, "{path}: the usage was taken");
            assert!(
                server.sessions.try_write().is_err(),
                "{path}: a deletion must not get the table between the take and the send"
            );
            drop(parked);
            assert_eq!(task.await.unwrap(), Ok(1), "{path}: sent");
            let mut buf = vec![0u8; 4096];
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                    .await
                    .expect("the report reaches the SMF");
            assert!(
                server.sessions.try_write().is_ok(),
                "{path}: released after the send"
            );
        }
    }

    /// #842 review minor: a failed harvest send restores the usage while the session
    /// table is STILL HELD, so a Session Deletion waiting on the table cannot build its
    /// TERMR in between and miss the restored bytes. Deterministic: the test holds the
    /// table itself and checks the usage is back before it lets go.
    #[tokio::test]
    async fn a_failed_harvest_send_restores_before_the_table_is_released() {
        let (server, _smf, _addr, _rx, dp, upf_seid) = established_session().await;
        let urr = urr1(&dp, upf_seid);
        urr.set_reporting(Some(1), None, None, None, None);
        server
            .sessions
            .write()
            .await
            .get_mut(&upf_seid)
            .unwrap()
            .smf_addr = "[::1]:8805".parse().unwrap();
        urr.record(600, true);

        let table = server.sessions.read().await;
        assert!(server
            .send_due_urr_reports_held(&table, upf_seid, 0x4242)
            .await
            .is_err());
        assert_eq!(
            urr.usage().ul_bytes,
            600,
            "restored while the table is held, so a waiting deletion's TERMR sees it"
        );
        drop(table);
        let termr = server.collect_final_usage_reports(upf_seid);
        assert_eq!(
            termr
                .iter()
                .filter_map(|r| r.volume_measurement.as_ref()?.total_volume)
                .sum::<u64>(),
            600
        );
    }

    /// #821 + #780 re-review: the harvest's send path end to end. A due report is
    /// taken and sent to the SMF while the session is held; a report whose send FAILS
    /// hands its usage back and is counted in `upf_dataplane_urr_reports_restored_total`.
    #[tokio::test]
    async fn the_harvest_send_path_sends_or_restores_and_counts_it() {
        let (server, smf, _addr, _rx, dp, upf_seid) = established_session().await;
        let urr = urr1(&dp, upf_seid);
        urr.set_reporting(Some(1), None, None, None, None);

        urr.record(300, true);
        assert_eq!(server.send_due_urr_reports(upf_seid, 0x4242).await, Ok(1));
        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("the report reaches the SMF")
                .expect("recv");
        assert_eq!(usage_reports_in_report(&buf[..len]), vec![(1, 300)]);
        assert_eq!(urr.usage().total_bytes(), 0);

        // Make the next send fail outright: an IPv6 destination on the IPv4 socket.
        server
            .sessions
            .write()
            .await
            .get_mut(&upf_seid)
            .unwrap()
            .smf_addr = "[::1]:8805".parse().unwrap();
        urr.record(400, false);
        assert!(server.send_due_urr_reports(upf_seid, 0x4242).await.is_err());
        assert_eq!(
            urr.usage().dl_bytes,
            400,
            "a failed send restores the usage"
        );
        assert_eq!(
            dp.stats.urr_reports_restored.load(Ordering::Relaxed),
            1,
            "and is counted"
        );
        assert!(dp
            .stats
            .render_prometheus()
            .contains("upf_dataplane_urr_reports_restored_total 1"));
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

    /// `(urr_id, Query URR Reference)` of each Usage Report in a Session
    /// Modification Response (#1835).
    fn report_references_1835(resp: &[u8]) -> Vec<(u32, Option<u32>)> {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        let mut out: Vec<(u32, Option<u32>)> =
            ParsedIe::find_all_ies(&ParsedIe::parse_all(body), pfcp_ie::USAGE_REPORT_SMR)
                .iter()
                .map(|ur| {
                    let inner = ParsedIe::parse_all(&ur.value);
                    let u32_of = |t: u16| {
                        ParsedIe::find_ie(&inner, t)
                            .map(|ie| u32::from_be_bytes(ie.value[..4].try_into().unwrap()))
                    };
                    (
                        u32_of(pfcp_ie::URR_ID).unwrap(),
                        u32_of(pfcp_ie::QUERY_URR_REFERENCE),
                    )
                })
                .collect();
        out.sort_unstable();
        out
    }

    /// **#1835, TS 29.244 §5.2.2.3.1, Table 7.5.4.1-1 and Table 7.5.5.2-1.** A
    /// Query URR Reference in a Session Modification Request is echoed in every
    /// usage report sent in response to its query, Query URR or QAURR alike, and
    /// in no other: a URR removed by the same message reports TERMR without it, and
    /// a query without a reference carries none. A reference too short for its
    /// value is discarded (§7.6.8). upfd never parsed the IE.
    #[tokio::test]
    async fn query_urr_reference_is_echoed_in_the_reports_it_triggers_1835() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;
        assert_eq!(
            pfcp_ie::QUERY_URR_REFERENCE,
            125,
            "TS 29.244 Table 8.1.2-1 (29244-k00.txt:27160)"
        );
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        for id in [2, 3] {
            b.add_tlv(
                pfcp_ie::CREATE_URR,
                &urr_body(id, Some(1_000_000), None, None),
            );
        }
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        let modify = |seq: u32, build: &dyn Fn(&mut crate::n4_build::PfcpMessageBuilder)| {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            build(&mut b);
            encode_pfcp(52, Some(upf_seid), seq, &b.build())
        };

        // Query URR 2 with a reference, and remove URR 1 in the same message.
        let resp = exchange(
            &smf,
            addr,
            &modify(4, &|b| {
                b.add_tlv(pfcp_ie::QUERY_URR, &remove_body_u32(pfcp_ie::URR_ID, 2));
                b.add_tlv(pfcp_ie::REMOVE_URR, &remove_body_u32(pfcp_ie::URR_ID, 1));
                b.add_u32(pfcp_ie::QUERY_URR_REFERENCE, 0xCAFE_1835);
            }),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            report_references_1835(&resp),
            vec![(1, None), (2, Some(0xCAFE_1835))],
            "the queried URR echoes the reference; the removed one's TERMR does not"
        );
        apply_next(&mut rx, &dp).await;

        // QAURR with a reference: every report answers the query.
        let resp = exchange(
            &smf,
            addr,
            &modify(5, &|b| {
                b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
                b.add_u32(pfcp_ie::QUERY_URR_REFERENCE, 7);
            }),
        )
        .await;
        assert_eq!(
            report_references_1835(&resp),
            vec![(2, Some(7)), (3, Some(7))]
        );

        // No reference, and a reference too short for its value: none echoed.
        for (seq, reference) in [(6, None), (7, Some(&[0x00, 0x01][..]))] {
            let resp = exchange(
                &smf,
                addr,
                &modify(seq, &|b| {
                    b.add_tlv(pfcp_ie::QUERY_URR, &remove_body_u32(pfcp_ie::URR_ID, 3));
                    if let Some(r) = reference {
                        b.add_tlv(pfcp_ie::QUERY_URR_REFERENCE, r);
                    }
                }),
            )
            .await;
            assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
            assert_eq!(report_references_1835(&resp), vec![(3, None)], "seq {seq}");
        }
    }

    /// Query URR (IE 77, TS 29.244 §7.5.4.10): report the URRs the SMF NAMED, and
    /// only those.
    ///
    /// QAURR has been honoured since #306 while this IE was ignored outright, so an
    /// SMF naming individual URRs got a bare acceptance and no reports. A second URR
    /// is installed so the filter has something to exclude -- with one URR in the
    /// session, "report the named one" and "report all" are indistinguishable and the
    /// test would pass against the QAURR path alone.
    #[tokio::test]
    async fn a_query_urr_ie_reports_only_the_named_urrs() {
        let (_server, smf, addr, mut rx, dp, upf_seid) = established_session().await;

        // URR 2 alongside the fixture's URR 1.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(
            pfcp_ie::CREATE_URR,
            &urr_body(2, Some(1_000_000), None, None),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;

        // Distinct volumes, so a report cannot be attributed to the wrong URR.
        {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            let urrs = session.urrs.read().unwrap();
            urrs.get(&1).unwrap().record(111, true);
            urrs.get(&2).unwrap().record(222, true);
        }

        // Query URR 2 only.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::QUERY_URR, &remove_body_u32(pfcp_ie::URR_ID, 2));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            usage_reports_in(&resp),
            vec![(2, 222)],
            "a Query URR naming URR 2 must report URR 2 and NOT URR 1 -- the whole \
             point of the per-URR form over QAURR"
        );

        // #821: the query TOOK URR 2's usage (TS 29.244 §5.2.2.3.1: every usage
        // report resets the measurement), now as in sgwud. The old non-resetting read
        // left the 222 B for the harvest to send again, double-billing it; with the
        // take being atomic (#771) there is no volume the harvest "had not yet
        // reported" left to protect. So a following QAURR carries URR 1's untouched
        // 111 B and NOTHING more for URR 2.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        let mut reports = usage_reports_in(&resp);
        reports.sort_unstable();
        assert_eq!(
            reports,
            vec![(1, 111), (2, 0)],
            "URR 2's 222 B were taken by the first query and must not be reported \
             twice; URR 1 was not queried and keeps its 111 B"
        );
    }

    /// NOTE 3 (`29244-k00.txt:22672`) makes QAURR and the Query URR IE **exclusive**.
    ///
    /// **#1816.** A request carrying both is rejected, Mandatory IE incorrect with
    /// the PFCPSMReq-Flags as the offending IE (§7.6.8), and applies NOTHING
    /// (§6.3.3): its Create FAR is not stored, its Remove URR neither removes nor
    /// reports URR 1, and no counter is reset, so a well-formed retry still
    /// collects the usage. Before, it was answered Request accepted with no Usage
    /// Report, and its other rule changes were applied.
    #[tokio::test]
    async fn qaurr_beside_a_query_urr_is_rejected_and_applies_nothing_1816() {
        let (server, smf, addr, mut rx, dp, upf_seid) = established_session().await;
        {
            let session = dp.sessions.find_by_seid(upf_seid).unwrap();
            let urrs = session.urrs.read().unwrap();
            urrs.get(&1).unwrap().record(444, true);
        }

        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
        b.add_tlv(pfcp_ie::QUERY_URR, &remove_body_u32(pfcp_ie::URR_ID, 1));
        b.add_tlv(pfcp_ie::REMOVE_URR, &remove_body_u32(pfcp_ie::URR_ID, 1));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(7, 0x02));
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 3, &b.build())).await;
        assert_eq!(
            (response_cause(&resp), offending_ie_1478(&resp)),
            (
                PfcpCause::MandatoryIeIncorrect as u8,
                Some(pfcp_ie::PFCPSMREQ_FLAGS)
            ),
            "QAURR beside a Query URR is rejected, naming the PFCPSMReq-Flags"
        );
        assert_eq!(pfcp_ie::PFCPSMREQ_FLAGS, 49, "TS 29.244 Table 8.1.2-1");
        assert!(
            usage_reports_in(&resp).is_empty(),
            "a rejected response carries no Usage Report"
        );
        {
            let sessions = server.sessions.read().await;
            let rules = &sessions.get(&upf_seid).unwrap().rules;
            assert!(!rules.far_ids.contains(&7), "the Create FAR is not applied");
            assert!(rules.urr_ids.contains(&1), "the Remove URR is not applied");
        }
        assert!(
            rx.try_recv().is_err(),
            "the data plane is told nothing of a rejected modification"
        );

        // NOTHING was reset, so a well-formed retry still collects the usage.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::PFCPSMREQ_FLAGS, pfcpsmreq_flags::QAURR);
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 4, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            usage_reports_in(&resp),
            vec![(1, 444)],
            "the refused request must not have consumed URR 1's counters"
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
            RuleIdPresence::Conditional,
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

    /// **#1822 item 1 (#1741, TS 29.244 §6.3.3).** A well-formed TSC Management
    /// Information in a modification REJECTED for another reason (Update FAR 99,
    /// which the session does not hold) is not applied: no bridge is created, an
    /// existing bridge gains no port, and the response echoes no TSC IE. The
    /// malformed-PMIC test above never reaches this gate, because a malformed IE
    /// is not collected at all.
    #[tokio::test]
    async fn a_rejected_modification_applies_no_tsc_management_information_1822() {
        let (server, smf, addr, _rx, _dp, upf_seid) = established_session().await;
        let bridge_ports = |server: &PfcpServer| {
            let sessions = server.sessions.try_read().expect("sessions");
            sessions
                .get(&upf_seid)
                .expect("session")
                .tsn_bridge
                .as_ref()
                .map(|b| {
                    let mut ports: Vec<u32> =
                        b.port_management_containers.keys().copied().collect();
                    ports.sort_unstable();
                    ports
                })
        };
        let rejected = |seq: u32, port: u32| {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_tlv(
                pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST,
                &tsc_ie(Some((&[0x77], port)), None),
            );
            b.add_tlv(pfcp_ie::UPDATE_FAR, &far_body(99, 0x02));
            encode_pfcp(52, Some(upf_seid), seq, &b.build())
        };

        let resp = exchange(&smf, addr, &rejected(20, 8)).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8
        );
        assert_eq!(
            bridge_ports(&server),
            None,
            "no bridge from a rejected message"
        );
        let (_h, payload) = ParsedPfcpHeader::parse(&resp).unwrap();
        assert!(
            ParsedIe::find_all_ies(
                &ParsedIe::parse_all(payload),
                pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_RESPONSE,
            )
            .is_empty(),
            "a rejected response echoes no TSC configuration"
        );

        // With a bridge in place, a rejected message adds no port to it.
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(
            pfcp_ie::TSC_MANAGEMENT_INFORMATION_WITHIN_SESSION_MODIFICATION_REQUEST,
            &tsc_ie(Some((&[0x55], 3)), None),
        );
        let resp = exchange(&smf, addr, &encode_pfcp(52, Some(upf_seid), 21, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(bridge_ports(&server), Some(vec![3]), "control: applied");

        let resp = exchange(&smf, addr, &rejected(22, 9)).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8
        );
        assert_eq!(
            bridge_ports(&server),
            Some(vec![3]),
            "the rejected message's port 9 is not applied"
        );
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

    /// #380: the sync-readable association gauge tracks the REAL wire path.
    ///
    /// This is what `upf_pfcp_associations` renders, and what the EPC bring-up readiness
    /// gate and the PGW-U container healthcheck poll. If the gauge did not follow
    /// Association Setup, a PGW-U whose Sxb association never came up would pass a gate
    /// asserting on a number that never moves — which is the defect class #380 exists to
    /// close, one step further down than the missing container itself.
    ///
    /// Driven entirely over the socket through the real handlers, never through a setter.
    #[tokio::test]
    async fn the_sync_association_gauge_follows_the_wire_association() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let gauge = server.associated_handle();

        // Before Association Setup: honestly zero. A gate polling this fails here rather
        // than passing a UPF that cannot legally carry a session (TS 29.244 §6.2.6.2).
        assert!(
            !gauge.load(Ordering::Relaxed),
            "a fresh server must not report an association"
        );

        let assoc = build_association_setup_request_payload(Some(1));
        let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RequestAccepted as u8,
            "the Association Setup this assertion depends on must succeed"
        );
        assert!(
            gauge.load(Ordering::Relaxed),
            "the gauge must follow a real Association Setup Request"
        );
        // The async authority and its projection must agree.
        assert_eq!(server.is_associated().await, gauge.load(Ordering::Relaxed));

        // And it must come back DOWN. A gauge that only ever counts up would satisfy the
        // assertion above and still be wrong.
        let release = {
            let mut b = crate::n4_build::PfcpMessageBuilder::new();
            b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 1)));
            b.build()
        };
        let resp = exchange(
            &smf,
            addr,
            &encode_pfcp(pfcp_type::ASSOCIATION_RELEASE_REQUEST, None, 2, &release),
        )
        .await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RequestAccepted as u8,
            "the Association Release this assertion depends on must succeed"
        );
        assert!(
            !gauge.load(Ordering::Relaxed),
            "the gauge must clear when the peer releases the association"
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
        let smf_b = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let mut rel = crate::n4_build::PfcpMessageBuilder::new();
        rel.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        let resp = exchange(&smf_b, addr, &encode_pfcp(9, None, 2, &rel.build())).await;

        // B is answered with "No established PFCP Association" (TS 29.244 §8.2.1
        // cause 72: any message but Association Setup / Heartbeat from a peer with no
        // association) ...
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_RELEASE_RESPONSE);
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
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
        let smf_b = UdpSocket::bind("127.0.0.2:0").await.unwrap();
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

    // ── #718: the association is identified by the CP function's Node ID ──

    /// The Node ID every SMF incarnation in these tests advertises. On k8s smfd's
    /// Node ID comes from `SMF_PFCP_ADDR`, so it is the same across pod restarts
    /// while the pod IP is not.
    const SMF_NODE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 9);

    /// The CP SEID every incarnation hands its first session: smfd without durable
    /// state derives it from the SM context reference, which restarts at 1 in every
    /// process (`1 | 0x1000` before the #718 review, `1 << 48 | 1` since). The value
    /// is arbitrary here; what matters is that each incarnation reuses it.
    const FIRST_CP_SEID: u64 = 0x1001;

    /// An Association Setup Request body: Node ID, Recovery Time Stamp and, when
    /// `retain` is `Some`, a PFCP Session Retention Information IE listing those
    /// CP PFCP entities (empty = keep every session).
    fn association_setup(node: Ipv4Addr, rts: u32, retain: Option<&[Ipv4Addr]>) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(node));
        b.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, rts);
        if let Some(entities) = retain {
            let mut inner = crate::n4_build::PfcpMessageBuilder::new();
            for ip in entities {
                let mut v = vec![0x02]; // V4
                v.extend_from_slice(&ip.octets());
                inner.add_tlv(pfcp_ie::CP_PFCP_ENTITY_IP_ADDRESS, &v);
            }
            b.add_tlv(pfcp_ie::PFCP_SESSION_RETENTION_INFORMATION, &inner.build());
        }
        b.build()
    }

    /// Associate `smf` and return the Association Setup Response.
    async fn associate(
        smf: &UdpSocket,
        upf: SocketAddr,
        node: Ipv4Addr,
        rts: u32,
        retain: Option<&[Ipv4Addr]>,
    ) -> Vec<u8> {
        let resp = exchange(
            smf,
            upf,
            &encode_pfcp(5, None, rts, &association_setup(node, rts, retain)),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        resp
    }

    /// Whether an Association Setup Response sets PSREI (TS 29.244 §8.2.134).
    fn psrei(resp: &[u8]) -> bool {
        let (_, body) = ParsedPfcpHeader::parse(resp).unwrap();
        let ies = ParsedIe::parse_all(body);
        ParsedIe::find_ie(&ies, pfcp_ie::PFCPASRSP_FLAGS)
            .and_then(|ie| ie.value.first().copied())
            .is_some_and(|f| f & 0x01 != 0)
    }

    /// Establish one session with CP F-SEID `cp_seid` from `smf`; returns its UPF SEID.
    async fn establish(server: &PfcpServer, smf: &UdpSocket, upf: SocketAddr, cp_seid: u64) -> u64 {
        let before: std::collections::HashSet<u64> =
            server.sessions.read().await.keys().copied().collect();
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(SMF_NODE));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: cp_seid,
            ipv4: Some(SMF_NODE),
            ipv6: None,
        });
        // #1834: each session on its own SMF-named TEID.
        b.add_tlv(
            pfcp_ie::CREATE_PDR,
            &pdr_body_on(1, 100, 1, 1, 1, 0x2000 + cp_seid as u32),
        );
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        let resp = exchange(smf, upf, &encode_pfcp(50, Some(0), 50, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let after = server.sessions.read().await;
        *after
            .keys()
            .find(|k| !before.contains(k))
            .expect("the accepted establishment must be held")
    }

    /// SECURITY: only the associated CP function may modify, delete or establish
    /// sessions, or release the association. A host that is NOT the associated SMF --
    /// here one that guesses a live SEID -- gets "No established PFCP Association"
    /// (cause 72, §5.8.3) and NOTHING is executed; the attempt is counted. Before, a
    /// Session Modification from any source re-pointed a UE's downlink tunnel and a
    /// Deletion tore the session down.
    #[tokio::test]
    async fn session_messages_from_a_host_that_is_not_the_associated_smf_are_refused() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let assoc = build_association_setup_request_payload(Some(100));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let upf_seid = establish(&server, &smf, addr, 0x5ec).await;
        let dl_before = server.sessions.read().await[&upf_seid].dl_teid;
        let before = PFCP_UNAUTHORIZED.load(Ordering::Relaxed);

        let attacker = UdpSocket::bind("127.0.0.66:0").await.unwrap();
        // Modification re-pointing the downlink tunnel.
        let mut far = crate::n4_build::PfcpMessageBuilder::new();
        far.add_u32(pfcp_ie::FAR_ID, 1);
        far.add_u8(pfcp_ie::APPLY_ACTION, 0x02);
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_FAR, &far.build());
        let resp = exchange(
            &attacker,
            addr,
            &encode_pfcp(52, Some(upf_seid), 60, &b.build()),
        )
        .await;
        assert_eq!(resp[1], pfcp_type::SESSION_MODIFICATION_RESPONSE);
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
        assert_eq!(server.sessions.read().await[&upf_seid].dl_teid, dl_before);

        // Deletion: the session survives.
        let resp = exchange(&attacker, addr, &encode_pfcp(54, Some(upf_seid), 61, &[])).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
        assert!(
            server.sessions.read().await.contains_key(&upf_seid),
            "not deleted"
        );

        // Establishment: no session is created for it.
        let n = server.sessions.read().await.len();
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(SMF_NODE));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0xbad,
            ipv4: Some(SMF_NODE),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr_body(1, 100, 1, 1, 1));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        let resp = exchange(&attacker, addr, &encode_pfcp(50, Some(0), 62, &b.build())).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
        assert_eq!(server.sessions.read().await.len(), n, "no session created");

        assert!(
            server.is_associated().await,
            "the real association is untouched"
        );
        assert!(
            PFCP_UNAUTHORIZED.load(Ordering::Relaxed) >= before + 3,
            "counted"
        );

        // The associated SMF itself is still served.
        let resp = exchange(&smf, addr, &encode_pfcp(54, Some(upf_seid), 63, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// SECURITY: a response from a host that is not where our request went is dropped:
    /// it can neither acknowledge our Session Report (so it keeps retransmitting) nor
    /// keep a dead peer looking alive with a Heartbeat Response.
    #[tokio::test]
    async fn responses_from_the_wrong_host_are_dropped() {
        let (server, smf, upf_seid, smf_seid) = server_with_session().await;
        server
            .send_downlink_data_report(upf_seid, smf_seid, 2, Some(9))
            .await
            .unwrap();
        let (hdr, _) = {
            let mut buf = vec![0u8; 2048];
            let (len, _) =
                tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            let (h, _) = ParsedPfcpHeader::parse(&buf[..len]).unwrap();
            (h.sequence_number, ())
        };
        let mut ok = crate::n4_build::PfcpMessageBuilder::new();
        ok.add_u8(pfcp_ie::CAUSE, PfcpCause::RequestAccepted as u8);
        let resp = encode_pfcp(
            pfcp_type::SESSION_REPORT_RESPONSE,
            Some(smf_seid),
            hdr,
            &ok.build(),
        );
        let attacker: SocketAddr = "127.0.0.66:8805".parse().unwrap();
        server.handle_message(&resp, attacker).await.unwrap();
        assert_eq!(
            server.pending_report_count().await,
            1,
            "still waiting for the SMF"
        );

        // The real SMF's answer does clear it.
        server
            .handle_message(&resp, smf.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(server.pending_report_count().await, 0);
    }

    /// Send an Association Setup Request from `sock` and return the response cause.
    async fn setup_cause(sock: &UdpSocket, upf: SocketAddr, node: Ipv4Addr, rts: u32) -> u8 {
        let resp = exchange(
            sock,
            upf,
            &encode_pfcp(5, None, rts, &association_setup(node, rts, None)),
        )
        .await;
        assert_eq!(resp[1], pfcp_type::ASSOCIATION_SETUP_RESPONSE);
        response_cause(&resp)
    }

    /// SECURITY (#968 review, BLOCKER 1): with an allowlist configured, a host that is
    /// not on it cannot associate -- with its own Node ID or with the real SMF's -- and
    /// a refused Setup touches nothing: the association, its sessions and the real
    /// SMF's control of them all survive. Before, one Setup from any host was accepted
    /// (cause 1), replaced the association, deleted every session and left the real
    /// SMF answered with cause 72.
    #[tokio::test]
    async fn with_an_allowlist_a_stranger_cannot_associate_or_take_anything() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        server.set_allowed_peers(PeerAllowlist::parse("127.0.0.1").unwrap());
        let stranger = UdpSocket::bind("127.0.0.66:0").await.unwrap();
        // With no association up, the stranger still cannot be the first to associate.
        assert_eq!(
            setup_cause(&stranger, upf, SMF_NODE, 6).await,
            PfcpCause::RequestRejected as u8
        );
        assert!(!server.is_associated().await);

        associate(&smf, upf, SMF_NODE, 100, None).await;
        let x = establish(&server, &smf, upf, FIRST_CP_SEID).await;
        let before = PFCP_UNAUTHORIZED.load(Ordering::Relaxed);

        for node in [Ipv4Addr::new(127, 0, 0, 66), SMF_NODE] {
            assert_eq!(
                setup_cause(&stranger, upf, node, 7).await,
                PfcpCause::RequestRejected as u8,
                "Node ID {node}: refused with cause 64"
            );
        }
        let smf_addr = smf.local_addr().unwrap();
        assert_eq!(held(&server).await, vec![(x, FIRST_CP_SEID, smf_addr)]);
        assert_eq!(
            server.association.read().await.as_ref().unwrap().peer_addr,
            smf_addr,
            "the association is still the real SMF's"
        );
        assert!(PFCP_UNAUTHORIZED.load(Ordering::Relaxed) >= before + 2);

        // The stranger is still refused session messages; the real SMF is served.
        let resp = exchange(&stranger, upf, &encode_pfcp(54, Some(x), 9, &[])).await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
        let resp = exchange(&smf, upf, &encode_pfcp(54, Some(x), 10, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// #1112: a CP function named by host name whose address the last resolution
    /// predates -- an SMF pod that just restarted -- is admitted on its FIRST Setup:
    /// the Setup is held while the names are re-resolved, off the receive task, and
    /// judged against the fresh answer.
    ///
    /// REVERT-VERIFIED: without the hold the SMF's first Setup is refused with cause
    /// 64 (the name was never resolved here, as on a pod the periodic refresh has not
    /// caught up with).
    #[tokio::test]
    async fn an_unresolved_cp_name_is_re_resolved_before_its_setup_is_refused() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        // `localhost` -> 127.0.0.1, the stand-in SMF's address. Never resolved:
        // no `spawn_host_refresh`.
        let allowed = PeerAllowlist::parse("localhost").unwrap();
        assert!(!allowed.permits(smf.local_addr().unwrap().ip()));
        server.set_allowed_peers(allowed);
        assert_eq!(
            setup_cause(&smf, upf, SMF_NODE, 6).await,
            PfcpCause::RequestAccepted as u8,
            "admitted on its first Setup"
        );
        assert!(server.is_associated().await);

        // A stranger right after: the resolution the SMF's Setup started is fresh, so
        // it is judged by it, without a lookup of its own, and refused.
        let stranger = UdpSocket::bind("127.0.0.66:0").await.unwrap();
        assert_eq!(
            setup_cause(&stranger, upf, Ipv4Addr::new(127, 0, 0, 66), 7).await,
            PfcpCause::RequestRejected as u8,
            "fail-closed: judged by the fresh resolution, and refused"
        );
        assert_eq!(
            server.association.read().await.as_ref().unwrap().peer_addr,
            smf.local_addr().unwrap()
        );
    }

    /// #1112, fail closed: a stranger whose Setup itself starts the re-resolution is
    /// held for it and refused once the fresh answer does not list it.
    #[tokio::test]
    async fn a_stranger_held_for_a_re_resolution_is_refused_after_it() {
        let (server, _smf, upf, _rx) = spawn_test_server().await;
        server.set_allowed_peers(PeerAllowlist::parse("localhost").unwrap());
        let stranger = UdpSocket::bind("127.0.0.66:0").await.unwrap();
        assert_eq!(
            setup_cause(&stranger, upf, Ipv4Addr::new(127, 0, 0, 66), 7).await,
            PfcpCause::RequestRejected as u8
        );
        assert!(!server.is_associated().await);
        assert!(
            server
                .admission
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .held
                .is_empty(),
            "nothing left held"
        );
    }

    /// A resolver as slow as a DNS outage: longer than the hold's bound
    /// ([`ADMISSION_LOOKUP_MAX`]) and the resolution slot's interval.
    fn slow_resolver(list: &PeerAllowlist) {
        std::thread::sleep(std::time::Duration::from_secs(3));
        list.resolve_hosts();
    }

    /// #1115 review n2: a Setup held for a resolution slower than the hold's bound is
    /// judged without it, and refused once: being judged again, it is not held again.
    ///
    /// REVERT-VERIFIED: without the `rejudging` guard the Setup is held again, and
    /// again, and never answered.
    #[tokio::test]
    async fn a_setup_held_past_a_slow_resolution_is_refused_not_held_again() {
        let (server, _smf, upf, _rx) = spawn_test_server().await;
        server.set_allowed_peers(PeerAllowlist::parse("localhost").unwrap());
        server.set_resolver_for_test(slow_resolver);
        let stranger = UdpSocket::bind("127.0.0.66:0").await.unwrap();
        stranger
            .send_to(
                &encode_pfcp(
                    5,
                    None,
                    7,
                    &association_setup(Ipv4Addr::new(127, 0, 0, 66), 7, None),
                ),
                upf,
            )
            .await
            .unwrap();
        // Answered once the hold's bound passes, before the slow lookup ends.
        let mut buf = vec![0u8; 2048];
        let (len, _) = tokio::time::timeout(
            ADMISSION_LOOKUP_MAX + std::time::Duration::from_millis(900),
            stranger.recv_from(&mut buf),
        )
        .await
        .expect("answered, not held again")
        .unwrap();
        assert_eq!(
            response_cause(&buf[..len]),
            PfcpCause::RequestRejected as u8
        );
    }

    /// #1115 review n2, n3: at most [`ADMISSION_MAX_HELD`] Setups are held, one per
    /// source. A host retransmitting, or re-sending under new sequence numbers, holds
    /// one place and is answered once; past the cap a Setup is refused at once.
    ///
    /// REVERT-VERIFIED: without the cap the 65th is held too; deduplicating by
    /// (source, sequence) lets one host take many places.
    #[tokio::test]
    async fn held_setups_are_capped_and_one_per_source() {
        let (server, _smf, upf, _rx) = spawn_test_server().await;
        server.set_allowed_peers(PeerAllowlist::parse("localhost").unwrap());
        server.set_resolver_for_test(slow_resolver);
        // One host, three Setups (a retransmission and a new sequence number).
        let repeat = UdpSocket::bind("127.0.0.70:0").await.unwrap();
        for seq in [1, 1, 2] {
            repeat
                .send_to(
                    &encode_pfcp(
                        5,
                        None,
                        seq,
                        &association_setup(Ipv4Addr::new(127, 0, 0, 70), seq, None),
                    ),
                    upf,
                )
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(server.admission.lock().unwrap().held.len(), 1, "one place");
        // 63 more sources fill the queue.
        let mut fillers = Vec::new();
        for host in 2u8..65 {
            let sock = UdpSocket::bind((Ipv4Addr::new(127, 0, 1, host), 0))
                .await
                .unwrap();
            sock.send_to(
                &encode_pfcp(
                    5,
                    None,
                    9,
                    &association_setup(Ipv4Addr::new(127, 0, 1, host), 9, None),
                ),
                upf,
            )
            .await
            .unwrap();
            fillers.push(sock);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            server.admission.lock().unwrap().held.len(),
            ADMISSION_MAX_HELD
        );
        // The next source is past the cap: refused at once, not held.
        let late = UdpSocket::bind("127.0.0.71:0").await.unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            setup_cause(&late, upf, Ipv4Addr::new(127, 0, 0, 71), 3).await,
            PfcpCause::RequestRejected as u8
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "at once"
        );
        // The repeating host is answered exactly once.
        let mut buf = vec![0u8; 2048];
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(4),
            repeat.recv_from(&mut buf),
        )
        .await
        .expect("answered");
        assert!(first.is_ok());
        let second = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            repeat.recv_from(&mut buf),
        )
        .await;
        assert!(second.is_err(), "once");
    }

    /// SECURITY (#968 re-review, fail closed): with NO allowlist configured, no host
    /// can associate -- not the first one to ask, which used to win and then lock the
    /// real SMF out -- and so nothing else is served either. `0.0.0.0/0` is the
    /// explicit lab opt-out.
    #[tokio::test]
    async fn without_an_allowlist_no_host_can_associate() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        server.set_allowed_peers(PeerAllowlist::default());
        let other = UdpSocket::bind("127.0.0.66:0").await.unwrap();
        for sock in [&smf, &other] {
            assert_eq!(
                setup_cause(sock, upf, SMF_NODE, 7).await,
                PfcpCause::RequestRejected as u8
            );
        }
        assert!(!server.is_associated().await);

        server.set_allowed_peers(PeerAllowlist::parse("0.0.0.0/0").unwrap());
        assert_eq!(
            setup_cause(&other, upf, Ipv4Addr::new(127, 0, 0, 66), 8).await,
            PfcpCause::RequestAccepted as u8,
            "the explicit any-host opt-out"
        );
    }

    /// #968 round 3: a listed host may move a LIVE association only as the same CP
    /// function -- same Node ID (the #718 new-pod-IP case) or one of its own hosts. A
    /// DIFFERENT CP function from another listed host is refused (cause 64) and the
    /// sessions stay; once the association is released, it may associate.
    #[tokio::test]
    async fn a_listed_host_moves_a_live_association_only_as_the_same_cp_function() {
        let (server, smf_a, upf, _rx) = spawn_test_server().await;
        server.set_allowed_peers(PeerAllowlist::parse("127.0.0.1, 127.0.0.2, 127.0.0.3").unwrap());
        associate(&smf_a, upf, SMF_NODE, 100, None).await;
        let x = establish(&server, &smf_a, upf, FIRST_CP_SEID).await;

        let other_cp = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        assert_eq!(
            setup_cause(&other_cp, upf, Ipv4Addr::new(127, 0, 0, 2), 5).await,
            PfcpCause::RequestRejected as u8,
            "another CP function cannot evict the live one"
        );
        assert_eq!(held(&server).await.len(), 1, "{x:#x} survives");
        assert_eq!(
            server.association.read().await.as_ref().unwrap().peer_addr,
            smf_a.local_addr().unwrap()
        );

        // The same CP function (same Node ID) at a new listed address moves it.
        let moved = UdpSocket::bind("127.0.0.3:0").await.unwrap();
        assert_eq!(
            setup_cause(&moved, upf, SMF_NODE, 6).await,
            PfcpCause::RequestAccepted as u8
        );
        assert_eq!(
            server.association.read().await.as_ref().unwrap().peer_addr,
            moved.local_addr().unwrap()
        );

        // Released: now the other CP function may associate.
        let mut rel = crate::n4_build::PfcpMessageBuilder::new();
        rel.add_node_id(&NodeId::Ipv4(SMF_NODE));
        let resp = exchange(&moved, upf, &encode_pfcp(9, None, 7, &rel.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            setup_cause(&other_cp, upf, Ipv4Addr::new(127, 0, 0, 2), 8).await,
            PfcpCause::RequestAccepted as u8
        );
    }

    /// #968 review, MAJOR 3: the association is the CP function's, not one UDP
    /// 4-tuple. Session messages from the SMF's host on ANOTHER source port, and from
    /// the address its IPv4 Node ID names, are served.
    #[tokio::test]
    async fn the_associated_smf_is_served_from_another_port_and_its_node_id_address() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        associate(&smf, upf, SMF_NODE, 100, None).await;
        let x = establish(&server, &smf, upf, FIRST_CP_SEID).await;
        let y = establish(&server, &smf, upf, FIRST_CP_SEID + 1).await;

        let other_port = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resp = exchange(&other_port, upf, &encode_pfcp(54, Some(x), 20, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);

        let node_id_addr = UdpSocket::bind(SocketAddr::from((SMF_NODE, 0)))
            .await
            .unwrap();
        let resp = exchange(&node_id_addr, upf, &encode_pfcp(54, Some(y), 21, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
    }

    /// An FQDN Node ID (§8.2.38 type 2) decodes from its label encoding, and its
    /// resolved addresses join the association: an SMF named `localhost` that set up
    /// from 127.0.0.2 is served from 127.0.0.1.
    #[tokio::test]
    async fn an_fqdn_node_id_adds_the_addresses_it_resolves_to() {
        assert_eq!(
            node_id_fqdn(b"\x02\x03smf\x04core\x03lab").as_deref(),
            Some("smf.core.lab")
        );
        assert_eq!(node_id_fqdn(b"\x02\x05sm"), None, "truncated label");
        assert_eq!(node_id_fqdn(&[0, 127, 0, 0, 1]), None, "not an FQDN");

        let (server, _smf, upf, _rx) = spawn_test_server().await;
        server.set_allowed_peers(PeerAllowlist::parse("127.0.0.1, 127.0.0.2").unwrap());
        let smf = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::NODE_ID, b"\x02\x09localhost");
        b.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, 1);
        let resp = exchange(&smf, upf, &encode_pfcp(5, None, 1, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let assoc = server.association.read().await.clone().unwrap();
        assert!(
            assoc.owns(IpAddr::from([127, 0, 0, 1])),
            "{:?}",
            assoc.addrs
        );
        assert!(assoc.owns(IpAddr::from([127, 0, 0, 2])));
        assert!(!assoc.owns(IpAddr::from([127, 0, 0, 3])));
    }

    /// #968 review, MAJOR 2: a message of an unknown type is ignored (TS 29.244 §7.6),
    /// not answered with type `t + 1` -- for type 255 that addition overflowed and
    /// panicked the receive task in debug builds. The server keeps serving.
    #[tokio::test]
    async fn a_message_of_unknown_type_is_ignored_and_the_server_keeps_serving() {
        let (_server, smf, upf, _rx) = spawn_test_server().await;
        let stranger = UdpSocket::bind("127.0.0.66:0").await.unwrap();
        for t in [255u8, 99, 18] {
            stranger
                .send_to(&encode_pfcp(t, None, 3, &[]), upf)
                .await
                .unwrap();
            let mut buf = [0u8; 64];
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    stranger.recv_from(&mut buf)
                )
                .await
                .is_err(),
                "type {t} must not be answered"
            );
        }
        let mut hb = crate::n4_build::PfcpMessageBuilder::new();
        hb.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, 1);
        let resp = exchange(&smf, upf, &encode_pfcp(1, None, 4, &hb.build())).await;
        assert_eq!(resp[1], pfcp_type::HEARTBEAT_RESPONSE, "still serving");
    }

    /// #995: the UPF's own Recovery Time Stamp is NTP-era seconds (TS 29.244
    /// §8.2.65), and a received stamp is stored as sent (#1033): a Unix-seconds
    /// stamp (a 0.1.x SMF) is not re-read as NTP.
    #[tokio::test]
    async fn recovery_time_stamps_are_ntp_seconds() {
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let now = nextgcore_pfcp::recovery_time::now();
        assert!(now.wrapping_sub(server.recovery_time_stamp) < 60);
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, unix as u32);
        assert_eq!(
            crate::n4_build::parse_recovery_time_stamp(&b.build()),
            Some(unix as u32),
            "the parser returns the wire value"
        );
        // ... and the association stores it as sent.
        let assoc = build_association_setup_request_payload(Some(unix as u32));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        assert_eq!(
            server
                .association
                .read()
                .await
                .as_ref()
                .unwrap()
                .recovery_time_stamp,
            unix as u32,
            "as sent, not normalised"
        );
    }

    /// The UPF's sessions as (UPF SEID, CP SEID, address it reports to).
    async fn held(server: &PfcpServer) -> Vec<(u64, u64, SocketAddr)> {
        let mut v: Vec<_> = server
            .sessions
            .read()
            .await
            .values()
            .map(|s| (s.upf_seid, s.smf_seid, s.smf_addr))
            .collect();
        v.sort();
        v
    }

    /// The first Session Report Request that reaches `smf`, as (CP SEID in the
    /// header, PDR ID in its Downlink Data Report).
    async fn first_report(smf: &UdpSocket) -> (u64, u16) {
        let pkt = recv_report(smf).await;
        let (header, body) = ParsedPfcpHeader::parse(&pkt).unwrap();
        assert_eq!(header.msg_type, pfcp_type::SESSION_REPORT_REQUEST);
        let ies = ParsedIe::parse_all(body);
        let dldr = ParsedIe::find_ie(&ies, 83).expect("Downlink Data Report (IE 83)");
        let inner = ParsedIe::parse_all(&dldr.value);
        let pdr = ParsedIe::find_ie(&inner, pfcp_ie::PDR_ID).expect("PDR ID");
        (
            header.seid,
            u16::from_be_bytes([pdr.value[0], pdr.value[1]]),
        )
    }

    /// #718: the cross-UE Session Report. Three SMF incarnations with one Node ID:
    /// the first at address A, the second at a new pod IP B, the third back at A
    /// (pod IPs are recycled). Each one starts from an empty context, so each gives
    /// its first UE the same CP SEID.
    ///
    /// On main, upfd keyed the association by source address, so neither
    /// re-association deleted anything. Incarnation 1's session survived, still
    /// reporting to A, and its Session Reports reached incarnation 3 carrying
    /// incarnation 3's own UE's CP SEID. Incarnation 3 then pages, or charges, the
    /// wrong subscriber. TS 29.244 §6.2.6.2.2: an Association Setup Request from a
    /// Node ID that already has an association overwrites it "regardless of the
    /// Recovery Timestamp" and deletes the existing association's sessions.
    #[tokio::test]
    async fn a_restarted_smf_at_a_new_address_does_not_inherit_its_predecessors_sessions() {
        let (server, smf_a, upf, mut rx) = spawn_test_server().await;
        let smf_b = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        // A new pod IP: accepted because the deployment allowlists its CP range (#968).
        server.set_allowed_peers(PeerAllowlist::parse("127.0.0.0/8").unwrap());
        let (a, b) = (smf_a.local_addr().unwrap(), smf_b.local_addr().unwrap());

        // Incarnation 1 at A: UE X.
        let resp = associate(&smf_a, upf, SMF_NODE, 100, None).await;
        assert!(!psrei(&resp), "nothing to retain on a first association");
        let x = establish(&server, &smf_a, upf, FIRST_CP_SEID).await;

        // Incarnation 2 at B: the restarted pod, empty context, UE Y.
        associate(&smf_b, upf, SMF_NODE, 200, None).await;
        let y = establish(&server, &smf_b, upf, FIRST_CP_SEID).await;

        // Incarnation 3, back at A: UE Z.
        associate(&smf_a, upf, SMF_NODE, 300, None).await;
        let z = establish(&server, &smf_a, upf, FIRST_CP_SEID).await;

        // Every session the UPF still holds reports downlink data: Z's with PDR 7,
        // any survivor with PDR 1. Survivors go first, so the first report A receives
        // is a survivor's whenever one reports to A.
        for (seid, cp_seid, _) in held(&server).await {
            if seid != z {
                server
                    .send_downlink_data_report(seid, cp_seid, 1, None)
                    .await
                    .unwrap();
            }
        }
        server
            .send_downlink_data_report(z, FIRST_CP_SEID, 7, None)
            .await
            .unwrap();
        assert_eq!(
            first_report(&smf_a).await,
            (FIRST_CP_SEID, 7),
            "incarnation 3 must receive only its own UE's report; a PDR 1 report under its UE's \
             CP SEID is incarnation 1's session (UPF SEID {x:#x}) reaching the wrong subscriber"
        );
        // And the UPF holds exactly the sessions the live SMF knows about.
        assert_eq!(
            held(&server).await,
            vec![(z, FIRST_CP_SEID, a)],
            "the sessions of incarnations 1 ({x:#x}) and 2 ({y:#x}, at {b}) must be gone"
        );
        // The data plane was told about each deletion.
        let mut failures = 0;
        while let Ok(evt) = rx.try_recv() {
            if matches!(evt, PfcpSessionEvent::PeerFailure { .. }) {
                failures += 1;
            }
        }
        assert_eq!(failures, 2, "one data-plane flush per replaced association");
    }

    /// #718: a CP function that restored its sessions (durable state) asks for them
    /// to be kept with a PFCP Session Retention Information IE. With no CP PFCP
    /// Entity IP Address in it, every session is kept (TS 29.244 Table 7.4.4.1-2) and
    /// PSREI says so. The kept session now reports to the new address, because the
    /// old pod IP is dead.
    #[tokio::test]
    async fn a_retention_request_from_the_same_node_keeps_the_sessions_and_says_so() {
        let (server, smf_a, upf, _rx) = spawn_test_server().await;
        let smf_b = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        // A new pod IP: accepted because the deployment allowlists its CP range (#968).
        server.set_allowed_peers(PeerAllowlist::parse("127.0.0.0/8").unwrap());
        associate(&smf_a, upf, SMF_NODE, 100, None).await;
        let x = establish(&server, &smf_a, upf, FIRST_CP_SEID).await;

        let resp = associate(&smf_b, upf, SMF_NODE, 200, Some(&[])).await;
        assert!(psrei(&resp), "PSREI: the requested sessions were retained");
        assert_eq!(
            held(&server).await,
            vec![(x, FIRST_CP_SEID, smf_b.local_addr().unwrap())]
        );
        server
            .send_downlink_data_report(x, FIRST_CP_SEID, 1, None)
            .await
            .unwrap();
        assert_eq!(first_report(&smf_b).await, (FIRST_CP_SEID, 1));
    }

    /// #1513: drive the N3 path to `gnb` in the data plane's path table to FAILED.
    fn fail_path(dp: &crate::data_plane::DataPlane, gnb: SocketAddr) {
        let mut pt = dp.path_table.write().unwrap();
        pt.sync_peers(&std::collections::HashSet::from([gnb]));
        pt.miss_threshold = 1;
        pt.tick();
        let (_, failed) = pt.tick();
        assert_eq!(failed, vec![gnb]);
    }

    /// #1513: the failed path to `gnb` answers an Echo Request: it RECOVERED.
    fn recover_path(dp: &crate::data_plane::DataPlane, gnb: SocketAddr) {
        let mut pt = dp.path_table.write().unwrap();
        let seq = pt.tick().0[0].1;
        assert_eq!(
            pt.on_echo_response(gnb, Some(seq)),
            crate::data_plane::EchoResponse::Answered { recovered: true }
        );
    }

    /// #1513: the next datagram `smf` receives, which must be a path Node Report:
    /// (sequence number, failure, the Remote GTP-U Peers it names).
    async fn next_path_report(smf: &UdpSocket) -> (u32, bool, Vec<IpAddr>) {
        let mut buf = vec![0u8; 2048];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("a path Node Report arrives")
                .expect("recv");
        assert_eq!(buf[1], pfcp_type::NODE_REPORT_REQUEST);
        let (hdr, body) = ParsedPfcpHeader::parse(&buf[..len]).unwrap();
        let ies = ParsedIe::parse_all(body);
        let nrt = ParsedIe::find_ie(&ies, crate::n4_build::pfcp_ie::NODE_REPORT_TYPE).unwrap();
        let failure = match nrt.value[0] {
            0x01 => true,
            0x02 => false,
            other => panic!("not a path report: Node Report Type {other:#x}"),
        };
        let ie = if failure {
            crate::n4_build::pfcp_ie::USER_PLANE_PATH_FAILURE_REPORT
        } else {
            crate::n4_build::pfcp_ie::USER_PLANE_PATH_RECOVERY_REPORT
        };
        let report = ParsedIe::find_ie(&ies, ie).expect("the path report IE");
        let peers = ParsedIe::parse_all(&report.value)
            .iter()
            .filter(|p| p.ie_type == crate::n4_build::pfcp_ie::REMOTE_GTP_U_PEER)
            .map(|p| {
                assert_eq!(p.value[0], 0x02, "V4");
                IpAddr::V4(Ipv4Addr::new(
                    p.value[1], p.value[2], p.value[3], p.value[4],
                ))
            })
            .collect();
        (hdr.sequence_number, failure, peers)
    }

    /// #1513: answer the Node Report `seq` with `cause`.
    async fn answer_node_report(smf: &UdpSocket, upf: SocketAddr, seq: u32, cause: u8) {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(SMF_NODE));
        b.add_u8(pfcp_ie::CAUSE, cause);
        smf.send_to(
            &encode_pfcp(pfcp_type::NODE_REPORT_RESPONSE, None, seq, &b.build()),
            upf,
        )
        .await
        .unwrap();
    }

    /// #1513: wait until the server has scheduled a path state re-report, and make it
    /// due now.
    async fn resend_now(server: &PfcpServer) {
        for _ in 0..200 {
            if server.test_path_resend_now() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no path state re-report was scheduled");
    }

    /// #1513: wait until every path report sent has had its response processed.
    async fn settled(server: &PfcpServer) {
        for _ in 0..200 {
            if server.test_path_in_flight() == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("path reports still in flight");
    }

    /// A model of the SMF's path handling as smfd implements it (#994, #1505): a
    /// report from a UPF it has marked down is refused with cause 72 and changes
    /// nothing; otherwise failed peers are held and recovered ones forgotten.
    #[derive(Default)]
    struct SmfPaths {
        associated: bool,
        failed: std::collections::HashSet<IpAddr>,
        /// Refuse this many more reports with 72 even when associated: smfd marks the
        /// association up only after it handled the Setup Response, so the first
        /// re-report after a re-association can race into a 72.
        refuse: u32,
        /// Refuse every recovery report (a third-party SMF's policy).
        refuse_recoveries: bool,
    }

    impl SmfPaths {
        fn on_report(&mut self, failure: bool, peers: &[IpAddr]) -> u8 {
            if !self.associated || self.refuse > 0 {
                self.refuse = self.refuse.saturating_sub(1);
                return PfcpCause::NoEstablishedPfcpAssociation as u8;
            }
            if !failure && self.refuse_recoveries {
                return PfcpCause::RequestRejected as u8;
            }
            for ip in peers {
                if failure {
                    self.failed.insert(*ip);
                } else {
                    self.failed.remove(ip);
                }
            }
            PfcpCause::RequestAccepted as u8
        }

        /// The SMF's next path report and its answer.
        async fn serve(&mut self, smf: &UdpSocket, upf: SocketAddr) -> (bool, Vec<IpAddr>, u8) {
            let (seq, failure, peers) = next_path_report(smf).await;
            let cause = self.on_report(failure, &peers);
            answer_node_report(smf, upf, seq, cause).await;
            (failure, peers, cause)
        }
    }

    /// #1513, the issue's scenario (TS 29.244 §6.2.9.2: only a "success" response
    /// delivers a Node Report). A path recovery refused with cause 72 by an SMF that
    /// marked this UPF down was dropped as delivered, so the SMF still held the path
    /// failed after re-associating and released the sessions on the healthy gNB when
    /// its hold expired. Now the refusal is not delivery: the recovery is re-reported,
    /// and once the SMF re-associates and keeps the sessions it learns the path is up.
    #[tokio::test]
    async fn a_path_recovery_refused_while_marked_down_reaches_the_smf_after_reassociation() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let gnb: SocketAddr = "10.1.1.1:2152".parse().unwrap();
        let mut smf_paths = SmfPaths {
            associated: true,
            ..Default::default()
        };
        associate(&smf, upf, SMF_NODE, 100, None).await;
        let x = establish(&server, &smf, upf, FIRST_CP_SEID).await;

        // 1. The gNB path fails; the SMF accepts the failure report (and holds it).
        fail_path(&dp, gnb);
        server.send_node_report(true, &[gnb.ip()]).await.unwrap();
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (true, vec![gnb.ip()], PfcpCause::RequestAccepted as u8)
        );
        settled(&server).await;
        assert_eq!(
            server.test_told_failed(),
            vec![gnb.ip()],
            "an accepted failure stands"
        );

        // 2. A one-way heartbeat loss marks the UPF down on the SMF.
        smf_paths.associated = false;

        // 3. The path recovers; the SMF refuses the recovery report with cause 72.
        recover_path(&dp, gnb);
        server.send_node_report(false, &[gnb.ip()]).await.unwrap();
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (
                false,
                vec![gnb.ip()],
                PfcpCause::NoEstablishedPfcpAssociation as u8
            )
        );
        settled(&server).await;
        // Not delivered: re-reported after T1, refused again while still marked down.
        resend_now(&server).await;
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (
                false,
                vec![gnb.ip()],
                PfcpCause::NoEstablishedPfcpAssociation as u8
            )
        );
        assert_eq!(server.test_told_failed(), vec![gnb.ip()]);

        // 4. The SMF re-associates and the UPF retains the sessions; the UPF re-reports
        //    the current path state, and the SMF accepts the recovery.
        smf_paths.associated = true;
        let resp = associate(&smf, upf, SMF_NODE, 100, Some(&[])).await;
        assert!(psrei(&resp), "the sessions are retained");
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (false, vec![gnb.ip()], PfcpCause::RequestAccepted as u8)
        );

        // 5. The hold expires: the SMF holds no failed path, so it releases nothing,
        //    and the UPF still holds the session.
        assert!(smf_paths.failed.is_empty(), "{:?}", smf_paths.failed);
        for _ in 0..200 {
            if server.test_told_failed().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(server.test_told_failed().is_empty());
        assert_eq!(
            held(&server).await,
            vec![(x, FIRST_CP_SEID, smf.local_addr().unwrap())]
        );
    }

    /// #1513: "a failure report sent in the same window is lost the same way". A path
    /// failure refused with cause 72 is re-reported once the SMF re-associates and
    /// keeps the sessions, so its hold is armed then.
    #[tokio::test]
    async fn a_path_failure_refused_while_marked_down_reaches_the_smf_after_reassociation() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let gnb: SocketAddr = "10.1.1.2:2152".parse().unwrap();
        let mut smf_paths = SmfPaths::default();
        associate(&smf, upf, SMF_NODE, 100, None).await;
        establish(&server, &smf, upf, FIRST_CP_SEID).await;

        fail_path(&dp, gnb);
        server.send_node_report(true, &[gnb.ip()]).await.unwrap();
        assert_eq!(
            smf_paths.serve(&smf, upf).await.2,
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );

        smf_paths.associated = true;
        assert!(psrei(&associate(&smf, upf, SMF_NODE, 100, Some(&[])).await));
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (true, vec![gnb.ip()], PfcpCause::RequestAccepted as u8)
        );
        assert_eq!(
            smf_paths.failed,
            std::collections::HashSet::from([gnb.ip()])
        );
    }

    /// #1513: a refused re-report is retried after T1, at most N1 times in a row; then
    /// the state waits for the next re-association. A path report abandoned after N1
    /// unanswered transmissions is not delivered either, and is re-reported.
    #[tokio::test]
    async fn path_state_re_reports_are_bounded_and_follow_an_abandoned_report() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let gnb: SocketAddr = "10.1.1.3:2152".parse().unwrap();
        associate(&smf, upf, SMF_NODE, 100, None).await;

        // Abandoned after N1: the original and N1 retransmissions go unanswered.
        fail_path(&dp, gnb);
        server.send_node_report(true, &[gnb.ip()]).await.unwrap();
        for _ in 0..=PFCP_N1_MAX_RETRANSMIT {
            let (_, failure, _) = next_path_report(&smf).await;
            assert!(failure);
            server.test_expire_pending_t1().await;
            server.retransmit_pending_reports().await;
        }
        assert_eq!(server.pending_report_count().await, 0, "abandoned");

        // Re-reported; each refusal schedules one more, N1 in all.
        for _ in 0..PFCP_N1_MAX_RETRANSMIT {
            resend_now(&server).await;
            let (seq, failure, peers) = next_path_report(&smf).await;
            assert_eq!((failure, peers), (true, vec![gnb.ip()]));
            answer_node_report(
                &smf,
                upf,
                seq,
                PfcpCause::NoEstablishedPfcpAssociation as u8,
            )
            .await;
            for _ in 0..200 {
                if server.test_path_in_flight() == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert_eq!(server.test_path_in_flight(), 0, "the refusal is processed");
        }
        assert!(
            !server.test_path_resend_now(),
            "after N1 refused re-reports, the state waits for a re-association"
        );
    }

    /// #1513: an Association Setup that does not retain the sessions starts afresh:
    /// what the previous CP function was told is forgotten and nothing is re-reported.
    #[tokio::test]
    async fn a_reassociation_without_retention_forgets_the_path_reports() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let gnb: SocketAddr = "10.1.1.4:2152".parse().unwrap();
        associate(&smf, upf, SMF_NODE, 100, None).await;
        fail_path(&dp, gnb);
        server.send_node_report(true, &[gnb.ip()]).await.unwrap();
        let (seq, _, _) = next_path_report(&smf).await;
        answer_node_report(
            &smf,
            upf,
            seq,
            PfcpCause::NoEstablishedPfcpAssociation as u8,
        )
        .await;
        resend_now(&server).await;
        let _ = next_path_report(&smf).await;
        assert_eq!(server.test_told_failed(), vec![gnb.ip()]);

        assert!(!psrei(&associate(&smf, upf, SMF_NODE, 200, None).await));
        assert!(server.test_told_failed().is_empty());
        assert!(!server.test_path_resend_now(), "nothing is re-reported");
    }

    /// A data plane attached to `server`, for the #1513 tests.
    fn attach_dp_1513(server: &PfcpServer) -> Arc<crate::data_plane::DataPlane> {
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        dp
    }

    fn set_path(dp: &crate::data_plane::DataPlane, gnb: SocketAddr, failed: bool) {
        dp.path_table
            .write()
            .unwrap()
            .set_path_state_for_test(gnb, failed);
    }

    /// #1531 review M-1: a transition that happens after a re-report round read the
    /// path table is reported AFTER the round, so the SMF ends with the newer state.
    /// The round reads gNB A as FAILED and is held there; A then recovers and its live
    /// recovery report is sent concurrently. Without the ordering the live recovery
    /// went first and the stale failure after it: the SMF held A failed while it was
    /// up, and its hold would release A's sessions with #39.
    #[tokio::test]
    async fn a_transition_after_a_re_report_read_the_table_is_reported_after_it() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        let dp = attach_dp_1513(&server);
        let a: SocketAddr = "10.1.2.1:2152".parse().unwrap();
        let mut smf_paths = SmfPaths::default();
        associate(&smf, upf, SMF_NODE, 100, None).await;
        establish(&server, &smf, upf, FIRST_CP_SEID).await;

        // A fails while the SMF has the UPF marked down: refused.
        set_path(&dp, a, true);
        server.send_node_report(true, &[a.ip()]).await.unwrap();
        assert_eq!(
            smf_paths.serve(&smf, upf).await.2,
            PfcpCause::NoEstablishedPfcpAssociation as u8
        );
        settled(&server).await;

        // The retained re-association starts a round; hold it after its table read.
        let (reached, proceed) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        *server.resend_hold.lock().unwrap() = Some((reached.clone(), proceed.clone()));
        smf_paths.associated = true;
        assert!(psrei(&associate(&smf, upf, SMF_NODE, 100, Some(&[])).await));
        tokio::time::timeout(std::time::Duration::from_secs(2), reached.notified())
            .await
            .expect("the round read the path table");
        *server.resend_hold.lock().unwrap() = None;

        // A recovers now, after the read: its live recovery report is sent.
        set_path(&dp, a, false);
        let live = {
            let server = server.clone();
            tokio::spawn(async move { server.send_node_report(false, &[a.ip()]).await })
        };
        // Give the live report every chance to overtake (it must not).
        let mut peek = [0u8; 16];
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            smf.peek_from(&mut peek),
        )
        .await;
        proceed.notify_one();

        // The SMF sees the round's (stale) failure first, then the newer recovery.
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (true, vec![a.ip()], PfcpCause::RequestAccepted as u8),
            "the round's report goes first"
        );
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (false, vec![a.ip()], PfcpCause::RequestAccepted as u8),
            "the newer transition goes last"
        );
        live.await.unwrap().unwrap();
        settled(&server).await;
        assert!(smf_paths.failed.is_empty(), "the SMF ends with A up");
        assert!(server.test_told_failed().is_empty());
    }

    /// #1531 review M-2: a retained Setup restarts the re-report rounds. The
    /// refusals while the SMF had the UPF marked down used up every round; the first
    /// re-report after the re-association is refused with 72 too (smfd marks the
    /// association up only after the Setup Response), and it is still retried.
    #[tokio::test]
    async fn a_retained_setup_restarts_the_re_report_rounds() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        let dp = attach_dp_1513(&server);
        let a: SocketAddr = "10.1.2.2:2152".parse().unwrap();
        let mut smf_paths = SmfPaths::default();
        associate(&smf, upf, SMF_NODE, 100, None).await;
        establish(&server, &smf, upf, FIRST_CP_SEID).await;

        set_path(&dp, a, true);
        server.send_node_report(true, &[a.ip()]).await.unwrap();
        smf_paths.serve(&smf, upf).await;
        settled(&server).await;
        for _ in 0..PFCP_N1_MAX_RETRANSMIT {
            resend_now(&server).await;
            assert_eq!(
                smf_paths.serve(&smf, upf).await.2,
                PfcpCause::NoEstablishedPfcpAssociation as u8
            );
            settled(&server).await;
        }
        assert!(!server.test_path_resend_now(), "every round is used up");

        smf_paths.associated = true;
        smf_paths.refuse = 1;
        assert!(psrei(&associate(&smf, upf, SMF_NODE, 100, Some(&[])).await));
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (
                true,
                vec![a.ip()],
                PfcpCause::NoEstablishedPfcpAssociation as u8
            ),
            "the first re-report races into a 72"
        );
        resend_now(&server).await;
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (true, vec![a.ip()], PfcpCause::RequestAccepted as u8),
            "and is retried"
        );
        assert_eq!(smf_paths.failed, std::collections::HashSet::from([a.ip()]));
    }

    /// #1531 review MINOR 2: the rounds are counted, not the refusals. A CP function
    /// that accepts every failure but refuses a recovery gets PFCP_N1_MAX_RETRANSMIT
    /// rounds and no more, although one report of every round is accepted. Before,
    /// each accepted failure reset the count and a round followed every T1 forever.
    #[tokio::test]
    async fn re_report_rounds_stay_bounded_when_one_report_of_each_round_is_accepted() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        let dp = attach_dp_1513(&server);
        let a: SocketAddr = "10.1.2.3:2152".parse().unwrap();
        let b: SocketAddr = "10.1.2.4:2152".parse().unwrap();
        let mut smf_paths = SmfPaths {
            associated: true,
            refuse_recoveries: true,
            ..Default::default()
        };
        associate(&smf, upf, SMF_NODE, 100, None).await;

        set_path(&dp, a, true);
        server.send_node_report(true, &[a.ip()]).await.unwrap();
        smf_paths.serve(&smf, upf).await;
        set_path(&dp, a, false);
        set_path(&dp, b, true);
        server.send_node_report(false, &[a.ip()]).await.unwrap();
        assert_eq!(
            smf_paths.serve(&smf, upf).await.2,
            PfcpCause::RequestRejected as u8
        );
        settled(&server).await;

        for _ in 0..PFCP_N1_MAX_RETRANSMIT {
            resend_now(&server).await;
            assert_eq!(
                smf_paths.serve(&smf, upf).await,
                (true, vec![b.ip()], PfcpCause::RequestAccepted as u8)
            );
            assert_eq!(
                smf_paths.serve(&smf, upf).await,
                (false, vec![a.ip()], PfcpCause::RequestRejected as u8)
            );
            settled(&server).await;
        }
        assert!(
            !server.test_path_resend_now(),
            "no round after PFCP_N1_MAX_RETRANSMIT rounds"
        );
    }

    /// #1531 review MINOR 3: a re-report says "recovered" only of a path known to be
    /// up. A path the SMF may hold failed whose state is unknown (no longer tracked:
    /// its sessions went) is not reported recovered; one that answered is.
    #[tokio::test]
    async fn a_re_report_recovers_only_paths_known_to_be_up() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        let dp = attach_dp_1513(&server);
        let a: SocketAddr = "10.1.2.5:2152".parse().unwrap();
        let b: SocketAddr = "10.1.2.6:2152".parse().unwrap();
        let mut smf_paths = SmfPaths {
            associated: true,
            ..Default::default()
        };
        associate(&smf, upf, SMF_NODE, 100, None).await;
        establish(&server, &smf, upf, FIRST_CP_SEID).await;
        set_path(&dp, a, true);
        set_path(&dp, b, true);
        server
            .send_node_report(true, &[a.ip(), b.ip()])
            .await
            .unwrap();
        smf_paths.serve(&smf, upf).await;
        settled(&server).await;

        // A is no longer tracked (unknown); B answered (up).
        dp.path_table.write().unwrap().remove_peer(&a);
        set_path(&dp, b, false);
        assert!(psrei(&associate(&smf, upf, SMF_NODE, 100, Some(&[])).await));
        assert_eq!(
            smf_paths.serve(&smf, upf).await,
            (false, vec![b.ip()], PfcpCause::RequestAccepted as u8),
            "only B is reported recovered"
        );
        settled(&server).await;
        assert_eq!(
            server.test_told_failed(),
            vec![a.ip()],
            "A may still be failed"
        );
    }

    /// #1531 review MINOR 3: a path report that cannot be sent is not delivered: it
    /// schedules a re-report, and nothing stays in flight.
    #[tokio::test]
    async fn a_path_report_that_cannot_be_sent_schedules_a_re_report() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        associate(&smf, upf, SMF_NODE, 100, None).await;
        // An IPv6 destination from the IPv4 socket: the send fails.
        server.association.write().await.as_mut().unwrap().peer_addr =
            "[::1]:8805".parse().unwrap();
        assert!(server
            .send_node_report(true, &["10.1.2.7".parse().unwrap()])
            .await
            .is_err());
        assert_eq!(server.test_path_in_flight(), 0);
        assert!(server.test_path_resend_now(), "a re-report is scheduled");
    }

    /// #1531 review MINOR 3: a heartbeat teardown deletes the sessions, and with them
    /// what the CP function was told: nothing stays to re-report.
    #[tokio::test]
    async fn a_heartbeat_teardown_clears_the_path_reports() {
        let (server, smf, upf, _rx) = spawn_test_server().await;
        associate(&smf, upf, SMF_NODE, 100, None).await;
        let ip: IpAddr = "10.1.2.8".parse().unwrap();
        server.send_node_report(true, &[ip]).await.unwrap();
        let (seq, _, _) = next_path_report(&smf).await;
        answer_node_report(
            &smf,
            upf,
            seq,
            PfcpCause::NoEstablishedPfcpAssociation as u8,
        )
        .await;
        resend_now(&server).await;
        assert_eq!(server.test_told_failed(), vec![ip]);

        for _ in 0..HEARTBEAT_MAX_MISSES {
            server.send_heartbeat_request().await.expect("sent");
            server.close_heartbeat_round().await;
        }
        assert!(!server.is_associated().await, "torn down");
        assert!(server.test_told_failed().is_empty());
        assert!(!server.test_path_resend_now(), "nothing is re-reported");
        assert_eq!(server.test_path_in_flight(), 0);
    }

    /// #1513: the ledger. A late acceptance of an older recovery does not clear a
    /// newer failure of the same peer; an accepted recovery that is the peer's latest
    /// report does. A response that is not to a path report is not one.
    #[test]
    fn the_path_report_ledger_applies_only_the_latest_report_per_peer() {
        let ip: IpAddr = "10.1.1.5".parse().unwrap();
        let mut l = PathReportLedger::default();
        l.sent(1, true, &[ip], false);
        assert!(l.answered(1, true));
        assert!(l.told_failed.contains(&ip), "an accepted failure stands");
        l.sent(2, false, &[ip], false);
        l.sent(3, true, &[ip], false);
        assert!(l.answered(2, true), "the recovery was a path report");
        assert!(l.told_failed.contains(&ip), "the newer failure stands");
        l.sent(4, false, &[ip], false);
        assert!(l.answered(4, true));
        assert!(
            !l.told_failed.contains(&ip),
            "the latest recovery was accepted"
        );
        assert!(!l.answered(99, true), "not a path report");
        assert!(!l.answered(4, true), "answered once");
    }

    /// #718: a retention request naming CP PFCP entities keeps only those
    /// entities' sessions. This session's CP F-SEID is 127.0.0.9, which the
    /// request does not list.
    #[tokio::test]
    async fn a_retention_request_keeps_only_the_listed_cp_entities_sessions() {
        let (server, smf_a, upf, _rx) = spawn_test_server().await;
        associate(&smf_a, upf, SMF_NODE, 100, None).await;
        let x = establish(&server, &smf_a, upf, FIRST_CP_SEID).await;

        let resp = associate(
            &smf_a,
            upf,
            SMF_NODE,
            100,
            Some(&[Ipv4Addr::new(10, 9, 9, 9)]),
        )
        .await;
        assert!(
            psrei(&resp),
            "the request was honoured, for the entities it named"
        );
        assert!(held(&server).await.is_empty(), "{x:#x} was not requested");

        let y = establish(&server, &smf_a, upf, FIRST_CP_SEID).await;
        let resp = associate(&smf_a, upf, SMF_NODE, 100, Some(&[SMF_NODE])).await;
        assert!(psrei(&resp));
        assert_eq!(
            held(&server).await,
            vec![(y, FIRST_CP_SEID, smf_a.local_addr().unwrap())],
            "the listed entity's session is kept"
        );
    }

    /// #718 / #968 round 3: retention is defined for the SAME Node ID only, and a
    /// DIFFERENT CP function cannot replace a live association at all: its Setup is
    /// refused (cause 64), so it can neither adopt nor delete the previous one's
    /// sessions.
    #[tokio::test]
    async fn a_different_cp_function_cannot_retain_the_previous_ones_sessions() {
        let (server, smf_a, upf, _rx) = spawn_test_server().await;
        let smf_b = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        server.set_allowed_peers(PeerAllowlist::parse("127.0.0.0/8").unwrap());
        associate(&smf_a, upf, SMF_NODE, 100, None).await;
        let x = establish(&server, &smf_a, upf, FIRST_CP_SEID).await;

        let resp = exchange(
            &smf_b,
            upf,
            &encode_pfcp(
                5,
                None,
                100,
                &association_setup(Ipv4Addr::new(127, 0, 0, 10), 100, Some(&[])),
            ),
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestRejected as u8);
        assert!(
            !psrei(&resp),
            "nothing was retained for a different Node ID"
        );
        assert_eq!(
            held(&server).await,
            vec![(x, FIRST_CP_SEID, smf_a.local_addr().unwrap())],
            "and nothing was deleted"
        );
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
                cp_f_seid_ipv4: None,
                cp_f_seid_ipv6: None,
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

    /// #780 review m2: a harvested URR report abandoned after N1 hands its usage back
    /// to the URR, so the next report carries it instead of it vanishing.
    #[tokio::test]
    async fn an_abandoned_urr_report_returns_its_usage_to_the_urr() {
        let (server, smf, upf_seid, smf_seid) = server_with_session().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            std::sync::atomic::AtomicBool::new(false),
        )));
        dp.add_session_from_pfcp(
            upf_seid,
            smf_seid,
            std::net::Ipv4Addr::new(10, 45, 7, 80),
            0x7801,
            0x7802,
            "127.0.0.1:2152".parse().unwrap(),
            Some(5),
            Some(9),
        );
        let urr = Arc::new(crate::data_plane::DataPlaneUrr::new(1));
        urr.set_reporting(Some(1), None, None, None, None);
        dp.sessions
            .find_by_seid(upf_seid)
            .unwrap()
            .urrs
            .write()
            .unwrap()
            .insert(1, Arc::clone(&urr));
        server.set_data_plane(Arc::clone(&dp));

        urr.record(1234, true);
        let reports = dp.collect_urr_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(urr.usage().total_bytes(), 0, "taken by the harvest");
        server
            .send_urr_report(upf_seid, smf_seid, reports)
            .await
            .unwrap();
        let _ = recv_report(&smf).await;
        for _ in 0..=PFCP_N1_MAX_RETRANSMIT {
            server.test_expire_pending_t1().await;
            server.retransmit_pending_reports().await;
        }
        assert_eq!(server.pending_report_count().await, 0, "abandoned after N1");
        assert_eq!(
            urr.usage().ul_bytes,
            1234,
            "the abandoned report's usage is back on the URR for the next report"
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

    // ---- #1389 part 3: per QoS flow per UE QoS monitoring (QFQM) over N4 ----

    /// A Create/Update SRR value: SRR ID, then one IE 242 for `qfis` (DL+UL
    /// packet delay, Event Triggered at 1 ms, no Minimum Wait Time).
    fn srr_body(srr_id: u8, qfis: &[u8]) -> Vec<u8> {
        use nextgcore_pfcp::qos_monitoring::{
            PacketDelayThresholds, QosMonitoringPerQosFlowControlInformation, ReportingFrequency,
            RequestedQosMonitoring, TypedIe,
        };
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::SRR_ID, srr_id);
        let mut v = b.build();
        let mut ie = bytes::BytesMut::new();
        QosMonitoringPerQosFlowControlInformation {
            qfis: qfis.to_vec(),
            requested_qos_monitoring: RequestedQosMonitoring {
                dlpd: true,
                ulpd: true,
                ..Default::default()
            },
            reporting_frequency: ReportingFrequency {
                evett: true,
                perio: false,
            },
            packet_delay_thresholds: Some(PacketDelayThresholds {
                downlink: Some(1),
                ..Default::default()
            }),
            minimum_wait_time: Some(0),
            measurement_period: None,
            extra: Vec::new(),
        }
        .encode_ie(&mut ie);
        v.extend_from_slice(&ie);
        v
    }

    fn srr_id_body(srr_id: u8) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_u8(pfcp_ie::SRR_ID, srr_id);
        b.build()
    }

    async fn modify(
        smf: &UdpSocket,
        addr: SocketAddr,
        seid: u64,
        seq: u32,
        ies: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        for (t, v) in ies {
            b.add_tlv(*t, v);
        }
        exchange(smf, addr, &encode_pfcp(52, Some(seid), seq, &b.build())).await
    }

    /// Give the monitor one answered probe of `qfi` on `seid` (10 ms N3 each way).
    fn measure_once(dp: &crate::data_plane::DataPlane, seid: u64, qfi: u8) {
        let now = std::time::Instant::now();
        let wall = std::time::SystemTime::now();
        dp.with_qos_flow_monitor(|m| {
            let r = m.round(now, wall);
            let p = r
                .dummies
                .iter()
                .find(|p| p.upf_seid == seid && p.qfi == qfi)
                .unwrap();
            let ms = (1u64 << 32) / 1000;
            let answer = crate::qos_flow_mon::QmpAnswer {
                t1: p.t1,
                t2: p.t1 + 10 * ms,
                t3: p.t1 + 11 * ms,
                t4: p.t1 + 21 * ms,
                dl_ran_ms: None,
                ul_ran_ms: None,
            };
            m.on_answer(seid, &answer, now, wall)
                .expect("answers the probe");
        });
    }

    #[tokio::test]
    async fn qfqm_is_advertised_only_with_qos_flow_monitoring() {
        for on in [false, true] {
            let (server, smf, addr, _rx) = spawn_test_server().await;
            server.set_qos_flow_monitoring(on);
            let payload = build_association_setup_request_payload(Some(1));
            let resp = exchange(&smf, addr, &encode_pfcp(5, None, 1, &payload)).await;
            let f = up_features(&resp);
            assert_eq!(f.len(), 8, "QFQM is octet 9: the IE does not grow");
            assert_eq!(f[4] & 0x02 != 0, on, "QFQM, octet 9 bit 2 (§8.2.25)");
        }
    }

    #[tokio::test]
    async fn an_srr_is_not_acted_on_without_qos_flow_monitoring() {
        let (_server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        let resp = modify(
            &smf,
            addr,
            upf_seid,
            3,
            &[(pfcp_ie::CREATE_SRR, srr_body(1, &[5]))],
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert!(
            !dp.with_qos_flow_monitor(|m| m.is_active()),
            "nothing monitored"
        );
    }

    #[tokio::test]
    async fn create_update_and_remove_srr_drive_monitoring_and_the_stop_report_reaches_the_smf() {
        use nextgcore_pfcp::qos_monitoring::{QosMonitoringReport, TypedIe};
        let (server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        server.set_qos_flow_monitoring(true);

        let resp = modify(
            &smf,
            addr,
            upf_seid,
            3,
            &[(pfcp_ie::CREATE_SRR, srr_body(3, &[5]))],
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            dp.with_qos_flow_monitor(|m| m.monitored_qfis(upf_seid)),
            vec![5]
        );
        measure_once(&dp, upf_seid, 5);

        // Update SRR: QFI 6 replaces QFI 5, so QFI 5's monitoring stops and what
        // it measured is reported after the response (§5.24.4.3).
        let resp = modify(
            &smf,
            addr,
            upf_seid,
            4,
            &[(pfcp_ie::UPDATE_SRR, srr_body(3, &[6]))],
        )
        .await;
        assert_eq!(resp[1], pfcp_type::SESSION_MODIFICATION_RESPONSE);
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert_eq!(
            dp.with_qos_flow_monitor(|m| m.monitored_qfis(upf_seid)),
            vec![6]
        );
        let mut buf = vec![0u8; 2048];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), smf.recv_from(&mut buf))
                .await
                .expect("a Session Report Request")
                .unwrap();
        assert_eq!(buf[1], pfcp_type::SESSION_REPORT_REQUEST);
        let (hdr, body) = ParsedPfcpHeader::parse(&buf[..n]).unwrap();
        assert_eq!(hdr.seid, 0x4242, "the SMF's SEID");
        let ies = ParsedIe::parse_all(body);
        assert_eq!(
            ParsedIe::find_ie(&ies, pfcp_ie::REPORT_TYPE).unwrap().value,
            vec![0x20],
            "SESR only (§8.2.21 bit 6)"
        );
        let sr = ParsedIe::find_ie(&ies, pfcp_ie::SESSION_REPORT).expect("Session Report IE 214");
        let members = ParsedIe::parse_all(&sr.value);
        assert_eq!(
            ParsedIe::find_ie(&members, pfcp_ie::SRR_ID).unwrap().value,
            vec![3]
        );
        let qmr = ParsedIe::find_ie(&members, 247).expect("QoS Monitoring Report IE 247");
        let rep = QosMonitoringReport::decode_value(&qmr.value).unwrap();
        assert_eq!(rep.qfi, 5);
        assert_eq!(
            rep.qos_monitoring_measurement.downlink_packet_delay,
            Some(10)
        );
        assert_eq!(rep.qos_monitoring_measurement.uplink_packet_delay, Some(10));
        assert_eq!(server.pending_report_count().await, 1, "tracked for T1/N1");

        // Remove SRR: monitoring ends. Nothing was measured on QFI 6, so there is
        // nothing to report.
        let resp = modify(
            &smf,
            addr,
            upf_seid,
            5,
            &[(pfcp_ie::REMOVE_SRR, srr_id_body(3))],
        )
        .await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        assert!(!dp.with_qos_flow_monitor(|m| m.is_active()));
    }

    #[tokio::test]
    async fn an_update_of_an_srr_the_session_does_not_hold_is_refused_with_its_failed_rule_id() {
        let (server, smf, addr, _rx, dp, upf_seid) = established_session().await;
        server.set_qos_flow_monitoring(true);
        let resp = modify(
            &smf,
            addr,
            upf_seid,
            3,
            &[(pfcp_ie::UPDATE_SRR, srr_body(9, &[5]))],
        )
        .await;
        assert_eq!(
            response_cause(&resp),
            PfcpCause::RuleCreationModificationFailure as u8
        );
        assert_eq!(
            failed_rule_id(&resp),
            Some(vec![6, 9]),
            "Rule ID Type 6 = SRR (§8.2.80)"
        );
        assert!(
            !dp.with_qos_flow_monitor(|m| m.is_active()),
            "a refused modification applies nothing"
        );
        // A Create SRR with no SRR ID is refused, not accepted: "Conditional IE
        // missing" naming the SRR ID (#1598, Create SRR is C in a modification).
        let mut no_id = srr_body(1, &[5]);
        no_id.drain(..5);
        let resp = modify(&smf, addr, upf_seid, 4, &[(pfcp_ie::CREATE_SRR, no_id)]).await;
        assert_eq!(response_cause(&resp), PfcpCause::ConditionalIeMissing as u8);
        assert_eq!(offending_ie_1478(&resp), Some(pfcp_ie::SRR_ID));
        assert!(!dp.with_qos_flow_monitor(|m| m.is_active()));
    }

    #[tokio::test]
    async fn an_establishment_s_create_srr_provisions_monitoring_and_deletion_ends_it() {
        let (server, smf, addr, mut rx) = spawn_test_server().await;
        server.set_qos_flow_monitoring(true);
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x4343,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr_body(1, 100, 1, 1, 1));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.add_tlv(pfcp_ie::CREATE_QER, &qer_body(1, 5));
        b.add_tlv(pfcp_ie::CREATE_SRR, &srr_body(2, &[5, 7]));
        let resp = exchange(&smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let upf_seid = *server.sessions.read().await.keys().next().unwrap();
        assert_eq!(
            dp.with_qos_flow_monitor(|m| m.monitored_qfis(upf_seid)),
            vec![5, 7]
        );
        assert_eq!(dp.with_qos_flow_monitor(|m| m.srr_ids(upf_seid)), vec![2]);
        let evt = rx.recv().await.unwrap();
        crate::handle_pfcp_session_event(&dp, evt).await;

        let resp = exchange(&smf, addr, &encode_pfcp(54, Some(upf_seid), 3, &[])).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        apply_next(&mut rx, &dp).await;
        assert!(
            !dp.with_qos_flow_monitor(|m| m.is_active()),
            "the session is gone"
        );
    }

    #[test]
    fn a_qos_monitoring_session_report_groups_its_reports_by_srr() {
        use nextgcore_pfcp::qos_monitoring::{QosMonitoringMeasurement, QosMonitoringReport};
        let rep = |qfi| QosMonitoringReport {
            qfi,
            qos_monitoring_measurement: QosMonitoringMeasurement {
                round_trip_packet_delay: Some(40),
                ..Default::default()
            },
            time_stamp: 0xe8a0_0001,
            start_time: None,
            extra: Vec::new(),
        };
        let body = crate::n4_build::build_qos_monitoring_session_report(&[
            (1, rep(5)),
            (2, rep(6)),
            (1, rep(7)),
        ]);
        let ies = ParsedIe::parse_all(&body);
        assert_eq!(ies[0].ie_type, pfcp_ie::REPORT_TYPE);
        let srs = ParsedIe::find_all_ies(&ies, pfcp_ie::SESSION_REPORT);
        assert_eq!(srs.len(), 2);
        let first = ParsedIe::parse_all(&srs[0].value);
        assert_eq!(
            first[0].ie_type,
            pfcp_ie::SRR_ID,
            "SRR ID first (Table 7.5.8.6-1)"
        );
        assert_eq!(first[0].value, vec![1]);
        assert_eq!(ParsedIe::find_all_ies(&first, 247).len(), 2, "QFIs 5 and 7");
        // Golden bytes of one QoS Monitoring Report IE: QFI 5, RPPD 40 ms, Time Stamp.
        assert_eq!(
            first[1].value,
            vec![
                0x00, 0x7c, 0x00, 0x01, 0x05, // QFI
                0x00, 0xf8, 0x00, 0x05, 0x04, 0x00, 0x00, 0x00, 0x28, // IE 248: RPPD, 40
                0x00, 0x9c, 0x00, 0x04, 0xe8, 0xa0, 0x00, 0x01, // Time Stamp (156)
            ]
        );
    }

    #[tokio::test]
    async fn an_establishment_s_create_srr_is_not_acted_on_without_qos_flow_monitoring() {
        // #1451 review m4: the establishment twin of the modification gate.
        let (server, smf, addr, _rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let assoc = build_association_setup_request_payload(Some(1));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let mut b = crate::n4_build::PfcpMessageBuilder::new();
        b.add_node_id(&NodeId::Ipv4(Ipv4Addr::new(127, 0, 0, 9)));
        b.add_f_seid(&crate::n4_build::FSeid {
            seid: 0x4444,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 9)),
            ipv6: None,
        });
        b.add_tlv(pfcp_ie::CREATE_PDR, &pdr_body(1, 100, 1, 1, 1));
        b.add_tlv(pfcp_ie::CREATE_FAR, &far_body(1, 0x02));
        b.add_tlv(pfcp_ie::CREATE_SRR, &srr_body(2, &[5]));
        let resp = exchange(&smf, addr, &encode_pfcp(50, Some(0), 2, &b.build())).await;
        assert_eq!(response_cause(&resp), PfcpCause::RequestAccepted as u8);
        let upf_seid = *server.sessions.read().await.keys().next().unwrap();
        assert!(server.sessions.read().await[&upf_seid]
            .rules
            .srr_ids
            .is_empty());
        assert!(
            !dp.with_qos_flow_monitor(|m| m.is_active()),
            "nothing monitored"
        );
    }

    #[tokio::test]
    async fn losing_the_association_ends_monitoring_with_no_data_plane_session() {
        // #1451 review m5: a monitored SEID whose data-plane install never
        // happened is still cleared when the association goes.
        let (server, smf, addr, _rx) = spawn_test_server().await;
        server.set_qos_flow_monitoring(true);
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let assoc = build_association_setup_request_payload(Some(100));
        let _ = exchange(&smf, addr, &encode_pfcp(5, None, 1, &assoc)).await;
        let srr = crate::n4_build::parse_srr(&srr_body(1, &[5])).unwrap();
        server.apply_srrs(0x77, &[], &[srr], &[]);
        assert!(dp.with_qos_flow_monitor(|m| m.is_active()));
        assert!(
            dp.sessions.find_by_seid(0x77).is_none(),
            "no data-plane session"
        );
        // A heartbeat with a new Recovery Time Stamp: the peer restarted.
        let mut hb = crate::n4_build::PfcpMessageBuilder::new();
        hb.add_u32(pfcp_ie::RECOVERY_TIME_STAMP, 200);
        let _ = exchange(&smf, addr, &encode_pfcp(1, None, 2, &hb.build())).await;
        for _ in 0..50 {
            if !dp.with_qos_flow_monitor(|m| m.is_active()) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the monitor outlived the association");
    }

    #[tokio::test]
    async fn a_report_for_a_session_gone_from_the_pfcp_table_ends_its_monitoring() {
        let (server, _smf, _addr, _rx) = spawn_test_server().await;
        let dp = Arc::new(crate::data_plane::DataPlane::new(Arc::new(
            AtomicBool::new(false),
        )));
        server.set_data_plane(dp.clone());
        let srr = crate::n4_build::parse_srr(&srr_body(1, &[5])).unwrap();
        server.apply_srrs(0x78, &[], &[srr], &[]);
        let rep = nextgcore_pfcp::qos_monitoring::QosMonitoringReport::default();
        assert!(server
            .send_qos_monitoring_report(0x78, &[(1, rep)])
            .await
            .is_err());
        assert!(!dp.with_qos_flow_monitor(|m| m.is_active()));
    }
}
