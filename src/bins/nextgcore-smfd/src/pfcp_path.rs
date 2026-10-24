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
    /// Our own Recovery Time Stamp (seconds since the epoch at startup)
    pub recovery_time_stamp: u32,
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

/// Drop the session → UPF binding once the session is deleted.
pub fn forget_session_peer(smf_n4_seid: u64) {
    if let Ok(mut map) = session_peers().write() {
        map.remove(&smf_n4_seid);
    }
    forget_session_bridge_info(smf_n4_seid);
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
    let peer = session_peers()
        .read()
        .ok()
        .and_then(|map| map.get(&smf_n4_seid).copied());
    if let Some(peer) = peer {
        if let Some(client) = global_pool().into_iter().find(|c| c.peer() == peer) {
            return Some(client);
        }
    }
    global_client()
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
        let recovery_time_stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(1);
        Self {
            socket,
            peer: std::sync::RwLock::new(peer),
            peer_host: None,
            node_ip,
            node_id: NodeId::new_ipv4(node_ip),
            recovery_time_stamp,
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

    /// Whether the N4 association is currently established.
    pub async fn is_associated(&self) -> bool {
        self.assoc.read().await.associated
    }

    /// Snapshot of the association state.
    pub async fn association(&self) -> AssociationState {
        self.assoc.read().await.clone()
    }

    /// Install a peer Recovery Time Stamp learned from a durable snapshot rather
    /// than from the wire (issue #191).
    ///
    /// This is what makes restoring the PFCP session map safe across an SMF
    /// restart. `check_peer_restart` can only detect a restart when it has a
    /// stored stamp to compare against, and a fresh process has `None` — so
    /// without this seed the first Association Setup after a reload accepts
    /// whatever stamp the UPF reports and the restored sessions are never
    /// questioned, even when the UPF restarted meanwhile and holds none of them.
    ///
    /// Deliberately does **not** set `associated`: the association still has to be
    /// established on the wire. Only the restart-detection input is restored.
    pub async fn seed_peer_recovery_time_stamp(&self, rts: u32) {
        let mut assoc = self.assoc.write().await;
        assoc.peer_recovery_time_stamp = Some(rts);
        log::info!(
            "PFCP {}: seeded peer Recovery Time Stamp {rts} from durable state; a different \
             stamp at Association Setup will flush the restored sessions",
            self.peer()
        );
    }

    /// Test-only: force association/load state. Unit tests cannot run the
    /// full Association Setup handshake for every selection scenario.
    #[cfg(test)]
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
            self.publish_associated(&assoc);
        }

        result
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
                // Staleness detection on the peer's Recovery Time Stamp
                if let Some(rts) = find_ie(body, 96)
                    .filter(|v| v.len() >= 4)
                    .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
                {
                    self.check_peer_restart(rts).await;
                }
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
                true
            }
            pfcp_message_type::ASSOCIATION_RELEASE_REQUEST => {
                log::warn!("PFCP Association Release Request from {from}");
                // Respond Node ID + Cause accepted via the library codec
                let msg = PfcpMessage::AssociationReleaseResponse(
                    nextgcore_pfcp::message::AssociationReleaseResponse::new(
                        self.node_id.clone(),
                        nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                    ),
                );
                let resp = build_message(&msg, header.sequence_number, None);
                let _ = self.socket.send_to(&resp, from).await;
                self.teardown_association("association released by peer")
                    .await;
                true
            }
            _ => false, // e.g. Session Report Request — handled by main.rs
        }
    }

    /// Compare a peer Recovery Time Stamp with the stored value; a change
    /// means the UPF restarted: all sessions on it are gone (TS 23.527 4.2).
    pub async fn check_peer_restart(&self, rts: u32) {
        self.detect_peer_restart(rts).await;
    }

    /// [`Self::check_peer_restart`], reporting whether a restart was detected (and
    /// the association torn down).
    async fn detect_peer_restart(&self, rts: u32) -> bool {
        let restarted = {
            let assoc = self.assoc.read().await;
            matches!(assoc.peer_recovery_time_stamp, Some(stored) if stored != rts)
        };
        if restarted {
            log::error!(
                "UPF {} restarted (recovery time stamp changed to {rts})",
                self.peer()
            );
            self.teardown_association("peer restarted").await;
            // Remember the new incarnation so re-association succeeds
            self.assoc.write().await.peer_recovery_time_stamp = Some(rts);
            // Issue #191: durably too, so a restart detected on a heartbeat is not
            // re-detected (or worse, missed) after an SMF restart.
            self.record_peer_recovery_time_stamp(rts);
        }
        restarted
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
        self.teardown_association_until(reason, None).await;
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
        #[cfg(test)]
        assert_teardown_is_serialised();
        // #720: only the sessions on THIS UPF. A pool member's restart, release or
        // heartbeat loss says nothing about the sessions on the other members, which
        // are alive; releasing them sent every UE in the pool a #39 and orphaned
        // their sessions on the healthy UPFs.
        let scope = self.session_scope();
        // #687: the EPC PDN connections on this PGW-U, which have no SM context. First,
        // so no fan-out deadline can cut them (#941 review M1).
        let epc_released =
            crate::restoration::release_epc_pdn_connections_in(reason, Some(&scope)).await;
        let notified =
            crate::restoration::notify_sessions_unrecoverable_until(reason, Some(&scope), deadline)
                .await;
        {
            let mut assoc = self.assoc.write().await;
            assoc.associated = false;
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

        // Restart detection against any previously stored timestamp
        let restarted = self.detect_peer_restart(resp.recovery_time_stamp).await;
        // #718: retention was asked for and the UP function did not confirm it
        // (PSREI, TS 29.244 §8.2.134). The sessions are gone there: it deleted them,
        // or it never had them. Believing them anyway would leave every one dead
        // until the UE noticed, so release them as a restart would.
        if retention_requested && !restarted && !sessions_retained(&resp_body) {
            log::warn!(
                "UPF {} did not retain the PFCP sessions this SMF holds (no PSREI in the \
                 Association Setup Response)",
                self.peer()
            );
            self.teardown_association("UPF did not retain the sessions")
                .await;
        }

        {
            let mut assoc = self.assoc.write().await;
            assoc.associated = true;
            assoc.peer_recovery_time_stamp = Some(resp.recovery_time_stamp);
            assoc.up_function_features = resp.up_function_features;
            self.publish_associated(&assoc);
            log::info!(
                "PFCP association established with {} (peer RTS={}, UP features={:?})",
                self.peer(),
                resp.recovery_time_stamp,
                assoc
                    .up_function_features
                    .as_ref()
                    .map(|f| (f.ftup, f.empu, f.bucp))
            );
        }
        // Issue #191: record the stamp durably so the NEXT process can compare
        // against it. Scoped after the async guard drops, and the std lock is not
        // held across an await.
        self.record_peer_recovery_time_stamp(resp.recovery_time_stamp);
        Ok(())
    }

    /// Store the peer's Recovery Time Stamp in the SMF context so it reaches the
    /// durable snapshot (issue #191). A no-op when persistence is disabled.
    fn record_peer_recovery_time_stamp(&self, rts: u32) {
        let peer = self.peer().to_string();
        if let Ok(ctx) = smf_self().read() {
            ctx.note_upf_recovery_time_stamp(&peer, rts);
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
            self.check_peer_restart(rts).await;
        } else {
            log::warn!("Heartbeat Response missing Recovery Time Stamp (mandatory IE)");
        }
        Ok(true)
    }
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

/// Whether `client` is the UPF the session with SMF-side N4 SEID `seid` lives on.
///
/// The recorded peer when it is this client's. Otherwise the routing
/// [`client_for_session`] applies: a session with no record (restored from durable
/// state, where the binding is not persisted), or whose recorded peer no pool
/// member has any more (a hostname UPF re-resolved), goes to the default client.
fn session_served_by(seid: u64, client: &PfcpClient) -> bool {
    let recorded = session_peers()
        .read()
        .ok()
        .and_then(|map| map.get(&seid).copied());
    if recorded == Some(client.peer()) {
        return true;
    }
    let routed_elsewhere =
        recorded.is_some_and(|peer| global_pool().iter().any(|c| c.peer() == peer));
    !routed_elsewhere && global_client().is_some_and(|c| std::ptr::eq(Arc::as_ptr(&c), client))
}

/// Whether this SMF holds a PFCP session on `client`'s UPF (#718 review M1).
///
/// Scoped to the peer. In a UPF pool, a member that associates late, or again
/// after its own heartbeat loss, holds none of the sessions on the other members;
/// asking it to retain them, and then releasing them all when it answered without
/// PSREI, released every UE on the healthy UPFs.
fn holds_pfcp_sessions_on(client: &PfcpClient) -> bool {
    held_session_seids()
        .into_iter()
        .any(|seid| session_served_by(seid, client))
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
        let five_g: Vec<(String, u64)> = five_g
            .into_iter()
            .filter(|(_, seid)| session_served_by(*seid, self))
            .collect();
        let epc: Vec<(u64, u64)> = epc
            .into_iter()
            .filter(|(_, seid)| session_served_by(*seid, self))
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
///   `pfcp_session_establish` proceeds or bails.
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
pub(crate) static N4_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        /// Answer Session Modifications with no Created PDR (#751): an incomplete
        /// answer to a request that created PDRs with CHOOSE.
        omit_created_pdrs: Arc<std::sync::atomic::AtomicBool>,
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
        _n4_guard: tokio::sync::MutexGuard<'static, ()>,
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
        let omit = omit_created_pdrs.clone();
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
                            let pdrs = create_pdrs(req_body);
                            let choose: Vec<&[u8]> = pdrs
                                .iter()
                                .copied()
                                .filter(|pdr| {
                                    find_ie(pdr, 2)
                                        .and_then(|pdi| find_ie(pdi, 21))
                                        .is_some_and(|f| f.len() >= 5 && f[1..5] == [0; 4])
                                })
                                .collect();
                            let answered = if choose.is_empty() {
                                pdrs.into_iter().take(1).collect()
                            } else {
                                choose
                            };
                            for (k, pdr) in answered.into_iter().enumerate() {
                                let Some(pdr_id) = find_ie(pdr, 56).filter(|v| v.len() >= 2) else {
                                    continue;
                                };
                                let mut f_teid = vec![0x01];
                                f_teid.extend_from_slice(
                                    &(N3_STAND_IN_TEID + k as u32).to_be_bytes(),
                                );
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
                    pfcp_message_type::SESSION_DELETION_REQUEST => Some(encode_wire_message(
                        pfcp_message_type::SESSION_DELETION_RESPONSE,
                        Some(h.seid),
                        h.sequence_number,
                        &tlv(
                            19,
                            &[answered_cause.load(std::sync::atomic::Ordering::SeqCst)],
                        ),
                    )),
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
            omit_created_pdrs,
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
        _n4_guard: tokio::sync::MutexGuard<'static, ()>,
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
        assert_eq!(st.peer_recovery_time_stamp, Some(777));
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
    /// re-resolves the name and lands on the new UPF, whose different Recovery
    /// Time Stamp then flushes the old sessions.
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
            Some(2000),
            "the new incarnation's stamp replaces the old one"
        );
    }

    /// Answer one Association Setup Request on `upf` with Request Accepted, the
    /// Recovery Time Stamp `rts`, and PSREI when `psrei`; returns the request body.
    async fn answer_association_setup(upf: UdpSocket, rts: u32, psrei: bool) -> Vec<u8> {
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
        client.seed_peer_recovery_time_stamp(600).await;
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
        // The same UPF incarnation: no restart, so only PSREI can tell.
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
        if let Ok(ctx) = smf_self().read() {
            for s in [&epc_a, &epc_b] {
                forget_session_peer(s.smf_n4_seid);
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
            Some(200),
            "new incarnation timestamp stored"
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

    // ── #191: a seeded stamp is what makes a restored session map checkable ──
    //
    // These two drive the process-global session map, as `test_teardown_clears_
    // load_state` above already does via `teardown_association`. Safe because no
    // smfd test asserts on the *contents* of the global `pfcp_sessions` map, and
    // each of these asserts only about its own uniquely-named key rather than
    // about the map being empty.

    /// A stamp restored from a snapshot must participate in restart detection.
    /// Without the seed a fresh process holds `None`, no restart is detectable,
    /// and the restored sessions are never questioned.
    #[tokio::test]
    async fn a_seeded_recovery_time_stamp_makes_a_peer_restart_detectable() {
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
            Some(200),
            "the new incarnation is remembered so re-association succeeds"
        );
    }

    /// The other half of the interlock: an unchanged stamp means the UPF did NOT
    /// restart, so the restored sessions are genuinely still valid and must be
    /// left alone. Without this, "flush on restart" could be satisfied by a
    /// version that flushes unconditionally — which would make the whole snapshot
    /// pointless.
    #[tokio::test]
    async fn an_unchanged_recovery_time_stamp_leaves_restored_sessions_alone() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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
    /// point production uses: a changed Recovery Time Stamp on a heartbeat or
    /// association reaches `check_peer_restart`, which tears the association
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
