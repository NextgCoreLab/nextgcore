//! SGWU GTP-U Path Management (TS 29.281)
//!
//! Port of src/sgwu/gtp-path.c. Owns the real GTP-U UDP socket (port 2152)
//! and the user-plane forwarding path: G-PDU in -> PDR match by TEID ->
//! FAR apply (FORW/BUFF/DROP) -> G-PDU out. All wire framing goes through
//! the nextgcore-gtp GTPv1-U codec; Echo Response carries the mandatory Recovery
//! IE and Error Indication carries Tunnel Endpoint Identifier Data I +
//! GTP-U Peer Address as proper IEs (TS 29.281 Section 7.3.1).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;

use nextgcore_gtp::v1::header::{Gtp1cMessageType, Gtp1uMessageType};
use nextgcore_gtp::v1::message::{ErrorIndication, Gtp1Message};
use nextgcore_gtp::GTPV1_U_UDP_PORT;

use crate::context::{apply_action, sgwu_self, SgwuFar, SgwuPdr};
use crate::pfcp_path;
use crate::sxa_build::{LocalFTeid, UserPlaneReport};

/// Default GTP-U bind address (TS 29.281 Section 4.4.2.3)
const DEFAULT_GTPU_BIND: &str = "0.0.0.0:2152";

// ============================================================================
// GTP-U Receive Result
// ============================================================================

/// Outcome of processing one received GTP-U datagram
#[derive(Debug)]
pub enum GtpuRecvResult {
    /// Packet handled (echo, end marker, ...)
    Handled,
    /// Echo response sent
    EchoResponse,
    /// G-PDU forwarded per FAR
    Forwarded,
    /// G-PDU buffered per FAR (BUFF)
    Buffered,
    /// Error Indication sent (no PDR matched)
    ErrorIndication,
    /// A Session Report was sent to the SGW-C
    SessionReport(UserPlaneReport),
    /// Packet dropped
    Dropped(String),
}

// ============================================================================
// GTP-U Server
// ============================================================================

struct GtpuInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    /// Destination UDP port for forwarded G-PDUs (2152 in deployment;
    /// configurable so tests can target ephemeral peers)
    peer_port: u16,
    running: AtomicBool,
}

/// GTP-U server bound to the S1-U/S5-U interface
#[derive(Clone)]
pub struct GtpuServer {
    inner: Arc<GtpuInner>,
}

impl GtpuServer {
    /// Bind the GTP-U socket and start the receive loop
    pub fn open(bind: &str, peer_port: u16) -> Result<Self, String> {
        let socket = UdpSocket::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| e.to_string())?;
        let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

        let inner = Arc::new(GtpuInner {
            socket,
            local_addr,
            peer_port,
            running: AtomicBool::new(true),
        });

        {
            let inner = inner.clone();
            std::thread::Builder::new()
                .name("sgwu-gtpu-recv".into())
                .spawn(move || {
                    let server = GtpuServer {
                        inner: inner.clone(),
                    };
                    let mut buf = [0u8; 9000];
                    let mut last_probe = Instant::now();
                    while inner.running.load(Ordering::SeqCst) {
                        // GTP-U path management (TS 23.007 Section 20.3.1): probe
                        // each peer we forward to and count unanswered Echoes.
                        // Driven from the receive loop, whose 100 ms read timeout
                        // gives it a cadence without a second thread to shut down.
                        if let Some(interval) = gtpu_echo_interval() {
                            if last_probe.elapsed() >= interval {
                                last_probe = Instant::now();
                                echo_round(|ip| {
                                    let dest = SocketAddr::new(ip, inner.peer_port);
                                    let echo = Gtp1Message::echo_request(0, 0).encode();
                                    if let Err(e) = inner.socket.send_to(&echo, dest) {
                                        log::warn!("GTP-U Echo Request to {dest} failed: {e}");
                                    }
                                });
                            }
                        }
                        match inner.socket.recv_from(&mut buf) {
                            Ok((len, peer)) => {
                                handle_gtpu_packet(&server, &buf[..len], peer);
                            }
                            Err(e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(e) => {
                                if inner.running.load(Ordering::SeqCst) {
                                    log::error!("GTP-U recv error: {e}");
                                }
                            }
                        }
                    }
                })
                .map_err(|e| e.to_string())?;
        }

        log::info!("GTP-U server listening on {local_addr}");
        Ok(Self { inner })
    }

    /// Stop the receive loop
    pub fn close(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Local bound address
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> Result<(), String> {
        self.inner
            .socket
            .send_to(packet, peer)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Resolve a FAR's Outer Header Creation into a peer socket address
    fn far_peer(&self, far: &SgwuFar) -> Option<(u32, SocketAddr)> {
        let (teid, v4, v6) = far.outer_header_creation.as_ref()?;
        let ip: IpAddr = match (v4, v6) {
            (Some(v4), _) => IpAddr::V4(*v4),
            (None, Some(v6)) => IpAddr::V6(*v6),
            (None, None) => return None,
        };
        Some((*teid, SocketAddr::new(ip, self.inner.peer_port)))
    }

    /// Forward a payload as a G-PDU per the FAR's Outer Header Creation
    fn forward_gpdu(&self, far: &SgwuFar, payload: &[u8]) -> Result<(), String> {
        let (teid, peer) = self
            .far_peer(far)
            .ok_or_else(|| format!("FAR {} has no outer header creation", far.far_id))?;
        let packet = Gtp1Message::gpdu(teid, Bytes::copy_from_slice(payload)).encode();
        self.send_to(&packet, peer)?;
        log::trace!(
            "FORW G-PDU FAR {} -> TEID=0x{:x} peer={} len={}",
            far.far_id,
            teid,
            peer,
            packet.len()
        );
        Ok(())
    }

    /// Send an End Marker through a FAR (TS 23.214 / TS 29.281 Section 7.3.2)
    pub fn send_end_marker(&self, sess_id: u64, far_id: u32) -> Result<(), String> {
        let ctx = sgwu_self();
        let far = ctx
            .far_find(sess_id, far_id)
            .ok_or_else(|| format!("FAR {far_id} not found"))?;
        let (teid, peer) = self
            .far_peer(&far)
            .ok_or_else(|| format!("FAR {far_id} has no outer header creation"))?;
        let packet = Gtp1Message::end_marker(teid).encode();
        self.send_to(&packet, peer)?;
        log::debug!("End Marker FAR {far_id} -> TEID=0x{teid:x} peer={peer}");
        Ok(())
    }

    /// Send any packets buffered on a FAR (BUFF -> FORW transition,
    /// TS 29.244 Section 5.3.1)
    pub fn send_buffered_packets(&self, sess_id: u64, far_id: u32) -> usize {
        let ctx = sgwu_self();
        let Some(far) = ctx.far_find(sess_id, far_id) else {
            return 0;
        };
        // #831 review: drain in steps until the queue is empty, which also ends the
        // flush (`far_flush_step`). Packets that queued behind the flush while it ran
        // are sent after the ones ahead of them, in arrival order.
        let mut sent = 0;
        loop {
            let batch = ctx.far_flush_step(sess_id, far_id);
            if batch.is_empty() {
                break;
            }
            for payload in &batch {
                match self.forward_gpdu(&far, payload) {
                    Ok(()) => sent += 1,
                    Err(e) => log::error!("Failed to send buffered packet: {e}"),
                }
            }
        }
        if sent > 0 {
            log::debug!("Sent {sent} buffered packets for FAR {far_id}");
        }
        sent
    }
}

// ============================================================================
// Global server instance (process lifecycle)
// ============================================================================

static GTPU_SERVER: OnceLock<GtpuServer> = OnceLock::new();

/// Get the global GTP-U server, if open
pub fn gtpu_server() -> Option<&'static GtpuServer> {
    GTPU_SERVER.get()
}

/// Initialize GTP-U subsystem
/// Port of sgwu_gtp_init
pub fn gtp_init() -> Result<(), String> {
    log::info!("GTP-U subsystem initialized");
    Ok(())
}

/// Finalize GTP-U subsystem
/// Port of sgwu_gtp_final
pub fn gtp_final() {
    log::info!("GTP-U subsystem finalized");
}

/// Open the GTP-U server socket
/// Port of sgwu_gtp_open
pub fn gtp_open() -> Result<(), String> {
    if GTPU_SERVER.get().is_some() {
        return Ok(());
    }

    let bind = std::env::var("SGWU_GTPU_BIND").unwrap_or_else(|_| DEFAULT_GTPU_BIND.to_string());
    let server = GtpuServer::open(&bind, GTPV1_U_UDP_PORT)?;

    // Advertise the bound address in allocated F-TEIDs, unless a distinct
    // advertise address is configured (e.g. behind NAT or wildcard bind)
    let ctx = sgwu_self();
    // Wildcard bind: SGWU_GTPU_ADVERTISE, then `sgwu.gtpu.server[0].address`
    // (#482). The SGW-U IS the user-plane node, so its configured GTP-U address is
    // the right one to put in F-TEIDs.
    let advertised = match server.local_addr().ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => std::env::var("SGWU_GTPU_ADVERTISE")
            .ok()
            .and_then(|v| v.parse::<Ipv4Addr>().ok())
            .or(crate::config::config().gtpu_ip),
    };
    ctx.set_gtpu_address(advertised);

    GTPU_SERVER
        .set(server)
        .map_err(|_| "GTP-U server already open".to_string())?;
    Ok(())
}

/// Close the GTP-U server socket
/// Port of sgwu_gtp_close
pub fn gtp_close() {
    if let Some(server) = GTPU_SERVER.get() {
        server.close();
    }
    log::info!("GTP-U server closed");
}

// ============================================================================
// Packet processing
// ============================================================================

/// Handle one received GTP-U datagram
/// Port of _gtpv1_u_recv_cb
pub fn handle_gtpu_packet(server: &GtpuServer, data: &[u8], peer: SocketAddr) -> GtpuRecvResult {
    let mut bytes = Bytes::copy_from_slice(data);
    let msg = match Gtp1Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            log::error!("[DROP] Cannot decode GTP-U packet from {peer}: {e}");
            return GtpuRecvResult::Dropped(format!("decode: {e}"));
        }
    };

    let msg_type = msg.header.message_type;
    match msg_type {
        t if t == Gtp1cMessageType::EchoRequest as u8 => handle_echo_request(server, &msg, peer),
        t if t == Gtp1cMessageType::EchoResponse as u8 => {
            // TS 23.007 Section 20.3.1: an Echo Response confirms the path, so it
            // clears the unanswered counter. Discarding it, as before, meant no
            // probe could ever be resolved and the path state never recovered.
            note_echo_answered(peer.ip());
            // TS 29.281 Section 8.2: the Recovery value in GTP-U shall be
            // ignored by the receiver; the response just confirms the path.
            log::debug!("[RECV] GTP-U Echo Response from {peer}");
            GtpuRecvResult::Handled
        }
        t if t == Gtp1uMessageType::ErrorIndication as u8 => handle_error_indication(&msg, peer),
        t if t == Gtp1uMessageType::EndMarker as u8 => handle_end_marker(server, &msg, peer),
        t if t == Gtp1uMessageType::GPdu as u8 => handle_gpdu(server, &msg, peer),
        other => {
            log::error!("[DROP] Invalid GTP-U message type [{other}] from {peer}");
            GtpuRecvResult::Dropped(format!("unknown type {other}"))
        }
    }
}

// ============================================================================
// GTP-U path management (TS 23.007 Section 20.3)
// ============================================================================

/// Default Echo probe interval toward each known GTP-U peer. `0` disables
/// probing. TS 23.007 Section 20.3.1 requires path-failure detection via Echo;
/// the cadence is a deployment choice.
const DEFAULT_GTPU_ECHO_INTERVAL_SECS: u64 = 60;

/// Default unanswered Echo Requests before the path is declared down
/// (N3-REQUESTS, TS 23.007 Section 20.3.1).
const DEFAULT_N3_REQUESTS: u32 = 3;

/// Per-peer GTP-U path state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GtpuPathState {
    /// Consecutive Echo Requests sent with no Echo Response.
    pub unanswered: u32,
    /// True once `unanswered` has exceeded N3-REQUESTS.
    pub failed: bool,
}

/// GTP-U path table keyed by peer IP.
static GTPU_PATHS: OnceLock<std::sync::Mutex<HashMap<IpAddr, GtpuPathState>>> = OnceLock::new();

/// Serialises the tests that assert on [`GTPU_PATHS`] as a whole, or that set
/// `SGWU_GTPU_N3_REQUESTS`.
///
/// Declared here beside the global rather than in `mod tests`, so there is one
/// agreement about it. Needed because `failed_gtpu_paths()` returns the WHOLE table:
/// two tests failing different peers concurrently each see the other's peer in the
/// list, and the symptom is an assertion about peer B reporting peer A — which reads
/// as a per-peer bug in the code under test rather than as test interference. `N3` is
/// worse: it is a process-wide env var, so one test lowering it changes how many
/// unanswered Echoes another test needs. `SGWU_GTPU_ECHO_INTERVAL_SECS` is covered
/// too: it decides whether an open GTP-U server's probe thread writes the table.
///
/// Every test that writes the table holds it, the async `pfcp_path` Node Report
/// tests included (#827: they held only `SXA_TEST_LOCK`, so their failed peer
/// showed up in `path_state_is_per_peer`'s whole-table assertion). It is a tokio
/// mutex so those tests can hold it across `.await`; the sync tests take it with
/// `blocking_lock()`. Lock order: `SXA_TEST_LOCK` first, then this.
///
/// Two production paths also write the table and cannot take a test lock: the
/// probe thread of every open `GtpuServer` (after `SGWU_GTPU_ECHO_INTERVAL_SECS`,
/// default 60 s) and the Echo Response receive arm. No test today runs a server
/// long enough to probe or sends one an Echo Response (#841 review). A test that
/// lowers the interval, or sends an Echo Response to a test server, must hold
/// this lock for its whole run.
#[cfg(test)]
pub(crate) static GTPU_PATH_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Forgets a test's peer when the test ends, pass or fail, so a later test's
/// whole-table assertion does not see it (#827). Declare it after taking
/// [`GTPU_PATH_TEST_LOCK`] so it drops while the lock is still held.
#[cfg(test)]
pub(crate) struct ForgetPathOnDrop(pub(crate) IpAddr);

#[cfg(test)]
impl Drop for ForgetPathOnDrop {
    fn drop(&mut self) {
        forget_gtpu_path(self.0);
    }
}

fn gtpu_paths() -> &'static std::sync::Mutex<HashMap<IpAddr, GtpuPathState>> {
    GTPU_PATHS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Echo probe interval, or `None` when probing is disabled
/// (`SGWU_GTPU_ECHO_INTERVAL_SECS=0`).
fn gtpu_echo_interval() -> Option<Duration> {
    let secs = std::env::var("SGWU_GTPU_ECHO_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_GTPU_ECHO_INTERVAL_SECS);
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// N3-REQUESTS: unanswered Echoes tolerated before the path is down.
fn n3_requests() -> u32 {
    std::env::var("SGWU_GTPU_N3_REQUESTS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_N3_REQUESTS)
}

/// Peers this SGW-U currently forwards to, from the installed FARs' Outer Header
/// Creation. These are the paths TS 23.007 Section 20.3.1 says to probe: the ones
/// we are "in contact with".
pub fn gtpu_peer_addresses() -> Vec<IpAddr> {
    let mut peers: Vec<IpAddr> = sgwu_self()
        .far_ohc_peers()
        .into_iter()
        .map(IpAddr::V4)
        .collect();
    peers.sort();
    peers.dedup();
    peers
}

/// Record that an Echo Request went unanswered, returning the new state.
///
/// The path is declared down once the counter EXCEEDS N3-REQUESTS, matching
/// Section 20.3.1's "down if the counter exceeds N3-REQUESTS" rather than
/// "reaches", which would fail a path one probe early.
pub fn note_echo_unanswered(peer: IpAddr) -> GtpuPathState {
    let limit = n3_requests();
    let (state, transitioned) = {
        let Ok(mut paths) = gtpu_paths().lock() else {
            return GtpuPathState::default();
        };
        let state = paths.entry(peer).or_default();
        state.unanswered = state.unanswered.saturating_add(1);
        let mut transitioned = false;
        if state.unanswered > limit && !state.failed {
            state.failed = true;
            transitioned = true;
            log::error!(
                "GTP-U path to {peer} is DOWN: {} unanswered Echo Requests exceeds \
                 N3-REQUESTS={limit} (TS 23.007 Section 20.3.1)",
                state.unanswered
            );
        }
        (state.clone(), transitioned)
    };
    // Report on the TRANSITION only (#217). Every further probe round for a peer
    // already known down re-enters this function, and reporting each time would be a
    // Node Report storm toward the SGW-C for one failure. The path lock is released
    // first: the report enqueues onto the async node, and holding a data-path mutex
    // across that is how the forwarding threads would come to wait on the control
    // plane.
    if transitioned {
        report_path_transition(peer, crate::pfcp_path::PathReport::Failure);
    }
    state
}

/// Send the Node Report for a path transition, or say why it could not be sent
/// (TS 23.007 §20.3.4 / §20.3.5.1).
///
/// A failure to report is logged at `warn` and NOT retried here: the transport
/// already retransmits T1×N1, and the two remaining reasons — no association yet, or
/// no transport running — are both states in which there is no SGW-C to tell. Silence
/// would be the wrong answer because the SGW-C then never learns the path is down,
/// which is the whole defect #217 names.
fn report_path_transition(peer: IpAddr, report: crate::pfcp_path::PathReport) {
    if let Err(e) = crate::pfcp_path::send_node_report_request(&[peer], report) {
        log::warn!("GTP-U path {report:?} for {peer} was NOT reported to the SGW-C: {e}");
    }
}

/// Record an Echo Response, clearing the path's failure state.
pub fn note_echo_answered(peer: IpAddr) -> GtpuPathState {
    let (state, recovered) = {
        let Ok(mut paths) = gtpu_paths().lock() else {
            return GtpuPathState::default();
        };
        // #831 review: UPDATE an existing entry only. An Echo Response from a peer we
        // never probed -- or a spoofed one -- has no counter to clear and no failure to
        // recover; inserting it let any sender grow this table without bound.
        let Some(state) = paths.get_mut(&peer) else {
            return GtpuPathState::default();
        };
        let recovered = state.failed;
        if recovered {
            log::warn!(
                "GTP-U path to {peer} RECOVERED after {} misses",
                state.unanswered
            );
        }
        state.unanswered = 0;
        state.failed = false;
        (state.clone(), recovered)
    };
    // The recovery is a transition too, and reported for the same reason (#217): an
    // SGW-C that suspended or tore down state on the failure has no other way to
    // learn it can stop. Only a path that was actually DOWN recovers — an answered
    // Echo on a healthy path reports nothing.
    if recovered {
        report_path_transition(peer, crate::pfcp_path::PathReport::Recovery);
    }
    state
}

/// Current path state for a peer.
pub fn gtpu_path_state(peer: IpAddr) -> GtpuPathState {
    gtpu_paths()
        .lock()
        .ok()
        .and_then(|p| p.get(&peer).cloned())
        .unwrap_or_default()
}

/// Peers whose path is currently down.
pub fn failed_gtpu_paths() -> Vec<IpAddr> {
    let Ok(paths) = gtpu_paths().lock() else {
        return Vec::new();
    };
    let mut failed: Vec<IpAddr> = paths
        .iter()
        .filter(|(_, s)| s.failed)
        .map(|(ip, _)| *ip)
        .collect();
    failed.sort();
    failed
}

/// One Echo round (TS 23.007 §20.3.1): prune the path table to the live peers,
/// count the previous round's probe to each live peer as missed (a response since
/// then has already cleared it), and `send` the next probe. Factored out of the
/// receive loop so the round itself -- not just its parts -- is testable (#831).
pub fn echo_round(mut send: impl FnMut(IpAddr)) {
    let peers = gtpu_peer_addresses();
    // #823: a peer no FAR references any more is not a path we are "in contact
    // with"; its entry goes, or the table keeps every peer ever seen.
    prune_gtpu_paths(&peers);
    for ip in peers {
        note_echo_unanswered(ip);
        send(ip);
    }
}

/// Drop the path state of every peer not in `current` -- the peers some FAR still
/// forwards to (#823) -- EXCEPT a peer whose path is DOWN (#831 review). The table is
/// then bounded by the live peers plus the real peers that failed, instead of by
/// every peer ever seen. A failed path is kept because forgetting it would make the
/// peer look healthy when FARs to it return, and the SGW-C would never receive the
/// Recovery report (TS 23.007 §20.3.4) for the failure it was told about.
pub fn prune_gtpu_paths(current: &[IpAddr]) {
    if let Ok(mut paths) = gtpu_paths().lock() {
        paths.retain(|ip, state| current.contains(ip) || state.failed);
    }
}

/// Forget a peer's path state (used when no FAR references it any more, so the
/// table does not grow without bound).
pub fn forget_gtpu_path(peer: IpAddr) {
    if let Ok(mut paths) = gtpu_paths().lock() {
        paths.remove(&peer);
    }
}

/// Echo Request -> Echo Response with the mandatory Recovery IE.
/// Per TS 29.281 Section 8.2 the restart counter value shall be set to 0
/// and ignored by the receiver.
fn handle_echo_request(server: &GtpuServer, msg: &Gtp1Message, peer: SocketAddr) -> GtpuRecvResult {
    log::debug!("[RECV] GTP-U Echo Request from {peer}");
    let seq = msg.header.sequence_number.unwrap_or(0);
    let response = Gtp1Message::echo_response(0, seq, 0);
    match server.send_to(&response.encode(), peer) {
        Ok(()) => {
            log::debug!("[SEND] GTP-U Echo Response to {peer}");
            GtpuRecvResult::EchoResponse
        }
        Err(e) => {
            log::error!("Echo Response to {peer} failed: {e}");
            GtpuRecvResult::Dropped(e)
        }
    }
}

/// Error Indication: the peer has no context for a TEID we are sending to.
/// Map it back to the FAR carrying that TEID and report ERIR to the SGW-C
/// (TS 29.244 Section 5.10).
fn handle_error_indication(msg: &Gtp1Message, peer: SocketAddr) -> GtpuRecvResult {
    let parsed = match ErrorIndication::decode(msg) {
        Ok(p) => p,
        Err(e) => {
            log::error!("[DROP] Malformed Error Indication from {peer}: {e}");
            return GtpuRecvResult::Dropped(format!("malformed error indication: {e}"));
        }
    };

    log::warn!(
        "[RECV] Error Indication from {} for TEID 0x{:x}",
        peer,
        parsed.teid
    );

    let ctx = sgwu_self();
    // TS 29.281 Section 7.3.1: the TEID and the GTP-U peer address TOGETHER
    // identify the bearer. Matching on the TEID alone attributes the report to
    // whichever session happens to hold that TEID first, so a collision with
    // another peer names — and may tear down — an unrelated bearer.
    let Some(far) = ctx.far_find_by_ohc_teid_peer(parsed.teid, peer.ip()) else {
        log::warn!(
            "Error Indication TEID 0x{:x} from {} matches no FAR for that peer; dropping \
             rather than attributing it to another peer's session (TS 29.281 Section 7.3.1)",
            parsed.teid,
            peer.ip()
        );
        return GtpuRecvResult::Handled;
    };
    let Some(sess) = ctx.sess_find_by_id(far.sess_id) else {
        return GtpuRecvResult::Handled;
    };

    let peer_v4 = match peer.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    };
    let report = UserPlaneReport {
        error_indication_report: true,
        remote_f_teid: Some(LocalFTeid {
            teid: parsed.teid,
            ipv4: peer_v4,
            ipv6: None,
        }),
        ..Default::default()
    };
    if let Err(e) = pfcp_path::send_session_report_request(&sess, &report) {
        log::error!("Session Report (ERIR) failed: {e}");
    }
    GtpuRecvResult::SessionReport(report)
}

/// End Marker: forward along the same path as G-PDUs for the matched PDR
fn handle_end_marker(server: &GtpuServer, msg: &Gtp1Message, peer: SocketAddr) -> GtpuRecvResult {
    let teid = msg.header.teid;
    log::debug!("[RECV] End Marker from {peer} TEID=0x{teid:x}");

    let ctx = sgwu_self();
    let Some(pdr) = ctx.pdr_find_by_teid(teid) else {
        // TS 29.281 Section 7.3.2.1: "If an End Marker message is received with
        // a TEID for which there is no context, then the receiver shall ignore
        // this message." An Error Indication here is not merely non-conformant:
        // End Markers arrive precisely during a handover path switch, so the
        // race this hits is the normal case, and the peer may read the
        // indication as loss of bearer context.
        log::debug!("End Marker TEID 0x{teid:x} from {peer} matches no PDR; ignoring per spec");
        return GtpuRecvResult::Handled;
    };
    let far = pdr.far_id.and_then(|fid| ctx.far_find(pdr.sess_id, fid));
    if let Some(far) = far {
        if far.apply_action & apply_action::FORW != 0 {
            if let Some((out_teid, out_peer)) = server.far_peer(&far) {
                let packet = Gtp1Message::end_marker(out_teid).encode();
                if let Err(e) = server.send_to(&packet, out_peer) {
                    log::error!("End Marker forward failed: {e}");
                }
            }
        }
    }
    GtpuRecvResult::Handled
}

/// G-PDU: PDR lookup by TEID, then apply the linked FAR
fn handle_gpdu(server: &GtpuServer, msg: &Gtp1Message, peer: SocketAddr) -> GtpuRecvResult {
    let teid = msg.header.teid;
    let payload = match &msg.payload {
        Some(p) => p.as_ref(),
        None => {
            log::warn!("[DROP] G-PDU without payload from {peer}");
            return GtpuRecvResult::Dropped("empty G-PDU".to_string());
        }
    };
    log::trace!(
        "[RECV] G-PDU from {} TEID=0x{:x} len={}",
        peer,
        teid,
        payload.len()
    );

    let ctx = sgwu_self();
    let Some(pdr) = ctx.pdr_find_by_teid(teid) else {
        log::warn!("[DROP] No PDR for TEID 0x{teid:x}: sending Error Indication");
        return send_error_indication(server, teid, peer);
    };

    apply_far(server, &pdr, payload)
}

/// Whether QER enforcement is switched on.
///
/// Off by default: enforcing a gate or an MBR changes forwarding behaviour, so a
/// mis-provisioned QER would drop traffic that flows today. nextgcore #60
/// requires the behaviour-changing half to be gated. `SGWU_QER_ENFORCEMENT=1`
/// enables it.
fn qer_enforcement_enabled() -> bool {
    matches!(
        std::env::var("SGWU_QER_ENFORCEMENT")
            .unwrap_or_default()
            .as_str(),
        "1" | "true" | "yes"
    )
}

/// Serialises the tests that toggle `SGWU_QER_ENFORCEMENT`.
///
/// The variable is PROCESS-GLOBAL. Until #215 only one test touched it, so there
/// was nothing to race with; adding a second made
/// `closed_qer_gate_drops_when_enforcement_is_enabled` fail intermittently with
/// "a CLOSED gate must drop, got Forwarded" — one test's `remove_var` landing
/// while the other had it set. Reproduced in 1 of 6 runs before the lock, then
/// 30 of 30 green after. Same shape as the carried `gtp_path` race over
/// `SGWU_GTPU_N3_REQUESTS`. Declared beside the reader it guards (#841 review),
/// not in `mod tests`.
#[cfg(test)]
pub(crate) static QER_ENFORCEMENT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Per-(session, QER, direction) token buckets for MBR policing.
///
/// **Lock order (#773 review):** `MBR_BUCKETS` -> `SgwuContext::qer_list` (read), taken
/// in [`mbr_allows`] to re-check that a QER is still installed before a bucket is
/// CREATED for it. Nobody may take this mutex while holding `qer_list` (or any other
/// context lock): `sess_remove` and `qer_remove` drop their guards before forgetting
/// buckets, which is what makes the re-check linearizable with them.
static MBR_BUCKETS: std::sync::OnceLock<std::sync::Mutex<HashMap<(u64, u32, bool), MbrBucket>>> =
    std::sync::OnceLock::new();

/// A token bucket sized to one second of the provisioned MBR.
struct MbrBucket {
    /// Tokens in BITS, so the MBR (bits per second) needs no unit conversion.
    tokens: f64,
    last: Instant,
}

/// Whether `len` bytes fit within the QER's MBR (TS 29.244 Section 5.2.5.1).
///
/// A token bucket refilled at the MBR and capped at one second's worth: that cap
/// is the burst tolerance, and without it an idle bearer would accumulate
/// unlimited credit and then blast far above its MBR.
///
/// Returns true (forward) when the bucket cannot be locked — a poisoned lock
/// must not become a traffic black hole.
fn mbr_allows(
    ctx: &crate::context::SgwuContext,
    sess_id: u64,
    qer_id: u32,
    uplink: bool,
    mbr_bps: u64,
    len: usize,
) -> bool {
    let buckets = MBR_BUCKETS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let Ok(mut buckets) = buckets.lock() else {
        return true;
    };
    let now = Instant::now();
    let bits = (len as f64) * 8.0;
    let capacity = mbr_bps as f64;

    let bucket = match buckets.entry((sess_id, qer_id, uplink)) {
        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::hash_map::Entry::Vacant(e) => {
            // #773 review: the caller read the QER BEFORE taking this mutex, so a
            // Session Deletion / Remove QER may have dropped it -- and forgotten its
            // buckets -- in between. Creating a bucket now would leak it for good
            // (session ids are never reused) or hand it to a later QER with the same
            // id. Re-checked under the mutex: a remover forgets AFTER taking the QER
            // out of `qer_list`, so either its forget runs after this insert and
            // removes it, or the QER is already gone here. The rule is gone either
            // way, so the packet is not policed by it.
            if ctx.qer_find(sess_id, qer_id).is_none() {
                return true;
            }
            e.insert(MbrBucket {
                tokens: capacity,
                last: now,
            })
        }
    };
    let elapsed = now.duration_since(bucket.last).as_secs_f64();
    bucket.last = now;
    bucket.tokens = (bucket.tokens + elapsed * capacity).min(capacity);

    if bucket.tokens >= bits {
        bucket.tokens -= bits;
        true
    } else {
        false
    }
}

/// Drop any MBR state held for a session. Called by `SgwuContext::sess_remove`,
/// which every session-removal path goes through (#773), so buckets do not
/// accumulate for dead sessions.
pub fn mbr_forget_session(sess_id: u64) {
    if let Some(buckets) = MBR_BUCKETS.get() {
        if let Ok(mut buckets) = buckets.lock() {
            buckets.retain(|(sid, _, _), _| *sid != sess_id);
        }
    }
}

/// Drop the MBR state of one QER (both directions), on Remove QER (#773).
pub fn mbr_forget_qer(sess_id: u64, qer_id: u32) {
    if let Some(buckets) = MBR_BUCKETS.get() {
        if let Ok(mut buckets) = buckets.lock() {
            buckets.retain(|(sid, qid, _), _| !(*sid == sess_id && *qid == qer_id));
        }
    }
}

/// How many MBR buckets are held for `sess_id` (and, with `qer_id`, that QER).
#[cfg(test)]
pub(crate) fn mbr_bucket_count(sess_id: u64, qer_id: Option<u32>) -> usize {
    MBR_BUCKETS.get().map_or(0, |b| {
        b.lock()
            .unwrap()
            .keys()
            .filter(|(sid, qid, _)| *sid == sess_id && qer_id.is_none_or(|q| q == *qid))
            .count()
    })
}

/// Apply the FAR linked to a PDR to a received payload
fn apply_far(server: &GtpuServer, pdr: &SgwuPdr, payload: &[u8]) -> GtpuRecvResult {
    apply_far_once(server, pdr, payload, false)
}

/// One application of the PDR's FAR. `retried` is set when a BUFF decision was
/// overtaken by an Update FAR (#823) and the packet is re-dispatched against the
/// FAR's new action: QER policing already ran (and consumed MBR tokens) for it, and
/// a second overtake in a row drops the packet rather than looping.
fn apply_far_once(
    server: &GtpuServer,
    pdr: &SgwuPdr,
    payload: &[u8],
    retried: bool,
) -> GtpuRecvResult {
    let ctx = sgwu_self();
    let Some(far_id) = pdr.far_id else {
        log::warn!("[DROP] PDR {} has no FAR", pdr.pdr_id);
        return GtpuRecvResult::Dropped("no FAR".to_string());
    };
    let Some(far) = ctx.far_find(pdr.sess_id, far_id) else {
        log::warn!("[DROP] FAR {far_id} not installed");
        return GtpuRecvResult::Dropped("FAR not found".to_string());
    };

    if far.apply_action & apply_action::DROP != 0 {
        log::trace!("DROP per FAR {far_id}");
        return GtpuRecvResult::Dropped("FAR action DROP".to_string());
    }

    // QER enforcement (TS 29.244 Section 5.2.5.1). Before this, a CLOSED gate
    // still forwarded and an MBR was never policed, so QoS provisioned by the
    // SGW-C was silently inert.
    //
    // Gated off by default: enforcement changes forwarding behaviour, and a
    // mis-provisioned QER would black-hole traffic that flows today. Enable with
    // SGWU_QER_ENFORCEMENT=1.
    if !retried && qer_enforcement_enabled() {
        if let Some(qer) = pdr.qer_id.and_then(|qid| ctx.qer_find(pdr.sess_id, qid)) {
            // Direction from the PDI: ACCESS-sourced traffic is uplink.
            let uplink = pdr.source_interface == crate::sxa_handler::pfcp_interface::ACCESS;
            if qer.gate_is_closed(uplink) {
                log::debug!(
                    "DROP per QER {} closed gate ({} direction)",
                    qer.qer_id,
                    if uplink { "UL" } else { "DL" }
                );
                return GtpuRecvResult::Dropped("QER gate CLOSED".to_string());
            }
            let mbr = qer.mbr_bps(uplink);
            if mbr > 0 && !mbr_allows(ctx, pdr.sess_id, qer.qer_id, uplink, mbr, payload.len()) {
                log::debug!("DROP per QER {} MBR {mbr} bps exceeded", qer.qer_id);
                return GtpuRecvResult::Dropped("QER MBR exceeded".to_string());
            }
        }
    }

    // #831 review: a FAR that just left BUFF and is still flushing takes this path
    // too, so a packet that read the NEW (FORW) action queues behind the buffered ones
    // instead of overtaking them; `far_buffer_packet` sends it straight back
    // (`NotBuffering`) once the flush has ended.
    if far.apply_action & apply_action::BUFF != 0 || far.flushing {
        let bar = ctx.bar_find_for_sess(pdr.sess_id);
        // TS 29.244 Section 8.2.48: honour the CP function's suggested packet
        // count when it gave one; the previous hardcoded 64 ignored it.
        let capacity = crate::context::buffer_capacity(
            bar.as_ref()
                .and_then(|b| b.dl_buffering_suggested_packet_count),
        );
        let outcome = ctx.far_buffer_packet(pdr.sess_id, far_id, payload.to_vec(), capacity);
        if matches!(outcome, Some(crate::context::BufferOutcome::NotBuffering)) {
            if retried {
                return GtpuRecvResult::Dropped("FAR action changed twice".to_string());
            }
            log::debug!("FAR {far_id} left BUFF while this packet was in flight: re-applying");
            return apply_far_once(server, pdr, payload, true);
        }
        let count = outcome.map(|o| o.buffered()).unwrap_or(0);
        let accepted = outcome.is_some_and(|o| o.accepted());
        log::debug!("BUFF per FAR {far_id} (buffered={count}/{capacity}, accepted={accepted})");
        // #215: a buffered packet HAS been handled by the UP function -- it was
        // accepted and will be delivered when the buffer flushes -- so it counts.
        // Counting it again on flush would double-bill, which is why the flush path
        // does not measure.
        //
        // #267: ONLY when it was actually accepted. `far_buffer_packet` discards the
        // packet once the queue is at capacity, and its old `Option<usize>` return
        // could not say so -- so a downlink burst past capacity billed its whole
        // tail, over-billing traffic the SGW-U dropped. A missing FAR (`None`) is
        // likewise not billed.
        if accepted {
            let _ = measure_and_report(pdr, payload.len() as u64);
        }
        // First buffered packet triggers a Downlink Data Report unless the
        // SGW-C suppressed notification (NOCP)
        if count == 1 && accepted && far.apply_action & apply_action::NOCP == 0 {
            if let Some(sess) = ctx.sess_find_by_id(pdr.sess_id) {
                let report = UserPlaneReport {
                    downlink_data_report: true,
                    pdr_id: Some(pdr.pdr_id),
                    ..Default::default()
                };
                // TS 29.244 Section 5.9 / TS 23.401 Section 5.3.4.2: the CP
                // function may ask the UP function to DELAY the notification so
                // several downlink packets can accumulate before the MME is
                // paged. Sending immediately, as before, ignores that request.
                if let Some(delay) = bar.as_ref().and_then(|b| b.ddn_delay()) {
                    let sess_for_delay = sess.clone();
                    let report_for_delay = report.clone();
                    // Detached: the receive loop must not stall for the delay,
                    // or every buffered packet behind it waits too.
                    std::thread::Builder::new()
                        .name("sgwu-ddn-delay".into())
                        .spawn(move || {
                            std::thread::sleep(delay);
                            if let Err(e) = pfcp_path::send_session_report_request(
                                &sess_for_delay,
                                &report_for_delay,
                            ) {
                                log::error!("Delayed Session Report (DLDR) failed: {e}");
                            }
                        })
                        .map(|_| log::debug!("DLDR delayed by {delay:?} per BAR"))
                        .unwrap_or_else(|e| {
                            // A thread we cannot spawn must not silently swallow
                            // the notification: send it undelayed instead.
                            log::error!("Cannot spawn DDN delay thread ({e}); reporting now");
                            if let Err(e) = pfcp_path::send_session_report_request(&sess, &report) {
                                log::error!("Session Report (DLDR) failed: {e}");
                            }
                        });
                } else if let Err(e) = pfcp_path::send_session_report_request(&sess, &report) {
                    log::error!("Session Report (DLDR) failed: {e}");
                }
                return GtpuRecvResult::SessionReport(report);
            }
        }
        return GtpuRecvResult::Buffered;
    }

    if far.apply_action & apply_action::FORW != 0 {
        return match server.forward_gpdu(&far, payload) {
            Ok(()) => {
                let _ = measure_and_report(pdr, payload.len() as u64);
                GtpuRecvResult::Forwarded
            }
            Err(e) => {
                log::error!("FORW per FAR {far_id} failed: {e}");
                GtpuRecvResult::Dropped(e)
            }
        };
    }

    GtpuRecvResult::Dropped(format!(
        "FAR {far_id} has no applicable action (0x{:x})",
        far.apply_action
    ))
}

/// Count a HANDLED packet against every URR the PDR names, and send a Session
/// Report Request for any URR that became reportable (issue #215).
///
/// ## What is counted, and why
///
/// Only traffic the UP function actually **handles**: forwarded, or accepted into a
/// BUFF FAR's buffer. Deliberately NOT counted:
///
/// * a packet dropped by a FAR whose Apply Action is DROP;
/// * a packet dropped by a **closed QER gate** or an exceeded **MBR**.
///
/// TS 29.244 §5.2.2.1 has the UP function measure "the network resources usage",
/// and a packet it discarded consumed none of the resource being billed. The issue
/// asks for this call to be made deliberately: counting QER-dropped traffic would
/// **over-bill** a subscriber for traffic the network refused to carry, which is
/// the worse of the two errors — under-counting a dropped packet costs the operator
/// nothing it was entitled to. `apply_far` therefore measures *after* the QER
/// decision, on the two paths that return `Forwarded` or `Buffered`, and a test
/// pins each case.
///
/// A forwarding attempt that FAILS (`forward_gpdu` errors) is not counted either:
/// nothing reached the peer.
/// Returns the reports it produced, so a test can assert on their CONTENT.
/// `apply_far` ignores the return: the reports have already been handed to
/// `send_session_report_request` by then.
fn measure_and_report(pdr: &SgwuPdr, bytes: u64) -> Vec<crate::sxa_build::UsageReport> {
    if pdr.urr_ids.is_empty() {
        return Vec::new();
    }
    let ctx = sgwu_self();
    // Direction from the PDI, matching how QER enforcement decides it: traffic
    // sourced from the ACCESS side is uplink.
    let uplink = pdr.source_interface == crate::sxa_handler::pfcp_interface::ACCESS;

    let mut reports = Vec::new();
    for urr_id in &pdr.urr_ids {
        // #267: recording and taking the report are ONE locked operation, so two
        // packets crossing the threshold concurrently cannot both produce a report
        // from the same counters. `urr_record` returns `Some` only when the packet
        // it just counted made the URR reportable.
        let Some((snapshot, ur_seqn)) = ctx.urr_record(pdr.sess_id, *urr_id, bytes, uplink) else {
            continue;
        };
        let report =
            crate::sxa_handler::usage_report_from(&snapshot, ur_seqn, snapshot.fired_trigger);
        log::debug!(
            "URR {} reportable (trigger {:?}): {} bytes, UR-SEQN {}",
            report.urr_id,
            report.trigger,
            report.volume.total.unwrap_or(0),
            report.ur_seqn
        );
        reports.push(report);
    }
    if reports.is_empty() {
        return reports;
    }
    let Some(sess) = ctx.sess_find_by_id(pdr.sess_id) else {
        log::warn!(
            "Usage report ready for session {} but the session is gone; \
             {} report(s) dropped",
            pdr.sess_id,
            reports.len()
        );
        return reports;
    };
    // `with_usage_reports` sets the USAR report-type bit alongside the reports, so
    // the bit is now set FROM THE DATA PATH rather than only in a unit test.
    let report = UserPlaneReport::with_usage_reports(reports);
    if let Err(e) = pfcp_path::send_session_report_request(&sess, &report) {
        log::error!("Session Report (USAR) failed: {e}");
    }
    report.usage_reports
}

/// Send an Error Indication for a G-PDU that matched no PDR
/// (TS 29.281 Section 7.3.1: TEID Data I + GTP-U Peer Address IEs)
fn send_error_indication(server: &GtpuServer, teid: u32, peer: SocketAddr) -> GtpuRecvResult {
    let local_addr: Vec<u8> = match sgwu_self()
        .gtpu_address()
        .map(IpAddr::V4)
        .unwrap_or_else(|| server.local_addr().ip())
    {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let msg = Gtp1Message::error_indication(0, teid, &local_addr);
    match server.send_to(&msg.encode(), peer) {
        Ok(()) => {
            log::debug!("[SEND] Error Indication to {peer} for TEID 0x{teid:x}");
            GtpuRecvResult::ErrorIndication
        }
        Err(e) => {
            log::error!("Error Indication to {peer} failed: {e}");
            GtpuRecvResult::Dropped(e)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{FSeid, SgwuFar, SgwuPdr};

    fn test_server(peer_port: u16) -> GtpuServer {
        GtpuServer::open("127.0.0.1:0", peer_port).unwrap()
    }

    fn client() -> UdpSocket {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock
    }

    fn recv_msg(sock: &UdpSocket) -> Gtp1Message {
        let mut buf = [0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf).unwrap();
        let mut bytes = Bytes::copy_from_slice(&buf[..len]);
        Gtp1Message::decode(&mut bytes).unwrap()
    }

    /// Install a session with a PDR (local TEID) linked to a FAR
    fn provision(seid: u64, local_teid: u32, far: SgwuFar) -> (u64, u32) {
        let ctx = sgwu_self();
        let f_seid = FSeid::with_ipv4(seid, Ipv4Addr::new(10, 0, 0, 1));
        let sess = ctx.sess_add(&f_seid).unwrap();
        let far_id = far.far_id;
        ctx.far_install(SgwuFar {
            sess_id: sess.id,
            ..far
        });
        ctx.pdr_install(SgwuPdr {
            sess_id: sess.id,
            pdr_id: 1,
            precedence: 255,
            source_interface: 0,
            local_teid,
            local_addr: Some(Ipv4Addr::new(127, 0, 0, 1)),
            outer_header_removal: Some(0),
            far_id: Some(far_id),
            qer_id: None,
            urr_ids: Vec::new(),
        });
        (sess.id, far_id)
    }

    #[test]
    fn test_echo_request_response_carries_recovery_ie() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let sock = client();

        let echo = Gtp1Message::echo_request(0, 0x42);
        sock.send_to(&echo.encode(), server.local_addr()).unwrap();

        let response = recv_msg(&sock);
        assert_eq!(
            response.header.message_type,
            Gtp1cMessageType::EchoResponse as u8
        );
        assert_eq!(response.header.sequence_number, Some(0x42));
        // Recovery IE is mandatory in GTP-U Echo Response
        // (TS 29.281 Section 7.2.2); its value shall be 0
        let recovery = response.get_ie(14).expect("Recovery IE missing");
        assert_eq!(recovery.value[0], 0);

        server.close();
    }

    #[test]
    fn test_gpdu_forwarded_per_far() {
        // Fake PGW peer to receive the forwarded G-PDU
        let pgw = client();
        let pgw_port = pgw.local_addr().unwrap().port();

        let server = test_server(pgw_port);
        let enb = client();

        let (_sess, _far) = provision(
            0xA001,
            0x1001,
            SgwuFar {
                far_id: 10,
                apply_action: apply_action::FORW,
                destination_interface: 1,
                outer_header_creation: Some((0x2002, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
                ..Default::default()
            },
        );

        let payload = [0x45, 0x00, 0x00, 0x1c, 0xDE, 0xAD, 0xBE, 0xEF];
        let gpdu = Gtp1Message::gpdu(0x1001, Bytes::copy_from_slice(&payload));
        enb.send_to(&gpdu.encode(), server.local_addr()).unwrap();

        let forwarded = recv_msg(&pgw);
        assert_eq!(forwarded.header.message_type, Gtp1uMessageType::GPdu as u8);
        assert_eq!(forwarded.header.teid, 0x2002); // outer header creation TEID
        assert_eq!(forwarded.payload.as_deref(), Some(&payload[..]));

        server.close();
    }

    #[test]
    fn test_gpdu_unknown_teid_triggers_error_indication() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let enb = client();

        let gpdu = Gtp1Message::gpdu(0xDEAD_BEEF, Bytes::from_static(&[1, 2, 3, 4]));
        enb.send_to(&gpdu.encode(), server.local_addr()).unwrap();

        let response = recv_msg(&enb);
        assert_eq!(
            response.header.message_type,
            Gtp1uMessageType::ErrorIndication as u8
        );
        // Header TEID is 0; the offending TEID is in TEID Data I
        assert_eq!(response.header.teid, 0);
        let parsed = ErrorIndication::decode(&response).unwrap();
        assert_eq!(parsed.teid, 0xDEAD_BEEF);
        assert!(!parsed.gsn_address.is_empty()); // GTP-U Peer Address present

        server.close();
    }

    #[test]
    fn test_gpdu_buffered_per_far_and_reported_once() {
        // #635: buffers through `buffer_capacity`, which reads the variable.
        let _buffer_env = crate::context::MAX_BUFFERED_PACKETS_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let server = test_server(GTPV1_U_UDP_PORT);
        let ctx = sgwu_self();

        let (sess_id, far_id) = provision(
            0xA002,
            0x1002,
            SgwuFar {
                far_id: 20,
                apply_action: apply_action::BUFF,
                destination_interface: 0,
                outer_header_creation: None,
                ..Default::default()
            },
        );

        let pdr = ctx.pdr_find_by_teid(0x1002).unwrap();

        // First buffered packet triggers a Downlink Data Report
        let gpdu1 = Gtp1Message::gpdu(0x1002, Bytes::from_static(&[1, 1]));
        let result =
            handle_gtpu_packet(&server, &gpdu1.encode(), "127.0.0.1:9999".parse().unwrap());
        assert!(matches!(result, GtpuRecvResult::SessionReport(_)));

        // Second packet is buffered silently
        let gpdu2 = Gtp1Message::gpdu(0x1002, Bytes::from_static(&[2, 2]));
        let result =
            handle_gtpu_packet(&server, &gpdu2.encode(), "127.0.0.1:9999".parse().unwrap());
        assert!(matches!(result, GtpuRecvResult::Buffered));

        let far = ctx.far_find(sess_id, far_id).unwrap();
        assert_eq!(far.buffered.len(), 2);
        let _ = pdr;

        server.close();
    }

    #[test]
    fn test_buffered_packets_drained_on_forw_transition() {
        // #635: buffers through `buffer_capacity`, which reads the variable.
        let _buffer_env = crate::context::MAX_BUFFERED_PACKETS_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Fake eNB peer that receives the drained downlink packets
        let enb = client();
        let enb_port = enb.local_addr().unwrap().port();
        let server = test_server(enb_port);
        let ctx = sgwu_self();

        let (sess_id, far_id) = provision(
            0xA003,
            0x1003,
            SgwuFar {
                far_id: 30,
                apply_action: apply_action::BUFF,
                destination_interface: 0,
                outer_header_creation: None,
                ..Default::default()
            },
        );

        // Buffer two downlink packets
        for payload in [&[1u8, 1][..], &[2u8, 2][..]] {
            let gpdu = Gtp1Message::gpdu(0x1003, Bytes::copy_from_slice(payload));
            handle_gtpu_packet(&server, &gpdu.encode(), "127.0.0.1:9999".parse().unwrap());
        }

        // SGW-C activates the bearer: FORW with the eNB outer header
        ctx.far_update_with(sess_id, far_id, |far| {
            far.apply_action = apply_action::FORW;
            far.outer_header_creation = Some((0xE0B1, Some(Ipv4Addr::new(127, 0, 0, 1)), None));
        });
        let sent = server.send_buffered_packets(sess_id, far_id);
        assert_eq!(sent, 2);

        let first = recv_msg(&enb);
        assert_eq!(first.header.teid, 0xE0B1);
        assert_eq!(first.payload.as_deref(), Some(&[1u8, 1][..]));
        let second = recv_msg(&enb);
        assert_eq!(second.payload.as_deref(), Some(&[2u8, 2][..]));

        // Buffer is drained
        assert!(ctx.far_find(sess_id, far_id).unwrap().buffered.is_empty());

        server.close();
    }

    #[test]
    fn test_gpdu_dropped_per_far() {
        let server = test_server(GTPV1_U_UDP_PORT);

        provision(
            0xA004,
            0x1004,
            SgwuFar {
                far_id: 40,
                apply_action: apply_action::DROP,
                ..Default::default()
            },
        );

        let gpdu = Gtp1Message::gpdu(0x1004, Bytes::from_static(&[9]));
        let result = handle_gtpu_packet(&server, &gpdu.encode(), "127.0.0.1:9999".parse().unwrap());
        assert!(matches!(result, GtpuRecvResult::Dropped(_)));

        server.close();
    }

    #[test]
    fn test_received_error_indication_reported_to_sgwc() {
        let server = test_server(GTPV1_U_UDP_PORT);

        let (_sess, _far) = provision(
            0xA005,
            0x1005,
            SgwuFar {
                far_id: 50,
                apply_action: apply_action::FORW,
                outer_header_creation: Some((0x5005, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
                ..Default::default()
            },
        );

        // Peer reports it has no context for the TEID we forward to
        let err_ind = Gtp1Message::error_indication(0, 0x5005, &[127, 0, 0, 1]);
        let result = handle_gtpu_packet(
            &server,
            &err_ind.encode(),
            "127.0.0.1:2152".parse().unwrap(),
        );
        match result {
            GtpuRecvResult::SessionReport(report) => {
                assert!(report.error_indication_report);
                assert_eq!(report.remote_f_teid.unwrap().teid, 0x5005);
            }
            other => panic!("expected SessionReport, got {other:?}"),
        }

        server.close();
    }

    #[test]
    fn test_end_marker_forwarded() {
        let peer = client();
        let peer_port = peer.local_addr().unwrap().port();
        let server = test_server(peer_port);

        provision(
            0xA006,
            0x1006,
            SgwuFar {
                far_id: 60,
                apply_action: apply_action::FORW,
                outer_header_creation: Some((0x6006, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
                ..Default::default()
            },
        );

        let end_marker = Gtp1Message::end_marker(0x1006);
        handle_gtpu_packet(
            &server,
            &end_marker.encode(),
            "127.0.0.1:9999".parse().unwrap(),
        );

        let forwarded = recv_msg(&peer);
        assert_eq!(
            forwarded.header.message_type,
            Gtp1uMessageType::EndMarker as u8
        );
        assert_eq!(forwarded.header.teid, 0x6006);

        server.close();
    }

    #[test]
    fn test_malformed_packet_dropped() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let result = handle_gtpu_packet(&server, &[0x00], "127.0.0.1:9999".parse().unwrap());
        assert!(matches!(result, GtpuRecvResult::Dropped(_)));
        server.close();
    }

    // ================================================================
    // nextgcore #60: End Marker, Error Indication peer match, QER gate
    // ================================================================

    /// TS 29.281 Section 7.3.2.1: "If an End Marker message is received with a
    /// TEID for which there is no context, then the receiver shall ignore this
    /// message." It used to answer with an Error Indication, which a peer may
    /// read as loss of bearer context — during a handover path switch, i.e.
    /// exactly when End Markers arrive.
    #[test]
    fn unknown_teid_end_marker_is_ignored_not_error_indicated() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();

        // A TEID no PDR was ever installed for.
        let end_marker = Gtp1Message::end_marker(0x0BAD_F00D);
        sock.send_to(&end_marker.encode(), server.local_addr())
            .unwrap();

        let mut buf = [0u8; 4096];
        assert!(
            sock.recv_from(&mut buf).is_err(),
            "an unknown-TEID End Marker must draw no reply at all"
        );
        server.close();
    }

    /// A G-PDU for an unknown TEID, by contrast, SHOULD still draw an Error
    /// Indication (TS 29.281 Section 7.3.1). Asserting this keeps the End Marker
    /// fix from being over-applied into "never send an Error Indication".
    #[test]
    fn unknown_teid_gpdu_still_gets_an_error_indication() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let sock = client();

        let gpdu = Gtp1Message::gpdu(0x0DEA_D000, Bytes::from_static(b"payload"));
        sock.send_to(&gpdu.encode(), server.local_addr()).unwrap();

        let reply = recv_msg(&sock);
        assert_eq!(
            reply.header.message_type,
            Gtp1uMessageType::ErrorIndication as u8,
            "a G-PDU for an unknown TEID is still an error"
        );
        server.close();
    }

    /// QER enforcement: a CLOSED gate must drop rather than forward. Driven
    /// through apply_far so the enforcement is exercised where forwarding is
    /// decided, not only in the gate decoder.
    #[test]
    fn closed_qer_gate_drops_when_enforcement_is_enabled() {
        let _env = QER_ENFORCEMENT_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ctx = sgwu_self();
        let server = test_server(GTPV1_U_UDP_PORT);

        let f_seid = FSeid::with_ipv4(0x6000, Ipv4Addr::new(10, 0, 0, 1));
        let sess = ctx.sess_add(&f_seid).unwrap();
        ctx.far_install(SgwuFar {
            sess_id: sess.id,
            far_id: 1,
            apply_action: apply_action::FORW,
            outer_header_creation: Some((0x999, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
            ..Default::default()
        });
        // UL gate CLOSED (bits 1-2 = 1), source interface ACCESS = uplink.
        ctx.qer_install(crate::context::SgwuQer {
            sess_id: sess.id,
            qer_id: 5,
            gate_status: Some(0x01),
            ..Default::default()
        });
        let pdr = SgwuPdr {
            sess_id: sess.id,
            pdr_id: 1,
            source_interface: crate::sxa_handler::pfcp_interface::ACCESS,
            local_teid: 0x6001,
            far_id: Some(1),
            qer_id: Some(5),
            ..Default::default()
        };
        ctx.pdr_install(pdr.clone());

        // Enforcement off (the shipped default): the packet still forwards, so
        // this change cannot alter behaviour until an operator opts in.
        std::env::remove_var("SGWU_QER_ENFORCEMENT");
        assert!(
            matches!(apply_far(&server, &pdr, b"data"), GtpuRecvResult::Forwarded),
            "with enforcement off the closed gate must NOT take effect"
        );

        // Enforcement on: the closed gate drops.
        std::env::set_var("SGWU_QER_ENFORCEMENT", "1");
        let result = apply_far(&server, &pdr, b"data");
        std::env::remove_var("SGWU_QER_ENFORCEMENT");
        assert!(
            matches!(&result, GtpuRecvResult::Dropped(reason) if reason.contains("gate")),
            "a CLOSED gate must drop, got {result:?}"
        );

        ctx.sess_remove(sess.id);
        server.close();
    }

    // -----------------------------------------------------------------
    // #215: URR measurement on the data path
    // -----------------------------------------------------------------

    /// Install a session with a forwarding FAR, a PDR pointing at it, and a URR.
    fn provision_urr(
        seid: u64,
        local_teid: u32,
        urr: crate::context::SgwuUrr,
        qer: Option<crate::context::SgwuQer>,
    ) -> (u64, SgwuPdr) {
        let ctx = sgwu_self();
        let f_seid = FSeid::with_ipv4(seid, Ipv4Addr::new(10, 0, 0, 1));
        let sess = ctx.sess_add(&f_seid).unwrap();
        ctx.far_install(SgwuFar {
            sess_id: sess.id,
            far_id: 1,
            apply_action: apply_action::FORW,
            outer_header_creation: Some((0x999, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
            ..Default::default()
        });
        let urr_id = urr.urr_id;
        ctx.urr_install(crate::context::SgwuUrr {
            sess_id: sess.id,
            ..urr
        });
        ctx.sess_register_urr(sess.id, urr_id);
        let qer_id = qer.map(|q| {
            let id = q.qer_id;
            ctx.qer_install(crate::context::SgwuQer {
                sess_id: sess.id,
                ..q
            });
            id
        });
        let pdr = SgwuPdr {
            sess_id: sess.id,
            pdr_id: 1,
            source_interface: crate::sxa_handler::pfcp_interface::ACCESS,
            local_teid,
            far_id: Some(1),
            qer_id,
            urr_ids: vec![urr_id],
            ..Default::default()
        };
        ctx.pdr_install(pdr.clone());
        (sess.id, pdr)
    }

    /// **Issue #215.** Forwarded traffic is counted against the PDR's URR, crossing
    /// a Volume Threshold produces a Usage Report with the accumulated counts, and
    /// the UR-SEQN advances across reports.
    ///
    /// Before this the SGW-U had no URR at all: no measurement, no thresholds and no
    /// Usage Report IEs, so mandatory usage reporting to the SGW-C could not
    /// function and SGW-CDR volume (TS 32.251) had no input.
    #[test]
    fn forwarded_traffic_crosses_a_volume_threshold_and_reports_with_advancing_ur_seqn() {
        use crate::context::{measurement_method, reporting_trigger, SgwuUrr, Volume};
        let _env = QER_ENFORCEMENT_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ctx = sgwu_self();
        let server = test_server(GTPV1_U_UDP_PORT);
        std::env::remove_var("SGWU_QER_ENFORCEMENT");

        // Threshold 250 bytes total; each packet below is 100 bytes.
        let (sess_id, pdr) = provision_urr(
            0x7100,
            0x7101,
            SgwuUrr {
                urr_id: 7,
                measurement_method: measurement_method::VOLUME | measurement_method::DURATION,
                reporting_triggers: reporting_trigger::VOLUME_THRESHOLD,
                volume_threshold: Volume {
                    total: Some(250),
                    ..Default::default()
                },
                ..Default::default()
            },
            None,
        );
        let packet = [0u8; 100];

        // Two packets: 200 bytes, still under the threshold, so NO report.
        assert!(measure_and_report(&pdr, packet.len() as u64).is_empty());
        assert!(measure_and_report(&pdr, packet.len() as u64).is_empty());
        let urr = ctx.urr_find(sess_id, 7).expect("URR installed");
        assert_eq!(urr.total_bytes, 200, "volume accumulates");
        assert_eq!(urr.uplink_bytes, 200, "ACCESS-sourced traffic is uplink");
        assert_eq!(urr.downlink_bytes, 0);
        assert_eq!(urr.total_packets, 2);
        assert_eq!(urr.next_ur_seqn, 0, "no report yet, so no UR-SEQN spent");

        // The third packet crosses 250 -> one report carrying all 300 bytes.
        let reports = measure_and_report(&pdr, packet.len() as u64);
        assert_eq!(reports.len(), 1, "crossing the threshold reports once");
        let report = &reports[0];
        assert_eq!(report.urr_id, 7);
        assert_eq!(report.ur_seqn, 0, "UR-SEQN starts at 0");
        assert!(report.trigger.volume_threshold, "VOLTH is the trigger");
        assert!(!report.trigger.volume_quota && !report.trigger.time_threshold);
        assert_eq!(
            report.volume.total,
            Some(300),
            "the report carries every byte measured in the period, not just the last packet"
        );
        assert_eq!(report.volume.uplink, Some(300));
        assert_eq!(report.volume.downlink, Some(0));
        assert_eq!(report.total_packets, Some(3));
        assert!(report.duration_secs.is_some(), "DURAT was provisioned");
        assert!(report.time_of_first_packet.is_some());

        // #267 FLIP: these asserted `total_bytes == 0` and `total_packets == 0`,
        // pinning the reset-on-report model. Counters are now CUMULATIVE for the
        // session and `reported_*` advances to cover what a report carried, so the
        // next report's DELTA is right while the cumulative total survives for the
        // Volume Quota check. Resetting made a quota unreachable whenever a
        // threshold also fired.
        let urr = ctx.urr_find(sess_id, 7).expect("URR still installed");
        assert_eq!(urr.total_bytes, 300, "cumulative volume is kept");
        assert_eq!(
            urr.reported_total_bytes, 300,
            "and the report is recorded as covering it"
        );
        assert_eq!(
            urr.measured_volume().total,
            Some(0),
            "so the next period's delta starts at zero"
        );
        assert_eq!(urr.total_packets, 3);
        assert_eq!(urr.next_ur_seqn, 1);

        // A second crossing reports UR-SEQN 1: monotonic, which is what lets the
        // SGW-C order and de-duplicate.
        for _ in 0..3 {
            let reports = measure_and_report(&pdr, packet.len() as u64);
            if let Some(r) = reports.first() {
                assert_eq!(r.ur_seqn, 1, "UR-SEQN must advance, not restart");
                assert_eq!(
                    r.volume.total,
                    Some(300),
                    "the second report carries its own period's delta, not the \
                     cumulative 600"
                );
            }
        }
        assert_eq!(ctx.urr_find(sess_id, 7).unwrap().next_ur_seqn, 2);

        ctx.sess_remove(sess_id);
        server.close();
    }

    /// **Issue #215.** Traffic the UP function DISCARDS is not counted — the issue
    /// asks for this call to be made deliberately, and this test pins it.
    ///
    /// TS 29.244 §5.2.2.1 measures "network resources usage", and a packet the SGW-U
    /// dropped consumed none of the resource being billed. Counting QER-dropped
    /// traffic would **over-bill** a subscriber for traffic the network refused to
    /// carry, which is the worse of the two errors.
    #[test]
    fn traffic_dropped_by_a_closed_qer_gate_or_a_drop_far_is_not_counted() {
        use crate::context::{measurement_method, reporting_trigger, SgwuQer, SgwuUrr, Volume};
        let _env = QER_ENFORCEMENT_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ctx = sgwu_self();
        let server = test_server(GTPV1_U_UDP_PORT);

        let (sess_id, pdr) = provision_urr(
            0x7200,
            0x7201,
            SgwuUrr {
                urr_id: 9,
                measurement_method: measurement_method::VOLUME,
                reporting_triggers: reporting_trigger::VOLUME_THRESHOLD,
                volume_threshold: Volume {
                    total: Some(10_000),
                    ..Default::default()
                },
                ..Default::default()
            },
            // UL gate CLOSED (bits 1-2 = 1); the PDR is ACCESS-sourced = uplink.
            Some(SgwuQer {
                qer_id: 5,
                gate_status: Some(0x01),
                ..Default::default()
            }),
        );
        let packet = [0u8; 100];

        // Enforcement ON: the closed gate drops, and nothing is counted.
        std::env::set_var("SGWU_QER_ENFORCEMENT", "1");
        let result = apply_far(&server, &pdr, &packet);
        std::env::remove_var("SGWU_QER_ENFORCEMENT");
        assert!(
            matches!(&result, GtpuRecvResult::Dropped(r) if r.contains("gate")),
            "the closed gate must drop, got {result:?}"
        );
        let urr = ctx.urr_find(sess_id, 9).expect("URR installed");
        assert_eq!(
            urr.total_bytes, 0,
            "a packet dropped by a closed QER gate must NOT be billed"
        );
        assert_eq!(urr.total_packets, 0);

        // With enforcement OFF the same packet forwards, and IS counted — so the
        // zero above is the gate's doing, not a broken measurement path.
        let result = apply_far(&server, &pdr, &packet);
        assert!(matches!(result, GtpuRecvResult::Forwarded), "{result:?}");
        assert_eq!(
            ctx.urr_find(sess_id, 9).unwrap().total_bytes,
            100,
            "forwarded traffic IS counted"
        );

        // A DROP FAR is likewise not counted.
        ctx.far_install(SgwuFar {
            sess_id,
            far_id: 1,
            apply_action: apply_action::DROP,
            ..Default::default()
        });
        let result = apply_far(&server, &pdr, &packet);
        assert!(
            matches!(&result, GtpuRecvResult::Dropped(r) if r.contains("DROP")),
            "{result:?}"
        );
        assert_eq!(
            ctx.urr_find(sess_id, 9).unwrap().total_bytes,
            100,
            "a DROP FAR must not add to the measured volume"
        );

        ctx.sess_remove(sess_id);
        server.close();
    }

    /// **Issue #267.** A downlink packet dropped because the BUFF buffer is FULL is
    /// not billed.
    ///
    /// `far_buffer_packet` discards the packet once the queue is at capacity, and its
    /// old `Option<usize>` return could not say so -- `apply_far` billed
    /// unconditionally, so a burst past capacity over-billed its entire tail. That is
    /// the over-billing direction the URR decision explicitly rules out.
    #[test]
    fn a_packet_dropped_because_the_buffer_is_full_is_not_billed() {
        use crate::context::{measurement_method, reporting_trigger, SgwuUrr, Volume};
        let _env = QER_ENFORCEMENT_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // #635: the variable's own lock, which every reader of it takes too.
        let _buffer_env = crate::context::MAX_BUFFERED_PACKETS_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ctx = sgwu_self();
        let server = test_server(GTPV1_U_UDP_PORT);
        std::env::set_var("SGWU_MAX_BUFFERED_PACKETS", "2");

        let (sess_id, pdr) = provision_urr(
            0x7400,
            0x7401,
            SgwuUrr {
                urr_id: 13,
                measurement_method: measurement_method::VOLUME,
                reporting_triggers: reporting_trigger::VOLUME_THRESHOLD,
                volume_threshold: Volume {
                    total: Some(1_000_000),
                    ..Default::default()
                },
                ..Default::default()
            },
            None,
        );
        // Switch the FAR to BUFF so packets queue instead of forwarding.
        ctx.far_install(SgwuFar {
            sess_id,
            far_id: 1,
            apply_action: apply_action::BUFF,
            ..Default::default()
        });

        let packet = [0u8; 100];
        // Capacity 2: the first two are accepted and billed, the next three are
        // dropped and must not be.
        for _ in 0..5 {
            apply_far(&server, &pdr, &packet);
        }
        std::env::remove_var("SGWU_MAX_BUFFERED_PACKETS");

        let urr = ctx.urr_find(sess_id, 13).expect("URR installed");
        assert_eq!(
            urr.total_bytes, 200,
            "only the two ACCEPTED packets may be billed, not the three the buffer \
             dropped"
        );
        assert_eq!(urr.total_packets, 2);

        ctx.sess_remove(sess_id);
        server.close();
    }

    /// **Issue #267.** A Volume Quota fires even when a Volume Threshold is also
    /// provisioned.
    ///
    /// The threshold reset the counters the quota was measured against, so with
    /// VOLTH=250 and VOLQU=1000 the total never climbed past 250 and quota exhaustion
    /// was UNREACHABLE -- the subscriber consumed unlimited volume against a quota
    /// that never reported.
    #[test]
    fn a_volume_quota_fires_even_when_a_threshold_keeps_resetting_the_period() {
        use crate::context::{measurement_method, reporting_trigger, SgwuUrr, Volume};
        let _env = QER_ENFORCEMENT_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ctx = sgwu_self();
        let server = test_server(GTPV1_U_UDP_PORT);
        std::env::remove_var("SGWU_QER_ENFORCEMENT");

        let (sess_id, pdr) = provision_urr(
            0x7500,
            0x7501,
            SgwuUrr {
                urr_id: 15,
                measurement_method: measurement_method::VOLUME,
                reporting_triggers: reporting_trigger::VOLUME_THRESHOLD
                    | reporting_trigger::VOLUME_QUOTA,
                volume_threshold: Volume {
                    total: Some(250),
                    ..Default::default()
                },
                volume_quota: Volume {
                    total: Some(1_000),
                    ..Default::default()
                },
                ..Default::default()
            },
            None,
        );

        let packet = [0u8; 100];
        let mut saw_threshold = false;
        let mut saw_quota = false;
        // 10 packets = 1000 bytes cumulative, crossing the 250-byte threshold four
        // times and the 1000-byte quota once.
        for _ in 0..10 {
            for report in measure_and_report(&pdr, packet.len() as u64) {
                saw_threshold |= report.trigger.volume_threshold;
                saw_quota |= report.trigger.volume_quota;
            }
        }
        assert!(saw_threshold, "the threshold must fire");
        assert!(
            saw_quota,
            "the quota must fire too: it is cumulative for the session, and a \
             threshold reset must not make it unreachable"
        );
        // The cumulative total survived every threshold report.
        assert_eq!(ctx.urr_find(sess_id, 15).unwrap().total_bytes, 1_000);

        ctx.sess_remove(sess_id);
        server.close();
    }

    /// **Issue #215.** A PDR with no URR measures nothing and costs nothing — the
    /// overwhelmingly common case, since a session without usage reporting must not
    /// pay for a store lookup per packet.
    #[test]
    fn a_pdr_with_no_urr_produces_no_report() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let (sess_id, far_id) = provision(
            0x7300,
            0x7301,
            SgwuFar {
                far_id: 1,
                apply_action: apply_action::FORW,
                outer_header_creation: Some((0x999, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
                ..Default::default()
            },
        );
        assert_eq!(far_id, 1);
        let pdr = sgwu_self().pdr_find(sess_id, 1).expect("PDR installed");
        assert!(pdr.urr_ids.is_empty());
        assert!(measure_and_report(&pdr, 100).is_empty());
        sgwu_self().sess_remove(sess_id);
        server.close();
    }

    /// A private context holding QERs `qer_ids` on one session, for the MBR tests:
    /// `mbr_allows` only creates a bucket for a QER that is installed.
    fn ctx_with_qers(first_sess_id: u64, qer_ids: &[u32]) -> (crate::context::SgwuContext, u64) {
        let ctx = crate::context::SgwuContext::with_first_sess_id(first_sess_id);
        let s = ctx
            .sess_add(&FSeid::with_ipv4(first_sess_id, Ipv4Addr::new(10, 7, 7, 4)))
            .unwrap();
        for &qer_id in qer_ids {
            ctx.qer_install(crate::context::SgwuQer {
                sess_id: s.id,
                qer_id,
                ..Default::default()
            });
        }
        (ctx, s.id)
    }

    /// The MBR token bucket: the first packet fits within one second of credit,
    /// and a packet far larger than the whole per-second allowance cannot.
    #[test]
    fn mbr_bucket_admits_within_rate_and_rejects_beyond_it() {
        let (ctx, sid) = ctx_with_qers(0x7740_0000, &[1, 2, 3]);
        // 8000 bits per second = 1000 bytes/s of credit.
        assert!(
            mbr_allows(&ctx, sid, 1, true, 8000, 100),
            "100 bytes must fit in a 1000 byte/s bucket"
        );
        // A single packet larger than the entire per-second capacity can never
        // fit, however long we wait.
        assert!(
            !mbr_allows(&ctx, sid, 2, true, 8000, 5000),
            "5000 bytes cannot fit a 1000 byte/s bucket"
        );
        // Directions are policed independently.
        assert!(mbr_allows(&ctx, sid, 3, true, 8000, 900));
        assert!(mbr_allows(&ctx, sid, 3, false, 8000, 900));

        ctx.sess_remove(sid);
    }

    /// #773 review MAJOR: a packet whose QER was read just before a Session Deletion /
    /// Remove QER must not RE-CREATE a bucket after the remover forgot it. The
    /// interleaving is driven deterministically: snapshot the QER as `apply_far` does,
    /// remove, then police with the snapshot. Before the re-check this left 1 bucket
    /// for a dead session, forever.
    #[test]
    fn a_packet_racing_removal_does_not_recreate_a_bucket() {
        let (ctx, sid) = ctx_with_qers(0x7750_0000, &[1, 2]);
        assert!(mbr_allows(&ctx, sid, 1, true, 8000, 10));
        assert!(mbr_allows(&ctx, sid, 2, true, 8000, 10));

        // Remove QER 2 while a packet holding its snapshot is in flight.
        let snapshot = ctx.qer_find(sid, 2).unwrap();
        ctx.qer_remove(sid, 2);
        assert!(mbr_allows(&ctx, sid, snapshot.qer_id, false, 8000, 10));
        assert_eq!(
            mbr_bucket_count(sid, Some(2)),
            0,
            "no bucket for a removed QER"
        );

        // Session Deletion while a packet holding QER 1's snapshot is in flight.
        let snapshot = ctx.qer_find(sid, 1).unwrap();
        ctx.sess_remove(sid);
        assert_eq!(mbr_bucket_count(sid, None), 0);
        assert!(mbr_allows(&ctx, sid, snapshot.qer_id, false, 8000, 10));
        assert_eq!(
            mbr_bucket_count(sid, None),
            0,
            "no bucket may be created for a dead session"
        );
    }

    /// #773: removing a QER, and removing a session by ANY path, drops the MBR
    /// buckets policing created for it. Before the fix `mbr_forget_session` had no
    /// production caller and `MBR_BUCKETS` grew by one entry per policed bearer
    /// direction for the life of the process.
    ///
    /// A private context whose session ids nothing else in the process uses, so the
    /// counts below cannot be disturbed by a concurrent test's buckets.
    #[test]
    fn removing_a_qer_or_a_session_drops_its_mbr_buckets() {
        let ctx = crate::context::SgwuContext::with_first_sess_id(0x7730_0000);
        let mk = |seid| {
            let s = ctx
                .sess_add(&FSeid::with_ipv4(seid, Ipv4Addr::new(10, 7, 7, 3)))
                .unwrap();
            for qer_id in [1, 2] {
                ctx.qer_install(crate::context::SgwuQer {
                    sess_id: s.id,
                    qer_id,
                    ..Default::default()
                });
                // Police both directions, as traffic on the bearer would.
                assert!(mbr_allows(&ctx, s.id, qer_id, true, 8000, 10));
                assert!(mbr_allows(&ctx, s.id, qer_id, false, 8000, 10));
            }
            assert_eq!(
                mbr_bucket_count(s.id, None),
                4,
                "policing created the buckets"
            );
            s.id
        };

        // Remove QER: only that QER's two buckets go.
        let a = mk(0x7731);
        assert!(ctx.qer_remove(a, 1).is_some());
        assert_eq!(mbr_bucket_count(a, Some(1)), 0);
        assert_eq!(
            mbr_bucket_count(a, Some(2)),
            2,
            "the other QER keeps policing"
        );

        // Session deletion (the Sx deletion handler's path).
        assert!(ctx.sess_remove(a).is_some());
        assert_eq!(
            mbr_bucket_count(a, None),
            0,
            "sess_remove must drop the buckets"
        );

        // Peer restart / shutdown paths go through sess_remove too.
        let b = mk(0x7732);
        let c = mk(0x7733);
        ctx.sess_remove_all();
        assert_eq!(mbr_bucket_count(b, None) + mbr_bucket_count(c, None), 0);
    }

    #[test]
    fn mbr_forget_session_drops_only_that_sessions_buckets() {
        let (ctx_a, a) = ctx_with_qers(0x7760_0000, &[1]);
        let (ctx_b, b) = ctx_with_qers(0x7770_0000, &[1]);
        assert!(mbr_allows(&ctx_a, a, 1, true, 8000, 10));
        assert!(mbr_allows(&ctx_b, b, 1, true, 8000, 10));
        mbr_forget_session(a);
        assert_eq!(mbr_bucket_count(a, None), 0);
        assert_eq!(
            mbr_bucket_count(b, None),
            1,
            "the other session keeps its bucket"
        );
        assert!(mbr_allows(&ctx_b, b, 1, true, 8000, 10));
        ctx_b.sess_remove(b);
    }

    // ================================================================
    // nextgcore #61: GTP-U path management (TS 23.007 Section 20.3)
    // ================================================================

    /// Section 20.3.1: "The path shall be considered to be down if the counter
    /// EXCEEDS N3-REQUESTS." Exceeds, not reaches — failing at N3 would declare
    /// a path down one probe early.
    #[test]
    fn path_fails_only_after_exceeding_n3_requests() {
        let _paths = GTPU_PATH_TEST_LOCK.blocking_lock();
        let peer = IpAddr::V4(Ipv4Addr::new(10, 61, 0, 1));
        forget_gtpu_path(peer);
        std::env::set_var("SGWU_GTPU_N3_REQUESTS", "3");

        for expected in 1..=3 {
            let state = note_echo_unanswered(peer);
            assert_eq!(state.unanswered, expected);
            assert!(
                !state.failed,
                "{expected} unanswered must not yet be a failure with N3=3"
            );
        }
        // The fourth EXCEEDS N3.
        let state = note_echo_unanswered(peer);
        assert_eq!(state.unanswered, 4);
        assert!(state.failed, "exceeding N3-REQUESTS declares the path down");
        assert_eq!(failed_gtpu_paths(), vec![peer]);

        std::env::remove_var("SGWU_GTPU_N3_REQUESTS");
        forget_gtpu_path(peer);
    }

    /// #823: the path table is pruned to the peers some FAR still forwards to, so it
    /// is bounded by the live peer set rather than by every peer ever seen.
    /// (`forget_gtpu_path` had only test callers, so nothing ever shrank it.)
    #[test]
    fn the_path_table_is_pruned_to_the_live_peers() {
        let _paths = GTPU_PATH_TEST_LOCK.blocking_lock();
        let live = IpAddr::V4(Ipv4Addr::new(10, 82, 3, 1));
        let gone = IpAddr::V4(Ipv4Addr::new(10, 82, 3, 2));
        note_echo_unanswered(live);
        note_echo_unanswered(gone);
        assert_eq!(gtpu_path_state(gone).unanswered, 1);

        prune_gtpu_paths(&[live]);
        assert_eq!(
            gtpu_path_state(live).unanswered,
            1,
            "a live peer keeps its state"
        );
        assert!(
            !gtpu_paths().lock().unwrap().contains_key(&gone),
            "a peer no FAR references is dropped from the table"
        );
        forget_gtpu_path(live);
    }

    /// #831 review MAJOR 1: an Echo Response from a peer we never probed -- here 1000
    /// of them, as a spoofing sender would produce -- inserts nothing.
    #[test]
    fn echo_responses_from_unknown_peers_do_not_grow_the_path_table() {
        let _paths = GTPU_PATH_TEST_LOCK.blocking_lock();
        let unknown = |i: u32| IpAddr::V4(Ipv4Addr::from(0x0A_83_00_00 | i));
        for i in 0..1000 {
            note_echo_answered(unknown(i));
        }
        let left = gtpu_paths()
            .lock()
            .unwrap()
            .keys()
            .filter(|ip| (0..1000).any(|i| unknown(i) == **ip))
            .count();
        assert_eq!(left, 0, "no entry for a peer that was never probed");
    }

    /// #831 review MAJOR 2: the Echo ROUND prunes -- tested through `echo_round`, the
    /// function the receive loop calls, not just the prune helper. A peer whose FAR is
    /// gone loses its entry, a live peer is probed, and a peer whose path is DOWN is
    /// kept (its Recovery must still be reported, TS 23.007 §20.3.4).
    #[test]
    fn an_echo_round_prunes_stale_peers_and_probes_live_ones() {
        let _paths = GTPU_PATH_TEST_LOCK.blocking_lock();
        let ctx = sgwu_self();
        let live_ip = Ipv4Addr::new(10, 83, 1, 1);
        let live = IpAddr::V4(live_ip);
        let stale = IpAddr::V4(Ipv4Addr::new(10, 83, 1, 2));
        let down = IpAddr::V4(Ipv4Addr::new(10, 83, 1, 3));
        let sess = ctx
            .sess_add(&FSeid::with_ipv4(0x8311, Ipv4Addr::new(10, 83, 0, 1)))
            .unwrap();
        ctx.far_install(SgwuFar {
            sess_id: sess.id,
            far_id: 1,
            apply_action: apply_action::FORW,
            outer_header_creation: Some((0x831, Some(live_ip), None)),
            ..Default::default()
        });
        note_echo_unanswered(stale);
        gtpu_paths().lock().unwrap().insert(
            down,
            GtpuPathState {
                failed: true,
                ..Default::default()
            },
        );

        let mut probed = Vec::new();
        echo_round(|ip| probed.push(ip));

        assert!(probed.contains(&live), "the live peer is probed");
        assert!(!probed.contains(&stale));
        let paths = gtpu_paths().lock().unwrap().clone();
        assert!(
            !paths.contains_key(&stale),
            "a peer no FAR references is pruned"
        );
        assert!(
            paths.contains_key(&down),
            "a DOWN path is kept until it recovers"
        );
        assert_eq!(paths.get(&live).map(|s| s.unanswered), Some(1));

        ctx.sess_remove(sess.id);
        forget_gtpu_path(live);
        forget_gtpu_path(down);
    }

    /// An Echo Response confirms the path and clears the counter. The old code
    /// discarded Echo Responses entirely, so nothing could ever recover.
    #[test]
    fn echo_response_clears_the_path_failure() {
        let _paths = GTPU_PATH_TEST_LOCK.blocking_lock();
        let peer = IpAddr::V4(Ipv4Addr::new(10, 61, 0, 2));
        forget_gtpu_path(peer);
        std::env::set_var("SGWU_GTPU_N3_REQUESTS", "1");

        note_echo_unanswered(peer);
        note_echo_unanswered(peer);
        assert!(
            gtpu_path_state(peer).failed,
            "path down after exceeding N3=1"
        );

        let state = note_echo_answered(peer);
        assert_eq!(state.unanswered, 0);
        assert!(!state.failed, "a response must clear the failure");
        assert!(failed_gtpu_paths().is_empty());

        std::env::remove_var("SGWU_GTPU_N3_REQUESTS");
        forget_gtpu_path(peer);
    }

    /// Paths are tracked per peer: one dead eNB must not mark another down.
    #[test]
    fn path_state_is_per_peer() {
        let _paths = GTPU_PATH_TEST_LOCK.blocking_lock();
        let dead = IpAddr::V4(Ipv4Addr::new(10, 61, 0, 3));
        let alive = IpAddr::V4(Ipv4Addr::new(10, 61, 0, 4));
        forget_gtpu_path(dead);
        forget_gtpu_path(alive);
        std::env::set_var("SGWU_GTPU_N3_REQUESTS", "1");

        note_echo_unanswered(dead);
        note_echo_unanswered(dead);
        note_echo_answered(alive);

        assert!(gtpu_path_state(dead).failed);
        assert!(!gtpu_path_state(alive).failed);
        assert_eq!(failed_gtpu_paths(), vec![dead]);

        std::env::remove_var("SGWU_GTPU_N3_REQUESTS");
        forget_gtpu_path(dead);
        forget_gtpu_path(alive);
    }

    /// Probing is configurable and disablable (the cadence is a deployment
    /// choice; Section 20.3.1 mandates the detection, not the interval).
    #[test]
    fn echo_interval_is_configurable_and_disablable() {
        let _paths = GTPU_PATH_TEST_LOCK.blocking_lock();
        std::env::set_var("SGWU_GTPU_ECHO_INTERVAL_SECS", "0");
        assert_eq!(gtpu_echo_interval(), None, "0 disables probing");
        std::env::set_var("SGWU_GTPU_ECHO_INTERVAL_SECS", "5");
        assert_eq!(gtpu_echo_interval(), Some(Duration::from_secs(5)));
        std::env::remove_var("SGWU_GTPU_ECHO_INTERVAL_SECS");
    }

    /// The peers probed are exactly those the installed FARs forward to
    /// (Section 20.3.1: the peers we are "in contact with"), deduplicated so a
    /// busy eNB is probed once rather than per bearer.
    #[test]
    fn probe_targets_come_from_installed_far_peers_deduplicated() {
        let ctx = sgwu_self();
        let f_seid = FSeid::with_ipv4(0x6100, Ipv4Addr::new(10, 0, 0, 1));
        let sess = ctx.sess_add(&f_seid).unwrap();
        let enb = Ipv4Addr::new(10, 61, 9, 1);

        // Two FARs toward the SAME peer, plus one toward another.
        for (far_id, ip) in [(1u32, enb), (2, enb), (3, Ipv4Addr::new(10, 61, 9, 2))] {
            ctx.far_install(SgwuFar {
                sess_id: sess.id,
                far_id,
                outer_header_creation: Some((0x100 + far_id, Some(ip), None)),
                ..Default::default()
            });
        }

        let peers = gtpu_peer_addresses();
        assert!(peers.contains(&IpAddr::V4(enb)));
        assert_eq!(
            peers.iter().filter(|p| **p == IpAddr::V4(enb)).count(),
            1,
            "a peer with several FARs must be probed once, not per bearer"
        );

        ctx.sess_remove(sess.id);
    }
}
