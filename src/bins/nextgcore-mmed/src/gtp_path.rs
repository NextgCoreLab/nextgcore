//! MME GTP Path Management
//!
//! Port of src/mme/mme-gtp-path.c - GTP path/send functions for S11 interface

use crate::context::MmeContext;
use crate::s11_build::{
    self, Gtp2BearerQos, GtpCause, GtpCreateAction, GtpDeleteAction, GtpModifyAction,
    GtpReleaseAction,
};
use bytes::Bytes;
use nextgcore_gtp::v2::xact::{Gtp2XactConfig, Gtp2XactMgr};
use nextgcore_gtp::v2::{Gtp2IeType, Gtp2Message, Gtp2MessageType, Gtp2RecoveryIe};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Echo interval when nothing overrides it (TS 23.007 §20: 60 s is the value the
/// spec suggests for GTP-C path management).
const DEFAULT_ECHO_INTERVAL_SECS: u64 = 60;

/// GTP-C path state per peer (TS 23.007 §20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GtpPeerState {
    /// Nothing heard from or sent to the peer yet.
    #[default]
    Idle,
    /// The peer has answered.
    Active,
    /// N3 retransmissions exhausted: the peer is unreachable.
    Failed,
}

struct GtpcInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    restart_counter: u8,
    xact: Mutex<Gtp2XactMgr>,
    /// Last Recovery (restart counter) seen per peer IP (TS 23.007 §18).
    peer_restart: Mutex<HashMap<IpAddr, u8>>,
    peer_state: Mutex<HashMap<SocketAddr, GtpPeerState>>,
    running: AtomicBool,
}

/// The MME's S11 GTPv2-C endpoint (#51).
///
/// Before this, `gtp_open` set a boolean and every `send_*` built a message into a
/// `_pkbuf` local that was dropped on the next line — twelve of them. So no Create
/// Session Request ever left the MME, nothing retransmitted, and nothing correlated
/// a response to a request. The EPS control plane was inoperable end to end.
///
/// Deliberately modelled on `sgwcd`'s `GtpcServer` rather than invented: the two are
/// the two ends of the same interface, and a second design would be two answers to
/// "how long may an S11 message take" and "when is a peer down". The shared
/// [`Gtp2XactMgr`] is what makes them agree — it was referenced only by sgwcd and
/// never instantiated by mmed, which is why the MME had no T3-RESPONSE/N3-REQUESTS
/// budget at all.
///
/// Synchronous (OS threads, blocking socket with a read timeout) for the same reason
/// sgwcd is: the NAS and S1AP paths that originate these messages are synchronous,
/// and putting an executor in front of them is a far larger change than this issue.
#[derive(Clone)]
pub struct GtpcServer {
    inner: Arc<GtpcInner>,
}

/// The process-wide S11 server, installed at startup.
///
/// A `OnceLock` and not a parameter, because the twelve senders are called from
/// synchronous NAS/S1AP code paths that thread no transport handle — the same shape
/// as `fd_path`'s S6a queue. `None` means the socket was never bound, and every send
/// then reports that rather than pretending to have transmitted.
static S11_SERVER: OnceLock<GtpcServer> = OnceLock::new();

/// Install the process-wide S11 server. Returns `false` if one is already installed.
pub fn install_server(server: GtpcServer) -> bool {
    S11_SERVER.set(server).is_ok()
}

/// The installed S11 server, or `None` when the socket was never bound.
pub fn server() -> Option<&'static GtpcServer> {
    S11_SERVER.get()
}

/// What a sent Create Session Request was for, so its response can continue the
/// procedure that started it (#329).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingCreate {
    /// The EMM/ESM procedure that triggered the request.
    pub create_action: GtpCreateAction,
    /// The eNB UE context the continuation has to answer on.
    pub enb_ue_id: u64,
    /// The session the response's PAA and bearer TEIDs belong to.
    pub sess_id: u64,
}

/// Pending Create Session Requests, keyed by S11 sequence number.
///
/// # Why this exists at all
///
/// `send_create_session_request` returns a `GtpXactData` carrying the create action
/// and the eNB UE id, and the caller was expected to hold it — but it had **no
/// caller**, so nothing did (#329). The response path
/// (`s11_handler::dispatch_triggered`) receives only the raw bytes, the message type,
/// the sequence number and the peer, so without this it cannot tell an attach's
/// Create Session Response from a TAU's, and would either answer every one with an
/// Attach Accept or none.
///
/// Keyed by SEQUENCE NUMBER because that is what the transaction layer already
/// correlates on (`GtpcInner::match_response`), so there is one notion of "which
/// request is this the answer to" rather than two that can disagree. Keyed by the
/// local TEID instead would collapse two concurrent requests for the same UE.
///
/// Entries are TAKEN, not read: a response consumes its record, so a retransmitted
/// or duplicated response cannot drive the continuation twice.
static PENDING_CREATES: OnceLock<Mutex<HashMap<u32, PendingCreate>>> = OnceLock::new();

fn pending_creates() -> &'static Mutex<HashMap<u32, PendingCreate>> {
    PENDING_CREATES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record what a Create Session Request at `seq` was for.
fn record_pending_create(seq: u32, pending: PendingCreate) {
    if let Ok(mut map) = pending_creates().lock() {
        map.insert(seq, pending);
    }
}

/// Take the record for the Create Session Request at `seq`, if this MME sent one.
///
/// `None` means either that the response is for a request this MME did not send, or
/// that its record was already consumed — both of which are reasons NOT to continue a
/// procedure, which is why the caller treats them the same way.
pub fn take_pending_create(seq: u32) -> Option<PendingCreate> {
    pending_creates().lock().ok()?.remove(&seq)
}

/// Serialises every test that installs the process-wide S11 server, touches the MME
/// context's GTP-C configuration, or drives the S11 response path.
///
/// Declared beside the globals it guards rather than inside a `mod tests`, per #308,
/// and `pub(crate)` so `s11_handler`'s tests share THIS lock: the globals involved are
/// `S11_SERVER`, `PENDING_CREATES`, and `mme_self()`'s UE/session/bearer pools plus its
/// `gtpc_list` / `sgwc_list`, and they cannot be guarded separately. A second lock over
/// the same variables would be two disjoint agreements rather than one — #276 showed
/// that mistake HANGS the suite rather than merely flaking it, which is why this is
/// promoted here instead of re-declared in `s11_handler` (#329).
#[cfg(test)]
pub(crate) static S11_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`S11_TEST_LOCK`], recovering from a poisoned guard so one failing test does
/// not cascade into every sibling.
#[cfg(test)]
pub(crate) fn lock_s11() -> std::sync::MutexGuard<'static, ()> {
    S11_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record a pending create without sending anything.
///
/// Test-only. The response path's behaviour turns entirely on whether a record exists
/// and what create action it names, and driving that through a real socket send would
/// make every response-side test also a transport test — so this seeds the one input
/// the response path reads. Callers hold [`S11_TEST_LOCK`].
#[cfg(test)]
pub(crate) fn record_pending_create_for_test(seq: u32, pending: PendingCreate) {
    record_pending_create(seq, pending);
}

/// Drop every pending record.
///
/// Declared here beside the map rather than in a `mod tests`: it is process-global, so
/// a test that mutates it races every sibling that reads it, and a second lock
/// declared elsewhere would be a second agreement rather than one. Callers hold
/// [`S11_TEST_LOCK`].
#[cfg(test)]
pub fn clear_pending_creates_for_test() {
    if let Ok(mut map) = pending_creates().lock() {
        map.clear();
    }
}

/// Send `msg` as an initial message to the configured Serving GW.
///
/// One place resolves the peer and reports the two ways a send can fail before it
/// reaches the wire — no socket, or no configured SGW-C — so the twelve senders do
/// not each grow their own version of that reporting.
fn send_to_sgwc(ctx: &MmeContext, msg: &Gtp2Message, data: u64) -> GtpPathResult<u32> {
    let server = server().ok_or_else(|| {
        GtpPathError::SocketError(
            "no S11 socket bound: mme.gtpc.server is unset or the bind failed".to_string(),
        )
    })?;
    let peer = *ctx.sgwc_list.first().ok_or_else(|| {
        GtpPathError::InvalidState(
            "no Serving GW peer configured (mme.gtpc.client.sgwc)".to_string(),
        )
    })?;
    server
        .send_request(peer, msg, data)
        .map_err(GtpPathError::SocketError)
}

/// Send `msg` as a triggered message, echoing the request's sequence number.
fn send_response_to(peer: SocketAddr, msg: &Gtp2Message) -> GtpPathResult<()> {
    let server = server().ok_or_else(|| {
        GtpPathError::SocketError("no S11 socket bound: cannot answer".to_string())
    })?;
    server
        .send_response(peer, msg)
        .map_err(GtpPathError::SocketError)
}

pub type GtpPathResult<T> = Result<T, GtpPathError>;

#[derive(Debug, Clone)]
pub enum GtpPathError {
    SocketError(String),
    BuildError(String),
    TransactionError(String),
    ContextNotFound,
    InvalidState(String),
}

impl std::fmt::Display for GtpPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketError(msg) => write!(f, "Socket error: {msg}"),
            Self::BuildError(msg) => write!(f, "Build error: {msg}"),
            Self::TransactionError(msg) => write!(f, "Transaction error: {msg}"),
            Self::ContextNotFound => write!(f, "Context not found"),
            Self::InvalidState(msg) => write!(f, "Invalid state: {msg}"),
        }
    }
}

impl std::error::Error for GtpPathError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteIndirectAction {
    HandoverComplete,
    HandoverCancel,
}

#[derive(Debug, Clone, Default)]
pub struct GtpXactData {
    pub xact_id: u64,
    pub create_action: Option<GtpCreateAction>,
    pub delete_action: Option<GtpDeleteAction>,
    pub modify_action: Option<GtpModifyAction>,
    pub release_action: Option<GtpReleaseAction>,
    pub delete_indirect_action: Option<DeleteIndirectAction>,
    pub local_teid: u32,
    pub enb_ue_id: u64,
}

#[derive(Debug, Default)]
pub struct GtpPathState {
    pub gtpc_addr: Option<SocketAddr>,
    pub gtpc_addr6: Option<SocketAddr>,
    pub initialized: bool,
}

impl GtpcServer {
    /// Bind the S11 socket and start the receive and retransmission loops.
    pub fn open(bind: &str, config: Gtp2XactConfig, restart_counter: u8) -> Result<Self, String> {
        let socket = UdpSocket::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
        // A read timeout rather than a non-blocking socket, so the receive thread
        // can observe `running` and exit at shutdown instead of spinning.
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| e.to_string())?;
        let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

        let inner = Arc::new(GtpcInner {
            socket,
            local_addr,
            restart_counter,
            xact: Mutex::new(Gtp2XactMgr::new(config)),
            peer_restart: Mutex::new(HashMap::new()),
            peer_state: Mutex::new(HashMap::new()),
            running: AtomicBool::new(true),
        });

        {
            let inner = inner.clone();
            std::thread::Builder::new()
                .name("mme-s11-recv".into())
                .spawn(move || {
                    let mut buf = [0u8; 4096];
                    while inner.running.load(Ordering::SeqCst) {
                        match inner.socket.recv_from(&mut buf) {
                            Ok((len, peer)) => handle_datagram(&inner, &buf[..len], peer),
                            Err(e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(e) => {
                                if inner.running.load(Ordering::SeqCst) {
                                    log::error!("S11 recv error: {e}");
                                }
                            }
                        }
                    }
                })
                .map_err(|e| e.to_string())?;
        }

        // T3-RESPONSE / N3-REQUESTS loop (TS 29.274 §7.6), which also drives Echo
        // path management because it already ticks.
        {
            let inner = inner.clone();
            let last_echo: Mutex<HashMap<SocketAddr, Instant>> = Mutex::new(HashMap::new());
            std::thread::Builder::new()
                .name("mme-s11-rtx".into())
                .spawn(move || {
                    while inner.running.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(20));
                        let poll = {
                            let mut xact = match inner.xact.lock() {
                                Ok(x) => x,
                                Err(_) => continue,
                            };
                            xact.poll(Instant::now())
                        };
                        for (peer, encoded) in poll.retransmits {
                            log::warn!("S11 T3 expiry: retransmitting to {peer}");
                            if let Err(e) = inner.socket.send_to(&encoded, peer) {
                                log::error!("S11 retransmit to {peer} failed: {e}");
                            }
                        }
                        for xact in poll.exhausted {
                            // TS 29.274 §7.6: the peer is unreachable once N3
                            // retransmissions are spent.
                            log::error!(
                                "S11 N3 exhausted: peer {} not responding (type={}, seq={})",
                                xact.peer,
                                xact.message_type,
                                xact.sequence_number
                            );
                            if let Ok(mut states) = inner.peer_state.lock() {
                                states.insert(xact.peer, GtpPeerState::Failed);
                            }
                        }

                        if let Some(interval) = echo_interval() {
                            let due: Vec<SocketAddr> = match inner.peer_state.lock() {
                                Ok(states) => states.keys().copied().collect(),
                                Err(_) => Vec::new(),
                            };
                            let now = Instant::now();
                            let mut last = match last_echo.lock() {
                                Ok(l) => l,
                                Err(_) => continue,
                            };
                            for peer in due {
                                // A peer is in `peer_state` BECAUSE we just heard
                                // from it, so the first sighting starts the interval
                                // rather than triggering a probe.
                                let send = match last.get(&peer) {
                                    Some(t) => now.duration_since(*t) >= interval,
                                    None => false,
                                };
                                if send || !last.contains_key(&peer) {
                                    last.insert(peer, now);
                                }
                                if send {
                                    let server = GtpcServer {
                                        inner: inner.clone(),
                                    };
                                    if let Err(e) = server.send_echo_request(peer) {
                                        log::warn!("S11 Echo Request to {peer} failed: {e}");
                                    }
                                }
                            }
                        }
                    }
                })
                .map_err(|e| e.to_string())?;
        }

        log::info!("MME S11 GTP-C server listening on {local_addr}");
        Ok(Self { inner })
    }

    /// Stop the receive and retransmission loops.
    pub fn close(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Local bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Path state for a peer.
    pub fn peer_state(&self, peer: SocketAddr) -> GtpPeerState {
        self.inner
            .peer_state
            .lock()
            .ok()
            .and_then(|s| s.get(&peer).copied())
            .unwrap_or(GtpPeerState::Idle)
    }

    /// Outstanding transactions awaiting a triggered message.
    pub fn outstanding(&self) -> usize {
        self.inner.xact.lock().map(|x| x.outstanding()).unwrap_or(0)
    }

    /// Allocate a GTPv2-C sequence number for an initial message.
    ///
    /// TS 29.274 §7.6 requires a sequence number per outstanding initial message,
    /// echoed in the corresponding response. Every builder used to write a literal
    /// `0`, so no response could be correlated to any request.
    pub fn alloc_sequence(&self) -> u32 {
        self.inner
            .xact
            .lock()
            .map(|mut x| x.alloc_sequence())
            .unwrap_or(1)
    }

    /// Send an initial (request) message and arm T3/N3 retransmission.
    pub fn send_request(
        &self,
        peer: SocketAddr,
        msg: &Gtp2Message,
        data: u64,
    ) -> Result<u32, String> {
        let encoded = Bytes::from(msg.encode().to_vec());
        let seq = msg.header.sequence_number;
        {
            let mut xact = self.inner.xact.lock().map_err(|e| e.to_string())?;
            xact.register_request(seq, msg.header.message_type, peer, encoded.clone(), data);
        }
        self.inner
            .socket
            .send_to(&encoded, peer)
            .map_err(|e| e.to_string())?;
        if let Ok(mut states) = self.inner.peer_state.lock() {
            states.entry(peer).or_insert(GtpPeerState::Idle);
        }
        log::debug!(
            "S11 TX request type={} seq={} to {peer} len={}",
            msg.header.message_type,
            seq,
            encoded.len()
        );
        Ok(seq)
    }

    /// Send a triggered (response) message bound to the request's sequence number,
    /// caching it so a retransmitted request is answered identically.
    pub fn send_response(&self, peer: SocketAddr, msg: &Gtp2Message) -> Result<(), String> {
        let encoded = Bytes::from(msg.encode().to_vec());
        if let Ok(mut xact) = self.inner.xact.lock() {
            xact.cache_response(peer, msg.header.sequence_number, encoded.clone());
        }
        self.inner
            .socket
            .send_to(&encoded, peer)
            .map_err(|e| e.to_string())?;
        log::debug!(
            "S11 TX response type={} seq={} to {peer} len={}",
            msg.header.message_type,
            msg.header.sequence_number,
            encoded.len()
        );
        Ok(())
    }

    /// Send an Echo Request (TS 29.274 §7.1.1).
    ///
    /// The builders for this existed and had no caller, so the MME had no path
    /// management at all: a Serving GW that went away was never noticed.
    pub fn send_echo_request(&self, peer: SocketAddr) -> Result<u32, String> {
        let seq = self.alloc_sequence();
        // The library's constructors already clear the TEID-presence flag, which a
        // node-level message requires (TS 29.274 §5.5.1).
        let mut msg = Gtp2Message::echo_request(seq);
        for ie in Gtp2Message::echo_response(seq, self.inner.restart_counter).ies {
            msg.add_ie(ie);
        }
        self.send_request(peer, &msg, 0)
    }
}

/// Where the local GTP-C restart counter is persisted (TS 23.007 §18).
const DEFAULT_RESTART_COUNTER_FILE: &str = "/var/lib/nextgcore/mme-restart-counter";

fn restart_counter_path() -> std::path::PathBuf {
    std::env::var("MME_RESTART_COUNTER_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_RESTART_COUNTER_FILE))
}

/// Read the persisted restart counter, advance it, write it back, and return the
/// value to advertise in Recovery IEs.
///
/// The counter has to SURVIVE the restart it signals — a value that resets to the
/// same number every start tells a peer nothing changed. Mirrors sgwcd's, which is
/// the same requirement on the other end of the same interface; a second design here
/// would be two answers to "has this node restarted".
///
/// * absent file → first start, begin at 1 and persist it;
/// * unreadable or malformed → log loudly and fall back to 1, because a wrong
///   counter is worse silently than loudly;
/// * wraparound at 255 → back to 1, which a peer reads as a restart either way.
pub(crate) fn advance_persistent_restart_counter(path: &std::path::Path) -> u8 {
    let previous = match std::fs::read_to_string(path) {
        Ok(text) => match text.trim().parse::<u8>() {
            Ok(v) => Some(v),
            Err(_) => {
                log::error!(
                    "Restart counter file {} is malformed ({:?}); restarting the count at 1, so \
                     peers may not detect this MME restart (TS 23.007 §18)",
                    path.display(),
                    text.trim()
                );
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            log::error!(
                "Cannot read restart counter file {}: {e}; restarting the count at 1, so peers \
                 may not detect this MME restart",
                path.display()
            );
            None
        }
    };

    let next = match previous {
        Some(v) => v.checked_add(1).unwrap_or(1),
        None => 1,
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                log::error!(
                    "Cannot create {} for the restart counter: {e}",
                    parent.display()
                );
            }
        }
    }
    let tmp = path.with_extension("tmp");
    let write = std::fs::write(&tmp, next.to_string()).and_then(|()| std::fs::rename(&tmp, path));
    match write {
        Ok(()) => log::info!(
            "Local GTP-C restart counter advanced to {next} (persisted at {})",
            path.display()
        ),
        Err(e) => log::error!(
            "Cannot persist restart counter to {}: {e}; the next start will not advance it and \
             peers will not detect that restart",
            path.display()
        ),
    }
    next
}

/// Echo interval, `0` disabling path management entirely.
fn echo_interval() -> Option<Duration> {
    let secs = std::env::var("MME_ECHO_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_ECHO_INTERVAL_SECS);
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

/// Note a peer's Recovery counter, logging a restart (TS 23.007 §18).
///
/// Recorded and logged rather than acted on: deleting this MME's contexts because the
/// SGW restarted is a decision about UE state that #51 does not own, and doing it
/// silently would detach every attached UE on a counter change that a reordered
/// datagram can also produce.
fn note_peer_recovery(inner: &Arc<GtpcInner>, peer: SocketAddr, counter: u8) {
    let Ok(mut seen) = inner.peer_restart.lock() else {
        return;
    };
    match seen.insert(peer.ip(), counter) {
        Some(previous) if previous != counter => log::warn!(
            "S11 peer {peer} restarted: Recovery {previous} -> {counter}; its S11 contexts are \
             stale (TS 23.007 §18)"
        ),
        _ => log::debug!("S11 peer {peer} Recovery counter {counter}"),
    }
}

/// Dispatch one received datagram.
fn handle_datagram(inner: &Arc<GtpcInner>, data: &[u8], peer: SocketAddr) {
    let mut bytes = Bytes::copy_from_slice(data);
    let msg = match Gtp2Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            log::error!("[DROP] cannot decode GTPv2-C datagram from {peer}: {e}");
            return;
        }
    };

    if let Some(rec_ie) = msg.get_ie(Gtp2IeType::Recovery as u8, 0) {
        if let Ok(rec) = Gtp2RecoveryIe::decode(&rec_ie.value) {
            note_peer_recovery(inner, peer, rec.restart_counter);
        }
    }

    let msg_type = msg.header.message_type;
    let seq = msg.header.sequence_number;

    // An Echo Request is answered from here: it is path management and needs no
    // session state, so routing it through the handler layer would only add a hop.
    if msg_type == Gtp2MessageType::EchoRequest as u8 {
        let reply = Gtp2Message::echo_response(seq, inner.restart_counter);
        let encoded = reply.encode();
        if let Err(e) = inner.socket.send_to(&encoded, peer) {
            log::error!("S11 Echo Response to {peer} failed: {e}");
        }
        if let Ok(mut states) = inner.peer_state.lock() {
            states.insert(peer, GtpPeerState::Active);
        }
        return;
    }

    // A triggered message closes its transaction. Matching FIRST and only then
    // dispatching is what makes the response correlated rather than merely received:
    // an unmatched response is one this MME did not ask for, and acting on it would
    // let a stray datagram mutate session state.
    let matched = {
        match inner.xact.lock() {
            Ok(mut xact) => xact.match_response(seq, msg_type),
            Err(_) => None,
        }
    };

    if let Some(xact) = matched {
        if let Ok(mut states) = inner.peer_state.lock() {
            states.insert(peer, GtpPeerState::Active);
        }
        log::debug!(
            "S11 RX response type={msg_type} seq={seq} from {peer} correlates to request type={}",
            xact.message_type
        );
        crate::s11_handler::dispatch_triggered(data, msg_type, seq, peer);
        return;
    }

    // Not a response to anything outstanding: either an initial message from the
    // SGW-C (Downlink Data Notification, Create/Update/Delete Bearer Request) or a
    // late duplicate of a response whose transaction has already closed.
    if let Ok(mut states) = inner.peer_state.lock() {
        states.entry(peer).or_insert(GtpPeerState::Active);
    }
    crate::s11_handler::dispatch_initial(data, msg_type, seq, peer);
}

/// Bind the S11 socket from configuration and install it process-wide (#51).
///
/// `gtp_open` used to set `state.initialized = true` and bind nothing, which is why
/// every `send_*` had nowhere to send. With no `mme.gtpc.server` configured this
/// still returns `Ok` and logs why: an MME with no S11 address is a deployment that
/// has not been given one, and refusing to start would break every existing config
/// that never needed the socket.
pub fn gtp_open(state: &mut GtpPathState) -> GtpPathResult<()> {
    let ctx = crate::context::mme_self();
    let Some(bind) = ctx.gtpc_list.first().copied() else {
        log::warn!(
            "no mme.gtpc.server address configured: the S11 interface is NOT bound, so no \
             Create Session Request can be sent and no EPS bearer can be established"
        );
        state.initialized = true;
        return Ok(());
    };

    // The restart counter advertised in Recovery, persisted so it survives the
    // restart it signals (TS 23.007 §18). An explicit override exists for tests and
    // for a deployment that manages the value itself.
    let restart_counter = match std::env::var("MME_RESTART_COUNTER")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
    {
        Some(v) => v,
        None => advance_persistent_restart_counter(&restart_counter_path()),
    };
    let server = GtpcServer::open(
        &bind.to_string(),
        Gtp2XactConfig::default(),
        restart_counter,
    )
    .map_err(GtpPathError::SocketError)?;
    state.gtpc_addr = Some(server.local_addr());
    if !install_server(server) {
        log::warn!("an S11 server is already installed; this one is dropped");
    }
    state.initialized = true;
    log::info!("S11 GTP-C path opened on {bind}");
    Ok(())
}

pub fn gtp_close(state: &mut GtpPathState) -> GtpPathResult<()> {
    log::info!("Closing GTP path");
    if let Some(server) = server() {
        server.close();
    }
    state.initialized = false;
    log::info!("GTP path closed");
    Ok(())
}

pub fn send_create_session_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    sess_id: u64,
    create_action: GtpCreateAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Create Session Request");

    let sess = ctx
        .sess_find_by_id(sess_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx
        .mme_ue_find_by_id(sess.mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    let target_sgw_ue = if create_action == GtpCreateAction::PathSwitchRequest {
        ctx.sgw_ue_find_by_id(sgw_ue.target_ue_id)
            .ok_or(GtpPathError::ContextNotFound)?
    } else {
        sgw_ue.clone()
    };

    // The bearers to create. TS 29.274 Table 7.2.1-1 makes at least one Bearer
    // Context mandatory, and the builder refuses without one rather than emitting a
    // request the SGW-C must reject.
    let bearers = bearers_of_session(ctx, &sess);
    let bearer_refs: Vec<&crate::context::MmeBearer> = bearers.iter().collect();

    // The Sender F-TEID's address is this MME's bound S11 address, so it is the
    // socket's own rather than whatever configuration says — a mismatch would send
    // the SGW's response to an address nothing is listening on.
    let local_s11 = server()
        .map(|s| s.local_addr())
        .or_else(|| ctx.gtpc_list.first().copied())
        .ok_or_else(|| {
            GtpPathError::InvalidState("no S11 local address to put in the Sender F-TEID".into())
        })?;

    let seq = sequence()?;
    let msg = s11_build::build_create_session_request(
        &sess,
        &mme_ue,
        &target_sgw_ue,
        create_action,
        seq,
        &bearer_refs,
        local_s11,
    )
    .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    let xact_id = ctx.next_pool_id();
    send_to_sgwc(ctx, &msg, xact_id)?;

    // #329: record what this request was for BEFORE returning, so the response path
    // can continue the procedure. Recorded after the send succeeds: a request that
    // never left would leave a record no response can ever consume.
    record_pending_create(
        seq,
        PendingCreate {
            create_action,
            enb_ue_id,
            sess_id,
        },
    );

    Ok(GtpXactData {
        xact_id,
        create_action: Some(create_action),
        // The LOCAL S11 TEID, which is what the SGW addresses the response to and
        // what `mme_ue_find_by_s11_local_teid` resolves. `gn.mme_gn_teid` is the Gn
        // interface's TEID and belongs to a different interface entirely.
        local_teid: mme_ue.mme_s11_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_modify_bearer_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
    uli_presence: bool,
    modify_action: GtpModifyAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Modify Bearer Request");

    let mme_ue = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    // The bearers whose eNB S1-U endpoint the SGW must switch to. Passed as an
    // EMPTY slice before #51, so the message asked the SGW to modify nothing.
    let bearers = bearers_of_ue(ctx, mme_ue_id);
    let bearer_refs: Vec<&crate::context::MmeBearer> = bearers.iter().collect();

    let seq = sequence()?;
    let msg =
        s11_build::build_modify_bearer_request(&mme_ue, &sgw_ue, &bearer_refs, uli_presence, seq)
            .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    let xact_id = ctx.next_pool_id();
    send_to_sgwc(ctx, &msg, xact_id)?;

    Ok(GtpXactData {
        xact_id,
        modify_action: Some(modify_action),
        local_teid: mme_ue.mme_s11_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_delete_session_request(
    ctx: &MmeContext,
    enb_ue_id: Option<u64>,
    sgw_ue_id: u64,
    sess_id: u64,
    action: GtpDeleteAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Delete Session Request");

    let sess = ctx
        .sess_find_by_id(sess_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx
        .mme_ue_find_by_id(sess.mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    // The Linked EPS Bearer ID is the DEFAULT bearer of the PDN connection being
    // torn down (TS 29.274 Table 7.2.9.1-1). A literal 5 was passed before #51,
    // which tears down the wrong PDN for any UE holding more than one.
    let linked_ebi = default_bearer_ebi(ctx, &sess).ok_or_else(|| {
        GtpPathError::InvalidState(format!(
            "session {} has no default bearer, so no Linked EPS Bearer ID can be sent",
            sess.id
        ))
    })?;

    let seq = sequence()?;
    let msg =
        s11_build::build_delete_session_request(&sess, &mme_ue, &sgw_ue, linked_ebi, action, seq)
            .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    let xact_id = ctx.next_pool_id();
    send_to_sgwc(ctx, &msg, xact_id)?;

    Ok(GtpXactData {
        xact_id,
        delete_action: Some(action),
        local_teid: mme_ue.mme_s11_teid,
        enb_ue_id: enb_ue_id.unwrap_or(0),
        ..Default::default()
    })
}

pub fn send_delete_all_sessions(
    ctx: &MmeContext,
    enb_ue_id: Option<u64>,
    mme_ue_id: u64,
    action: GtpDeleteAction,
) -> GtpPathResult<Vec<GtpXactData>> {
    log::debug!("Sending Delete All Sessions");

    let mme_ue = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue_id = mme_ue.sgw_ue_id;

    let mut xacts = Vec::new();
    for sess_id in &mme_ue.sess_list {
        if ctx.sess_find_by_id(*sess_id).is_some() {
            let xact = send_delete_session_request(ctx, enb_ue_id, sgw_ue_id, *sess_id, action)?;
            xacts.push(xact);
        }
    }
    Ok(xacts)
}

pub fn send_create_bearer_response(
    ctx: &MmeContext,
    bearer_id: u64,
    cause_value: GtpCause,
    peer: SocketAddr,
    sequence_number: u32,
) -> GtpPathResult<()> {
    log::debug!("Sending Create Bearer Response");

    let bearer = ctx
        .bearer_find_by_id(bearer_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx
        .mme_ue_find_by_id(bearer.mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    // A TRIGGERED message: it must echo the sequence number of the request it
    // answers and go back to the peer that sent it (TS 29.274 §7.6). Both are
    // supplied by the caller, because only the receive path knows them.
    let msg = s11_build::build_create_bearer_response(
        &bearer,
        &mme_ue,
        &sgw_ue,
        cause_value,
        sequence_number,
    )
    .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    send_response_to(peer, &msg)
}

pub fn send_update_bearer_response(
    ctx: &MmeContext,
    bearer_id: u64,
    cause_value: GtpCause,
    peer: SocketAddr,
    sequence_number: u32,
) -> GtpPathResult<()> {
    log::debug!("Sending Update Bearer Response");

    let bearer = ctx
        .bearer_find_by_id(bearer_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx
        .mme_ue_find_by_id(bearer.mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    // A TRIGGERED message: it must echo the sequence number of the request it
    // answers and go back to the peer that sent it (TS 29.274 §7.6). Both are
    // supplied by the caller, because only the receive path knows them.
    let msg = s11_build::build_update_bearer_response(
        &bearer,
        &mme_ue,
        &sgw_ue,
        cause_value,
        sequence_number,
    )
    .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    send_response_to(peer, &msg)
}

pub fn send_delete_bearer_response(
    ctx: &MmeContext,
    bearer_id: u64,
    cause_value: GtpCause,
    peer: SocketAddr,
    sequence_number: u32,
) -> GtpPathResult<()> {
    log::debug!("Sending Delete Bearer Response");

    let bearer = ctx
        .bearer_find_by_id(bearer_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx
        .mme_ue_find_by_id(bearer.mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    // A TRIGGERED message: it must echo the sequence number of the request it
    // answers and go back to the peer that sent it (TS 29.274 §7.6). Both are
    // supplied by the caller, because only the receive path knows them.
    let msg = s11_build::build_delete_bearer_response(
        &bearer,
        &mme_ue,
        &sgw_ue,
        cause_value,
        sequence_number,
    )
    .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    send_response_to(peer, &msg)
}

pub fn send_release_access_bearers_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
    action: GtpReleaseAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Release Access Bearers Request");

    let mme_ue = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    // An INITIAL message, so its sequence number comes from the transaction layer.
    // `ctx.next_pool_id() as u32` was a POOL INDEX in the sequence position — it
    // collides with every other pool allocation and means nothing to the peer.
    let seq = sequence()?;
    let msg = s11_build::build_release_access_bearers_request(sgw_ue.sgw_s11_teid, seq);
    let xact_id = ctx.next_pool_id();
    send_to_sgwc(ctx, &msg, xact_id)?;

    Ok(GtpXactData {
        xact_id,
        release_action: Some(action),
        local_teid: mme_ue.mme_s11_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_release_all_ue_in_enb(
    ctx: &MmeContext,
    enb_id: u64,
    action: GtpReleaseAction,
) -> GtpPathResult<Vec<GtpXactData>> {
    log::debug!("Sending Release All UE in eNB");

    let enb = ctx
        .enb_find_by_id(enb_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let mut xacts = Vec::new();

    for enb_ue_id in &enb.enb_ue_list {
        if let Some(enb_ue) = ctx.enb_ue_find_by_id(*enb_ue_id) {
            if ctx.mme_ue_find_by_id(enb_ue.mme_ue_id).is_some() {
                let xact =
                    send_release_access_bearers_request(ctx, *enb_ue_id, enb_ue.mme_ue_id, action)?;
                xacts.push(xact);
            }
        }
    }
    Ok(xacts)
}

pub fn send_downlink_data_notification_ack(
    ctx: &MmeContext,
    bearer_id: u64,
    cause_value: GtpCause,
    sequence_number: u32,
) -> GtpPathResult<()> {
    log::debug!("Sending Downlink Data Notification Ack");

    let bearer = ctx
        .bearer_find_by_id(bearer_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx
        .mme_ue_find_by_id(bearer.mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    let peer = *ctx
        .sgwc_list
        .first()
        .ok_or_else(|| GtpPathError::InvalidState("no Serving GW peer configured".to_string()))?;
    send_downlink_data_notification_ack_to(peer, sgw_ue.sgw_s11_teid, sequence_number, cause_value)
}

/// Answer a Downlink Data Notification, echoing its sequence number (TS 29.274
/// §7.2.11).
///
/// The Ack is a TRIGGERED message. `ctx.next_pool_id() as u32` used to occupy the
/// sequence position, which is a pool index: even had the message been transmitted,
/// the SGW-C could not have matched it to the notification it answered.
pub fn send_downlink_data_notification_ack_to(
    peer: SocketAddr,
    teid: u32,
    sequence_number: u32,
    cause_value: GtpCause,
) -> GtpPathResult<()> {
    let msg = s11_build::build_downlink_data_notification_ack(teid, sequence_number, cause_value)
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    send_response_to(peer, &msg)
}

pub fn send_create_indirect_data_forwarding_tunnel_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Create Indirect Data Forwarding Tunnel Request");

    let mme_ue = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    let bearers = bearers_of_ue(ctx, mme_ue_id);
    let bearer_refs: Vec<&crate::context::MmeBearer> = bearers.iter().collect();
    let seq = sequence()?;
    let msg = s11_build::build_create_indirect_data_forwarding_tunnel_request(
        &mme_ue,
        &sgw_ue,
        &bearer_refs,
        seq,
    )
    .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    let xact_id = ctx.next_pool_id();
    send_to_sgwc(ctx, &msg, xact_id)?;

    Ok(GtpXactData {
        xact_id,
        local_teid: mme_ue.mme_s11_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_delete_indirect_data_forwarding_tunnel_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
    action: DeleteIndirectAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Delete Indirect Data Forwarding Tunnel Request");

    let mme_ue = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    Ok(GtpXactData {
        xact_id: ctx.next_pool_id(),
        delete_indirect_action: Some(action),
        local_teid: mme_ue.gn.mme_gn_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_bearer_resource_command(
    ctx: &MmeContext,
    bearer_id: u64,
    linked_bearer_ebi: u8,
    pti: u8,
    tad: &[u8],
    qos: Option<&Gtp2BearerQos>,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Bearer Resource Command");

    let bearer = ctx
        .bearer_find_by_id(bearer_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx
        .mme_ue_find_by_id(bearer.mme_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .ok_or(GtpPathError::ContextNotFound)?;

    let seq = sequence()?;
    let msg = s11_build::build_bearer_resource_command(
        &bearer,
        &mme_ue,
        &sgw_ue,
        linked_bearer_ebi,
        pti,
        tad,
        qos,
        seq,
    )
    .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    let xact_id = ctx.next_pool_id() | GTP_CMD_XACT_ID_FLAG;
    send_to_sgwc(ctx, &msg, xact_id)?;

    Ok(GtpXactData {
        xact_id,
        local_teid: mme_ue.mme_s11_teid,
        ..Default::default()
    })
}

/// A sequence number from the transaction layer for an initial message.
///
/// Every builder wrote a literal `0` before #51, and two senders substituted
/// `ctx.next_pool_id()` — a pool index. TS 29.274 §7.6 requires one sequence number
/// per outstanding initial message, echoed in the response, so both spellings made
/// correlation impossible.
fn sequence() -> GtpPathResult<u32> {
    server().map(|s| s.alloc_sequence()).ok_or_else(|| {
        GtpPathError::SocketError("no S11 socket bound: cannot allocate a sequence".to_string())
    })
}

/// The bearers of one session, in EBI order.
fn bearers_of_session(
    ctx: &MmeContext,
    sess: &crate::context::MmeSess,
) -> Vec<crate::context::MmeBearer> {
    let mut bearers: Vec<crate::context::MmeBearer> = sess
        .bearer_list
        .iter()
        .filter_map(|id| ctx.bearer_find_by_id(*id))
        .collect();
    bearers.sort_by_key(|b| b.ebi);
    bearers
}

/// Every bearer of every session of one UE, in EBI order.
fn bearers_of_ue(ctx: &MmeContext, mme_ue_id: u64) -> Vec<crate::context::MmeBearer> {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return Vec::new();
    };
    let mut bearers: Vec<crate::context::MmeBearer> = mme_ue
        .sess_list
        .iter()
        .filter_map(|sess_id| ctx.sess_find_by_id(*sess_id))
        .flat_map(|sess| bearers_of_session(ctx, &sess))
        .collect();
    bearers.sort_by_key(|b| b.ebi);
    bearers
}

/// The EBI of a session's DEFAULT bearer — the lowest, since
/// `materialise_subscribed_sessions` allocates one default bearer per APN from the
/// bottom of the range (TS 24.007 §11.2.3.1.5 reserves 0-4).
///
/// `None` for a session with no bearers, which the caller reports rather than
/// falling back to a literal: TS 29.274 Table 7.2.9.1-1 makes the Linked EPS Bearer
/// ID mandatory and naming the wrong one tears down the wrong PDN connection.
fn default_bearer_ebi(ctx: &MmeContext, sess: &crate::context::MmeSess) -> Option<u8> {
    bearers_of_session(ctx, sess).first().map(|b| b.ebi)
}

const GTP_CMD_XACT_ID_FLAG: u64 = 0x8000_0000_0000_0000;

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_s11() -> std::sync::MutexGuard<'static, ()> {
        super::lock_s11()
    }

    #[test]
    fn test_gtp_path_state_default() {
        let state = GtpPathState::default();
        assert!(!state.initialized);
    }

    #[test]
    fn test_delete_indirect_action() {
        assert_ne!(
            DeleteIndirectAction::HandoverComplete,
            DeleteIndirectAction::HandoverCancel
        );
    }

    /// The restart counter must SURVIVE the restart it signals (TS 23.007 §18): a
    /// value that resets to the same number every start tells a peer nothing changed.
    #[test]
    fn the_restart_counter_advances_across_starts() {
        let dir = std::env::temp_dir().join(format!("mme-restart-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("counter");
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            advance_persistent_restart_counter(&path),
            1,
            "a first start begins at 1"
        );
        assert_eq!(
            advance_persistent_restart_counter(&path),
            2,
            "the next start must ADVANCE, or the peer cannot detect the restart"
        );

        std::fs::write(&path, "not-a-number").expect("write");
        assert_eq!(
            advance_persistent_restart_counter(&path),
            1,
            "malformed contents fall back to 1 rather than panicking"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Install a server bound to an ephemeral port, with a stand-in SGW-C socket as
    /// its configured peer.
    ///
    /// The server is a real bound socket running its real receive and T3/N3 threads —
    /// the point of #51 is that these messages reach a wire, so a test that stubbed
    /// the transport would assert the half that already worked.
    fn spawn_server_and_peer(config: Gtp2XactConfig) -> (GtpcServer, UdpSocket, SocketAddr) {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("peer bind");
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("peer timeout");
        let peer_addr = peer.local_addr().expect("peer addr");
        let server = GtpcServer::open("127.0.0.1:0", config, 7).expect("server bind");
        (server, peer, peer_addr)
    }

    /// #51 criterion 3: the Create Session Request carries every IE a conformant peer
    /// requires, asserted after a real round trip through the socket.
    ///
    /// The required set MIRRORS `sgwcd`'s `s11_parse.rs:85-120` — IMSI, RAT Type,
    /// Sender F-TEID, APN, and a Bearer Context with EBI and Bearer QoS. It is a
    /// mirrored list rather than a call into that parser because `sgwcd` is a binary
    /// with no lib target, so its `require()` is unreachable from here. See the spec's
    /// Ceilings.
    #[test]
    fn a_create_session_request_reaches_the_wire_with_every_mandatory_ie() {
        let _guard = lock_s11();
        let (server, peer, peer_addr) = spawn_server_and_peer(Gtp2XactConfig::default());

        // Build the message the way the sender does, from real context state.
        let mut mme_ue = crate::context::MmeUe {
            mme_s11_teid: 0x0000_1234,
            rat_type: s11_build::rat_type::EUTRAN,
            ..Default::default()
        };
        mme_ue.imsi_len = 8;
        mme_ue.imsi[..8].copy_from_slice(&[0x09, 0x91, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let sess = crate::context::MmeSess {
            apn: "internet".to_string(),
            ..Default::default()
        };
        let sgw_ue = crate::context::SgwUe::default();
        let bearer = crate::context::MmeBearer {
            ebi: 5,
            qos: crate::context::Qos {
                qci: 9,
                arp: crate::context::Arp {
                    priority_level: 8,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        // The Sender F-TEID needs a configured local address; without one the builder
        // refuses rather than emitting a request missing a mandatory IE.
        let seq = server.alloc_sequence();
        let msg = s11_build::build_create_session_request(
            &sess,
            &mme_ue,
            &sgw_ue,
            GtpCreateAction::AttachRequest,
            seq,
            &[&bearer],
            server.local_addr(),
        )
        .expect("the CSR must build");
        server
            .send_request(peer_addr, &msg, 1)
            .expect("the CSR must reach the socket");

        let mut buf = [0u8; 4096];
        let (len, _) = peer.recv_from(&mut buf).expect("the peer must receive it");
        let mut bytes = Bytes::copy_from_slice(&buf[..len]);
        let received = Gtp2Message::decode(&mut bytes).expect("a conformant peer must decode it");

        assert_eq!(
            received.header.message_type,
            s11_build::message_type::CREATE_SESSION_REQUEST
        );
        assert_eq!(
            received.header.sequence_number, seq,
            "the sequence number on the wire is the allocated one, not 0"
        );

        // The mandatory set, mirroring sgwcd's require() list.
        for (ie_type, name) in [
            (Gtp2IeType::Imsi as u8, "IMSI"),
            (Gtp2IeType::RatType as u8, "RAT Type"),
            (Gtp2IeType::FTeid as u8, "Sender F-TEID"),
            (Gtp2IeType::Apn as u8, "APN"),
            (
                Gtp2IeType::BearerContext as u8,
                "Bearer Contexts to be created",
            ),
            // Added by #52: a conformant PGW answers ConditionalIeMissing for an E-UTRAN
            // session without these, so the MME -> SGW-C -> PGW chain cannot complete
            // while they are absent. Found by building the anchor, not by inspection.
            (Gtp2IeType::ServingNetwork as u8, "Serving Network"),
            (Gtp2IeType::Uli as u8, "User Location Information"),
        ] {
            assert!(
                received.get_ie(ie_type, 0).is_some(),
                "{name} is mandatory (TS 29.274 Table 7.2.1-1) and sgwcd's parser require()s it"
            );
        }

        // RAT Type from the UE context, not a literal.
        assert_eq!(
            received
                .get_ie(Gtp2IeType::RatType as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(s11_build::rat_type::EUTRAN)
        );

        // The Sender F-TEID names the S11 MME control-plane interface and this UE's
        // own local TEID, which is what the response has to be addressed to.
        let fteid = nextgcore_gtp::v2::Gtp2FTeidIe::decode(
            &received.get_ie(Gtp2IeType::FTeid as u8, 0).unwrap().value,
        )
        .expect("the F-TEID must decode");
        assert_eq!(
            fteid.interface_type,
            s11_build::f_teid_interface::S11_MME_GTP_C
        );
        assert_eq!(fteid.teid, 0x0000_1234);

        // The Bearer Context carries both sub-IEs sgwcd require()s.
        let bc = nextgcore_gtp::v2::Gtp2BearerContextIe::decode(
            &received
                .get_ie(Gtp2IeType::BearerContext as u8, 0)
                .unwrap()
                .value,
        )
        .expect("the Bearer Context must decode");
        assert_eq!(bc.ebi().expect("EBI is mandatory"), 5);
        let qos = bc
            .bearer_qos()
            .expect("Bearer QoS must decode")
            .expect("Bearer QoS is mandatory");
        assert_eq!(qos.qci, 9);

        server.close();
    }

    /// #51 criterion 8(b): a response is correlated back to its request by sequence
    /// number, and an UNSOLICITED one is not.
    #[test]
    fn a_response_is_correlated_to_its_request_by_sequence_number() {
        let _guard = lock_s11();
        let (server, peer, peer_addr) = spawn_server_and_peer(Gtp2XactConfig::default());

        let seq = server.alloc_sequence();
        let request = s11_build::build_release_access_bearers_request(0x99, seq);
        server
            .send_request(peer_addr, &request, 4242)
            .expect("send");
        assert_eq!(server.outstanding(), 1, "the transaction must be armed");

        let mut buf = [0u8; 4096];
        let (_, from) = peer.recv_from(&mut buf).expect("peer receives");

        // Answer with the SAME sequence number: the transaction closes.
        let response = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            s11_build::message_type::RELEASE_ACCESS_BEARERS_RESPONSE,
            0x99,
            seq,
        ));
        peer.send_to(&response.encode(), from)
            .expect("peer answers");
        for _ in 0..200 {
            if server.outstanding() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            server.outstanding(),
            0,
            "a matching sequence number must close the transaction"
        );

        // And a response for a sequence nobody asked about must NOT close anything,
        // because acting on an uncorrelated datagram lets a stray packet mutate state.
        let seq2 = server.alloc_sequence();
        let request2 = s11_build::build_release_access_bearers_request(0x99, seq2);
        server.send_request(peer_addr, &request2, 1).expect("send");
        let (_, from2) = peer.recv_from(&mut buf).expect("peer receives");
        let stray = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            s11_build::message_type::RELEASE_ACCESS_BEARERS_RESPONSE,
            0x99,
            seq2.wrapping_add(1000),
        ));
        peer.send_to(&stray.encode(), from2).expect("peer answers");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            server.outstanding(),
            1,
            "a response for an unknown sequence number must leave the transaction open"
        );

        server.close();
    }

    /// #51 criterion 8(c): a dropped response triggers T3-RESPONSE retransmission, and
    /// N3-REQUESTS bounds it.
    ///
    /// The peer deliberately never answers. Before #51 there was no transaction layer
    /// at all, so a lost response stalled the procedure silently and forever.
    #[test]
    fn a_dropped_response_is_retransmitted_and_then_exhausts_n3() {
        let _guard = lock_s11();
        let (server, peer, peer_addr) = spawn_server_and_peer(Gtp2XactConfig {
            t3_response: Duration::from_millis(120),
            n3_requests: 2,
            response_hold: Duration::from_secs(1),
        });

        let seq = server.alloc_sequence();
        let request = s11_build::build_release_access_bearers_request(0x99, seq);
        server.send_request(peer_addr, &request, 1).expect("send");

        // The original plus n3_requests retransmissions, all with the same sequence
        // number — a retransmission that renumbered would be a new transaction.
        let mut seen = 0;
        let mut buf = [0u8; 4096];
        for _ in 0..3 {
            let (len, _) = match peer.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => break,
            };
            let mut bytes = Bytes::copy_from_slice(&buf[..len]);
            let decoded = Gtp2Message::decode(&mut bytes).expect("decode");
            assert_eq!(
                decoded.header.sequence_number, seq,
                "a retransmission repeats the sequence number, it does not allocate a new one"
            );
            seen += 1;
        }
        assert!(
            seen >= 2,
            "T3-RESPONSE must retransmit an unanswered request; saw {seen} sends"
        );

        // Once N3 is spent the peer is declared unreachable rather than waited on.
        for _ in 0..200 {
            if server.peer_state(peer_addr) == GtpPeerState::Failed {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            server.peer_state(peer_addr),
            GtpPeerState::Failed,
            "N3 exhaustion must mark the path failed (TS 29.274 §7.6)"
        );
        assert_eq!(
            server.outstanding(),
            0,
            "an exhausted transaction must not stay outstanding forever"
        );

        server.close();
    }

    /// An Echo Request is answered with a Recovery-bearing Echo Response, which is the
    /// path management the MME had none of: the Echo builders existed and were never
    /// called, so a Serving GW that went away was never noticed.
    #[test]
    fn an_echo_request_is_answered_with_this_nodes_recovery() {
        let _guard = lock_s11();
        let (server, peer, _) = spawn_server_and_peer(Gtp2XactConfig::default());

        let echo = Gtp2Message::echo_request(11);
        peer.send_to(&echo.encode(), server.local_addr())
            .expect("send echo");

        let mut buf = [0u8; 4096];
        let (len, _) = peer
            .recv_from(&mut buf)
            .expect("the MME must answer an Echo");
        let mut bytes = Bytes::copy_from_slice(&buf[..len]);
        let reply = Gtp2Message::decode(&mut bytes).expect("decode");
        assert_eq!(
            reply.header.message_type,
            Gtp2MessageType::EchoResponse as u8
        );
        assert_eq!(
            reply.header.sequence_number, 11,
            "the Echo Response echoes the request's sequence number"
        );
        let recovery = reply
            .get_ie(Gtp2IeType::Recovery as u8, 0)
            .expect("Recovery is mandatory in an Echo Response");
        assert_eq!(recovery.value.first().copied(), Some(7));

        server.close();
    }
}
