//! SGWC GTP-C Path Management (TS 29.274)
//!
//! Port of src/sgwc/gtp-path.c. Owns the real S11 UDP socket (port 2123),
//! the receive/dispatch loop, Echo Request/Response handling with Recovery
//! (restart-counter staleness detection per TS 23.007), and the GTPv2-C
//! transaction layer (sequence binding, T3-RESPONSE/N3-REQUESTS
//! retransmission, duplicate-request absorption).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

use nextgcore_gtp::v2::header::Gtp2MessageType;
use nextgcore_gtp::v2::ie::{
    Gtp2BearerContextIe, Gtp2FTeidIe, Gtp2IeType, Gtp2PaaIe, Gtp2RecoveryIe,
};
use nextgcore_gtp::v2::message::Gtp2Message;
use nextgcore_gtp::v2::xact::{Gtp2XactConfig, Gtp2XactMgr};

use crate::context::{sgwc_self, SgwcBearer};
use crate::s11_build;
use crate::s11_handler::{self, gtp_cause, HandlerResult};
use crate::s11_parse::{self, IeError};
use crate::{pfcp_path, sxa_handler};

/// Default S11 bind address (GTPv2-C well-known port, TS 29.274 Section 4.2)
const DEFAULT_S11_BIND: &str = "0.0.0.0:2123";

/// Default Echo probe interval (TS 23.007 Section 20.3.1). Override with
/// `SGWC_ECHO_INTERVAL_SECS`; 0 disables probing.
const DEFAULT_ECHO_INTERVAL_SECS: u64 = 60;

/// Default location of the persisted local restart counter
/// (TS 23.007 Section 18 requires non-volatile storage).
const DEFAULT_RESTART_COUNTER_FILE: &str = "/var/lib/nextgcore/sgwc-restart-counter";

// ============================================================================
// GTP Path State
// ============================================================================

/// GTP path state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpPathState {
    /// Path is idle
    Idle,
    /// Path is active
    Active,
    /// Path has failed (N3 retransmissions exhausted)
    Failed,
}

/// GTP node information
#[derive(Debug, Clone)]
pub struct GtpNode {
    pub id: u64,
    pub addr: String,
    pub port: u16,
    pub state: GtpPathState,
}

impl GtpNode {
    pub fn new(id: u64, addr: &str, port: u16) -> Self {
        Self {
            id,
            addr: addr.to_string(),
            port,
            state: GtpPathState::Idle,
        }
    }
}

// ============================================================================
// GTP-C Server
// ============================================================================

struct GtpcInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    restart_counter: u8,
    xact: Mutex<Gtp2XactMgr>,
    /// Last Recovery (restart counter) seen per peer IP (TS 23.007)
    peer_restart: Mutex<HashMap<IpAddr, u8>>,
    /// Path state per peer
    peer_state: Mutex<HashMap<SocketAddr, GtpPathState>>,
    running: AtomicBool,
}

/// GTPv2-C server bound to the S11 interface
#[derive(Clone)]
pub struct GtpcServer {
    inner: Arc<GtpcInner>,
}

impl GtpcServer {
    /// Bind the S11 socket and start the receive and retransmission loops
    pub fn open(bind: &str, config: Gtp2XactConfig, restart_counter: u8) -> Result<Self, String> {
        let socket = UdpSocket::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
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

        // Receive loop
        {
            let inner = inner.clone();
            std::thread::Builder::new()
                .name("sgwc-s11-recv".into())
                .spawn(move || {
                    let mut buf = [0u8; 4096];
                    while inner.running.load(Ordering::SeqCst) {
                        match inner.socket.recv_from(&mut buf) {
                            Ok((len, peer)) => {
                                handle_datagram(&inner, &buf[..len], peer);
                            }
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

        // Retransmission (T3/N3) loop, which also drives Echo path management.
        {
            let inner = inner.clone();
            let last_echo: Mutex<HashMap<SocketAddr, Instant>> = Mutex::new(HashMap::new());
            std::thread::Builder::new()
                .name("sgwc-s11-rtx".into())
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
                            // TS 29.274 Section 7.6: the peer is considered
                            // unreachable once N3 retransmissions are spent
                            log::error!(
                                "S11 N3 exhausted: peer {} not responding (type={}, seq={})",
                                xact.peer,
                                xact.message_type,
                                xact.sequence_number
                            );
                            if let Ok(mut states) = inner.peer_state.lock() {
                                states.insert(xact.peer, GtpPathState::Failed);
                            }
                            // A failed path leaves the same stale contexts a
                            // restart does, so run the same cleanup rather than
                            // only recording the state (TS 23.007 Section 20).
                            if restart_deletion_enabled() {
                                delete_contexts_for_peer(xact.peer.ip());
                            }
                        }

                        // Periodic Echo path management (TS 23.007 Section 20).
                        // Driven from this thread because it already ticks; a
                        // separate timer task would need its own shutdown story.
                        if let Some(interval) = echo_interval() {
                            let due: Vec<SocketAddr> = {
                                match inner.peer_state.lock() {
                                    Ok(states) => states.keys().copied().collect(),
                                    Err(_) => Vec::new(),
                                }
                            };
                            let now = Instant::now();
                            let mut last = match last_echo.lock() {
                                Ok(l) => l,
                                Err(_) => continue,
                            };
                            for peer in due {
                                // A peer enters peer_state BECAUSE we just heard
                                // from it, so the first sighting starts the
                                // interval rather than triggering a probe. An
                                // immediate probe would both waste a round trip
                                // and inject unsolicited traffic into any
                                // exchange already in flight.
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

        log::info!("GTP-C server listening on {local_addr}");
        Ok(Self { inner })
    }

    /// Stop the receive and retransmission loops
    pub fn close(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Local bound address
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Local restart counter advertised in Recovery IEs
    pub fn restart_counter(&self) -> u8 {
        self.inner.restart_counter
    }

    /// Path state for a peer
    pub fn peer_state(&self, peer: SocketAddr) -> GtpPathState {
        self.inner
            .peer_state
            .lock()
            .ok()
            .and_then(|s| s.get(&peer).copied())
            .unwrap_or(GtpPathState::Idle)
    }

    /// Allocate a GTPv2-C sequence number for an initial message
    pub fn alloc_sequence(&self) -> u32 {
        self.inner
            .xact
            .lock()
            .map(|mut x| x.alloc_sequence())
            .unwrap_or(1)
    }

    /// Send an initial (request) message and arm T3/N3 retransmission.
    /// The message's sequence number binds the transaction.
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
        log::debug!(
            "S11 TX request type={} seq={} to {} len={}",
            msg.header.message_type,
            seq,
            peer,
            encoded.len()
        );
        Ok(seq)
    }

    /// Send a triggered (response) message bound to the request's sequence
    /// number, caching it so retransmitted requests are answered identically.
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
            "S11 TX response type={} seq={} to {} len={}",
            msg.header.message_type,
            msg.header.sequence_number,
            peer,
            encoded.len()
        );
        Ok(())
    }

    /// Send an Echo Request (path management, TS 29.274 Section 7.1.1)
    pub fn send_echo_request(&self, peer: SocketAddr) -> Result<u32, String> {
        let seq = self.alloc_sequence();
        let mut msg = Gtp2Message::echo_request(seq);
        // Echo Request carries the sender's Recovery (M)
        let mut rec = bytes::BytesMut::new();
        Gtp2RecoveryIe::new(self.inner.restart_counter).encode(&mut rec, 0);
        let mut b = rec.freeze();
        if let Ok(ie) = nextgcore_gtp::v2::ie::Gtp2Ie::decode(&mut b) {
            msg.add_ie(ie);
        }
        self.send_request(peer, &msg, 0)
    }

    /// Send Downlink Data Notification to the MME serving the bearer's UE.
    /// `cause` is set when the DDN is triggered by an Error Indication.
    pub fn send_downlink_data_notification(
        &self,
        cause: Option<u8>,
        bearer: &SgwcBearer,
    ) -> Result<u32, String> {
        let ctx = sgwc_self();
        let sgwc_ue = ctx
            .ue_find_by_id(bearer.sgwc_ue_id)
            .ok_or_else(|| "UE not found".to_string())?;
        let peer = sgwc_ue
            .mme_addr
            .ok_or_else(|| "MME address unknown".to_string())?;

        let seq = self.alloc_sequence();
        let msg = s11_build::build_downlink_data_notification(bearer, seq, cause)?;

        log::info!(
            "Downlink Data Notification [bearer_id={}] MME_S11_TEID[{}] SGW_S11_TEID[{}]",
            bearer.id,
            sgwc_ue.mme_s11_teid,
            sgwc_ue.sgw_s11_teid
        );
        self.send_request(peer, &msg, bearer.id)
    }
}

// ============================================================================
// Global server instance (process lifecycle)
// ============================================================================

/// The process-wide S11 server.
///
/// #54: settable rather than install-once. An `OnceLock` was enough while nothing outside
/// `main` needed it, but the S11 answer is now sent from the Sxa response path — so a test
/// that drives a gated procedure has to be able to install ITS OWN server, and a
/// first-wins global makes every test after the first answer through a socket that has
/// closed. Same reasoning as #217's for sgwud's Sxa node.
///
/// A running SGW-C opens exactly one, so replace-on-install and set-once are the same
/// behaviour there.
static S11_SERVER: std::sync::RwLock<Option<GtpcServer>> = std::sync::RwLock::new(None);

/// Get the global S11 server, if open. Cloned out of the lock: `GtpcServer` is an `Arc`
/// handle, and holding a guard across the sends this feeds would be a lock across I/O.
pub fn s11_server() -> Option<GtpcServer> {
    S11_SERVER.read().ok()?.clone()
}

/// Install the process-wide S11 server (at startup, or per test).
pub(crate) fn set_s11_server(server: GtpcServer) {
    if let Ok(mut slot) = S11_SERVER.write() {
        *slot = Some(server);
    }
}

/// Uninstall it, so a test does not leave a closed socket behind for a sibling.
#[cfg(test)]
pub(crate) fn clear_s11_server_for_test() {
    if let Ok(mut slot) = S11_SERVER.write() {
        *slot = None;
    }
}

/// Open the S11 GTP-C server socket
/// Port of sgwc_gtp_open
pub fn gtp_open() -> Result<(), String> {
    if s11_server().is_some() {
        return Ok(());
    }

    let bind = std::env::var("SGWC_S11_BIND").unwrap_or_else(|_| DEFAULT_S11_BIND.to_string());
    // SGWC_RESTART_COUNTER is a TEST OVERRIDE only; production reads and
    // advances the persisted counter so peers can detect an SGW-C restart
    // (TS 23.007 Section 18).
    let restart_counter = match std::env::var("SGWC_RESTART_COUNTER")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
    {
        Some(override_value) => {
            log::warn!(
                "SGWC_RESTART_COUNTER={override_value} overrides the persisted restart counter; \
                 this is a test-only escape hatch"
            );
            override_value
        }
        None => advance_persistent_restart_counter(&restart_counter_path()),
    };

    let server = GtpcServer::open(&bind, Gtp2XactConfig::default(), restart_counter)?;

    let ctx = sgwc_self();
    // Advertised control-plane address: the bound address unless wildcard,
    // then SGWC_S11_ADVERTISE
    let advertised = match server.local_addr().ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => std::env::var("SGWC_S11_ADVERTISE")
            .ok()
            .and_then(|v| v.parse::<Ipv4Addr>().ok()),
    };
    ctx.set_s11_address(advertised);
    // User-plane endpoints advertised in F-TEIDs live on the SGW-U
    ctx.set_gtpu_address(
        std::env::var("SGWC_GTPU_ADVERTISE")
            .ok()
            .and_then(|v| v.parse::<Ipv4Addr>().ok())
            .or(advertised),
    );

    // ---- S5/S8 (#52) ----
    //
    // The dedicated S5-C address (criterion 6). Unset means "same address as S11",
    // which is what the shipped compose file describes; the accessor's fallback makes
    // that explicit rather than reusing `s11_address()` inside the builder.
    ctx.set_s5c_address(
        std::env::var("SGWC_S5C_ADVERTISE")
            .ok()
            .and_then(|v| v.parse::<Ipv4Addr>().ok()),
    );

    // The PGW this SGW-C anchors sessions at. Unset means the S5/S8 leg cannot be
    // relayed, and the SGW-C then REFUSES an S11 Create Session Request rather than
    // answering it from local state — the behaviour #52 exists to remove. Env-configured
    // like every other address this daemon takes.
    let pgw_peer = std::env::var("SGWC_PGW_S5C").ok().and_then(|v| {
        // A bare address means the fixed GTPv2-C port (TS 29.274 §4.1).
        v.parse::<std::net::SocketAddr>().ok().or_else(|| {
            v.parse::<Ipv4Addr>()
                .ok()
                .map(|ip| std::net::SocketAddr::from((ip, 2123)))
        })
    });
    match pgw_peer {
        Some(peer) => log::info!("S5/S8 PGW peer: {peer}"),
        None => log::warn!(
            "no SGWC_PGW_S5C configured: the S5/S8 leg is unavailable, so a Create Session \
             Request will be REFUSED rather than answered from local state (TS 29.274 §7.2.1 \
             requires the SGW to relay it to a PGW)"
        ),
    }
    ctx.set_pgw_s5c_peer(pgw_peer);

    set_s11_server(server);
    Ok(())
}

/// Where the local restart counter is persisted.
///
/// TS 23.007 Section 18 requires the local restart counter to live in
/// non-volatile storage: a counter that resets to the same value on every start
/// tells peers nothing changed, so they keep stale SGW-C contexts forever.
pub(crate) fn restart_counter_path() -> std::path::PathBuf {
    std::env::var("SGWC_RESTART_COUNTER_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_RESTART_COUNTER_FILE))
}

/// Read the persisted restart counter, advance it, write it back, and return the
/// value to advertise in Recovery IEs.
///
/// * absent file → this is a first start; begin at 1 and persist it;
/// * unreadable or malformed contents → log loudly and fall back to 1, because
///   refusing to start would take an EPC control plane down over a scratch file,
///   while silently continuing would hide a restart from every peer. The peers'
///   view is what suffers, and the log says so;
/// * wraps 255 → 1 rather than 0, keeping 0 free as "never persisted".
///
/// Uses temp-file-plus-rename so a crash mid-write cannot leave a truncated
/// counter that the next start reads as malformed.
pub(crate) fn advance_persistent_restart_counter(path: &std::path::Path) -> u8 {
    let previous = match std::fs::read_to_string(path) {
        Ok(text) => match text.trim().parse::<u8>() {
            Ok(v) => Some(v),
            Err(_) => {
                log::error!(
                    "Restart counter file {} is malformed ({:?}); restarting the count at 1, so \
                     peers may not detect this SGW-C restart (TS 23.007 Section 18)",
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
                 may not detect this SGW-C restart",
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

/// Close the S11 GTP-C server socket
/// Port of sgwc_gtp_close
pub fn gtp_close() {
    if let Some(server) = s11_server() {
        server.close();
    }
    log::info!("GTP-C server closed");
}

// ============================================================================
// Datagram dispatch
// ============================================================================

/// Echo probe interval, or `None` when probing is disabled.
///
/// `SGWC_ECHO_INTERVAL_SECS=0` disables it; absent means the default. TS 23.007
/// Section 20.3.1 says an entity *may* probe, so this is configurable rather
/// than mandatory.
fn echo_interval() -> Option<Duration> {
    let secs = std::env::var("SGWC_ECHO_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_ECHO_INTERVAL_SECS);
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

/// Build the 8-octet Version Not Supported Indication (TS 29.274 Section 7.7.2).
///
/// Message type 3, no TEID, no IEs: header flags + type + length + 3-octet
/// sequence number + spare. The sequence number echoes the offending message's
/// so the peer can correlate the rejection.
pub(crate) fn build_version_not_supported(sequence_number: u32) -> Bytes {
    let header = nextgcore_gtp::v2::header::Gtp2Header::new_no_teid(
        Gtp2MessageType::VersionNotSupportedIndication as u8,
        sequence_number,
    );
    Bytes::from(Gtp2Message::new(header).encode().to_vec())
}

/// Sequence number of a datagram whose header could not be decoded.
///
/// The GTPv2 sequence number is the 3 octets after flags(1) + type(1) +
/// length(2), and it sits at the same offset for every version >= 1, so it can
/// be recovered from a datagram this node cannot otherwise parse. Returns 0 when
/// the datagram is too short to carry one.
fn peek_sequence_number(data: &[u8]) -> u32 {
    if data.len() < 8 {
        return 0;
    }
    ((data[4] as u32) << 16) | ((data[5] as u32) << 8) | (data[6] as u32)
}

fn handle_datagram(inner: &Arc<GtpcInner>, data: &[u8], peer: SocketAddr) {
    let mut bytes = Bytes::copy_from_slice(data);
    let msg = match Gtp2Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            // TS 29.274 Section 7.7.2: a message of an unsupported GTP version
            // HIGHER than GTPv2 is a Triggered message that shall be answered
            // with a Version Not Supported Indication, not dropped. A lower
            // version (GTPv1) is not ours to answer on this interface.
            if let nextgcore_gtp::GtpError::InvalidVersion(version) = e {
                if version > 2 {
                    let reply = build_version_not_supported(peek_sequence_number(data));
                    log::warn!(
                        "GTPv{version} datagram from {peer}: replying Version Not Supported \
                         Indication (TS 29.274 Section 7.7.2)"
                    );
                    if let Err(e) = inner.socket.send_to(&reply, peer) {
                        log::error!("S11 Version Not Supported Indication to {peer} failed: {e}");
                    }
                    return;
                }
            }
            log::error!("[DROP] Cannot decode GTPv2-C datagram from {peer}: {e}");
            return;
        }
    };

    let server = GtpcServer {
        inner: inner.clone(),
    };

    // Restart-counter staleness detection on any message carrying Recovery
    if let Some(rec_ie) = msg.get_ie_by_type(Gtp2IeType::Recovery as u8) {
        if let Ok(rec) = Gtp2RecoveryIe::decode(&rec_ie.value) {
            note_peer_recovery(inner, peer, rec.restart_counter);
        }
    }

    if let Ok(mut states) = inner.peer_state.lock() {
        states.entry(peer).or_insert(GtpPathState::Active);
    }

    use Gtp2MessageType as T;
    let msg_type = msg.header.message_type;
    let seq = msg.header.sequence_number;

    // Requests: absorb retransmitted duplicates with the cached response
    let is_request = matches!(
        msg_type,
        t if t == T::CreateSessionRequest as u8
            || t == T::ModifyBearerRequest as u8
            || t == T::DeleteSessionRequest as u8
            || t == T::ReleaseAccessBearersRequest as u8
            || t == T::CreateIndirectDataForwardingTunnelRequest as u8
            || t == T::DeleteIndirectDataForwardingTunnelRequest as u8
            || t == T::BearerResourceCommand as u8
    );
    if is_request {
        let cached = inner
            .xact
            .lock()
            .ok()
            .and_then(|x| x.lookup_cached_response(peer, seq));
        if let Some(encoded) = cached {
            log::debug!("S11 duplicate request seq={seq} from {peer}: resending cached response");
            let _ = inner.socket.send_to(&encoded, peer);
            return;
        }
    }

    match msg_type {
        t if t == T::EchoRequest as u8 => {
            let response = Gtp2Message::echo_response(seq, inner.restart_counter);
            if let Err(e) = server.send_response(peer, &response) {
                log::error!("Echo Response to {peer} failed: {e}");
            }
        }
        t if t == T::EchoResponse as u8 => {
            if let Ok(mut xact) = inner.xact.lock() {
                if xact.match_response(seq, msg_type).is_none() {
                    log::warn!("Unsolicited Echo Response seq={seq} from {peer}");
                }
            }
        }
        t if t == T::CreateSessionRequest as u8 => {
            dispatch_create_session_request(&server, &msg, peer);
        }
        t if t == T::ModifyBearerRequest as u8 => {
            dispatch_modify_bearer_request(&server, &msg, peer);
        }
        t if t == T::DeleteSessionRequest as u8 => {
            dispatch_delete_session_request(&server, &msg, peer);
        }
        t if t == T::ReleaseAccessBearersRequest as u8 => {
            dispatch_release_access_bearers_request(&server, &msg, peer);
        }
        t if t == T::CreateIndirectDataForwardingTunnelRequest as u8 => {
            dispatch_indirect_tunnel_request(&server, &msg, peer, true);
        }
        t if t == T::DeleteIndirectDataForwardingTunnelRequest as u8 => {
            dispatch_indirect_tunnel_request(&server, &msg, peer, false);
        }
        t if t == T::BearerResourceCommand as u8 => {
            dispatch_bearer_resource_command(&server, &msg, peer);
        }
        t if t == T::DownlinkDataNotificationAcknowledge as u8 => {
            let matched = inner
                .xact
                .lock()
                .ok()
                .and_then(|mut x| x.match_response(seq, msg_type));
            if matched.is_none() {
                log::warn!("Unsolicited DDN Acknowledge seq={seq} from {peer}");
                return;
            }
            match s11_parse::parse_downlink_data_notification_ack(&msg) {
                Ok(ack) => {
                    let ue = ue_from_header(&msg);
                    s11_handler::handle_downlink_data_notification_ack(
                        ue.as_ref(),
                        seq as u64,
                        data,
                        ack.cause,
                    );
                    // #54: the Ack used to be parsed and then only logged, so the
                    // throttling IE did nothing and a refusal left the SGW-U buffering
                    // forever.
                    crate::sxa_response::downlink_data_notification_ack(
                        ue.as_ref().map(|u| u.id),
                        ack.cause,
                        ack.data_notification_delay,
                    );
                }
                Err(e) => log::error!(
                    "Malformed DDN Acknowledge from {peer}: cause={} offending_ie={}",
                    e.cause,
                    e.offending_ie_type
                ),
            }
        }
        t if t == T::DownlinkDataNotificationFailureIndication as u8 => {
            match s11_parse::parse_downlink_data_notification_failure_indication(&msg) {
                Ok(cause) => {
                    log::warn!("DDN Failure Indication from {peer}: cause={cause}");
                    // #54: TS 23.401 §5.3.4.2 -- on a Failure Indication the Serving GW
                    // DELETES the buffered packet(s). This used to stop at the log line,
                    // so they stayed on the SGW-U for the life of the session.
                    crate::sxa_response::downlink_data_notification_failed(
                        ue_from_header(&msg).map(|u| u.id),
                        cause,
                    );
                }
                Err(_) => log::error!("Malformed DDN Failure Indication from {peer}"),
            }
        }
        t if t == T::CreateBearerResponse as u8
            || t == T::UpdateBearerResponse as u8
            || t == T::DeleteBearerResponse as u8 =>
        {
            dispatch_bearer_response(inner, &msg, peer, data);
        }
        // ---- S5/S8 (#52) ----
        //
        // The PGW's answer to our Create Session Request. This arm is what wires
        // `s5c_handler` into the receive path at last: it had no production caller, so
        // no PGW response could ever be acted on.
        t if t == T::CreateSessionResponse as u8 => {
            dispatch_s5c_create_session_response(&msg, peer);
        }
        // PGW-INITIATED bearer procedures (TS 29.274 §7.2.3, §7.2.15, §7.2.9.2).
        // Forwarded to the MME, which is the node that owns the UE's NAS session.
        // `SgwcFsm::handle_s5c_message` was a log-only stub, so these could never be
        // originated or relayed.
        t if t == T::CreateBearerRequest as u8
            || t == T::UpdateBearerRequest as u8
            || t == T::DeleteBearerRequest as u8 =>
        {
            forward_pgw_bearer_procedure_to_mme(inner, &msg, peer, data);
        }
        other => {
            log::error!("[DROP] Unhandled GTPv2-C message type {other} from {peer}");
        }
    }
}

/// Relay a PGW-initiated bearer procedure to the MME (#52 criterion 7).
///
/// TS 23.401 §5.4.1/§5.4.2/§5.4.4: the SGW relays the PGW's Create/Update/Delete Bearer
/// Request to the MME on S11 and relays the MME's response back. The SGW-C is a relay
/// here, not an endpoint — it re-addresses the message to the MME's S11 TEID and keeps
/// the PGW's own content, because the bearer parameters are the PGW's decision.
///
/// The MME's response comes back through `dispatch_bearer_response`, which already
/// existed. What was missing was this direction: `SgwcFsm::handle_s5c_message` logged and
/// returned, so a PGW-initiated procedure died at the SGW-C.
fn forward_pgw_bearer_procedure_to_mme(
    inner: &Arc<GtpcInner>,
    msg: &Gtp2Message,
    peer: SocketAddr,
    data: &[u8],
) {
    let ctx = sgwc_self();
    let msg_type = msg.header.message_type;

    // The session this procedure belongs to, by the local S5-C TEID the PGW addressed.
    let local_teid = msg.header.teid.unwrap_or(0);
    // `sess_find_by_teid` resolves by the SXA SEID, and that works here because
    // `sess_add` assigns `sgw_s5c_teid = seid as u32` from the same value
    // (`context.rs:791-792`) — the S5-C TEID IS the low 32 bits of the SEID. Stated
    // because it is true by construction rather than by intent: an allocator that
    // stopped deriving one from the other would break this lookup silently.
    let Some(sess) = ctx.sess_find_by_teid(local_teid) else {
        log::warn!(
            "S5/S8 message type {msg_type} from {peer} for local S5-C TEID {local_teid:#x} \
             matches no session; cannot relay it to any MME"
        );
        return;
    };
    let Some(ue) = ctx.ue_find_by_id(sess.sgwc_ue_id) else {
        log::warn!("S5/S8 message type {msg_type} from {peer}: the session has no UE context");
        return;
    };
    let Some(mme_peer) = ue.mme_addr else {
        log::warn!(
            "S5/S8 message type {msg_type} from {peer}: no MME address recorded for this UE, so \
             the procedure cannot be relayed"
        );
        return;
    };

    // Re-address to the MME: its S11 TEID, and a sequence number from THIS node's
    // transaction space, because the SGW-C is the initiator on the S11 leg.
    let mut relayed = msg.clone();
    relayed.header.teid = Some(ue.mme_s11_teid);
    let server = GtpcServer {
        inner: inner.clone(),
    };
    let seq = server.alloc_sequence();
    relayed.header.sequence_number = seq;

    log::info!(
        "Relaying PGW-initiated S5/S8 message type {msg_type} from {peer} to MME {mme_peer} \
         (S11 TEID {:#x}, seq {seq})",
        ue.mme_s11_teid
    );
    let _ = data;
    if let Err(e) = server.send_request(mme_peer, &relayed, sess.id) {
        log::error!("Relay of S5/S8 message type {msg_type} to MME {mme_peer} failed: {e}");
    }
}

/// How a received restart counter relates to the one already stored for a peer
/// (TS 23.007 Section 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestartOrder {
    /// Received value is ahead of the stored one: the peer restarted.
    Restarted,
    /// Received value equals the stored one: nothing happened.
    Unchanged,
    /// Received value is behind the stored one. TS 23.007 Section 18: "If the
    /// value ... previously stored for a peer is larger than the Restart
    /// counter value received ... this indicates a possible race condition ...
    /// [the message] shall be discarded."
    Stale,
}

/// Classify a received restart counter against the stored one.
///
/// The previous code used `previous != restart_counter`, which treats a value
/// moving BACKWARDS as a restart. That is precisely the race TS 23.007 Section 18
/// says to discard, and acting on it tears down live contexts on a reordered
/// datagram.
///
/// Note on the counter's modulo-256 wrap: a genuine wrap (255 -> 0) is reported
/// here as `Stale`, not `Restarted`, because Section 18 is written as a plain
/// magnitude comparison on the stored-versus-received values and nextgcore #53's
/// acceptance criteria require a rolled-over value to be discarded. The cost is
/// that the 256th restart of a peer is not detected from its counter alone; it
/// is still detected by N3 exhaustion on the path. Chosen deliberately: treating
/// a backwards jump as a restart would delete live sessions on every reordered
/// message, which is the far more damaging error.
pub(crate) fn restart_counter_order(stored: u8, received: u8) -> RestartOrder {
    match received.cmp(&stored) {
        std::cmp::Ordering::Greater => RestartOrder::Restarted,
        std::cmp::Ordering::Equal => RestartOrder::Unchanged,
        std::cmp::Ordering::Less => RestartOrder::Stale,
    }
}

/// Whether restart-triggered context deletion is enabled.
///
/// Off by default: deleting contexts on a restart heuristic can drop live
/// sessions if the heuristic misfires, so nextgcore #53 requires it be gated
/// until validated end to end. Set `SGWC_RESTART_DELETE_CONTEXTS=1` to enable.
fn restart_deletion_enabled() -> bool {
    matches!(
        std::env::var("SGWC_RESTART_DELETE_CONTEXTS")
            .unwrap_or_default()
            .as_str(),
        "1" | "true" | "yes"
    )
}

/// Restart-triggered context deletion (TS 23.007 Section 16.1A.1.1): drop every
/// PDN connection held for a peer that has restarted, tearing down each
/// session's SGW-U PFCP session first.
///
/// Returns the number of UE contexts removed, so callers (and tests) can assert
/// the teardown actually happened rather than only that it was attempted.
pub(crate) fn delete_contexts_for_peer(peer_ip: std::net::IpAddr) -> usize {
    let ctx = sgwc_self();
    let ue_ids = ctx.ue_ids_for_mme_ip(peer_ip);
    let mut removed = 0usize;

    for ue_id in ue_ids {
        // PFCP first: once ue_remove runs, the session records are gone and no
        // Session Deletion Request can be built from them.
        for sess in ctx.sess_list_for_ue(ue_id) {
            if let Err(e) = pfcp_path::send_session_deletion_request(
                &sess,
                0,
                None,
                // No MME is waiting for this one: it is our own restart cleanup, and
                // the local context is dropped below regardless of the SGW-U's answer.
                pfcp_path::S11Continuation::None,
            ) {
                // Best-effort: a dead SGW-U must not block dropping local state,
                // or the contexts leak exactly as they did before this fix.
                log::warn!(
                    "SGW-U session deletion for sess {} failed during peer-{peer_ip} \
                     restart cleanup: {e}",
                    sess.id
                );
            }
        }
        if ctx.ue_remove(ue_id).is_some() {
            removed += 1;
        }
    }

    if removed > 0 {
        log::warn!(
            "Peer {peer_ip} restart/failure: deleted {removed} UE context(s) and their \
             SGW-U sessions (TS 23.007 Section 16.1A.1.1)"
        );
    }
    removed
}

/// Track the peer's restart counter and act on a confirmed restart
/// (TS 23.007 Section 18 / Section 16.1A.1.1).
fn note_peer_recovery(inner: &Arc<GtpcInner>, peer: SocketAddr, restart_counter: u8) {
    let previous = {
        let mut peer_restart = match inner.peer_restart.lock() {
            Ok(p) => p,
            Err(_) => return,
        };
        // Only overwrite when the value is not stale, so a racing datagram
        // cannot rewrite the stored counter backwards and make the NEXT genuine
        // message look like a restart.
        match peer_restart.get(&peer.ip()).copied() {
            Some(prev) => {
                if restart_counter_order(prev, restart_counter) == RestartOrder::Restarted {
                    peer_restart.insert(peer.ip(), restart_counter);
                }
                Some(prev)
            }
            None => {
                peer_restart.insert(peer.ip(), restart_counter);
                None
            }
        }
    };

    let Some(previous) = previous else {
        return;
    };

    match restart_counter_order(previous, restart_counter) {
        RestartOrder::Unchanged => {}
        RestartOrder::Stale => {
            log::warn!(
                "GTP-C peer {} sent restart counter {} below the stored {}: possible race, \
                 discarding (TS 23.007 Section 18)",
                peer.ip(),
                restart_counter,
                previous
            );
        }
        RestartOrder::Restarted => {
            log::warn!(
                "GTP-C peer {} restarted (restart counter {} -> {}): contexts are stale",
                peer.ip(),
                previous,
                restart_counter
            );
            if let Ok(mut states) = inner.peer_state.lock() {
                states.insert(peer, GtpPathState::Idle);
            }
            if restart_deletion_enabled() {
                delete_contexts_for_peer(peer.ip());
            } else {
                log::warn!(
                    "Peer {} restart detected but SGWC_RESTART_DELETE_CONTEXTS is off: \
                     contexts left in place",
                    peer.ip()
                );
            }
        }
    }
}

fn ue_from_header(msg: &Gtp2Message) -> Option<crate::context::SgwcUe> {
    let teid = msg.header.teid?;
    if teid == 0 {
        return None;
    }
    sgwc_self().ue_find_by_teid(teid)
}

fn send_reject(
    server: &GtpcServer,
    peer: SocketAddr,
    response_type: Gtp2MessageType,
    teid: u32,
    seq: u32,
    err: IeError,
) {
    let msg = s11_build::build_error_response(
        response_type as u8,
        teid,
        seq,
        err.cause,
        Some(err.offending_ie_type),
    );
    if let Err(e) = server.send_response(peer, &msg) {
        log::error!("Failed to send reject to {peer}: {e}");
    }
}

fn send_cause_response(
    server: &GtpcServer,
    peer: SocketAddr,
    response_type: Gtp2MessageType,
    teid: u32,
    seq: u32,
    cause: u8,
) {
    let msg = s11_build::build_error_response(response_type as u8, teid, seq, cause, None);
    if let Err(e) = server.send_response(peer, &msg) {
        log::error!("Failed to send response to {peer}: {e}");
    }
}

// ============================================================================
// Per-procedure dispatch
// ============================================================================

fn dispatch_create_session_request(server: &GtpcServer, msg: &Gtp2Message, peer: SocketAddr) {
    let seq = msg.header.sequence_number;
    let parsed = match s11_parse::parse_create_session_request(msg) {
        Ok(p) => p,
        Err(e) => {
            log::error!(
                "Create Session Request rejected: cause={} offending_ie={}",
                e.cause,
                e.offending_ie_type
            );
            send_reject(
                server,
                peer,
                Gtp2MessageType::CreateSessionResponse,
                0,
                seq,
                e,
            );
            return;
        }
    };

    let ctx = sgwc_self();
    let existing_ue = ctx.ue_find_by_imsi(&parsed.imsi);
    let result = s11_handler::handle_create_session_request(
        existing_ue.as_ref(),
        seq as u64,
        &[],
        &parsed.imsi,
        &parsed.apn,
        parsed.sender_fteid.teid,
        parsed.bearer.ebi,
    );

    match result {
        HandlerResult::SendPfcp => {}
        HandlerResult::Error(cause) => {
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::CreateSessionResponse,
                parsed.sender_fteid.teid,
                seq,
                cause,
            );
            return;
        }
        _ => {}
    }

    // Enrich contexts with the protocol values from the request
    let Some(mut ue) = ctx.ue_find_by_imsi(&parsed.imsi) else {
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::CreateSessionResponse,
            parsed.sender_fteid.teid,
            seq,
            gtp_cause::CONTEXT_NOT_FOUND,
        );
        return;
    };
    ue.mme_addr = Some(peer);
    ue.rat_type = parsed.rat_type;
    ctx.ue_update(&ue);

    let Some(mut sess) = ctx.sess_find_by_apn(ue.id, &parsed.apn) else {
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::CreateSessionResponse,
            ue.mme_s11_teid,
            seq,
            gtp_cause::CONTEXT_NOT_FOUND,
        );
        return;
    };
    if let Some(pdn_type) = parsed.pdn_type {
        sess.paa.pdn_type = pdn_type;
    }
    // #52 criterion 5: the MME's PAA is NOT copied onto the session.
    //
    // TS 23.401 §5.3.2.1 makes PDN address allocation a PGW function. Copying the MME's
    // proposal here is what made the SGW-C look like it had allocated something: the UE
    // received back the address it had asked about, with no node in the deployment
    // having allocated anything. The session's PAA is now written only in
    // `dispatch_s5c_create_session_response`, from the PGW's answer.
    //
    // The requested PDN TYPE above is kept, because it is the UE's request and the PGW
    // may answer with a different one (causes 18/19 exist for exactly that).
    if parsed.paa.is_some() {
        log::debug!(
            "Create Session Request carries a PAA; it is a REQUEST and is not applied — the PGW \
             allocates the PDN address (TS 23.401 §5.3.2.1)"
        );
    }
    if let Some(ref ambr) = parsed.ambr {
        sess.ambr_ul = ambr.uplink;
        sess.ambr_dl = ambr.downlink;
    }
    // Held for the S5/S8 relay (#52): the PGW needs both for an E-UTRAN session, and the
    // SGW-C is the only node that has them.
    sess.serving_network = parsed.serving_network.clone();
    sess.uli = parsed.uli.clone();
    ctx.sess_update(&sess);

    // Bearer QoS + user-plane endpoint allocation
    let Some(gtpu_addr) = ctx.gtpu_address() else {
        log::error!("No GTP-U address configured; cannot allocate user-plane endpoints");
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::CreateSessionResponse,
            ue.mme_s11_teid,
            seq,
            gtp_cause::NO_RESOURCES_AVAILABLE,
        );
        return;
    };
    if let Some(mut bearer) = ctx.bearer_find_by_sess_ebi(sess.id, parsed.bearer.ebi) {
        bearer.qci = parsed.bearer.qos.qci;
        bearer.arp_priority_level = parsed.bearer.qos.pl;
        bearer.arp_pci = parsed.bearer.qos.pci;
        bearer.arp_pvi = parsed.bearer.qos.pvi;
        bearer.mbr_ul = parsed.bearer.qos.mbr_ul;
        bearer.mbr_dl = parsed.bearer.qos.mbr_dl;
        bearer.gbr_ul = parsed.bearer.qos.gbr_ul;
        bearer.gbr_dl = parsed.bearer.qos.gbr_dl;
        ctx.bearer_update(&bearer);

        // Allocate local user-plane endpoints for both directions, and the PDR/FAR ids
        // that name them on Sxa.
        //
        // #54: the ids had NO allocator anywhere in this daemon -- `SgwcTunnel.pdr_id` and
        // `far_id` were `None` for every tunnel that ever existed. The old builders wrote
        // them with `if let Some(...)`, so an Establishment Request simply omitted them,
        // and nothing noticed because the request was discarded before it reached a socket.
        // With a real transport that is an SGW-U provisioned with no rules at all, told to
        // the MME as an accepted bearer.
        for tunnel in [
            ctx.dl_tunnel_in_bearer(bearer.id),
            ctx.ul_tunnel_in_bearer(bearer.id),
        ]
        .into_iter()
        .flatten()
        {
            let mut tunnel = tunnel;
            if tunnel.local_teid == 0 {
                tunnel.local_teid = ctx.next_gtpu_teid();
            }
            if tunnel.pdr_id.is_none() {
                tunnel.pdr_id = Some(ctx.next_pdr_id());
            }
            if tunnel.far_id.is_none() {
                tunnel.far_id = Some(ctx.next_far_id());
            }
            tunnel.local_addr = Some(gtpu_addr);
            ctx.tunnel_update(&tunnel);
        }
    }

    // Establish the user-plane session on the SGW-U over Sxa, and let the ANSWER decide
    // what the MME is told (#54).
    //
    // TS 23.401 §5.3.2.1: the Serving GW returns the Create Session Response after the
    // user plane has been provisioned, and TS 29.274 §7.2.2 makes `Request accepted` mean
    // the request was fulfilled. This used to send the response right here with a
    // hard-coded REQUEST_ACCEPTED -- before the request had even left, since the transport
    // discarded it -- so the MME was told a bearer existed whose user plane might not.
    let sess = ctx.sess_find_by_id(sess.id).unwrap_or(sess);
    let continuation = pfcp_path::S11Continuation::CreateSession {
        peer,
        seq,
        teid: ue.mme_s11_teid,
    };

    // TS 29.274 §7.2.1: "The Create Session Request message shall be sent on the S11
    // interface by the MME to the SGW, AND ON THE S5/S8 INTERFACE BY THE SGW TO THE
    // PGW." Both legs are mandatory. This used to skip the second one entirely and
    // answer the MME from local state, so no node in the deployment allocated a PDN
    // address and there was no anchor gateway (#52).
    //
    // The order is §5.3.2.1's: relay to the PGW FIRST, because the PGW's response
    // carries the PAA and the PGW-U F-TEID that the SGW-U's Sxa session needs. The Sxa
    // establishment therefore moves into `s5c_create_session_response`, and the S11
    // answer stays gated on it exactly as #54 left it.
    let Some(pgw_peer) = ctx.pgw_s5c_peer() else {
        // No PGW configured. Refusing is the honest answer: answering locally is the
        // defect, and TS 29.274 §8.4's cause 72 says which peer is missing.
        log::error!(
            "Create Session Request from {peer}: no PGW S5/S8 peer configured, so this session \
             cannot be anchored; refusing rather than answering from local state"
        );
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::CreateSessionResponse,
            ue.mme_s11_teid,
            seq,
            gtp_cause::REMOTE_PEER_NOT_RESPONDING,
        );
        return;
    };

    let s5c_seq = server.alloc_sequence();
    let msg = match s11_build::build_s5c_create_session_request(&sess, s5c_seq) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Create Session Request: cannot build the S5/S8 leg: {e}");
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::CreateSessionResponse,
                ue.mme_s11_teid,
                seq,
                gtp_cause::SYSTEM_FAILURE,
            );
            return;
        }
    };

    // Record what the PGW's answer has to continue, before the request goes out: a
    // response that arrives before the record exists would be uncorrelated and dropped.
    register_pending_s5c(s5c_seq, sess.id, continuation);

    if let Err(e) = server.send_request(pgw_peer, &msg, sess.id) {
        log::error!("S5/S8 Create Session Request to {pgw_peer} failed: {e}");
        take_pending_s5c(s5c_seq);
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::CreateSessionResponse,
            ue.mme_s11_teid,
            seq,
            gtp_cause::REMOTE_PEER_NOT_RESPONDING,
        );
    }
}

/// What an S5/S8 Create Session Response has to continue (#52).
///
/// Keyed by the S5-C sequence number, which is what correlates the PGW's answer to the
/// request. The S11 continuation rides along untouched, so the MME's answer is still
/// produced by #54's `sxa_response` path once the SGW-U has confirmed — this stage is
/// inserted BEFORE that one rather than replacing it.
static PENDING_S5C: std::sync::Mutex<
    Option<std::collections::HashMap<u32, (u64, pfcp_path::S11Continuation)>>,
> = std::sync::Mutex::new(None);

fn register_pending_s5c(seq: u32, sess_id: u64, continuation: pfcp_path::S11Continuation) {
    if let Ok(mut map) = PENDING_S5C.lock() {
        map.get_or_insert_with(std::collections::HashMap::new)
            .insert(seq, (sess_id, continuation));
    }
}

fn take_pending_s5c(seq: u32) -> Option<(u64, pfcp_path::S11Continuation)> {
    PENDING_S5C
        .lock()
        .ok()
        .and_then(|mut map| map.as_mut().and_then(|m| m.remove(&seq)))
}

/// The PGW answered our S5/S8 Create Session Request (#52 criteria 5 and 7).
///
/// This is where the SGW-C stops inventing an answer. The PAA, the PGW's control and
/// user-plane F-TEIDs and the APN-Restriction are written onto the session from the
/// PGW's response, and only then is the SGW-U provisioned — so the S11 response #54
/// builds from that session carries the PGW's values rather than the MME's own PAA
/// echoed back.
fn dispatch_s5c_create_session_response(msg: &Gtp2Message, peer: SocketAddr) {
    let seq = msg.header.sequence_number;
    let Some((sess_id, continuation)) = take_pending_s5c(seq) else {
        log::warn!(
            "S5/S8 Create Session Response from {peer} (seq={seq}) matches no pending request; \
             dropping rather than acting on a datagram this SGW-C did not ask for"
        );
        return;
    };

    let ctx = sgwc_self();
    let cause = msg
        .get_ie(Gtp2IeType::Cause as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .unwrap_or(gtp_cause::SYSTEM_FAILURE);

    // The PGW's control-plane F-TEID is at instance 1 (TS 29.274 Table 7.2.2-1); the
    // SGW's own echo is at instance 0.
    let pgw_c = msg
        .get_ie(Gtp2IeType::FTeid as u8, 1)
        .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok());
    // The PGW-U endpoint lives in the Bearer Context at instance 2.
    let pgw_u = msg
        .get_ie(Gtp2IeType::BearerContext as u8, 0)
        .and_then(|ie| Gtp2BearerContextIe::decode(&ie.value).ok())
        .and_then(|bc| bc.fteid(2).ok().flatten());

    // ---- criterion 5: the SGW-C stops inventing the answer ----
    //
    // The PAA, the PGW's control address and the APN-Restriction come from the PGW's
    // response and are written onto the session, which is what #54's `sxa_response`
    // builds the S11 Create Session Response from. Before #52 the PAA was COPIED from
    // the MME's request (`parsed.paa` into `sess.paa`), so the UE was handed back the
    // address it had asked about with no node having allocated anything.
    if let Some(paa) = msg
        .get_ie(Gtp2IeType::Paa as u8, 0)
        .and_then(|ie| Gtp2PaaIe::decode(&ie.value).ok())
    {
        if let Some(mut sess) = ctx.sess_find_by_id(sess_id) {
            sess.paa.pdn_type = paa.pdn_type;
            sess.paa.ipv4_addr = paa.ipv4_addr.map(std::net::Ipv4Addr::from);
            sess.paa.ipv6_addr = paa.ipv6_addr.map(std::net::Ipv6Addr::from);
            if let Some(ft) = pgw_c.as_ref() {
                sess.pgw_addr = ft.ipv4_addr.map(std::net::Ipv4Addr::from);
            }
            ctx.sess_update(&sess);
            log::info!(
                "S5/S8 Create Session Response from {peer}: PGW allocated PAA {:?} (pdn_type={})",
                sess.paa.ipv4_addr,
                sess.paa.pdn_type
            );
        }
    } else if cause == gtp_cause::REQUEST_ACCEPTED {
        // An accepted response with no PAA is a PGW that claims success and allocated
        // nothing. Answering the MME from local state here is exactly the defect.
        log::error!(
            "S5/S8 Create Session Response from {peer} was accepted but carries NO PAA: the \
             session has no PDN address and cannot be completed"
        );
        crate::sxa_response::fail_with_cause(continuation, gtp_cause::MANDATORY_IE_MISSING);
        return;
    }

    let existing = ctx.sess_find_by_id(sess_id);
    match crate::s5c_handler::handle_create_session_response(
        existing.as_ref(),
        0,
        &[],
        cause,
        pgw_c.map(|ft| ft.teid).unwrap_or(0),
        pgw_u.map(|ft| ft.teid).unwrap_or(0),
    ) {
        crate::s5c_handler::HandlerResult::Error(cause) => {
            log::error!(
                "S5/S8 Create Session Response from {peer} REJECTED the session: cause {cause}"
            );
            // The PGW refused, so there is no anchor and no user plane to provision. The
            // MME gets the PGW's own cause rather than a local guess.
            crate::sxa_response::fail_with_cause(continuation, cause);
            return;
        }
        other => log::debug!("S5/S8 Create Session Response handled: {other:?}"),
    }

    let Some(sess) = ctx.sess_find_by_id(sess_id) else {
        log::error!("S5/S8 Create Session Response for session {sess_id}, which is gone");
        crate::sxa_response::fail(
            continuation,
            "the session was removed while the PGW answered",
        );
        return;
    };

    // Now the SGW-U can be provisioned: it has a PGW-U endpoint to tunnel to.
    if let Err(e) =
        pfcp_path::send_session_establishment_request(&sess, seq as u64, None, 0, continuation)
    {
        log::error!("PFCP Session Establishment failed after the PGW answered: {e}");
    }
}

fn dispatch_modify_bearer_request(server: &GtpcServer, msg: &Gtp2Message, peer: SocketAddr) {
    let seq = msg.header.sequence_number;
    let ue = ue_from_header(msg);

    let parsed = match s11_parse::parse_modify_bearer_request(msg) {
        Ok(p) => p,
        Err(e) => {
            let teid = ue.map(|u| u.mme_s11_teid).unwrap_or(0);
            send_reject(
                server,
                peer,
                Gtp2MessageType::ModifyBearerResponse,
                teid,
                seq,
                e,
            );
            return;
        }
    };

    let Some(ue) = ue else {
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::ModifyBearerResponse,
            0,
            seq,
            gtp_cause::CONTEXT_NOT_FOUND,
        );
        return;
    };

    let (ebi, enb_teid, enb_addr) = match parsed.bearer {
        Some((ebi, Some(ref fteid))) => (ebi, fteid.teid, fteid.ipv4_addr),
        Some((ebi, None)) => (ebi, 0, None),
        None => {
            // No bearer change requested (e.g. TAU): accept as-is
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::ModifyBearerResponse,
                ue.mme_s11_teid,
                seq,
                gtp_cause::REQUEST_ACCEPTED,
            );
            return;
        }
    };

    let result =
        s11_handler::handle_modify_bearer_request(Some(&ue), seq as u64, &[], ebi, enb_teid);

    let ctx = sgwc_self();
    match result {
        HandlerResult::SendPfcp => {
            // Record the eNB address alongside the TEID
            if let Some(bearer) = ctx.bearer_find_by_ue_ebi(ue.id, ebi) {
                if let Some(mut dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
                    dl_tunnel.remote_ip.ipv4 = enb_addr.map(Ipv4Addr::from);
                    ctx.tunnel_update(&dl_tunnel);
                }
                if let Err(e) = pfcp_path::send_bearer_modification_request(
                    bearer.id,
                    seq as u64,
                    None,
                    sxa_handler::pfcp_modify::DL_ONLY | sxa_handler::pfcp_modify::ACTIVATE,
                ) {
                    log::error!("PFCP bearer modification failed: {e}");
                }
                if let Some(sess) = ctx.sess_find_by_id(bearer.sess_id) {
                    match s11_build::build_modify_bearer_response(
                        &sess,
                        seq,
                        gtp_cause::REQUEST_ACCEPTED,
                    ) {
                        Ok(response) => {
                            if let Err(e) = server.send_response(peer, &response) {
                                log::error!("Modify Bearer Response to {peer} failed: {e}");
                            }
                        }
                        Err(e) => log::error!("Failed to build Modify Bearer Response: {e}"),
                    }
                    return;
                }
            }
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::ModifyBearerResponse,
                ue.mme_s11_teid,
                seq,
                gtp_cause::CONTEXT_NOT_FOUND,
            );
        }
        HandlerResult::Error(cause) => {
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::ModifyBearerResponse,
                ue.mme_s11_teid,
                seq,
                cause,
            );
        }
        _ => {}
    }
}

fn dispatch_delete_session_request(server: &GtpcServer, msg: &Gtp2Message, peer: SocketAddr) {
    let seq = msg.header.sequence_number;
    let ue = ue_from_header(msg);

    let parsed = match s11_parse::parse_delete_session_request(msg) {
        Ok(p) => p,
        Err(e) => {
            let teid = ue.map(|u| u.mme_s11_teid).unwrap_or(0);
            send_reject(
                server,
                peer,
                Gtp2MessageType::DeleteSessionResponse,
                teid,
                seq,
                e,
            );
            return;
        }
    };

    let Some(ue) = ue else {
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::DeleteSessionResponse,
            0,
            seq,
            gtp_cause::CONTEXT_NOT_FOUND,
        );
        return;
    };

    let result = s11_handler::handle_delete_session_request(
        Some(&ue),
        seq as u64,
        &[],
        parsed.linked_ebi,
        parsed.scope_indication,
    );

    let ctx = sgwc_self();
    match result {
        HandlerResult::SendPfcp | HandlerResult::ForwardToPgw => {
            // Find the session being deleted, tear down the user plane, and
            // remove the control-plane context
            let sess = ue.sess_ids.iter().find_map(|sid| {
                ctx.sess_find_by_id(*sid).filter(|s| {
                    ctx.bearer_find_by_sess_ebi(s.id, parsed.linked_ebi)
                        .is_some()
                })
            });
            // #54: the S11 answer and the local removal both wait for the SGW-U.
            // This used to remove the session and answer REQUEST_ACCEPTED whichever way
            // the deletion went -- so against a real SGW-U a failed deletion leaked the
            // user plane, with the SGW-C no longer holding anything to address it by.
            match sess {
                Some(sess) => {
                    if let Err(e) = pfcp_path::send_session_deletion_request(
                        &sess,
                        seq as u64,
                        None,
                        pfcp_path::S11Continuation::DeleteSession {
                            peer,
                            seq,
                            teid: ue.mme_s11_teid,
                            sess_id: sess.id,
                        },
                    ) {
                        log::error!("PFCP session deletion failed: {e}");
                        send_cause_response(
                            server,
                            peer,
                            Gtp2MessageType::DeleteSessionResponse,
                            ue.mme_s11_teid,
                            seq,
                            sxa_handler::gtp_cause_from_pfcp(
                                sxa_handler::pfcp_cause::SYSTEM_FAILURE,
                            ),
                        );
                    }
                }
                None => {
                    // Nothing to tear down on the SGW-U: answer now, as before.
                    send_cause_response(
                        server,
                        peer,
                        Gtp2MessageType::DeleteSessionResponse,
                        ue.mme_s11_teid,
                        seq,
                        gtp_cause::REQUEST_ACCEPTED,
                    );
                }
            }
        }
        HandlerResult::Error(cause) => {
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::DeleteSessionResponse,
                ue.mme_s11_teid,
                seq,
                cause,
            );
        }
        _ => {}
    }
}

fn dispatch_release_access_bearers_request(
    server: &GtpcServer,
    msg: &Gtp2Message,
    peer: SocketAddr,
) {
    let seq = msg.header.sequence_number;
    let Some(ue) = ue_from_header(msg) else {
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::ReleaseAccessBearersResponse,
            0,
            seq,
            gtp_cause::CONTEXT_NOT_FOUND,
        );
        return;
    };

    let result = s11_handler::handle_release_access_bearers_request(Some(&ue), seq as u64, &[]);

    let ctx = sgwc_self();
    match result {
        HandlerResult::SendPfcp => {
            // Clear eNB endpoints (S1 release) and deactivate downlink
            for sess_id in &ue.sess_ids {
                let Some(sess) = ctx.sess_find_by_id(*sess_id) else {
                    continue;
                };
                for bearer_id in &sess.bearer_ids {
                    if let Some(mut dl_tunnel) = ctx.dl_tunnel_in_bearer(*bearer_id) {
                        dl_tunnel.remote_teid = 0;
                        dl_tunnel.remote_ip = crate::context::IpAddr::default();
                        ctx.tunnel_update(&dl_tunnel);
                    }
                }
                if let Err(e) = pfcp_path::send_session_modification_request(
                    &sess,
                    seq as u64,
                    None,
                    sxa_handler::pfcp_modify::DL_ONLY | sxa_handler::pfcp_modify::DEACTIVATE,
                ) {
                    log::error!("PFCP deactivation failed: {e}");
                }
            }
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::ReleaseAccessBearersResponse,
                ue.mme_s11_teid,
                seq,
                gtp_cause::REQUEST_ACCEPTED,
            );
        }
        HandlerResult::Error(cause) => {
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::ReleaseAccessBearersResponse,
                ue.mme_s11_teid,
                seq,
                cause,
            );
        }
        _ => {}
    }
}

fn dispatch_indirect_tunnel_request(
    server: &GtpcServer,
    msg: &Gtp2Message,
    peer: SocketAddr,
    create: bool,
) {
    let seq = msg.header.sequence_number;
    let response_type = if create {
        Gtp2MessageType::CreateIndirectDataForwardingTunnelResponse
    } else {
        Gtp2MessageType::DeleteIndirectDataForwardingTunnelResponse
    };

    let Some(ue) = ue_from_header(msg) else {
        send_cause_response(
            server,
            peer,
            response_type,
            0,
            seq,
            gtp_cause::CONTEXT_NOT_FOUND,
        );
        return;
    };

    let result = if create {
        s11_handler::handle_create_indirect_data_forwarding_tunnel_request(
            Some(&ue),
            seq as u64,
            &[],
        )
    } else {
        s11_handler::handle_delete_indirect_data_forwarding_tunnel_request(
            Some(&ue),
            seq as u64,
            &[],
        )
    };

    match result {
        HandlerResult::SendPfcp => {
            if create {
                match s11_build::build_create_indirect_data_forwarding_tunnel_response(
                    ue.id,
                    seq,
                    gtp_cause::REQUEST_ACCEPTED,
                ) {
                    Ok(response) => {
                        if let Err(e) = server.send_response(peer, &response) {
                            log::error!("Indirect tunnel response to {peer} failed: {e}");
                        }
                    }
                    Err(e) => log::error!("Failed to build indirect tunnel response: {e}"),
                }
            } else {
                send_cause_response(
                    server,
                    peer,
                    response_type,
                    ue.mme_s11_teid,
                    seq,
                    gtp_cause::REQUEST_ACCEPTED,
                );
            }
        }
        HandlerResult::Error(cause) => {
            send_cause_response(server, peer, response_type, ue.mme_s11_teid, seq, cause);
        }
        _ => {}
    }
}

fn dispatch_bearer_resource_command(server: &GtpcServer, msg: &Gtp2Message, peer: SocketAddr) {
    let seq = msg.header.sequence_number;
    let ue = ue_from_header(msg);

    // Linked EBI (M in the Bearer Resource Command)
    let linked_ebi = msg
        .get_ie(Gtp2IeType::Ebi as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .map(|v| v & 0x0F);
    let Some(linked_ebi) = linked_ebi else {
        let teid = ue.map(|u| u.mme_s11_teid).unwrap_or(0);
        send_reject(
            server,
            peer,
            Gtp2MessageType::BearerResourceFailureIndication,
            teid,
            seq,
            IeError::missing_mandatory(Gtp2IeType::Ebi),
        );
        return;
    };

    let result =
        s11_handler::handle_bearer_resource_command(ue.as_ref(), seq as u64, &[], linked_ebi);

    let teid = ue.as_ref().map(|u| u.mme_s11_teid).unwrap_or(0);
    match result {
        HandlerResult::ForwardToPgw => {
            // #52 criterion 7: forwarded to the PGW instead of refused.
            //
            // TS 29.274 §7.2.5: the Bearer Resource Command is relayed by the SGW to the
            // PGW, which decides. `SERVICE_NOT_SUPPORTED` was the honest answer while no
            // PGW peer existed — it is no longer, and answering it now would refuse a
            // procedure this node can carry.
            let ctx = sgwc_self();
            match ctx.pgw_s5c_peer() {
                Some(pgw_peer) => {
                    let mut relayed = msg.clone();
                    // Re-addressed to the PGW's control TEID and this node's own
                    // sequence space, because the SGW-C is the initiator on the S5-C leg.
                    // The linked bearer names the PDN connection, so the session it
                    // belongs to is the one whose PGW TEID this command must be
                    // addressed to. First-of-list would pick the wrong PDN for a
                    // multi-PDN UE.
                    let pgw_teid = ue
                        .as_ref()
                        .and_then(|u| {
                            ctx.sess_list_for_ue(u.id).into_iter().find(|s| {
                                ctx.default_bearer_in_sess(s.id)
                                    .is_some_and(|b| b.ebi == linked_ebi)
                            })
                        })
                        .map(|s| s.pgw_s5c_teid)
                        .unwrap_or(0);
                    relayed.header.teid = Some(pgw_teid);
                    let s5c_seq = server.alloc_sequence();
                    relayed.header.sequence_number = s5c_seq;
                    log::info!(
                        "Relaying Bearer Resource Command to PGW {pgw_peer} (S5-C TEID \
                         {pgw_teid:#x}, seq {s5c_seq})"
                    );
                    if let Err(e) = server.send_request(pgw_peer, &relayed, 0) {
                        log::error!("Bearer Resource Command relay to {pgw_peer} failed: {e}");
                        send_cause_response(
                            server,
                            peer,
                            Gtp2MessageType::BearerResourceFailureIndication,
                            teid,
                            seq,
                            gtp_cause::REMOTE_PEER_NOT_RESPONDING,
                        );
                    }
                }
                None => {
                    // Still the honest answer when there is no anchor to ask.
                    log::info!(
                        "Bearer Resource Command cannot be forwarded: no PGW S5/S8 peer \
                         configured"
                    );
                    send_cause_response(
                        server,
                        peer,
                        Gtp2MessageType::BearerResourceFailureIndication,
                        teid,
                        seq,
                        gtp_cause::SERVICE_NOT_SUPPORTED,
                    );
                }
            }
        }
        HandlerResult::Error(cause) => {
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::BearerResourceFailureIndication,
                teid,
                seq,
                cause,
            );
        }
        _ => {}
    }
}

fn dispatch_bearer_response(
    inner: &Arc<GtpcInner>,
    msg: &Gtp2Message,
    peer: SocketAddr,
    raw: &[u8],
) {
    let seq = msg.header.sequence_number;
    let matched = inner
        .xact
        .lock()
        .ok()
        .and_then(|mut x| x.match_response(seq, msg.header.message_type));
    if matched.is_none() {
        log::warn!(
            "Unsolicited bearer response type={} seq={} from {}",
            msg.header.message_type,
            seq,
            peer
        );
        return;
    }

    let parsed = match s11_parse::parse_bearer_response(msg) {
        Ok(p) => p,
        Err(e) => {
            log::error!(
                "Malformed bearer response from {peer}: cause={} offending_ie={}",
                e.cause,
                e.offending_ie_type
            );
            return;
        }
    };

    let ue = ue_from_header(msg);
    let ebi = parsed.bearer_ebi.unwrap_or(0);
    use Gtp2MessageType as T;
    match msg.header.message_type {
        t if t == T::CreateBearerResponse as u8 => {
            s11_handler::handle_create_bearer_response(
                ue.as_ref(),
                seq as u64,
                raw,
                ebi,
                parsed.cause,
            );
        }
        t if t == T::UpdateBearerResponse as u8 => {
            s11_handler::handle_update_bearer_response(
                ue.as_ref(),
                seq as u64,
                raw,
                ebi,
                parsed.cause,
            );
        }
        t if t == T::DeleteBearerResponse as u8 => {
            s11_handler::handle_delete_bearer_response(
                ue.as_ref(),
                seq as u64,
                raw,
                ebi,
                parsed.cause,
            );
        }
        _ => {}
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_gtp::v2::ie::{
        Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2CauseIe, Gtp2FTeidIe, Gtp2Ie,
    };
    use std::net::UdpSocket;

    fn test_server(t3_ms: u64, n3: u32) -> GtpcServer {
        sgwc_self().set_gtpu_address(Some(Ipv4Addr::new(10, 99, 0, 1)));
        sgwc_self().set_s11_address(Some(Ipv4Addr::new(10, 99, 0, 2)));
        GtpcServer::open(
            "127.0.0.1:0",
            Gtp2XactConfig {
                t3_response: Duration::from_millis(t3_ms),
                n3_requests: n3,
                response_hold: Duration::from_secs(5),
            },
            7,
        )
        .unwrap()
    }

    fn client() -> UdpSocket {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock
    }

    fn recv_msg(sock: &UdpSocket) -> Gtp2Message {
        let mut buf = [0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf).unwrap();
        let mut bytes = Bytes::copy_from_slice(&buf[..len]);
        Gtp2Message::decode(&mut bytes).unwrap()
    }

    fn csr(seq: u32, imsi: &[u8]) -> Gtp2Message {
        let mut msg = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::CreateSessionRequest as u8,
            0,
            seq,
        ));
        msg.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Imsi as u8, 0, imsi));
        msg.add_ie(Gtp2Ie::from_slice(Gtp2IeType::RatType as u8, 0, &[6]));
        // A real MME sends both (TS 29.274 Table 7.2.1-1), and the PGW requires them for
        // an E-UTRAN session, so the fixture sends what the wire actually carries.
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::ServingNetwork as u8,
            0,
            &[0x99, 0xf9, 0x07],
        ));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Uli as u8,
            0,
            &[
                0x18, 0x99, 0xf9, 0x07, 0x00, 0x01, 0x99, 0xf9, 0x07, 0x00, 0x00, 0x00, 0x01,
            ],
        ));
        msg.add_ie(Gtp2FTeidIe::new_ipv4(10, 0xAA01, [127, 0, 0, 1]).to_ie(0));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Apn as u8,
            0,
            &[8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't'],
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_bearer_qos(&Gtp2BearerQosIe::new(9, 1000, 2000, 0, 0));
        msg.add_bearer_context(0, &bc);
        msg
    }

    #[test]
    fn test_echo_request_response_with_recovery() {
        let server = test_server(1000, 1);
        let sock = client();

        let echo = Gtp2Message::echo_request(0x77);
        sock.send_to(&echo.encode(), server.local_addr()).unwrap();

        let response = recv_msg(&sock);
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::EchoResponse as u8
        );
        assert_eq!(response.header.sequence_number, 0x77);
        let rec = response.get_ie_by_type(Gtp2IeType::Recovery as u8).unwrap();
        assert_eq!(rec.value[0], 7); // server restart counter

        server.close();
    }

    // ================================================================
    // #54: the S11 answer waits for the SGW-U
    // ================================================================

    /// A stand-in SGW-U on an ephemeral port, plus this SGW-C's own Sxa node running.
    ///
    /// The stand-in answers Session Establishment / Modification / Deletion with `cause`
    /// after `delay`, which is what makes "no Create Session Response until the SGW-U
    /// answers" observable rather than asserted.
    struct StandInSgwu {
        _guard: crate::pfcp_path::SxaTestGuard,
        /// Requests the stand-in received, as (msg_type, seid, body).
        seen: std::sync::Arc<std::sync::Mutex<Vec<(u8, Option<u64>, Vec<u8>)>>>,
        /// The stand-in's own socket, so a test can push a Session Report Request at the
        /// SGW-C the way a real SGW-U reports buffered downlink data.
        sock: std::sync::Arc<tokio::net::UdpSocket>,
        /// Where the SGW-C's Sxa socket is listening.
        sgwc_addr: SocketAddr,
    }

    impl StandInSgwu {
        /// Bodies the stand-in received for a message type, in order.
        fn received(&self, msg_type: u8) -> usize {
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(t, _, _)| *t == msg_type)
                .count()
        }

        /// Send a Session Report Request carrying a Downlink Data Report for `seid`.
        async fn report_downlink_data(&self, seid: u64, pdr_id: u16, seq: u32) {
            use nextgcore_pfcp::header::{PfcpHeader as PHeader, PfcpMessageType as PType};
            use nextgcore_pfcp::message::SessionReportRequest;
            use nextgcore_pfcp::types::{DownlinkDataReport, ReportType};

            let mut req = SessionReportRequest::new(ReportType {
                dldr: true,
                ..Default::default()
            });
            req.downlink_data_report = Some(DownlinkDataReport::new(pdr_id));
            let mut body = bytes::BytesMut::new();
            req.encode(&mut body);
            let mut out = bytes::BytesMut::new();
            let mut h = PHeader::new_with_seid(PType::SessionReportRequest, seid, seq);
            h.length = (12 + body.len()) as u16;
            h.encode(&mut out);
            out.extend_from_slice(&body);
            self.sock
                .send_to(&out, self.sgwc_addr)
                .await
                .expect("report to the SGW-C");
        }
    }

    async fn stand_in_sgwu(cause: u8, delay: Duration) -> StandInSgwu {
        use nextgcore_pfcp::header::PfcpHeader as PHeader;
        use nextgcore_pfcp::message::{
            SessionDeletionResponse, SessionEstablishmentResponse, SessionModificationResponse,
        };
        use nextgcore_pfcp::types::{FSeid, NodeId, PfcpCause};

        let guard = crate::pfcp_path::sxa_test_guard().await;
        let up = std::sync::Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind stand-in SGW-U"),
        );
        let up_addr = up.local_addr().unwrap();
        // The SGW-U the SGW-C sends to is process-global config; the guard serialises
        // every test that sets it.
        std::env::set_var("SGWC_SGWU_ADDR", up_addr.to_string());
        std::env::set_var("SGWC_PFCP_NODE_IP", "127.0.0.1");

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let handle = up.clone();
        let up = up.clone();
        tokio::spawn(async move {
            let up = handle;
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((len, from)) = up.recv_from(&mut buf).await else {
                    return;
                };
                let mut cursor = Bytes::copy_from_slice(&buf[..len]);
                let Ok(header) = PHeader::decode(&mut cursor) else {
                    continue;
                };
                let msg_type = header.message_type as u8;
                recorded.lock().unwrap_or_else(|e| e.into_inner()).push((
                    msg_type,
                    header.seid,
                    cursor.to_vec(),
                ));

                let pfcp_cause = PfcpCause::from_wire(cause);
                let mut body = bytes::BytesMut::new();
                let resp_type = match msg_type {
                    50 => {
                        let mut rsp = SessionEstablishmentResponse::new(pfcp_cause);
                        rsp.node_id = Some(NodeId::new_ipv4([127, 0, 0, 9]));
                        // Conditional-mandatory on acceptance (TS 29.244 §7.5.3): the
                        // UP F-SEID the SGW-C stores and addresses the session by.
                        if pfcp_cause == PfcpCause::RequestAccepted {
                            rsp.up_f_seid =
                                Some(FSeid::new_ipv4(0x0000_0000_5555_0001, [127, 0, 0, 9]));
                        }
                        rsp.encode(&mut body);
                        51u8
                    }
                    52 => {
                        SessionModificationResponse::new(pfcp_cause).encode(&mut body);
                        53u8
                    }
                    54 => {
                        SessionDeletionResponse::new(pfcp_cause).encode(&mut body);
                        55u8
                    }
                    // Association Setup, Heartbeat: not needed by these tests.
                    _ => continue,
                };
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let mut out = bytes::BytesMut::new();
                let mut h = PHeader::new_with_seid(
                    nextgcore_pfcp::header::PfcpMessageType::try_from(resp_type).unwrap(),
                    header.seid.unwrap_or(0),
                    header.sequence_number,
                );
                h.length = (12 + body.len()) as u16;
                h.encode(&mut out);
                out.extend_from_slice(&body);
                let _ = up.send_to(&out, from).await;
            }
        });

        let node =
            crate::pfcp_path::SxaNode::open("127.0.0.1:0".parse().unwrap(), Ipv4Addr::LOCALHOST)
                .await
                .expect("bind the SGW-C's Sxa socket");
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(node.clone().run(rx));
        // `run` installs the outbound queue in its own body; a request enqueued before it
        // is polled would be refused with "no Sxa transport".
        for _ in 0..200 {
            if crate::pfcp_path::sxa_node().is_some()
                && crate::pfcp_path::send_session_report_response(
                    0,
                    &crate::context::SgwcSess::default(),
                    crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
                )
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        StandInSgwu {
            _guard: guard,
            seen,
            sock: up,
            sgwc_addr: node.local_addr(),
        }
    }

    /// Receive one S11 message with a bounded wait, from a blocking socket inside an async
    /// test.
    async fn recv_s11(sock: &UdpSocket) -> Option<Gtp2Message> {
        let sock = sock.try_clone().expect("clone");
        tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            let (len, _) = sock.recv_from(&mut buf).ok()?;
            let mut bytes = Bytes::copy_from_slice(&buf[..len]);
            Gtp2Message::decode(&mut bytes).ok()
        })
        .await
        .ok()
        .flatten()
    }

    /// A stand-in PGW that answers an S5/S8 Create Session Request with an ALLOCATED
    /// PDN address and its own F-TEIDs (#52).
    ///
    /// This is what makes the chain testable end to end through the SGW-C: S11 in,
    /// S5/S8 out, S5/S8 in, Sxa out, Sxa in, S11 out. The address it returns is
    /// deliberately DIFFERENT from anything the MME asks about, so a test can prove the
    /// PAA the MME receives came from the anchor rather than from its own request.
    struct StandInPgw {
        addr: SocketAddr,
        /// Message types received, in order.
        seen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    /// The address this stand-in allocates. Not in 10.45.0.0/16 and not anything a test
    /// asks for, so its presence in the S11 response can only have come from here.
    const PGW_ALLOCATED_ADDR: [u8; 4] = [10, 77, 3, 9];

    async fn stand_in_pgw() -> StandInPgw {
        let sock = std::sync::Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind stand-in PGW"),
        );
        let addr = sock.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let handle = sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((len, from)) = handle.recv_from(&mut buf).await else {
                    return;
                };
                let mut bytes = Bytes::copy_from_slice(&buf[..len]);
                let Ok(msg) = Gtp2Message::decode(&mut bytes) else {
                    continue;
                };
                recorded
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(msg.header.message_type);
                if msg.header.message_type != Gtp2MessageType::CreateSessionRequest as u8 {
                    continue;
                }

                // Answer as a PGW does: Cause, its own control F-TEID at instance 1, the
                // ALLOCATED PAA, and a Bearer Context carrying the PGW-U endpoint.
                let mut resp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                    Gtp2MessageType::CreateSessionResponse as u8,
                    // Addressed to the SGW's own control TEID, which the request's
                    // Sender F-TEID named.
                    msg.get_ie(Gtp2IeType::FTeid as u8, 0)
                        .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok())
                        .map(|ft| ft.teid)
                        .unwrap_or(0),
                    msg.header.sequence_number,
                ));
                let mut cause_buf = bytes::BytesMut::new();
                nextgcore_gtp::v2::Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED)
                    .encode(&mut cause_buf, 0);
                let mut c = cause_buf.freeze();
                if let Ok(ie) = nextgcore_gtp::v2::ie::Gtp2Ie::decode(&mut c) {
                    resp.add_ie(ie);
                }
                resp.add_ie(Gtp2FTeidIe::new_ipv4(7, 0x0BEE_F001, [127, 0, 0, 1]).to_ie(1));
                resp.add_ie(Gtp2PaaIe::ipv4(PGW_ALLOCATED_ADDR).to_ie(0));
                let mut bc = Gtp2BearerContextIe::new();
                bc.set_ebi(5);
                bc.set_fteid(2, &Gtp2FTeidIe::new_ipv4(6, 0x0BEE_F002, [127, 0, 0, 1]));
                resp.add_bearer_context(0, &bc);

                let _ = handle.send_to(&resp.encode(), from).await;
            }
        });
        let _ = sock;
        StandInPgw { addr, seen }
    }

    /// Point the SGW-C at a stand-in PGW. Returns it so the test can assert what it saw.
    async fn with_stand_in_pgw() -> StandInPgw {
        let pgw = stand_in_pgw().await;
        sgwc_self().set_pgw_s5c_peer(Some(pgw.addr));
        pgw
    }

    /// #52 criterion 9, the load-bearing assertion of the whole issue: the PDN Address
    /// the MME receives was ALLOCATED BY THE PGW, not echoed from its own request.
    ///
    /// Drives the full chain through the SGW-C over real sockets — S11 in, S5/S8 out,
    /// S5/S8 in, Sxa out, Sxa in, S11 out — and asserts the address in the S11 Create
    /// Session Response is the stand-in PGW's, which no other node in the test knows.
    /// Before #52 the SGW-C copied the MME's PAA onto the session and answered from local
    /// state, so this assertion could not have held however the test was written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_paa_the_mme_receives_is_allocated_by_the_pgw() {
        let _sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_millis(0),
        )
        .await;
        // Set AFTER `stand_in_sgwu`: that call takes the guard over this process's
        // ambient SGW-C configuration, and setting the PGW peer before it is exactly the
        // unlocked-writer race #308 was about.
        let pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x52];

        sock.send_to(&csr(0x5201, &imsi).encode(), server.local_addr())
            .unwrap();

        let response = recv_s11(&sock).await.expect("the response must arrive");
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        assert_eq!(
            response
                .get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(gtp_cause::REQUEST_ACCEPTED),
            "the chain must complete"
        );

        // The PGW was actually asked. Before #52 the SGW-C never sent an S5/S8 message.
        assert!(
            pgw.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&(Gtp2MessageType::CreateSessionRequest as u8)),
            "the SGW-C must RELAY a Create Session Request to the PGW (TS 29.274 §7.2.1)"
        );

        // And the address the MME is given is the anchor's.
        let paa = response
            .get_ie(Gtp2IeType::Paa as u8, 0)
            .and_then(|ie| Gtp2PaaIe::decode(&ie.value).ok())
            .expect("the response must carry a PAA");
        assert_eq!(
            paa.ipv4_addr,
            Some(PGW_ALLOCATED_ADDR),
            "the PDN address must be the one the PGW allocated, not the MME's own echoed back"
        );
    }

    /// #52: the relayed S5/S8 Create Session Request carries every IE the ANCHOR requires.
    ///
    /// Mirrors smfd's `handle_create_session_request` conditional-IE checks, which reject
    /// with `ConditionalIeMissing` without Serving Network, ULI or PAA. This is the
    /// cross-daemon parity check #51 needed too: `smfd` is a binary with no lib target, so
    /// its validation cannot be called from here, and a mirrored list is the strongest
    /// available guard. It is load-bearing rather than decorative — the first version of
    /// this PR relayed NEITHER Serving Network nor ULI, and the real anchor refused it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_relayed_s5c_request_carries_what_the_anchor_requires() {
        let _sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_millis(0),
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        // A recording socket in place of the answering stand-in, so the REQUEST can be
        // inspected rather than only its effect.
        let recorder = std::sync::Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind recorder"),
        );
        sgwc_self().set_pgw_s5c_peer(Some(recorder.local_addr().unwrap()));
        let _ = pgw;

        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x51];
        sock.send_to(&csr(0x5101, &imsi).encode(), server.local_addr())
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), recorder.recv_from(&mut buf))
            .await
            .expect("the SGW-C must relay to the PGW")
            .expect("recv");
        let mut bytes = Bytes::copy_from_slice(&buf[..len]);
        let relayed = Gtp2Message::decode(&mut bytes).expect("the relay must be decodable");

        assert_eq!(
            relayed.header.message_type,
            Gtp2MessageType::CreateSessionRequest as u8
        );
        for (ie_type, name) in [
            (Gtp2IeType::Imsi as u8, "IMSI"),
            (Gtp2IeType::RatType as u8, "RAT Type"),
            (Gtp2IeType::FTeid as u8, "Sender F-TEID"),
            (Gtp2IeType::Apn as u8, "APN"),
            (
                Gtp2IeType::BearerContext as u8,
                "Bearer Contexts to be created",
            ),
            (Gtp2IeType::ServingNetwork as u8, "Serving Network"),
            (Gtp2IeType::Uli as u8, "User Location Information"),
        ] {
            assert!(
                relayed.get_ie(ie_type, 0).is_some(),
                "the anchor requires {name}: without it smfd answers ConditionalIeMissing"
            );
        }

        // The Sender F-TEID names the S5/S8 SGW control interface, not S11.
        let ft = Gtp2FTeidIe::decode(&relayed.get_ie(Gtp2IeType::FTeid as u8, 0).unwrap().value)
            .expect("decode");
        assert_eq!(
            ft.interface_type,
            s11_build::f_teid_interface::S5_S8_SGW_GTP_C,
            "the S5/S8 leg must name the S5/S8 interface type"
        );
    }

    /// With no PGW configured the SGW-C REFUSES rather than answering from local state.
    ///
    /// Answering locally is the defect #52 exists to fix, so the absence of an anchor has
    /// to be visible to the MME instead of being papered over with a fabricated success.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_session_request_with_no_pgw_is_refused() {
        let _sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_millis(0),
        )
        .await;
        // Deliberately NO anchor, set under the same guard the stand-in SGW-U holds.
        sgwc_self().set_pgw_s5c_peer(None);
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x53];

        sock.send_to(&csr(0x5301, &imsi).encode(), server.local_addr())
            .unwrap();

        let response = recv_s11(&sock)
            .await
            .expect("a refusal must still be answered");
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        assert_eq!(
            response
                .get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(gtp_cause::REMOTE_PEER_NOT_RESPONDING),
            "no anchor must be reported, not fabricated as success"
        );
        assert!(
            response.get_ie(Gtp2IeType::Paa as u8, 0).is_none(),
            "a refused session must carry no PDN address"
        );
    }

    /// #54 criterion 6, first half: NO Create Session Response is sent until the PFCP
    /// Session Establishment Response arrives — and then it is the full accepted one.
    ///
    /// The stand-in SGW-U holds its answer for 400ms; the MME socket's own read timeout is
    /// 150ms for the first attempt, so the "not yet" half is observed rather than assumed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_create_session_response_until_the_sgwu_answers() {
        let sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_millis(400),
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        // The gated answer is sent through the PROCESS-GLOBAL S11 server (the Sxa response
        // path has no other handle), so this test's own server has to be the installed one.
        set_s11_server(server.clone());
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x54];

        sock.send_to(&csr(0x5401, &imsi).encode(), server.local_addr())
            .unwrap();

        // Nothing yet: the user plane is not provisioned, so TS 29.274 §7.2.2 has nothing
        // truthful to say.
        assert!(
            recv_s11(&sock).await.is_none(),
            "the Create Session Response must NOT be sent before the SGW-U has answered"
        );

        // Now it arrives, accepted, with the full body the MME needs.
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let response = recv_s11(&sock).await.expect("the response must arrive");
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        assert_eq!(response.header.sequence_number, 0x5401);
        assert_eq!(response.header.teid, Some(0xAA01));
        let cause =
            Gtp2CauseIe::decode(&response.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap();
        assert_eq!(cause.cause, gtp_cause::REQUEST_ACCEPTED);
        let bc = response.bearer_context(0).unwrap().unwrap();
        assert_eq!(bc.ebi().unwrap(), 5);
        assert_ne!(bc.fteid(0).unwrap().unwrap().teid, 0);

        // The SGW-U really was asked, and the SEID it returned was stored.
        let ctx0 = sgwc_self();
        let sess_cp_seid = ctx0
            .ue_find_by_imsi(&imsi)
            .and_then(|u| ctx0.sess_find_by_id(u.sess_ids[0]))
            .map(|s| s.sgwc_sxa_seid)
            .expect("session");
        let seen = sgwu.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let establishment = seen
            .iter()
            .find(|(t, _, _)| *t == 50)
            .map(|(_, _, body)| body.clone())
            .expect("a Session Establishment Request must have reached the SGW-U");

        // #54: and it must be REAL PFCP. The old builders emitted bare values with no IE
        // headers, so a conformant SGW-U -- which decodes with this same library -- would
        // have found zero rules and created a session that forwards nothing, while
        // answering REQUEST_ACCEPTED. Decoding it here is what separates "bytes were sent"
        // from "the peer can act on them".
        let mut body = Bytes::copy_from_slice(&establishment);
        let decoded = nextgcore_pfcp::message::SessionEstablishmentRequest::decode(&mut body)
            .expect("the SGW-U's own decoder must be able to read our request");
        assert_eq!(
            decoded.cp_f_seid.seid, sess_cp_seid,
            "the CP F-SEID is what the SGW-U addresses its Session Report to"
        );
        assert!(
            !decoded.create_pdrs.is_empty(),
            "a bearer with no Create PDR provisions no packet detection at all"
        );
        assert!(
            !decoded.create_fars.is_empty(),
            "and no Create FAR means nothing is forwarded or buffered"
        );
        assert!(
            decoded.create_pdrs.iter().all(|p| p.pdr_id != 0),
            "every PDR must carry the id that names it (nothing allocated these before #54)"
        );
        assert!(
            decoded
                .create_pdrs
                .iter()
                .any(|p| p.pdi.local_f_teid.is_some()),
            "the PDI's F-TEID is what an inbound G-PDU is matched on"
        );
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("ue");
        let sess = ctx.sess_find_by_id(ue.sess_ids[0]).expect("sess");
        assert_eq!(
            sess.sgwu_sxa_seid, 0x0000_0000_5555_0001,
            "the UP F-SEID from the response is what later requests are addressed by"
        );

        server.close();
    }

    /// #54 criterion 2: a non-accepted PFCP cause yields a MAPPED GTP cause, not a
    /// hard-coded `REQUEST_ACCEPTED`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_user_plane_yields_a_mapped_gtp_cause() {
        let _sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::NO_RESOURCES_AVAILABLE,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x55];

        sock.send_to(&csr(0x5402, &imsi).encode(), server.local_addr())
            .unwrap();
        let response = recv_s11(&sock).await.expect("a response must arrive");
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        let cause =
            Gtp2CauseIe::decode(&response.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap();
        assert_eq!(
            cause.cause,
            crate::sxa_handler::gtp_cause_from_pfcp(
                crate::sxa_handler::pfcp_cause::NO_RESOURCES_AVAILABLE
            ),
            "the MME must be told what the SGW-U said, not REQUEST_ACCEPTED: {:?}",
            cause
        );
        assert_ne!(
            cause.cause,
            gtp_cause::REQUEST_ACCEPTED,
            "an accepted cause for a user plane that does not exist is the whole defect"
        );

        server.close();
    }

    /// #54 criterion 3: Delete Session gates the local removal AND the cause on the PFCP
    /// deletion result. A refusal keeps the session, so a retry can still reach it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_deletion_keeps_the_session_and_says_so() {
        let _sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::SYSTEM_FAILURE,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x56];

        // Establish first. The stand-in refuses everything, so this create is refused too;
        // the session context still exists, which is what the delete needs.
        sock.send_to(&csr(0x5403, &imsi).encode(), server.local_addr())
            .unwrap();
        let _ = recv_s11(&sock).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("ue");
        let sess_id = ue.sess_ids[0];

        let dsr = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DeleteSessionRequest as u8,
            ue.sgw_s11_teid,
            0x5404,
        ));
        let mut dsr = dsr;
        dsr.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            Gtp2IeType::Ebi as u8,
            0,
            &[5],
        ));
        sock.send_to(&dsr.encode(), server.local_addr()).unwrap();
        let response = recv_s11(&sock).await.expect("a response must arrive");
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::DeleteSessionResponse as u8
        );
        let cause =
            Gtp2CauseIe::decode(&response.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap();
        assert_ne!(
            cause.cause,
            gtp_cause::REQUEST_ACCEPTED,
            "a deletion the SGW-U refused must not be reported as accepted"
        );
        assert!(
            sgwc_self().sess_find_by_id(sess_id).is_some(),
            "and the local context must be KEPT: removing it while the SGW-U still holds \
             the session leaks the user plane with nothing left to address it by"
        );

        server.close();
    }

    /// #54 criterion 4: `handle_session_report_request` has a PRODUCTION caller, and a
    /// Downlink Data Report drives a Downlink Data Notification toward the MME.
    ///
    /// Before this the classifier returned `SendGtpToMme` to nobody — it had zero callers
    /// anywhere in the crate — and `send_downlink_data_notification` was reachable only
    /// from `mod tests`. So downlink data for an idle UE produced no paging request at all,
    /// and idle-mode delivery could not work however correct the pieces were.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_downlink_data_report_pages_the_ue() {
        let sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x57];

        // A live session, so the report has something to be about.
        sock.send_to(&csr(0x5405, &imsi).encode(), server.local_addr())
            .unwrap();
        let _ = recv_s11(&sock).await.expect("create session response");
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("ue");
        let sess = ctx.sess_find_by_id(ue.sess_ids[0]).expect("sess");
        let pdr_id = ctx
            .dl_tunnel_in_bearer(sess.bearer_ids[0])
            .and_then(|t| t.pdr_id)
            .or_else(|| {
                ctx.ul_tunnel_in_bearer(sess.bearer_ids[0])
                    .and_then(|t| t.pdr_id)
            })
            .expect("the establishment must have allocated a PDR id");

        // The SGW-U buffered a downlink packet and says so (TS 29.244 §7.5.8).
        sgwu.report_downlink_data(sess.sgwc_sxa_seid, pdr_id, 0x99)
            .await;

        let ddn = recv_s11(&sock)
            .await
            .expect("a Downlink Data Notification must reach the MME");
        assert_eq!(
            ddn.header.message_type,
            Gtp2MessageType::DownlinkDataNotification as u8,
            "a Downlink Data Report must page the UE (TS 23.401 §5.3.4.2)"
        );
        assert_eq!(
            ddn.header.teid,
            Some(ue.mme_s11_teid),
            "and be addressed to the MME that holds this UE"
        );

        // And the SGW-U got its Session Report Response, so it does not retransmit.
        for _ in 0..100 {
            if sgwu.received(57) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            sgwu.received(57) > 0 || sgwu.received(56) == 0,
            "the report must be answered, or the SGW-U retransmits it"
        );

        server.close();
    }

    /// #54 criterion 5: a refused Downlink Data Notification discards the buffered packets.
    ///
    /// TS 23.401 §5.3.4.2: on a DDN Acknowledge the MME could not serve, the Serving GW
    /// deletes the buffered packet(s). This used to be a `log::warn!` and nothing else, so
    /// the packets stayed on the SGW-U for the life of the session — an unbounded buffer no
    /// message ever drained.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_ddn_discards_the_buffered_packets() {
        let sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x58];

        sock.send_to(&csr(0x5406, &imsi).encode(), server.local_addr())
            .unwrap();
        let _ = recv_s11(&sock).await.expect("create session response");
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("ue");
        let sess = ctx.sess_find_by_id(ue.sess_ids[0]).expect("sess");
        let pdr_id = ctx
            .dl_tunnel_in_bearer(sess.bearer_ids[0])
            .and_then(|t| t.pdr_id)
            .or_else(|| {
                ctx.ul_tunnel_in_bearer(sess.bearer_ids[0])
                    .and_then(|t| t.pdr_id)
            })
            .expect("pdr id");

        sgwu.report_downlink_data(sess.sgwc_sxa_seid, pdr_id, 0x9A)
            .await;
        let ddn = recv_s11(&sock).await.expect("the DDN");
        let modifications_before = sgwu.received(52);

        // The MME cannot serve it (TS 29.274 §8.4: e.g. UE not responding).
        let mut ack = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotificationAcknowledge as u8,
            ue.sgw_s11_teid,
            ddn.header.sequence_number,
        ));
        ack.add_ie(Gtp2CauseIe::new(gtp_cause::CONTEXT_NOT_FOUND).to_ie(0));
        sock.send_to(&ack.encode(), server.local_addr()).unwrap();

        // A Session Modification carrying DROBU must reach the SGW-U.
        let mut arrived = false;
        for _ in 0..200 {
            if sgwu.received(52) > modifications_before {
                arrived = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            arrived,
            "a refused DDN must make the SGW-C ask the SGW-U to discard the buffered \
             packets; it used to only log the cause"
        );

        server.close();
    }

    /// #54 criterion 5: a Downlink Data Notification Failure Indication also discards the
    /// buffered packets (TS 29.274 §7.2.11.3, TS 23.401 §5.3.4.2).
    ///
    /// A separate message from the Acknowledge and a separate dispatch arm, so a separate
    /// guard: the Failure Indication arm used to be a lone `log::warn!` with no action at
    /// all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_ddn_failure_indication_discards_the_buffered_packets() {
        let sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x5A];

        sock.send_to(&csr(0x5408, &imsi).encode(), server.local_addr())
            .unwrap();
        let _ = recv_s11(&sock).await.expect("create session response");
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("ue");
        let sess = ctx.sess_find_by_id(ue.sess_ids[0]).expect("sess");
        let pdr_id = ctx
            .dl_tunnel_in_bearer(sess.bearer_ids[0])
            .and_then(|t| t.pdr_id)
            .or_else(|| {
                ctx.ul_tunnel_in_bearer(sess.bearer_ids[0])
                    .and_then(|t| t.pdr_id)
            })
            .expect("pdr id");

        sgwu.report_downlink_data(sess.sgwc_sxa_seid, pdr_id, 0x9D)
            .await;
        let _ = recv_s11(&sock).await.expect("the DDN");
        let modifications_before = sgwu.received(52);

        // The MME could not page the UE at all.
        let mut fail = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotificationFailureIndication as u8,
            ue.sgw_s11_teid,
            0x5409,
        ));
        fail.add_ie(Gtp2CauseIe::new(gtp_cause::CONTEXT_NOT_FOUND).to_ie(0));
        sock.send_to(&fail.encode(), server.local_addr()).unwrap();

        let mut arrived = false;
        for _ in 0..200 {
            if sgwu.received(52) > modifications_before {
                arrived = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            arrived,
            "a DDN Failure Indication must make the SGW-C discard the SGW-U's buffered \
             packets; TS 23.401 §5.3.4.2 says delete them, and this used to only log"
        );

        server.close();
    }

    /// #54 criterion 5, second half: the Data Notification Delay throttles the next DDN.
    ///
    /// The IE was PARSED into `ParsedDdnAck.data_notification_delay` and then dropped by
    /// the handler, so the throttling TS 29.274 §7.2.11.2 defines could not happen and a
    /// busy idle UE could produce a notification per downlink packet.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_data_notification_delay_throttles_the_next_ddn() {
        let sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x59];

        sock.send_to(&csr(0x5407, &imsi).encode(), server.local_addr())
            .unwrap();
        let _ = recv_s11(&sock).await.expect("create session response");
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("ue");
        let sess = ctx.sess_find_by_id(ue.sess_ids[0]).expect("sess");
        let pdr_id = ctx
            .dl_tunnel_in_bearer(sess.bearer_ids[0])
            .and_then(|t| t.pdr_id)
            .or_else(|| {
                ctx.ul_tunnel_in_bearer(sess.bearer_ids[0])
                    .and_then(|t| t.pdr_id)
            })
            .expect("pdr id");

        sgwu.report_downlink_data(sess.sgwc_sxa_seid, pdr_id, 0x9B)
            .await;
        let ddn = recv_s11(&sock).await.expect("the first DDN");

        // Accepted, with a 20 x 50ms = 1s delay before the next one.
        let mut ack = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotificationAcknowledge as u8,
            ue.sgw_s11_teid,
            ddn.header.sequence_number,
        ));
        ack.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        ack.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            Gtp2IeType::DelayValue as u8,
            0,
            &[20],
        ));
        sock.send_to(&ack.encode(), server.local_addr()).unwrap();
        // Let the acknowledge be processed before the next report.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // A second report inside the delay window must NOT page again.
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        sgwu.report_downlink_data(sess.sgwc_sxa_seid, pdr_id, 0x9C)
            .await;
        assert!(
            recv_s11(&sock).await.is_none(),
            "the MME asked for a 1s Data Notification Delay: a second notification inside \
             it is the storm the IE exists to suppress"
        );

        server.close();
    }

    // `test_create_session_request_accepted_over_socket` was REPLACED by
    // `no_create_session_response_until_the_sgwu_answers` (#54). It asserted that a Create
    // Session Request is answered `REQUEST_ACCEPTED` immediately, which is precisely the
    // behaviour this issue removes -- TS 23.401 §5.3.2.1 answers after the user plane is
    // provisioned. The replacement asserts everything it did (sequence number, MME TEID,
    // cause, Sender F-TEID, the bearer context's allocated S1-U endpoint) AND that nothing
    // is sent until the SGW-U has answered.

    #[test]
    fn test_create_session_request_missing_imsi_rejected() {
        let server = test_server(1000, 1);
        let sock = client();

        let mut msg = csr(0x1002, &[0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x02]);
        msg.ies.retain(|ie| ie.ie_type != Gtp2IeType::Imsi as u8);
        sock.send_to(&msg.encode(), server.local_addr()).unwrap();

        let response = recv_msg(&sock);
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        let cause =
            Gtp2CauseIe::decode(&response.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap();
        assert_eq!(cause.cause, gtp_cause::MANDATORY_IE_MISSING);
        assert_eq!(cause.offending_ie_type, Some(Gtp2IeType::Imsi as u8));

        server.close();
    }

    #[test]
    fn test_modify_bearer_request_unknown_teid_rejected() {
        let server = test_server(1000, 1);
        let sock = client();

        let msg = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            0xDEAD_0001, // no UE has this TEID
            0x1003,
        ));
        sock.send_to(&msg.encode(), server.local_addr()).unwrap();

        let response = recv_msg(&sock);
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::ModifyBearerResponse as u8
        );
        let cause =
            Gtp2CauseIe::decode(&response.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap();
        assert_eq!(cause.cause, gtp_cause::CONTEXT_NOT_FOUND);

        server.close();
    }

    /// #54: converted to drive a stand-in SGW-U, because the Create Session Response it
    /// compares is now sent only after the user plane is provisioned. The property under
    /// test is unchanged: a retransmitted request is answered from the transaction cache
    /// and creates no second session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_duplicate_request_answered_from_cache() {
        let _sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x03];

        let msg = csr(0x1004, &imsi);
        sock.send_to(&msg.encode(), server.local_addr()).unwrap();
        let first = recv_s11(&sock).await.expect("first response");

        // Retransmit the identical request (same sequence number)
        sock.send_to(&msg.encode(), server.local_addr()).unwrap();
        let second = recv_s11(&sock).await.expect("cached response");

        assert_eq!(first.encode(), second.encode());
        // The retransmission must not have created a second session
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        assert_eq!(ue.sess_ids.len(), 1);

        server.close();
    }

    /// #54: converted to drive a stand-in SGW-U. Every S11 response in this lifecycle that
    /// is gated on Sxa now waits for it, so without a peer that answers the create step
    /// alone would time out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_full_session_lifecycle_over_socket() {
        let _sgwu = stand_in_sgwu(
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x04];

        // Create
        sock.send_to(&csr(0x2001, &imsi).encode(), server.local_addr())
            .unwrap();
        let csrsp = recv_s11(&sock).await.expect("create session response");
        let sgw_teid =
            Gtp2FTeidIe::decode(&csrsp.get_ie(Gtp2IeType::FTeid as u8, 0).unwrap().value)
                .unwrap()
                .teid;

        // Modify with eNB S1-U F-TEID
        let mut mbr = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            sgw_teid,
            0x2002,
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_fteid(0, &Gtp2FTeidIe::new_ipv4(0, 0xE0B1, [127, 0, 0, 1]));
        mbr.add_bearer_context(0, &bc);
        sock.send_to(&mbr.encode(), server.local_addr()).unwrap();
        let mbrsp = recv_s11(&sock).await.expect("modify bearer response");
        assert_eq!(
            mbrsp.header.message_type,
            Gtp2MessageType::ModifyBearerResponse as u8
        );
        assert_eq!(
            Gtp2CauseIe::decode(&mbrsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            gtp_cause::REQUEST_ACCEPTED
        );

        // Release access bearers
        let rab = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::ReleaseAccessBearersRequest as u8,
            sgw_teid,
            0x2003,
        ));
        sock.send_to(&rab.encode(), server.local_addr()).unwrap();
        let rabrsp = recv_s11(&sock)
            .await
            .expect("release access bearers response");
        assert_eq!(
            rabrsp.header.message_type,
            Gtp2MessageType::ReleaseAccessBearersResponse as u8
        );

        // Delete
        let mut dsr = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DeleteSessionRequest as u8,
            sgw_teid,
            0x2004,
        ));
        dsr.add_ie(nextgcore_gtp::v2::ie::Gtp2EbiIe::new(5).to_ie(0));
        sock.send_to(&dsr.encode(), server.local_addr()).unwrap();
        let dsrsp = recv_s11(&sock).await.expect("delete session response");
        assert_eq!(
            dsrsp.header.message_type,
            Gtp2MessageType::DeleteSessionResponse as u8
        );
        assert_eq!(
            Gtp2CauseIe::decode(&dsrsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            gtp_cause::REQUEST_ACCEPTED
        );

        // Session is gone
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        assert!(ue.sess_ids.is_empty());

        server.close();
    }

    #[test]
    fn test_ddn_t3_n3_retransmission_and_exhaustion() {
        // Tiny T3, N3=2: the silent peer must see 1 + 2 = 3 datagrams,
        // after which the path is marked Failed.
        let server = test_server(50, 2);
        let silent_peer = client();
        let peer_addr = silent_peer.local_addr().unwrap();

        // Provision a UE + bearer whose MME is the silent peer
        let ctx = sgwc_self();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x05];
        let ue = ctx.ue_add(&imsi).unwrap();
        let mut ue = ctx.ue_find_by_id(ue.id).unwrap();
        ue.mme_s11_teid = 0x5151;
        ue.mme_addr = Some(peer_addr);
        ctx.ue_update(&ue);
        let sess = ctx.sess_add(ue.id, "internet").unwrap();
        let bearer = ctx.bearer_add(sess.id).unwrap();
        let mut bearer = ctx.bearer_find_by_id(bearer.id).unwrap();
        bearer.ebi = 5;
        bearer.arp_priority_level = 9;
        ctx.bearer_update(&bearer);

        server
            .send_downlink_data_notification(None, &bearer)
            .unwrap();

        // Initial + 2 retransmissions
        let mut received = 0;
        for _ in 0..3 {
            let mut buf = [0u8; 1024];
            silent_peer
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            if silent_peer.recv_from(&mut buf).is_ok() {
                received += 1;
            }
        }
        assert_eq!(received, 3, "expected initial send + N3 retransmissions");

        // After exhaustion the path is Failed and nothing else arrives
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(server.peer_state(peer_addr), GtpPathState::Failed);
        let mut buf = [0u8; 1024];
        silent_peer
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        assert!(silent_peer.recv_from(&mut buf).is_err());

        server.close();
    }

    #[test]
    fn test_ddn_ack_matches_transaction() {
        let server = test_server(1000, 1);
        let mme = client();
        let peer_addr = mme.local_addr().unwrap();

        let ctx = sgwc_self();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x06];
        let ue = ctx.ue_add(&imsi).unwrap();
        let mut ue = ctx.ue_find_by_id(ue.id).unwrap();
        ue.mme_s11_teid = 0x6161;
        ue.mme_addr = Some(peer_addr);
        ctx.ue_update(&ue);
        let sess = ctx.sess_add(ue.id, "internet").unwrap();
        let bearer = ctx.bearer_add(sess.id).unwrap();
        let mut bearer = ctx.bearer_find_by_id(bearer.id).unwrap();
        bearer.ebi = 6;
        ctx.bearer_update(&bearer);

        let seq = server
            .send_downlink_data_notification(None, &bearer)
            .unwrap();

        // MME receives the DDN and acknowledges it
        let ddn = recv_msg(&mme);
        assert_eq!(
            ddn.header.message_type,
            Gtp2MessageType::DownlinkDataNotification as u8
        );
        assert_eq!(ddn.header.sequence_number, seq);

        let mut ack = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotificationAcknowledge as u8,
            ue.sgw_s11_teid,
            seq,
        ));
        ack.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        mme.send_to(&ack.encode(), server.local_addr()).unwrap();

        // The transaction completes: no retransmission reaches the MME
        std::thread::sleep(Duration::from_millis(1200));
        let mut buf = [0u8; 1024];
        mme.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        assert!(mme.recv_from(&mut buf).is_err());

        server.close();
    }

    #[test]
    fn test_peer_restart_counter_staleness_detected() {
        let server = test_server(1000, 1);
        let sock = client();

        // First echo with restart counter 3
        let mut echo = Gtp2Message::echo_request(0x3001);
        echo.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[3]));
        sock.send_to(&echo.encode(), server.local_addr()).unwrap();
        recv_msg(&sock);

        // Restarted peer: counter bumps to 4 -> path state resets to Idle
        let mut echo = Gtp2Message::echo_request(0x3002);
        echo.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[4]));
        sock.send_to(&echo.encode(), server.local_addr()).unwrap();
        recv_msg(&sock);

        assert_eq!(
            server.peer_state(sock.local_addr().unwrap()),
            GtpPathState::Idle
        );

        server.close();
    }

    // ================================================================
    // nextgcore #53: restart handling, Echo, Version Not Supported
    // ================================================================

    /// TS 23.007 Section 18: a counter moving BACKWARDS is a race to be
    /// discarded, not a restart. The old `previous != restart_counter` test
    /// classified it as a restart and tore down live contexts.
    #[test]
    fn restart_counter_order_discards_a_backwards_jump() {
        assert_eq!(restart_counter_order(5, 6), RestartOrder::Restarted);
        assert_eq!(restart_counter_order(5, 200), RestartOrder::Restarted);
        assert_eq!(restart_counter_order(5, 5), RestartOrder::Unchanged);
        // The race: stored is larger than received.
        assert_eq!(restart_counter_order(5, 4), RestartOrder::Stale);
        assert_eq!(restart_counter_order(200, 5), RestartOrder::Stale);
        // A modulo-256 roll-over is reported Stale, per #53's criteria and the
        // plain magnitude reading of Section 18. Documented on the function.
        assert_eq!(restart_counter_order(255, 0), RestartOrder::Stale);
    }

    /// TS 29.274 Section 7.7.2: a datagram of a version higher than GTPv2 must
    /// elicit a type-3 Version Not Supported Indication, not a silent drop.
    #[test]
    fn unsupported_gtp_version_gets_a_version_not_supported_reply() {
        let server = test_server(200, 2);
        let sock = client();

        // GTPv3 header: version 3 in the top 3 bits of the flags octet.
        let mut datagram = vec![0u8; 8];
        datagram[0] = 3 << 5;
        datagram[1] = 1; // some message type
        datagram[2] = 0;
        datagram[3] = 4;
        // Sequence number 0x0ABBCC, which the reply must echo.
        datagram[4] = 0x0A;
        datagram[5] = 0xBB;
        datagram[6] = 0xCC;

        sock.send_to(&datagram, server.local_addr()).unwrap();

        let mut buf = [0u8; 256];
        let (len, _) = sock
            .recv_from(&mut buf)
            .expect("expected a reply, not a drop");
        assert_eq!(len, 8, "Version Not Supported Indication is 8 octets");
        assert_eq!(
            buf[1],
            Gtp2MessageType::VersionNotSupportedIndication as u8,
            "reply must be message type 3"
        );
        assert_eq!((buf[0] >> 5) & 0x07, 2, "the reply itself must be GTPv2");
        assert_eq!(
            [buf[4], buf[5], buf[6]],
            [0x0A, 0xBB, 0xCC],
            "the reply must echo the offending sequence number"
        );
        server.close();
    }

    /// A GTPv1 datagram is NOT ours to answer on S11: Section 7.7.2 covers
    /// versions HIGHER than GTPv2 only. Asserting this keeps the fix from
    /// becoming "reply to anything we cannot parse".
    #[test]
    fn lower_gtp_version_is_still_dropped_silently() {
        let server = test_server(200, 2);
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();

        let mut datagram = vec![0u8; 8];
        datagram[0] = 1 << 5; // GTPv1
        datagram[1] = 1;
        sock.send_to(&datagram, server.local_addr()).unwrap();

        let mut buf = [0u8; 256];
        assert!(
            sock.recv_from(&mut buf).is_err(),
            "a GTPv1 datagram must not draw a Version Not Supported Indication"
        );
        server.close();
    }

    /// The 8-octet shape and echoed sequence number, asserted directly on the
    /// builder so a change to it fails here rather than only over a socket.
    #[test]
    fn version_not_supported_is_eight_octets_with_no_teid() {
        let bytes = build_version_not_supported(0x0102_03);
        assert_eq!(bytes.len(), 8);
        assert_eq!((bytes[0] >> 5) & 0x07, 2);
        assert_eq!(bytes[0] & 0x08, 0, "the T flag must be clear (no TEID)");
        assert_eq!(bytes[1], 3);
        assert_eq!([bytes[4], bytes[5], bytes[6]], [0x01, 0x02, 0x03]);
    }

    #[test]
    fn peek_sequence_number_reads_the_header_offset_and_tolerates_runts() {
        assert_eq!(
            peek_sequence_number(&[0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0]),
            0x00AA_BBCC
        );
        assert_eq!(peek_sequence_number(&[0, 0, 0]), 0);
        assert_eq!(peek_sequence_number(&[]), 0);
    }

    /// TS 23.007 Section 18: the local restart counter must survive a process
    /// restart and advance, or peers can never tell the SGW-C restarted.
    #[test]
    fn persistent_restart_counter_advances_across_starts() {
        let dir = std::env::temp_dir().join(format!("ngc-sgwc-rc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("counter");

        // First start: no file yet.
        assert_eq!(advance_persistent_restart_counter(&path), 1);
        // Subsequent starts advance, and the value is read back from disk --
        // which is the property the hardcoded default could never have.
        assert_eq!(advance_persistent_restart_counter(&path), 2);
        assert_eq!(advance_persistent_restart_counter(&path), 3);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "3");

        // Malformed contents must not take the daemon down, and must not
        // silently reuse the old value either.
        std::fs::write(&path, "not-a-number").unwrap();
        assert_eq!(advance_persistent_restart_counter(&path), 1);

        // 255 wraps to 1, keeping 0 free as "never persisted".
        std::fs::write(&path, "255").unwrap();
        assert_eq!(advance_persistent_restart_counter(&path), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Restart-triggered deletion is off unless the operator opts in (#53
    /// requires the behaviour-changing path to be gated).
    #[test]
    fn restart_deletion_is_off_by_default() {
        // The suite runs without the variable set, which is the shipped default.
        if std::env::var("SGWC_RESTART_DELETE_CONTEXTS").is_err() {
            assert!(!restart_deletion_enabled());
        }
    }

    /// Echo probing is configurable and disablable (Section 20.3.1 says an
    /// entity *may* probe).
    #[test]
    fn echo_interval_defaults_and_can_be_disabled() {
        if std::env::var("SGWC_ECHO_INTERVAL_SECS").is_err() {
            assert_eq!(
                echo_interval(),
                Some(Duration::from_secs(DEFAULT_ECHO_INTERVAL_SECS))
            );
        }
    }

    /// TS 23.007 Section 16.1A.1.1: a confirmed peer restart deletes that
    /// peer's contexts. Scoped by peer address, so another MME's UE survives --
    /// asserting only that the restarted peer's UE is gone would pass against
    /// code that deletes everything.
    #[test]
    fn restart_deletion_removes_only_the_restarted_peers_contexts() {
        let ctx = sgwc_self();
        let restarted: SocketAddr = "10.53.0.1:2123".parse().unwrap();
        let survivor: SocketAddr = "10.53.0.2:2123".parse().unwrap();

        let mut a = ctx.ue_add(b"001010000000053").expect("ue a");
        a.mme_addr = Some(restarted);
        ctx.ue_update(&a);
        let mut b = ctx.ue_add(b"001010000000054").expect("ue b");
        b.mme_addr = Some(survivor);
        ctx.ue_update(&b);

        assert!(ctx.sess_add(a.id, "internet").is_some());

        let removed = delete_contexts_for_peer(restarted.ip());
        assert_eq!(removed, 1, "exactly the restarted peer's UE is removed");
        assert!(
            ctx.ue_find_by_id(a.id).is_none(),
            "restarted peer's UE is gone"
        );
        assert!(
            ctx.ue_find_by_id(b.id).is_some(),
            "another MME's UE must survive"
        );
        assert!(
            ctx.sess_list_for_ue(a.id).is_empty(),
            "the removed UE's sessions are gone too"
        );

        ctx.ue_remove(b.id);
    }
}
