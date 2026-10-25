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
    /// Commands relayed MME -> PGW and awaiting their triggered message, keyed by
    /// (PGW peer, S5-C sequence number) (#591).
    command_relays: Mutex<HashMap<(SocketAddr, u32), CommandRelay>>,
    /// PGW-initiated Create/Update/Delete Bearer Requests relayed to the MME and
    /// awaiting its response, keyed by (MME peer, S11 sequence number) (#607).
    pgw_requests: Mutex<HashMap<(SocketAddr, u32), PgwRequestRelay>>,
    /// Change Notification Requests relayed MME -> PGW and awaiting the PGW's
    /// response, keyed by (PGW peer, S5-C sequence number) (#614). The value is
    /// where the MME expects the answer, as for a Command.
    change_notifications: Mutex<HashMap<(SocketAddr, u32), CommandRelay>>,
    running: AtomicBool,
}

/// A PGW-initiated bearer Request this SGW-C relayed to the MME (#607).
///
/// TS 23.401 §5.4.2.1 / §5.4.4.1 step 8: the SGW answers the PGW once the MME has
/// answered. The S11 leg runs under this node's sequence number, so the PGW's
/// number and S5-C TEID are kept here for the answer (TS 29.274 §7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PgwRequestRelay {
    /// The PGW that sent the Request.
    pgw_peer: SocketAddr,
    /// The Request's S5-C sequence number.
    pgw_seq: u32,
    /// The PGW's S5-C TEID, which the relayed answer is addressed to.
    pgw_teid: u32,
    /// The Request's message type.
    msg_type: u8,
    /// The SGW-C session the Request named.
    sess_id: u64,
}

/// A Command this SGW-C relayed from the MME to the PGW (#591).
///
/// TS 29.274 §7.6: the triggered message of a Command carries the Command's
/// sequence number. The SGW-C renumbers the Command into its own S5-C sequence
/// space, so the PGW's triggered message comes back under that number, and must
/// go on to the MME under the number the MME used, or the MME cannot tell that
/// its Command was answered and keeps retransmitting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandRelay {
    /// The MME that sent the Command.
    mme_peer: SocketAddr,
    /// The Command's sequence number on S11.
    mme_seq: u32,
    /// The MME's S11 control TEID, which the relayed answer is addressed to.
    mme_teid: u32,
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
            command_relays: Mutex::new(HashMap::new()),
            pgw_requests: Mutex::new(HashMap::new()),
            change_notifications: Mutex::new(HashMap::new()),
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
                            if let Ok(mut relays) = inner.command_relays.lock() {
                                relays.remove(&(xact.peer, xact.sequence_number));
                            }
                            // #607: an MME that never answers leaves no relay behind;
                            // the PGW's own T3/N3 runs out on its side.
                            if let Ok(mut relays) = inner.pgw_requests.lock() {
                                relays.remove(&(xact.peer, xact.sequence_number));
                            }
                            // #614: a PGW that never answers a relayed Change
                            // Notification leaves no relay behind; TS 29.274
                            // §7.3.15 lets the MME go without the answer.
                            if let Ok(mut relays) = inner.change_notifications.lock() {
                                relays.remove(&(xact.peer, xact.sequence_number));
                            }
                            // #607: a relayed Create Bearer Request's bearers are
                            // removed, and the PGW told.
                            crate::dedicated_bearer::mme_silent(xact.peer, xact.sequence_number);
                            // #1025: a PGW that never answers a relayed Delete
                            // Session does not keep the session alive here.
                            if xact.message_type == Gtp2MessageType::DeleteSessionRequest as u8 {
                                continue_delete_session_after_pgw(xact.sequence_number, None);
                            }
                            // #1152: a PGW that never answers a relayed Create
                            // Session leaves the MME answered and nothing behind.
                            if xact.message_type == Gtp2MessageType::CreateSessionRequest as u8 {
                                abandon_create_session_without_pgw(xact.peer, xact.sequence_number);
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

    /// Allocate a GTPv2-C sequence number for a Command relayed on S5/S8: most
    /// significant bit set (TS 29.274 §7.6, #727). The PGW's triggered Request
    /// echoes it, and the PGW's own initial Requests, MSB clear, cannot collide.
    pub fn alloc_command_sequence(&self) -> u32 {
        self.inner
            .xact
            .lock()
            .map(|mut x| x.alloc_command_sequence())
            .unwrap_or(nextgcore_gtp::v2::GTP2_COMMAND_SEQUENCE_FLAG | 1)
    }

    /// A sequence number for an initial S11 request to `peer` (#792 review): from
    /// [`Self::alloc_sequence`], skipping any number in use towards that peer by
    /// an outstanding transaction or by a Command relay whose triggered message
    /// will carry it. A legacy MME's Commands may have the MSB clear (TS 29.274
    /// §7.6 asks for it set), so their numbers share this node's initial space.
    pub fn alloc_sequence_to(&self, peer: SocketAddr) -> u32 {
        // Allocation and registration are not atomic, which is fine: S11
        // requests to a peer are originated from this node's single dispatch
        // context, so nothing takes the number in between.
        let mut seq = self.alloc_sequence();
        for _ in 0..64 {
            if !self.sequence_in_use(peer, seq) {
                return seq;
            }
            seq = self.alloc_sequence();
        }
        log::warn!(
            "S11 sequence space towards {peer} saturated: 64 consecutive numbers in use; \
             using {seq} anyway"
        );
        seq
    }

    /// Whether `seq` towards `peer` is taken (see [`Self::alloc_sequence_to`]).
    fn sequence_in_use(&self, peer: SocketAddr, seq: u32) -> bool {
        self.inner
            .xact
            .lock()
            .is_ok_and(|x| x.is_outstanding(peer, seq))
            || self.command_relay_in_flight(peer, seq)
    }

    /// Remember a Command relayed to `pgw_peer` at S5-C sequence `s5c_seq` (#591).
    fn record_command_relay(&self, pgw_peer: SocketAddr, s5c_seq: u32, relay: CommandRelay) {
        if let Ok(mut relays) = self.inner.command_relays.lock() {
            relays.insert((pgw_peer, s5c_seq), relay);
        }
    }

    /// Whether the MME's Command at (`mme_peer`, `mme_seq`) is already relayed and
    /// waiting for its triggered message (#606).
    fn command_relay_in_flight(&self, mme_peer: SocketAddr, mme_seq: u32) -> bool {
        self.inner.command_relays.lock().is_ok_and(|relays| {
            relays
                .values()
                .any(|r| r.mme_peer == mme_peer && r.mme_seq == mme_seq)
        })
    }

    /// Whether the MME's Change Notification at (`mme_peer`, `mme_seq`) is relayed
    /// and not yet answered (#614).
    fn change_notification_in_flight(&self, mme_peer: SocketAddr, mme_seq: u32) -> bool {
        self.inner.change_notifications.lock().is_ok_and(|relays| {
            relays
                .values()
                .any(|r| r.mme_peer == mme_peer && r.mme_seq == mme_seq)
        })
    }

    /// Forget a relayed Command, returning what was recorded for it.
    fn take_command_relay(&self, pgw_peer: SocketAddr, s5c_seq: u32) -> Option<CommandRelay> {
        self.inner
            .command_relays
            .lock()
            .ok()?
            .remove(&(pgw_peer, s5c_seq))
    }

    /// If `msg_type` from `pgw_peer` at `s5c_seq` is the triggered message of a
    /// Command this node relayed, close the Command's S5-C transaction (TS 29.274
    /// §7.6) and return where the MME expects the answer (#591).
    fn close_command_relay(
        &self,
        pgw_peer: SocketAddr,
        s5c_seq: u32,
        msg_type: u8,
    ) -> Option<CommandRelay> {
        let closed = self
            .inner
            .xact
            .lock()
            .ok()?
            .match_response_from(pgw_peer, s5c_seq, msg_type)?;
        if !nextgcore_gtp::v2::xact::is_command(closed.message_type) {
            return None;
        }
        self.take_command_relay(pgw_peer, s5c_seq)
    }

    /// Whether the PGW's bearer Request at (`pgw_peer`, `pgw_seq`) is relayed to
    /// the MME and not yet answered (#607).
    fn pgw_request_in_flight(&self, pgw_peer: SocketAddr, pgw_seq: u32, msg_type: u8) -> bool {
        self.inner.pgw_requests.lock().is_ok_and(|relays| {
            relays
                .values()
                .any(|r| r.pgw_peer == pgw_peer && r.pgw_seq == pgw_seq && r.msg_type == msg_type)
        })
    }

    /// Forget the PGW Request relayed to `mme_peer` at S11 `s11_seq` (#607).
    fn take_pgw_request(&self, mme_peer: SocketAddr, s11_seq: u32) -> Option<PgwRequestRelay> {
        self.inner
            .pgw_requests
            .lock()
            .ok()?
            .remove(&(mme_peer, s11_seq))
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
        // After the cache (#1121 review m1): a retransmission arriving in between is
        // answered from it, not processed again as a new request.
        if msg.header.message_type == Gtp2MessageType::CreateSessionResponse as u8 {
            end_create_session(peer, msg.header.sequence_number);
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
        let seq = self.alloc_sequence_to(peer);
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

        let seq = self.alloc_sequence_to(peer);
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

/// The S11 address to advertise and the GTP-U address to put in F-TEIDs.
///
/// S11: the bound address when specific; otherwise `SGWC_S11_ADVERTISE`, then the
/// config's `sgwc.gtpc.server` address (#482). GTP-U: `SGWC_GTPU_ADVERTISE`, else
/// the S11 address ONLY when it came from the bind or the environment — never from
/// the YAML control-plane address, which names the SGW-C, not the SGW-U.
fn advertised_addresses(
    bound: IpAddr,
    env_s11: Option<Ipv4Addr>,
    yaml_gtpc: Option<Ipv4Addr>,
    env_gtpu: Option<Ipv4Addr>,
) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
    let from_bind_or_env = match bound {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => env_s11,
    };
    let s11 = from_bind_or_env.or(yaml_gtpc);
    (s11, env_gtpu.or(from_bind_or_env))
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
    let env_ip = |name: &str| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<Ipv4Addr>().ok())
    };
    let (advertised, gtpu) = advertised_addresses(
        server.local_addr().ip(),
        env_ip("SGWC_S11_ADVERTISE"),
        ctx.gtpc_server_ip(),
        env_ip("SGWC_GTPU_ADVERTISE"),
    );
    ctx.set_s11_address(advertised);
    ctx.set_gtpu_address(gtpu);

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
            log::warn!(
                "Cannot read restart counter file {} (set SGWC_RESTART_COUNTER_FILE to a writable path): {e}; restarting the count at 1, so peers \
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
                log::warn!(
                    "Cannot create {} for the restart counter (set SGWC_RESTART_COUNTER_FILE to a writable path): {e}",
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
        Err(e) => log::warn!(
            "Cannot persist restart counter to {} (set SGWC_RESTART_COUNTER_FILE to a writable path): {e}; the next start will not advance it and \
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
            || t == T::DeleteBearerCommand as u8
            || t == T::ModifyBearerCommand as u8
            // #607: a PGW's bearer Request answered already gets the cached answer.
            || t == T::CreateBearerRequest as u8
            || t == T::UpdateBearerRequest as u8
            || t == T::DeleteBearerRequest as u8
            // #614: an answered Change Notification gets the cached answer.
            || t == T::ChangeNotificationRequest as u8
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
        // #606: TS 23.401 §5.4.4.2 step 2 / §5.4.2.2: the MME's Delete Bearer Command
        // and Modify Bearer Command go to the PGW like the Bearer Resource Command.
        t if t == T::DeleteBearerCommand as u8 => {
            dispatch_bearer_command(&server, &msg, peer, BearerCommand::DeleteBearer);
        }
        t if t == T::ModifyBearerCommand as u8 => {
            dispatch_bearer_command(&server, &msg, peer, BearerCommand::ModifyBearer);
        }
        // #614, TS 29.274 §7.3.14-15, TS 23.401 §5.9.2: location change reporting.
        t if t == T::ChangeNotificationRequest as u8 => {
            dispatch_change_notification_request(&server, &msg, peer);
        }
        t if t == T::ChangeNotificationResponse as u8 => {
            relay_change_notification_response(&server, &msg, peer);
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
        // #1025: the PGW's answer to a relayed Delete Session Request.
        t if t == T::DeleteSessionResponse as u8 => {
            // Only the answer that completes the transaction continues the
            // deletion: a late duplicate must not answer the MME twice.
            let completes = inner
                .xact
                .lock()
                .map(|mut xact| xact.match_response(seq, msg_type).is_some())
                .unwrap_or(false);
            if completes {
                dispatch_s5c_delete_session_response(&msg, peer);
            } else {
                log::debug!(
                    "S5/S8 Delete Session Response seq={seq} from {peer} completes no \
                     outstanding transaction (late duplicate?)"
                );
            }
        }
        t if t == T::CreateSessionResponse as u8 => {
            // TS 29.274 §7.6: the response completes the request, so its T3/N3
            // retransmission stops. This arm never completed the transaction, so
            // the S5-C Create Session Request kept being retransmitted every T3
            // after the PGW had answered (#482).
            if let Ok(mut xact) = inner.xact.lock() {
                if xact.match_response(seq, msg_type).is_none() {
                    log::debug!(
                        "S5/S8 Create Session Response seq={seq} from {peer} completes no \
                         outstanding transaction (late duplicate?)"
                    );
                }
            }
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
            // #591: the triggered Request of a Command this node relayed closes
            // that Command's S5-C transaction and goes to the MME under the
            // Command's S11 sequence number.
            // #607, TS 29.274 §7.6: a retransmission of a Request still being
            // relayed is discarded; the S11 transaction already retransmits it.
            if server.pgw_request_in_flight(peer, seq, msg_type)
                || (msg_type == T::CreateBearerRequest as u8
                    && crate::dedicated_bearer::in_flight(peer, seq))
            {
                log::info!(
                    "PGW {peer} retransmitted bearer Request type {msg_type} seq={seq}: still \
                     awaiting the MME's answer, discarded"
                );
                return;
            }
            let relay = server.close_command_relay(peer, seq, msg_type);
            // #607: a Create Bearer Request sets up the bearer here and at the SGW-U
            // first, and goes to the MME with this node's S1-U F-TEID.
            if msg_type == T::CreateBearerRequest as u8 {
                crate::dedicated_bearer::on_pgw_request(
                    &server,
                    &msg,
                    peer,
                    relay.map(|r| (r.mme_peer, r.mme_seq, r.mme_teid)),
                );
                return;
            }
            forward_pgw_bearer_procedure_to_mme(inner, &msg, peer, data, relay);
        }
        // #591: a Command the PGW refused. The Failure Indication is the Command's
        // triggered message on both legs, so it is relayed under the S11 sequence
        // number, not dropped as an unknown message.
        t if t == T::BearerResourceFailureIndication as u8
            || t == T::DeleteBearerFailureIndication as u8
            || t == T::ModifyBearerFailureIndication as u8 =>
        {
            match server.close_command_relay(peer, seq, msg_type) {
                Some(relay) => {
                    let mut relayed = msg.clone();
                    relayed.header.teid = Some(relay.mme_teid);
                    relayed.header.sequence_number = relay.mme_seq;
                    log::info!(
                        "Relaying Failure Indication type {msg_type} from PGW {peer} to MME {} \
                         (seq {seq} -> {})",
                        relay.mme_peer,
                        relay.mme_seq
                    );
                    if let Err(e) = server.send_response(relay.mme_peer, &relayed) {
                        log::error!("Failure Indication relay to {} failed: {e}", relay.mme_peer);
                    }
                }
                None => log::warn!(
                    "Failure Indication type {msg_type} seq={seq} from {peer} answers no Command \
                     this node relayed; dropped"
                ),
            }
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
    triggered_by: Option<CommandRelay>,
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
    let Some(mme_peer) = triggered_by.map(|r| r.mme_peer).or(ue.mme_addr) else {
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
    // A triggered Request keeps the MME's Command sequence number (TS 29.274
    // §7.6, #591); any other is a new transaction in this node's space.
    let seq = match triggered_by {
        Some(relay) => relay.mme_seq,
        None => server.alloc_sequence_to(mme_peer),
    };
    relayed.header.sequence_number = seq;

    log::info!(
        "Relaying PGW-initiated S5/S8 message type {msg_type} from {peer} to MME {mme_peer} \
         (S11 TEID {:#x}, seq {seq})",
        ue.mme_s11_teid
    );
    let _ = data;
    // #607: remembered before the send, so a fast answer finds it.
    if let Ok(mut relays) = inner.pgw_requests.lock() {
        relays.insert(
            (mme_peer, seq),
            PgwRequestRelay {
                pgw_peer: peer,
                pgw_seq: msg.header.sequence_number,
                pgw_teid: sess.pgw_s5c_teid,
                msg_type,
                sess_id: sess.id,
            },
        );
    }
    if let Err(e) = server.send_request(mme_peer, &relayed, sess.id) {
        log::error!("Relay of S5/S8 message type {msg_type} to MME {mme_peer} failed: {e}");
        server.take_pgw_request(mme_peer, seq);
    }
}

/// TS 23.007 §18 ordering of Restart counters, with the 8-bit roll-over taken into
/// account. Shared with mmed in `nextgcore-gtp` (#728); before that this node
/// compared plain magnitudes, so a peer's 255 -> 0 restart read as a stale value.
pub(crate) use nextgcore_gtp::v2::{restart_counter_order, RestartOrder};

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
    removed + delete_pdn_connections_for_pgw(peer_ip)
}

/// TS 23.007 §16.1A.2 (#1137): the peer is a PGW that restarted or failed. Every
/// PDN connection anchored at it goes: its SGW-U PFCP session, then the local
/// session (and the UE context, when it had no other). The MME is told with a
/// Delete Bearer Request for the PDN connection (its LBI), cause Reactivation
/// requested, so it deactivates it or detaches the UE with re-attach required
/// (TS 23.401 §5.10.3 / §5.3.8.3), as §16.1A.2's restoration describes; mmed
/// has no PGW Restart Notification (TS 29.274 §7.9.5). Returns the number of PDN
/// connections removed.
fn delete_pdn_connections_for_pgw(pgw_ip: std::net::IpAddr) -> usize {
    let ctx = sgwc_self();
    let sessions = ctx.sess_list_for_pgw_ip(pgw_ip);
    let server = s11_server();
    let mut removed = 0usize;
    for sess in sessions {
        let ue = ctx.ue_find_by_id(sess.sgwc_ue_id);
        let lbi = ctx.default_bearer_in_sess(sess.id).map(|b| b.ebi);
        if let (Some(server), Some(ue), Some(lbi)) = (server.as_ref(), ue.as_ref(), lbi) {
            if let Some(mme) = ue.mme_addr {
                let mut dbr = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
                    Gtp2MessageType::DeleteBearerRequest as u8,
                    ue.mme_s11_teid,
                    server.alloc_sequence_to(mme),
                ));
                dbr.add_ie(nextgcore_gtp::v2::ie::Gtp2EbiIe::new(lbi).to_ie(0));
                dbr.add_ie(
                    nextgcore_gtp::v2::ie::Gtp2CauseIe::new(gtp_cause::REACTIVATION_REQUESTED)
                        .to_ie(0),
                );
                if let Err(e) = server.send_request(mme, &dbr, 0) {
                    log::warn!("Delete Bearer Request to MME {mme} for LBI {lbi} not sent: {e}");
                }
            }
        }
        if let Err(e) = pfcp_path::send_session_deletion_request(
            &sess,
            0,
            None,
            pfcp_path::S11Continuation::None,
        ) {
            log::warn!(
                "SGW-U session deletion for sess {} failed during PGW {pgw_ip} cleanup: {e}",
                sess.id
            );
        }
        ctx.sess_remove(sess.id);
        if ue.is_some_and(|u| {
            ctx.ue_find_by_id(u.id)
                .is_some_and(|u| u.sess_ids.is_empty())
        }) {
            ctx.ue_remove(sess.sgwc_ue_id);
        }
        removed += 1;
    }
    if removed > 0 {
        log::warn!(
            "PGW {pgw_ip} restart/failure: deleted {removed} PDN connection(s) and their SGW-U \
             sessions; the MMEs are told (TS 23.007 §16.1A.2)"
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

/// Create Session Requests being processed, by (MME, sequence number), with when
/// each began. An entry ends when its Create Session Response is sent
/// ([`GtpcServer::send_response`]); one older than [`CREATE_SESSION_IN_FLIGHT_MAX`]
/// is dropped, so a request whose answer never went out does not block its
/// sequence number for good.
static CREATE_SESSIONS_IN_FLIGHT: Mutex<Option<HashMap<(SocketAddr, u32), Instant>>> =
    Mutex::new(None);

/// Longer than any Create Session can take: the PGW's and the SGW-U's T3 x N3.
const CREATE_SESSION_IN_FLIGHT_MAX: Duration = Duration::from_secs(60);

/// Record that the Create Session Request `seq` from `peer` is being processed.
/// `false` when it already is: the caller drops the retransmission.
fn begin_create_session(peer: SocketAddr, seq: u32) -> bool {
    let mut map = CREATE_SESSIONS_IN_FLIGHT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let map = map.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    map.retain(|_, began| now.duration_since(*began) < CREATE_SESSION_IN_FLIGHT_MAX);
    if map.contains_key(&(peer, seq)) {
        return false;
    }
    map.insert((peer, seq), now);
    true
}

/// The Create Session Request `seq` from `peer` has been answered.
fn end_create_session(peer: SocketAddr, seq: u32) {
    if let Some(map) = CREATE_SESSIONS_IN_FLIGHT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
    {
        map.remove(&(peer, seq));
    }
}

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

    // #1010 review: with no Sxa association the user plane cannot be provisioned
    // (TS 29.244 §6.2.6.1), so the request is refused here, before anything is
    // created and before the PGW is asked to anchor a session nobody would delete.
    if !pfcp_path::sgwu_associated() {
        log::warn!(
            "Create Session Request from {peer} refused: no PFCP association with the \
             SGW-U {} (No resources available)",
            pfcp_path::configured_sgwu_addr()
        );
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::CreateSessionResponse,
            parsed.sender_fteid.teid,
            seq,
            gtp_cause::NO_RESOURCES_AVAILABLE,
        );
        return;
    }

    // TS 29.274 §7.6: a retransmission of a request still being processed is not
    // processed again; its answer is the first one's, which the response cache then
    // repeats. Without this, a retransmission while the PGW or the SGW-U had not yet
    // answered created a second session and the MME got two different answers.
    if !begin_create_session(peer, seq) {
        log::debug!("Create Session Request seq={seq} from {peer} is already in progress");
        return;
    }

    let ctx = sgwc_self();
    let existing_ue = ctx.ue_find_by_imsi(&parsed.imsi);
    if let Some(ue) = existing_ue.as_ref() {
        resolve_create_session_collision(
            ue,
            parsed.bearer.ebi,
            msg.header.teid.unwrap_or(0),
            ctx.pgw_s5c_peer(),
        );
    }
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

    // The new session, by its default bearer's EBI: unique once the collision is
    // resolved, where the APN is not (two PDN connections may share one).
    let Some(mut sess) = ctx
        .bearer_find_by_ue_ebi(ue.id, parsed.bearer.ebi)
        .and_then(|b| ctx.sess_find_by_id(b.sess_id))
    else {
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
             allocates the PDN address (TS 23.401 §5.3.2.1) — but it is relayed on S5/S8 (#491)"
        );
    }
    sess.requested_paa = parsed.paa.clone();
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

/// S5-C sequence numbers of Create Session Requests abandoned after N3 (#1152),
/// with when, so a late accepted answer still gets its PDN connection deleted at
/// the PGW (#1190 review). Kept for [`ABANDONED_S5C_HOLD`].
static ABANDONED_S5C: std::sync::Mutex<Vec<(SocketAddr, u32, Instant)>> =
    std::sync::Mutex::new(Vec::new());

/// How long an abandoned Create's sequence number is remembered: far beyond any
/// PGW's own T3 x N3.
const ABANDONED_S5C_HOLD: Duration = Duration::from_secs(60);

fn remember_abandoned_s5c(pgw: SocketAddr, seq: u32) {
    let now = Instant::now();
    if let Ok(mut list) = ABANDONED_S5C.lock() {
        list.retain(|(_, _, at)| now.duration_since(*at) < ABANDONED_S5C_HOLD);
        list.push((pgw, seq, now));
    }
}

fn take_abandoned_s5c(pgw: SocketAddr, seq: u32) -> bool {
    let now = Instant::now();
    ABANDONED_S5C.lock().is_ok_and(|mut list| {
        list.retain(|(_, _, at)| now.duration_since(*at) < ABANDONED_S5C_HOLD);
        let found = list.iter().position(|(p, s, _)| *p == pgw && *s == seq);
        if let Some(i) = found {
            list.remove(i);
        }
        found.is_some()
    })
}

/// The S5/S8 Create Session Request at S5-C `seq` ran out its N3 (#1152, TS
/// 29.274 §7.6): the PGW is not answering. The MME is answered Remote peer not
/// responding (§8.4, cause 100) through the parked continuation, and the local
/// session goes, with its UE when it has no other. No SGW-U session exists yet:
/// the PFCP establishment follows the PGW's answer.
fn abandon_create_session_without_pgw(pgw: SocketAddr, seq: u32) {
    let Some((sess_id, continuation)) = take_pending_s5c(seq) else {
        return;
    };
    remember_abandoned_s5c(pgw, seq);
    log::error!(
        "S5/S8 Create Session Request seq={seq} unanswered after N3: the MME is answered \
         Remote peer not responding and session {sess_id} is removed"
    );
    crate::sxa_response::fail_with_cause(continuation, gtp_cause::REMOTE_PEER_NOT_RESPONDING);
    let ctx = sgwc_self();
    if let Some(sess) = ctx.sess_remove(sess_id) {
        if ctx
            .ue_find_by_id(sess.sgwc_ue_id)
            .is_some_and(|ue| ue.sess_ids.is_empty())
        {
            ctx.ue_remove(sess.sgwc_ue_id);
        }
    }
}

/// The EBI of the default bearer a Create Session Response's Bearer Context names
/// (5 when it names none: the first EBI an MME assigns).
fn created_lbi(msg: &Gtp2Message) -> u8 {
    msg.get_ie(Gtp2IeType::BearerContext as u8, 0)
        .and_then(|ie| Gtp2BearerContextIe::decode(&ie.value).ok())
        .and_then(|bc| bc.ebi().ok())
        .unwrap_or(5)
}

/// What the SGW-C takes from an S5/S8 Create Session Response.
#[derive(Debug, Clone)]
pub struct S5cCreateSessionAnswer {
    /// The Cause (instance 0); System failure when absent.
    pub cause: u8,
    /// The PGW's S5/S8-C F-TEID: "PGW S5/S8/S2a/S2b F-TEID ... for GTP based Control
    /// Plane interface", instance 1 of TS 29.274 Table 7.2.2-1. Instance 0 is the
    /// S11/S4 Sender F-TEID, which a PGW does not send.
    pub pgw_c: Option<Gtp2FTeidIe>,
    /// The PGW-U's S5/S8-U F-TEID: instance 2 of the Bearer Context created
    /// (Table 7.2.2-2).
    pub pgw_u: Option<Gtp2FTeidIe>,
    /// The PDN address the PGW allocated.
    pub paa: Option<Gtp2PaaIe>,
}

/// F-TEID interface type 32, S2b PGW GTP-C (TS 29.274 §8.22).
const S2B_PGW_GTP_C: u8 = 32;

/// Decode an S5/S8 Create Session Response at the IE instances TS 29.274 Tables
/// 7.2.2-1 / 7.2.2-2 give them. Public so the PGW-C's tests can read the response
/// it builds with this, the SGW-C's own decoder (#1113).
pub fn parse_s5c_create_session_response(msg: &Gtp2Message) -> S5cCreateSessionAnswer {
    S5cCreateSessionAnswer {
        cause: msg
            .get_ie(Gtp2IeType::Cause as u8, 0)
            .and_then(|ie| ie.value.first().copied())
            .unwrap_or(gtp_cause::SYSTEM_FAILURE),
        // A PGW-C from before #1113 sent its control F-TEID at instance 0, the Sender
        // F-TEID's slot. Its interface type still names it (S5/S8 or S2b PGW GTP-C), so
        // it is accepted there too: a rolling upgrade does not leak sessions behind an
        // old PGW-C.
        pgw_c: msg
            .get_ie(Gtp2IeType::FTeid as u8, 1)
            .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok())
            .or_else(|| {
                msg.get_ie(Gtp2IeType::FTeid as u8, 0)
                    .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok())
                    .filter(|ft| {
                        ft.interface_type == s11_build::f_teid_interface::S5_S8_PGW_GTP_C
                            || ft.interface_type == S2B_PGW_GTP_C
                    })
            }),
        pgw_u: msg
            .get_ie(Gtp2IeType::BearerContext as u8, 0)
            .and_then(|ie| Gtp2BearerContextIe::decode(&ie.value).ok())
            .and_then(|bc| bc.fteid(2).ok().flatten()),
        paa: msg
            .get_ie(Gtp2IeType::Paa as u8, 0)
            .and_then(|ie| Gtp2PaaIe::decode(&ie.value).ok()),
    }
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
        // #1190 review: the answer to a Create this SGW-C gave up on after N3
        // (#1152). The MME was refused and the session removed; if the PGW
        // accepted after all, it holds a PDN connection nobody else knows of,
        // so it is deleted at the S5/S8-C TEID the answer gives.
        if take_abandoned_s5c(peer, seq) {
            let answer = parse_s5c_create_session_response(msg);
            if crate::s5c_handler::session_created(answer.cause) {
                abandon_pgw_session_at(
                    peer,
                    answer.pgw_c.as_ref().map(|ft| ft.teid).unwrap_or(0),
                    created_lbi(msg),
                    "the PGW answered the Create after N3 ran out",
                );
            }
            return;
        }
        log::warn!(
            "S5/S8 Create Session Response from {peer} (seq={seq}) matches no pending request; \
             dropping rather than acting on a datagram this SGW-C did not ask for"
        );
        return;
    };

    let ctx = sgwc_self();
    let S5cCreateSessionAnswer {
        cause,
        pgw_c,
        pgw_u,
        paa,
    } = parse_s5c_create_session_response(msg);

    // ---- criterion 5: the SGW-C stops inventing the answer ----
    //
    // The PAA, the PGW's control address and the APN-Restriction come from the PGW's
    // response and are written onto the session, which is what #54's `sxa_response`
    // builds the S11 Create Session Response from. Before #52 the PAA was COPIED from
    // the MME's request (`parsed.paa` into `sess.paa`), so the UE was handed back the
    // address it had asked about with no node having allocated anything.
    if let Some(paa) = paa {
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
    if existing.is_none() {
        log::error!("S5/S8 Create Session Response for session {sess_id}, which is gone");
        crate::sxa_response::fail(
            continuation,
            "the session was removed while the PGW answered",
        );
        // #1032 review: a Delete Session that raced this Create removed the local
        // session before the PGW had a TEID to be told; if the PGW anchored it, it
        // is deleted there now.
        if crate::s5c_handler::session_created(cause) {
            abandon_pgw_session(
                pgw_c.as_ref().map(|ft| ft.teid).unwrap_or(0),
                created_lbi(msg),
                "its local session was deleted while the PGW answered the Create",
            );
        }
        return;
    }
    match crate::s5c_handler::handle_create_session_response(
        existing.as_ref(),
        0,
        &[],
        cause,
        pgw_c.as_ref().map(|ft| ft.teid).unwrap_or(0),
        pgw_u.as_ref().map(|ft| ft.teid).unwrap_or(0),
        crate::context::IpAddr {
            ipv4: pgw_u
                .as_ref()
                .and_then(|ft| ft.ipv4_addr)
                .map(std::net::Ipv4Addr::from),
            ipv6: pgw_u
                .as_ref()
                .and_then(|ft| ft.ipv6_addr)
                .map(std::net::Ipv6Addr::from),
        },
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
        // Removed between the check above and here: the PGW anchored it.
        abandon_pgw_session(
            pgw_c.as_ref().map(|ft| ft.teid).unwrap_or(0),
            created_lbi(msg),
            "its local session was deleted while the PGW answered the Create",
        );
        return;
    };

    // Now the SGW-U can be provisioned: it has a PGW-U endpoint to tunnel to.
    if let Err(e) =
        pfcp_path::send_session_establishment_request(&sess, seq as u64, None, 0, continuation)
    {
        // #1010 review: the refusal hands the procedure back, so the MME is answered
        // rather than left to its own timer. The association went down while the PGW
        // answered: the cause is the one an up-front refusal gives.
        log::error!(
            "PFCP Session Establishment not sent after the PGW answered ({e}); the Create \
             Session Request is refused"
        );
        crate::sxa_response::fail_with_cause(continuation, gtp_cause::NO_RESOURCES_AVAILABLE);
        // #1010 review: the PGW anchored a session the MME was just refused, and the
        // local one is abandoned with it.
        let lbi = ctx
            .default_bearer_in_sess(sess.id)
            .map(|b| b.ebi)
            .unwrap_or_else(|| created_lbi(msg));
        abandon_pgw_session(
            sess.pgw_s5c_teid,
            lbi,
            "no Sxa association to provision it when the PGW answered",
        );
        ctx.sess_remove(sess.id);
        // #1052 review: a UE whose first PDN connection this was has nothing left;
        // its context goes too, as it would have had the request been refused at
        // once.
        if ctx
            .ue_find_by_id(sess.sgwc_ue_id)
            .is_some_and(|ue| ue.sess_ids.is_empty())
        {
            ctx.ue_remove(sess.sgwc_ue_id);
        }
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

    // A retransmission of a request still waiting for the SGW-U is not
    // processed again: the answer goes out when the SGW-U has spoken (#838).
    if crate::sxa_response::modify_bearer_in_flight(peer, seq) {
        log::debug!("Modify Bearer Request seq={seq} from {peer} is already in progress");
        return;
    }
    if parsed.bearers.is_empty() {
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
    if !parsed.to_remove.is_empty() {
        log::info!(
            "Modify Bearer Request: EBIs {:?} are Bearer Contexts to be removed; the MME \
             removes them by a separate procedure (TS 29.274 Table 7.2.7-1 NOTE 3)",
            parsed.to_remove
        );
    }

    // #766, TS 29.274 Tables 7.2.7-1 / 7.2.8-1: every Bearer Context to be
    // modified is switched, and each is answered on its own. Before #766 only
    // the first was switched and every bearer of the session was reported
    // modified, so a dedicated bearer kept its downlink on the source eNB after
    // a handover while the MME believed it switched.
    let ctx = sgwc_self();
    let mut modified: Vec<(u64, u8)> = Vec::new();
    let mut marked_for_removal: Vec<(u8, u8)> = Vec::new();
    // Bearers to activate in the user plane, per session: one PFCP Session
    // Modification Request each.
    let mut per_session: std::collections::BTreeMap<u64, Vec<crate::sxa_response::SwitchedBearer>> =
        Default::default();
    for (ebi, fteid) in &parsed.bearers {
        let Some(enb_fteid) = fteid else {
            // No S1-U eNodeB F-TEID: nothing to switch for this bearer. It is
            // reported as held (modified), and its downlink tunnel is left as
            // it is rather than pointed at TEID 0.
            match ctx.bearer_find_by_ue_ebi(ue.id, *ebi) {
                Some(bearer) => modified.push((bearer.id, *ebi)),
                None => marked_for_removal.push((*ebi, gtp_cause::CONTEXT_NOT_FOUND)),
            }
            continue;
        };
        let enb_teid = enb_fteid.teid;
        // The endpoint before this request, restored if the SGW-U refuses.
        let previous = ctx
            .bearer_find_by_ue_ebi(ue.id, *ebi)
            .and_then(|b| ctx.dl_tunnel_in_bearer(b.id))
            .map(|t| (t.remote_teid, t.remote_ip.clone()));
        match s11_handler::handle_modify_bearer_request(Some(&ue), seq as u64, &[], *ebi, enb_teid)
        {
            HandlerResult::SendPfcp => {}
            HandlerResult::Error(cause) => {
                marked_for_removal.push((*ebi, cause));
                continue;
            }
            _ => {
                marked_for_removal.push((*ebi, gtp_cause::CONTEXT_NOT_FOUND));
                continue;
            }
        }
        let Some(bearer) = ctx.bearer_find_by_ue_ebi(ue.id, *ebi) else {
            marked_for_removal.push((*ebi, gtp_cause::CONTEXT_NOT_FOUND));
            continue;
        };
        if let Some(mut dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
            // #936, TS 29.274 §8.22: the F-TEID carries IPv4, IPv6 or both;
            // whichever families it carries are the eNB's.
            dl_tunnel.remote_ip.ipv4 = enb_fteid.ipv4_addr.map(Ipv4Addr::from);
            dl_tunnel.remote_ip.ipv6 = enb_fteid.ipv6_addr.map(std::net::Ipv6Addr::from);
            // Every Modify Bearer write is a new generation, even one that
            // writes the endpoint the tunnel already holds (#991 review): its
            // refusal must not undo a later writer that wrote the same value.
            dl_tunnel.generation = dl_tunnel.generation.wrapping_add(1);
            ctx.tunnel_update(&dl_tunnel);
        }
        // The generation this request's writes left (TEID by the handler, IP
        // above).
        let written = ctx
            .dl_tunnel_in_bearer(bearer.id)
            .map(|t| t.generation)
            .unwrap_or(0);
        per_session
            .entry(bearer.sess_id)
            .or_default()
            .push(crate::sxa_response::SwitchedBearer {
                bearer_id: bearer.id,
                ebi: *ebi,
                previous,
                written,
            });
        // Settled as modified only when the SGW-U confirms (#838).
    }

    // #838, TS 23.401 §5.5.1.1.2 steps 3-4 / TS 29.274 §7.2.2: the answer
    // waits for the SGW-U. One PFCP Session Modification per session gates it,
    // and a session the SGW-U refuses (or never answers) has its bearers
    // reported not modified. Before #838 the MME got Request accepted at once,
    // whatever the user plane did.
    let pending = crate::sxa_response::PendingModifyBearer {
        peer,
        seq,
        mme_teid: ue.mme_s11_teid,
        waiting: per_session.clone(),
        modified,
        marked_for_removal,
    };
    if per_session.is_empty() {
        crate::sxa_response::answer_modify_bearer(&pending, None);
        return;
    }
    let join = crate::sxa_response::park_modify_bearer(pending);
    for (sess_id, switched) in &per_session {
        let bearer_ids: Vec<u64> = switched.iter().map(|b| b.bearer_id).collect();
        let bearer_ids = &bearer_ids;
        let continuation = pfcp_path::S11Continuation::ModifyBearer {
            join,
            sess_id: *sess_id,
        };
        let sent = match ctx.sess_find_by_id(*sess_id) {
            Some(sess) => pfcp_path::send_bearer_to_modify_list_gating(
                &sess,
                bearer_ids,
                sxa_handler::pfcp_modify::DL_ONLY | sxa_handler::pfcp_modify::ACTIVATE,
                continuation,
            ),
            None => Err(format!("session {sess_id} is gone")),
        };
        if let Err(e) = sent {
            log::error!("PFCP bearer modification for session {sess_id} not sent: {e}");
            crate::sxa_response::modify_bearer_session_done(
                join,
                *sess_id,
                Some(gtp_cause::SYSTEM_FAILURE),
            );
        }
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
                    // #1025, TS 23.401 §5.3.8.2.1 steps 4-7 / §5.10.3: a detach or
                    // PDN disconnection (OI set, SI clear, TS 29.274 Table 7.2.9.1-1)
                    // is relayed to the PGW first; the SGW-U's session goes when the
                    // PGW has answered. A Serving GW relocation (SI) or a request
                    // without OI deletes the local resources only.
                    // The MME's retransmission while its request waits for the
                    // PGW is answered by that request, not relayed again.
                    if delete_relay_in_flight(peer, seq) {
                        log::debug!(
                            "Delete Session Request seq={seq} from {peer} is waiting for the \
                             PGW; retransmission absorbed"
                        );
                        return;
                    }
                    let forward = matches!(result, HandlerResult::ForwardToPgw)
                        && parsed.operation_indication;
                    if forward
                        && relay_delete_session_to_pgw(server, &sess, peer, seq, ue.mme_s11_teid)
                    {
                        return;
                    }
                    delete_session_user_plane(&sess, peer, seq, ue.mme_s11_teid);
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

/// Release the UE's S1-U bearers at the user plane (TS 23.401 §5.3.5 step 3): the
/// eNodeB endpoints are forgotten and the downlink FARs go to BUFF + NOCP, so the
/// next downlink packet is buffered and reported, and a Downlink Data Notification
/// pages the UE. The EPS bearer contexts are kept. Used by Release Access Bearers and
/// by an S1-U path failure (#994). Returns the PFCP modifications sent.
pub(crate) fn release_s1u_bearers(ue: &crate::context::SgwcUe, xact: u64) -> usize {
    let ctx = sgwc_self();
    let mut sent = 0;
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
        match pfcp_path::send_session_modification_request(
            &sess,
            xact,
            None,
            sxa_handler::pfcp_modify::DL_ONLY | sxa_handler::pfcp_modify::DEACTIVATE,
        ) {
            Ok(()) => sent += 1,
            Err(e) => log::error!("PFCP deactivation failed: {e}"),
        }
    }
    sent
}

/// Delete Session Requests relayed from the MME to the PGW over S5/S8 (#1025).
pub static S5_DELETES_RELAYED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// S5/S8 Delete Session Responses the PGW answered Request accepted (#1025).
pub static S5_DELETES_ACCEPTED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Prometheus lines for the S5/S8 Delete Session counters (#1052 review: the EPC
/// E2E detach stage reads these rather than log text).
pub(crate) fn render_s5_delete_metrics(out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "# HELP sgwc_s5_delete_session_relayed_total Delete Session Requests relayed to \
         the PGW\n# TYPE sgwc_s5_delete_session_relayed_total counter\n\
         sgwc_s5_delete_session_relayed_total {}",
        S5_DELETES_RELAYED_TOTAL.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "# HELP sgwc_s5_delete_session_accepted_total S5/S8 Delete Session Responses with \
         Request accepted\n# TYPE sgwc_s5_delete_session_accepted_total counter\n\
         sgwc_s5_delete_session_accepted_total {}",
        S5_DELETES_ACCEPTED_TOTAL.load(Ordering::Relaxed)
    );
}

/// A Delete Session Request sent to the PGW, waiting for its answer (#1025), by the
/// S5/S8 sequence number: the session, and the MME request to answer when it is a
/// relay. `mme` is `None` for a session the SGW-C abandons itself after the PGW
/// anchored it (#1032 / #1010 review): nobody waits, the PGW's session just goes.
#[derive(Debug, Clone, Copy)]
struct PendingS5cDelete {
    sess_id: u64,
    mme: Option<MmeDeleteRequest>,
}

/// The MME's Delete Session Request a relay answers.
#[derive(Debug, Clone, Copy)]
struct MmeDeleteRequest {
    peer: SocketAddr,
    seq: u32,
    teid: u32,
}

static PENDING_S5C_DELETE: Mutex<Option<HashMap<u32, PendingS5cDelete>>> = Mutex::new(None);

/// Whether the MME's Delete Session Request `mme_seq` from `mme` is relayed and
/// waiting for the PGW.
fn delete_relay_in_flight(mme: SocketAddr, mme_seq: u32) -> bool {
    PENDING_S5C_DELETE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|m| {
            m.values()
                .any(|p| p.mme.is_some_and(|r| r.peer == mme && r.seq == mme_seq))
        })
}

fn take_pending_s5c_delete(seq: u32) -> Option<PendingS5cDelete> {
    PENDING_S5C_DELETE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .and_then(|m| m.remove(&seq))
}

/// Relay the MME's Delete Session Request for `sess` to its PGW over S5/S8 (TS
/// 29.274 §7.2.9.1: "sent on the S11 interface by the MME to the SGW and on the
/// S5/S8 interface by the SGW to the PGW"), addressed to the PGW's S5/S8-C TEID
/// with the Linked EBI and the Operation Indication. The MME is answered when the
/// PGW has answered and the SGW-U has deleted the session
/// ([`dispatch_s5c_delete_session_response`]). Returns false when nothing could be
/// relayed (no PGW session or peer, a build or send failure): the caller then
/// deletes the local resources at once.
fn relay_delete_session_to_pgw(
    server: &GtpcServer,
    sess: &crate::context::SgwcSess,
    mme: SocketAddr,
    mme_seq: u32,
    mme_teid: u32,
) -> bool {
    if sess.pgw_s5c_teid == 0 {
        log::warn!(
            "Delete Session for session {}: no PGW S5/S8 session to relay to; deleting \
             locally",
            sess.id
        );
        return false;
    }
    let Some(pgw) = sgwc_self().pgw_s5c_peer() else {
        log::warn!(
            "Delete Session for session {}: no PGW S5/S8 peer configured; deleting locally",
            sess.id
        );
        return false;
    };
    let s5c_seq = server.alloc_sequence();
    let msg = match s11_build::build_s5c_delete_session_request(sess, s5c_seq) {
        Ok(m) => m,
        Err(e) => {
            log::error!(
                "S5/S8 Delete Session Request for session {} not built: {e}",
                sess.id
            );
            return false;
        }
    };
    // Recorded before the send: the answer can race it.
    PENDING_S5C_DELETE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(
            s5c_seq,
            PendingS5cDelete {
                sess_id: sess.id,
                mme: Some(MmeDeleteRequest {
                    peer: mme,
                    seq: mme_seq,
                    teid: mme_teid,
                }),
            },
        );
    if let Err(e) = server.send_request(pgw, &msg, sess.id) {
        log::error!("S5/S8 Delete Session Request to {pgw} failed: {e}; deleting locally");
        take_pending_s5c_delete(s5c_seq);
        return false;
    }
    S5_DELETES_RELAYED_TOTAL.fetch_add(1, Ordering::Relaxed);
    log::info!(
        "Delete Session Request for session {} relayed to the PGW {pgw} (seq={s5c_seq})",
        sess.id
    );
    true
}

/// The PGW answered (or never answered) the relayed Delete Session Request at
/// `s5c_seq` (#1025): the SGW-U's session is deleted and the MME answered, as for a
/// local deletion. A PGW refusal does not keep the session: the UE is detached or
/// the PDN connection released either way, and keeping it would only leak the
/// SGW-U's.
fn continue_delete_session_after_pgw(s5c_seq: u32, pgw_cause: Option<u8>) {
    let Some(pending) = take_pending_s5c_delete(s5c_seq) else {
        log::warn!(
            "S5/S8 Delete Session Response (seq={s5c_seq}) matches no relayed request; dropped"
        );
        return;
    };
    let Some(mme) = pending.mme else {
        // An abandoned session: nothing waits for the PGW's answer.
        match pgw_cause {
            Some(gtp_cause::REQUEST_ACCEPTED) => {
                log::info!("The PGW deleted the abandoned session (S5/S8 seq={s5c_seq})")
            }
            Some(c) => {
                log::warn!("The PGW answered the abandoned session's Delete Session with cause {c}")
            }
            None => log::error!(
                "The PGW never answered the abandoned session's Delete Session (N3): its \
                 session may remain"
            ),
        }
        return;
    };
    match pgw_cause {
        Some(gtp_cause::REQUEST_ACCEPTED) => {}
        Some(c) => log::warn!(
            "The PGW answered the Delete Session for session {} with cause {c}; deleting it \
             locally all the same",
            pending.sess_id
        ),
        None => log::warn!(
            "The PGW never answered the Delete Session for session {} (N3); deleting it \
             locally",
            pending.sess_id
        ),
    }
    let Some(sess) = sgwc_self().sess_find_by_id(pending.sess_id) else {
        // Already gone (a restart cleanup, say): what the MME asked for is done.
        crate::sxa_response::fail_with_cause(
            pfcp_path::S11Continuation::DeleteSession {
                peer: mme.peer,
                seq: mme.seq,
                teid: mme.teid,
                sess_id: pending.sess_id,
            },
            gtp_cause::REQUEST_ACCEPTED,
        );
        return;
    };
    delete_session_user_plane(&sess, mme.peer, mme.seq, mme.teid);
}

/// Delete at the PGW a session this SGW-C abandons after the PGW anchored it
/// (#1032 / #1010 review): a Create Session that could not be completed (no Sxa
/// association when the PGW answered), or one whose local session was deleted
/// while the PGW's answer was in flight. Without this the PGW keeps the session
/// and the UE's address. Nobody waits for the answer.
fn abandon_pgw_session(pgw_s5c_teid: u32, lbi: u8, why: &str) {
    let Some(pgw) = sgwc_self().pgw_s5c_peer() else {
        log::error!("Cannot delete the abandoned PGW session ({why}): no S5/S8 path");
        return;
    };
    abandon_pgw_session_at(pgw, pgw_s5c_teid, lbi, why);
}

/// [`abandon_pgw_session`] toward the PGW at `pgw`.
fn abandon_pgw_session_at(pgw: SocketAddr, pgw_s5c_teid: u32, lbi: u8, why: &str) {
    let Some(server) = s11_server() else {
        log::error!("Cannot delete the abandoned PGW session ({why}): no S5/S8 path");
        return;
    };
    if pgw_s5c_teid == 0 {
        return;
    }
    let seq = server.alloc_sequence();
    let msg = s11_build::build_s5c_delete_session_request_to(pgw_s5c_teid, lbi, seq);
    PENDING_S5C_DELETE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(
            seq,
            PendingS5cDelete {
                sess_id: 0,
                mme: None,
            },
        );
    match server.send_request(pgw, &msg, 0) {
        Ok(_) => log::warn!(
            "Delete Session Request to the PGW {pgw} for an abandoned session \
             (TEID {pgw_s5c_teid:#x}, LBI {lbi}): {why}"
        ),
        Err(e) => {
            take_pending_s5c_delete(seq);
            log::error!("Delete Session Request to {pgw} for an abandoned session failed: {e}");
        }
    }
}

/// Resolve a Create Session Request's collision with a PDN connection this SGW-C
/// still holds, before the new one is created (TS 29.274 §7.2.1).
///
/// The existing context is identified by the IMSI and the EPS Bearer ID the request
/// names. When the request has TEID 0 in its header, or names the default bearer of
/// an existing PDN connection, that PDN connection is deleted locally -- on the SGW-U
/// as well, since its user plane is this SGW's -- and, only when the new request
/// goes to a different PGW, at the old PGW too: a PGW that receives the new request
/// resolves the collision itself. A dedicated bearer named with a non-zero TEID is
/// deleted alone.
///
/// Before, the collision was found by IMSI and APN and only removed from the local
/// context: the old SGW-U PFCP session leaked, a second PDN connection to the same
/// APN was taken for a collision, and one with the same EBI to another APN was not.
fn resolve_create_session_collision(
    ue: &crate::context::SgwcUe,
    ebi: u8,
    header_teid: u32,
    new_pgw: Option<SocketAddr>,
) {
    let ctx = sgwc_self();
    let Some(bearer) = ctx.bearer_find_by_ue_ebi(ue.id, ebi) else {
        return;
    };
    let Some(old) = ctx.sess_find_by_id(bearer.sess_id) else {
        return;
    };
    let is_default = ctx
        .default_bearer_in_sess(old.id)
        .is_some_and(|b| b.id == bearer.id);
    if header_teid != 0 && !is_default {
        log::info!(
            "Create Session Request for IMSI[{}] EBI {ebi} collides with a dedicated bearer \
             of session {}: that bearer is deleted",
            ue.imsi_bcd,
            old.id
        );
        // Its PDRs and FARs go from the SGW-U too (#1121 review m6), while the
        // bearer's tunnels still name them.
        if old.sgwu_sxa_seid != 0 {
            if let Err(e) = pfcp_path::send_bearer_modification_request(
                bearer.id,
                0,
                None,
                crate::sxa_handler::pfcp_modify::REMOVE,
            ) {
                log::warn!(
                    "Bearer EBI {ebi} of session {}: its SGW-U rules were not removed: {e}",
                    old.id
                );
            }
        }
        ctx.bearer_remove(bearer.id);
        return;
    }
    log::info!(
        "Create Session Request for IMSI[{}] EBI {ebi} collides with session {} (APN {:?}): \
         the existing PDN connection is deleted first (TS 29.274 §7.2.1)",
        ue.imsi_bcd,
        old.id,
        old.apn()
    );
    release_replaced_session(&old, new_pgw);
    ctx.sess_remove(old.id);
}

/// Delete `old` on the SGW-U, and at its PGW when the new request goes elsewhere.
/// Nobody waits for either answer: the MME is answered for the NEW session.
fn release_replaced_session(old: &crate::context::SgwcSess, new_pgw: Option<SocketAddr>) {
    let ctx = sgwc_self();
    let lbi = ctx
        .default_bearer_in_sess(old.id)
        .map(|b| b.ebi)
        .unwrap_or(5);
    // A session whose Sxa establishment is still in flight has no SGW-U SEID yet; the
    // late response deletes what it created (`sxa_response`).
    if old.sgwu_sxa_seid != 0 {
        match pfcp_path::send_session_deletion_request(
            old,
            0,
            None,
            pfcp_path::S11Continuation::None,
        ) {
            Ok(()) => log::info!(
                "Replaced session {}: PFCP Session Deletion sent to the SGW-U (SEID {:#x})",
                old.id,
                old.sgwu_sxa_seid
            ),
            Err(e) => log::warn!(
                "Replaced session {}: PFCP Session Deletion not sent ({e}); the SGW-U \
                 keeps it",
                old.id
            ),
        }
    }
    let Some(old_pgw) = old.pgw_addr else {
        return;
    };
    let same_pgw = new_pgw.is_some_and(|p| p.ip() == std::net::IpAddr::V4(old_pgw));
    if old.pgw_s5c_teid != 0 && !same_pgw {
        let port = new_pgw.map(|p| p.port()).unwrap_or(2123);
        abandon_pgw_session_at(
            SocketAddr::new(std::net::IpAddr::V4(old_pgw), port),
            old.pgw_s5c_teid,
            lbi,
            "a new Create Session Request replaces it and goes to another PGW",
        );
    }
}

/// The PGW's answer to a relayed Delete Session Request (#1025).
fn dispatch_s5c_delete_session_response(msg: &Gtp2Message, peer: SocketAddr) {
    let cause = msg
        .get_ie(Gtp2IeType::Cause as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .unwrap_or(gtp_cause::SYSTEM_FAILURE);
    log::info!(
        "S5/S8 Delete Session Response from {peer} (seq={}) cause={cause}",
        msg.header.sequence_number
    );
    if cause == gtp_cause::REQUEST_ACCEPTED {
        S5_DELETES_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    continue_delete_session_after_pgw(msg.header.sequence_number, Some(cause));
}

/// Delete `sess` on the SGW-U and answer the MME's Delete Session Request when it
/// confirms (#54): the local context is removed only then.
fn delete_session_user_plane(
    sess: &crate::context::SgwcSess,
    mme: SocketAddr,
    mme_seq: u32,
    mme_teid: u32,
) {
    if let Err(e) = pfcp_path::send_session_deletion_request(
        sess,
        mme_seq as u64,
        None,
        pfcp_path::S11Continuation::DeleteSession {
            peer: mme,
            seq: mme_seq,
            teid: mme_teid,
            sess_id: sess.id,
        },
    ) {
        log::error!("PFCP session deletion failed: {e}");
        if let Some(server) = s11_server() {
            send_cause_response(
                &server,
                mme,
                Gtp2MessageType::DeleteSessionResponse,
                mme_teid,
                mme_seq,
                sxa_handler::gtp_cause_from_pfcp(sxa_handler::pfcp_cause::SYSTEM_FAILURE),
            );
        }
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

    match result {
        HandlerResult::SendPfcp => {
            release_s1u_bearers(&ue, seq as u64);
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

    // #48: the DECODED message, not `&[]`. The handler needs the request's Bearer
    // Contexts to know which bearers to allocate forwarding tunnels for and where the
    // target eNB wants the data sent; passing an empty slice is why it could only ever
    // return a bare accept.
    let result = if create {
        s11_handler::handle_create_indirect_data_forwarding_tunnel_request(
            Some(&ue),
            seq as u64,
            msg,
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
                // #48: the answer is now GATED on the SGW-U installing the forwarding
                // rules. It used to be built right here with a hard-coded
                // REQUEST_ACCEPTED and no F-TEIDs, before any PFCP message existed --
                // the same "accepted means fulfilled" violation #54 fixed for Create
                // Session, one procedure over.
                match install_indirect_forwarding(&ue, peer, seq) {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!(
                            "Failed to install indirect forwarding rules on the SGW-U: {e}"
                        );
                        send_cause_response(
                            server,
                            peer,
                            response_type,
                            ue.mme_s11_teid,
                            seq,
                            gtp_cause::SYSTEM_FAILURE,
                        );
                    }
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

/// Ask the SGW-U to install the forwarding rules the CIDFT handler just allocated, and
/// gate the MME's answer on its response (#48).
fn install_indirect_forwarding(
    ue: &crate::context::SgwcUe,
    peer: SocketAddr,
    seq: u32,
) -> Result<(), String> {
    let ctx = sgwc_self();
    // A UE may hold several sessions; the forwarding tunnels were allocated on the
    // bearers of whichever session held the requested EBIs, so each session with a
    // forwarding tunnel gets its own modification. In practice that is one.
    let mut sent = 0usize;
    for sess_id in &ue.sess_ids {
        let Some(sess) = ctx.sess_find_by_id(*sess_id) else {
            continue;
        };
        let bearer_ids: Vec<u64> = sess
            .bearer_ids
            .iter()
            .copied()
            .filter(|bid| has_forwarding_tunnel(&ctx, *bid))
            .collect();
        if bearer_ids.is_empty() {
            continue;
        }
        pfcp_path::send_indirect_forwarding_tunnels(
            &sess,
            &bearer_ids,
            pfcp_path::S11Continuation::IndirectForwarding {
                peer,
                seq,
                teid: ue.mme_s11_teid,
                sgwc_ue_id: ue.id,
            },
        )?;
        sent += 1;
    }
    if sent == 0 {
        return Err("no session carries a forwarding tunnel".to_string());
    }
    Ok(())
}

/// Whether a bearer carries at least one data-forwarding tunnel.
fn has_forwarding_tunnel(ctx: &crate::context::SgwcContext, bearer_id: u64) -> bool {
    let Some(bearer) = ctx.bearer_find_by_id(bearer_id) else {
        return false;
    };
    bearer.tunnel_ids.iter().any(|tid| {
        ctx.tunnel_find_by_id(*tid).is_some_and(|t| {
            matches!(
                t.interface_type,
                crate::context::gtp_interface::SGW_GTP_U_DL_DATA_FORWARDING
                    | crate::context::gtp_interface::SGW_GTP_U_UL_DATA_FORWARDING
            )
        })
    })
}

/// The two Commands #606 relays besides the Bearer Resource Command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerCommand {
    /// Delete Bearer Command (TS 29.274 §7.2.17.1).
    DeleteBearer,
    /// Modify Bearer Command (TS 29.274 §7.2.14.1).
    ModifyBearer,
}

impl BearerCommand {
    fn name(self) -> &'static str {
        match self {
            Self::DeleteBearer => "Delete Bearer Command",
            Self::ModifyBearer => "Modify Bearer Command",
        }
    }

    /// The Failure Indication that answers it when it cannot be carried.
    fn failure(self) -> Gtp2MessageType {
        match self {
            Self::DeleteBearer => Gtp2MessageType::DeleteBearerFailureIndication,
            Self::ModifyBearer => Gtp2MessageType::ModifyBearerFailureIndication,
        }
    }
}

/// Relay a Delete Bearer Command or a Modify Bearer Command from the MME to the PGW
/// (#606).
///
/// Both carry their bearers in Bearer Context IEs (Tables 7.2.17.1-1 and 7.2.14.1-1,
/// mandatory). The first bearer names the PDN connection: the dedicated bearers being
/// deleted, or the default bearer whose APN-AMBR is modified. The Command goes to that
/// connection's PGW S5/S8-C TEID, renumbered into this node's S5-C space and recorded as a
/// [`CommandRelay`] (#591), so the PGW's triggered Delete/Update Bearer Request or Failure
/// Indication reaches the MME under the MME's number. Anything that stops the relay is
/// answered with the Command's Failure Indication.
fn dispatch_bearer_command(
    server: &GtpcServer,
    msg: &Gtp2Message,
    peer: SocketAddr,
    command: BearerCommand,
) {
    let seq = msg.header.sequence_number;
    let ue = ue_from_header(msg);
    let teid = ue.as_ref().map(|u| u.mme_s11_teid).unwrap_or(0);
    let ebi = msg
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter(|ie| ie.instance == 0)
        .find_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok());
    let Some(ebi) = ebi else {
        send_reject(
            server,
            peer,
            command.failure(),
            teid,
            seq,
            IeError::missing_mandatory(Gtp2IeType::BearerContext),
        );
        return;
    };
    let ctx = sgwc_self();
    let sess = ue
        .as_ref()
        .and_then(|u| ctx.bearer_find_by_ue_ebi(u.id, ebi))
        .and_then(|b| ctx.sess_find_by_id(b.sess_id));
    let Some(sess) = sess else {
        log::warn!(
            "{} from {peer} (seq={seq}) names EBI {ebi}, which no PDN connection of this UE holds",
            command.name()
        );
        send_cause_response(
            server,
            peer,
            command.failure(),
            teid,
            seq,
            gtp_cause::CONTEXT_NOT_FOUND,
        );
        return;
    };
    let Some(pgw_peer) = ctx.pgw_s5c_peer() else {
        log::info!(
            "{} cannot be forwarded: no PGW S5/S8 peer configured",
            command.name()
        );
        send_cause_response(
            server,
            peer,
            command.failure(),
            teid,
            seq,
            gtp_cause::SERVICE_NOT_SUPPORTED,
        );
        return;
    };
    relay_command_to_pgw(
        server,
        msg,
        peer,
        pgw_peer,
        sess.pgw_s5c_teid,
        teid,
        command.name(),
        command.failure(),
    );
}

/// Send a Command on to the PGW (#591, #606): re-addressed to `pgw_teid`, renumbered
/// into this node's S5-C space, and recorded so its triggered message returns to the MME
/// under the MME's number. A retransmission of a Command already in flight is not
/// relayed again: the S5-C transaction retransmits on its own, and a second relay would
/// be a second Command at the PGW.
#[allow(clippy::too_many_arguments)]
fn relay_command_to_pgw(
    server: &GtpcServer,
    msg: &Gtp2Message,
    mme_peer: SocketAddr,
    pgw_peer: SocketAddr,
    pgw_teid: u32,
    mme_teid: u32,
    name: &str,
    failure: Gtp2MessageType,
) {
    let mme_seq = msg.header.sequence_number;
    if server.command_relay_in_flight(mme_peer, mme_seq) {
        log::debug!("{name} seq={mme_seq} from {mme_peer} is already relayed; not relayed again");
        return;
    }
    // #792 review: a legacy MME's Command with the MSB clear (TS 29.274 §7.6)
    // whose number this node is already using for its own outstanding request
    // to that MME: the triggered Request would have to carry the same number
    // and would replace that transaction. The Command is dropped unanswered
    // (#872 review): a Failure Indication would close it at the MME, and be
    // cached here against its retransmission. The MME's T3 retransmission,
    // once the own transaction has completed, is relayed normally.
    let own_in_use = !nextgcore_gtp::v2::is_command_sequence(mme_seq)
        && server
            .inner
            .xact
            .lock()
            .is_ok_and(|x| x.is_outstanding(mme_peer, mme_seq));
    if own_in_use {
        log::warn!(
            "{name} seq={mme_seq} from {mme_peer} has the MSB clear and clashes with an \
             outstanding S11 request of this node; dropped until the MME retransmits it"
        );
        return;
    }
    let mut relayed = msg.clone();
    relayed.header.teid = Some(pgw_teid);
    // A Command keeps the MSB set on every leg (TS 29.274 §7.6, #727).
    let s5c_seq = server.alloc_command_sequence();
    relayed.header.sequence_number = s5c_seq;
    log::info!("Relaying {name} to PGW {pgw_peer} (S5-C TEID {pgw_teid:#x}, seq {s5c_seq})");
    // Remembered before the send, so a triggered message that races the return of
    // `send_to` still finds it.
    server.record_command_relay(
        pgw_peer,
        s5c_seq,
        CommandRelay {
            mme_peer,
            mme_seq,
            mme_teid,
        },
    );
    if let Err(e) = server.send_request(pgw_peer, &relayed, 0) {
        server.take_command_relay(pgw_peer, s5c_seq);
        log::error!("{name} relay to {pgw_peer} failed: {e}");
        send_cause_response(
            server,
            mme_peer,
            failure,
            mme_teid,
            mme_seq,
            gtp_cause::REMOTE_PEER_NOT_RESPONDING,
        );
    }
}

/// The MME's Change Notification Request (#614, TS 29.274 §7.3.14, TS 23.401
/// §5.9.2): relayed to the PGW of the PDN connection its LBI names, on this
/// node's own S5-C sequence number and to the PGW's S5-C TEID. The PGW's answer
/// comes back to the MME under the MME's number
/// ([`relay_change_notification_response`]). A retransmission while the PGW
/// decides is discarded; one after the answer gets the cached answer.
///
/// No such PDN connection: answered here with "IMSI/IMEI not known" and the CS
/// bit 0 (§7.3.15: the SGW "shall return Change Notification Response with the
/// CS bit set to 0", so the MME stops reporting and deletes the PDN connection
/// locally). No PGW S5/S8 peer: "Service not supported", as for a Command.
fn dispatch_change_notification_request(server: &GtpcServer, msg: &Gtp2Message, peer: SocketAddr) {
    let seq = msg.header.sequence_number;
    let ue = ue_from_header(msg);
    let mme_teid = ue.as_ref().map(|u| u.mme_s11_teid).unwrap_or(0);
    if server.change_notification_in_flight(peer, seq) {
        log::debug!(
            "Change Notification Request seq={seq} from {peer} is already relayed; discarded"
        );
        return;
    }
    let ctx = sgwc_self();
    let lbi = msg
        .get_ie(Gtp2IeType::Ebi as u8, 0)
        .and_then(|ie| ie.value.first().map(|v| v & 0x0f));
    // #1161 review: no LBI and several PDN connections names none of them.
    // Relaying it to an arbitrary one would report location for the wrong
    // charging session; the LBI is conditional (Table 7.3.14-1: "shall be sent
    // by the MME/SGSN on S11/S4"), so it is answered Conditional IE missing.
    if let (None, Some(u)) = (lbi, ue.as_ref()) {
        if ctx.sess_list_for_ue(u.id).len() > 1 {
            log::warn!(
                "Change Notification Request from {peer} (seq={seq}) has no LBI and the UE \
                 has several PDN connections: answered Conditional IE missing"
            );
            let rsp = s11_build::build_error_response(
                Gtp2MessageType::ChangeNotificationResponse as u8,
                mme_teid,
                seq,
                gtp_cause::CONDITIONAL_IE_MISSING,
                Some(Gtp2IeType::Ebi as u8),
            );
            if let Err(e) = server.send_response(peer, &rsp) {
                log::error!("Change Notification Response to {peer} failed: {e}");
            }
            return;
        }
    }
    let sess = ue.as_ref().and_then(|u| match lbi {
        Some(lbi) => ctx
            .bearer_find_by_ue_ebi(u.id, lbi)
            .and_then(|b| ctx.sess_find_by_id(b.sess_id)),
        // An earlier-release MME without the LBI: unambiguous only with one PDN
        // connection.
        None => {
            let mut sessions = ctx.sess_list_for_ue(u.id);
            (sessions.len() == 1).then(|| sessions.remove(0))
        }
    });
    let Some(sess) = sess else {
        log::warn!(
            "Change Notification Request from {peer} (seq={seq}, LBI {lbi:?}) names no PDN \
             connection of this SGW: answered IMSI/IMEI not known, CS 0 (TS 29.274 §7.3.15)"
        );
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::ChangeNotificationResponse,
            mme_teid,
            seq,
            gtp_cause::IMSI_IMEI_NOT_KNOWN,
        );
        return;
    };
    let Some(pgw_peer) = ctx.pgw_s5c_peer() else {
        log::info!("Change Notification Request cannot be forwarded: no PGW S5/S8 peer");
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::ChangeNotificationResponse,
            mme_teid,
            seq,
            gtp_cause::SERVICE_NOT_SUPPORTED,
        );
        return;
    };
    let mut relayed = msg.clone();
    relayed.header.teid = Some(sess.pgw_s5c_teid);
    // The MME's Recovery is not this node's (TS 23.007 §18).
    relayed
        .ies
        .retain(|ie| ie.ie_type != Gtp2IeType::Recovery as u8);
    let s5c_seq = server.alloc_sequence_to(pgw_peer);
    relayed.header.sequence_number = s5c_seq;
    log::info!(
        "Relaying Change Notification Request from MME {peer} to PGW {pgw_peer} (S5-C TEID \
         {:#x}, seq {seq} -> {s5c_seq})",
        sess.pgw_s5c_teid
    );
    if let Ok(mut relays) = server.inner.change_notifications.lock() {
        relays.insert(
            (pgw_peer, s5c_seq),
            CommandRelay {
                mme_peer: peer,
                mme_seq: seq,
                mme_teid,
            },
        );
    }
    if let Err(e) = server.send_request(pgw_peer, &relayed, sess.id) {
        if let Ok(mut relays) = server.inner.change_notifications.lock() {
            relays.remove(&(pgw_peer, s5c_seq));
        }
        log::error!("Change Notification relay to {pgw_peer} failed: {e}");
    }
}

/// The PGW's Change Notification Response (#614): it completes this node's S5-C
/// transaction and goes to the MME under the MME's sequence number and to its
/// S11 TEID, cached so the MME's retransmission is answered the same way.
fn relay_change_notification_response(server: &GtpcServer, msg: &Gtp2Message, peer: SocketAddr) {
    let seq = msg.header.sequence_number;
    let completed = server.inner.xact.lock().ok().and_then(|mut x| {
        x.match_response_from(peer, seq, Gtp2MessageType::ChangeNotificationResponse as u8)
    });
    let relay = completed.and_then(|_| {
        server
            .inner
            .change_notifications
            .lock()
            .ok()?
            .remove(&(peer, seq))
    });
    let Some(relay) = relay else {
        log::warn!(
            "Change Notification Response seq={seq} from {peer} answers nothing this node \
             relayed; dropped"
        );
        return;
    };
    let mut relayed = msg.clone();
    relayed.header.teid = Some(relay.mme_teid);
    relayed.header.sequence_number = relay.mme_seq;
    relayed
        .ies
        .retain(|ie| ie.ie_type != Gtp2IeType::Recovery as u8);
    log::info!(
        "Relaying Change Notification Response from PGW {peer} to MME {} (seq {seq} -> {})",
        relay.mme_peer,
        relay.mme_seq
    );
    if let Err(e) = server.send_response(relay.mme_peer, &relayed) {
        log::error!(
            "Change Notification Response relay to {} failed: {e}",
            relay.mme_peer
        );
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
                    relay_command_to_pgw(
                        server,
                        msg,
                        peer,
                        pgw_peer,
                        pgw_teid,
                        teid,
                        "Bearer Resource Command",
                        Gtp2MessageType::BearerResourceFailureIndication,
                    );
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
    let server = GtpcServer {
        inner: inner.clone(),
    };
    // #607: the answer to a Create Bearer Request relayed by `dedicated_bearer`.
    if msg.header.message_type == Gtp2MessageType::CreateBearerResponse as u8
        && crate::dedicated_bearer::owns_answer(peer, seq)
    {
        crate::dedicated_bearer::on_mme_answer(&server, msg, peer);
        return;
    }
    let relay = server.take_pgw_request(peer, seq);

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
            // #641 stop-gap: a refusal (mmed answers "Service not supported")
            // creates nothing at the SGW-U, so it goes on to the PGW as it is,
            // and the PGW stops waiting (TS 23.401 §5.4.1 step 8). An accepted
            // answer is not relayed: it needs the dedicated bearer's tunnels at
            // the SGW-U and the S1-U / S5/S8-U F-TEIDs rewritten in each
            // direction (the Create Bearer half of #607, part of the #619/#641
            // decision).
            let accepted = matches!(
                parsed.cause,
                gtp_cause::REQUEST_ACCEPTED | gtp_cause::REQUEST_ACCEPTED_PARTIALLY
            );
            match relay {
                Some(relay) if !accepted => relay_bearer_response_to_pgw(&server, msg, peer, relay),
                Some(_) => log::error!(
                    "Create Bearer Response seq={seq} from {peer} accepts a dedicated bearer \
                     this SGW-C cannot provision at the SGW-U (#607); not relayed"
                ),
                None => {}
            }
        }
        t if t == T::UpdateBearerResponse as u8 => {
            s11_handler::handle_update_bearer_response(
                ue.as_ref(),
                seq as u64,
                raw,
                ebi,
                parsed.cause,
            );
            // TS 23.401 §5.4.2.1 step 8: nothing at the SGW-U changes (the bearer
            // keeps its tunnels); the answer goes to the PGW.
            if let Some(relay) = relay {
                relay_bearer_response_to_pgw(&server, msg, peer, relay);
            }
        }
        t if t == T::DeleteBearerResponse as u8 => {
            let Some(relay) = relay else {
                s11_handler::handle_delete_bearer_response(
                    ue.as_ref(),
                    seq as u64,
                    raw,
                    ebi,
                    parsed.cause,
                );
                return;
            };
            // TS 23.401 §5.4.4.1 step 8: the SGW deletes the bearer contexts the MME
            // released, then answers the PGW.
            delete_released_bearers(msg, parsed.cause, relay.sess_id);
            relay_bearer_response_to_pgw(&server, msg, peer, relay);
        }
        _ => {}
    }
}

/// Send the MME's answer to a relayed PGW bearer Request on to the PGW, under the
/// PGW's sequence number and addressed to its S5-C TEID (#607, TS 29.274 §7.6). It
/// is cached, so a retransmitted Request is answered the same way.
fn relay_bearer_response_to_pgw(
    server: &GtpcServer,
    msg: &Gtp2Message,
    mme_peer: SocketAddr,
    relay: PgwRequestRelay,
) {
    let mut relayed = msg.clone();
    relayed.header.teid = Some(relay.pgw_teid);
    relayed.header.sequence_number = relay.pgw_seq;
    // #1146 review, TS 23.007 §18: a Recovery IE names its sender's restart
    // counter. The MME's would reach the PGW as this SGW's, and a changed one
    // reads as an SGW restart there. It is conditional ("if contacting the peer
    // for the first time"), so it is dropped rather than replaced.
    relayed
        .ies
        .retain(|ie| ie.ie_type != Gtp2IeType::Recovery as u8);
    log::info!(
        "Relaying bearer response type {} from MME {mme_peer} to PGW {} (seq {} -> {}, S5-C \
         TEID {:#x})",
        msg.header.message_type,
        relay.pgw_peer,
        msg.header.sequence_number,
        relay.pgw_seq,
        relay.pgw_teid
    );
    if let Err(e) = server.send_response(relay.pgw_peer, &relayed) {
        log::error!(
            "Bearer response relay to PGW {} failed: {e}",
            relay.pgw_peer
        );
    }
}

/// What a Delete Bearer Response releases (TS 29.274 Table 7.2.10.2-1): the whole
/// PDN connection when it carries the Linked EBI, else each Bearer Context whose
/// own cause (or, without one, the message's) accepts the deletion.
#[derive(Debug, PartialEq, Eq)]
enum ReleasedBearers {
    PdnConnection(u8),
    Bearers(Vec<u8>),
}

fn released_bearers(msg: &Gtp2Message, cause: u8) -> ReleasedBearers {
    let deleted = |c: u8| {
        matches!(
            c,
            gtp_cause::REQUEST_ACCEPTED
                | gtp_cause::REQUEST_ACCEPTED_PARTIALLY
                // The MME has no such context: the bearer is gone there already.
                | gtp_cause::CONTEXT_NOT_FOUND
        )
    };
    let contexts: Vec<(u8, Option<u8>)> = msg
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter(|ie| ie.instance == 0)
        .filter_map(|ie| {
            let bc = Gtp2BearerContextIe::decode(&ie.value).ok()?;
            Some((bc.ebi().ok()?, bc.cause().ok().flatten().map(|c| c.cause)))
        })
        .collect();
    // #710: the answer to a Request naming the LBI carries the LBI and no
    // Bearer Context.
    let lbi = msg
        .get_ie(Gtp2IeType::Ebi as u8, 0)
        .and_then(|ie| ie.value.first().map(|v| v & 0x0f));
    if let (Some(lbi), true) = (lbi, contexts.is_empty()) {
        if deleted(cause) {
            return ReleasedBearers::PdnConnection(lbi);
        }
        return ReleasedBearers::Bearers(Vec::new());
    }
    if !deleted(cause) {
        return ReleasedBearers::Bearers(Vec::new());
    }
    ReleasedBearers::Bearers(
        contexts
            .into_iter()
            .filter(|(_, c)| deleted(c.unwrap_or(cause)))
            .map(|(ebi, _)| ebi)
            .collect(),
    )
}

/// Remove at the SGW-U and locally what an MME's Delete Bearer Response released
/// in session `sess_id` (#607, #710; TS 23.401 §5.4.4.1 step 8).
fn delete_released_bearers(msg: &Gtp2Message, cause: u8, sess_id: u64) {
    let ctx = sgwc_self();
    let Some(sess) = ctx.sess_find_by_id(sess_id) else {
        log::warn!("Delete Bearer Response for session {sess_id}, which is gone");
        return;
    };
    match released_bearers(msg, cause) {
        ReleasedBearers::PdnConnection(lbi) => {
            log::info!(
                "Delete Bearer Response: PDN connection of LBI {lbi} released; its SGW-U \
                 session is deleted, then the SGW-C's"
            );
            // The local session goes when the SGW-U confirms (`ReleasePdn`).
            if let Err(e) = pfcp_path::send_session_deletion_request(
                &sess,
                0,
                None,
                pfcp_path::S11Continuation::ReleasePdn { sess_id: sess.id },
            ) {
                log::warn!("SGW-U session deletion for sess {} not sent: {e}", sess.id);
            }
        }
        ReleasedBearers::Bearers(ebis) => {
            let bearers: Vec<SgwcBearer> = ebis
                .iter()
                .filter_map(|ebi| ctx.bearer_find_by_sess_ebi(sess.id, *ebi))
                .collect();
            if bearers.is_empty() {
                return;
            }
            let ids: Vec<u64> = bearers.iter().map(|b| b.id).collect();
            log::info!(
                "Delete Bearer Response: EBI(s) {ebis:?} released; their SGW-U rules are \
                 removed"
            );
            if let Err(e) = pfcp_path::send_bearer_to_modify_list(
                &sess,
                0,
                &ids,
                sxa_handler::pfcp_modify::REMOVE,
            ) {
                log::warn!("SGW-U rule removal for sess {} not sent: {e}", sess.id);
            }
            for id in ids {
                ctx.bearer_remove(id);
            }
        }
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

    /// Requires `&ProcessStateGuard` because it writes the process-global scalar
    /// address slots: a sibling that reads one back through production code sees
    /// whatever was written last (#368). The guard is taken by the test rather than
    /// here, so a test that also builds a stand-in SGW-U does not deadlock on itself.
    fn test_server(
        _ambient: &crate::pfcp_path::ProcessStateGuard,
        t3_ms: u64,
        n3: u32,
    ) -> GtpcServer {
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
        // PDN Type IPv4 and a dynamic-allocation PAA, as nextgcore's mmed sends them
        // since #479 (TS 29.274 Table 7.2.1-1, §8.14).
        msg.add_ie(Gtp2Ie::from_slice(Gtp2IeType::PdnType as u8, 0, &[1]));
        msg.add_ie(Gtp2PaaIe::ipv4([0; 4]).to_ie(0));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_bearer_qos(&Gtp2BearerQosIe::new(9, 1000, 2000, 0, 0));
        msg.add_bearer_context(0, &bc);
        msg
    }

    #[test]
    fn test_echo_request_response_with_recovery() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 1000, 1);
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
        /// Datagrams the stand-in received, as (msg_type, seid, body): one entry
        /// per datagram, PFCP T1 retransmissions included. To count or index
        /// requests use [`Self::received`] and [`Self::requests`] (#1160 review).
        seen: std::sync::Arc<std::sync::Mutex<Vec<(u8, Option<u64>, Vec<u8>)>>>,
        /// The stand-in's own socket, so a test can push a Session Report Request at the
        /// SGW-C the way a real SGW-U reports buffered downlink data.
        sock: std::sync::Arc<tokio::net::UdpSocket>,
        /// Where the SGW-C's Sxa socket is listening.
        sgwc_addr: SocketAddr,
        /// When non-zero, the cause every Session Deletion is answered with
        /// (#1146 review: a refused deletion).
        deletion_cause: std::sync::Arc<std::sync::atomic::AtomicU8>,
        /// (msg_type, PFCP sequence number) of each request received, so a T1
        /// retransmission (same number, TS 29.244 §7.6) is not counted twice
        /// (#1158).
        seqs: std::sync::Arc<std::sync::Mutex<Vec<(u8, u32)>>>,
    }

    impl StandInSgwu {
        /// The stand-in's Sxa address (the SGW-C's association peer).
        fn addr(&self) -> SocketAddr {
            self.sock.local_addr().unwrap()
        }

        /// How many distinct requests of `msg_type` the stand-in received: a PFCP
        /// T1 retransmission keeps its sequence number and is the same request
        /// (#1158: counting it made `received(54) == 1` flake under load).
        /// The bodies of the distinct requests of `msg_type`, in arrival order: a
        /// T1 retransmission (same sequence number) is not a second request
        /// (#1160 review). Indexes agree with [`Self::received`].
        fn requests(&self, msg_type: u8) -> Vec<Vec<u8>> {
            let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            let seqs = self.seqs.lock().unwrap_or_else(|e| e.into_inner());
            let mut taken: Vec<u32> = Vec::new();
            let mut bodies = Vec::new();
            for ((t, _, body), (_, seq)) in seen.iter().zip(seqs.iter()) {
                if *t == msg_type && !taken.contains(seq) {
                    taken.push(*seq);
                    bodies.push(body.clone());
                }
            }
            bodies
        }

        fn received(&self, msg_type: u8) -> usize {
            let mut numbers: Vec<u32> = self
                .seqs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(t, _)| *t == msg_type)
                .map(|(_, seq)| *seq)
                .collect();
            numbers.sort_unstable();
            numbers.dedup();
            numbers.len()
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

    async fn stand_in_sgwu(
        ambient: &crate::pfcp_path::ProcessStateGuard,
        cause: u8,
        delay: Duration,
    ) -> StandInSgwu {
        stand_in_sgwu_scripted(ambient, cause, delay, Vec::new(), 0x5555_0001).await
    }

    /// [`stand_in_sgwu`] whose Session Modification Responses follow `script`
    /// in order, one (cause, delay) each, then fall back to `cause` and `delay`.
    /// The stand-in answers one request at a time, so a request arriving while
    /// a delayed one is pending is answered after it.
    async fn stand_in_sgwu_scripted(
        _ambient: &crate::pfcp_path::ProcessStateGuard,
        cause: u8,
        delay: Duration,
        script: Vec<(u8, Duration)>,
        seid_base: u64,
    ) -> StandInSgwu {
        use nextgcore_pfcp::header::PfcpHeader as PHeader;
        use nextgcore_pfcp::message::{
            SessionDeletionResponse, SessionEstablishmentResponse, SessionModificationResponse,
        };
        use nextgcore_pfcp::types::{FSeid, NodeId, PfcpCause};

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

        let deletion_cause = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        let deletion_override = deletion_cause.clone();
        let seqs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let numbered = seqs.clone();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let handle = up.clone();
        let up = up.clone();
        tokio::spawn(async move {
            let up = handle;
            let mut script = std::collections::VecDeque::from(script);
            let mut established: u64 = 0;
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
                numbered
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((msg_type, header.sequence_number));

                // #1001: the SGW-C sends no session message before the association
                // (TS 29.244 §6.2.6.1), so the stand-in accepts the Association Setup.
                if msg_type == 5 {
                    let mut body = bytes::BytesMut::new();
                    nextgcore_pfcp::message::AssociationSetupResponse::new(
                        NodeId::new_ipv4([127, 0, 0, 9]),
                        PfcpCause::RequestAccepted,
                        1,
                    )
                    .encode(&mut body);
                    let mut out = bytes::BytesMut::new();
                    let mut h = PHeader::new(
                        nextgcore_pfcp::header::PfcpMessageType::AssociationSetupResponse,
                        header.sequence_number,
                    );
                    h.length = (4 + body.len()) as u16;
                    h.encode(&mut out);
                    out.extend_from_slice(&body);
                    let _ = up.send_to(&out, from).await;
                    continue;
                }
                let (cause, delay) = match msg_type {
                    52 => script.pop_front().unwrap_or((cause, delay)),
                    54 => match deletion_override.load(std::sync::atomic::Ordering::SeqCst) {
                        0 => (cause, delay),
                        refused => (refused, delay),
                    },
                    _ => (cause, delay),
                };
                let pfcp_cause = PfcpCause::from_wire(cause);
                let mut body = bytes::BytesMut::new();
                let resp_type = match msg_type {
                    50 => {
                        let mut rsp = SessionEstablishmentResponse::new(pfcp_cause);
                        rsp.node_id = Some(NodeId::new_ipv4([127, 0, 0, 9]));
                        // Conditional-mandatory on acceptance (TS 29.244 §7.5.3): the
                        // UP F-SEID the SGW-C stores and addresses the session by.
                        if pfcp_cause == PfcpCause::RequestAccepted {
                            // A distinct UP SEID per session, from `seid_base`, so a
                            // test can tell which one a deletion names.
                            rsp.up_f_seid =
                                Some(FSeid::new_ipv4(seid_base + established, [127, 0, 0, 9]));
                            established += 1;
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
                    // Heartbeat: not needed by these tests.
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
        node.associate(up_addr)
            .await
            .expect("the stand-in accepts the association");
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
            seen,
            sock: up,
            sgwc_addr: node.local_addr(),
            deletion_cause,
            seqs,
        }
    }

    /// #1158: a PFCP request sent twice under the same sequence number (a T1
    /// retransmission) counts once; another number counts again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_stand_in_counts_a_retransmission_once() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let cp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let deletion = |seq: u32| {
            let mut out = bytes::BytesMut::new();
            let mut h = nextgcore_pfcp::header::PfcpHeader::new_with_seid(
                nextgcore_pfcp::header::PfcpMessageType::SessionDeletionRequest,
                0x1158,
                seq,
            );
            h.length = 12;
            h.encode(&mut out);
            out
        };
        for seq in [0x1158, 0x1158, 0x1159] {
            cp.send_to(&deletion(seq), sgwu.addr()).await.unwrap();
        }
        for _ in 0..300 {
            if sgwu
                .seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, _, _)| *t == 54)
                .count()
                == 3
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            sgwu.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, _, _)| *t == 54)
                .count(),
            3,
            "all three datagrams arrived"
        );
        assert_eq!(sgwu.received(54), 2, "the retransmission counts once");
        assert_eq!(
            sgwu.requests(54).len(),
            2,
            "requests() agrees with received(), so it can be indexed by it"
        );
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
        /// Delete Session Requests received (#1025): (header TEID, Linked EBI, OI).
        deletes: std::sync::Arc<std::sync::Mutex<Vec<(Option<u32>, Option<u8>, bool)>>>,
        /// Whether a Delete Session Request is answered.
        answer_deletes: std::sync::Arc<std::sync::atomic::AtomicBool>,
        /// The cause a Delete Session Request is answered with.
        delete_cause: std::sync::Arc<std::sync::atomic::AtomicU8>,
        /// How long a Create Session Request waits for its answer, in ms.
        create_delay_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
        /// The cause a Create Session Request is answered with (#1190 review).
        create_cause: std::sync::Arc<std::sync::atomic::AtomicU8>,
        /// When set, the S5/S8-U F-TEID the Create Session Response gives is
        /// IPv6-only, at this address (#1156).
        s5u_ipv6: std::sync::Arc<std::sync::Mutex<Option<[u8; 16]>>>,
        /// Every message received, decoded (#607).
        msgs: std::sync::Arc<std::sync::Mutex<Vec<Gtp2Message>>>,
        /// The stand-in's socket, so a test can send PGW-initiated Requests (#607).
        sock: std::sync::Arc<tokio::net::UdpSocket>,
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
        let msgs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = msgs.clone();
        let deletes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let answer_deletes = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let delete_cause = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            gtp_cause::REQUEST_ACCEPTED,
        ));
        let create_delay_ms = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let create_cause = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            gtp_cause::REQUEST_ACCEPTED,
        ));
        let created_cause = create_cause.clone();
        let s5u_ipv6 = std::sync::Arc::new(std::sync::Mutex::new(None::<[u8; 16]>));
        let s5u_v6 = s5u_ipv6.clone();
        let creates_seen = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let (dels, answer_dels) = (deletes.clone(), answer_deletes.clone());
        let (del_cause, create_delay) = (delete_cause.clone(), create_delay_ms.clone());
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
                kept.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(msg.clone());
                if msg.header.message_type == Gtp2MessageType::DeleteSessionRequest as u8 {
                    let lbi = msg
                        .get_ie(Gtp2IeType::Ebi as u8, 0)
                        .and_then(|ie| nextgcore_gtp::v2::ie::Gtp2EbiIe::decode(&ie.value).ok())
                        .map(|e| e.ebi);
                    let oi = msg
                        .get_ie(Gtp2IeType::Indication as u8, 0)
                        .and_then(|ie| {
                            nextgcore_gtp::v2::ie::Gtp2IndicationIe::decode(&ie.value).ok()
                        })
                        .is_some_and(|i| i.oi);
                    dels.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((msg.header.teid, lbi, oi));
                    if answer_dels.load(std::sync::atomic::Ordering::SeqCst) {
                        let mut resp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                            Gtp2MessageType::DeleteSessionResponse as u8,
                            0,
                            msg.header.sequence_number,
                        ));
                        resp.add_ie(
                            nextgcore_gtp::v2::Gtp2CauseIe::new(
                                del_cause.load(std::sync::atomic::Ordering::SeqCst),
                            )
                            .to_ie(0),
                        );
                        let _ = handle.send_to(&resp.encode(), from).await;
                    }
                    continue;
                }
                if msg.header.message_type != Gtp2MessageType::CreateSessionRequest as u8 {
                    continue;
                }
                let delay = create_delay.load(std::sync::atomic::Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
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
                nextgcore_gtp::v2::Gtp2CauseIe::new(
                    created_cause.load(std::sync::atomic::Ordering::SeqCst),
                )
                .encode(&mut cause_buf, 0);
                let mut c = cause_buf.freeze();
                if let Ok(ie) = nextgcore_gtp::v2::ie::Gtp2Ie::decode(&mut c) {
                    resp.add_ie(ie);
                }
                // A distinct control TEID per Create, from 0x0BEE_F001: a test that
                // creates twice can tell the two sessions apart.
                let teid =
                    0x0BEE_F001 + creates_seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                resp.add_ie(Gtp2FTeidIe::new_ipv4(7, teid, [127, 0, 0, 1]).to_ie(1));
                resp.add_ie(Gtp2PaaIe::ipv4(PGW_ALLOCATED_ADDR).to_ie(0));
                let mut bc = Gtp2BearerContextIe::new();
                bc.set_ebi(5);
                let s5u = match *s5u_v6.lock().unwrap_or_else(|e| e.into_inner()) {
                    Some(v6) => Gtp2FTeidIe::new_ipv6(6, 0x0BEE_F002, v6),
                    None => Gtp2FTeidIe::new_ipv4(6, 0x0BEE_F002, [127, 0, 0, 1]),
                };
                bc.set_fteid(2, &s5u);
                resp.add_bearer_context(0, &bc);

                let _ = handle.send_to(&resp.encode(), from).await;
            }
        });
        StandInPgw {
            addr,
            seen,
            deletes,
            answer_deletes,
            delete_cause,
            create_delay_ms,
            create_cause,
            s5u_ipv6,
            msgs,
            sock,
        }
    }

    /// #1113: the PGW's control F-TEID is instance 1 of a Create Session Response
    /// (TS 29.274 Table 7.2.2-1). A PGW-C from before #1113 sent it at instance 0; its
    /// interface type (S5/S8 or S2b PGW GTP-C) still names it, so it is read there
    /// too, and only then -- an instance-0 F-TEID of any other type is not the PGW's.
    #[test]
    fn the_pgw_control_fteid_is_instance_1_or_a_pgw_typed_instance_0() {
        let csrsp = |fteids: &[(u8, u8, u32)]| {
            let mut msg = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                Gtp2MessageType::CreateSessionResponse as u8,
                1,
                1,
            ));
            for (instance, iface, teid) in fteids {
                msg.add_ie(Gtp2FTeidIe::new_ipv4(*iface, *teid, [10, 0, 0, 66]).to_ie(*instance));
            }
            parse_s5c_create_session_response(&msg)
                .pgw_c
                .map(|ft| ft.teid)
        };
        assert_eq!(csrsp(&[(1, 7, 0x11)]), Some(0x11));
        assert_eq!(csrsp(&[(0, 7, 0x10)]), Some(0x10), "a pre-#1113 PGW-C");
        assert_eq!(csrsp(&[(0, 32, 0x20)]), Some(0x20), "S2b PGW GTP-C");
        assert_eq!(
            csrsp(&[(0, 11, 0x0b)]),
            None,
            "an S11 SGW F-TEID is not the PGW's"
        );
        assert_eq!(
            csrsp(&[(0, 7, 0x10), (1, 7, 0x11)]),
            Some(0x11),
            "instance 1 wins"
        );
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_millis(0),
        )
        .await;
        // Set AFTER `stand_in_sgwu`: that call takes the guard over this process's
        // ambient SGW-C configuration, and setting the PGW peer before it is exactly the
        // unlocked-writer race #308 was about.
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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

    /// [`csr`] for `ebi` and `apn` (one label), with `teid` in the header.
    fn csr_for(seq: u32, imsi: &[u8], ebi: u8, apn: &str, teid: u32) -> Gtp2Message {
        let mut msg = csr(seq, imsi);
        msg.header.teid = Some(teid);
        let mut label = vec![apn.len() as u8];
        label.extend(apn.as_bytes());
        for ie in msg.ies.iter_mut() {
            if ie.ie_type == Gtp2IeType::Apn as u8 {
                ie.value = Bytes::from(label.clone());
            }
        }
        msg.ies
            .retain(|ie| ie.ie_type != Gtp2IeType::BearerContext as u8);
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(ebi);
        bc.set_bearer_qos(&Gtp2BearerQosIe::new(9, 1000, 2000, 0, 0));
        msg.add_bearer_context(0, &bc);
        msg
    }

    /// A stand-in SGW-U whose UP SEIDs are `tag << 32` + 1, 2, ..., so a test can
    /// tell its own sessions' deletions from a late one an earlier test's sessions
    /// sent to the process-wide SGW-U address (#1121 review m5).
    async fn own_stand_in_sgwu(
        ambient: &crate::pfcp_path::ProcessStateGuard,
        tag: u64,
        delay: Duration,
    ) -> StandInSgwu {
        stand_in_sgwu_scripted(
            ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            delay,
            Vec::new(),
            (tag << 32) | 1,
        )
        .await
    }

    /// The SEIDs of the Session Deletion Requests the stand-in SGW-U received for
    /// sessions it tagged `tag` ([`own_stand_in_sgwu`]).
    fn sgwu_deletions(sgwu: &StandInSgwu, tag: u64) -> Vec<u64> {
        sgwu.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(t, _, _)| *t == 54)
            .filter_map(|(_, seid, _)| *seid)
            .filter(|seid| seid >> 32 == tag)
            .collect()
    }

    /// Wait (bounded) for `done`, polling: the deletions are fire-and-forget.
    async fn eventually(done: impl Fn() -> bool) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !done() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        done()
    }

    fn accepted(r: &Gtp2Message) -> bool {
        r.get_ie(Gtp2IeType::Cause as u8, 0)
            .and_then(|ie| ie.value.first().copied())
            == Some(gtp_cause::REQUEST_ACCEPTED)
    }

    /// TS 29.274 §7.2.1: a Create Session Request naming the EBI of a PDN connection
    /// the SGW-C still holds -- an MME re-attaching a UE whose old session it never
    /// deleted, as after a PGW restart -- collides with it, and the existing PDN
    /// connection is deleted first: on the SGW-U, since its user plane is this SGW's,
    /// but NOT at the PGW the new request goes to, which resolves the collision
    /// itself. The new session is kept.
    ///
    /// REVERT-VERIFIED: with only the local removal, the SGW-U deletes nothing
    /// (sgwu_pfcp_sessions 2 against upf_pfcp_sessions 1 on devtest1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_colliding_create_deletes_the_old_pdn_connection_on_the_sgwu() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = own_stand_in_sgwu(&ambient, 0x77, Duration::from_millis(0)).await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x77];

        sock.send_to(&csr(0x7701, &imsi).encode(), server.local_addr())
            .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("first")));
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("the UE");
        let old = ctx
            .sess_find_by_apn(ue.id, "internet")
            .expect("the session");
        assert_ne!(old.sgwu_sxa_seid, 0);

        // The same IMSI and EBI again, with no Delete Session in between.
        sock.send_to(&csr(0x7702, &imsi).encode(), server.local_addr())
            .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("second")));

        assert!(
            eventually(|| sgwu_deletions(&sgwu, 0x77) == vec![old.sgwu_sxa_seid]).await,
            "the OLD SGW-U session is deleted, and only it: {:?}",
            sgwu_deletions(&sgwu, 0x77)
        );
        let sessions = ctx.sess_list_for_ue(ue.id);
        assert_eq!(sessions.len(), 1, "one PDN connection");
        assert_ne!(sessions[0].id, old.id, "the new one");
        assert_ne!(sessions[0].sgwu_sxa_seid, old.sgwu_sxa_seid);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            pgw.deletes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "the same PGW resolves the collision itself: no Delete Session"
        );
        ctx.ue_remove(ue.id);
    }

    /// TS 29.274 §7.2.1: when the colliding request goes to another PGW, the old PGW
    /// is told, at its own address and for its own session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_colliding_create_toward_another_pgw_deletes_the_old_pgw_session() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = own_stand_in_sgwu(&ambient, 0x78, Duration::from_millis(0)).await;
        let old_pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x78];

        sock.send_to(&csr(0x7801, &imsi).encode(), server.local_addr())
            .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("first")));

        // The PGW the SGW-C selects is another one now (the stand-ins share 127.0.0.1,
        // so the old one's address is moved to tell them apart).
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("the UE");
        let mut old = ctx
            .sess_find_by_apn(ue.id, "internet")
            .expect("the session");
        old.pgw_addr = Some(Ipv4Addr::new(127, 0, 0, 2));
        ctx.sess_update(&old);
        let new_pgw = with_stand_in_pgw().await;
        // The old PGW listens at its own address on the S5/S8 port in use (2123 in a
        // deployment; the new stand-in's here).
        let relocated = tokio::net::UdpSocket::bind(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            new_pgw.addr.port(),
        ))
        .await
        .expect("bind the old PGW's address");
        let _ = old_pgw;

        sock.send_to(&csr(0x7802, &imsi).encode(), server.local_addr())
            .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("second")));

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), relocated.recv_from(&mut buf))
            .await
            .expect("the old PGW is sent a Delete Session Request")
            .unwrap();
        let mut bytes = Bytes::copy_from_slice(&buf[..len]);
        let dsr = Gtp2Message::decode(&mut bytes).unwrap();
        assert_eq!(
            dsr.header.message_type,
            Gtp2MessageType::DeleteSessionRequest as u8
        );
        assert_eq!(dsr.header.teid, Some(old.pgw_s5c_teid));
        ctx.ue_remove(ue.id);
    }

    /// Two PDN connections to the same APN are legal: a Create Session Request with a
    /// new EBI does not collide with the first, whatever its APN. And one with the same
    /// EBI to ANOTHER APN does collide.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_collision_is_by_ebi_not_by_apn() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = own_stand_in_sgwu(&ambient, 0x79, Duration::from_millis(0)).await;
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x79];

        sock.send_to(&csr(0x7901, &imsi).encode(), server.local_addr())
            .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("PDN 1")));
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("the UE");
        // A second PDN connection to the same APN, EBI 6.
        sock.send_to(
            &csr_for(0x7902, &imsi, 6, "internet", ue.sgw_s11_teid).encode(),
            server.local_addr(),
        )
        .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("PDN 2")));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            sgwu_deletions(&sgwu, 0x79).is_empty(),
            "no collision: nothing deleted"
        );
        assert_eq!(ctx.sess_list_for_ue(ue.id).len(), 2);

        // EBI 6 again, to another APN: it collides with PDN 2, and only PDN 2 goes.
        let pdn2 = ctx
            .bearer_find_by_ue_ebi(ue.id, 6)
            .and_then(|b| ctx.sess_find_by_id(b.sess_id))
            .expect("PDN 2");
        sock.send_to(
            &csr_for(0x7903, &imsi, 6, "ims", ue.sgw_s11_teid).encode(),
            server.local_addr(),
        )
        .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("PDN 3")));
        assert!(eventually(|| sgwu_deletions(&sgwu, 0x79) == vec![pdn2.sgwu_sxa_seid]).await);
        let apns: Vec<String> = ctx
            .sess_list_for_ue(ue.id)
            .iter()
            .filter_map(|s| s.apn().map(str::to_string))
            .collect();
        assert_eq!(apns.len(), 2, "{apns:?}");
        assert!(apns.contains(&"internet".to_string()) && apns.contains(&"ims".to_string()));
        ctx.ue_remove(ue.id);
    }

    /// TS 29.274 §7.2.1: a non-zero-TEID request naming a DEDICATED bearer's EBI
    /// deletes only that bearer; its PDN connection stays.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_collision_with_a_dedicated_bearer_deletes_only_that_bearer() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = own_stand_in_sgwu(&ambient, 0x7a, Duration::from_millis(0)).await;
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x7a];

        sock.send_to(&csr(0x7a01, &imsi).encode(), server.local_addr())
            .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("PDN 1")));
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("the UE");
        let pdn1 = ctx.sess_find_by_apn(ue.id, "internet").expect("PDN 1");
        let dedicated = ctx.bearer_add(pdn1.id).unwrap();
        let mut dedicated = ctx.bearer_find_by_id(dedicated.id).unwrap();
        dedicated.ebi = 7;
        ctx.bearer_update(&dedicated);
        // Its rules on the SGW-U, as its establishment would have installed them.
        for (i, tunnel_id) in dedicated.tunnel_ids.iter().enumerate() {
            let mut tunnel = ctx.tunnel_find_by_id(*tunnel_id).unwrap();
            tunnel.pdr_id = Some(0x70 + i as u16);
            tunnel.far_id = Some(0x70 + i as u32);
            ctx.tunnel_update(&tunnel);
        }

        sock.send_to(
            &csr_for(0x7a02, &imsi, 7, "ims", ue.sgw_s11_teid).encode(),
            server.local_addr(),
        )
        .unwrap();
        assert!(accepted(&recv_s11(&sock).await.expect("PDN 2")));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(ctx.sess_find_by_id(pdn1.id).is_some(), "PDN 1 stays");
        assert!(sgwu_deletions(&sgwu, 0x7a).is_empty());
        assert!(
            ctx.bearer_find_by_sess_ebi(pdn1.id, 7).is_none(),
            "its bearer 7 went"
        );
        // ...from the SGW-U too (#1121 review m6, m7): one Session Modification on
        // PDN 1's session removing exactly the bearer's rules -- both tunnels' PDRs
        // and FARs -- and creating or updating nothing.
        let modifications: Vec<nextgcore_pfcp::message::SessionModificationRequest> = sgwu
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(t, seid, _)| *t == 52 && *seid == Some(pdn1.sgwu_sxa_seid))
            .map(|(_, _, body)| {
                nextgcore_pfcp::message::SessionModificationRequest::decode(
                    &mut Bytes::copy_from_slice(body),
                )
                .expect("a Session Modification Request")
            })
            .collect();
        assert_eq!(modifications.len(), 1, "one Session Modification");
        let m = &modifications[0];
        let mut pdrs: Vec<u16> = m.remove_pdrs.iter().map(|r| r.pdr_id).collect();
        let mut fars: Vec<u32> = m.remove_fars.iter().map(|r| r.far_id).collect();
        pdrs.sort_unstable();
        fars.sort_unstable();
        assert_eq!(pdrs, vec![0x70, 0x71], "both tunnels' PDRs");
        assert_eq!(fars, vec![0x70, 0x71], "both tunnels' FARs");
        assert!(
            m.create_pdrs.is_empty()
                && m.create_fars.is_empty()
                && m.update_pdrs.is_empty()
                && m.update_fars.is_empty(),
            "removal only"
        );
        assert_eq!(ctx.sess_list_for_ue(ue.id).len(), 2);
        ctx.ue_remove(ue.id);
    }

    /// TS 29.274 §7.6: a Create Session Request retransmitted while the first is
    /// still being processed is not processed again. The PGW sees one Create, and the
    /// MME one answer (then the cached one, for later retransmissions).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_session_retransmitted_in_flight_is_not_processed_again() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = own_stand_in_sgwu(&ambient, 0x7b, Duration::from_millis(0)).await;
        let pgw = with_stand_in_pgw().await;
        pgw.create_delay_ms
            .store(800, std::sync::atomic::Ordering::SeqCst);
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x7b];
        let request = csr(0x7b01, &imsi).encode();

        sock.send_to(&request, server.local_addr()).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        sock.send_to(&request, server.local_addr()).unwrap();
        let first = recv_s11(&sock).await.expect("the answer");
        assert!(accepted(&first));
        // A later retransmission gets the cached answer, the same one.
        sock.send_to(&request, server.local_addr()).unwrap();
        let again = recv_s11(&sock).await.expect("the cached answer");
        assert_eq!(again.encode(), first.encode());
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        assert!(
            recv_s11(&sock).await.is_none(),
            "no second, different answer"
        );
        let creates = pgw
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|t| **t == Gtp2MessageType::CreateSessionRequest as u8)
            .count();
        assert_eq!(creates, 1, "the PGW is asked once");
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).expect("the UE");
        assert_eq!(ctx.sess_list_for_ue(ue.id).len(), 1);
        ctx.ue_remove(ue.id);
    }

    /// A session replaced while the SGW-U was still establishing it has no SGW-U SEID
    /// to delete; the late Establishment Response, finding no session, deletes the
    /// SGW-U session it created instead of leaving it to leak.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_removed_mid_establishment_is_deleted_on_the_sgwu() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = own_stand_in_sgwu(&ambient, 0x7c, Duration::from_millis(600)).await;
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x7c];

        sock.send_to(&csr(0x7c01, &imsi).encode(), server.local_addr())
            .unwrap();
        // The PGW has answered and the establishment is waiting at the SGW-U.
        let ctx = sgwc_self();
        assert!(
            eventually(|| {
                sgwu.seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|(t, _, _)| *t == 50)
            })
            .await
        );
        let ue = ctx.ue_find_by_imsi(&imsi).expect("the UE");
        let first = ctx
            .sess_find_by_apn(ue.id, "internet")
            .expect("the session");
        assert_eq!(first.sgwu_sxa_seid, 0, "not established yet");
        sock.send_to(&csr(0x7c02, &imsi).encode(), server.local_addr())
            .unwrap();

        // Both answers come back; the first session's late response deletes the
        // SGW-U session it created (the stand-in's first SEID).
        let _ = recv_s11(&sock).await;
        let _ = recv_s11(&sock).await;
        assert!(
            eventually(|| sgwu_deletions(&sgwu, 0x7c).contains(&0x7c_0000_0001)).await,
            "{:?}",
            sgwu_deletions(&sgwu, 0x7c)
        );
        let sessions = ctx.sess_list_for_ue(ue.id);
        assert_eq!(sessions.len(), 1);
        assert_ne!(
            sessions[0].sgwu_sxa_seid, 0x7c_0000_0001,
            "the survivor is the second"
        );
        ctx.ue_remove(ue.id);
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
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

        let server = test_server(&ambient, 1000, 1);
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
            // #491, Table 7.2.1-1: conditional, present for an E-UTRAN initial attach.
            (Gtp2IeType::Paa as u8, "PDN Address Allocation"),
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_millis(0),
        )
        .await;
        // Deliberately NO anchor, set under the same guard the stand-in SGW-U holds.
        sgwc_self().set_pgw_s5c_peer(None);
        let server = test_server(&ambient, 1000, 1);
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

    /// #1010 review MAJOR 1, TS 29.244 §6.2.6.1: with no Sxa association a Create
    /// Session Request is answered at once with No resources available. Nothing is
    /// relayed to the PGW (no anchored session is left behind) and no UE context is
    /// created. Before, the PGW anchored the session, the PFCP establishment was
    /// refused locally, and the MME got no answer at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_session_request_with_no_sxa_association_is_refused_before_the_pgw() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        // The Sxa path runs, but nothing ever answers the Association Setup.
        let node =
            crate::pfcp_path::SxaNode::open("127.0.0.1:0".parse().unwrap(), Ipv4Addr::LOCALHOST)
                .await
                .expect("bind the SGW-C's Sxa socket");
        let (_stop, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(node.clone().run(rx));
        assert!(!crate::pfcp_path::sgwu_associated());
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x01, 0xf0];

        sock.send_to(&csr(0x1010, &imsi).encode(), server.local_addr())
            .unwrap();
        let response = recv_s11(&sock).await.expect("the MME must be answered");
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        assert_eq!(response.header.sequence_number, 0x1010);
        assert_eq!(
            response
                .get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(gtp_cause::NO_RESOURCES_AVAILABLE)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            pgw.seen.lock().unwrap().is_empty(),
            "nothing relayed to the PGW"
        );
        assert!(
            sgwc_self().ue_find_by_imsi(&imsi).is_none(),
            "no UE context created"
        );
        sgwc_self().set_pgw_s5c_peer(None);
    }

    /// #54 criterion 6, first half: NO Create Session Response is sent until the PFCP
    /// Session Establishment Response arrives — and then it is the full accepted one.
    ///
    /// The stand-in SGW-U holds its answer for 400ms; the MME socket's own read timeout is
    /// 150ms for the first attempt, so the "not yet" half is observed rather than assumed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_create_session_response_until_the_sgwu_answers() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_millis(400),
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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

    /// #303: the uplink FAR sent to the SGW-U forwards to the PGW-U's S5/S8-U F-TEID --
    /// its ADDRESS as well as its TEID.
    ///
    /// The S5/S8 Create Session Response's Bearer Context carries the PGW-U endpoint at
    /// F-TEID instance 2 (TS 29.274 Table 7.2.2-2). Only the TEID used to be stored, and
    /// `outer_header_creation` (rightly) builds no header without an address, so the
    /// SGW-U got an uplink FAR with no Outer Header Creation and dropped every uplink
    /// G-PDU ("FAR has no outer header creation"). The stand-in PGW answers with TEID
    /// 0x0BEE_F002 at 127.0.0.1, so both halves are asserted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_uplink_far_forwards_to_the_pgw_s5u_address_and_teid() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x59];

        sock.send_to(&csr(0x5407, &imsi).encode(), server.local_addr())
            .unwrap();
        let _ = recv_s11(&sock).await.expect("create session response");

        let seen = sgwu.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let establishment = seen
            .iter()
            .find(|(t, _, _)| *t == 50)
            .map(|(_, _, body)| body.clone())
            .expect("a Session Establishment Request must have reached the SGW-U");
        let mut body = Bytes::copy_from_slice(&establishment);
        let decoded = nextgcore_pfcp::message::SessionEstablishmentRequest::decode(&mut body)
            .expect("decodable establishment");
        let headers: Vec<_> = decoded
            .create_fars
            .iter()
            .filter_map(|f| f.forwarding_parameters.as_ref())
            .filter_map(|fp| fp.outer_header_creation.as_ref())
            .map(|ohc| (ohc.teid, ohc.ipv4_addr))
            .collect();
        assert!(
            headers.contains(&(Some(0x0BEE_F002), Some([127, 0, 0, 1]))),
            "the uplink FAR must tunnel to the PGW-U's S5/S8-U F-TEID (TEID 0x0BEE_F002 at \
             127.0.0.1); FARs carried {headers:?}"
        );

        server.close();
    }

    /// #1156, TS 29.274 §8.22, TS 29.244 §8.2.56: a PGW-U S5/S8-U F-TEID carrying
    /// only IPv6 gives the uplink FAR a GTP-U/UDP/IPv6 Outer Header Creation to
    /// that address. Before, only the IPv4 half was stored and the FAR had none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_ipv6_pgw_s5u_fteid_is_the_uplink_outer_header() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let v6: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x56,
        ];
        *pgw.s5u_ipv6.lock().unwrap() = Some(v6);
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x56, 0xf1];
        sock.send_to(&csr(0x1156, &imsi).encode(), server.local_addr())
            .unwrap();
        let _ = recv_s11(&sock).await.expect("create session response");

        let establishment = sgwu
            .requests(50)
            .into_iter()
            .next()
            .expect("a Session Establishment Request reached the SGW-U");
        let decoded = nextgcore_pfcp::message::SessionEstablishmentRequest::decode(
            &mut Bytes::from(establishment),
        )
        .expect("decodable establishment");
        let uplink: Vec<_> = decoded
            .create_fars
            .iter()
            .filter_map(|f| f.forwarding_parameters.as_ref())
            .filter_map(|fp| fp.outer_header_creation.as_ref())
            .filter(|ohc| ohc.teid == Some(0x0BEE_F002))
            .map(|ohc| (ohc.description.gtpu_udp_ipv6, ohc.ipv6_addr, ohc.ipv4_addr))
            .collect();
        assert_eq!(
            uplink,
            vec![(true, Some(v6), None)],
            "IPv6 outer header to the PGW-U"
        );
        let ue = sgwc_self().ue_find_by_imsi(&imsi).unwrap();
        sgwc_self().ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1152, TS 29.274 §7.6 / §8.4: a PGW that never answers the relayed Create
    /// Session Request (N3 exhausted) leaves the MME answered Remote peer not
    /// responding under its own number, and the session and UE removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unanswered_s5_create_session_is_answered_and_removed() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        // The PGW sits on the request far longer than T3 x (N3 + 1).
        pgw.create_delay_ms
            .store(10_000, std::sync::atomic::Ordering::SeqCst);
        let server = test_server(&ambient, 100, 1);
        set_s11_server(server.clone());
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x52, 0xf1];
        sock.send_to(&csr(0x1152, &imsi).encode(), server.local_addr())
            .unwrap();
        let rsp = recv_s11(&sock).await.expect("the MME is answered");
        assert_eq!(
            rsp.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        assert_eq!(rsp.header.sequence_number, 0x1152);
        assert_eq!(cause_of(&rsp), gtp_cause::REMOTE_PEER_NOT_RESPONDING);
        assert!(
            sgwc_self().ue_find_by_imsi(&imsi).is_none(),
            "the session and the UE are removed"
        );
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1190 review: the PGW accepts the Create only after N3 ran out. The MME was
    /// refused and the session removed, so the PGW's PDN connection is deleted
    /// with a Delete Session Request to the S5/S8-C TEID its answer gives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_late_pgw_answer_after_n3_deletes_the_pgw_session() {
        for (n, cause) in [
            gtp_cause::REQUEST_ACCEPTED,
            gtp_cause::NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY,
        ]
        .into_iter()
        .enumerate()
        {
            let ambient = crate::pfcp_path::process_state_test_guard().await;
            let _sgwu = stand_in_sgwu(
                &ambient,
                crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
                Duration::ZERO,
            )
            .await;
            let pgw = with_stand_in_pgw().await;
            // Longer than T3 x (N3 + 1) = 200 ms, then the PGW creates it.
            pgw.create_delay_ms
                .store(600, std::sync::atomic::Ordering::SeqCst);
            pgw.create_cause
                .store(cause, std::sync::atomic::Ordering::SeqCst);
            let server = test_server(&ambient, 100, 1);
            set_s11_server(server.clone());
            let sock = client();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x90, 0xf1 - n as u8];
            sock.send_to(&csr(0x1190 + n as u32, &imsi).encode(), server.local_addr())
                .unwrap();
            let rsp = recv_s11(&sock).await.expect("the MME is answered");
            assert_eq!(cause_of(&rsp), gtp_cause::REMOTE_PEER_NOT_RESPONDING);
            // At least one: the stand-in is still sleeping on the retransmitted
            // Create, so the Delete Session may itself be retransmitted (T3 100 ms).
            let deletes = pgw_deletes(&pgw, 1).await;
            assert!(
                deletes
                    .iter()
                    .all(|d| *d == (Some(0x0BEE_F001), Some(5), true)),
                "cause {cause}: the PGW's late PDN connection is deleted: {deletes:?}"
            );
            sgwc_self().set_pgw_s5c_peer(None);
            server.close();
            drop(ambient);
        }
    }

    /// #1132, TS 29.274 Table 7.2.2-2: the S11 Create Session Response's Bearer
    /// Context created carries the S5/S8-U PGW F-TEID at instance 2 (interface
    /// type 5): the endpoint the stand-in PGW gave (TEID 0x0BEE_F002 at
    /// 127.0.0.1). Golden bytes of the F-TEID IE: type 0x57, length 9, instance
    /// 2, V4 | interface 5, TEID, IPv4. mmed's parser reads this instance and type
    /// (`s11_handler::tests::bearer_contexts_created_parse_as_sgwcd_encodes_them`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_s11_create_session_response_carries_the_pgw_s5u_fteid() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x32, 0xf1];
        sock.send_to(&csr(0x1132, &imsi).encode(), server.local_addr())
            .unwrap();
        let rsp = recv_s11(&sock).await.expect("create session response");
        assert_eq!(cause_of(&rsp), gtp_cause::REQUEST_ACCEPTED);
        let bc_ie = rsp
            .get_ie(Gtp2IeType::BearerContext as u8, 0)
            .expect("a Bearer Context created");
        let bc = Gtp2BearerContextIe::decode(&bc_ie.value).unwrap();
        let pgw_u = bc.fteid(2).unwrap().expect("the S5/S8-U PGW F-TEID");
        assert_eq!(pgw_u.interface_type, 5, "S5/S8 PGW GTP-U");
        assert_eq!(pgw_u.teid, 0x0BEE_F002);
        assert_eq!(pgw_u.ipv4_addr, Some([127, 0, 0, 1]));
        let golden = [
            0x57, 0x00, 0x09, 0x02, 0x85, 0x0B, 0xEE, 0xF0, 0x02, 0x7F, 0x00, 0x00, 0x01,
        ];
        assert!(
            bc_ie.value.windows(golden.len()).any(|w| w == golden),
            "the F-TEID IE on the wire: {:02x?}",
            &bc_ie.value[..]
        );
        let ue = sgwc_self().ue_find_by_imsi(&imsi).unwrap();
        sgwc_self().ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #54 criterion 2: a non-accepted PFCP cause yields a MAPPED GTP cause, not a
    /// hard-coded `REQUEST_ACCEPTED`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_user_plane_yields_a_mapped_gtp_cause() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::NO_RESOURCES_AVAILABLE,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::SYSTEM_FAILURE,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        // Its own IMSI: the uplink-FAR test above used 0x59 too, and its UE outlives it,
        // so this create collided with it (TS 29.274 §7.2.1) once collisions are resolved.
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x5f];

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
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        // #52: the S11 Create Session Request is now RELAYED to a PGW, so the chain
        // needs an anchor. Set AFTER `stand_in_sgwu`, because that call is what takes the
        // guard over this process's ambient SGW-C configuration — setting the PGW peer
        // before it is exactly the unlocked-writer race #308 was about.
        let _pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
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

    /// Create a session over S11 through the stand-ins; returns the SGW's S11 TEID.
    async fn created_session(server: &GtpcServer, sock: &UdpSocket, imsi: &[u8], seq: u32) -> u32 {
        sock.send_to(&csr(seq, imsi).encode(), server.local_addr())
            .unwrap();
        let csrsp = recv_s11(sock).await.expect("create session response");
        Gtp2FTeidIe::decode(&csrsp.get_ie(Gtp2IeType::FTeid as u8, 0).unwrap().value)
            .unwrap()
            .teid
    }

    /// A Delete Session Request for EBI 5 with Indication flags `oi` / `si`.
    fn delete_session(sgw_teid: u32, seq: u32, oi: bool, si: bool) -> Gtp2Message {
        let mut dsr = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DeleteSessionRequest as u8,
            sgw_teid,
            seq,
        ));
        dsr.add_ie(nextgcore_gtp::v2::ie::Gtp2EbiIe::new(5).to_ie(0));
        dsr.add_ie(
            nextgcore_gtp::v2::ie::Gtp2IndicationIe {
                oi,
                si,
                ..Default::default()
            }
            .to_ie(0),
        );
        dsr
    }

    fn cause_of(msg: &Gtp2Message) -> u8 {
        Gtp2CauseIe::decode(&msg.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
            .unwrap()
            .cause
    }

    /// Wait until the stand-in PGW has seen `n` Delete Session Requests.
    async fn pgw_deletes(pgw: &StandInPgw, n: usize) -> Vec<(Option<u32>, Option<u8>, bool)> {
        for _ in 0..300 {
            let d = pgw.deletes.lock().unwrap().clone();
            if d.len() >= n {
                return d;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the PGW did not see {n} Delete Session Request(s)");
    }

    /// #1032 review, TS 29.274 Table 7.2.9.1-1: a Delete Session Request with
    /// neither OI nor SI deletes the local resources only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_delete_session_without_oi_or_si_stays_local() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x32, 0xf1];
        let sgw_teid = created_session(&server, &sock, &imsi, 0x3201).await;
        sock.send_to(
            &delete_session(sgw_teid, 0x3202, false, false).encode(),
            server.local_addr(),
        )
        .unwrap();
        let dsrsp = recv_s11(&sock).await.expect("delete session response");
        assert_eq!(cause_of(&dsrsp), gtp_cause::REQUEST_ACCEPTED);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            pgw.deletes.lock().unwrap().is_empty(),
            "not relayed without OI"
        );
        assert_eq!(sgwu.received(54), 1, "deleted locally");
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1032 review: a PGW that refuses the relayed Delete Session (here Context
    /// not found) does not keep the session: the SGW-U's goes and the MME is
    /// answered Request accepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pgw_refusing_the_delete_session_does_not_keep_it() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        pgw.delete_cause.store(
            gtp_cause::CONTEXT_NOT_FOUND,
            std::sync::atomic::Ordering::SeqCst,
        );
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x32, 0xf2];
        let sgw_teid = created_session(&server, &sock, &imsi, 0x3211).await;
        sock.send_to(
            &delete_session(sgw_teid, 0x3212, true, false).encode(),
            server.local_addr(),
        )
        .unwrap();
        let dsrsp = recv_s11(&sock).await.expect("delete session response");
        assert_eq!(dsrsp.header.sequence_number, 0x3212);
        assert_eq!(cause_of(&dsrsp), gtp_cause::REQUEST_ACCEPTED);
        assert_eq!(pgw.deletes.lock().unwrap().len(), 1);
        assert_eq!(
            sgwu.received(54),
            1,
            "the SGW-U's session is deleted all the same"
        );
        assert!(sgwc_self()
            .ue_find_by_imsi(&imsi)
            .unwrap()
            .sess_ids
            .is_empty());
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1032 review: a Delete Session that removes the session while its Create
    /// is still at the PGW (no PGW TEID to relay to yet) no longer orphans the
    /// PGW's session: when the PGW's Create answer arrives for the vanished
    /// session, the SGW-C deletes it at the PGW (its S5/S8-C TEID, the LBI).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_delete_racing_a_pending_create_deletes_the_pgw_session() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        pgw.create_delay_ms
            .store(400, std::sync::atomic::Ordering::SeqCst);
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x32, 0xf3];
        sock.send_to(&csr(0x3221, &imsi).encode(), server.local_addr())
            .unwrap();
        // The Create is at the PGW; the session exists locally with no PGW TEID.
        let mut sgw_teid = 0;
        for _ in 0..100 {
            if let Some(ue) = sgwc_self().ue_find_by_imsi(&imsi) {
                if !ue.sess_ids.is_empty() && ue.sgw_s11_teid != 0 {
                    sgw_teid = ue.sgw_s11_teid;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_ne!(sgw_teid, 0);
        sock.send_to(
            &delete_session(sgw_teid, 0x3222, true, false).encode(),
            server.local_addr(),
        )
        .unwrap();
        let first = recv_s11(&sock).await.expect("an answer");
        assert_eq!(
            first.header.message_type,
            Gtp2MessageType::DeleteSessionResponse as u8
        );
        let deletes = pgw_deletes(&pgw, 1).await;
        assert_eq!(
            deletes,
            vec![(Some(0x0BEE_F001), Some(5), true)],
            "the PGW's session is deleted at its S5/S8-C TEID"
        );
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1010 review MAJOR 1, second half: the Sxa association goes down while the
    /// PGW is answering the Create. The MME is refused (No resources available),
    /// the PGW's session is deleted, and the local session removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_association_lost_while_the_pgw_answers_deletes_the_pgw_session() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        pgw.create_delay_ms
            .store(300, std::sync::atomic::Ordering::SeqCst);
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let sock = client();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x10, 0xf4];
        sock.send_to(&csr(0x1011, &imsi).encode(), server.local_addr())
            .unwrap();
        // #1197: wait until the Create is at the PGW (it holds it 300 ms), not
        // for a fixed 100 ms: under load the S5/S8 relay can come later.
        for _ in 0..300 {
            if pgw
                .seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&(Gtp2MessageType::CreateSessionRequest as u8))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // The Create is at the PGW: the association goes.
        crate::pfcp_path::sxa_node()
            .unwrap()
            .drop_association_for_test(sgwu.addr())
            .await;
        assert!(!crate::pfcp_path::sgwu_associated());
        let rsp = recv_s11(&sock).await.expect("the MME is answered");
        assert_eq!(
            rsp.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        assert_eq!(cause_of(&rsp), gtp_cause::NO_RESOURCES_AVAILABLE);
        let deletes = pgw_deletes(&pgw, 1).await;
        assert_eq!(deletes, vec![(Some(0x0BEE_F001), Some(5), true)]);
        // #1197: the PGW's Delete Session goes out before the local session and
        // UE are removed, so its arrival is no proof they are gone yet: wait.
        for _ in 0..300 {
            if sgwc_self().ue_find_by_imsi(&imsi).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            sgwc_self().ue_find_by_imsi(&imsi).is_none(),
            "the first PDN connection's UE context is removed with its session"
        );
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1025, TS 29.274 §7.2.9.1, TS 23.401 §5.3.8.2.1 steps 3-7: a detach's Delete
    /// Session Request (OI set) is relayed to the PGW, at its S5/S8-C TEID with the
    /// Linked EBI and OI; the SGW-U's session is deleted after the PGW's answer, and
    /// then the MME is answered. Before, the PGW never heard of it and kept the
    /// session and its UE IP address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_detach_delete_session_is_relayed_to_the_pgw() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x25, 0xf1];
        let sgw_teid = created_session(&server, &sock, &imsi, 0x2501).await;

        sock.send_to(
            &delete_session(sgw_teid, 0x2502, true, false).encode(),
            server.local_addr(),
        )
        .unwrap();
        let dsrsp = recv_s11(&sock).await.expect("delete session response");
        assert_eq!(
            dsrsp.header.message_type,
            Gtp2MessageType::DeleteSessionResponse as u8
        );
        assert_eq!(dsrsp.header.sequence_number, 0x2502);
        assert_eq!(cause_of(&dsrsp), gtp_cause::REQUEST_ACCEPTED);
        assert_eq!(
            *pgw.deletes.lock().unwrap(),
            vec![(Some(0x0BEE_F001), Some(5), true)],
            "relayed once, to the PGW's S5/S8-C TEID, with the LBI and OI"
        );
        // #1052 review: what the EPC E2E detach stage reads.
        let metrics = crate::main_render_metrics_for_test();
        assert!(metrics.contains("# TYPE sgwc_s5_delete_session_relayed_total counter"));
        assert!(S5_DELETES_RELAYED_TOTAL.load(Ordering::Relaxed) >= 1);
        assert!(S5_DELETES_ACCEPTED_TOTAL.load(Ordering::Relaxed) >= 1);
        assert_eq!(sgwu.received(54), 1, "the SGW-U's session is deleted");
        let ue = sgwc_self().ue_find_by_imsi(&imsi).unwrap();
        assert!(ue.sess_ids.is_empty(), "the session is gone");
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// The PGW's messages of `msg_type` received so far.
    fn pgw_got(pgw: &StandInPgw, msg_type: Gtp2MessageType) -> Vec<Gtp2Message> {
        pgw.msgs
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.header.message_type == msg_type as u8)
            .cloned()
            .collect()
    }

    /// Wait until the PGW has `n` messages of `msg_type`.
    async fn pgw_wait(pgw: &StandInPgw, msg_type: Gtp2MessageType, n: usize) -> Vec<Gtp2Message> {
        for _ in 0..300 {
            let got = pgw_got(pgw, msg_type);
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the PGW did not receive {n} {msg_type:?}");
    }

    /// A PGW-initiated bearer Request on the session of `imsi`, addressed to the
    /// SGW's S5-C TEID.
    fn pgw_request(
        msg_type: Gtp2MessageType,
        sgw_s5c_teid: u32,
        seq: u32,
        ies: &[(u8, u8, &[u8])],
    ) -> Gtp2Message {
        let mut m = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            msg_type as u8,
            sgw_s5c_teid,
            seq,
        ));
        for (t, inst, v) in ies {
            m.add_ie(Gtp2Ie::from_slice(*t, *inst, v));
        }
        m
    }

    /// Whether `sock` receives a GTPv2-C message within `ms`.
    async fn quiet_for(sock: &UdpSocket, ms: u64) -> bool {
        let sock = sock.try_clone().unwrap();
        tokio::task::spawn_blocking(move || {
            sock.set_read_timeout(Some(Duration::from_millis(ms)))
                .unwrap();
            let mut buf = [0u8; 2048];
            let quiet = sock.recv_from(&mut buf).is_err();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            quiet
        })
        .await
        .unwrap()
    }

    /// The session of `imsi`, and a dedicated bearer EBI 6 added to it with its
    /// SGW-U rule ids (as a Create Bearer would leave it).
    fn session_with_dedicated_bearer(imsi: &[u8]) -> (crate::context::SgwcSess, u64) {
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);
        let mut bearer = ctx.bearer_add(sess.id).unwrap();
        bearer.ebi = 6;
        ctx.bearer_update(&bearer);
        for tid in &ctx.bearer_find_by_id(bearer.id).unwrap().tunnel_ids {
            let mut t = ctx.tunnel_find_by_id(*tid).unwrap();
            t.pdr_id = Some(ctx.next_pdr_id());
            t.far_id = t.pdr_id.map(u32::from);
            ctx.tunnel_update(&t);
        }
        (ctx.sess_find_by_id(sess.id).unwrap(), bearer.id)
    }

    /// #607, TS 23.401 §5.4.4.1 step 8, TS 29.274 §7.6: the MME's Delete Bearer
    /// Response to a PGW-initiated Delete Bearer Request goes back to the PGW, under
    /// the PGW's sequence number and to its S5-C TEID, after the released bearer's
    /// rules are removed at the SGW-U. A PGW retransmission while the MME decides is
    /// not relayed again; one after the answer gets the same answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pgw_delete_bearer_request_is_answered_with_the_mmes_response() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x06, 0xf7];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x6071).await;
        let (sess, dedicated) = session_with_dedicated_bearer(&imsi);
        let modifications = sgwu.received(52);

        let dbr = pgw_request(
            Gtp2MessageType::DeleteBearerRequest,
            sess.sgw_s5c_teid,
            0x0607,
            &[(Gtp2IeType::Ebi as u8, 1, &[6])],
        );
        pgw.sock
            .send_to(&dbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        assert_eq!(
            at_mme.header.message_type,
            Gtp2MessageType::DeleteBearerRequest as u8
        );
        let s11_seq = at_mme.header.sequence_number;
        // Retransmitted while the MME decides: discarded.
        pgw.sock
            .send_to(&dbr.encode(), server.local_addr())
            .await
            .unwrap();
        assert!(quiet_for(&mme, 300).await, "not relayed a second time");

        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DeleteBearerResponse as u8,
            sgw_s11_teid,
            s11_seq,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(6);
        bc.set_cause(&Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED));
        rsp.add_bearer_context(0, &bc);
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();

        let answered = pgw_wait(&pgw, Gtp2MessageType::DeleteBearerResponse, 1).await;
        assert_eq!(
            answered[0].header.sequence_number, 0x0607,
            "the PGW's number"
        );
        assert_eq!(
            answered[0].header.teid,
            Some(0x0BEE_F001),
            "the PGW's S5-C TEID"
        );
        assert_eq!(cause_of(&answered[0]), gtp_cause::REQUEST_ACCEPTED);
        for _ in 0..300 {
            if sgwu.received(52) > modifications {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // At least one: a PFCP T1 retransmission under load is a second copy.
        assert!(
            sgwu.received(52) > modifications,
            "the bearer's rules are removed at the SGW-U"
        );
        assert!(
            sgwc_self().bearer_find_by_id(dedicated).is_none(),
            "EBI 6 is gone"
        );
        assert!(
            sgwc_self().bearer_find_by_sess_ebi(sess.id, 5).is_some(),
            "the default bearer stays"
        );

        // Retransmitted after the answer: the same answer, nothing to the MME.
        pgw.sock
            .send_to(&dbr.encode(), server.local_addr())
            .await
            .unwrap();
        let again = pgw_wait(&pgw, Gtp2MessageType::DeleteBearerResponse, 2).await;
        assert_eq!(again[1].header.sequence_number, 0x0607);
        assert!(quiet_for(&mme, 200).await, "the MME is not asked again");
        assert!(server.inner.pgw_requests.lock().unwrap().is_empty());

        sgwc_self().ue_remove(sess.sgwc_ue_id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #710, TS 29.274 Table 7.2.10.2-1: the answer to a Delete Bearer Request that
    /// named the LBI carries the LBI and no Bearer Context. It is relayed to the PGW,
    /// and the PDN connection goes: the SGW-U session is deleted and so is the
    /// SGW-C's (and the UE context, which has no other).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_delete_bearer_response_carrying_the_lbi_releases_the_pdn_connection() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x07, 0xf1];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x7101).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);

        let dbr = pgw_request(
            Gtp2MessageType::DeleteBearerRequest,
            sess.sgw_s5c_teid,
            0x0710,
            &[(Gtp2IeType::Ebi as u8, 0, &[5])],
        );
        pgw.sock
            .send_to(&dbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DeleteBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        rsp.add_ie(nextgcore_gtp::v2::ie::Gtp2EbiIe::new(5).to_ie(0));
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();

        let answered = pgw_wait(&pgw, Gtp2MessageType::DeleteBearerResponse, 1).await;
        assert_eq!(answered[0].header.sequence_number, 0x0710);
        assert_eq!(answered[0].header.teid, Some(0x0BEE_F001));
        assert_eq!(
            answered[0]
                .get_ie(Gtp2IeType::Ebi as u8, 0)
                .map(|ie| ie.value[0] & 0x0f),
            Some(5),
            "the LBI is relayed"
        );
        for _ in 0..300 {
            if sgwu.received(54) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // At least one: a PFCP T1 retransmission under load is a second copy.
        assert!(sgwu.received(54) >= 1, "the SGW-U session is deleted");
        // The local session goes once the SGW-U has confirmed.
        for _ in 0..300 {
            if ctx.ue_find_by_imsi(&imsi).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            ctx.sess_find_by_id(sess.id).is_none(),
            "the session is gone"
        );
        assert!(ctx.ue_find_by_imsi(&imsi).is_none(), "and the UE with it");
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #641 stop-gap, TS 23.401 §5.4.1 step 8: the MME's refusal of a
    /// PGW-initiated Create Bearer Request ("Service not supported") reaches the
    /// PGW under the PGW's number and S5-C TEID, with its Bearer Context. #607: the
    /// bearer the SGW-C set up for it is removed, here and at the SGW-U.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_create_bearer_is_answered_to_the_pgw() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x41, 0xf6];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x6411).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);

        let cbr = dedicated_cbr(sess.sgw_s5c_teid, 0x0641, 0x0BEE_F0D1);
        pgw.sock
            .send_to(&cbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        assert_eq!(
            at_mme.header.message_type,
            Gtp2MessageType::CreateBearerRequest as u8
        );
        assert_eq!(
            ctx.sess_find_by_id(sess.id).unwrap().bearer_ids.len(),
            2,
            "the dedicated bearer is held while the MME decides"
        );
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::CreateBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::SERVICE_NOT_SUPPORTED).to_ie(0));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(0);
        bc.set_cause(&Gtp2CauseIe::new(gtp_cause::SERVICE_NOT_SUPPORTED));
        rsp.add_bearer_context(0, &bc);
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();

        let answered = pgw_wait(&pgw, Gtp2MessageType::CreateBearerResponse, 1).await;
        assert_eq!(answered[0].header.sequence_number, 0x0641);
        assert_eq!(answered[0].header.teid, Some(0x0BEE_F001));
        assert_eq!(cause_of(&answered[0]), gtp_cause::SERVICE_NOT_SUPPORTED);
        assert_eq!(
            answered[0].get_ies(Gtp2IeType::BearerContext as u8).len(),
            1,
            "one Bearer Context per requested bearer (Table 7.2.4-1)"
        );
        assert_eq!(
            ctx.sess_find_by_id(sess.id).unwrap().bearer_ids.len(),
            1,
            "the refused bearer is removed"
        );
        let removals = sgwu_modifications(&sgwu)
            .iter()
            .filter(|m| m.remove_pdrs.len() == 2 && m.remove_fars.len() == 2)
            .count();
        assert_eq!(removals, 1, "and its rules at the SGW-U");
        assert_eq!(crate::dedicated_bearer::pending_count(), 0);
        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// A PGW's Create Bearer Request for one dedicated bearer (TS 29.274 Table 7.2.3-2 on
    /// S5/S8): LBI 5, and a Bearer Context with EBI 0, a TFT, the PGW's S5/S8-U F-TEID
    /// (`pgw_s5u_teid` at 127.0.0.1, instance 1) and a Bearer QoS.
    fn dedicated_cbr(sgw_s5c_teid: u32, seq: u32, pgw_s5u_teid: u32) -> Gtp2Message {
        let mut cbr = pgw_request(
            Gtp2MessageType::CreateBearerRequest,
            sgw_s5c_teid,
            seq,
            &[(Gtp2IeType::Ebi as u8, 0, &[5])],
        );
        // The PGW's restart counter, which must not reach the MME as this SGW's.
        cbr.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[0x2a]));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(0);
        // Create new TFT, one bidirectional filter: protocol UDP (TS 24.008 §10.5.6.12).
        bc.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::BearerTft as u8,
            0,
            &[0x21, 0x31, 0x00, 0x02, 0x30, 0x11],
        ));
        bc.set_fteid(
            1,
            &Gtp2FTeidIe::new_ipv4(
                crate::s11_build::f_teid_interface::S5_S8_PGW_GTP_U,
                pgw_s5u_teid,
                [127, 0, 0, 1],
            ),
        );
        let mut qos = nextgcore_gtp::v2::Gtp2BearerQosIe::new(1, 128, 128, 64, 64);
        qos.pl = 2;
        bc.set_bearer_qos(&qos);
        cbr.add_bearer_context(0, &bc);
        cbr
    }

    /// The Session Modification Requests the stand-in SGW-U received, decoded.
    fn sgwu_modifications(
        sgwu: &StandInSgwu,
    ) -> Vec<nextgcore_pfcp::message::SessionModificationRequest> {
        sgwu.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(t, _, _)| *t == 52)
            .map(|(_, _, body)| {
                let mut b = Bytes::copy_from_slice(body);
                nextgcore_pfcp::message::SessionModificationRequest::decode(&mut b)
                    .expect("decodable modification")
            })
            .collect()
    }

    /// Wait until the stand-in SGW-U has received `n` Session Modification Requests.
    async fn sgwu_wait_modifications(sgwu: &StandInSgwu, n: usize) {
        for _ in 0..400 {
            if sgwu.received(52) >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "the SGW-U received {} Session Modification(s), not {n}",
            sgwu.received(52)
        );
    }

    /// #607 (Create Bearer half), TS 23.401 §5.4.1 steps 2-3 and 7-8: the SGW-C sets
    /// up the dedicated bearer at the SGW-U, relays the request to the MME with its own
    /// S1-U F-TEID, switches the downlink to the eNB the MME names, and answers the PGW
    /// with its S5/S8-U F-TEID (Tables 7.2.3-2, 7.2.4-2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_bearer_request_sets_up_the_dedicated_bearer_on_both_legs() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x61, 0xf7];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x6071).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);
        let before = sgwu.received(52);

        const PGW_S5U: u32 = 0x0BEE_F0D1;
        const ENB_S1U: u32 = 0x0E0B_0006;
        let cbr = dedicated_cbr(sess.sgw_s5c_teid, 0x0607, PGW_S5U);
        pgw.sock
            .send_to(&cbr.encode(), server.local_addr())
            .await
            .unwrap();

        // Step 2: both directions at the SGW-U before anything reaches the MME.
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        assert_eq!(
            at_mme.header.message_type,
            Gtp2MessageType::CreateBearerRequest as u8
        );
        sgwu_wait_modifications(&sgwu, before + 1).await;
        let install = sgwu_modifications(&sgwu).remove(before);
        assert_eq!(install.create_pdrs.len(), 2, "an uplink and a downlink PDR");
        assert_eq!(install.create_fars.len(), 2);
        let bearer = ctx
            .sess_find_by_id(sess.id)
            .unwrap()
            .bearer_ids
            .iter()
            .filter_map(|&id| ctx.bearer_find_by_id(id))
            .find(|b| b.ebi == 0)
            .expect("the dedicated bearer is held with EBI 0");
        let ul = ctx.ul_tunnel_in_bearer(bearer.id).unwrap();
        let dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        let far = |id: Option<u32>| {
            install
                .create_fars
                .iter()
                .find(|f| Some(f.far_id) == id)
                .cloned()
                .expect("the FAR is created")
        };
        let ul_far = far(ul.far_id);
        assert_eq!(
            ul_far
                .forwarding_parameters
                .as_ref()
                .and_then(|fp| fp.outer_header_creation.as_ref())
                .map(|o| (o.teid, o.ipv4_addr)),
            Some((Some(PGW_S5U), Some([127, 0, 0, 1]))),
            "the uplink tunnels to the PGW's S5/S8-U F-TEID"
        );
        assert!(
            far(dl.far_id).apply_action.buff,
            "the downlink buffers until the eNB is known"
        );

        // The S11 request: the S1-U SGW F-TEID at instance 0, the PGW's kept at 1, and no
        // Recovery.
        let bc = at_mme.bearer_context(0).unwrap().expect("a Bearer Context");
        let s1u = bc
            .fteid(0)
            .unwrap()
            .expect("the S1-U SGW F-TEID (instance 0)");
        assert_eq!(
            (s1u.interface_type, s1u.teid, s1u.ipv4_addr),
            (
                crate::s11_build::f_teid_interface::S1_U_SGW_GTP_U,
                ul.local_teid,
                Some([10, 99, 0, 1])
            )
        );
        assert_eq!(bc.fteid(1).unwrap().map(|f| f.teid), Some(PGW_S5U));
        assert!(bc.get_ie(Gtp2IeType::BearerTft as u8, 0).is_some());
        assert_eq!(at_mme.header.teid, Some(ue.mme_s11_teid));
        assert!(
            at_mme.get_ie(Gtp2IeType::Recovery as u8, 0).is_none(),
            "the PGW's Recovery is not relayed as this SGW's"
        );

        // A retransmission from the PGW while the MME decides is not relayed again.
        pgw.sock
            .send_to(&cbr.encode(), server.local_addr())
            .await
            .unwrap();
        assert!(
            quiet_for(&mme, 300).await,
            "a retransmission was relayed again"
        );

        // Step 7: the MME accepts, EBI 6, with the eNB's S1-U F-TEID.
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::CreateBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(6);
        bc.set_cause(&Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED));
        bc.set_fteid(
            0,
            &Gtp2FTeidIe::new_ipv4(
                crate::s11_build::f_teid_interface::S1_U_ENODEB_GTP_U,
                ENB_S1U,
                [127, 0, 0, 6],
            ),
        );
        bc.set_fteid(1, &s1u);
        rsp.add_bearer_context(0, &bc);
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();

        // Step 8: the PGW's answer, after the downlink switch.
        let answered = pgw_wait(&pgw, Gtp2MessageType::CreateBearerResponse, 1).await;
        let a = &answered[0];
        assert_eq!(a.header.sequence_number, 0x0607);
        assert_eq!(a.header.teid, Some(0x0BEE_F001));
        assert_eq!(cause_of(a), gtp_cause::REQUEST_ACCEPTED);
        let abc = a.bearer_context(0).unwrap().expect("the Bearer Context");
        assert_eq!(abc.ebi().unwrap(), 6);
        let sgw_s5u = abc
            .fteid(2)
            .unwrap()
            .expect("the S5/S8-U SGW F-TEID (instance 2)");
        assert_eq!(
            (sgw_s5u.interface_type, sgw_s5u.teid),
            (
                crate::s11_build::f_teid_interface::S5_S8_SGW_GTP_U,
                dl.local_teid
            )
        );
        assert_eq!(abc.fteid(3).unwrap().map(|f| f.teid), Some(PGW_S5U));
        assert!(
            abc.fteid(0).unwrap().is_none() && abc.fteid(1).unwrap().is_none(),
            "the S1-U F-TEIDs are S11-only"
        );
        let switch = sgwu_modifications(&sgwu).remove(before + 1);
        assert!(
            switch.update_fars.iter().any(|f| {
                Some(f.far_id) == dl.far_id
                    && f.forwarding_parameters
                        .as_ref()
                        .and_then(|fp| fp.outer_header_creation.as_ref())
                        .is_some_and(|o| o.teid == Some(ENB_S1U))
            }),
            "the downlink forwards to the eNB's S1-U F-TEID"
        );
        let stored = ctx.bearer_find_by_id(bearer.id).unwrap();
        assert_eq!(stored.ebi, 6);
        assert_eq!(
            ctx.dl_tunnel_in_bearer(bearer.id).unwrap().remote_teid,
            ENB_S1U
        );
        assert_eq!(crate::dedicated_bearer::pending_count(), 0);

        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #607: an SGW-U that refuses the dedicated bearer's rules gets the PGW a refusal
    /// ("System failure"), and the MME never hears of the bearer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_bearer_the_sgwu_refuses_is_refused_to_the_pgw() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        // The establishment is accepted, the bearer install (the first modification)
        // refused.
        let _sgwu = stand_in_sgwu_scripted(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
            vec![(
                crate::sxa_handler::pfcp_cause::NO_RESOURCES_AVAILABLE,
                Duration::ZERO,
            )],
            0x5555_0001,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x61, 0xf8];
        let _ = created_session(&server, &mme, &imsi, 0x6072).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);

        let cbr = dedicated_cbr(sess.sgw_s5c_teid, 0x0608, 0x0BEE_F0D2);
        pgw.sock
            .send_to(&cbr.encode(), server.local_addr())
            .await
            .unwrap();
        let answered = pgw_wait(&pgw, Gtp2MessageType::CreateBearerResponse, 1).await;
        assert_eq!(answered[0].header.sequence_number, 0x0608);
        assert_eq!(cause_of(&answered[0]), gtp_cause::SYSTEM_FAILURE);
        assert!(quiet_for(&mme, 300).await, "the MME must not be asked");
        assert_eq!(
            ctx.sess_find_by_id(sess.id).unwrap().bearer_ids.len(),
            1,
            "nothing is kept"
        );
        assert_eq!(crate::dedicated_bearer::pending_count(), 0);

        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// [`dedicated_cbr`] with a second Bearer Context, its PGW S5/S8-U F-TEID `second`.
    fn two_bearer_cbr(sgw_s5c_teid: u32, seq: u32, first: u32, second: u32) -> Gtp2Message {
        let mut cbr = dedicated_cbr(sgw_s5c_teid, seq, first);
        let one = dedicated_cbr(sgw_s5c_teid, seq, second);
        let bc = one.bearer_context(0).unwrap().unwrap();
        cbr.add_bearer_context(0, &bc);
        cbr
    }

    /// The MME's Bearer Context answering a bearer: `ebi`, `cause`, the eNB's F-TEID
    /// `enb` (instance 0) and the echoed S1-U SGW F-TEID `s1u` (instance 1).
    fn mme_bc(ebi: u8, cause: u8, enb: u32, s1u: &Gtp2FTeidIe) -> Gtp2BearerContextIe {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(ebi);
        bc.set_cause(&Gtp2CauseIe::new(cause));
        if cause == gtp_cause::REQUEST_ACCEPTED {
            bc.set_fteid(
                0,
                &Gtp2FTeidIe::new_ipv4(
                    crate::s11_build::f_teid_interface::S1_U_ENODEB_GTP_U,
                    enb,
                    [127, 0, 0, 6],
                ),
            );
        }
        bc.set_fteid(1, s1u);
        bc
    }

    /// (EBI, cause, S5/S8-U SGW TEID at instance 2) per Bearer Context of a PGW answer.
    fn pgw_bearers(msg: &Gtp2Message) -> Vec<(u8, u8, Option<u32>)> {
        msg.get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .map(|ie| {
                let bc = Gtp2BearerContextIe::decode(&ie.value).unwrap();
                (
                    bc.ebi().unwrap(),
                    bc.cause().unwrap().unwrap().cause,
                    bc.fteid(2).unwrap().map(|f| f.teid),
                )
            })
            .collect()
    }

    /// #1189 review: a two-bearer request the MME answers in REVERSE order, the first
    /// bearer refused. Each answer is matched to its bearer by the echoed S1-U SGW
    /// F-TEID, so the accepted bearer gets ITS eNB tunnel; the PGW hears "Request
    /// accepted partially" with per-bearer causes; the refused bearer is removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_two_bearer_create_bearer_answered_out_of_order_is_partially_accepted() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x61, 0xfa];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x6074).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);

        let cbr = two_bearer_cbr(sess.sgw_s5c_teid, 0x0611, 0x0BEE_0001, 0x0BEE_0002);
        pgw.sock
            .send_to(&cbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        let s1u: Vec<Gtp2FTeidIe> = at_mme
            .get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .map(|ie| {
                Gtp2BearerContextIe::decode(&ie.value)
                    .unwrap()
                    .fteid(0)
                    .unwrap()
                    .unwrap()
            })
            .collect();
        assert_eq!(s1u.len(), 2);
        assert_ne!(s1u[0].teid, s1u[1].teid, "an S1-U tunnel each");
        // The bearers, by their S1-U TEID, before the answer renames them.
        let bearer_of = |teid: u32| {
            ctx.sess_find_by_id(sess.id)
                .unwrap()
                .bearer_ids
                .iter()
                .copied()
                .find(|&id| {
                    ctx.ul_tunnel_in_bearer(id)
                        .is_some_and(|t| t.local_teid == teid)
                })
                .unwrap()
        };
        let (first, second) = (bearer_of(s1u[0].teid), bearer_of(s1u[1].teid));

        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::CreateBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED_PARTIALLY).to_ie(0));
        rsp.add_bearer_context(
            0,
            &mme_bc(7, gtp_cause::REQUEST_ACCEPTED, 0x0E0B_0007, &s1u[1]),
        );
        rsp.add_bearer_context(0, &mme_bc(0, gtp_cause::UE_REFUSES, 0, &s1u[0]));
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();

        let answered = pgw_wait(&pgw, Gtp2MessageType::CreateBearerResponse, 1).await;
        assert_eq!(
            cause_of(&answered[0]),
            gtp_cause::REQUEST_ACCEPTED_PARTIALLY,
            "one of two bearers"
        );
        let dl2 = ctx.dl_tunnel_in_bearer(second).unwrap();
        assert_eq!(
            dl2.remote_teid, 0x0E0B_0007,
            "the second bearer's own eNB tunnel"
        );
        assert_eq!(ctx.bearer_find_by_id(second).unwrap().ebi, 7);
        assert_eq!(
            pgw_bearers(&answered[0]),
            vec![
                (0, gtp_cause::UE_REFUSES, None),
                (7, gtp_cause::REQUEST_ACCEPTED, Some(dl2.local_teid)),
            ]
        );
        assert!(
            ctx.bearer_find_by_id(first).is_none(),
            "the refused bearer is removed"
        );
        assert_eq!(crate::dedicated_bearer::pending_count(), 0);
        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1189 review: two bearers answered with the SAME EBI. The second is not a free EPS
    /// bearer identity of the PDN connection, so it is refused ("Mandatory IE
    /// incorrect") and removed; the PGW hears "Request accepted partially".
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_bearer_answered_with_a_duplicate_ebi_refuses_the_second() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x61, 0xfb];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x6075).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);
        let cbr = two_bearer_cbr(sess.sgw_s5c_teid, 0x0612, 0x0BEE_0003, 0x0BEE_0004);
        pgw.sock
            .send_to(&cbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        let s1u: Vec<Gtp2FTeidIe> = at_mme
            .get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .map(|ie| {
                Gtp2BearerContextIe::decode(&ie.value)
                    .unwrap()
                    .fteid(0)
                    .unwrap()
                    .unwrap()
            })
            .collect();
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::CreateBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        rsp.add_bearer_context(
            0,
            &mme_bc(6, gtp_cause::REQUEST_ACCEPTED, 0x0E0B_0016, &s1u[0]),
        );
        rsp.add_bearer_context(
            0,
            &mme_bc(6, gtp_cause::REQUEST_ACCEPTED, 0x0E0B_0026, &s1u[1]),
        );
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();
        let answered = pgw_wait(&pgw, Gtp2MessageType::CreateBearerResponse, 1).await;
        assert_eq!(
            cause_of(&answered[0]),
            gtp_cause::REQUEST_ACCEPTED_PARTIALLY
        );
        let causes: Vec<(u8, u8)> = pgw_bearers(&answered[0])
            .iter()
            .map(|b| (b.0, b.1))
            .collect();
        assert_eq!(
            causes,
            vec![
                (6, gtp_cause::REQUEST_ACCEPTED),
                (6, gtp_cause::MANDATORY_IE_INCORRECT)
            ]
        );
        assert_eq!(
            ctx.sess_find_by_id(sess.id).unwrap().bearer_ids.len(),
            2,
            "the default bearer and the first dedicated one"
        );
        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1189 review: the SGW-U refuses the downlink switch (the ACTIVATE) after the MME
    /// accepted. The bearer is removed at the SGW-U and here, and the PGW is refused
    /// "System failure" (the disclosed ceiling: the MME still holds it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_bearer_whose_downlink_switch_the_sgwu_refuses_is_undone() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        // The install (first modification) accepted, the ACTIVATE (second) refused.
        let sgwu = stand_in_sgwu_scripted(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
            vec![
                (
                    crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
                    Duration::ZERO,
                ),
                (
                    crate::sxa_handler::pfcp_cause::NO_RESOURCES_AVAILABLE,
                    Duration::ZERO,
                ),
            ],
            0x5555_0001,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x61, 0xfc];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x6076).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);
        let cbr = dedicated_cbr(sess.sgw_s5c_teid, 0x0613, 0x0BEE_0005);
        pgw.sock
            .send_to(&cbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        let s1u = at_mme
            .bearer_context(0)
            .unwrap()
            .unwrap()
            .fteid(0)
            .unwrap()
            .unwrap();
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::CreateBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        rsp.add_bearer_context(
            0,
            &mme_bc(6, gtp_cause::REQUEST_ACCEPTED, 0x0E0B_0036, &s1u),
        );
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();
        let answered = pgw_wait(&pgw, Gtp2MessageType::CreateBearerResponse, 1).await;
        assert_eq!(cause_of(&answered[0]), gtp_cause::SYSTEM_FAILURE);
        assert_eq!(
            ctx.sess_find_by_id(sess.id).unwrap().bearer_ids.len(),
            1,
            "the bearer is removed here"
        );
        let mut removed = false;
        for _ in 0..200 {
            if sgwu_modifications(&sgwu)
                .iter()
                .any(|m| m.remove_pdrs.len() == 2 && m.remove_fars.len() == 2)
            {
                removed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(removed, "and at the SGW-U");
        assert_eq!(crate::dedicated_bearer::pending_count(), 0);
        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #607: an MME that never answers the relayed Create Bearer Request (S11 N3 runs
    /// out) leaves no bearer behind, here or at the SGW-U, and the PGW is told
    /// "Remote peer not responding" (TS 29.274 §8.4) rather than left to time out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_bearer_the_mme_never_answers_is_undone() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 100, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x61, 0xf9];
        let _ = created_session(&server, &mme, &imsi, 0x6073).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);

        let cbr = dedicated_cbr(sess.sgw_s5c_teid, 0x0609, 0x0BEE_F0D3);
        pgw.sock
            .send_to(&cbr.encode(), server.local_addr())
            .await
            .unwrap();
        let _ = recv_s11(&mme)
            .await
            .expect("relayed to the MME, which stays silent");
        let answered = pgw_wait(&pgw, Gtp2MessageType::CreateBearerResponse, 1).await;
        assert_eq!(answered[0].header.sequence_number, 0x0609);
        assert_eq!(
            cause_of(&answered[0]),
            gtp_cause::REMOTE_PEER_NOT_RESPONDING
        );
        assert_eq!(
            ctx.sess_find_by_id(sess.id).unwrap().bearer_ids.len(),
            1,
            "the bearer is removed"
        );
        let removed = sgwu_modifications(&sgwu)
            .iter()
            .any(|m| m.remove_pdrs.len() == 2 && m.remove_fars.len() == 2);
        assert!(removed, "and its rules at the SGW-U");
        assert_eq!(crate::dedicated_bearer::pending_count(), 0);

        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1146 review: a PDN connection the PGW and the MME have released goes
    /// locally even when the SGW-U refuses its deletion (nobody will ask again,
    /// and keeping it would leak it), and the unconfirmed release is counted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_pdn_release_still_removes_the_session_locally() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        sgwu.deletion_cause.store(
            crate::sxa_handler::pfcp_cause::REQUEST_REJECTED,
            Ordering::SeqCst,
        );
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x46, 0xf1];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x1461).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);
        let unconfirmed = crate::sxa_response::PDN_RELEASES_UNCONFIRMED.load(Ordering::Relaxed);

        let dbr = pgw_request(
            Gtp2MessageType::DeleteBearerRequest,
            sess.sgw_s5c_teid,
            0x1146,
            &[(Gtp2IeType::Ebi as u8, 0, &[5])],
        );
        pgw.sock
            .send_to(&dbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DeleteBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        rsp.add_ie(nextgcore_gtp::v2::ie::Gtp2EbiIe::new(5).to_ie(0));
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();
        pgw_wait(&pgw, Gtp2MessageType::DeleteBearerResponse, 1).await;
        for _ in 0..300 {
            if ctx.ue_find_by_imsi(&imsi).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ctx.sess_find_by_id(sess.id).is_none(), "removed locally");
        assert!(ctx.ue_find_by_imsi(&imsi).is_none(), "and the UE with it");
        assert!(
            crate::sxa_response::PDN_RELEASES_UNCONFIRMED.load(Ordering::Relaxed) > unconfirmed,
            "counted as unconfirmed"
        );
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1146 review: a PDN release whose session is already gone locally (here
    /// removed while the SGW-U decides, as a same-APN Create Session would) but
    /// that the SGW-U accepts is confirmed, not counted as unconfirmed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_accepted_pdn_release_of_a_replaced_session_is_not_unconfirmed() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_millis(300),
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x46, 0xf3];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x1463).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);
        let unconfirmed = crate::sxa_response::PDN_RELEASES_UNCONFIRMED.load(Ordering::Relaxed);
        let deletions = sgwu.received(54);

        let dbr = pgw_request(
            Gtp2MessageType::DeleteBearerRequest,
            sess.sgw_s5c_teid,
            0x1148,
            &[(Gtp2IeType::Ebi as u8, 0, &[5])],
        );
        pgw.sock
            .send_to(&dbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DeleteBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        rsp.add_ie(nextgcore_gtp::v2::ie::Gtp2EbiIe::new(5).to_ie(0));
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();
        pgw_wait(&pgw, Gtp2MessageType::DeleteBearerResponse, 1).await;
        // The SGW-U's answer is 300 ms away: the session goes locally first.
        for _ in 0..300 {
            if sgwu.received(54) > deletions {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        ctx.sess_remove(sess.id);
        // Then the SGW-U accepts.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            crate::sxa_response::PDN_RELEASES_UNCONFIRMED.load(Ordering::Relaxed),
            unconfirmed,
            "an accepted deletion is confirmed, whatever happened locally"
        );
        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1146 review, TS 29.274 Table 7.2.10.2-1: a Delete Bearer Response
    /// "Request accepted partially" releases only the bearers whose own cause
    /// accepts; a bearer the MME refused (here 73) is kept at the SGW-C.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_partially_accepted_delete_bearer_keeps_the_refused_bearer() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x46, 0xf2];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x1462).await;
        let (sess, six) = session_with_dedicated_bearer(&imsi);
        let ctx = sgwc_self();
        let mut seven = ctx.bearer_add(sess.id).unwrap();
        seven.ebi = 7;
        ctx.bearer_update(&seven);

        let dbr = pgw_request(
            Gtp2MessageType::DeleteBearerRequest,
            sess.sgw_s5c_teid,
            0x1147,
            &[
                (Gtp2IeType::Ebi as u8, 1, &[6]),
                (Gtp2IeType::Ebi as u8, 1, &[7]),
            ],
        );
        pgw.sock
            .send_to(&dbr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::DeleteBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED_PARTIALLY).to_ie(0));
        for (ebi, cause) in [(6u8, gtp_cause::REQUEST_ACCEPTED), (7, 73)] {
            let mut bc = Gtp2BearerContextIe::new();
            bc.set_ebi(ebi);
            bc.set_cause(&Gtp2CauseIe::new(cause));
            rsp.add_bearer_context(0, &bc);
        }
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();
        pgw_wait(&pgw, Gtp2MessageType::DeleteBearerResponse, 1).await;
        assert!(
            ctx.bearer_find_by_id(six).is_none(),
            "EBI 6 accepted: released"
        );
        assert!(
            ctx.bearer_find_by_id(seven.id).is_some(),
            "EBI 7 refused (73): kept"
        );
        ctx.ue_remove(sess.sgwc_ue_id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #607, TS 23.401 §5.4.2.1 step 8: the MME's Update Bearer Response goes back to
    /// the PGW under the PGW's sequence number and S5-C TEID.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pgw_update_bearer_request_is_answered_with_the_mmes_response() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 2000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x06, 0xf8];
        let sgw_s11_teid = created_session(&server, &mme, &imsi, 0x6081).await;
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        let sess = ctx.sess_list_for_ue(ue.id).remove(0);

        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        let mut ubr = pgw_request(
            Gtp2MessageType::UpdateBearerRequest,
            sess.sgw_s5c_teid,
            0x0608,
            &[],
        );
        ubr.add_bearer_context(0, &bc);
        pgw.sock
            .send_to(&ubr.encode(), server.local_addr())
            .await
            .unwrap();
        let at_mme = recv_s11(&mme).await.expect("relayed to the MME");
        assert_eq!(
            at_mme.header.message_type,
            Gtp2MessageType::UpdateBearerRequest as u8
        );
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::header::Gtp2Header::new(
            Gtp2MessageType::UpdateBearerResponse as u8,
            sgw_s11_teid,
            at_mme.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        rsp.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[42]));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_cause(&Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED));
        rsp.add_bearer_context(0, &bc);
        mme.send_to(&rsp.encode(), server.local_addr()).unwrap();

        let answered = pgw_wait(&pgw, Gtp2MessageType::UpdateBearerResponse, 1).await;
        assert!(
            answered[0].get_ie(Gtp2IeType::Recovery as u8, 0).is_none(),
            "#1146 review: the MME's Recovery is not relayed as the SGW's"
        );
        assert_eq!(answered[0].header.sequence_number, 0x0608);
        assert_eq!(answered[0].header.teid, Some(0x0BEE_F001));
        assert_eq!(cause_of(&answered[0]), gtp_cause::REQUEST_ACCEPTED);
        assert!(ctx.bearer_find_by_sess_ebi(sess.id, 5).is_some());
        ctx.ue_remove(ue.id);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1025, TS 29.274 Table 7.2.9.1-1: a Delete Session Request for a Serving GW
    /// relocation (SI set, OI clear) deletes the local resources only: the PGW keeps
    /// the session the new SGW now serves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_relocation_delete_session_is_not_relayed_to_the_pgw() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x25, 0xf2];
        let sgw_teid = created_session(&server, &sock, &imsi, 0x2511).await;

        sock.send_to(
            &delete_session(sgw_teid, 0x2512, false, true).encode(),
            server.local_addr(),
        )
        .unwrap();
        let dsrsp = recv_s11(&sock).await.expect("delete session response");
        assert_eq!(cause_of(&dsrsp), gtp_cause::REQUEST_ACCEPTED);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(pgw.deletes.lock().unwrap().is_empty(), "not relayed");
        assert_eq!(sgwu.received(54), 1, "deleted locally");
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #1025: the MME's answer waits for the PGW; a PGW that never answers (N3
    /// exhausted) does not keep the session: it is deleted on the SGW-U and the MME
    /// answered then.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pgw_that_never_answers_the_delete_session_does_not_keep_it() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let pgw = with_stand_in_pgw().await;
        let server = test_server(&ambient, 300, 1);
        set_s11_server(server.clone());
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x25, 0xf3];
        let sgw_teid = created_session(&server, &sock, &imsi, 0x2521).await;
        pgw.answer_deletes
            .store(false, std::sync::atomic::Ordering::SeqCst);

        sock.set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        sock.send_to(
            &delete_session(sgw_teid, 0x2522, true, false).encode(),
            server.local_addr(),
        )
        .unwrap();
        assert!(
            recv_s11(&sock).await.is_none(),
            "no answer while the PGW may still answer"
        );
        // The MME retransmits: absorbed, not relayed a second time.
        sock.send_to(
            &delete_session(sgw_teid, 0x2522, true, false).encode(),
            server.local_addr(),
        )
        .unwrap();
        assert_eq!(
            sgwu.received(54),
            0,
            "the SGW-U's session waits for the PGW"
        );
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let dsrsp = recv_s11(&sock).await.expect("answered after N3");
        assert_eq!(dsrsp.header.sequence_number, 0x2522);
        assert_eq!(cause_of(&dsrsp), gtp_cause::REQUEST_ACCEPTED);
        assert_eq!(
            pgw.deletes.lock().unwrap().len(),
            2,
            "sent, then retransmitted once on T3; the MME's retransmission is not relayed"
        );
        assert_eq!(sgwu.received(54), 1);
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #482, TS 29.274 §7.6: a Create Session Response completes the request, so
    /// the S5-C Create Session Request is not retransmitted after it. The arm never
    /// completed the transaction, and T3 kept firing every period at a PGW that had
    /// already answered.
    #[test]
    fn a_create_session_response_stops_the_requests_retransmission() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        // N3 = 100 (about 5 s of T3): a response delayed by load still finds its
        // transaction rather than one already exhausted, and the wait below
        // ends long before exhaustion could empty the table.
        let server = test_server(&ambient, 50, 100);
        let pgw = client();
        let pgw_addr = pgw.local_addr().unwrap();

        let seq = server.alloc_sequence();
        let request = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::CreateSessionRequest as u8,
            0,
            seq,
        ));
        server.send_request(pgw_addr, &request, 0).unwrap();
        let mut buf = [0u8; 2048];
        pgw.recv_from(&mut buf).expect("the initial request");

        // The PGW answers (a reject is still an answer).
        let mut response = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::CreateSessionResponse as u8,
            0,
            seq,
        ));
        response.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[109, 0]));
        pgw.send_to(&response.encode(), server.local_addr())
            .unwrap();

        // #909: wait until the response has completed the transaction. Under
        // load, T3 (50 ms) can expire before the receive thread gets to the
        // response; a retransmission sent before that is legitimate. Drain those.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while server.inner.xact.lock().unwrap().outstanding() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the response completes the transaction"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        pgw.set_nonblocking(true).unwrap();
        while pgw.recv_from(&mut buf).is_ok() {}
        pgw.set_nonblocking(false).unwrap();

        // Several T3 periods later, nothing more has arrived.
        pgw.set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        assert!(
            pgw.recv_from(&mut buf).is_err(),
            "the request must not be retransmitted after its response"
        );
        assert_eq!(server.inner.xact.lock().unwrap().outstanding(), 0);

        server.close();
    }

    /// A UE whose MME is `mme`, with one session anchored at a PGW and default
    /// bearer 5. Returns (UE id, SGW S11 TEID, SGW S5-C TEID).
    fn ue_with_pgw_session(mme: SocketAddr, imsi: &[u8]) -> (u64, u32, u32) {
        let ctx = sgwc_self();
        let mut ue = ctx.ue_add(imsi).expect("ue");
        ue.mme_addr = Some(mme);
        ue.mme_s11_teid = 0x0000_0591;
        ctx.ue_update(&ue);
        let mut sess = ctx.sess_add(ue.id, "internet").expect("sess");
        sess.pgw_s5c_teid = 0x0000_5c5c;
        ctx.sess_update(&sess);
        let mut bearer = ctx.bearer_add(sess.id).expect("bearer");
        bearer.ebi = 5;
        ctx.bearer_update(&bearer);
        (ue.id, ue.sgw_s11_teid, sess.sgw_s5c_teid)
    }

    /// #792 review: a legacy MME's Command with the MSB clear whose number this
    /// node already uses for its own outstanding S11 request to that MME is
    /// dropped, neither answered (a Failure Indication on that number would
    /// close the own request at the MME) nor relayed, so the triggered Request
    /// cannot replace that transaction; the MME's retransmission is relayed once
    /// the own request is answered. And this node's own initial requests skip
    /// numbers in use towards a peer.
    #[test]
    fn a_legacy_command_number_cannot_clash_with_an_own_request() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 2000, 3);
        let mme = client();
        let pgw = client();
        pgw.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        sgwc_self().set_pgw_s5c_peer(Some(pgw.local_addr().unwrap()));
        let (ue_id, s11_teid, _) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010792000001");
        let mme_addr = mme.local_addr().unwrap();

        // This node's own request to the MME is outstanding at seq N.
        let n = server.alloc_sequence();
        let own = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotification as u8,
            0x0591,
            n,
        ));
        server.send_request(mme_addr, &own, 0).unwrap();
        let _ddn = recv_msg(&mme);

        // The MME's Delete Bearer Command uses the same number, MSB clear: it
        // is dropped, with no Failure Indication (which would close it at the
        // MME) and no relay.
        let cmd = bearer_command(Gtp2MessageType::DeleteBearerCommand, s11_teid, n, 5);
        mme.send_to(&cmd.encode(), server.local_addr()).unwrap();
        mme.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut buf = [0u8; 2048];
        assert!(mme.recv_from(&mut buf).is_err(), "no answer to the MME");
        mme.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert!(pgw.recv_from(&mut buf).is_err(), "not relayed to the PGW");
        assert!(
            server
                .inner
                .xact
                .lock()
                .unwrap()
                .is_outstanding(mme_addr, n),
            "the own transaction is intact"
        );

        // The MME answers the own request; its retransmitted Command is then
        // relayed.
        let mut ack = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotificationAcknowledge as u8,
            s11_teid,
            n,
        ));
        ack.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[16, 0]));
        mme.send_to(&ack.encode(), server.local_addr()).unwrap();
        for _ in 0..100 {
            if !server
                .inner
                .xact
                .lock()
                .unwrap()
                .is_outstanding(mme_addr, n)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        mme.send_to(&cmd.encode(), server.local_addr()).unwrap();
        pgw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let relayed = recv_msg(&pgw);
        assert_eq!(
            relayed.header.message_type,
            Gtp2MessageType::DeleteBearerCommand as u8
        );

        // The allocator skips a number in use towards that peer.
        let next = server.alloc_sequence() + 1;
        let busy = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotification as u8,
            0x0591,
            next,
        ));
        server.send_request(mme_addr, &busy, 0).unwrap();
        let _ = recv_msg(&mme);
        assert_ne!(server.alloc_sequence_to(mme_addr), next);

        sgwc_self().set_pgw_s5c_peer(None);
        sgwc_self().ue_remove(ue_id);
        server.close();
    }

    /// #766, TS 29.274 Tables 7.2.7-1 / 7.2.8-1: a Modify Bearer Request with
    /// two bearer contexts switches BOTH downlink tunnels, and the response
    /// names each in Bearer Contexts modified; a bearer the SGW does not hold is
    /// answered in Bearer Contexts marked for removal, with Request accepted
    /// partially. Before #766 only the first was switched and every bearer of
    /// the session was reported modified.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_modify_bearer_request_switches_every_bearer_context() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let (ue_id, s11_teid, _) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010766000001");
        let ctx = sgwc_self();
        let sess_id = ctx.bearer_find_by_ue_ebi(ue_id, 5).unwrap().sess_id;
        let mut dedicated = ctx.bearer_add(sess_id).unwrap();
        dedicated.ebi = 6;
        ctx.bearer_update(&dedicated);
        // The FAR ids session establishment would have allocated: the
        // downlink tunnel's FAR is what the modification updates.
        for (n, ebi) in [5u8, 6].into_iter().enumerate() {
            let bearer = ctx.bearer_find_by_ue_ebi(ue_id, ebi).unwrap();
            let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
            dl.far_id = Some(0x0766_0000 + n as u32);
            ctx.tunnel_update(&dl);
        }

        let mut mbr = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            s11_teid,
            0x0766,
        ));
        for (ebi, teid) in [(5u8, 0x8805u32), (6, 0x8806), (9, 0x8809)] {
            let mut bc = Gtp2BearerContextIe::new();
            bc.set_ebi(ebi);
            bc.set_fteid(
                0,
                &nextgcore_gtp::v2::Gtp2FTeidIe::new_ipv4(0, teid, [10, 0, 0, 8]),
            );
            mbr.add_bearer_context(0, &bc);
        }
        mme.send_to(&mbr.encode(), server.local_addr()).unwrap();
        let rsp = recv_s11(&mme).await.expect("a Modify Bearer Response");
        assert_eq!(
            rsp.header.message_type,
            Gtp2MessageType::ModifyBearerResponse as u8
        );
        assert_eq!(
            Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            gtp_cause::REQUEST_ACCEPTED_PARTIALLY
        );
        let contexts = |instance: u8| -> Vec<(u8, u8)> {
            rsp.get_ies(Gtp2IeType::BearerContext as u8)
                .into_iter()
                .filter(|ie| ie.instance == instance)
                .map(|ie| {
                    let bc = Gtp2BearerContextIe::decode(&ie.value).unwrap();
                    (bc.ebi().unwrap(), bc.cause().unwrap().unwrap().cause)
                })
                .collect()
        };
        assert_eq!(
            contexts(0),
            vec![
                (5, gtp_cause::REQUEST_ACCEPTED),
                (6, gtp_cause::REQUEST_ACCEPTED)
            ],
            "both bearers modified"
        );
        assert_eq!(
            contexts(1),
            vec![(9, gtp_cause::CONTEXT_NOT_FOUND)],
            "the unknown bearer is marked for removal"
        );
        for (ebi, teid) in [(5u8, 0x8805u32), (6, 0x8806)] {
            let bearer = ctx.bearer_find_by_ue_ebi(ue_id, ebi).unwrap();
            let dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
            assert_eq!(dl.remote_teid, teid, "EBI {ebi}'s downlink is switched");
            assert_eq!(dl.remote_ip.ipv4, Some(Ipv4Addr::new(10, 0, 0, 8)));
        }
        // One PFCP Session Modification for the session, updating the FAR of
        // BOTH bearers (Update FAR, IE type 10, TS 29.244 §7.5.4.3).
        let mut modification = None;
        for _ in 0..200 {
            modification = sgwu
                .seen
                .lock()
                .unwrap()
                .iter()
                .find(|(t, _, _)| *t == 52)
                .map(|(_, _, body)| body.clone());
            if modification.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let body = modification.expect("a PFCP Session Modification Request reaches the SGW-U");
        let mut update_fars = 0;
        let mut at = 0;
        while at + 4 <= body.len() {
            let ie_type = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
            if ie_type == 10 {
                update_fars += 1;
            }
            at += 4 + len;
        }
        assert_eq!(update_fars, 2, "both bearers' downlink FARs are updated");
        assert_eq!(
            sgwu.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, _, _)| *t == 52)
                .count(),
            1,
            "one modification per session"
        );
        ctx.ue_remove(ue_id);
        server.close();
    }

    /// #936, TS 29.274 §8.22, TS 29.244 §8.2.56: an S1-U eNodeB F-TEID carrying
    /// only IPv6 switches the downlink to that address. The Update FAR's Outer
    /// Header Creation is GTP-U/UDP/IPv6 with it. Before, the tunnel kept the TEID
    /// with no address and the FAR had no Outer Header Creation. A dual-stack
    /// F-TEID keeps both families and forwards over IPv4.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_ipv6_enb_fteid_is_the_downlink_outer_header() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let v6: std::net::Ipv6Addr = "2001:db8::936".parse().unwrap();
        let v4 = Ipv4Addr::new(10, 0, 9, 36);
        for (n, fteid) in [
            Gtp2FTeidIe::new_ipv6(0, 0x9361, v6.octets()),
            Gtp2FTeidIe::new_dual(0, 0x9362, v4.octets(), v6.octets()),
        ]
        .into_iter()
        .enumerate()
        {
            let imsi = format!("00101093600000{n}");
            let (ue_id, s11_teid, _) =
                ue_with_pgw_session(mme.local_addr().unwrap(), imsi.as_bytes());
            let ctx = sgwc_self();
            let bearer = ctx.bearer_find_by_ue_ebi(ue_id, 5).unwrap();
            let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
            dl.far_id = Some(0x0936 + n as u32);
            dl.remote_teid = 0x1111;
            dl.remote_ip.ipv4 = Some(Ipv4Addr::new(10, 0, 0, 1));
            ctx.tunnel_update(&dl);
            let before = sgwu.received(52);

            let mut mbr = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                Gtp2MessageType::ModifyBearerRequest as u8,
                s11_teid,
                0x0009_3600 + n as u32,
            ));
            let mut bc = Gtp2BearerContextIe::new();
            bc.set_ebi(5);
            bc.set_fteid(0, &fteid);
            mbr.add_bearer_context(0, &bc);
            mme.send_to(&mbr.encode(), server.local_addr()).unwrap();
            let rsp = recv_s11(&mme).await.expect("a Modify Bearer Response");
            assert_eq!(
                Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                    .unwrap()
                    .cause,
                gtp_cause::REQUEST_ACCEPTED
            );

            let dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
            assert_eq!(
                dl.remote_ip.ipv6,
                Some(v6),
                "the eNB's IPv6 address is kept"
            );
            let expect_v4 = (n == 1).then_some(v4);
            assert_eq!(dl.remote_ip.ipv4, expect_v4);

            let body = sgwu
                .requests(52)
                .into_iter()
                .nth(before)
                .expect("the Session Modification reached the SGW-U");
            let req =
                nextgcore_pfcp::message::SessionModificationRequest::decode(&mut Bytes::from(body))
                    .unwrap();
            let far = req
                .update_fars
                .iter()
                .find(|f| f.far_id == 0x0936 + n as u32)
                .expect("the downlink FAR is updated");
            let ohc = far
                .forwarding_parameters
                .as_ref()
                .and_then(|fp| fp.outer_header_creation.as_ref())
                .expect("with an Outer Header Creation");
            if n == 0 {
                assert!(ohc.description.gtpu_udp_ipv6, "{ohc:?}");
                assert_eq!(ohc.ipv6_addr, Some(v6.octets()));
                assert_eq!(ohc.teid, Some(0x9361));
            } else {
                assert!(ohc.description.gtpu_udp_ipv4, "{ohc:?}");
                assert_eq!(ohc.ipv4_addr, Some(v4.octets()));
                assert_eq!(ohc.teid, Some(0x9362));
            }
            ctx.ue_remove(ue_id);
        }
        server.close();
    }

    /// #838, TS 23.401 §5.5.1.1.2 steps 3-4: the Modify Bearer Response waits
    /// for the SGW-U. When it refuses the Session Modification the MME is not told
    /// Request accepted: the bearers are marked for removal with System failure.
    /// A retransmission while the SGW-U is deciding is not processed again (one
    /// PFCP modification, one answer).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_modify_bearer_response_waits_for_the_sgwu_and_reports_its_refusal() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_REJECTED,
            Duration::from_millis(300),
        )
        .await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let (ue_id, s11_teid, _) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010838000001");
        let ctx = sgwc_self();
        let bearer = ctx.bearer_find_by_ue_ebi(ue_id, 5).unwrap();
        let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        dl.far_id = Some(0x0838);
        // The source eNB's endpoint, which the refusal must leave in place.
        dl.remote_teid = 0x1111;
        dl.remote_ip.ipv4 = Some(Ipv4Addr::new(10, 0, 0, 1));
        ctx.tunnel_update(&dl);

        let mut mbr = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            s11_teid,
            0x0838,
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_fteid(
            0,
            &nextgcore_gtp::v2::Gtp2FTeidIe::new_ipv4(0, 0x8805, [10, 0, 0, 8]),
        );
        mbr.add_bearer_context(0, &bc);
        mme.send_to(&mbr.encode(), server.local_addr()).unwrap();
        // The MME retransmits before the SGW-U has answered.
        tokio::time::sleep(Duration::from_millis(50)).await;
        mme.send_to(&mbr.encode(), server.local_addr()).unwrap();

        let rsp = recv_s11(&mme).await.expect("a Modify Bearer Response");
        let cause = Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
            .unwrap()
            .cause;
        assert_eq!(cause, gtp_cause::SYSTEM_FAILURE, "not Request accepted");
        let marked: Vec<u8> = rsp
            .get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .filter(|ie| ie.instance == 1)
            .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok())
            .collect();
        assert_eq!(marked, vec![5]);
        assert!(rsp
            .get_ies(Gtp2IeType::BearerContext as u8)
            .iter()
            .all(|ie| ie.instance != 0));
        assert_eq!(
            sgwu.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, _, _)| *t == 52)
                .count(),
            1,
            "the retransmission did not reach the SGW-U a second time"
        );
        assert_eq!(crate::sxa_response::modify_bearer_pending_count(), 0);
        // #839 review: the SGW-C's downlink endpoint is rolled back with the
        // refusal, so it agrees with the SGW-U's FAR and the MME's view.
        let dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        assert_eq!(dl.remote_teid, 0x1111, "the old eNB TEID is restored");
        assert_eq!(dl.remote_ip.ipv4, Some(Ipv4Addr::new(10, 0, 0, 1)));
        ctx.ue_remove(ue_id);
        server.close();
    }

    /// #991/#1000 review: every Modify Bearer write is a new generation, even one
    /// writing the endpoint the tunnel already holds. MBR1 points the bearer at
    /// eNB F-TEID B and the SGW-U refuses it slowly; meanwhile MBR2 writes the
    /// same B and is accepted. MBR1's refusal must not roll the tunnel back to
    /// the source endpoint A under MBR2: with an unchanged generation it would.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refusal_does_not_undo_a_later_write_of_the_same_endpoint() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu_scripted(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
            vec![(
                crate::sxa_handler::pfcp_cause::REQUEST_REJECTED,
                Duration::from_millis(300),
            )],
            0x5555_0001,
        )
        .await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let (ue_id, s11_teid, _) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010991000001");
        let ctx = sgwc_self();
        let bearer = ctx.bearer_find_by_ue_ebi(ue_id, 5).unwrap();
        let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        dl.far_id = Some(0x0991);
        // A: the source eNB's endpoint.
        dl.remote_teid = 0x1111;
        dl.remote_ip.ipv4 = Some(Ipv4Addr::new(10, 0, 0, 1));
        ctx.tunnel_update(&dl);

        let mbr = |seq: u32| {
            let mut m = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                Gtp2MessageType::ModifyBearerRequest as u8,
                s11_teid,
                seq,
            ));
            let mut bc = Gtp2BearerContextIe::new();
            bc.set_ebi(5);
            // B: the target eNB's endpoint, in both requests.
            bc.set_fteid(
                0,
                &nextgcore_gtp::v2::Gtp2FTeidIe::new_ipv4(0, 0x2222, [10, 0, 0, 2]),
            );
            m.add_bearer_context(0, &bc);
            m.encode()
        };
        // #1111: MBR2 goes out only once MBR1's Session Modification has reached
        // the SGW-U, so MBR1 is the one the script refuses whatever the load.
        let modifications = || {
            sgwu.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(t, _, _)| *t == 52)
                .count()
        };
        let before = modifications();
        mme.send_to(&mbr(0x0991), server.local_addr()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while modifications() == before {
            assert!(
                std::time::Instant::now() < deadline,
                "MBR1's modification reached the SGW-U"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        mme.send_to(&mbr(0x0992), server.local_addr()).unwrap();

        let cause_of = |rsp: &Gtp2Message| {
            Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause
        };
        // Matched by sequence number, not by arrival order (#1111).
        let mut answers = std::collections::HashMap::new();
        for _ in 0..2 {
            let rsp = recv_s11(&mme).await.expect("a Modify Bearer Response");
            answers.insert(rsp.header.sequence_number, cause_of(&rsp));
        }
        assert_eq!(
            answers.get(&0x0991),
            Some(&gtp_cause::SYSTEM_FAILURE),
            "MBR1 refused"
        );
        assert_eq!(
            answers.get(&0x0992),
            Some(&gtp_cause::REQUEST_ACCEPTED),
            "MBR2 accepted"
        );
        let dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        assert_eq!(
            (dl.remote_teid, dl.remote_ip.ipv4),
            (0x2222, Some(Ipv4Addr::new(10, 0, 0, 2))),
            "the tunnel holds B, which the SGW-U accepted"
        );
        ctx.ue_remove(ue_id);
        server.close();
    }

    /// #839 review: a Bearer Context with no S1-U eNodeB F-TEID is reported held
    /// (modified) and its downlink tunnel is not touched; with nothing to switch,
    /// no PFCP modification is sent and the answer goes out at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_bearer_context_without_an_enb_fteid_is_held_and_untouched() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let (ue_id, s11_teid, _) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010839000001");
        let ctx = sgwc_self();
        let bearer = ctx.bearer_find_by_ue_ebi(ue_id, 5).unwrap();
        let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        dl.remote_teid = 0x2222;
        dl.remote_ip.ipv4 = Some(Ipv4Addr::new(10, 0, 0, 2));
        ctx.tunnel_update(&dl);

        let mut mbr = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            s11_teid,
            0x0839,
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        mbr.add_bearer_context(0, &bc);
        mme.send_to(&mbr.encode(), server.local_addr()).unwrap();
        let rsp = recv_s11(&mme).await.expect("a Modify Bearer Response");
        assert_eq!(
            Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            gtp_cause::REQUEST_ACCEPTED
        );
        let modified: Vec<u8> = rsp
            .get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .filter(|ie| ie.instance == 0)
            .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok())
            .collect();
        assert_eq!(modified, vec![5], "held, reported modified");
        let dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        assert_eq!(
            (dl.remote_teid, dl.remote_ip.ipv4),
            (0x2222, Some(Ipv4Addr::new(10, 0, 0, 2))),
            "the downlink tunnel is not pointed at TEID 0"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            sgwu.seen.lock().unwrap().iter().all(|(t, _, _)| *t != 52),
            "no PFCP Session Modification"
        );
        ctx.ue_remove(ue_id);
        server.close();
    }

    /// #839 review: an SGW-U that never answers the Session Modification (T1 x
    /// (N1 + 1) runs out) gets the MME Remote peer not responding, the bearer
    /// marked for removal, and the SGW-C's endpoint rolled back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_modify_bearer_the_sgwu_never_answers_is_remote_peer_not_responding() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::from_secs(60),
        )
        .await;
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let mme = client();
        mme.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        let (ue_id, s11_teid, _) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010839000002");
        let ctx = sgwc_self();
        let bearer = ctx.bearer_find_by_ue_ebi(ue_id, 5).unwrap();
        let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        dl.far_id = Some(0x0839);
        dl.remote_teid = 0x3333;
        ctx.tunnel_update(&dl);

        let mut mbr = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            s11_teid,
            0x0840,
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_fteid(
            0,
            &nextgcore_gtp::v2::Gtp2FTeidIe::new_ipv4(0, 0x8805, [10, 0, 0, 8]),
        );
        mbr.add_bearer_context(0, &bc);
        mme.send_to(&mbr.encode(), server.local_addr()).unwrap();
        let rsp = recv_s11(&mme).await.expect("a Modify Bearer Response");
        assert_eq!(
            Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            gtp_cause::REMOTE_PEER_NOT_RESPONDING
        );
        let marked: Vec<u8> = rsp
            .get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .filter(|ie| ie.instance == 1)
            .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok())
            .collect();
        assert_eq!(marked, vec![5]);
        assert_eq!(
            ctx.dl_tunnel_in_bearer(bearer.id).unwrap().remote_teid,
            0x3333
        );
        assert_eq!(crate::sxa_response::modify_bearer_pending_count(), 0);
        ctx.ue_remove(ue_id);
        server.close();
    }

    /// A Command with one Bearer Context naming `ebi`, as the MME sends it.
    fn bearer_command(t: Gtp2MessageType, s11_teid: u32, seq: u32, ebi: u8) -> Gtp2Message {
        let mut msg = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(t as u8, s11_teid, seq));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(ebi);
        msg.add_bearer_context(0, &bc);
        msg
    }

    /// #614, TS 29.274 §7.3.14-15, TS 23.401 §5.9.2: the MME's Change Notification
    /// Request reaches the PGW of the PDN connection its LBI names, on this node's
    /// S5-C number and to the PGW's S5-C TEID, without the MME's Recovery. The
    /// PGW's answer reaches the MME under the MME's number and S11 TEID. A
    /// retransmission while the PGW decides is not relayed again; one after the
    /// answer gets the same answer. An LBI naming no PDN connection is answered
    /// here: IMSI/IMEI not known, CS 0. No PGW peer: Service not supported.
    #[test]
    fn a_change_notification_is_relayed_to_the_pgw_and_answered() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 2000, 3);
        let mme = client();
        let pgw = client();
        sgwc_self().set_pgw_s5c_peer(Some(pgw.local_addr().unwrap()));
        let (ue_id, s11_teid, s5c_teid) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010614000001");
        let cnr = |seq: u32, lbi: u8| {
            let mut m = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                Gtp2MessageType::ChangeNotificationRequest as u8,
                s11_teid,
                seq,
            ));
            m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::RatType as u8, 0, &[6]));
            m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 0, &[lbi]));
            m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[9]));
            m.encode()
        };
        let mut buf = [0u8; 2048];
        let quiet = |sock: &UdpSocket, buf: &mut [u8]| {
            sock.set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let q = sock.recv_from(buf).is_err();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            q
        };

        mme.send_to(&cnr(0x0614, 5), server.local_addr()).unwrap();
        let at_pgw = recv_msg(&pgw);
        assert_eq!(
            at_pgw.header.message_type,
            Gtp2MessageType::ChangeNotificationRequest as u8
        );
        assert_eq!(at_pgw.header.teid, Some(0x0000_5c5c), "the PGW's S5-C TEID");
        assert!(
            at_pgw.get_ie(Gtp2IeType::Recovery as u8, 0).is_none(),
            "the MME's Recovery is not this SGW's"
        );
        assert!(
            at_pgw.get_ie(Gtp2IeType::Ebi as u8, 0).is_some(),
            "the LBI is forwarded"
        );
        let s5c_seq = at_pgw.header.sequence_number;
        // The MME retransmits before the PGW answers: not relayed again.
        mme.send_to(&cnr(0x0614, 5), server.local_addr()).unwrap();
        assert!(quiet(&pgw, &mut buf), "relayed once");

        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::ChangeNotificationResponse as u8,
            s5c_teid,
            s5c_seq,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        pgw.send_to(&rsp.encode(), server.local_addr()).unwrap();
        let at_mme = recv_msg(&mme);
        assert_eq!(
            at_mme.header.message_type,
            Gtp2MessageType::ChangeNotificationResponse as u8
        );
        assert_eq!(at_mme.header.sequence_number, 0x0614, "the MME's number");
        assert_eq!(at_mme.header.teid, Some(0x0000_0591), "the MME's S11 TEID");
        assert_eq!(
            Gtp2CauseIe::decode(&at_mme.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            gtp_cause::REQUEST_ACCEPTED
        );
        // Retransmitted after the answer: the cached answer, nothing to the PGW.
        mme.send_to(&cnr(0x0614, 5), server.local_addr()).unwrap();
        assert_eq!(recv_msg(&mme).header.sequence_number, 0x0614);
        assert!(quiet(&pgw, &mut buf), "the PGW is not asked again");
        assert!(server.inner.change_notifications.lock().unwrap().is_empty());
        assert_eq!(server.inner.xact.lock().unwrap().outstanding(), 0);

        // No such PDN connection: answered here, IMSI/IMEI not known, CS 0.
        mme.send_to(&cnr(0x0615, 9), server.local_addr()).unwrap();
        let rsp = recv_msg(&mme);
        let cause =
            Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value).unwrap();
        assert_eq!(cause.cause, gtp_cause::IMSI_IMEI_NOT_KNOWN);
        assert!(!cause.cs, "CS 0: the PDN connection is not in the SGW");
        assert!(quiet(&pgw, &mut buf));

        // No PGW peer at all.
        sgwc_self().set_pgw_s5c_peer(None);
        mme.send_to(&cnr(0x0616, 5), server.local_addr()).unwrap();
        let rsp = recv_msg(&mme);
        assert_eq!(
            rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value[0],
            gtp_cause::SERVICE_NOT_SUPPORTED
        );
        sgwc_self().ue_remove(ue_id);
        server.close();
    }

    /// #1161 review: the PGW's Recovery in its answer is not relayed to the MME as
    /// this SGW's (TS 23.007 §18). A CNR without an LBI goes to the UE's only PDN
    /// connection; with several, it names none, and is answered Conditional IE
    /// missing (offending IE: EBI) instead of reaching an arbitrary PGW session.
    #[test]
    fn a_change_notification_answer_and_the_lbi_less_request() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 2000, 3);
        let mme = client();
        let pgw = client();
        sgwc_self().set_pgw_s5c_peer(Some(pgw.local_addr().unwrap()));
        let (ue_id, s11_teid, s5c_teid) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010614000002");
        let cnr = |seq: u32| {
            let mut m = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                Gtp2MessageType::ChangeNotificationRequest as u8,
                s11_teid,
                seq,
            ));
            m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::RatType as u8, 0, &[6]));
            m.encode()
        };
        // One PDN connection, no LBI: relayed to it.
        mme.send_to(&cnr(0x0617), server.local_addr()).unwrap();
        let at_pgw = recv_msg(&pgw);
        assert_eq!(at_pgw.header.teid, Some(0x0000_5c5c));
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            Gtp2MessageType::ChangeNotificationResponse as u8,
            s5c_teid,
            at_pgw.header.sequence_number,
        ));
        rsp.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        rsp.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[7]));
        pgw.send_to(&rsp.encode(), server.local_addr()).unwrap();
        let at_mme = recv_msg(&mme);
        assert_eq!(at_mme.header.sequence_number, 0x0617);
        assert!(
            at_mme.get_ie(Gtp2IeType::Recovery as u8, 0).is_none(),
            "the PGW's Recovery is not this SGW's"
        );

        // A second PDN connection: no LBI names none of them.
        let ctx = sgwc_self();
        let mut sess2 = ctx.sess_add(ue_id, "ims").expect("sess");
        sess2.pgw_s5c_teid = 0x0000_6c6c;
        ctx.sess_update(&sess2);
        let mut b6 = ctx.bearer_add(sess2.id).expect("bearer");
        b6.ebi = 6;
        ctx.bearer_update(&b6);
        mme.send_to(&cnr(0x0618), server.local_addr()).unwrap();
        let rsp = recv_msg(&mme);
        let cause =
            Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value).unwrap();
        assert_eq!(cause.cause, gtp_cause::CONDITIONAL_IE_MISSING);
        assert_eq!(cause.offending_ie_type, Some(Gtp2IeType::Ebi as u8));
        pgw.set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut buf = [0u8; 2048];
        assert!(pgw.recv_from(&mut buf).is_err(), "not relayed to either");
        sgwc_self().set_pgw_s5c_peer(None);
        sgwc_self().ue_remove(ue_id);
        server.close();
    }

    /// #606: the MME's Delete Bearer Command and Modify Bearer Command reach the PGW of
    /// the PDN connection their bearer belongs to, and the PGW's answer (the triggered
    /// Delete Bearer Request, or a Failure Indication) reaches the MME under the MME's
    /// number. A retransmitted Command is not relayed twice. Before #606 both Commands
    /// fell to "[DROP] Unhandled GTPv2-C message type", so mmed's Delete Bearer Command
    /// for an eNB-released bearer (#584) reached no PGW.
    #[test]
    fn delete_and_modify_bearer_commands_are_relayed_to_the_pgw() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 400, 3);
        let mme = client();
        let pgw = client();
        sgwc_self().set_pgw_s5c_peer(Some(pgw.local_addr().unwrap()));
        let (ue_id, s11_teid, s5c_teid) =
            ue_with_pgw_session(mme.local_addr().unwrap(), b"001010606000001");
        // A dedicated bearer 6 in the same PDN connection.
        let ctx = sgwc_self();
        let sess_id = ctx.bearer_find_by_ue_ebi(ue_id, 5).unwrap().sess_id;
        let mut dedicated = ctx.bearer_add(sess_id).unwrap();
        dedicated.ebi = 6;
        ctx.bearer_update(&dedicated);

        for (command, ebi, answer) in [
            (
                Gtp2MessageType::DeleteBearerCommand,
                6,
                Gtp2MessageType::DeleteBearerRequest,
            ),
            (
                Gtp2MessageType::ModifyBearerCommand,
                5,
                Gtp2MessageType::ModifyBearerFailureIndication,
            ),
        ] {
            // MSB set: a Command's number (TS 29.274 §7.6).
            let mme_seq = 0x0086_0600 + ebi as u32;
            let cmd = bearer_command(command, s11_teid, mme_seq, ebi);
            mme.send_to(&cmd.encode(), server.local_addr()).unwrap();
            let relayed = recv_msg(&pgw);
            assert_eq!(relayed.header.message_type, command as u8);
            assert_eq!(
                relayed.header.teid,
                Some(0x0000_5c5c),
                "addressed to the PDN connection's PGW S5/S8-C TEID"
            );
            let s5c_seq = relayed.header.sequence_number;
            assert!(
                nextgcore_gtp::v2::is_command_sequence(s5c_seq),
                "#727: the S5-C Command's number has the MSB set (TS 29.274 §7.6): {s5c_seq:#x}"
            );
            // The MME retransmits before the PGW answers: not relayed again.
            mme.send_to(&cmd.encode(), server.local_addr()).unwrap();
            pgw.set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let mut buf = [0u8; 2048];
            assert!(pgw.recv_from(&mut buf).is_err(), "relayed once");
            pgw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

            let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                answer as u8,
                s5c_teid,
                s5c_seq,
            ));
            rsp.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 1, &[ebi]));
            pgw.send_to(&rsp.encode(), server.local_addr()).unwrap();
            let at_mme = recv_msg(&mme);
            assert_eq!(at_mme.header.message_type, answer as u8);
            assert_eq!(at_mme.header.sequence_number, mme_seq);
            assert_eq!(at_mme.header.teid, Some(0x0000_0591));
            if answer == Gtp2MessageType::DeleteBearerRequest {
                let mut done = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                    Gtp2MessageType::DeleteBearerResponse as u8,
                    s11_teid,
                    mme_seq,
                ));
                done.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[16, 0]));
                mme.send_to(&done.encode(), server.local_addr()).unwrap();
                // #607: the MME's answer to the triggered Request goes on to the
                // PGW under the PGW's number.
                let relayed = recv_msg(&pgw);
                assert_eq!(
                    relayed.header.message_type,
                    Gtp2MessageType::DeleteBearerResponse as u8
                );
                assert_eq!(relayed.header.sequence_number, s5c_seq);
                assert_eq!(relayed.header.teid, Some(0x0000_5c5c));
            }
            assert!(server.inner.command_relays.lock().unwrap().is_empty());
        }

        // A bearer the UE does not hold, and no PGW at all: the Failure Indication.
        let unknown = bearer_command(
            Gtp2MessageType::DeleteBearerCommand,
            s11_teid,
            0x0606_0009,
            9,
        );
        mme.send_to(&unknown.encode(), server.local_addr()).unwrap();
        let fi = recv_msg(&mme);
        assert_eq!(
            fi.header.message_type,
            Gtp2MessageType::DeleteBearerFailureIndication as u8
        );
        assert_eq!(
            fi.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value[0],
            gtp_cause::CONTEXT_NOT_FOUND
        );
        sgwc_self().set_pgw_s5c_peer(None);
        let no_pgw = bearer_command(
            Gtp2MessageType::ModifyBearerCommand,
            s11_teid,
            0x0606_000A,
            5,
        );
        mme.send_to(&no_pgw.encode(), server.local_addr()).unwrap();
        let fi = recv_msg(&mme);
        assert_eq!(
            fi.header.message_type,
            Gtp2MessageType::ModifyBearerFailureIndication as u8
        );
        assert_eq!(
            fi.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value[0],
            gtp_cause::SERVICE_NOT_SUPPORTED
        );
        sgwc_self().ue_remove(ue_id);
        server.close();
    }

    /// #591, TS 29.274 §7.6: a Bearer Resource Command relayed to the PGW is
    /// closed by the PGW's triggered message, which goes on to the MME under the
    /// sequence number the MME used. Before #591 the S5-C Command was retransmitted
    /// until N3, the triggered Create Bearer Request reached the MME under a new
    /// number (so the MME's Command never closed either), and a Bearer Resource
    /// Failure Indication was dropped as an unknown message.
    #[test]
    fn a_relayed_command_is_closed_by_its_triggered_message_on_both_legs() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 100, 3);
        let mme = client();
        let pgw = client();
        sgwc_self().set_pgw_s5c_peer(Some(pgw.local_addr().unwrap()));

        // #607: a triggered Create Bearer Request is no longer relayed verbatim (it
        // needs the SGW-U first), so a triggered Update Bearer Request carries the
        // relay case; an incomplete triggered Create Bearer Request, refused here, gets
        // the MME a Bearer Resource Failure Indication under the Command's number.
        for (n, triggered) in [
            Gtp2MessageType::UpdateBearerRequest,
            Gtp2MessageType::BearerResourceFailureIndication,
            Gtp2MessageType::CreateBearerRequest,
        ]
        .into_iter()
        .enumerate()
        {
            let imsi = format!("00101059100000{n}");
            let (ue_id, s11_teid, s5c_teid) =
                ue_with_pgw_session(mme.local_addr().unwrap(), imsi.as_bytes());
            let mme_seq = 0x0085_9100 + n as u32;
            let mut brc = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                Gtp2MessageType::BearerResourceCommand as u8,
                s11_teid,
                mme_seq,
            ));
            brc.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 0, &[5]));
            mme.send_to(&brc.encode(), server.local_addr()).unwrap();

            let relayed = recv_msg(&pgw);
            assert_eq!(
                relayed.header.message_type,
                Gtp2MessageType::BearerResourceCommand as u8
            );
            assert_eq!(relayed.header.teid, Some(0x0000_5c5c));
            let s5c_seq = relayed.header.sequence_number;
            assert!(
                nextgcore_gtp::v2::is_command_sequence(s5c_seq),
                "#727: TS 29.274 §7.6 MSB on the S5-C Command: {s5c_seq:#x}"
            );

            // The PGW answers with the triggered message under the S5-C number.
            let mut answer = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                triggered as u8,
                s5c_teid,
                s5c_seq,
            ));
            answer.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 0, &[5]));
            answer.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Pti as u8, 0, &[9]));
            if triggered == Gtp2MessageType::BearerResourceFailureIndication {
                answer.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[73, 0]));
            }
            pgw.send_to(&answer.encode(), server.local_addr()).unwrap();

            // The MME receives it under ITS number, addressed to its TEID.
            let at_mme = recv_msg(&mme);
            let expected = if triggered == Gtp2MessageType::CreateBearerRequest {
                Gtp2MessageType::BearerResourceFailureIndication
            } else {
                triggered
            };
            assert_eq!(at_mme.header.message_type, expected as u8);
            assert_eq!(
                at_mme.header.sequence_number, mme_seq,
                "{triggered:?} must reach the MME under the Command's S11 sequence number"
            );
            assert_eq!(at_mme.header.teid, Some(0x0000_0591));
            if triggered == Gtp2MessageType::UpdateBearerRequest {
                // The MME answers the triggered Request under the same number,
                // which closes the SGW-C's S11 transaction for it.
                let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
                    Gtp2MessageType::UpdateBearerResponse as u8,
                    s11_teid,
                    mme_seq,
                ));
                rsp.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[16, 0]));
                mme.send_to(&rsp.encode(), server.local_addr()).unwrap();
            }
            if triggered == Gtp2MessageType::CreateBearerRequest {
                // The refusal names the cause, the LBI and the PTI (Table 7.2.6-1).
                assert_eq!(
                    at_mme
                        .get_ie(Gtp2IeType::Cause as u8, 0)
                        .map(|ie| ie.value[0]),
                    Some(gtp_cause::MANDATORY_IE_MISSING)
                );
                assert_eq!(
                    at_mme
                        .get_ie(Gtp2IeType::Ebi as u8, 0)
                        .map(|ie| ie.value[0]),
                    Some(5)
                );
                assert_eq!(
                    at_mme
                        .get_ie(Gtp2IeType::Pti as u8, 0)
                        .map(|ie| ie.value[0]),
                    Some(9)
                );
                // And the PGW's request is answered with the same refusal.
                let at_pgw = recv_msg(&pgw);
                assert_eq!(
                    at_pgw.header.message_type,
                    Gtp2MessageType::CreateBearerResponse as u8
                );
                assert_eq!(at_pgw.header.sequence_number, s5c_seq);
            }

            // And the S5-C Command is not retransmitted after its answer.
            pgw.set_read_timeout(Some(Duration::from_millis(450)))
                .unwrap();
            let mut buf = [0u8; 2048];
            let mut retransmitted = 0;
            while let Ok((len, _)) = pgw.recv_from(&mut buf) {
                if buf[..len].get(1) == Some(&(Gtp2MessageType::BearerResourceCommand as u8)) {
                    retransmitted += 1;
                }
            }
            assert_eq!(retransmitted, 0, "the S5-C Command was retransmitted");
            pgw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert!(server.inner.command_relays.lock().unwrap().is_empty());
            assert_eq!(server.inner.xact.lock().unwrap().outstanding(), 0);
            sgwc_self().ue_remove(ue_id);
        }
        sgwc_self().set_pgw_s5c_peer(None);
        server.close();
    }

    /// #482: which addresses go where.
    #[test]
    fn s11_and_gtpu_advertisement_rules() {
        let wild = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let yaml = Some(Ipv4Addr::new(172, 24, 0, 3));
        let env = Some(Ipv4Addr::new(10, 0, 0, 3));
        let gtpu = Some(Ipv4Addr::new(172, 24, 0, 6));
        // Wildcard bind, nothing else: the YAML address is the S11 address but is
        // NOT used for GTP-U (it names the SGW-C, not the SGW-U).
        assert_eq!(advertised_addresses(wild, None, yaml, None), (yaml, None));
        // The environment wins over the file, and still feeds the GTP-U fallback.
        assert_eq!(advertised_addresses(wild, env, yaml, None), (env, env));
        // A specific bind is used for both, as before.
        let bound = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
        assert_eq!(
            advertised_addresses(bound, None, yaml, None),
            (
                Some(Ipv4Addr::new(127, 0, 0, 3)),
                Some(Ipv4Addr::new(127, 0, 0, 3))
            )
        );
        // An explicit GTP-U address always wins.
        assert_eq!(advertised_addresses(wild, None, yaml, gtpu), (yaml, gtpu));
    }

    #[test]
    fn test_ddn_t3_n3_retransmission_and_exhaustion() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        // Tiny T3, N3=2: the silent peer must see 1 + 2 = 3 datagrams,
        // after which the path is marked Failed.
        let server = test_server(&ambient, 50, 2);
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
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 1000, 1);
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
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 1000, 1);
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
        assert_eq!(restart_counter_order(5, 132), RestartOrder::Restarted);
        assert_eq!(restart_counter_order(5, 5), RestartOrder::Unchanged);
        // The race: stored is larger than received.
        assert_eq!(restart_counter_order(5, 4), RestartOrder::Stale);
        assert_eq!(restart_counter_order(5, 200), RestartOrder::Stale);
        // Section 18 says "taking the integer roll-over into account" (#728):
        // 255 -> 0 is the next incarnation, and 0 -> 255 the stale one.
        assert_eq!(restart_counter_order(255, 0), RestartOrder::Restarted);
        assert_eq!(restart_counter_order(0, 255), RestartOrder::Stale);
    }

    /// TS 29.274 Section 7.7.2: a datagram of a version higher than GTPv2 must
    /// elicit a type-3 Version Not Supported Indication, not a silent drop.
    #[test]
    fn unsupported_gtp_version_gets_a_version_not_supported_reply() {
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 200, 2);
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
        let ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let server = test_server(&ambient, 200, 2);
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
        let bytes = build_version_not_supported(0x0001_0203);
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
        // #1137: the restart tests set the variable under the process-state guard.
        let _ambient = crate::pfcp_path::process_state_test_guard_blocking();
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

    /// `SGWC_RESTART_DELETE_CONTEXTS=1` for one test, removed when it ends, pass or
    /// fail (the variable is process-wide; hold the process-state guard).
    struct RestartDeletionOn;

    impl RestartDeletionOn {
        fn new(_ambient: &crate::pfcp_path::ProcessStateGuard) -> Self {
            std::env::set_var("SGWC_RESTART_DELETE_CONTEXTS", "1");
            Self
        }
    }

    impl Drop for RestartDeletionOn {
        fn drop(&mut self) {
            std::env::remove_var("SGWC_RESTART_DELETE_CONTEXTS");
        }
    }

    /// A UE whose MME is `mme`, with one PDN connection anchored at the PGW `pgw`
    /// (its S5/S8 control address), default bearer 5. Returns (UE id, session id).
    fn ue_with_session_at_pgw(mme: SocketAddr, pgw: Ipv4Addr, imsi: &[u8]) -> (u64, u64) {
        let (ue_id, _, _) = ue_with_pgw_session(mme, imsi);
        let ctx = sgwc_self();
        let mut sess = ctx.sess_list_for_ue(ue_id).remove(0);
        sess.pgw_addr = Some(pgw);
        ctx.sess_update(&sess);
        (ue_id, sess.id)
    }

    /// The Delete Bearer Request the MME at `mme` receives: (header TEID, LBI,
    /// Cause).
    async fn mme_dbr(mme: &UdpSocket) -> (Option<u32>, Option<u8>, Option<u8>) {
        loop {
            let msg = recv_s11(mme)
                .await
                .expect("a Delete Bearer Request to the MME");
            if msg.header.message_type != Gtp2MessageType::DeleteBearerRequest as u8 {
                continue;
            }
            return (
                msg.header.teid,
                msg.get_ie(Gtp2IeType::Ebi as u8, 0)
                    .map(|ie| ie.value[0] & 0x0f),
                msg.get_ie(Gtp2IeType::Cause as u8, 0).map(|ie| ie.value[0]),
            );
        }
    }

    /// #1137, TS 23.007 §16.1A.2: a confirmed PGW restart (a higher restart
    /// counter in its Echo Request's Recovery) deletes every PDN connection
    /// anchored at it: the SGW-U session, then the local session and UE. The MME
    /// gets a Delete Bearer Request for the LBI, cause Reactivation requested.
    /// A PDN connection at another PGW survives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pgw_restart_deletes_its_pdn_connections_and_tells_the_mme() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let _deletion = RestartDeletionOn::new(&ambient);
        let server = test_server(&ambient, 1000, 1);
        set_s11_server(server.clone());
        let mme = client();
        let pgw = UdpSocket::bind("127.0.0.2:0").expect("a PGW at 127.0.0.2");
        let (ue_id, sess_id) = ue_with_session_at_pgw(
            mme.local_addr().unwrap(),
            Ipv4Addr::new(127, 0, 0, 2),
            b"001011137000001",
        );
        let (other_ue, other_sess) = ue_with_session_at_pgw(
            mme.local_addr().unwrap(),
            Ipv4Addr::new(127, 0, 0, 3),
            b"001011137000002",
        );
        let deletions = sgwu.received(54);
        let echo = |seq: u32, counter: u8| {
            let mut m = Gtp2Message::echo_request(seq);
            m.add_ie(Gtp2Ie::from_slice(
                Gtp2IeType::Recovery as u8,
                0,
                &[counter],
            ));
            m.encode()
        };
        pgw.send_to(&echo(0x1137, 4), server.local_addr()).unwrap();
        pgw.send_to(&echo(0x1138, 5), server.local_addr()).unwrap();

        let (teid, lbi, cause) = mme_dbr(&mme).await;
        assert_eq!(teid, Some(0x0000_0591), "to the MME's S11 TEID");
        assert_eq!(lbi, Some(5), "the PDN connection's LBI");
        assert_eq!(cause, Some(gtp_cause::REACTIVATION_REQUESTED));
        for _ in 0..300 {
            if sgwu.received(54) > deletions {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            sgwu.received(54) > deletions,
            "the SGW-U session is deleted"
        );
        let ctx = sgwc_self();
        assert!(
            ctx.sess_find_by_id(sess_id).is_none(),
            "the PDN connection is gone"
        );
        assert!(ctx.ue_find_by_id(ue_id).is_none(), "and its UE");
        assert!(
            ctx.sess_find_by_id(other_sess).is_some(),
            "a PDN connection at another PGW survives"
        );
        ctx.ue_remove(other_ue);
        server.close();
    }

    /// #1137, TS 23.007 §16.1A.2 / §20: an S5/S8 path failure (N3 exhausted on a
    /// request to the PGW) deletes the PDN connections anchored at it and tells
    /// the MME, as a restart does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_s5_path_failure_deletes_the_pgws_pdn_connections() {
        let ambient = crate::pfcp_path::process_state_test_guard().await;
        let _sgwu = stand_in_sgwu(
            &ambient,
            crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            Duration::ZERO,
        )
        .await;
        let _deletion = RestartDeletionOn::new(&ambient);
        let server = test_server(&ambient, 50, 1);
        set_s11_server(server.clone());
        let mme = client();
        // A PGW that never answers.
        let pgw = UdpSocket::bind("127.0.0.2:0").expect("a PGW at 127.0.0.2");
        let (ue_id, sess_id) = ue_with_session_at_pgw(
            mme.local_addr().unwrap(),
            Ipv4Addr::new(127, 0, 0, 2),
            b"001011137000003",
        );
        server.send_echo_request(pgw.local_addr().unwrap()).unwrap();

        let (_, lbi, cause) = mme_dbr(&mme).await;
        assert_eq!(lbi, Some(5));
        assert_eq!(cause, Some(gtp_cause::REACTIVATION_REQUESTED));
        let ctx = sgwc_self();
        assert!(
            ctx.sess_find_by_id(sess_id).is_none(),
            "the PDN connection is gone"
        );
        assert!(ctx.ue_find_by_id(ue_id).is_none());
        server.close();
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
