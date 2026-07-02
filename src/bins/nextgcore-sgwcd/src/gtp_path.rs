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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;

use nextgcore_gtp::v2::header::Gtp2MessageType;
use nextgcore_gtp::v2::ie::{Gtp2IeType, Gtp2RecoveryIe};
use nextgcore_gtp::v2::message::Gtp2Message;
use nextgcore_gtp::v2::xact::{Gtp2XactConfig, Gtp2XactMgr};

use crate::context::{sgwc_self, SgwcBearer};
use crate::s11_build;
use crate::s11_handler::{self, gtp_cause, HandlerResult};
use crate::s11_parse::{self, IeError};
use crate::{pfcp_path, sxa_handler};

/// Default S11 bind address (GTPv2-C well-known port, TS 29.274 Section 4.2)
const DEFAULT_S11_BIND: &str = "0.0.0.0:2123";

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

        // Retransmission (T3/N3) loop
        {
            let inner = inner.clone();
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

static S11_SERVER: OnceLock<GtpcServer> = OnceLock::new();

/// Get the global S11 server, if open
pub fn s11_server() -> Option<&'static GtpcServer> {
    S11_SERVER.get()
}

/// Open the S11 GTP-C server socket
/// Port of sgwc_gtp_open
pub fn gtp_open() -> Result<(), String> {
    if S11_SERVER.get().is_some() {
        return Ok(());
    }

    let bind = std::env::var("SGWC_S11_BIND").unwrap_or_else(|_| DEFAULT_S11_BIND.to_string());
    let restart_counter = std::env::var("SGWC_RESTART_COUNTER")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(1);

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

    S11_SERVER
        .set(server)
        .map_err(|_| "S11 server already open".to_string())?;
    Ok(())
}

/// Close the S11 GTP-C server socket
/// Port of sgwc_gtp_close
pub fn gtp_close() {
    if let Some(server) = S11_SERVER.get() {
        server.close();
    }
    log::info!("GTP-C server closed");
}

// ============================================================================
// Datagram dispatch
// ============================================================================

fn handle_datagram(inner: &Arc<GtpcInner>, data: &[u8], peer: SocketAddr) {
    let mut bytes = Bytes::copy_from_slice(data);
    let msg = match Gtp2Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
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
        other => {
            log::error!("[DROP] Unhandled GTPv2-C message type {other} from {peer}");
        }
    }
}

/// Track the peer's restart counter; a change means the peer restarted and
/// its contexts are stale (TS 23.007 Section 18)
fn note_peer_recovery(inner: &Arc<GtpcInner>, peer: SocketAddr, restart_counter: u8) {
    let mut peer_restart = match inner.peer_restart.lock() {
        Ok(p) => p,
        Err(_) => return,
    };
    match peer_restart.insert(peer.ip(), restart_counter) {
        Some(previous) if previous != restart_counter => {
            log::warn!(
                "GTP-C peer {} restarted (restart counter {} -> {}): contexts are stale",
                peer.ip(),
                previous,
                restart_counter
            );
            if let Ok(mut states) = inner.peer_state.lock() {
                states.insert(peer, GtpPathState::Idle);
            }
        }
        _ => {}
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
    if let Some(ref paa) = parsed.paa {
        sess.paa.pdn_type = paa.pdn_type;
        sess.paa.ipv4_addr = paa.ipv4_addr.map(Ipv4Addr::from);
        sess.paa.ipv6_addr = paa.ipv6_addr.map(std::net::Ipv6Addr::from);
    }
    if let Some(ref ambr) = parsed.ambr {
        sess.ambr_ul = ambr.uplink;
        sess.ambr_dl = ambr.downlink;
    }
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

        // Allocate local user-plane endpoints for both directions
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
            tunnel.local_addr = Some(gtpu_addr);
            ctx.tunnel_update(&tunnel);
        }
    }

    // Establish the user-plane session on the SGW-U over Sxa
    let sess = ctx.sess_find_by_id(sess.id).unwrap_or(sess);
    if let Err(e) = pfcp_path::send_session_establishment_request(&sess, seq as u64, None, 0) {
        log::error!("PFCP Session Establishment failed: {e}");
        send_cause_response(
            server,
            peer,
            Gtp2MessageType::CreateSessionResponse,
            ue.mme_s11_teid,
            seq,
            sxa_handler::gtp_cause_from_pfcp(sxa_handler::pfcp_cause::SYSTEM_FAILURE),
        );
        return;
    }

    // NOTE: the triggered response is sent once the local provisioning is
    // complete. When the Sxa transport delivers asynchronous PFCP
    // responses, this send moves to the Session Establishment Response
    // handler in sxa_handler.
    match s11_build::build_create_session_response(&sess, seq, server.restart_counter()) {
        Ok(response) => {
            if let Err(e) = server.send_response(peer, &response) {
                log::error!("Create Session Response to {peer} failed: {e}");
            }
        }
        Err(e) => {
            log::error!("Failed to build Create Session Response: {e}");
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::CreateSessionResponse,
                ue.mme_s11_teid,
                seq,
                gtp_cause::SYSTEM_FAILURE,
            );
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
            if let Some(sess) = sess {
                if let Err(e) = pfcp_path::send_session_deletion_request(&sess, seq as u64, None) {
                    log::error!("PFCP session deletion failed: {e}");
                }
                ctx.sess_remove(sess.id);
            }
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::DeleteSessionResponse,
                ue.mme_s11_teid,
                seq,
                gtp_cause::REQUEST_ACCEPTED,
            );
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

    let teid = ue.map(|u| u.mme_s11_teid).unwrap_or(0);
    match result {
        HandlerResult::ForwardToPgw => {
            // S5-C forwarding toward a live PGW peer is not wired yet; the
            // spec triggered message on failure is the Bearer Resource
            // Failure Indication (TS 29.274 Section 7.2.6)
            send_cause_response(
                server,
                peer,
                Gtp2MessageType::BearerResourceFailureIndication,
                teid,
                seq,
                gtp_cause::SERVICE_NOT_SUPPORTED,
            );
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

    #[test]
    fn test_create_session_request_accepted_over_socket() {
        let server = test_server(1000, 1);
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x01];

        sock.send_to(&csr(0x1001, &imsi).encode(), server.local_addr())
            .unwrap();
        let response = recv_msg(&sock);
        assert_eq!(
            response.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        assert_eq!(response.header.sequence_number, 0x1001);
        // MME TEID from the Sender F-TEID we put in the request
        assert_eq!(response.header.teid, Some(0xAA01));

        let cause =
            Gtp2CauseIe::decode(&response.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap();
        assert_eq!(cause.cause, gtp_cause::REQUEST_ACCEPTED);

        // Sender F-TEID + bearer context with allocated S1-U SGW endpoint
        let sender =
            Gtp2FTeidIe::decode(&response.get_ie(Gtp2IeType::FTeid as u8, 0).unwrap().value)
                .unwrap();
        assert_ne!(sender.teid, 0);
        let bc = response.bearer_context(0).unwrap().unwrap();
        assert_eq!(bc.ebi().unwrap(), 5);
        let s1u = bc.fteid(0).unwrap().unwrap();
        assert_ne!(s1u.teid, 0);
        assert_eq!(s1u.ipv4_addr, Some([10, 99, 0, 1]));

        server.close();
    }

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

    #[test]
    fn test_duplicate_request_answered_from_cache() {
        let server = test_server(1000, 1);
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x03];

        let msg = csr(0x1004, &imsi);
        sock.send_to(&msg.encode(), server.local_addr()).unwrap();
        let first = recv_msg(&sock);

        // Retransmit the identical request (same sequence number)
        sock.send_to(&msg.encode(), server.local_addr()).unwrap();
        let second = recv_msg(&sock);

        assert_eq!(first.encode(), second.encode());
        // The retransmission must not have created a second session
        let ctx = sgwc_self();
        let ue = ctx.ue_find_by_imsi(&imsi).unwrap();
        assert_eq!(ue.sess_ids.len(), 1);

        server.close();
    }

    #[test]
    fn test_full_session_lifecycle_over_socket() {
        let server = test_server(1000, 1);
        let sock = client();
        let imsi = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x04];

        // Create
        sock.send_to(&csr(0x2001, &imsi).encode(), server.local_addr())
            .unwrap();
        let csrsp = recv_msg(&sock);
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
        let mbrsp = recv_msg(&sock);
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
        let rabrsp = recv_msg(&sock);
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
        let dsrsp = recv_msg(&sock);
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
}
