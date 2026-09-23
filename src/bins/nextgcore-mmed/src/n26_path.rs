//! The MME's N26/S10 GTPv2-C endpoint and the idle-mode TAU-with-N26 procedure (#347).
//!
//! TS 23.502 §4.11.1.3.2 ("5GS to EPS Idle mode mobility using N26 interface") layered
//! over TS 23.401 §5.3.3.1 ("Tracking Area Update procedure with Serving GW change").
//! This MME is the **new** node: a UE that has left NG-RAN sends it a TRACKING AREA
//! UPDATE REQUEST, and the UE's context has to be fetched from the AMF that still holds
//! it.
//!
//! ```text
//! UE --TAU REQUEST--> MME
//!                     MME --Context Request (130)--> AMF
//!                     MME <--Context Response (131)-- AMF   (MM Context + PDN Connections)
//!                     MME --Context Acknowledge (132)--> AMF
//!                     MME --Modify Bearer Request--> SGW
//! UE <--TAU ACCEPT--- MME
//! ```
//!
//! # A runtime switch, not a cargo feature
//!
//! `MME_N26_INTERWORKING=1`, default **off**, for the reason `smfd/src/eps_iwk.rs:19-29`
//! records: CI builds default features, so a cargo-feature-gated path is left
//! **uncompiled** and rots. A runtime switch is compiled always and exercised in *both*
//! states by one `cargo test` run — which is what makes #347's criterion 8 ("standalone
//! EPC unchanged with the switch off") something a test asserts rather than a claim about
//! a build CI never performs.
//!
//! # Modelled on `gtp_path`, deliberately
//!
//! Same [`Gtp2XactMgr`], same `OnceLock` server, same blocking socket with a read
//! timeout and a receive thread. N26 and S11 are two GTPv2-C interfaces on one node, and
//! a second transport design would be a second answer to "how long may a GTPv2-C message
//! take" and "when is a peer down". The NAS path that originates a Context Request
//! (`nas_dispatch::emm_tau_request`) is synchronous, so a blocking socket is also what
//! fits the caller.

use crate::context::{mme_self, EpsGuti, MmeContext};
use crate::n26_build::{self, ContextResponseData};
use bytes::Bytes;
use nextgcore_gtp::v2::xact::{Gtp2XactConfig, Gtp2XactMgr};
use nextgcore_gtp::v2::{Gtp2FTeidIe, Gtp2Ie, Gtp2Message, Gtp2MessageType, Gtp2RecoveryIe};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Is the N26 interworking leg enabled for this process?
static N26_ENABLED: AtomicBool = AtomicBool::new(false);

/// The environment variable that turns the leg on.
pub const N26_ENV_VAR: &str = "MME_N26_INTERWORKING";

/// Read the switch from the environment and record it.
///
/// Called once from startup, before anything can ask [`enabled`]. Returns whether the
/// leg is on, so the caller can decide whether to bind a socket.
pub fn init_from_env() -> bool {
    let on = std::env::var(N26_ENV_VAR)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    N26_ENABLED.store(on, Ordering::SeqCst);
    if on {
        log::info!(
            "[MME] N26 interworking ENABLED: an inter-system TAU from 5GS will retrieve the \
             UE context from the old AMF with a GTPv2-C Context Request (TS 23.502 \
             §4.11.1.3.2)"
        );
    } else {
        log::info!(
            "[MME] N26 interworking is OFF ({N26_ENV_VAR} unset): an inter-system TAU from \
             5GS is rejected with EMM cause #9, as TS 24.301 requires of an MME with no \
             N26 interface"
        );
    }
    on
}

/// Whether the N26 leg is enabled.
pub fn enabled() -> bool {
    N26_ENABLED.load(Ordering::SeqCst)
}

/// Test-only: set the switch without going through startup.
///
/// The caller must hold [`crate::gtp_path::S11_TEST_LOCK`] via
/// [`crate::gtp_path::lock_s11`]. This module deliberately declares **no lock of its
/// own**: one lock per switch serialises that switch's writers and orders nothing else,
/// and the globals involved here (`N26_ENABLED`, `N26_SERVER`, `PENDING_CONTEXT_REQUESTS`
/// and the UE/session/bearer pools this procedure writes) overlap the ones S11's lock
/// already guards. #276 showed that a second lock over the same variables *hangs* the
/// suite rather than merely flaking it.
#[cfg(test)]
pub fn set_for_test(on: bool) {
    N26_ENABLED.store(on, Ordering::SeqCst);
}

struct N26Inner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    restart_counter: u8,
    xact: Mutex<Gtp2XactMgr>,
    running: AtomicBool,
}

/// The MME's N26 (and S10) GTPv2-C endpoint.
#[derive(Clone)]
pub struct N26Server {
    inner: Arc<N26Inner>,
}

/// The process-wide N26 server, installed at startup.
///
/// A `OnceLock` rather than a parameter, for the same reason `gtp_path::S11_SERVER` is
/// one: the NAS path that originates a Context Request is synchronous code that threads
/// no transport handle. `None` means the socket was never bound — because the switch is
/// off or no address was configured — and every send then reports that rather than
/// pretending to have transmitted.
static N26_SERVER: OnceLock<N26Server> = OnceLock::new();

/// Install the process-wide N26 server. Returns `false` if one is already installed.
pub fn install_server(server: N26Server) -> bool {
    N26_SERVER.set(server).is_ok()
}

/// The installed N26 server, or `None` when the socket was never bound.
pub fn server() -> Option<&'static N26Server> {
    N26_SERVER.get()
}

/// What a sent Context Request was for, so its response can continue the TAU that
/// started it.
///
/// # Why this exists
///
/// Exactly the shape `gtp_path::PENDING_CREATES` exists for, and for the reason #329
/// records: the response path receives only raw bytes, a message type, a sequence number
/// and a peer. Without a record it cannot tell which UE's TAU a Context Response answers,
/// and would either continue the wrong procedure or none.
///
/// Keyed by **sequence number** because that is what the transaction layer already
/// correlates on ([`Gtp2XactMgr::match_response`]), so there is one notion of "which
/// request is this the answer to" rather than two that can disagree. Keying by the local
/// TEID instead would collapse two concurrent TAUs for the same UE.
///
/// Entries are **taken**, not read: a response consumes its record, so a retransmitted or
/// duplicated Context Response cannot drive the TAU continuation twice — which would send
/// the UE two TAU ACCEPTs and install its bearers twice.
#[derive(Debug, Clone, Copy)]
pub struct PendingContextRequest {
    /// The UE whose context is being fetched.
    pub mme_ue_id: u64,
    /// The eNB UE context the TAU ACCEPT has to be answered on.
    pub enb_ue_id: u64,
}

static PENDING_CONTEXT_REQUESTS: OnceLock<Mutex<HashMap<u32, PendingContextRequest>>> =
    OnceLock::new();

fn pending_context_requests() -> &'static Mutex<HashMap<u32, PendingContextRequest>> {
    PENDING_CONTEXT_REQUESTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Take the record for the Context Request at `seq`, if this MME sent one.
///
/// `None` means either a response to a request this MME did not send, or one whose record
/// a first copy already consumed. Both are reasons NOT to continue the procedure, which
/// is why the caller treats them the same way.
pub fn take_pending_context_request(seq: u32) -> Option<PendingContextRequest> {
    pending_context_requests().lock().ok()?.remove(&seq)
}

fn record_pending_context_request(seq: u32, pending: PendingContextRequest) {
    if let Ok(mut map) = pending_context_requests().lock() {
        map.insert(seq, pending);
    }
}

/// Record a pending Context Request without sending anything.
///
/// Test-only. The response path's behaviour turns entirely on whether a record exists and
/// which UE it names, and driving that through a real socket would make every
/// response-side test also a transport test. Callers hold
/// [`crate::gtp_path::S11_TEST_LOCK`].
#[cfg(test)]
pub fn record_pending_context_request_for_test(seq: u32, pending: PendingContextRequest) {
    record_pending_context_request(seq, pending);
}

/// Drop every pending record. Declared beside the map, not in a `mod tests`, per #308.
#[cfg(test)]
pub fn clear_pending_context_requests_for_test() {
    if let Ok(mut map) = pending_context_requests().lock() {
        map.clear();
    }
}

impl N26Server {
    /// Bind the N26 socket and start the receive and retransmission loops.
    pub fn open(
        bind: SocketAddr,
        config: Gtp2XactConfig,
        restart_counter: u8,
    ) -> Result<Self, String> {
        let socket = UdpSocket::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
        // A read timeout rather than a non-blocking socket, so the receive thread can
        // observe `running` and exit at shutdown instead of spinning — same as S11's.
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| e.to_string())?;
        let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

        let inner = Arc::new(N26Inner {
            socket,
            local_addr,
            restart_counter,
            xact: Mutex::new(Gtp2XactMgr::new(config)),
            running: AtomicBool::new(true),
        });

        {
            let inner = inner.clone();
            std::thread::Builder::new()
                .name("mme-n26-recv".into())
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
                                    log::error!("N26 recv error: {e}");
                                }
                            }
                        }
                    }
                })
                .map_err(|e| e.to_string())?;
        }

        // T3-RESPONSE / N3-REQUESTS (TS 29.274 §7.6). A Context Request that is never
        // answered has to time out, or the UE's TAU hangs with no reject and the UE
        // waits out its own T3430 instead of re-attaching.
        {
            let inner = inner.clone();
            std::thread::Builder::new()
                .name("mme-n26-rtx".into())
                .spawn(move || {
                    while inner.running.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(20));
                        let poll = {
                            let Ok(mut xact) = inner.xact.lock() else {
                                continue;
                            };
                            xact.poll(std::time::Instant::now())
                        };
                        for (peer, encoded) in poll.retransmits {
                            log::warn!("N26 T3 expiry: retransmitting to {peer}");
                            if let Err(e) = inner.socket.send_to(&encoded, peer) {
                                log::error!("N26 retransmit to {peer} failed: {e}");
                            }
                        }
                        for xact in poll.exhausted {
                            log::error!(
                                "N26 N3 exhausted: AMF {} not responding (type={}, seq={}). The \
                                 UE's inter-system TAU cannot be completed; its pending record \
                                 is dropped so a late response cannot drive it.",
                                xact.peer,
                                xact.message_type,
                                xact.sequence_number
                            );
                            // Dropped here and not left to rot: a record that outlives its
                            // transaction would let a response arriving after N3 exhaustion
                            // resume a procedure the MME has already given up on, and the UE
                            // would get a TAU ACCEPT long after it stopped waiting.
                            take_pending_context_request(xact.sequence_number);
                        }
                    }
                })
                .map_err(|e| e.to_string())?;
        }

        log::info!("MME N26 GTP-C server listening on {local_addr}");
        Ok(Self { inner })
    }

    /// Stop the receive and retransmission loops.
    pub fn close(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Local bound address — the one the MME puts in its own F-TEID.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Outstanding transactions awaiting a triggered message.
    pub fn outstanding(&self) -> usize {
        self.inner.xact.lock().map(|x| x.outstanding()).unwrap_or(0)
    }

    /// Allocate a GTPv2-C sequence number for an initial message.
    pub fn alloc_sequence(&self) -> u32 {
        self.inner
            .xact
            .lock()
            .map(|mut x| x.alloc_sequence())
            .unwrap_or(1)
    }

    /// Send an initial (request) message and arm T3/N3.
    pub fn send_request(&self, peer: SocketAddr, msg: &Gtp2Message) -> Result<u32, String> {
        let encoded = Bytes::from(msg.encode().to_vec());
        let seq = msg.header.sequence_number;
        {
            let mut xact = self.inner.xact.lock().map_err(|e| e.to_string())?;
            xact.register_request(seq, msg.header.message_type, peer, encoded.clone(), 0);
        }
        self.inner
            .socket
            .send_to(&encoded, peer)
            .map_err(|e| e.to_string())?;
        log::debug!(
            "N26 TX request type={} seq={seq} to {peer} len={}",
            msg.header.message_type,
            encoded.len()
        );
        Ok(seq)
    }

    /// Send a triggered (response) message, caching it so a retransmitted request is
    /// answered identically.
    pub fn send_response(&self, peer: SocketAddr, msg: &Gtp2Message) -> Result<(), String> {
        let encoded = Bytes::from(msg.encode().to_vec());
        if let Ok(mut xact) = self.inner.xact.lock() {
            xact.cache_response(peer, msg.header.sequence_number, encoded.clone());
        }
        self.inner
            .socket
            .send_to(&encoded, peer)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Route an N26 datagram.
///
/// Correlation happens FIRST and only then dispatch, the same ordering
/// `gtp_path::handle_datagram` uses and for the same reason: an uncorrelated response is
/// one this MME did not ask for, and letting it reach the procedure would allow a stray
/// datagram to install a UE's security context.
fn handle_datagram(inner: &Arc<N26Inner>, data: &[u8], peer: SocketAddr) {
    let mut bytes = Bytes::copy_from_slice(data);
    let msg = match Gtp2Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            log::error!("[DROP] cannot decode N26 datagram from {peer}: {e}");
            return;
        }
    };
    let msg_type = msg.header.message_type;
    let seq = msg.header.sequence_number;

    // Echo is path management and needs no session state (TS 29.274 §7.1.1).
    if msg_type == Gtp2MessageType::EchoRequest as u8 {
        let reply = Gtp2Message::echo_response(seq, inner.restart_counter);
        if let Err(e) = inner.socket.send_to(&reply.encode(), peer) {
            log::error!("N26 Echo Response to {peer} failed: {e}");
        }
        return;
    }
    if msg_type == Gtp2MessageType::EchoResponse as u8 {
        return;
    }

    let matched = match inner.xact.lock() {
        Ok(mut xact) => xact.match_response(seq, msg_type),
        Err(_) => None,
    };

    if matched.is_some() {
        if msg_type == Gtp2MessageType::ContextResponse as u8 {
            handle_context_response(&msg, seq, peer);
        } else {
            log::info!(
                "N26 triggered message type={msg_type} seq={seq} from {peer} correlated but \
                 not acted on: this MME has no handler for it"
            );
        }
        return;
    }

    log::info!(
        "N26 message type={msg_type} seq={seq} from {peer} matches no outstanding \
         transaction: either an initial message this MME does not serve (it is the NEW \
         node in the only N26 procedure it implements) or a late duplicate response"
    );
}

/// Send a **Context Request** to the old AMF for a UE performing an inter-system TAU
/// (TS 23.401 §5.3.3.1 step 4).
///
/// Returns the sequence number on success. Every failure is named rather than silently
/// swallowed, because the caller has to decide between continuing the TAU and rejecting
/// it — and a Context Request that was never sent must not leave the UE waiting.
///
/// # Production caller
///
/// [`crate::nas_dispatch::emm_tau_request`], reached from
/// `nas_dispatch::emm_message_dispatch`'s `emm_type::TAU_REQUEST` arm — a live S1AP NAS
/// path, not a test-only function. "Correct but unreachable" is this tree's commonest
/// defect, so this is stated where a reader will look for it.
pub fn send_context_request(
    ctx: &MmeContext,
    mme_ue_id: u64,
    enb_ue_id: u64,
    guti: &EpsGuti,
    complete_tau_request: &[u8],
    ue_validated: bool,
) -> Result<u32, String> {
    if !enabled() {
        return Err(format!(
            "N26 interworking is off ({N26_ENV_VAR} unset), so no Context Request is sent"
        ));
    }
    let server = server().ok_or_else(|| {
        "no N26 socket bound: mme.n26.server is unset or the bind failed".to_string()
    })?;
    let peer = *ctx
        .amf_n26_list
        .first()
        .ok_or_else(|| "no AMF N26 peer configured (mme.n26.client.amf)".to_string())?;

    let seq = server.alloc_sequence();
    // The MME's own F-TEID: the address the socket is actually bound to, so the AMF
    // answers where this MME listens. The TEID is the local S11 TEID space's -- the
    // sequence number is reused as the N26 TEID because this MME keys the response by
    // sequence number anyway (see `PendingContextRequest`), and a second TEID allocator
    // would be a second identity space for one transaction.
    let local = Gtp2FTeidIe::new_ipv4(
        n26_build::S10_N26_MME_GTP_C,
        seq,
        match server.local_addr().ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            std::net::IpAddr::V6(_) => {
                return Err(
                    "the N26 socket is bound to an IPv6 address; TS 29.274 §8.22 allows it \
                     but this MME builds an IPv4 F-TEID only, so the AMF would be told an \
                     address it cannot reach"
                        .to_string(),
                )
            }
        },
    );

    let mut msg =
        n26_build::build_context_request(seq, guti, complete_tau_request, &local, ue_validated);
    // Recovery, so the AMF learns this MME's restart counter (TS 23.007 §18) on the
    // first message of the interface rather than only from an Echo.
    let mut rec = bytes::BytesMut::new();
    Gtp2RecoveryIe::new(server.inner.restart_counter).encode(&mut rec, 0);
    let mut rec = rec.freeze();
    if let Ok(ie) = Gtp2Ie::decode(&mut rec) {
        msg.add_ie(ie);
    }

    // Recorded BEFORE the send, so a send that fails after the datagram left the socket
    // cannot lose the record of what it was for -- the #359 lesson, applied the same way
    // `gtp_path::send_create_session_request` applies it.
    record_pending_context_request(
        seq,
        PendingContextRequest {
            mme_ue_id,
            enb_ue_id,
        },
    );

    match server.send_request(peer, &msg) {
        Ok(seq) => {
            log::info!(
                "N26 Context Request sent to AMF {peer} (seq={seq}) for 4G-GUTI \
                 (MME GID={:#06x}, MME code={:#04x}, M-TMSI={:#010x}) mapped from the UE's \
                 5G-GUTI; awaiting MM context and PDN connections (TS 23.502 §4.11.1.3.2 \
                 step 4)",
                guti.mme_gid,
                guti.mme_code,
                guti.m_tmsi
            );
            Ok(seq)
        }
        Err(e) => {
            // The record is useless now and would let a stray datagram resume a TAU
            // whose request never reached the AMF.
            take_pending_context_request(seq);
            Err(e)
        }
    }
}

/// Apply a **Context Response** and continue the TAU (TS 23.401 §5.3.3.1 steps 5-8).
///
/// This is where the transfer becomes real: without the write-back below, the MME would
/// have decoded a correct message and kept no record of it — the defect #223 found in
/// smfd, where `create_session` mutated a clone returned by `sess_add_by_apn` so the wire
/// response was right while the SMF held nothing.
fn handle_context_response(msg: &Gtp2Message, seq: u32, peer: SocketAddr) {
    let data = match n26_build::parse_context_response(msg) {
        Ok(data) => data,
        Err(e) => {
            log::error!("N26 Context Response from {peer} (seq={seq}) unparsable: {e}");
            return;
        }
    };

    let Some(pending) = take_pending_context_request(seq) else {
        log::debug!(
            "N26 Context Response (seq={seq}) has no pending record; nothing continued. \
             Either this MME did not send the request or a first copy already consumed it."
        );
        return;
    };

    let ctx = mme_self();

    if !data.accepted() {
        // TS 29.274 §7.3.6 names "IMSI/IMEI not known", "P-TMSI Signature mismatch",
        // "User authentication failed" and "Target access restricted for the subscriber".
        // Any of them means the old AMF will not hand the context over, so the UE has to
        // re-attach: EMM cause #9 is what TS 24.301 §5.5.3.2.5 gives for an identity the
        // network cannot derive.
        log::warn!(
            "N26 Context Response from {peer} REFUSED the transfer (cause={}); the UE's \
             inter-system TAU is rejected so it re-attaches rather than waiting",
            data.cause
        );
        reject_inter_system_tau(ctx, pending, "the old AMF refused the context transfer");
        return;
    }

    if let Err(why) = install_transferred_context(ctx, pending.mme_ue_id, &data) {
        log::error!(
            "N26 Context Response from {peer} was accepted by the AMF but could not be \
             installed: {why}. The UE's TAU is rejected rather than accepted with a partial \
             context, which would leave it believing it has bearers this MME cannot serve."
        );
        reject_inter_system_tau(
            ctx,
            pending,
            "the transferred context could not be installed",
        );
        return;
    }

    // Step 7: Context Acknowledge. Sent only after the context is installed, so an
    // acknowledge cannot tell the AMF to release state this MME then failed to take over.
    if let Some(server) = server() {
        let amf_teid = data.amf_fteid.as_ref().map(|f| f.teid).unwrap_or(0);
        let ack =
            n26_build::build_context_acknowledge(seq, amf_teid, n26_build::CAUSE_REQUEST_ACCEPTED);
        if let Err(e) = server.send_response(peer, &ack) {
            log::error!(
                "N26 Context Acknowledge to {peer} failed: {e}. The old AMF will keep this \
                 UE's context until its guard timer expires (TS 23.502 §4.11.1.3.2 step 6) \
                 and will not discard buffered data (TS 23.401 §5.3.3.1 step 5)."
            );
        } else {
            log::info!("N26 Context Acknowledge sent to AMF {peer} (seq={seq})");
        }
    }

    // Steps 8-11 then 16-18: Modify Bearer toward the SGW for the transferred bearers,
    // then the TAU ACCEPT. Both are the existing S11 and NAS paths -- this procedure
    // supplies the context they were always missing for an inter-system move.
    crate::nas_dispatch::continue_inter_system_tau(ctx, pending.mme_ue_id, pending.enb_ue_id);
}

/// Install a transferred context, for tests, through the **production** function.
///
/// Exposed rather than reimplemented so the end-to-end test drives the same write-back the
/// receive loop drives. A test that installed the context itself would prove only that the
/// test can write to the pools — and the write-back is exactly where #223 found smfd
/// mutating a detached clone while the wire response looked right.
#[cfg(test)]
pub fn install_transferred_context_for_test(
    ctx: &MmeContext,
    mme_ue_id: u64,
    data: &ContextResponseData,
) -> Result<(), String> {
    install_transferred_context(ctx, mme_ue_id, data)
}

/// Install a transferred MM context and its PDN connections onto this MME's UE.
///
/// Returns `Err` naming what was wrong rather than installing part of it: a session with
/// no bearers, or bearers with no security context, is a UE the MME would accept and then
/// be unable to serve.
fn install_transferred_context(
    ctx: &MmeContext,
    mme_ue_id: u64,
    data: &ContextResponseData,
) -> Result<(), String> {
    let mm_context = data
        .mm_context
        .as_ref()
        .ok_or_else(|| "accepted Context Response carries no MM Context".to_string())?;

    // Decode every PDN connection BEFORE writing anything, so a malformed second
    // connection cannot leave the first half-installed.
    let mut connections = Vec::new();
    for pdn in &data.pdn_connections {
        connections.push(n26_build::transferred_pdn_connection(pdn)?);
    }
    if connections.is_empty() {
        return Err(
            "accepted Context Response carries no PDN Connection: TS 29.274 §7.3.6 makes it \
             conditional on the UE having at least one PDU session, so an accept with none \
             describes a UE with nothing to transfer"
                .to_string(),
        );
    }

    // The security context and identity, under the pool write lock. `&mut` rather than a
    // clone-and-put-back: `mme_ue_find_by_id` hands out a CLONE, and mutating that is the
    // single most repeated defect in this tree (#223, #361).
    {
        let mut pool = ctx
            .mme_ue_pool
            .write()
            .map_err(|_| "UE pool poisoned".to_string())?;
        let mme_ue = pool
            .get_mut(&mme_ue_id)
            .ok_or_else(|| format!("UE {mme_ue_id} is gone"))?;
        n26_build::apply_mm_context(mme_ue, mm_context);
        if let Some(imsi) = &data.imsi_bcd {
            mme_ue.imsi_bcd = imsi.clone();
            let encoded = n26_build::string_to_bcd(imsi);
            let len = encoded.len().min(mme_ue.imsi.len());
            mme_ue.imsi[..len].copy_from_slice(&encoded[..len]);
            mme_ue.imsi_len = len;
        }
        if let Some(mei) = (!mm_context.mei.is_empty()).then_some(&mm_context.mei) {
            let len = mei.len().min(mme_ue.imeisv.len());
            mme_ue.imeisv[..len].copy_from_slice(&mei[..len]);
            mme_ue.imeisv_len = len;
        }
    }

    // Then the sessions and bearers.
    for conn in &connections {
        let sess_id = ctx.sess_add(mme_ue_id, 0);
        {
            let mut pool = ctx
                .sess_pool
                .write()
                .map_err(|_| "session pool poisoned".to_string())?;
            let sess = pool
                .get_mut(&sess_id)
                .ok_or_else(|| format!("session {sess_id} vanished after sess_add"))?;
            sess.apn = conn.apn.clone();
            sess.pgw_s5c_teid = conn.pgw_s5c_teid;
            if let Some(v4) = conn.pgw_s5c_ipv4 {
                // `context::IpAddr` is mmed's own optional-v4/optional-v6 pair, not
                // `std::net::IpAddr`: an S5/S8 endpoint may be reachable over either
                // family or both, and `Option<Ipv4Addr>` alone cannot say "both".
                sess.pgw_s5c_ip = crate::context::IpAddr {
                    ipv4: Some(v4),
                    ipv6: None,
                };
            }
            sess.ambr.uplink = conn.ambr_uplink;
            sess.ambr.downlink = conn.ambr_downlink;
            if let Some(v4) = conn.ue_ipv4 {
                // Table 7.3.6-2 makes the IPv4 Address IE conditional and says it "shall
                // not be included if no IPv4 Address is assigned", so its presence IS the
                // statement that the PDN connection is IPv4. IPv6 over N26 would need the
                // instance-1 IP Address IE, which this AMF does not produce (the 5GC side
                // allocates IPv4 only), so claiming Ipv4v6 here would tell the UE it has a
                // prefix nobody assigned.
                sess.paa.pdn_type = crate::esm_build::PdnType::Ipv4;
                sess.paa.addr = v4;
            }
        }

        for bearer in &conn.bearers {
            let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
            {
                let mut pool = ctx
                    .bearer_pool
                    .write()
                    .map_err(|_| "bearer pool poisoned".to_string())?;
                let b = pool
                    .get_mut(&bearer_id)
                    .ok_or_else(|| format!("bearer {bearer_id} vanished after bearer_add"))?;
                b.ebi = bearer.ebi;
                b.qos.qci = bearer.qci;
                if let Some(teid) = bearer.pgw_s5u_teid {
                    b.pgw_s5u_teid = teid;
                }
                if let Some(v4) = bearer.pgw_s5u_ipv4 {
                    b.pgw_s5u_ip = crate::context::IpAddr {
                        ipv4: Some(v4),
                        ipv6: None,
                    };
                }
            }
            // The session has to KNOW its bearers: `nas_dispatch` reads
            // `sess.bearer_list` to build the TAU ACCEPT's EPS bearer context status, so
            // a bearer in the pool but not on the list is a bearer the UE is never told
            // about.
            if let Ok(mut pool) = ctx.sess_pool.write() {
                if let Some(sess) = pool.get_mut(&sess_id) {
                    sess.bearer_list.push(bearer_id);
                }
            }
        }

        if let Ok(mut pool) = ctx.mme_ue_pool.write() {
            if let Some(mme_ue) = pool.get_mut(&mme_ue_id) {
                mme_ue.sess_list.push(sess_id);
                mme_ue.num_of_session = mme_ue.sess_list.len();
            }
        }

        log::info!(
            "N26: installed transferred PDN connection APN='{}' (linked EBI {}, PGW-C \
             S5/S8 TEID={:#010x}, {} bearer(s)) on UE {mme_ue_id}",
            conn.apn,
            conn.linked_ebi,
            conn.pgw_s5c_teid,
            conn.bearers.len()
        );
    }

    Ok(())
}

/// Reject an inter-system TAU that could not be completed.
///
/// EMM cause **#9** "UE identity cannot be derived by the network", which is not a choice:
/// TS 24.301 (`24301-k00.txt:18854-18858`) requires it of an MME that cannot serve an
/// inter-system change from N1 mode to S1 mode, and case (c) at `:18876-18878` repeats it
/// for the failed-verification path.
pub fn reject_inter_system_tau(ctx: &MmeContext, pending: PendingContextRequest, why: &str) {
    log::info!(
        "Rejecting the inter-system TAU for UE {} with EMM cause #9 'UE identity cannot \
         be derived by the network' ({why}). TS 24.301 requires cause #9 of an MME that \
         cannot complete an N1-to-S1 change, so the UE re-attaches on EPS rather than \
         retrying a move that cannot succeed.",
        pending.mme_ue_id
    );
    let Some(enb_ue) = ctx.enb_ue_find_by_id(pending.enb_ue_id) else {
        log::warn!("the eNB UE context for the rejected TAU is gone; no TAU Reject can be sent");
        return;
    };
    let Ok(mut pool) = ctx.mme_ue_pool.write() else {
        return;
    };
    let Some(mme_ue) = pool.get_mut(&pending.mme_ue_id) else {
        return;
    };
    if let Err(e) = crate::nas_path::nas_eps_send_tau_reject(
        &enb_ue,
        mme_ue,
        crate::emm_build::EmmCause::UeIdentityCannotBeDerived,
    ) {
        log::error!("TAU Reject send failed: {e}");
    }
}

/// Bind the N26 socket from configuration and install it process-wide.
///
/// Returns `Ok(())` and logs why when the leg is off or no address is configured: an MME
/// with no N26 address is a standalone-EPC deployment, and refusing to start would break
/// every existing config that never needed the socket — which is exactly #347's criterion
/// 8.
pub fn n26_open() -> Result<(), String> {
    if !init_from_env() {
        return Ok(());
    }
    let ctx = mme_self();
    let Some(bind) = ctx.n26_list.first().copied() else {
        log::warn!(
            "{N26_ENV_VAR} is set but no mme.n26.server address is configured: the N26 \
             interface is NOT bound, so an inter-system TAU is still rejected with EMM \
             cause #9"
        );
        return Ok(());
    };
    if ctx.amf_n26_list.is_empty() {
        log::warn!(
            "{N26_ENV_VAR} is set and mme.n26.server is bound, but no mme.n26.client.amf \
             peer is configured: a Context Request has nowhere to go"
        );
    }
    // The restart counter S11 already advertises, READ from the installed server rather
    // than derived again. TS 23.007 §18 makes the counter a property of the node, and
    // `gtp_path::advance_persistent_restart_counter` increments and persists — so calling
    // it a second time here would have N26 advertise one number and S11 another, telling
    // a peer the MME had restarted between binding its two sockets.
    //
    // `gtp_open` runs before this (see `main.rs`), so the server is installed. Falling
    // back to 0 if it is not: TS 23.007 §18 treats 0 as "restart counter not available",
    // which is the truthful answer when there is no S11 socket to have derived one.
    let restart_counter = crate::gtp_path::server()
        .map(|s| s.restart_counter())
        .unwrap_or(0);
    let server = N26Server::open(bind, Gtp2XactConfig::default(), restart_counter)?;
    if !install_server(server) {
        log::warn!("an N26 server is already installed; this one is dropped");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gtp_path::lock_s11;

    /// With the switch off nothing is sent, and the reason names the switch.
    ///
    /// This is #347's criterion 8 as an assertion rather than a claim: the code is
    /// compiled in (a runtime switch, not a cargo feature), and it still declines.
    #[test]
    fn with_the_switch_off_no_context_request_is_sent() {
        let _guard = lock_s11();
        set_for_test(false);
        let ctx = mme_self();
        let err = send_context_request(ctx, 1, 1, &EpsGuti::default(), &[0x07], true)
            .expect_err("the switch is off");
        assert!(
            err.contains(N26_ENV_VAR),
            "the refusal must name the switch so an operator can find it, got {err:?}"
        );
        assert!(
            !enabled(),
            "and the switch must read as off, which is what iwk_n26_posture reads"
        );
    }

    /// The switch reads back what was set, in both directions.
    #[test]
    fn the_n26_switch_reads_back_in_both_directions() {
        let _guard = lock_s11();
        set_for_test(true);
        assert!(enabled());
        set_for_test(false);
        assert!(!enabled());
    }

    /// A pending record is TAKEN, so a duplicated Context Response cannot drive the TAU
    /// twice.
    ///
    /// Driving it twice would send the UE two TAU ACCEPTs and install its bearers twice,
    /// so the idempotency here is not hygiene — it is the difference between one session
    /// and two for the same APN.
    #[test]
    fn a_pending_context_request_is_consumed_by_the_first_response() {
        let _guard = lock_s11();
        clear_pending_context_requests_for_test();
        record_pending_context_request_for_test(
            0x5347,
            PendingContextRequest {
                mme_ue_id: 11,
                enb_ue_id: 22,
            },
        );
        let first = take_pending_context_request(0x5347).expect("the first take succeeds");
        assert_eq!(first.mme_ue_id, 11);
        assert_eq!(first.enb_ue_id, 22);
        assert!(
            take_pending_context_request(0x5347).is_none(),
            "a second Context Response with the same sequence number must find nothing: \
             continuing twice would install the UE's bearers twice"
        );
        clear_pending_context_requests_for_test();
    }

    /// **#347 criterion 4**: the idle-mode TAU-with-N26 transfer completes, end to end,
    /// across BOTH daemons — and the transferred context is readable from the MME's store
    /// afterwards.
    ///
    /// # Why this drives amfd rather than a fixture
    ///
    /// The Context Response is built by `nextgcore_amfd::n26_path::build_context_response`,
    /// the **real** producer, from a real `AmfUe` — and its MM Context by the real
    /// `build_mm_context`. A Context Response hand-written in this crate would agree with
    /// this crate's parser by construction and could not catch the two sides drifting; that
    /// is the whole point of the strict-peer pattern lmfd, pcfd and udmd already use.
    ///
    /// # Every assertion is POSITIVE
    ///
    /// Not "no error was returned" — a negative assertion is satisfied by every path that
    /// never arrives, which is exactly the trap that let a dead MBS manager and a caller-less
    /// `udm_nrf_register` ship. So each of the five things a transfer is *for* is read back
    /// out of the MME's own pools:
    ///
    /// 1. the **IMSI** the AMF holds;
    /// 2. the **K_ASME'**, compared against an independently computed
    ///    `kdf_kasme_prime(kamf, ul_count)` so a zeroed or copied key fails;
    /// 3. the **EBI** on a real `MmeBearer`;
    /// 4. the **PGW-C S5/S8 control TEID** on a real `MmeSess`;
    /// 5. the **APN**.
    #[test]
    fn an_idle_mode_tau_with_n26_transfers_the_ue_context_to_the_mme() {
        use nextgcore_gtp::v2::{
            Gtp2AmbrIe, Gtp2ApnIe, Gtp2FTeidIe, Gtp2Message, Gtp2PdnConnectionIe,
        };

        let _guard = lock_s11();
        clear_pending_context_requests_for_test();

        // ---------------- The AMF side: a UE it still serves ----------------
        //
        // Literal values distinct from every sibling test's: the MME context is
        // process-global and keyed by identity, so a shared IMSI or EBI would let two tests
        // resolve each other's UE. `0x347` prefixes mark them as this test's.
        const IMSI: &str = "001010000000347";
        const EBI: u8 = 9;
        const PGW_TEID: u32 = 0x0347_0BC1;
        const APN: &str = "n26test";
        const KAMF: [u8; 32] = [0x47; 32];
        const UL_COUNT: u32 = 0x0347;

        let mut amf_ue = nextgcore_amfd::context::AmfUe::new(0x347_0100, 100);
        amf_ue.supi = Some(format!("imsi-{IMSI}"));
        amf_ue.kamf = KAMF;
        amf_ue.ul_count = UL_COUNT;
        amf_ue.dl_count = 0x0348;
        amf_ue.nas.amf_ksi = 6;
        amf_ue.selected_enc_algorithm = 2;
        amf_ue.selected_int_algorithm = 1;

        // The PDN connection the AMF assembles from what the SMF returned. Built through
        // the library's grouped-IE API, i.e. the same calls `pdn_connection_from_smf_container`
        // makes, and carrying a REAL PGW-C control-plane F-TEID so the test can assert the
        // MME recorded it. (Production sends the reserved value because this tree's SMF does
        // not supply one; that ceiling is asserted separately in amfd's own tests, and using
        // a real value here is what makes assertion 4 able to fail.)
        let mut pdn = Gtp2PdnConnectionIe::new();
        pdn.add_ie(Gtp2ApnIe::from_string(APN).to_ie(0));
        pdn.add_ie(nextgcore_gtp::v2::Gtp2EbiIe::new(EBI).to_ie(0));
        // Interface type 7 = S5/S8 PGW GTP-C (TS 29.274 Table 8.22-1).
        pdn.add_ie(Gtp2FTeidIe::new_ipv4(7, PGW_TEID, [10, 45, 3, 47]).to_ie(0));
        let mut bearer = nextgcore_gtp::v2::Gtp2BearerContextIe::new();
        bearer.set_ebi(EBI);
        bearer.set_bearer_qos(&nextgcore_gtp::v2::Gtp2BearerQosIe::new(9, 0, 0, 0, 0));
        pdn.add_ie(bearer.to_ie(0));
        pdn.add_ie(Gtp2AmbrIe::new(1_000, 2_000).to_ie(0));

        // The AMF's REAL Context Response builder.
        let response = nextgcore_amfd::n26_path::build_context_response(
            0x347,
            0xDEAD_0347,
            &amf_ue,
            "10.0.0.47:2124".parse().unwrap(),
            std::slice::from_ref(&pdn),
        );

        // ---------------- The wire ----------------
        //
        // Encoded and decoded, so this is a transfer over GTPv2-C rather than a struct
        // handed between two modules. A bug in the message framing fails here.
        let encoded = response.encode();
        let mut bytes = bytes::Bytes::from(encoded.to_vec());
        let on_the_wire =
            Gtp2Message::decode(&mut bytes).expect("the AMF's Context Response decodes");
        assert_eq!(
            on_the_wire.header.message_type, 131,
            "what crossed the wire must be a Context Response (TS 29.274 type 131)"
        );

        // ---------------- The MME side: parse and install ----------------
        let data = crate::n26_build::parse_context_response(&on_the_wire)
            .expect("the MME must parse the AMF's Context Response");
        assert!(
            data.accepted(),
            "the AMF accepted, so the MME must read the cause as Request Accepted"
        );

        let ctx = mme_self();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 0x347);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);

        // Through the PRODUCTION install path, not a test reimplementation of it.
        install_transferred_context_for_test(ctx, mme_ue_id, &data)
            .expect("the transferred context must install");

        // ---------------- Assertions: read it back OUT of the MME ----------------

        let mme_ue = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .expect("the UE must still be in the MME's pool");

        // 1. The IMSI. This is the subscriber identity the MME has, and before the transfer
        //    it had none — which is why the pre-#347 TAU path rejected the UE.
        assert_eq!(
            mme_ue.imsi_bcd, IMSI,
            "the transferred IMSI must be readable from the MME's UE context"
        );

        // 2. The mapped EPS security context, against an INDEPENDENT derivation. A stubbed,
        //    zeroed or copied-from-K_AMF key fails here and nowhere else.
        let expected_kasme = nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime(&KAMF, UL_COUNT);
        assert_eq!(
            mme_ue.kasme, expected_kasme,
            "the MME's K_ASME must be K_ASME' = KDF(K_AMF, FC 0x73, uplink NAS COUNT) per \
             TS 33.501 Annex A.14.1 -- computed here from K_AMF and the COUNT, not read from \
             the message, so a zeroed or copied key cannot pass"
        );
        assert_ne!(
            mme_ue.kasme, KAMF,
            "and it must NOT be K_AMF itself: that would be a key the AMF still uses"
        );
        assert_eq!(
            mme_ue.nas_eps.mme_ksi.tsc, 1,
            "TSC = 1 marks the context MAPPED, not native (TS 33.501 §8.6.1)"
        );
        assert_eq!(
            mme_ue.nas_eps.mme_ksi.ksi, 6,
            "the eKSI value is the ngKSI's"
        );
        assert!(
            mme_ue.security_context_available,
            "the MME must now hold an established security context: without this the TAU \
             path rejects the very UE whose context it just fetched"
        );

        // 3. and 5. The session: APN and the PGW-C's S5/S8 control-plane TEID.
        assert_eq!(
            mme_ue.sess_list.len(),
            1,
            "one transferred PDN connection must produce exactly one MME session"
        );
        let sess = ctx
            .sess_find_by_id(mme_ue.sess_list[0])
            .expect("the session must be in the MME's pool");
        assert_eq!(sess.apn, APN, "the transferred APN must be readable");
        assert_eq!(
            sess.pgw_s5c_teid, PGW_TEID,
            "the PGW-C's S5/S8 control-plane TEID must be recorded: every later Modify \
             Bearer or Delete Session for this PDN connection is addressed to it, so a \
             session that decoded correctly and stored nothing is the #223 defect exactly"
        );
        assert_eq!(
            sess.pgw_s5c_ip.ipv4,
            Some([10, 45, 3, 47]),
            "and the PGW-C's address with it"
        );
        // TS 29.274 §8.7 AMBR is kbps; MmeSess::ambr is bps.
        assert_eq!(
            sess.ambr.uplink, 1_000_000,
            "the APN-AMBR must be converted from the IE's kbps to the context's bps"
        );
        assert_eq!(sess.ambr.downlink, 2_000_000);

        // 4. The bearer, with its EBI and QoS.
        assert_eq!(
            sess.bearer_list.len(),
            1,
            "the bearer must be on the SESSION's list, not merely in the pool: \
             `continue_inter_system_tau` reads `sess.bearer_list` to build the TAU ACCEPT's \
             EPS bearer context status, so a bearer missing from the list is one the UE is \
             never told about"
        );
        let installed = ctx
            .bearer_find_by_id(sess.bearer_list[0])
            .expect("the bearer must be in the MME's pool");
        assert_eq!(
            installed.ebi, EBI,
            "the transferred EPS Bearer Identity must be readable from the MME's bearer"
        );
        assert_eq!(
            installed.qos.qci, 9,
            "and its QCI, which the SMF mapped from the 5QI per TS 23.502 Annex C"
        );

        clear_pending_context_requests_for_test();
    }

    /// An accepted Context Response with **no** PDN connection is REFUSED, not half-installed.
    ///
    /// A UE accepted onto EPS with a security context and no bearers is worse than one
    /// rejected: it completes a TAU and then has no PDN connection to carry traffic, and the
    /// UE has no way to discover that except by timing out.
    #[test]
    fn an_accepted_response_with_no_pdn_connection_is_refused() {
        let _guard = lock_s11();

        let mut kasme = [0u8; 32];
        kasme[0] = 0x47;
        let data = ContextResponseData {
            cause: crate::n26_build::CAUSE_REQUEST_ACCEPTED,
            imsi_bcd: Some("001010000000348".to_string()),
            mm_context: Some(nextgcore_gtp::v2::Gtp2MmContextIe {
                kasme,
                ..Default::default()
            }),
            pdn_connections: Vec::new(),
            amf_fteid: None,
        };

        let ctx = mme_self();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 0x348);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);

        let err = install_transferred_context_for_test(ctx, mme_ue_id, &data)
            .expect_err("an accept with no PDN connection must not install");
        assert!(
            err.contains("PDN Connection"),
            "the error must name what was missing, got {err:?}"
        );
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id)
                .expect("the UE is still there")
                .sess_list
                .is_empty(),
            "and no session may be left behind: a UE with a security context and no bearer \
             would complete a TAU and then carry no traffic"
        );
    }

    /// An accepted Context Response with **no MM Context** is refused.
    ///
    /// §7.3.6 makes the MM Context conditional on "Request Accepted", so an accept without
    /// one is self-contradictory — and installing the bearers anyway would give the UE
    /// bearers it cannot integrity-protect any NAS message to use.
    #[test]
    fn an_accepted_response_with_no_mm_context_is_refused() {
        let _guard = lock_s11();
        let data = ContextResponseData {
            cause: crate::n26_build::CAUSE_REQUEST_ACCEPTED,
            imsi_bcd: None,
            mm_context: None,
            pdn_connections: Vec::new(),
            amf_fteid: None,
        };
        let ctx = mme_self();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 0x349);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        let err = install_transferred_context_for_test(ctx, mme_ue_id, &data)
            .expect_err("an accept with no MM Context must not install");
        assert!(
            err.contains("MM Context"),
            "the error must name the missing MM Context, got {err:?}"
        );
    }
}
