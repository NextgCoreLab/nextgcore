//! N4mb PFCP node for MBS multicast transport (TS 29.244, TS 23.247 §7.3).
//!
//! A long-lived async PFCP control endpoint toward the MB-UPF that replaces the
//! previous fire-and-forget `UdpSocket::bind("0.0.0.0:0")` + `send_to` (which
//! dropped the socket, never read a response, and hard-coded the SBI reply to
//! `ESTABLISHMENT_PENDING`). [mbsmfd-02]
//!
//! The node:
//!   - owns one persistent UDP socket bound to the PFCP port;
//!   - performs a PFCP **Association Setup** with the MB-UPF and gates all
//!     session establishment on a successful association (TS 29.244 §6.2.6.1);
//!   - correlates responses by PFCP **sequence number** via a pending-request
//!     table fed by a background recv/decode loop;
//!   - drives **T1 / N1** retransmission of each request until a response
//!     arrives or the retries are exhausted (TS 29.244 §6.4);
//!   - on a successful Session Establishment Response surfaces the UP-allocated
//!     SEID + transport address so the caller can mark the session `Established`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use nextgcore_pfcp::header::PfcpHeader;
use nextgcore_pfcp::message::{
    build_message, parse_message, AssociationSetupRequest, HeartbeatResponse, PfcpMessage,
    SessionDeletionRequest, SessionEstablishmentRequest, SessionReportResponse,
};
use nextgcore_pfcp::types::{
    ApplyAction, CreateFar, CreatePdr, DestinationInterface, FSeid, FTeid, ForwardingParameters,
    NodeId, OuterHeaderCreation, Pdi, PfcpCause, SourceInterface,
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

/// Default T1 retransmission timer (TS 29.244 §6.4) — time to wait for a
/// response before retransmitting.
pub const DEFAULT_T1: Duration = Duration::from_secs(3);
/// Default N1 retransmission count (TS 29.244 §6.4) — number of retransmissions
/// before the request is declared failed.
pub const DEFAULT_N1: u32 = 2;

/// Parameters for an N4mb Session Establishment Request (TS 29.244 §7.5.2).
#[derive(Debug, Clone)]
pub struct N4mbEstablishParams {
    /// CP F-SEID local SEID (MB-SMF side).
    pub local_seid: u64,
    /// MB-SMF (CP function) Node ID / F-SEID IPv4 address.
    pub cp_addr: [u8; 4],
    /// MB-UPF transport address used in the PDI F-TEID.
    pub upf_addr: [u8; 4],
    /// Downlink multicast GTP-U TEID carried in the PDI F-TEID.
    pub dl_teid: u32,
    /// Multicast downlink PDR id.
    pub pdr_id: u16,
    /// Multicast forwarding FAR id.
    pub far_id: u32,
    /// OuterHeaderCreation transport address (the IP multicast group toward
    /// NG-RAN) for DL GTP-U distribution. [mbsmfd-09]
    pub mcast_transport_addr: [u8; 4],
    /// OuterHeaderCreation GTP-U common TEID (C-TEID). [mbsmfd-09]
    pub c_teid: u32,
}

/// Build the N4mb Session Establishment Request message via the conformant
/// `nextgcore-pfcp` encoders (TS 29.244). [mbsmfd-01 + mbsmfd-09]
///
/// Structure:
///   - Node ID (IPv4 of the MB-SMF / CP function)              §7.5.2.1
///   - CP F-SEID (local SEID + CP IPv4)                        §8.2.37
///   - Create PDR: PDI Source-Interface=ACCESS, F-TEID (V4=0x01, DL TEID)
///   - Create FAR: Apply-Action=FORW (octet5=0x02), Forwarding-Parameters
///     Destination-Interface=ACCESS + OuterHeaderCreation (GTP-U/UDP/IPv4,
///     multicast transport addr + C-TEID, IE type 84) for DL multicast
///     distribution toward NG-RAN. [mbsmfd-09]
pub fn build_establishment_request(p: &N4mbEstablishParams) -> SessionEstablishmentRequest {
    let node_id = NodeId::new_ipv4(p.cp_addr);
    let cp_f_seid = FSeid::new_ipv4(p.local_seid, p.cp_addr);

    // Multicast downlink PDR: ACCESS source interface, F-TEID (V4 flag = 0x01).
    let mut pdi = Pdi::new(SourceInterface::Access);
    pdi.local_f_teid = Some(FTeid::new_ipv4(p.dl_teid, p.upf_addr));
    let mut create_pdr = CreatePdr::new(p.pdr_id, 100, pdi);
    create_pdr.far_id = Some(p.far_id);

    // Multicast forwarding FAR: FORW + Forwarding-Parameters targeting ACCESS
    // with an OuterHeaderCreation (GTP-U/UDP/IPv4) toward the multicast
    // transport address / C-TEID for downlink distribution toward NG-RAN.
    let mut create_far = CreateFar::new(p.far_id, ApplyAction::forward());
    let mut fp = ForwardingParameters::new(DestinationInterface::Access);
    fp.outer_header_creation = Some(OuterHeaderCreation::new_gtpu_ipv4(
        p.c_teid,
        p.mcast_transport_addr,
    ));
    create_far.forwarding_parameters = Some(fp);

    let mut req = SessionEstablishmentRequest::new(node_id, cp_f_seid);
    req.create_pdrs.push(create_pdr);
    req.create_fars.push(create_far);
    req
}

/// Outcome of a successful N4mb Session Establishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishOutcome {
    /// UP-allocated remote SEID (from the response UP F-SEID).
    pub remote_seid: u64,
    /// UP transport address (from the response UP F-SEID), if present.
    pub transport_addr: Option<Ipv4Addr>,
    /// UP-allocated DL TEID (from a Created PDR), if the UP chose one.
    pub up_dl_teid: Option<u32>,
}

/// Errors from the N4mb PFCP node.
#[derive(Debug)]
pub enum N4mbError {
    /// Socket I/O failure.
    Io(std::io::Error),
    /// The MB-UPF rejected the PFCP Association.
    AssociationRejected(PfcpCause),
    /// The MB-UPF rejected the Session Establishment.
    EstablishmentRejected(PfcpCause),
    /// No response after N1 retransmissions (T1 each).
    Timeout,
    /// A response of an unexpected type arrived.
    UnexpectedResponse,
}

impl std::fmt::Display for N4mbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "n4mb I/O error: {e}"),
            Self::AssociationRejected(c) => write!(f, "PFCP association rejected: {}", c.name()),
            Self::EstablishmentRejected(c) => {
                write!(f, "PFCP session establishment rejected: {}", c.name())
            }
            Self::Timeout => write!(f, "no PFCP response after N1 retransmissions"),
            Self::UnexpectedResponse => write!(f, "unexpected PFCP response type"),
        }
    }
}

impl std::error::Error for N4mbError {}

impl From<std::io::Error> for N4mbError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

type PendingTable = Mutex<HashMap<u32, oneshot::Sender<(PfcpHeader, PfcpMessage)>>>;

/// A Session Report the MB-UPF sent us, surfaced to the session driver (#76).
///
/// Carries the SEID it arrived on rather than a resolved session, because the
/// recv loop must not take the context lock: it would hold it across the reply
/// send, and the context's own writers call back into this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N4mbSessionReport {
    /// The SEID the report arrived on — the MB-SMF's own local SEID, since the UP
    /// addresses a report to the CP F-SEID it was given at establishment.
    pub seid: u64,
    /// Whether the report carried a Downlink Data Report, i.e. traffic arrived for
    /// a deactivated session (TS 23.247 §7.2.5.2).
    pub downlink_data: bool,
}

/// A long-lived N4mb PFCP node toward one MB-UPF (TS 29.244). [mbsmfd-02]
pub struct N4mbPfcpNode {
    socket: Arc<UdpSocket>,
    upf_dest: SocketAddr,
    cp_addr: [u8; 4],
    recovery_time_stamp: u32,
    seq: AtomicU32,
    associated: AtomicBool,
    pending: Arc<PendingTable>,
    t1: Duration,
    n1: u32,
    /// Session Reports received from the MB-UPF, in arrival order (#76).
    ///
    /// A queue rather than a callback: the recv loop answers the report on the
    /// wire immediately (the UP is waiting, and TS 29.244 §7.5.8 makes the
    /// response mandatory), and the *consequence* — activating a deactivated
    /// multicast session per TS 23.247 §7.2.5.2 — is driven by whoever owns the
    /// session state. Invoking that from the recv loop would put a context-lock
    /// acquisition inside the socket loop, and the context's writers call back
    /// into this node.
    reports: Arc<Mutex<Vec<N4mbSessionReport>>>,
}

impl N4mbPfcpNode {
    /// Bind the persistent PFCP socket and spawn the background recv/decode loop.
    pub async fn new(
        bind_addr: SocketAddr,
        upf_dest: SocketAddr,
        cp_addr: [u8; 4],
    ) -> std::io::Result<Arc<Self>> {
        Self::with_timers(bind_addr, upf_dest, cp_addr, DEFAULT_T1, DEFAULT_N1).await
    }

    /// Like [`new`](Self::new) but with explicit T1 / N1 (used by tests to drive
    /// the retransmission path quickly).
    pub async fn with_timers(
        bind_addr: SocketAddr,
        upf_dest: SocketAddr,
        cp_addr: [u8; 4],
        t1: Duration,
        n1: u32,
    ) -> std::io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let node = Arc::new(Self {
            socket,
            upf_dest,
            cp_addr,
            recovery_time_stamp: crate::context::now_unix() as u32,
            seq: AtomicU32::new(1),
            associated: AtomicBool::new(false),
            pending: Arc::new(Mutex::new(HashMap::new())),
            t1,
            n1,
            reports: Arc::new(Mutex::new(Vec::new())),
        });
        node.clone().spawn_recv_loop();
        Ok(node)
    }

    /// Local socket address (useful for tests / diagnostics).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Background loop: decode every datagram and hand it to the waiter keyed by
    /// the PFCP sequence number.
    fn spawn_recv_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                match self.socket.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        let mut bytes = Bytes::copy_from_slice(&buf[..n]);
                        match parse_message(&mut bytes) {
                            Ok((header, msg)) => {
                                let seq = header.sequence_number;
                                // #76: UP-INITIATED requests are answered here,
                                // BEFORE the pending-table lookup. They have no
                                // waiter by definition, so the old code logged
                                // "unsolicited PFCP, ignoring" and dropped them --
                                // which meant the MB-UPF could not detect this node
                                // as alive (§6.2.3.2) and could not report downlink
                                // data arrival (§7.5.8), so a deactivated multicast
                                // session never reactivated when traffic resumed.
                                if self.handle_up_initiated(&header, &msg, src).await {
                                    continue;
                                }
                                // Lock, take the waiter, drop the guard before
                                // any await (none here, but keep it tight).
                                let waiter = {
                                    let mut pending =
                                        self.pending.lock().expect("pending table poisoned");
                                    pending.remove(&seq)
                                };
                                if let Some(tx) = waiter {
                                    let _ = tx.send((header, msg));
                                } else {
                                    log::debug!("[N4mb] unsolicited PFCP seq={seq}, ignoring");
                                }
                            }
                            Err(e) => log::warn!("[N4mb] failed to decode PFCP datagram: {e}"),
                        }
                    }
                    Err(e) => {
                        log::warn!("[N4mb] recv loop terminated: {e}");
                        break;
                    }
                }
            }
        });
    }

    /// Answer a UP-initiated request, or return `false` when the message is not
    /// one (#76).
    ///
    /// The response echoes the request's **sequence number**, which is what makes
    /// it an answer rather than a new transaction: TS 29.244 §7.2.2.4 requires a
    /// response to carry the sequence number of the request it answers, and the UP
    /// correlates on exactly that.
    ///
    /// Sent to `src` rather than to `self.upf_dest`: a response must go back to
    /// whoever asked. Those are the same address in a normal deployment, and using
    /// the configured destination would silently swallow a request from a UP whose
    /// source port differs from the one we send to.
    async fn handle_up_initiated(
        &self,
        header: &PfcpHeader,
        msg: &PfcpMessage,
        src: SocketAddr,
    ) -> bool {
        let seq = header.sequence_number;
        match msg {
            // §6.2.3.2: "a node shall be prepared to receive a Heartbeat Request at
            // any time and shall reply with a Heartbeat Response."
            PfcpMessage::HeartbeatRequest(_) => {
                let resp = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(
                    self.recovery_time_stamp,
                ));
                let bytes = build_message(&resp, seq, None).to_vec();
                if let Err(e) = self.socket.send_to(&bytes, src).await {
                    log::warn!("[N4mb] failed to answer a Heartbeat Request from {src}: {e}");
                } else {
                    log::debug!("[N4mb] answered a Heartbeat Request from {src} (seq={seq})");
                }
                true
            }
            // §7.5.8: the UP reports events; the CP must respond. A Downlink Data
            // Report means traffic arrived for a session whose distribution is
            // deactivated (TS 23.247 §7.2.5.2), which is what reactivates it.
            PfcpMessage::SessionReportRequest(req) => {
                let downlink_data = req.downlink_data_report.is_some();
                let seid = header.seid.unwrap_or(0);
                let resp = PfcpMessage::SessionReportResponse(SessionReportResponse::new(
                    PfcpCause::RequestAccepted,
                ));
                // The response is addressed to the SEID the request arrived on,
                // per §7.2.2.4.2.
                let bytes = build_message(&resp, seq, Some(seid)).to_vec();
                if let Err(e) = self.socket.send_to(&bytes, src).await {
                    log::warn!("[N4mb] failed to answer a Session Report from {src}: {e}");
                }
                log::info!(
                    "[N4mb] Session Report from {src} (seid=0x{seid:016x}, \
                     downlink_data={downlink_data}) answered"
                );
                if let Ok(mut reports) = self.reports.lock() {
                    reports.push(N4mbSessionReport {
                        seid,
                        downlink_data,
                    });
                }
                true
            }
            _ => false,
        }
    }

    /// Drain the reports received since the last call (#76).
    ///
    /// Draining rather than peeking, so one report drives one activation: leaving
    /// them in place would have a periodic driver re-activate an already-active
    /// session on every tick.
    pub fn take_reports(&self) -> Vec<N4mbSessionReport> {
        self.reports
            .lock()
            .map(|mut r| std::mem::take(&mut *r))
            .unwrap_or_default()
    }

    /// How many reports are queued. For tests and diagnostics.
    pub fn pending_report_count(&self) -> usize {
        self.reports.lock().map(|r| r.len()).unwrap_or(0)
    }

    /// Send a request and await its correlated response, retransmitting on T1
    /// expiry up to N1 times (TS 29.244 §6.4).
    async fn transact(
        &self,
        msg: PfcpMessage,
        seid: Option<u64>,
    ) -> Result<(PfcpHeader, PfcpMessage), N4mbError> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let bytes = build_message(&msg, seq, seid).to_vec();

        for attempt in 0..=self.n1 {
            let (tx, rx) = oneshot::channel();
            {
                let mut pending = self.pending.lock().expect("pending table poisoned");
                pending.insert(seq, tx);
            }
            self.socket.send_to(&bytes, self.upf_dest).await?;

            match tokio::time::timeout(self.t1, rx).await {
                Ok(Ok(resp)) => return Ok(resp),
                // Sender dropped without a value (recv loop ended): treat as a
                // lost response and let the retransmission logic proceed.
                Ok(Err(_)) => {}
                Err(_elapsed) => {
                    // T1 expired: discard the stale waiter and retransmit.
                    let mut pending = self.pending.lock().expect("pending table poisoned");
                    pending.remove(&seq);
                }
            }
            if attempt < self.n1 {
                log::warn!(
                    "[N4mb] T1 expired (seq={seq}), retransmit {}/{}",
                    attempt + 1,
                    self.n1
                );
            }
        }
        Err(N4mbError::Timeout)
    }

    /// True once a PFCP association with the MB-UPF has been established.
    pub fn is_associated(&self) -> bool {
        self.associated.load(Ordering::Acquire)
    }

    /// Ensure a PFCP association exists (TS 29.244 §6.2.6.1). Idempotent: once
    /// associated, returns immediately. **Gates** session establishment.
    pub async fn ensure_association(&self) -> Result<(), N4mbError> {
        if self.is_associated() {
            return Ok(());
        }
        let req =
            AssociationSetupRequest::new(NodeId::new_ipv4(self.cp_addr), self.recovery_time_stamp);
        let (_h, resp) = self
            .transact(PfcpMessage::AssociationSetupRequest(req), None)
            .await?;
        match resp {
            PfcpMessage::AssociationSetupResponse(r) if r.cause.is_success() => {
                self.associated.store(true, Ordering::Release);
                log::info!("[N4mb] PFCP association established with {}", self.upf_dest);
                Ok(())
            }
            PfcpMessage::AssociationSetupResponse(r) => {
                Err(N4mbError::AssociationRejected(r.cause))
            }
            _ => Err(N4mbError::UnexpectedResponse),
        }
    }

    /// Establish an N4mb PFCP session for multicast transport. Gated on a
    /// successful association; on a "Request accepted" response returns the
    /// UP-allocated SEID + transport address. [mbsmfd-02]
    pub async fn establish_session(
        &self,
        params: &N4mbEstablishParams,
    ) -> Result<EstablishOutcome, N4mbError> {
        self.ensure_association().await?;

        let req = build_establishment_request(params);
        // SEID toward the UP is 0 for the initial establishment (§7.2.2.4.2).
        let (_h, resp) = self
            .transact(PfcpMessage::SessionEstablishmentRequest(req), Some(0))
            .await?;

        match resp {
            PfcpMessage::SessionEstablishmentResponse(r) if r.cause.is_success() => {
                let (remote_seid, transport_addr) = match &r.up_f_seid {
                    Some(fseid) => (fseid.seid, fseid.ipv4_addr.map(Ipv4Addr::from)),
                    None => (0, None),
                };
                let up_dl_teid = r
                    .created_pdrs
                    .first()
                    .and_then(|c| c.local_f_teid.as_ref())
                    .map(|f| f.teid);
                Ok(EstablishOutcome {
                    remote_seid,
                    transport_addr,
                    up_dl_teid,
                })
            }
            PfcpMessage::SessionEstablishmentResponse(r) => {
                Err(N4mbError::EstablishmentRejected(r.cause))
            }
            _ => Err(N4mbError::UnexpectedResponse),
        }
    }

    /// Release a previously-established N4mb session (TS 29.244 §7.5.4). The
    /// request is addressed to the UP-allocated `remote_seid`.
    pub async fn release_session(&self, remote_seid: u64) -> Result<(), N4mbError> {
        let (_h, resp) = self
            .transact(
                PfcpMessage::SessionDeletionRequest(SessionDeletionRequest::new()),
                Some(remote_seid),
            )
            .await?;
        match resp {
            PfcpMessage::SessionDeletionResponse(_) => Ok(()),
            _ => Err(N4mbError::UnexpectedResponse),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_pfcp::message::{AssociationSetupResponse, SessionEstablishmentResponse};

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Minimal MB-UPF responder: echoes the right response type per request,
    /// preserving the sequence number, on a loopback UDP socket.
    async fn spawn_fake_upf(remote_seid: u64, transport: [u8; 4]) -> SocketAddr {
        let sock = UdpSocket::bind(loopback(0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let mut bytes = Bytes::copy_from_slice(&buf[..n]);
                let (header, msg) = match parse_message(&mut bytes) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let seq = header.sequence_number;
                let (reply, seid) = match msg {
                    PfcpMessage::AssociationSetupRequest(_) => (
                        PfcpMessage::AssociationSetupResponse(AssociationSetupResponse::new(
                            NodeId::new_ipv4(transport),
                            PfcpCause::RequestAccepted,
                            42,
                        )),
                        None,
                    ),
                    PfcpMessage::SessionEstablishmentRequest(_) => {
                        let mut rsp = SessionEstablishmentResponse::new(PfcpCause::RequestAccepted);
                        rsp.node_id = Some(NodeId::new_ipv4(transport));
                        rsp.up_f_seid = Some(FSeid::new_ipv4(remote_seid, transport));
                        (
                            PfcpMessage::SessionEstablishmentResponse(rsp),
                            Some(remote_seid),
                        )
                    }
                    // #76: the fake UP now answers a Session Deletion too, and the
                    // SEID it arrived on is what the test reads back.
                    PfcpMessage::SessionDeletionRequest(_) => (
                        PfcpMessage::SessionDeletionResponse(
                            nextgcore_pfcp::message::SessionDeletionResponse::new(
                                PfcpCause::RequestAccepted,
                            ),
                        ),
                        header.seid,
                    ),
                    _ => continue,
                };
                let out = build_message(&reply, seq, seid).to_vec();
                let _ = sock.send_to(&out, src).await;
            }
        });
        addr
    }

    fn params(cp: [u8; 4], upf: [u8; 4]) -> N4mbEstablishParams {
        N4mbEstablishParams {
            local_seid: 0x100,
            cp_addr: cp,
            upf_addr: upf,
            dl_teid: 0x0BCA_0001,
            pdr_id: 1002,
            far_id: 2002,
            mcast_transport_addr: [239, 1, 0, 1],
            c_teid: 0x0BCA_0001,
        }
    }

    // mbsmfd-02 acceptance: association gating + establishment via a loopback
    // UPF that returns a crafted SessionEstablishmentResponse.
    #[tokio::test]
    async fn test_node_associates_then_establishes() {
        let remote_seid = 0xDEAD_BEEF;
        let transport = [10, 0, 0, 7];
        let upf = spawn_fake_upf(remote_seid, transport).await;

        let node = N4mbPfcpNode::with_timers(
            loopback(0),
            upf,
            [127, 0, 0, 1],
            Duration::from_millis(200),
            2,
        )
        .await
        .unwrap();

        assert!(!node.is_associated());
        let outcome = node
            .establish_session(&params([127, 0, 0, 1], transport))
            .await
            .expect("establishment succeeds");
        // Association gating: establishment drove the association first.
        assert!(node.is_associated());
        assert_eq!(outcome.remote_seid, remote_seid);
        assert_eq!(outcome.transport_addr, Some(Ipv4Addr::from(transport)));
    }

    // mbsmfd-02 acceptance: with no responder, the node retransmits T1×(N1+1)
    // then surfaces a Timeout failure.
    #[tokio::test]
    async fn test_node_retransmits_then_times_out() {
        // A bound-but-silent destination (nothing ever replies).
        let silent = UdpSocket::bind(loopback(0)).await.unwrap();
        let dest = silent.local_addr().unwrap();

        let node = N4mbPfcpNode::with_timers(
            loopback(0),
            dest,
            [127, 0, 0, 1],
            Duration::from_millis(80),
            2,
        )
        .await
        .unwrap();

        let start = std::time::Instant::now();
        let err = node
            .ensure_association()
            .await
            .expect_err("association must fail without a responder");
        assert!(matches!(err, N4mbError::Timeout));
        assert!(!node.is_associated());
        // 1 initial + 2 retransmissions × 80ms ≈ ≥240ms elapsed.
        assert!(start.elapsed() >= Duration::from_millis(200));
    }

    // mbsmfd-09 byte-vector: the encoded FAR carries an OuterHeaderCreation IE
    // (type 84) with the expected C-TEID + IPv4, and round-trips.
    #[test]
    fn test_far_outer_header_creation_byte_vector() {
        let p = params([127, 0, 0, 1], [10, 0, 0, 7]);
        let req = build_establishment_request(&p);

        let mut body = bytes::BytesMut::new();
        nextgcore_pfcp::message::PfcpMessage::SessionEstablishmentRequest(req.clone())
            .encode_body(&mut body);

        // OuterHeaderCreation IE: type 84 = 0x0054, len 10 (desc 2 + teid 4 +
        // ipv4 4), description GTP-U/UDP/IPv4 = 0x0100 (TS 29.244 Table 8.2.56-1,
        // octet 5 bit 1).
        let teid = p.c_teid.to_be_bytes();
        let needle = [
            0x00, 0x54, 0x00, 0x0A, 0x01, 0x00, teid[0], teid[1], teid[2], teid[3], 239, 1, 0, 1,
        ];
        assert!(
            body.windows(needle.len()).any(|w| w == needle),
            "OuterHeaderCreation IE (type 84) with C-TEID + multicast IPv4 present"
        );

        // Round-trip: the FAR forwarding parameters carry the OHC + Dest=ACCESS.
        let far = &req.create_fars[0];
        let fp = far.forwarding_parameters.as_ref().unwrap();
        assert_eq!(fp.destination_interface, DestinationInterface::Access);
        let ohc = fp.outer_header_creation.as_ref().unwrap();
        assert!(ohc.description.gtpu_udp_ipv4);
        assert_eq!(ohc.teid, Some(p.c_teid));
        assert_eq!(ohc.ipv4_addr, Some([239, 1, 0, 1]));
    }
    // ---- #76: UP-initiated requests -----------------------------------------

    /// #76 criterion 1: a Heartbeat Request on the N4mb socket is ANSWERED.
    ///
    /// It used to be logged as "unsolicited PFCP, ignoring" and dropped, so the
    /// MB-UPF could not detect this node as alive — TS 29.244 §6.2.3.2 makes the
    /// response mandatory and peer-failure detection depends on it.
    ///
    /// The assertion is on the datagram the fake UP receives back, decoded with the
    /// production parser: a test that only checked no warning was logged would pass
    /// against a node that answered with garbage.
    #[tokio::test]
    async fn a_heartbeat_request_is_answered_with_a_heartbeat_response() {
        use nextgcore_pfcp::message::HeartbeatRequest;

        // The "UP" here is a bare socket: it sends the request and reads the reply.
        let upf = UdpSocket::bind(loopback(0)).await.unwrap();
        let upf_addr = upf.local_addr().unwrap();
        let node = N4mbPfcpNode::with_timers(
            loopback(0),
            upf_addr,
            [127, 0, 0, 1],
            Duration::from_millis(100),
            0,
        )
        .await
        .unwrap();
        let node_addr = node.local_addr().unwrap();

        let req = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(4242));
        let bytes = build_message(&req, 77, None).to_vec();
        upf.send_to(&bytes, node_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), upf.recv_from(&mut buf))
            .await
            .expect("the node must answer a Heartbeat Request within 5s")
            .unwrap();
        assert_eq!(from, node_addr, "the answer must come from the node");

        let mut bytes = Bytes::copy_from_slice(&buf[..n]);
        let (header, msg) = parse_message(&mut bytes).expect("the answer is a PFCP message");
        assert_eq!(
            header.sequence_number, 77,
            "a response must echo the request's sequence number (§7.2.2.4); the UP \
             correlates on exactly that"
        );
        match msg {
            PfcpMessage::HeartbeatResponse(r) => assert_ne!(
                r.recovery_time_stamp, 0,
                "the response must carry this node's own Recovery Time Stamp"
            ),
            other => panic!("expected a HeartbeatResponse, got {other:?}"),
        }
    }

    /// #76 criterion 2, the wire half: a Session Report Request is answered and
    /// surfaced.
    ///
    /// A Downlink Data Report means traffic arrived for a session whose distribution
    /// is deactivated (TS 23.247 §7.2.5.2), and it was being dropped — so a
    /// deactivated multicast session never reactivated when traffic resumed. The
    /// activation itself is driven by the report queue's consumer; what is asserted
    /// here is the response on the wire and the report being queued for it.
    #[tokio::test]
    async fn a_session_report_is_answered_and_queued_for_the_session_driver() {
        use nextgcore_pfcp::message::SessionReportRequest;
        use nextgcore_pfcp::types::{DownlinkDataReport, ReportType};

        let upf = UdpSocket::bind(loopback(0)).await.unwrap();
        let upf_addr = upf.local_addr().unwrap();
        let node = N4mbPfcpNode::with_timers(
            loopback(0),
            upf_addr,
            [127, 0, 0, 1],
            Duration::from_millis(100),
            0,
        )
        .await
        .unwrap();
        let node_addr = node.local_addr().unwrap();
        assert_eq!(node.pending_report_count(), 0);

        let mut req = SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        });
        req.downlink_data_report = Some(DownlinkDataReport::new(1));
        let bytes = build_message(
            &PfcpMessage::SessionReportRequest(req),
            88,
            Some(0x0102_0304_0506_0708),
        )
        .to_vec();
        upf.send_to(&bytes, node_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), upf.recv_from(&mut buf))
            .await
            .expect("the node must answer a Session Report within 5s")
            .unwrap();
        let mut bytes = Bytes::copy_from_slice(&buf[..n]);
        let (header, msg) = parse_message(&mut bytes).expect("the answer is a PFCP message");
        assert_eq!(header.sequence_number, 88);
        assert_eq!(
            header.seid,
            Some(0x0102_0304_0506_0708),
            "the response is addressed to the SEID the request arrived on (§7.2.2.4.2)"
        );
        match msg {
            PfcpMessage::SessionReportResponse(r) => {
                assert!(r.cause.is_success(), "got cause {}", r.cause.name())
            }
            other => panic!("expected a SessionReportResponse, got {other:?}"),
        }

        let reports = node.take_reports();
        assert_eq!(
            reports,
            vec![N4mbSessionReport {
                seid: 0x0102_0304_0506_0708,
                downlink_data: true,
            }],
            "the report must be surfaced so the session driver can activate the session"
        );
        assert!(
            node.take_reports().is_empty(),
            "reports are DRAINED, so one report drives one activation rather than \
             re-activating on every tick"
        );
    }

    /// A UP-initiated request must not consume a pending waiter.
    ///
    /// The dispatch runs before the pending-table lookup, and getting that order
    /// wrong the other way would have a Heartbeat Request arriving mid-transaction
    /// steal the waiter for an in-flight Session Establishment — which would look
    /// like a UPF timeout.
    #[tokio::test]
    async fn an_inbound_request_does_not_steal_a_pending_waiter() {
        let upf_addr = spawn_fake_upf(0x55, [10, 0, 0, 9]).await;
        let node = N4mbPfcpNode::with_timers(
            loopback(0),
            upf_addr,
            [127, 0, 0, 1],
            Duration::from_millis(300),
            1,
        )
        .await
        .unwrap();
        let node_addr = node.local_addr().unwrap();

        // A heartbeat from a THIRD party arrives while the association is in flight.
        let intruder = UdpSocket::bind(loopback(0)).await.unwrap();
        let hb = build_message(
            &PfcpMessage::HeartbeatRequest(nextgcore_pfcp::message::HeartbeatRequest::new(1)),
            1,
            None,
        )
        .to_vec();

        let assoc = tokio::spawn({
            let node = node.clone();
            async move { node.ensure_association().await.is_ok() }
        });
        // Sequence 1 is also the first sequence number the node itself uses, which is
        // the collision this test is about.
        intruder.send_to(&hb, node_addr).await.unwrap();

        assert!(
            assoc.await.unwrap(),
            "the association must still complete: an inbound request must not consume \
             the waiter for an in-flight transaction"
        );
    }
    /// #76 criteria 3 + 4, the wire half: a Session Deletion Request is really
    /// transmitted, addressed to the UP-allocated SEID.
    ///
    /// `release_session` existed and had NO callers — `grep` found only its
    /// definition — so both the DELETE and TERMINATE paths mutated local state and
    /// left the MB-UPF session behind. This asserts the datagram the UP receives,
    /// decoded with the production parser: the SEID it carries is the thing that
    /// makes it a deletion of the right session, and addressing it to the LOCAL seid
    /// (which the old `session_context_terminate` discarded before anything could
    /// read it) would delete nothing.
    #[tokio::test]
    async fn a_session_deletion_request_is_transmitted_to_the_up_allocated_seid() {
        let seen: std::sync::Arc<
            Mutex<Vec<(nextgcore_pfcp::header::PfcpMessageType, Option<u64>)>>,
        > = std::sync::Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let sock = UdpSocket::bind(loopback(0)).await.unwrap();
        let upf_addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let mut bytes = Bytes::copy_from_slice(&buf[..n]);
                let Ok((header, msg)) = parse_message(&mut bytes) else {
                    continue;
                };
                if let Ok(mut s) = sink.lock() {
                    s.push((header.message_type, header.seid));
                }
                let reply = match msg {
                    PfcpMessage::SessionDeletionRequest(_) => PfcpMessage::SessionDeletionResponse(
                        nextgcore_pfcp::message::SessionDeletionResponse::new(
                            PfcpCause::RequestAccepted,
                        ),
                    ),
                    _ => continue,
                };
                let out = build_message(&reply, header.sequence_number, header.seid).to_vec();
                let _ = sock.send_to(&out, src).await;
            }
        });

        let node = N4mbPfcpNode::with_timers(
            loopback(0),
            upf_addr,
            [127, 0, 0, 1],
            Duration::from_millis(300),
            1,
        )
        .await
        .unwrap();

        node.release_session(0x00ab_cdef_0123_4567)
            .await
            .expect("the deletion must be acknowledged");

        let requests = seen.lock().unwrap().clone();
        let (msg_type, seid) = requests
            .iter()
            .find(|(t, _)| *t == nextgcore_pfcp::header::PfcpMessageType::SessionDeletionRequest)
            .copied()
            .unwrap_or_else(|| {
                panic!("a Session Deletion Request must reach the UP, got {requests:?}")
            });
        assert_eq!(
            msg_type,
            nextgcore_pfcp::header::PfcpMessageType::SessionDeletionRequest
        );
        assert_eq!(
            seid,
            Some(0x00ab_cdef_0123_4567),
            "the request must be addressed to the UP-ALLOCATED SEID (TS 29.244 §7.5.4); \
             the local one names a session the UP does not know"
        );
    }
}
