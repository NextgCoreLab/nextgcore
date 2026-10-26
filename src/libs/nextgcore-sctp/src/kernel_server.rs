//! Async kernel-SCTP NGAP server (production remediation T0.2b).
//!
//! This is the server-side counterpart to [`crate::kernel::KernelSctpSocket`]:
//! a native (Linux kernel) SCTP listener that an **independent RAN**
//! (e.g. UERANSIM) can connect to over standard SCTP — the path the userspace
//! `sctp-proto` backend cannot serve, because that backend speaks SCTP-over-UDP
//! and only interoperates with the matched nextgsim gNB.
//!
//! It deliberately mirrors the public surface of the userspace
//! [`crate::server::SctpServer`] (`bind` / `local_addr` / `set_event_sender` /
//! `recv` / `send`) and emits the same [`ServerEvent`]s, so the AMF NGAP path
//! can dispatch over either backend behind one enum.
//!
//! ## Model
//! One-to-one SOCK_STREAM + `accept`: each gNB association is its own accepted
//! socket. The listener and every accepted socket are set non-blocking and
//! driven by tokio's [`AsyncFd`] readiness; an accept loop spawns one read loop
//! per association. Inbound data is delivered as [`ServerEvent::DataReceived`];
//! SCTP shutdown / comm-lost notifications and EOF become
//! [`ServerEvent::AssociationClosed`].
//!
//! ## Runtime status
//! Compiles under `--features kernel` (type-checked on any host) and **links +
//! runs only on Linux with `libsctp`**. It is wired but **not yet
//! runtime-validated** end-to-end against a real RAN — that is the job of the
//! strict-peer exit gate (T6.3), which runs in Linux Docker. Until then this is
//! reviewed, gated scaffolding, not a proven interop path.
//!
//! Gated on both `kernel` and `sctp-proto` because it reuses the server event
//! types defined alongside the userspace server.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::kernel::{
    KernelSctpSocket, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC, SCTP_COMM_LOST, SCTP_RESTART,
    SCTP_SHUTDOWN_COMP, SCTP_SHUTDOWN_EVENT,
};
use crate::server::{SctpServerConfig, ServerError, ServerEvent};
use crate::{ReceivedMessage, SctpError, MSG_EOR, MSG_NOTIFICATION, NEXTGCORE_MAX_SDU_LEN};

type Result<T> = std::result::Result<T, ServerError>;

/// Name the application protocol a server carries, for its log lines, from the
/// PPID it is configured with (TS 38.412 §7: NGAP 60; TS 36.412 §7: S1AP 18).
fn protocol_name(ppid: u32) -> &'static str {
    match ppid {
        crate::NGAP_PPID => "NGAP",
        crate::NEXTGCORE_SCTP_S1AP_PPID => "S1AP",
        crate::NEXTGCORE_SCTP_SBCAP_PPID => "SBc-AP",
        _ => "SCTP",
    }
}

/// Borrowed-fd shim so a tokio [`AsyncFd`] can track readiness on a descriptor
/// *without owning* it. The real `OwnedFd` lives in the [`KernelSctpSocket`]
/// behind an `Arc`; dropping the `AsyncFd` only deregisters from the reactor
/// and must not close the socket (the `Arc` does that).
struct FdRef(RawFd);

impl AsRawFd for FdRef {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Per-association state shared between its read loop and the `send` path.
struct Assoc {
    sock: Arc<KernelSctpSocket>,
    afd: Arc<AsyncFd<FdRef>>,
    #[allow(dead_code)]
    remote: SocketAddr,
}

/// Why [`Admission`] refused an association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The peer is not in `allowed_peers`.
    Peer,
    /// `max_associations` are up.
    Limit,
}

/// Which associations the server accepts (#1071: SBc-AP takes only its configured
/// CBCs). A refused association is aborted at once (SCTP ABORT, `SO_LINGER` 0) and
/// never reported as a [`ServerEvent::NewAssociation`]; `on_refused` hears of it.
#[derive(Clone)]
pub struct Admission {
    /// The remote addresses allowed; an IPv4-mapped IPv6 peer is its IPv4 address.
    pub allowed_peers: Vec<std::net::IpAddr>,
    /// The most simultaneous associations.
    pub max_associations: usize,
    /// Told of each refusal (counters, a rate-limited log).
    pub on_refused: Arc<dyn Fn(SocketAddr, Refusal) + Send + Sync>,
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission")
            .field("allowed_peers", &self.allowed_peers)
            .field("max_associations", &self.max_associations)
            .finish_non_exhaustive()
    }
}

impl Admission {
    /// The decision for `peer` with `live` associations up.
    pub fn check(&self, peer: std::net::IpAddr, live: usize) -> Option<Refusal> {
        let peer = match peer {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(std::net::IpAddr::V4)
                .unwrap_or(std::net::IpAddr::V6(v6)),
            v4 => v4,
        };
        if !self.allowed_peers.contains(&peer) {
            Some(Refusal::Peer)
        } else if live >= self.max_associations {
            Some(Refusal::Limit)
        } else {
            None
        }
    }
}

/// Native kernel-SCTP server, used for NGAP (amfd) and S1AP (mmed S1-MME);
/// the protocol is selected by [`SctpServerConfig::ppid`].
pub struct KernelSctpServer {
    listener: Arc<KernelSctpSocket>,
    local_addr: SocketAddr,
    config: SctpServerConfig,
    associations: Arc<Mutex<HashMap<u64, Assoc>>>,
    next_id: Arc<AtomicU64>,
    accept_task: Option<JoinHandle<()>>,
    running: bool,
    admission: Option<Arc<Admission>>,
}

impl KernelSctpServer {
    /// Bind a non-blocking listening SCTP socket on `addr`.
    pub async fn bind(addr: SocketAddr, config: SctpServerConfig) -> Result<Self> {
        let listener = KernelSctpSocket::server(addr).map_err(sctp_to_server_err)?;
        listener.set_nonblocking(true).map_err(sctp_to_server_err)?;
        let local_addr = listener.local_addr();

        log::info!(
            "Kernel-SCTP {} server listening on {local_addr} (native one-to-one SCTP, PPID {})",
            protocol_name(config.ppid),
            config.ppid
        );

        Ok(Self {
            listener: Arc::new(listener),
            local_addr,
            config,
            associations: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            accept_task: None,
            running: true,
            admission: None,
        })
    }

    /// Local bound address (after any ephemeral-port resolution).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Number of live associations.
    pub fn num_associations(&self) -> usize {
        self.associations.lock().unwrap().len()
    }

    /// Accept only what `admission` allows (#1071). Call before
    /// [`Self::set_event_sender`], which starts accepting.
    pub fn set_admission(&mut self, admission: Admission) {
        self.admission = Some(Arc::new(admission));
    }

    /// Install the event sink and start accepting. Associations and their data
    /// are delivered asynchronously through `tx`; the AMF NGAP path drains that
    /// channel on each poll iteration (see [`Self::recv`]).
    pub fn set_event_sender(&mut self, tx: mpsc::UnboundedSender<ServerEvent>) {
        let listener = Arc::clone(&self.listener);
        let associations = Arc::clone(&self.associations);
        let next_id = Arc::clone(&self.next_id);
        let recv_cap = (self.config.max_message_size as usize).max(NEXTGCORE_MAX_SDU_LEN);
        let ppid = self.config.ppid;
        let admission = self.admission.clone();

        let handle = tokio::spawn(async move {
            accept_loop(
                listener,
                associations,
                next_id,
                tx,
                recv_cap,
                ppid,
                admission,
            )
            .await;
        });
        self.accept_task = Some(handle);
    }

    /// Mirror of [`crate::server::SctpServer::recv`].
    ///
    /// The kernel backend is fully task-driven (the accept/read loops push
    /// events straight into the channel installed by [`Self::set_event_sender`]),
    /// so this just paces the caller's poll loop for `recv_timeout` and reports
    /// no synchronous delivery. Returning `Ok(false)` is correct because the AMF
    /// path drains the event channel independently each poll cycle.
    pub async fn recv(&mut self, recv_timeout: Duration) -> Result<bool> {
        tokio::time::sleep(recv_timeout).await;
        Ok(false)
    }

    /// Mirror of [`crate::server::SctpServer::recv_or_wake`] (#981): the pacing sleep
    /// ends early when `wake` completes. Nothing is read here, so nothing can be lost.
    pub async fn recv_or_wake(
        &mut self,
        recv_timeout: Duration,
        wake: impl std::future::Future<Output = ()>,
    ) -> Result<crate::server::RecvOutcome> {
        tokio::select! {
            () = tokio::time::sleep(recv_timeout) => Ok(crate::server::RecvOutcome::Timeout),
            () = wake => Ok(crate::server::RecvOutcome::Woken),
        }
    }

    /// Send `data` to `association_id` on `stream_id` with the configured PPID
    /// ([`SctpServerConfig::ppid`]; NGAP 60 by default, S1AP 18 for S1-MME).
    pub async fn send(&mut self, association_id: u64, stream_id: u16, data: &[u8]) -> Result<()> {
        let (sock, afd) = {
            let guard = self.associations.lock().unwrap();
            match guard.get(&association_id) {
                Some(a) => (Arc::clone(&a.sock), Arc::clone(&a.afd)),
                None => return Err(ServerError::AssociationNotFound(association_id)),
            }
        };
        let ppid = self.config.ppid;

        loop {
            let mut ready = afd.writable().await.map_err(ServerError::Io)?;
            let attempt = ready.try_io(|_| match sock.send(data, ppid, stream_id) {
                Ok(n) => Ok(n),
                Err(SctpError::SendFailed(e)) => Err(e),
                Err(other) => Err(io::Error::other(other.to_string())),
            });
            match attempt {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => return Err(ServerError::SendError(e.to_string())),
                Err(_would_block) => continue, // readiness cleared; await writable again
            }
        }
    }

    /// The negotiated number of outbound streams of `association_id`; `None` for an
    /// unknown association or when the kernel cannot report it (#813).
    pub fn outbound_streams(&self, association_id: u64) -> Option<u16> {
        let sock = Arc::clone(&self.associations.lock().unwrap().get(&association_id)?.sock);
        match sock.negotiated_streams() {
            Ok((_, outbound)) => Some(outbound),
            Err(e) => {
                log::warn!(
                    "Kernel-SCTP: association {association_id}: SCTP_STATUS unavailable ({e})"
                );
                None
            }
        }
    }

    /// Close one association (graceful SCTP SHUTDOWN). Its read loop reports it
    /// closed once the shutdown completes; an unknown id is a no-op.
    pub fn close_association(&mut self, association_id: u64) -> Result<()> {
        let sock = self
            .associations
            .lock()
            .unwrap()
            .get(&association_id)
            .map(|a| Arc::clone(&a.sock));
        if let Some(sock) = sock {
            sock.shutdown().map_err(sctp_to_server_err)?;
            log::info!("Kernel-SCTP: association {association_id} shut down");
        }
        Ok(())
    }

    /// Stop accepting and drop all associations.
    pub fn stop(&mut self) {
        self.running = false;
        if let Some(handle) = self.accept_task.take() {
            handle.abort();
        }
        self.associations.lock().unwrap().clear();
    }

    /// Whether the server is still running.
    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl Drop for KernelSctpServer {
    fn drop(&mut self) {
        if let Some(handle) = self.accept_task.take() {
            handle.abort();
        }
    }
}

/// Accept loop: register the listener with the reactor and, on each readiness,
/// drain pending associations, spawning a read loop per accepted socket.
async fn accept_loop(
    listener: Arc<KernelSctpSocket>,
    associations: Arc<Mutex<HashMap<u64, Assoc>>>,
    next_id: Arc<AtomicU64>,
    tx: mpsc::UnboundedSender<ServerEvent>,
    recv_cap: usize,
    ppid: u32,
    admission: Option<Arc<Admission>>,
) {
    let afd = match AsyncFd::new(FdRef(listener.as_raw_fd())) {
        Ok(afd) => afd,
        Err(e) => {
            log::error!("Kernel-SCTP accept loop: failed to register listener fd: {e}");
            return;
        }
    };

    loop {
        let mut ready = match afd.readable().await {
            Ok(g) => g,
            Err(e) => {
                log::error!("Kernel-SCTP accept loop readiness error: {e}");
                return;
            }
        };

        let accepted = ready.try_io(|_| match listener.accept() {
            Ok(pair) => Ok(pair),
            Err(SctpError::ReceiveFailed(e)) => Err(e),
            Err(other) => Err(io::Error::other(other.to_string())),
        });

        match accepted {
            Ok(Ok((sock, remote))) => {
                if let Some(adm) = admission.as_deref() {
                    let live = associations.lock().unwrap().len();
                    if let Some(refusal) = adm.check(remote.ip(), live) {
                        // Closed with SO_LINGER 0 right here: an SCTP ABORT, and the
                        // association never reaches the application.
                        if let Err(e) = sock.set_abort_on_close() {
                            log::warn!("Kernel-SCTP: SO_LINGER on a refused association: {e}");
                        }
                        drop(sock);
                        (adm.on_refused)(remote, refusal);
                        continue;
                    }
                }
                if let Err(e) = sock.set_nonblocking(true) {
                    log::warn!("Kernel-SCTP: failed to set accepted socket non-blocking: {e}");
                }
                let sock = Arc::new(sock);
                let sub_afd = match AsyncFd::new(FdRef(sock.as_raw_fd())) {
                    Ok(a) => Arc::new(a),
                    Err(e) => {
                        log::error!("Kernel-SCTP: failed to register accepted fd: {e}");
                        continue;
                    }
                };
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                associations.lock().unwrap().insert(
                    id,
                    Assoc {
                        sock: Arc::clone(&sock),
                        afd: Arc::clone(&sub_afd),
                        remote,
                    },
                );
                let _ = tx.send(ServerEvent::NewAssociation {
                    association_id: id,
                    remote_addr: remote,
                });

                let read_tx = tx.clone();
                let read_assocs = Arc::clone(&associations);
                tokio::spawn(async move {
                    read_loop(id, sock, sub_afd, read_tx, read_assocs, recv_cap, ppid).await;
                });
            }
            Ok(Err(e)) => {
                log::warn!("Kernel-SCTP accept error: {e}");
            }
            Err(_would_block) => { /* readiness cleared by try_io; await again */ }
        }
    }
}

/// Per-association read loop: deliver data, translate close notifications/EOF.
async fn read_loop(
    id: u64,
    sock: Arc<KernelSctpSocket>,
    afd: Arc<AsyncFd<FdRef>>,
    tx: mpsc::UnboundedSender<ServerEvent>,
    associations: Arc<Mutex<HashMap<u64, Assoc>>>,
    recv_cap: usize,
    ppid: u32,
) {
    // A message larger than the receive buffer arrives in pieces: every piece but
    // the last has MSG_EOR clear (RFC 6458 §8.1.20 / §5.3.4). They are gathered
    // here, under the FIRST piece's stream and PPID, and delivered as one message
    // only when MSG_EOR arrives (#510). Bounded so a peer cannot grow it at will.
    let reassembly_cap = reassembly_limit(recv_cap);
    let mut partial: Option<(Vec<u8>, crate::NextgcoreSctpInfo)> = None;
    loop {
        let mut ready = match afd.readable().await {
            Ok(g) => g,
            Err(e) => {
                emit_closed(&tx, &associations, id, &format!("readiness error: {e}"));
                return;
            }
        };

        let mut buf = vec![0u8; recv_cap];
        let io_res = ready.try_io(|_| match sock.recv_msg(&mut buf) {
            Ok(t) => Ok(t),
            Err(SctpError::ReceiveFailed(e)) => Err(e),
            Err(other) => Err(io::Error::other(other.to_string())),
        });

        match io_res {
            Ok(Ok((0, _info, _flags))) => {
                // SOCK_STREAM EOF: peer performed an orderly shutdown.
                emit_closed(&tx, &associations, id, "peer shutdown (EOF)");
                return;
            }
            Ok(Ok((n, info, flags))) => {
                if flags & MSG_NOTIFICATION != 0 {
                    if is_close_notification(&buf[..n]) {
                        emit_closed(&tx, &associations, id, "SCTP association down");
                        return;
                    }
                    if is_restart_notification(&buf[..n]) {
                        log::warn!("Kernel-SCTP: association {id} restarted by its peer");
                        let _ = tx.send(ServerEvent::AssociationRestarted { association_id: id });
                    }
                    // Other non-terminal notifications (e.g. COMM_UP): nothing to deliver.
                    continue;
                }
                buf.truncate(n);
                let (data, info) = match partial.take() {
                    Some((mut acc, first)) => {
                        acc.extend_from_slice(&buf);
                        (acc, first)
                    }
                    None => (buf, info),
                };
                if flags & MSG_EOR == 0 {
                    if data.len() > reassembly_cap {
                        emit_closed(
                            &tx,
                            &associations,
                            id,
                            &format!("message exceeds the {reassembly_cap}-octet reassembly limit"),
                        );
                        return;
                    }
                    // More of this message to come.
                    partial = Some((data, info));
                    continue;
                }
                // An inbound PPID of 0 means the peer did not stamp one; fall
                // back to the association's configured application protocol.
                let ppid = if info.ppid == 0 { ppid } else { info.ppid };
                let _ = tx.send(ServerEvent::DataReceived {
                    association_id: id,
                    message: ReceivedMessage {
                        stream_id: info.stream_no,
                        data: Bytes::from(data),
                        ppid,
                    },
                });
            }
            Ok(Err(e)) => {
                emit_closed(&tx, &associations, id, &format!("recv error: {e}"));
                return;
            }
            Err(_would_block) => { /* readiness cleared; await again */ }
        }
    }
}

/// The largest message the read loop will reassemble from partial deliveries: 16
/// receive buffers, and never less than 1 MiB -- comfortably above any NGAP or
/// S1AP PDU, while still a hard stop for a peer that never sends MSG_EOR.
fn reassembly_limit(recv_cap: usize) -> usize {
    recv_cap.saturating_mul(16).max(1 << 20)
}

/// Emit an `AssociationClosed` event and drop the association from the registry.
fn emit_closed(
    tx: &mpsc::UnboundedSender<ServerEvent>,
    associations: &Arc<Mutex<HashMap<u64, Assoc>>>,
    id: u64,
    reason: &str,
) {
    associations.lock().unwrap().remove(&id);
    let _ = tx.send(ServerEvent::AssociationClosed {
        association_id: id,
        reason: reason.to_string(),
    });
}

/// Decide whether an SCTP event notification means the association is gone.
///
/// Layout (kernel ABI): every notification starts with `__u16 sn_type`. For
/// `SCTP_ASSOC_CHANGE` the `sac_state` field follows `sac_type`(2) +
/// `sac_flags`(2) + `sac_length`(4), i.e. at byte offset 8.
fn is_close_notification(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let sn_type = u16::from_ne_bytes([buf[0], buf[1]]);
    match sn_type {
        SCTP_SHUTDOWN_EVENT => true,
        SCTP_ASSOC_CHANGE if buf.len() >= 10 => {
            let state = u16::from_ne_bytes([buf[8], buf[9]]);
            matches!(
                state,
                SCTP_COMM_LOST | SCTP_SHUTDOWN_COMP | SCTP_CANT_STR_ASSOC
            )
        }
        _ => false,
    }
}

/// Whether a notification is `SCTP_ASSOC_CHANGE` / `SCTP_RESTART` (RFC 6458 §6.1.1): the
/// peer restarted the association, which stays up under the same id with streams
/// negotiated afresh (RFC 9260 §5.2.2).
fn is_restart_notification(buf: &[u8]) -> bool {
    buf.len() >= 10
        && u16::from_ne_bytes([buf[0], buf[1]]) == SCTP_ASSOC_CHANGE
        && u16::from_ne_bytes([buf[8], buf[9]]) == SCTP_RESTART
}

/// Map a primitive [`SctpError`] to a server-layer error for setup paths.
fn sctp_to_server_err(e: SctpError) -> ServerError {
    ServerError::Io(io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {

    /// #1088 review: closing one association shuts it down at the SCTP level: the
    /// SHUTDOWN completes, and the read loop reports the association closed and
    /// forgets it.
    #[tokio::test]
    async fn closing_an_association_shuts_it_down() {
        let mut server = KernelSctpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            crate::server::SctpServerConfig::default(),
        )
        .await
        .expect("bind");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        server.set_event_sender(tx);
        let client = KernelSctpSocket::client(server.local_addr(), None).expect("client");
        let id = match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
            Ok(Some(ServerEvent::NewAssociation { association_id, .. })) => association_id,
            other => panic!("expected NewAssociation, got {other:?}"),
        };
        server.close_association(id).expect("close");
        let closed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match rx.recv().await {
                    Some(ServerEvent::AssociationClosed { association_id, .. }) => {
                        break association_id
                    }
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .expect("the association is reported closed");
        assert_eq!(closed, id);
        assert_eq!(server.num_associations(), 0);
        drop(client);
    }
    use super::*;

    /// #870 follow-up: an `SCTP_RESTART` assoc change is a restart, not a close; the other
    /// states are not restarts.
    #[test]
    fn assoc_change_restart_is_a_restart_not_a_close() {
        let change = |state: u16| {
            let mut buf = vec![0u8; 20];
            buf[0..2].copy_from_slice(&SCTP_ASSOC_CHANGE.to_ne_bytes());
            buf[8..10].copy_from_slice(&state.to_ne_bytes());
            buf
        };
        assert!(is_restart_notification(&change(SCTP_RESTART)));
        assert!(!is_close_notification(&change(SCTP_RESTART)));
        for state in [
            0u16,
            SCTP_COMM_LOST,
            SCTP_SHUTDOWN_COMP,
            SCTP_CANT_STR_ASSOC,
        ] {
            assert!(!is_restart_notification(&change(state)), "state {state}");
        }
        let mut shutdown = vec![0u8; 20];
        shutdown[0..2].copy_from_slice(&SCTP_SHUTDOWN_EVENT.to_ne_bytes());
        shutdown[8..10].copy_from_slice(&SCTP_RESTART.to_ne_bytes());
        assert!(!is_restart_notification(&shutdown), "only an assoc change");
        assert!(!is_restart_notification(&change(SCTP_RESTART)[..9]));
    }

    #[test]
    fn shutdown_event_is_close() {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&SCTP_SHUTDOWN_EVENT.to_ne_bytes());
        assert!(is_close_notification(&buf));
    }

    #[test]
    fn assoc_change_comm_lost_is_close() {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&SCTP_ASSOC_CHANGE.to_ne_bytes());
        buf[8..10].copy_from_slice(&SCTP_COMM_LOST.to_ne_bytes());
        assert!(is_close_notification(&buf));
    }

    #[test]
    fn assoc_change_comm_up_is_not_close() {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&SCTP_ASSOC_CHANGE.to_ne_bytes());
        // sac_state left 0 (SCTP_COMM_UP)
        assert!(!is_close_notification(&buf));
    }

    #[test]
    fn short_buffer_is_not_close() {
        assert!(!is_close_notification(&[]));
        assert!(!is_close_notification(&[0x05]));
    }
}
