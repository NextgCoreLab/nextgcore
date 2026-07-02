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
    KernelSctpSocket, SCTP_ASSOC_CHANGE, SCTP_CANT_STR_ASSOC, SCTP_COMM_LOST, SCTP_SHUTDOWN_COMP,
    SCTP_SHUTDOWN_EVENT,
};
use crate::server::{SctpServerConfig, ServerError, ServerEvent};
use crate::{ReceivedMessage, SctpError, MSG_NOTIFICATION, NEXTGCORE_MAX_SDU_LEN, NGAP_PPID};

type Result<T> = std::result::Result<T, ServerError>;

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

/// Native kernel-SCTP NGAP server.
pub struct KernelSctpServer {
    listener: Arc<KernelSctpSocket>,
    local_addr: SocketAddr,
    config: SctpServerConfig,
    associations: Arc<Mutex<HashMap<u64, Assoc>>>,
    next_id: Arc<AtomicU64>,
    accept_task: Option<JoinHandle<()>>,
    running: bool,
}

impl KernelSctpServer {
    /// Bind a non-blocking listening SCTP socket on `addr`.
    pub async fn bind(addr: SocketAddr, config: SctpServerConfig) -> Result<Self> {
        let listener = KernelSctpSocket::server(addr).map_err(sctp_to_server_err)?;
        listener.set_nonblocking(true).map_err(sctp_to_server_err)?;
        let local_addr = listener.local_addr();

        log::info!("Kernel-SCTP NGAP server listening on {local_addr} (native one-to-one SCTP)");

        Ok(Self {
            listener: Arc::new(listener),
            local_addr,
            config,
            associations: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            accept_task: None,
            running: true,
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

    /// Install the event sink and start accepting. Associations and their data
    /// are delivered asynchronously through `tx`; the AMF NGAP path drains that
    /// channel on each poll iteration (see [`Self::recv`]).
    pub fn set_event_sender(&mut self, tx: mpsc::UnboundedSender<ServerEvent>) {
        let listener = Arc::clone(&self.listener);
        let associations = Arc::clone(&self.associations);
        let next_id = Arc::clone(&self.next_id);
        let recv_cap = (self.config.max_message_size as usize).max(NEXTGCORE_MAX_SDU_LEN);

        let handle = tokio::spawn(async move {
            accept_loop(listener, associations, next_id, tx, recv_cap).await;
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

    /// Send `data` to `association_id` on `stream_id` with the NGAP PPID.
    pub async fn send(&mut self, association_id: u64, stream_id: u16, data: &[u8]) -> Result<()> {
        let (sock, afd) = {
            let guard = self.associations.lock().unwrap();
            match guard.get(&association_id) {
                Some(a) => (Arc::clone(&a.sock), Arc::clone(&a.afd)),
                None => return Err(ServerError::AssociationNotFound(association_id)),
            }
        };

        loop {
            let mut ready = afd.writable().await.map_err(ServerError::Io)?;
            let attempt = ready.try_io(|_| match sock.send(data, NGAP_PPID, stream_id) {
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
                    read_loop(id, sock, sub_afd, read_tx, read_assocs, recv_cap).await;
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
) {
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
                    // Non-terminal notification (e.g. COMM_UP): nothing to deliver.
                    continue;
                }
                buf.truncate(n);
                let ppid = if info.ppid == 0 { NGAP_PPID } else { info.ppid };
                let _ = tx.send(ServerEvent::DataReceived {
                    association_id: id,
                    message: ReceivedMessage {
                        stream_id: info.stream_no,
                        data: Bytes::from(buf),
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

/// Map a primitive [`SctpError`] to a server-layer error for setup paths.
fn sctp_to_server_err(e: SctpError) -> ServerError {
    ServerError::Io(io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
