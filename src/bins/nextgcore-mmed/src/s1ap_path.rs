//! S1-MME transport (issue #42, TS 36.412 / TS 36.413 §8.7.3.2).
//!
//! Before this module the MME had a complete, unit-tested S1AP message layer
//! that never reached the wire: nothing bound port 36412,
//! [`handle_s1ap_message`] had no non-test caller, and every downlink PDU that
//! `nas_path` built was dropped. This module is the missing transport.
//!
//! ## Model
//!
//! S1AP is carried over SCTP on port 36412 with PPID 18 (TS 36.412), and the
//! MME is the passive side that accepts eNB-initiated associations. The
//! transport reuses [`nextgcore_sctp::KernelSctpServer`] — the same native
//! one-to-one kernel-SCTP listener amfd uses for NGAP — configured with the
//! S1AP PPID instead of NGAP's.
//!
//! ## Ingress
//!
//! [`S1apServer::poll_once`] drains the server's event channel:
//!
//! - `NewAssociation` → register the peer with `ctx.enb_add(addr)` and map the
//!   association to that eNB pool id;
//! - `DataReceived` → `handle_s1ap_message(ctx, enb_id, data)`, transmitting
//!   every returned [`S1apSend`] (S1 Setup Response, error indications, …);
//! - `AssociationClosed` → drop the mapping and `ctx.enb_remove(enb_id)`.
//!
//! ## Egress
//!
//! Downlink PDUs are produced by *synchronous* code deep inside the EMM/ESM
//! handlers (`nas_path::nas_eps_send_to_enb` and the E-RAB builders). Rather
//! than make those call trees async, they push onto a process-global unbounded
//! **send queue** via [`s1ap_send`], which `poll_once` drains and routes to the
//! addressed eNB's association. The push is non-blocking and never fails the
//! caller's procedure.
//!
//! ## Feature gating
//!
//! The kernel-SCTP backend needs Linux + `libsctp`, so it sits behind the
//! `kernel-sctp` feature (mirroring amfd). Without it the daemon still builds
//! and runs, with the transport reported as unavailable rather than silently
//! absent. The userspace `sctp-proto` backend is deliberately NOT offered here:
//! it is SCTP-over-UDP, so it could not carry an association from a real eNB,
//! and offering it would make the gap look closed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::OnceLock;

use tokio::sync::mpsc;

use crate::context::MmeContext;
use crate::s1ap_handler::{handle_s1ap_message, S1apSend};

/// SCTP stream used for S1AP signalling.
///
/// TS 36.412 reserves stream 0 for non-UE-associated signalling. UE-associated
/// signalling may use other streams; [`S1apSend`] does not currently carry a
/// stream id, so everything goes out on stream 0 — valid, and the conservative
/// choice until the handler layer tracks per-UE streams.
const S1AP_STREAM_ID: u16 = 0;

/// Process-global sender for the downlink S1AP queue.
///
/// A `OnceLock` (not a `Mutex<Option<..>>`) because the sender is installed once
/// at startup and only ever cloned afterwards, so the egress path needs no lock.
static SEND_TX: OnceLock<mpsc::UnboundedSender<S1apSend>> = OnceLock::new();

/// Queue an S1AP PDU for transmission to `enb_id`.
///
/// Callable from synchronous code on any thread; it never blocks and never
/// fails the caller's procedure. Returns `false` when the PDU could not be
/// queued — the transport is not up (no [`S1apServer::bind`] yet, e.g. in a
/// unit test) or the server has shut down — which is logged and otherwise
/// ignored, exactly as an unreachable eNB would be.
pub fn s1ap_send(message: S1apSend) -> bool {
    let Some(tx) = SEND_TX.get() else {
        log::warn!(
            "S1AP send dropped: transport not initialised (enb_id={}, {} bytes)",
            message.enb_id,
            message.pdu.len()
        );
        return false;
    };
    let enb_id = message.enb_id;
    let len = message.pdu.len();
    match tx.send(message) {
        Ok(()) => {
            log::debug!("S1AP PDU queued for eNB {enb_id} ({len} bytes)");
            true
        }
        Err(_) => {
            log::warn!("S1AP send dropped: transport closed (enb_id={enb_id}, {len} bytes)");
            false
        }
    }
}

/// Convenience wrapper around [`s1ap_send`] for a raw encoded PDU.
pub fn s1ap_send_pdu(enb_id: u64, pdu: Vec<u8>) -> bool {
    s1ap_send(S1apSend { enb_id, pdu })
}

/// Install the process-global send queue, returning the receiving half to hand
/// to [`S1apServer::bind`].
///
/// Returns `None` if a queue is already installed (the sender is set once per
/// process), so a second call cannot silently orphan the first queue. Kept
/// separate from `bind` so a test can drive a server off its own local queue
/// without consuming the one global slot.
pub fn install_send_queue() -> Option<mpsc::UnboundedReceiver<S1apSend>> {
    let (tx, rx) = mpsc::unbounded_channel();
    match SEND_TX.set(tx) {
        Ok(()) => Some(rx),
        Err(_) => None,
    }
}

/// The S1AP transport backend.
enum Backend {
    /// Native Linux kernel SCTP (the only backend that is real SCTP on the
    /// wire, so the only one a third-party eNB can associate with).
    #[cfg(feature = "kernel-sctp")]
    Kernel(Box<nextgcore_sctp::KernelSctpServer>),
    /// Built without `kernel-sctp`: no S1-MME transport. The daemon runs, but
    /// no eNB can associate and queued downlink PDUs are drained and dropped.
    Disabled,
}

/// The S1-MME server: owns the SCTP listener, the association↔eNB mapping, and
/// both directions of the S1AP data path.
pub struct S1apServer {
    backend: Backend,
    /// Inbound events from the SCTP backend.
    events: mpsc::UnboundedReceiver<nextgcore_sctp::ServerEvent>,
    /// Retained clone of the event sender.
    ///
    /// Keeps the channel open for the lifetime of the server so `events.recv()`
    /// parks when idle instead of resolving to `None` — which would turn
    /// [`S1apServer::poll_once`] into a busy loop once the backend's accept task
    /// ends (or immediately, when the transport is disabled).
    _event_tx: mpsc::UnboundedSender<nextgcore_sctp::ServerEvent>,
    /// Outbound PDUs pushed by the synchronous NAS/E-RAB paths.
    send_rx: mpsc::UnboundedReceiver<S1apSend>,
    /// SCTP association id → eNB pool id.
    assoc_to_enb: HashMap<u64, u64>,
    /// eNB pool id → SCTP association id.
    enb_to_assoc: HashMap<u64, u64>,
    /// Bound address, once known.
    local_addr: Option<SocketAddr>,
    /// The MME context S1AP procedures run against.
    ///
    /// Injected rather than read from `mme_self()` inside the event handler so a
    /// wire test can drive the server against a context it has configured (e.g.
    /// with a served GUMMEI, without which S1 Setup is answered with a Failure).
    /// Mirrors amfd's NGAP path, which likewise takes its context as a parameter.
    ctx: &'static MmeContext,
}

impl S1apServer {
    /// Bind the S1-MME SCTP listener on `addr` (conventionally `:36412`).
    ///
    /// Without the `kernel-sctp` feature this succeeds with the transport
    /// disabled rather than failing startup: the rest of the MME (S11, S6a
    /// state, timers) is unaffected by the absence of an S1 interface, and a
    /// hard failure would make the default build unable to boot at all.
    pub async fn bind(
        addr: SocketAddr,
        send_rx: mpsc::UnboundedReceiver<S1apSend>,
        ctx: &'static MmeContext,
    ) -> anyhow::Result<Self> {
        let (event_tx, events) = mpsc::unbounded_channel();

        #[cfg(feature = "kernel-sctp")]
        let (backend, local_addr) = {
            let config = nextgcore_sctp::SctpServerConfig {
                // S1AP PPID 18 (TS 36.412), NOT NGAP's 60. This is why
                // SctpServerConfig carries a ppid at all.
                ppid: nextgcore_sctp::NEXTGCORE_SCTP_S1AP_PPID,
                ..Default::default()
            };
            let mut server = nextgcore_sctp::KernelSctpServer::bind(addr, config)
                .await
                .map_err(|e| anyhow::anyhow!("failed to bind S1-MME SCTP socket on {addr}: {e}"))?;
            let bound = server.local_addr();
            server.set_event_sender(event_tx.clone());
            log::info!(
                "S1-MME SCTP server listening on {bound} (PPID {}, kernel SCTP)",
                nextgcore_sctp::NEXTGCORE_SCTP_S1AP_PPID
            );
            (Backend::Kernel(Box::new(server)), Some(bound))
        };

        #[cfg(not(feature = "kernel-sctp"))]
        let (backend, local_addr) = {
            log::warn!(
                "S1-MME transport unavailable: nextgcore-mmed was built without the \
                 `kernel-sctp` feature, so nothing is listening on {addr}. No eNB can \
                 establish an S1 association and S1 Setup cannot complete \
                 (TS 36.413 §8.7.3.2). Rebuild with --features kernel-sctp on Linux \
                 with libsctp to enable it."
            );
            (Backend::Disabled, None)
        };

        Ok(Self {
            backend,
            events,
            _event_tx: event_tx,
            send_rx,
            assoc_to_enb: HashMap::new(),
            enb_to_assoc: HashMap::new(),
            local_addr,
            ctx,
        })
    }

    /// The bound listen address, or `None` when the transport is disabled.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Whether a live SCTP listener is bound.
    pub fn is_enabled(&self) -> bool {
        !matches!(self.backend, Backend::Disabled)
    }

    /// Number of live eNB associations.
    pub fn num_associations(&self) -> usize {
        self.assoc_to_enb.len()
    }

    /// Drive one step of the S1AP data path: handle the next inbound event or
    /// transmit the next queued downlink PDU, whichever is ready first.
    ///
    /// Cancel-safe: both branches are `mpsc::Receiver::recv`, so a dropped
    /// future consumes no message.
    pub async fn poll_once(&mut self) {
        tokio::select! {
            event = self.events.recv() => {
                if let Some(event) = event {
                    self.handle_event(event).await;
                }
            }
            outbound = self.send_rx.recv() => {
                if let Some(outbound) = outbound {
                    self.transmit(outbound).await;
                }
            }
        }
    }

    /// Dispatch one SCTP event.
    async fn handle_event(&mut self, event: nextgcore_sctp::ServerEvent) {
        use nextgcore_sctp::ServerEvent;
        let ctx: &MmeContext = self.ctx;

        match event {
            ServerEvent::NewAssociation {
                association_id,
                remote_addr,
            } => {
                // TS 36.412: the eNB initiates the association; register it so
                // S1AP procedures can address this peer by eNB pool id.
                let enb_id = ctx.enb_add(remote_addr);
                self.assoc_to_enb.insert(association_id, enb_id);
                self.enb_to_assoc.insert(enb_id, association_id);
                log::info!(
                    "S1 association up from {remote_addr} (assoc={association_id}, enb_id={enb_id})"
                );
            }
            ServerEvent::DataReceived {
                association_id,
                message,
            } => {
                let Some(&enb_id) = self.assoc_to_enb.get(&association_id) else {
                    log::warn!(
                        "S1AP data on unknown association {association_id} ({} bytes) — dropping",
                        message.data.len()
                    );
                    return;
                };
                log::debug!(
                    "S1AP PDU from eNB {enb_id} ({} bytes, ppid={})",
                    message.data.len(),
                    message.ppid
                );
                // The S1AP handler's first non-test caller: decode, run the
                // procedure, and transmit whatever it answers with.
                let outbound = handle_s1ap_message(ctx, enb_id, &message.data);
                for out in outbound {
                    self.transmit(out).await;
                }
            }
            ServerEvent::AssociationClosed {
                association_id,
                reason,
            } => {
                if let Some(enb_id) = self.assoc_to_enb.remove(&association_id) {
                    self.enb_to_assoc.remove(&enb_id);
                    ctx.enb_remove(enb_id);
                    log::info!(
                        "S1 association down (assoc={association_id}, enb_id={enb_id}): {reason}"
                    );
                } else {
                    log::debug!("S1 association {association_id} closed: {reason}");
                }
            }
        }
    }

    /// Transmit one S1AP PDU to its addressed eNB.
    async fn transmit(&mut self, message: S1apSend) {
        let S1apSend { enb_id, pdu } = message;

        let Some(&association_id) = self.enb_to_assoc.get(&enb_id) else {
            log::warn!(
                "cannot send S1AP PDU to eNB {enb_id}: no live S1 association ({} bytes dropped)",
                pdu.len()
            );
            return;
        };

        match &mut self.backend {
            #[cfg(feature = "kernel-sctp")]
            Backend::Kernel(server) => {
                match server.send(association_id, S1AP_STREAM_ID, &pdu).await {
                    Ok(()) => log::debug!(
                        "S1AP PDU sent to eNB {enb_id} ({} bytes, assoc={association_id})",
                        pdu.len()
                    ),
                    Err(e) => log::error!(
                        "failed to send S1AP PDU to eNB {enb_id} (assoc={association_id}): {e}"
                    ),
                }
            }
            Backend::Disabled => {
                // Drain rather than accumulate: the queue is unbounded, so a
                // disabled transport must not let it grow without limit.
                log::debug!(
                    "S1AP transport disabled: dropping {} bytes for eNB {enb_id} \
                     (assoc={association_id})",
                    pdu.len()
                );
            }
        }
    }

    /// Stop the listener and drop all associations.
    pub fn stop(&mut self) {
        match &mut self.backend {
            #[cfg(feature = "kernel-sctp")]
            Backend::Kernel(server) => server.stop(),
            Backend::Disabled => {}
        }
        self.assoc_to_enb.clear();
        self.enb_to_assoc.clear();
        log::debug!("S1-MME transport stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leaked `&'static MmeContext` with a served GUMMEI, so S1 Setup is
    /// answered with a Response rather than a Failure. Leaked because
    /// [`S1apServer`] holds `&'static MmeContext` (matching `mme_self()`'s
    /// lifetime); one leak per test process is acceptable.
    fn static_ctx_with_gummei() -> &'static MmeContext {
        use crate::context::{PlmnId, ServedGummei};
        let mut ctx = MmeContext::new();
        ctx.init();
        ctx.mme_name = Some("wire-test-mme".to_string());
        ctx.served_gummei = vec![ServedGummei {
            num_of_plmn_id: 1,
            plmn_id: vec![PlmnId::new("310", "410")],
            num_of_mme_gid: 1,
            mme_gid: vec![2],
            num_of_mme_code: 1,
            mme_code: vec![1],
        }];
        ctx.num_of_served_gummei = 1;
        Box::leak(Box::new(ctx))
    }

    /// `s1ap_send` must never panic or block when no transport is up — the
    /// state the default build's startup window and every unit test is in.
    #[test]
    fn send_without_transport_is_a_noop() {
        // Total function: whether or not another test in this binary has
        // installed the global queue, this must not panic.
        let _ = s1ap_send_pdu(1, vec![0x00, 0x01]);
    }

    #[test]
    fn install_send_queue_is_once_per_process() {
        // The global sender is set once; a second install must be refused so it
        // cannot orphan the first queue.
        let first = install_send_queue();
        let second = install_send_queue();
        assert!(
            first.is_some() != second.is_some() || second.is_none(),
            "install_send_queue must not hand out two live global queues"
        );
        assert!(second.is_none(), "the second install must be refused");
    }

    #[test]
    fn s1ap_stream_is_zero_for_non_ue_signalling() {
        // TS 36.412: stream 0 carries non-UE-associated signalling.
        assert_eq!(S1AP_STREAM_ID, 0);
    }

    /// Queued downlink PDUs addressed to an eNB with no live association are
    /// dropped with a warning, not retained or panicked on.
    #[tokio::test]
    async fn transmit_without_association_is_dropped() {
        let (tx, rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut server = S1apServer::bind(addr, rx, static_ctx_with_gummei())
            .await
            .expect("bind");
        tx.send(S1apSend {
            enb_id: 999,
            pdu: vec![0xde, 0xad],
        })
        .expect("queue");
        server.poll_once().await;
        assert_eq!(server.num_associations(), 0);
        server.stop();
    }

    /// **The #42 acceptance test.** A native kernel-SCTP client acts as an eNB:
    /// it associates with the bound S1-MME socket, sends an S1 Setup Request,
    /// and must receive an S1 Setup Response back over the association — i.e.
    /// the S1 interface becomes operational (TS 36.413 §8.7.3.2).
    ///
    /// This is the criterion that could not be met before: nothing bound 36412,
    /// so no association could exist and `handle_s1ap_message` never ran on
    /// live data. Gated on Linux + `kernel-sctp` because kernel SCTP needs both.
    /// Multi-threaded runtime: the blocking libc `connect`/`send`/`recv_msg`
    /// calls on the client side run via `spawn_blocking`/`block_in_place`, which
    /// the current-thread flavour rejects.
    #[cfg(all(feature = "kernel-sctp", target_os = "linux"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn s1_setup_request_over_real_sctp_is_answered() {
        use crate::context::PlmnId;
        use nextgcore_s1ap::{
            builder, decode_s1ap_pdu, GlobalEnbId, PagingDrx, S1SetupRequest, S1apMessage,
            SupportedTaItem,
        };

        let ctx = static_ctx_with_gummei();
        let (_tx, rx) = mpsc::unbounded_channel();

        // Bind on an ephemeral port: 36412 may be taken, and the port number is
        // not what this test is about.
        let mut server = S1apServer::bind("127.0.0.1:0".parse().unwrap(), rx, ctx)
            .await
            .expect("bind S1-MME SCTP socket");
        let bound = server
            .local_addr()
            .expect("kernel backend reports its addr");

        // --- the "eNB": a real kernel-SCTP client association ---
        let client = tokio::task::spawn_blocking(move || {
            nextgcore_sctp::KernelSctpSocket::client(bound, None)
                .expect("eNB kernel-SCTP client connect")
        })
        .await
        .expect("client task");

        // Let the server's accept loop register the association.
        for _ in 0..50 {
            tokio::time::timeout(std::time::Duration::from_millis(20), server.poll_once())
                .await
                .ok();
            if server.num_associations() > 0 {
                break;
            }
        }
        assert_eq!(
            server.num_associations(),
            1,
            "the eNB's SCTP association must be registered on COMM_UP"
        );

        // --- S1 Setup Request in, over PPID 18 ---
        let request = S1SetupRequest {
            global_enb_id: GlobalEnbId {
                plmn_identity: crate::s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                enb_id: nextgcore_s1ap::EnbId::Macro(0x1234),
            },
            enb_name: Some("wire-test-enb".to_string()),
            supported_tas: vec![SupportedTaItem {
                tac: 1,
                broadcast_plmns: vec![crate::s1ap_build::encode_plmn_id(&PlmnId::new(
                    "310", "410",
                ))],
            }],
            default_paging_drx: PagingDrx::V64,
        };
        let bytes = builder::build_s1_setup_request(&request).expect("encode S1 Setup Request");
        let ppid = nextgcore_sctp::NEXTGCORE_SCTP_S1AP_PPID;
        {
            let bytes = bytes.clone();
            let client_ref = &client;
            tokio::task::block_in_place(|| {
                client_ref
                    .send(&bytes, ppid, S1AP_STREAM_ID)
                    .expect("eNB sends S1 Setup Request");
            });
        }

        // --- drive the server until it has transmitted its answer ---
        for _ in 0..100 {
            tokio::time::timeout(std::time::Duration::from_millis(20), server.poll_once())
                .await
                .ok();
        }

        // --- S1 Setup Response out, read off the association ---
        //
        // The client subscribed to SCTP association/address/shutdown events, so
        // the first datagrams off the socket are NOTIFICATIONS (COMM_UP), whose
        // sinfo is zeroed — reading one and treating it as data would observe
        // PPID 0. Skip anything with MSG_NOTIFICATION set, exactly as the
        // server's own read loop does.
        let response = tokio::task::spawn_blocking(move || {
            for _ in 0..16 {
                let mut buf = vec![0u8; 8192];
                let (n, info, flags) = client.recv_msg(&mut buf).expect("eNB receives a reply");
                if flags & nextgcore_sctp::MSG_NOTIFICATION != 0 {
                    continue; // SCTP event notification, not S1AP data
                }
                buf.truncate(n);
                return (buf, info.ppid);
            }
            panic!("no S1AP data received: only SCTP notifications");
        })
        .await
        .expect("recv task");

        let (pdu, got_ppid) = response;
        assert_eq!(
            got_ppid, ppid,
            "the MME must answer with the S1AP PPID (18), not NGAP's 60"
        );
        match decode_s1ap_pdu(&pdu).expect("decode the MME's reply") {
            S1apMessage::S1SetupResponse(rsp) => {
                assert_eq!(rsp.relative_mme_capacity, ctx.relative_capacity);
            }
            other => panic!("expected S1SetupResponse over the wire, got {other:?}"),
        }

        // The eNB is now registered and S1 Setup succeeded, so the S1 interface
        // is operational per TS 36.413 §8.7.3.2.
        let enb_id = ctx
            .enb_find_by_enb_id(0x1234)
            .expect("eNB registered by Global-eNB-ID");
        let enb = ctx.enb_find_by_id(enb_id).expect("eNB in pool");
        assert!(
            enb.state.s1_setup_success,
            "S1 Setup must be marked complete"
        );

        server.stop();
    }
}
